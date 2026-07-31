// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Startup catalog reconcile: apply each key's `missing` policy (design §3.7).
//!
//! After the [`BackendManager`] is built and **before** the broker binds its
//! socket, [`BackendManager::reconcile`] walks every catalog key, checks whether
//! its material exists in the routed [`Backend`], and applies the key's
//! [`MissingPolicy`]:
//!
//! - **present** → no-op.
//! - **`error`** (default) + absent → collected into a **fatal** reconcile error
//!   (every missing required key is reported at once, not just the first).
//! - **`warn`** + absent → a [`tracing::warn`] line; the key's ops fail at request
//!   time until it exists.
//! - **`generate`** + absent → create material: a crypto key (`asymmetric` /
//!   `symmetric`) at its catalog path via the backend's named-create methods, a
//!   `value` / `public` key by running its `generate` recipe and writing it as the
//!   first KV-v2 version.
//!
//! # Absent vs. unreachable
//!
//! The existence probe distinguishes **absent** (a reachable backend with no
//! material: a `404`, surfaced as [`BackendError::KeyNotFound`]) from
//! **unreachable / failed** (a transport error or any other backend rejection). A
//! backend that is *down* during reconcile is a clean **fatal** startup error
//! ([`ReconcileError::Probe`]). It is never silently treated as "absent" and
//! generated/over, which would mask an outage and could double-create material
//! once the backend recovers. Fail closed.

use crate::backend::BackendError;
use crate::catalog::{Class, Engine, GenerateSpec, KeyAlgorithm, KeyEntry, MissingPolicy};
use crate::manager::{BackendManager, ManagerError, Routed};
use basil_proto::{AeadAlgorithm, KeyType};

/// The outcome of a successful reconcile pass: a summary for the startup log.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReconcileSummary {
    /// Keys whose material already existed (no action taken).
    pub present: usize,
    /// Keys that were absent and **generated** (crypto keys + value/public).
    pub generated: usize,
    /// Keys that were absent under `missing="warn"` (logged, left absent).
    pub warned: usize,
}

/// A fatal reconcile failure (fail closed).
///
/// Either a backend was unreachable while probing for a key (never treated as
/// "absent"), one or more required keys are missing, or generating an absent
/// `missing="generate"` key failed.
#[derive(Debug, thiserror::Error)]
pub enum ReconcileError {
    /// One or more `missing="error"` (or default) keys are absent from their
    /// backend. Every such key is reported, not just the first.
    #[error("required key(s) absent from backend: {}", .0.join(", "))]
    RequiredMissing(Vec<String>),

    /// A backend was **unreachable** (or otherwise failed) while probing a key's
    /// existence. This is *not* "absent": a down backend at startup is fatal, so
    /// reconcile fails closed rather than generating over a real-but-unreachable
    /// key.
    #[error("probing key `{key}` failed (backend unreachable or rejecting): {source}")]
    Probe {
        /// The key being probed.
        key: String,
        /// The underlying backend error (transport / rejection).
        source: BackendError,
    },

    /// Generating material for an absent `missing="generate"` key failed.
    #[error("generating key `{key}` failed: {source}")]
    Generate {
        /// The key being generated.
        key: String,
        /// The underlying manager/backend error.
        source: ManagerError,
    },
}

/// Whether a probe found the key present or cleanly absent. A fatal (unreachable)
/// backend is surfaced as the surrounding [`Result`]'s `Err`, not a variant here.
enum Existence {
    Present,
    Absent,
}

/// The state of one catalog key in a [`CheckReport`] (the read-only counterpart
/// to reconcile's apply step).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStatus {
    /// The key's material exists in its backend (a clean probe hit).
    Present,
    /// The key's material is absent from its (reachable) backend. The key's
    /// [`MissingPolicy`] tells the caller how reconcile *would* treat it:
    /// `error` (would fail startup), `warn` (logged, left absent), or `generate`
    /// (would be created). A `check` never creates anything.
    Missing(MissingPolicy),
}

/// A single `(key, status)` row of a [`CheckReport`].
#[derive(Debug, Clone)]
pub struct KeyCheck {
    /// The dotted catalog name.
    pub name: String,
    /// Whether the key is present or absent (and, if absent, its `missing` policy).
    pub status: KeyStatus,
}

/// The result of a **read-only** [`BackendManager::check`] pass.
///
/// Every catalog key is classified as present or missing (with its `missing`
/// policy), in catalog name order. Unlike [`BackendManager::reconcile`], `check`
/// never creates or mutates anything; it only reports. A backend that is
/// *unreachable* during the probe is still a fatal error (the surrounding
/// [`Result`]'s `Err`), never silently read as "absent".
#[derive(Debug, Clone, Default)]
pub struct CheckReport {
    /// One row per catalog key, in name order.
    pub keys: Vec<KeyCheck>,
}

impl CheckReport {
    /// Count of keys whose material is present.
    #[must_use]
    pub fn present_count(&self) -> usize {
        self.keys
            .iter()
            .filter(|k| k.status == KeyStatus::Present)
            .count()
    }

    /// All absent keys, in name order, with their `missing` policy.
    pub fn missing(&self) -> impl Iterator<Item = (&str, MissingPolicy)> {
        self.keys.iter().filter_map(|k| match k.status {
            KeyStatus::Missing(policy) => Some((k.name.as_str(), policy)),
            KeyStatus::Present => None,
        })
    }

    /// The dotted names of absent keys whose `missing` policy is `error`: the
    /// required keys whose absence would fail startup reconcile. This is the
    /// predicate `--strict` gates on: a CI check **should fail** iff this is
    /// non-empty.
    #[must_use]
    pub fn required_missing(&self) -> Vec<&str> {
        self.missing()
            .filter(|(_, policy)| *policy == MissingPolicy::Error)
            .map(|(name, _)| name)
            .collect()
    }

    /// Whether a `--strict` gate should fail: true iff at least one absent key
    /// carries the `error` (required) policy. `warn`/`generate`-absent keys do
    /// **not** trip this: they are not failures of a pre-deploy check.
    #[must_use]
    pub fn should_fail_required(&self) -> bool {
        self.missing()
            .any(|(_, policy)| policy == MissingPolicy::Error)
    }
}

impl BackendManager {
    /// Reconcile every catalog key against its backend, applying the key's
    /// [`MissingPolicy`](crate::catalog::MissingPolicy) (§3.7).
    ///
    /// Returns a [`ReconcileSummary`] on success. Fails closed with a
    /// [`ReconcileError`] if a backend is unreachable while probing, if any
    /// required (`error`) key is absent, or if generating an absent
    /// `generate` key fails. All required-missing keys are collected and reported
    /// together.
    ///
    /// # Errors
    ///
    /// [`ReconcileError::Probe`] (unreachable backend), [`ReconcileError::RequiredMissing`]
    /// (one or more `error`-policy keys absent), or [`ReconcileError::Generate`]
    /// (a `generate` key could not be created).
    pub async fn reconcile(&self) -> Result<ReconcileSummary, ReconcileError> {
        use crate::catalog::MissingPolicy;

        let mut summary = ReconcileSummary::default();
        let mut required_missing: Vec<String> = Vec::new();

        // Collect (name, entry) up front: `resolve` borrows `self` immutably and
        // every op below is also `&self`, so a single immutable walk is fine.
        let keys: Vec<(String, KeyEntry)> = self
            .keys()
            .map(|(name, entry)| (name.clone(), entry.clone()))
            .collect();

        for (name, entry) in &keys {
            match self.probe(name).await? {
                Existence::Present => summary.present += 1,
                Existence::Absent => match entry.missing {
                    MissingPolicy::Error => {
                        required_missing.push(name.clone());
                    }
                    MissingPolicy::Warn => {
                        tracing::warn!(
                            key = %name,
                            "catalog key absent from backend (missing=warn); ops will fail until it exists"
                        );
                        summary.warned += 1;
                    }
                    MissingPolicy::Generate => {
                        self.generate_missing(name, entry).await?;
                        tracing::info!(key = %name, "generated absent key (missing=generate)");
                        summary.generated += 1;
                    }
                },
            }
        }

        if !required_missing.is_empty() {
            required_missing.sort();
            return Err(ReconcileError::RequiredMissing(required_missing));
        }
        Ok(summary)
    }

    /// **Read-only** counterpart to [`reconcile`](Self::reconcile): probe every
    /// catalog key and report whether it is present or absent (with its
    /// [`MissingPolicy`](crate::catalog::MissingPolicy)), **without** generating
    /// or mutating anything. For CI / pre-deploy lint checks.
    ///
    /// Reuses the same existence probe as `reconcile` (crypto via `key_metadata`,
    /// value/public via `kv_get`). A backend that is unreachable during the probe
    /// is *not* "absent": it is a fatal [`ReconcileError::Probe`] (fail closed),
    /// exactly as in reconcile: a down backend must never be reported as a clean
    /// "missing" that a caller might act on.
    ///
    /// Returns a [`CheckReport`] over every key in catalog name order. Use
    /// [`CheckReport::should_fail_required`] to gate a `--strict` CI check.
    ///
    /// # Errors
    ///
    /// [`ReconcileError::Probe`] if any backend is unreachable (or rejecting)
    /// while probing a key's existence.
    pub async fn check(&self) -> Result<CheckReport, ReconcileError> {
        // Catalog iteration is name-ordered (BTreeMap), so the report is too.
        let mut report = CheckReport::default();
        for (name, entry) in self.keys() {
            let status = match self.probe(name).await? {
                Existence::Present => KeyStatus::Present,
                Existence::Absent => KeyStatus::Missing(entry.missing),
            };
            report.keys.push(KeyCheck {
                name: name.clone(),
                status,
            });
        }
        Ok(report)
    }

    /// Probe whether `name`'s material exists in its backend.
    ///
    /// Crypto keys (`asymmetric` / `symmetric`) probe via `key_metadata` (a
    /// transit key-info read); `value` / `public` keys probe via `kv_get` of the
    /// latest version. A [`BackendError::KeyNotFound`] (a backend `404`) is the
    /// clean **absent** signal; **any other** error means the backend is
    /// unreachable or rejecting and is a fatal [`ReconcileError::Probe`]: a down
    /// backend is never silently treated as "absent".
    async fn probe(&self, name: &str) -> Result<Existence, ReconcileError> {
        let routed = self.resolve(name).map_err(|source| ReconcileError::Probe {
            key: name.to_string(),
            // An UnknownKey/UnknownBackend here is a manager-construction
            // invariant violation, surfaced through the backend error channel.
            source: match source {
                ManagerError::Backend(e) => e,
                other => BackendError::Backend(other.to_string()),
            },
        })?;

        // Probe by where the material actually lives: transit keys via
        // `key_metadata`, KV-backed material (value/public, and the
        // materialize-to-use keys) via a `kv_get`. Branch on the effective engine,
        // not just the class, so a materialize-to-sign key is probed in KV rather
        // than against a transit name that would 404.
        let result = match (routed.class(), routed.engine) {
            // Materialize-to-use keys (sealing X25519, engine=kv2 Ed25519,
            // §17.7): the private lives in KV, and basil-o86 provisions the
            // public out of band too. BOTH halves must exist for the key to be
            // "present": an absent public is as fatal (under missing=error) as an
            // absent private, since wrap/get_public_key/verify need it.
            (Class::Asymmetric, Engine::Kv2) | (Class::Sealing, _) => {
                self.probe_materialize_to_use(&routed).await
            }
            (Class::Asymmetric | Class::Symmetric, _) => {
                routed.backend.key_metadata(routed.path()).await.map(|_| ())
            }
            (Class::Value | Class::Public, _) => {
                routed.backend.kv_get(routed.path(), None).await.map(|_| ())
            }
        };

        match result {
            Ok(()) => Ok(Existence::Present),
            Err(BackendError::KeyNotFound(_)) => Ok(Existence::Absent),
            Err(source) => Err(ReconcileError::Probe {
                key: name.to_string(),
                source,
            }),
        }
    }

    /// Existence probe for a materialize-to-use key (sealing X25519 / engine=kv2
    /// Ed25519, §17.7): both the private (at `path`) **and** the
    /// out-of-band-provisioned public (at `public_path`, basil-o86) must exist in
    /// KV. A [`BackendError::KeyNotFound`] from either is the clean "absent"
    /// signal the caller maps to [`Existence::Absent`]; any other error is fatal.
    /// A materialize key with no `public_path` is a misprovisioned catalog (the
    /// loader normally rejects it), surfaced as "absent" so it fails closed under
    /// `missing=error` rather than booting a key whose public can never resolve.
    async fn probe_materialize_to_use(&self, routed: &Routed<'_>) -> Result<(), BackendError> {
        // The private half (materialized seed / X25519 private).
        routed.backend.kv_get(routed.path(), None).await?;
        // The public half, provisioned out of band.
        let public_path = routed.public_path().ok_or_else(|| {
            BackendError::KeyNotFound(format!(
                "{} has no public_path; its public half is not provisioned",
                routed.path()
            ))
        })?;
        routed.backend.kv_get(public_path, None).await?;
        Ok(())
    }

    /// Create material for an absent `missing="generate"` key: a crypto key at its
    /// catalog path, or a value/public secret from its `generate` recipe written
    /// as the first KV-v2 version.
    async fn generate_missing(&self, name: &str, entry: &KeyEntry) -> Result<(), ReconcileError> {
        let to_err = |source| ReconcileError::Generate {
            key: name.to_string(),
            source,
        };
        let routed = self.resolve(name).map_err(to_err)?;
        let path = routed.path().to_string();

        match entry.class {
            // A materialize-to-sign Ed25519 key (`engine=kv2`, `vault-iiz`) cannot
            // be generated through transit: Basil has no in-broker keygen for it,
            // and writing a fresh seed in reconcile would mint signing authority
            // silently. Its 32-byte seed is provisioned out of band (operator writes
            // the base64 seed into KV). Fail closed, mirroring the sealing arm.
            // Never log the (absent) value.
            Class::Asymmetric if routed.engine == Engine::Kv2 => {
                return Err(ReconcileError::Generate {
                    key: name.to_string(),
                    source: ManagerError::Backend(BackendError::Backend(format!(
                        "value-store signing key `{name}` (engine=kv2) cannot be \
                         generated in-broker; provision its Ed25519 seed out of band"
                    ))),
                });
            }
            Class::Asymmetric => {
                let key_type = asym_key_type(name, entry.key_type).map_err(to_err)?;
                routed
                    .require_mint_key_type("generate", key_type)
                    .map_err(to_err)?;
                routed
                    .backend
                    .create_named_key(&path, key_type)
                    .await
                    .map_err(ManagerError::from)
                    .map_err(to_err)?;
            }
            Class::Symmetric => {
                let aead = sym_aead(name, entry.key_type).map_err(to_err)?;
                routed
                    .backend
                    .create_named_aead(&path, aead)
                    .await
                    .map_err(ManagerError::from)
                    .map_err(to_err)?;
            }
            Class::Sealing => {
                // Basil cannot generate an X25519 keypair through transit (no such
                // engine), so a sealing key's private must be provisioned out of
                // band (BYOK `set` of the raw X25519 private). Fail closed rather
                // than silently leaving the key absent.
                return Err(ReconcileError::Generate {
                    key: name.to_string(),
                    source: ManagerError::Backend(BackendError::Backend(format!(
                        "sealing key `{name}` cannot be generated in-broker; \
                         provision its X25519 private out of band"
                    ))),
                });
            }
            Class::Value | Class::Public => {
                // The loader guarantees a value/public key with missing=generate
                // carries a recipe (GenerateWithoutRecipe is a fatal load error),
                // so `generate` is Some here; fail closed if it somehow is not.
                let spec: &GenerateSpec =
                    entry
                        .generate
                        .as_ref()
                        .ok_or_else(|| ReconcileError::Generate {
                            key: name.to_string(),
                            source: ManagerError::Backend(BackendError::Backend(
                                "missing=generate value/public key has no generate recipe".into(),
                            )),
                        })?;
                for write in self
                    .generated_writes_for_key(name, spec)
                    .await
                    .map_err(to_err)?
                {
                    let write_route = self.resolve(&write.key_id).map_err(to_err)?;
                    write_route
                        .backend
                        .kv_put(write_route.path(), &write.value)
                        .await
                        .map_err(ManagerError::from)
                        .map_err(to_err)?;
                }
            }
        }
        Ok(())
    }
}

/// The wire [`KeyType`] for an asymmetric catalog `key_type`. The loader requires
/// asymmetric keys to carry a `key_type`; an absent or non-signing algorithm here
/// is a misconfigured catalog and fails closed.
fn asym_key_type(name: &str, key_type: Option<KeyAlgorithm>) -> Result<KeyType, ManagerError> {
    match key_type {
        Some(KeyAlgorithm::Ed25519) => Ok(KeyType::Ed25519),
        Some(KeyAlgorithm::Ed25519Nkey) => Ok(KeyType::Ed25519Nkey),
        Some(KeyAlgorithm::Rsa2048) => Ok(KeyType::Rsa2048),
        Some(KeyAlgorithm::EcdsaP256) => Ok(KeyType::EcdsaP256),
        Some(KeyAlgorithm::EcdsaP384) => Ok(KeyType::EcdsaP384),
        Some(KeyAlgorithm::EcdsaP521) => Ok(KeyType::EcdsaP521),
        // ML-DSA software-custodied signing keys are not transit keys: their seed
        // is generated, sealed, and written as a custody record by the
        // local-software provider (the `new_key` RPC path), never created through
        // a backend `create_named_key` at startup reconcile. Fail closed if a
        // catalog marks one `missing=generate`.
        Some(KeyAlgorithm::MlDsa44 | KeyAlgorithm::MlDsa65 | KeyAlgorithm::MlDsa87) => {
            Err(ManagerError::Backend(BackendError::Backend(format!(
                "ML-DSA signing key `{name}` is software-custodied; provision it \
                 via the `new_key` provider path, not startup generate"
            ))))
        }
        Some(
            KeyAlgorithm::Aes256Gcm
            | KeyAlgorithm::ChaCha20Poly1305
            | KeyAlgorithm::X25519
            | KeyAlgorithm::MlKem512
            | KeyAlgorithm::MlKem768
            | KeyAlgorithm::MlKem1024,
        )
        | None => Err(ManagerError::Backend(BackendError::Backend(format!(
            "asymmetric key `{name}` has no signing keyType to generate from"
        )))),
    }
}

/// The [`AeadAlgorithm`] for a symmetric catalog `key_type`. A symmetric key
/// always carries an AEAD algorithm; anything else fails closed.
fn sym_aead(name: &str, key_type: Option<KeyAlgorithm>) -> Result<AeadAlgorithm, ManagerError> {
    match key_type {
        Some(KeyAlgorithm::Aes256Gcm) => Ok(AeadAlgorithm::Aes256Gcm),
        Some(KeyAlgorithm::ChaCha20Poly1305) => Ok(AeadAlgorithm::Chacha20Poly1305),
        _ => Err(ManagerError::Backend(BackendError::Backend(format!(
            "symmetric key `{name}` has no AEAD keyType to generate from"
        )))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{Backend, KeyMetadata, KvValue, NewKey, PublicKey};
    use crate::catalog::Catalog;
    use async_trait::async_trait;
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// How a mock backend answers an existence probe (`key_metadata` / `kv_get`).
    #[derive(Clone, Copy)]
    enum Probe {
        /// The key exists, so probes return `Ok` (Present).
        Present,
        /// The key is absent, so probes return `KeyNotFound` (a backend 404).
        Absent,
        /// The backend is unreachable, so probes return a transport error (fatal).
        Unreachable,
    }

    /// A reconcile-focused mock: a single backend whose probe disposition is fixed
    /// at construction, recording every create/write op so a test can assert which
    /// generation path ran.
    #[derive(Default)]
    struct Recorder {
        create_named_key_calls: AtomicUsize,
        create_named_aead_calls: AtomicUsize,
        kv_put_calls: AtomicUsize,
        last_create_path: Mutex<Option<String>>,
        last_kv_put: Mutex<Option<(String, Vec<u8>)>>,
        last_aead: Mutex<Option<AeadAlgorithm>>,
        last_key_type: Mutex<Option<KeyType>>,
    }

    struct MockBackend {
        probe: Probe,
        rec: std::sync::Arc<Recorder>,
    }

    impl MockBackend {
        fn new(probe: Probe) -> (Self, std::sync::Arc<Recorder>) {
            let rec = std::sync::Arc::new(Recorder::default());
            (
                Self {
                    probe,
                    rec: rec.clone(),
                },
                rec,
            )
        }
    }

    #[async_trait]
    impl Backend for MockBackend {
        fn kind(&self) -> &'static str {
            "mock"
        }

        async fn new_key(&self, _key_type: KeyType) -> Result<NewKey, BackendError> {
            Err(BackendError::Unsupported(
                "new_key (unused in reconcile tests)",
            ))
        }

        async fn public_key(&self, _key_id: &str) -> Result<Vec<u8>, BackendError> {
            Err(BackendError::Unsupported("public_key"))
        }

        async fn public_key_with_meta(&self, _key_id: &str) -> Result<PublicKey, BackendError> {
            Err(BackendError::Unsupported("public_key_with_meta"))
        }

        /// The crypto-key existence probe.
        async fn key_metadata(&self, _key_id: &str) -> Result<KeyMetadata, BackendError> {
            match self.probe {
                Probe::Present => Ok(KeyMetadata {
                    key_type: Some(KeyType::Ed25519),
                    latest_version: 1,
                }),
                Probe::Absent => Err(BackendError::KeyNotFound("absent".into())),
                Probe::Unreachable => Err(BackendError::Transport("connection refused".into())),
            }
        }

        /// The value/public existence probe.
        async fn kv_get(
            &self,
            _key_id: &str,
            _version: Option<u32>,
        ) -> Result<KvValue, BackendError> {
            match self.probe {
                Probe::Present => Ok(KvValue {
                    value: b"present".to_vec(),
                    version: 1,
                }),
                Probe::Absent => Err(BackendError::KeyNotFound("absent".into())),
                Probe::Unreachable => Err(BackendError::Transport("connection refused".into())),
            }
        }

        /// Sealing is never reconciled (a sealing private is operator-provisioned
        /// out-of-band), so this mock mirrors the value/public probe shape.
        async fn kv_get_secret(
            &self,
            _key_id: &str,
            _version: Option<u32>,
        ) -> Result<crate::backend::KvSecret, BackendError> {
            match self.probe {
                Probe::Present => Ok(crate::backend::KvSecret {
                    value: zeroize::Zeroizing::new(b"present".to_vec()),
                    version: 1,
                }),
                Probe::Absent => Err(BackendError::KeyNotFound("absent".into())),
                Probe::Unreachable => Err(BackendError::Transport("connection refused".into())),
            }
        }

        async fn create_named_key(
            &self,
            key_id: &str,
            key_type: KeyType,
        ) -> Result<NewKey, BackendError> {
            self.rec
                .create_named_key_calls
                .fetch_add(1, Ordering::SeqCst);
            *self.rec.last_create_path.lock().unwrap() = Some(key_id.to_string());
            *self.rec.last_key_type.lock().unwrap() = Some(key_type);
            Ok(NewKey {
                key_id: key_id.to_string(),
                public_key: vec![1, 2, 3],
            })
        }

        async fn create_named_aead(
            &self,
            key_id: &str,
            aead: AeadAlgorithm,
        ) -> Result<(), BackendError> {
            self.rec
                .create_named_aead_calls
                .fetch_add(1, Ordering::SeqCst);
            *self.rec.last_create_path.lock().unwrap() = Some(key_id.to_string());
            *self.rec.last_aead.lock().unwrap() = Some(aead);
            Ok(())
        }

        async fn kv_put(&self, key_id: &str, value: &[u8]) -> Result<u32, BackendError> {
            self.rec.kv_put_calls.fetch_add(1, Ordering::SeqCst);
            *self.rec.last_kv_put.lock().unwrap() = Some((key_id.to_string(), value.to_vec()));
            Ok(1)
        }

        async fn sign(&self, _key_id: &str, _message: &[u8]) -> Result<Vec<u8>, BackendError> {
            Err(BackendError::Unsupported("sign"))
        }

        async fn verify(
            &self,
            _key_id: &str,
            _message: &[u8],
            _signature: &[u8],
        ) -> Result<bool, BackendError> {
            Err(BackendError::Unsupported("verify"))
        }
    }

    /// A catalog with one key of each (class, missing) combination this reconcile
    /// exercises, all routed to the single mock backend `b`.
    const CATALOG: &str = r#"{
      "schema": "catalog",
      "backends": { "b": { "kind": "vault", "addr": "http://127.0.0.1:8200" } },
      "keys": {
        "req.signer": {
          "class": "asymmetric", "keyType": "ed25519", "backend": "b",
          "path": "req-signer", "writable": true, "missing": "error",
          "description": "a required signing key"
        },
        "warn.value": {
          "class": "value", "backend": "b", "engine": "kv2",
          "path": "secret/data/warn/value", "writable": true, "missing": "warn",
          "description": "a warn-on-missing value"
        },
        "gen.signer": {
          "class": "asymmetric", "keyType": "ed25519", "backend": "b",
          "path": "gen-signer", "writable": true, "missing": "generate",
          "description": "a generate-on-missing signing key"
        },
        "gen.box": {
          "class": "symmetric", "keyType": "aes-256-gcm", "backend": "b",
          "path": "gen-box", "writable": true, "missing": "generate",
          "description": "a generate-on-missing AEAD key"
        },
        "gen.value": {
          "class": "value", "backend": "b", "engine": "kv2",
          "path": "secret/data/gen/value", "writable": true, "missing": "generate",
          "generate": { "format": "ascii-printable", "bytes": 24 },
          "description": "a generate-on-missing value"
        }
      }
    }"#;

    fn parse() -> Catalog {
        serde_json::from_str(CATALOG).expect("catalog parses")
    }

    /// Build a manager over the fixture catalog, every key routed to one mock with
    /// the given probe disposition; returns the manager + the recorder.
    fn manager_with(probe: Probe) -> (BackendManager, std::sync::Arc<Recorder>) {
        let (backend, rec) = MockBackend::new(probe);
        let mut backends: BTreeMap<String, Box<dyn Backend>> = BTreeMap::new();
        backends.insert("b".into(), Box::new(backend));
        let mgr = BackendManager::new(parse(), backends).expect("manager constructs");
        (mgr, rec)
    }

    #[tokio::test]
    async fn all_present_is_a_noop_with_present_count() {
        let (mgr, rec) = manager_with(Probe::Present);
        let summary = mgr.reconcile().await.expect("all-present reconciles ok");
        assert_eq!(summary.present, 5);
        assert_eq!(summary.generated, 0);
        assert_eq!(summary.warned, 0);
        // Nothing was created when every key already existed.
        assert_eq!(rec.create_named_key_calls.load(Ordering::SeqCst), 0);
        assert_eq!(rec.create_named_aead_calls.load(Ordering::SeqCst), 0);
        assert_eq!(rec.kv_put_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn required_missing_is_fatal_and_reports_the_key() {
        // Every key is absent: req.signer (missing=error) must make reconcile fail,
        // and the error names it. warn/generate keys do NOT make it fail.
        let (mgr, _rec) = manager_with(Probe::Absent);
        let err = mgr
            .reconcile()
            .await
            .expect_err("a required-missing key must fail closed");
        match err {
            ReconcileError::RequiredMissing(keys) => {
                assert_eq!(keys, vec!["req.signer".to_string()]);
            }
            other => panic!("expected RequiredMissing, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn warn_missing_is_ok_and_counted() {
        // Make ONLY the warn key absent by using a catalog where the error key is
        // dropped; here we instead assert the warn count surfaces when the run
        // otherwise succeeds. Use a generate-everything probe path: with all keys
        // absent, the warn key is logged + counted but the required key still
        // fails. So test warn in isolation via a catalog with no required keys.
        const NO_REQUIRED: &str = r#"{
          "schema": "catalog",
          "backends": {
            "b": {
              "kind": "vault", "addr": "http://127.0.0.1:8200",
              "engines": ["transit", "kv2"], "capabilities": [],
              "mintKeyTypes": ["ed25519"]
            }
          },
          "keys": {
            "warn.value": {
              "class": "value", "backend": "b", "engine": "kv2",
              "path": "secret/data/warn/value", "writable": true, "missing": "warn",
              "description": "a warn-on-missing value"
            }
          }
        }"#;
        let cat: Catalog = serde_json::from_str(NO_REQUIRED).expect("parses");
        let (backend, _rec) = MockBackend::new(Probe::Absent);
        let mut backends: BTreeMap<String, Box<dyn Backend>> = BTreeMap::new();
        backends.insert("b".into(), Box::new(backend));
        let mgr = BackendManager::new(cat, backends).expect("constructs");
        let summary = mgr.reconcile().await.expect("warn-only reconciles ok");
        assert_eq!(summary.warned, 1);
        assert_eq!(summary.present, 0);
        assert_eq!(summary.generated, 0);
    }

    #[tokio::test]
    async fn generate_missing_creates_crypto_and_value_keys() {
        // A catalog with ONLY generate keys (asym + sym + value), all absent: each
        // must be created via its class-specific path.
        const GEN_ONLY: &str = r#"{
          "schema": "catalog",
          "backends": { "b": { "kind": "vault", "addr": "http://127.0.0.1:8200" } },
          "keys": {
            "gen.signer": {
              "class": "asymmetric", "keyType": "ed25519", "backend": "b",
              "path": "gen-signer", "writable": true, "missing": "generate",
              "description": "asym generate"
            },
            "gen.box": {
              "class": "symmetric", "keyType": "aes-256-gcm", "backend": "b",
              "path": "gen-box", "writable": true, "missing": "generate",
              "description": "sym generate"
            },
            "gen.value": {
              "class": "value", "backend": "b", "engine": "kv2",
              "path": "secret/data/gen/value", "writable": true, "missing": "generate",
              "generate": { "format": "ascii-printable", "bytes": 24 },
              "description": "value generate"
            }
          }
        }"#;
        let cat: Catalog = serde_json::from_str(GEN_ONLY).expect("parses");
        let (backend, rec) = MockBackend::new(Probe::Absent);
        let mut backends: BTreeMap<String, Box<dyn Backend>> = BTreeMap::new();
        backends.insert("b".into(), Box::new(backend));
        let mgr = BackendManager::new(cat, backends).expect("constructs");

        let summary = mgr.reconcile().await.expect("generate reconciles ok");
        assert_eq!(summary.generated, 3);
        assert_eq!(summary.present, 0);
        assert_eq!(summary.warned, 0);

        // Crypto asym -> create_named_key at the catalog PATH.
        assert_eq!(rec.create_named_key_calls.load(Ordering::SeqCst), 1);
        assert_eq!(*rec.last_key_type.lock().unwrap(), Some(KeyType::Ed25519));
        // Crypto sym -> create_named_aead with the catalog AEAD suite.
        assert_eq!(rec.create_named_aead_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            *rec.last_aead.lock().unwrap(),
            Some(AeadAlgorithm::Aes256Gcm)
        );
        // Value -> generate_value + kv_put at the catalog PATH, a 24-byte printable.
        assert_eq!(rec.kv_put_calls.load(Ordering::SeqCst), 1);
        let (path, value) = rec.last_kv_put.lock().unwrap().clone().expect("a kv write");
        assert_eq!(path, "secret/data/gen/value");
        assert_eq!(value.len(), 24);
        assert!(value.iter().all(|b| (b'!'..=b'~').contains(b)));
    }

    fn generated_asymmetric_catalog(key_type: &str, mint_key_types: &str) -> String {
        format!(
            r#"{{
          "schema": "catalog",
          "backends": {{
            "b": {{
              "kind": "vault", "addr": "http://127.0.0.1:8200",
              "engines": ["transit"], "capabilities": [],
              "mintKeyTypes": [{mint_key_types}]
            }}
          }},
          "keys": {{
            "gen.signer": {{
              "class": "asymmetric", "keyType": "{key_type}", "backend": "b",
              "path": "gen-signer", "writable": true, "missing": "generate",
              "description": "generated signer"
            }}
          }}
        }}"#
        )
    }

    #[tokio::test]
    async fn generate_missing_creates_rsa_when_static_preset_allows_it() {
        let cat: Catalog =
            serde_json::from_str(&generated_asymmetric_catalog("rsa-2048", r#""rsa-2048""#))
                .expect("parses");
        let (backend, rec) = MockBackend::new(Probe::Absent);
        let mut backends: BTreeMap<String, Box<dyn Backend>> = BTreeMap::new();
        backends.insert("b".into(), Box::new(backend));
        let mgr = BackendManager::new(cat, backends).expect("constructs");

        let summary = mgr.reconcile().await.expect("rsa generate reconciles ok");
        assert_eq!(summary.generated, 1);
        assert_eq!(rec.create_named_key_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            rec.last_create_path.lock().unwrap().as_deref(),
            Some("gen-signer")
        );
        assert_eq!(*rec.last_key_type.lock().unwrap(), Some(KeyType::Rsa2048));
    }

    #[tokio::test]
    async fn generate_missing_creates_ecdsa_p256_when_static_preset_allows_it() {
        let cat: Catalog = serde_json::from_str(&generated_asymmetric_catalog(
            "ecdsa-p256",
            r#""ecdsa-p256""#,
        ))
        .expect("parses");
        let (backend, rec) = MockBackend::new(Probe::Absent);
        let mut backends: BTreeMap<String, Box<dyn Backend>> = BTreeMap::new();
        backends.insert("b".into(), Box::new(backend));
        let mgr = BackendManager::new(cat, backends).expect("constructs");

        let summary = mgr.reconcile().await.expect("ecdsa generate reconciles ok");
        assert_eq!(summary.generated, 1);
        assert_eq!(rec.create_named_key_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            rec.last_create_path.lock().unwrap().as_deref(),
            Some("gen-signer")
        );
        assert_eq!(*rec.last_key_type.lock().unwrap(), Some(KeyType::EcdsaP256));
    }

    #[tokio::test]
    async fn generate_missing_creates_nkey_when_static_preset_allows_it() {
        let cat: Catalog = serde_json::from_str(&generated_asymmetric_catalog(
            "ed25519-nkey",
            r#""ed25519-nkey""#,
        ))
        .expect("parses");
        let (backend, rec) = MockBackend::new(Probe::Absent);
        let mut backends: BTreeMap<String, Box<dyn Backend>> = BTreeMap::new();
        backends.insert("b".into(), Box::new(backend));
        let mgr = BackendManager::new(cat, backends).expect("constructs");

        let summary = mgr.reconcile().await.expect("nkey generate reconciles ok");
        assert_eq!(summary.generated, 1);
        assert_eq!(rec.create_named_key_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            rec.last_create_path.lock().unwrap().as_deref(),
            Some("gen-signer")
        );
        assert_eq!(
            *rec.last_key_type.lock().unwrap(),
            Some(KeyType::Ed25519Nkey)
        );
    }

    #[tokio::test]
    async fn generate_missing_rejects_key_type_absent_from_static_backend_preset() {
        const GEN_RSA_UNSUPPORTED: &str = r#"{
          "schema": "catalog",
          "backends": {
            "b": {
              "kind": "vault", "addr": "http://127.0.0.1:8200",
              "engines": ["transit"], "capabilities": [],
              "mintKeyTypes": ["ed25519"]
            }
          },
          "keys": {
            "gen.rsa": {
              "class": "asymmetric", "keyType": "rsa-2048", "backend": "b",
              "path": "gen-rsa", "writable": true, "missing": "generate",
              "description": "rsa generate"
            }
          }
        }"#;
        let cat: Catalog = serde_json::from_str(GEN_RSA_UNSUPPORTED).expect("parses");
        let (backend, rec) = MockBackend::new(Probe::Absent);
        let mut backends: BTreeMap<String, Box<dyn Backend>> = BTreeMap::new();
        backends.insert("b".into(), Box::new(backend));
        let mgr = BackendManager::new(cat, backends).expect("constructs");

        let err = mgr
            .reconcile()
            .await
            .expect_err("rsa is absent from preset");
        assert!(matches!(
            err,
            ReconcileError::Generate {
                source: ManagerError::UnsupportedKeyType {
                    backend,
                    op: "generate",
                    key_type: KeyType::Rsa2048
                },
                ..
            } if backend == "b"
        ));
        assert_eq!(rec.create_named_key_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn kv2_signer_missing_generate_refuses_in_broker() {
        // A value-store Ed25519 signing key (engine=kv2, vault-iiz) with
        // missing=generate must FAIL closed: Basil cannot mint its seed in-broker,
        // and it must NOT call create_named_key (that would route to transit) or
        // write a fresh seed (silently minting signing authority). The seed is
        // provisioned out of band.
        const KV2_SIGNER: &str = r#"{
          "schema": "catalog",
          "backends": { "b": { "kind": "vault", "addr": "http://127.0.0.1:8200" } },
          "keys": {
            "kv2.signer": {
              "class": "asymmetric", "keyType": "ed25519", "backend": "b", "engine": "kv2",
              "path": "secret/data/kv2/signer", "writable": true, "missing": "generate",
              "description": "a value-store materialize-to-sign key"
            }
          }
        }"#;
        let cat: Catalog = serde_json::from_str(KV2_SIGNER).expect("parses");
        let (backend, rec) = MockBackend::new(Probe::Absent);
        let mut backends: BTreeMap<String, Box<dyn Backend>> = BTreeMap::new();
        backends.insert("b".into(), Box::new(backend));
        let mgr = BackendManager::new(cat, backends).expect("constructs");

        let err = mgr
            .reconcile()
            .await
            .expect_err("a kv2 signing key cannot be generated in-broker");
        assert!(matches!(err, ReconcileError::Generate { .. }));
        // Crucially: NOT created via transit, and no fresh seed written to KV.
        assert_eq!(rec.create_named_key_calls.load(Ordering::SeqCst), 0);
        assert_eq!(rec.kv_put_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn kv2_signer_present_probes_kv_not_transit() {
        // The existence probe for an engine=kv2 signing key must hit KV (kv_get),
        // not key_metadata (a transit name that would 404). With Probe::Present the
        // key resolves as present and reconcile is a clean no-op.
        const KV2_SIGNER: &str = r#"{
          "schema": "catalog",
          "backends": { "b": { "kind": "vault", "addr": "http://127.0.0.1:8200" } },
          "keys": {
            "kv2.signer": {
              "class": "asymmetric", "keyType": "ed25519", "backend": "b", "engine": "kv2",
              "path": "secret/data/kv2/signer",
              "publicPath": "secret/data/kv2/signer-public",
              "writable": true, "missing": "error",
              "description": "a value-store materialize-to-sign key"
            }
          }
        }"#;
        let cat: Catalog = serde_json::from_str(KV2_SIGNER).expect("parses");
        let (backend, rec) = MockBackend::new(Probe::Present);
        let mut backends: BTreeMap<String, Box<dyn Backend>> = BTreeMap::new();
        backends.insert("b".into(), Box::new(backend));
        let mgr = BackendManager::new(cat, backends).expect("constructs");

        let summary = mgr
            .reconcile()
            .await
            .expect("present kv2 signer reconciles");
        assert_eq!(summary.present, 1);
        assert_eq!(summary.generated, 0);
        // It was probed via kv_get; no transit-style creation happened.
        assert_eq!(rec.create_named_key_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn materialize_key_without_public_path_probes_absent() {
        // basil-o86: a materialize-to-use key whose public half is NOT provisioned
        // (no publicPath) is treated as ABSENT even when the private is Present,
        // so under missing=error it fails closed rather than booting a key whose
        // wrap/get_public_key can never resolve a public.
        const NO_PUB: &str = r#"{
          "schema": "catalog",
          "backends": { "b": { "kind": "vault", "addr": "http://127.0.0.1:8200" } },
          "keys": {
            "kv2.signer": {
              "class": "asymmetric", "keyType": "ed25519", "backend": "b", "engine": "kv2",
              "path": "secret/data/kv2/signer", "writable": true, "missing": "error",
              "description": "a kv2 signer missing its publicPath"
            }
          }
        }"#;
        let cat: Catalog = serde_json::from_str(NO_PUB).expect("parses");
        // Probe::Present: the private would probe present, but the absent publicPath
        // makes the key absent overall.
        let (backend, _rec) = MockBackend::new(Probe::Present);
        let mut backends: BTreeMap<String, Box<dyn Backend>> = BTreeMap::new();
        backends.insert("b".into(), Box::new(backend));
        let mgr = BackendManager::new(cat, backends).expect("constructs");

        let err = mgr
            .reconcile()
            .await
            .expect_err("a materialize key with no publicPath must fail closed");
        match err {
            ReconcileError::RequiredMissing(keys) => assert_eq!(keys, vec!["kv2.signer"]),
            other => panic!("expected RequiredMissing, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unreachable_backend_is_fatal_not_treated_as_absent() {
        // A down backend must FAIL reconcile (Probe error), never be read as
        // "absent" and generated/over.
        let (mgr, rec) = manager_with(Probe::Unreachable);
        let err = mgr
            .reconcile()
            .await
            .expect_err("an unreachable backend must fail closed");
        match err {
            ReconcileError::Probe { source, .. } => {
                assert!(matches!(source, BackendError::Transport(_)));
            }
            other => panic!("expected Probe (unreachable), got {other:?}"),
        }
        // Crucially: nothing was generated despite generate-policy keys being
        // present: an unreachable backend is never silently "absent".
        assert_eq!(rec.create_named_key_calls.load(Ordering::SeqCst), 0);
        assert_eq!(rec.create_named_aead_calls.load(Ordering::SeqCst), 0);
        assert_eq!(rec.kv_put_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn present_keys_are_never_created() {
        // Even generate-policy keys that already exist must NOT be re-created.
        let (mgr, rec) = manager_with(Probe::Present);
        mgr.reconcile().await.expect("reconciles");
        assert_eq!(rec.create_named_key_calls.load(Ordering::SeqCst), 0);
        assert_eq!(rec.create_named_aead_calls.load(Ordering::SeqCst), 0);
        assert_eq!(rec.kv_put_calls.load(Ordering::SeqCst), 0);
    }

    // ---- check(): the read-only report (vault-roe) -------------------------

    fn status_of<'a>(report: &'a CheckReport, name: &str) -> &'a KeyStatus {
        &report
            .keys
            .iter()
            .find(|k| k.name == name)
            .expect("key in report")
            .status
    }

    #[tokio::test]
    async fn check_all_present_reports_every_key_present_and_creates_nothing() {
        let (mgr, rec) = manager_with(Probe::Present);
        let report = mgr.check().await.expect("check succeeds when reachable");
        // Every fixture key (5) is present; nothing is missing; nothing fails.
        assert_eq!(report.keys.len(), 5);
        assert_eq!(report.present_count(), 5);
        assert_eq!(report.missing().count(), 0);
        assert!(!report.should_fail_required());
        assert!(report.required_missing().is_empty());
        // A check is read-only: it never creates/mutates anything.
        assert_eq!(rec.create_named_key_calls.load(Ordering::SeqCst), 0);
        assert_eq!(rec.create_named_aead_calls.load(Ordering::SeqCst), 0);
        assert_eq!(rec.kv_put_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn check_all_absent_classifies_each_key_by_its_missing_policy() {
        // Every key is absent: the report must classify each by its catalog
        // `missing` policy, NOT generate or mutate anything.
        let (mgr, rec) = manager_with(Probe::Absent);
        let report = mgr.check().await.expect("check succeeds when reachable");

        assert_eq!(report.present_count(), 0);
        // req.signer (error), warn.value (warn), gen.signer/gen.box/gen.value (generate).
        assert_eq!(
            *status_of(&report, "req.signer"),
            KeyStatus::Missing(MissingPolicy::Error)
        );
        assert_eq!(
            *status_of(&report, "warn.value"),
            KeyStatus::Missing(MissingPolicy::Warn)
        );
        assert_eq!(
            *status_of(&report, "gen.signer"),
            KeyStatus::Missing(MissingPolicy::Generate)
        );
        assert_eq!(
            *status_of(&report, "gen.box"),
            KeyStatus::Missing(MissingPolicy::Generate)
        );
        assert_eq!(
            *status_of(&report, "gen.value"),
            KeyStatus::Missing(MissingPolicy::Generate)
        );

        // Read-only: not one create/write despite generate-policy keys absent.
        assert_eq!(rec.create_named_key_calls.load(Ordering::SeqCst), 0);
        assert_eq!(rec.create_named_aead_calls.load(Ordering::SeqCst), 0);
        assert_eq!(rec.kv_put_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn check_should_fail_required_iff_an_error_class_key_is_absent() {
        // All absent: req.signer is missing=error -> the --strict gate must trip,
        // and required_missing names exactly it (warn/generate-absent excluded).
        let (mgr, _rec) = manager_with(Probe::Absent);
        let report = mgr.check().await.expect("check ok");
        assert!(report.should_fail_required());
        assert_eq!(report.required_missing(), vec!["req.signer"]);

        // All present: nothing required is absent -> the gate must NOT trip.
        let (mgr, _rec) = manager_with(Probe::Present);
        let report = mgr.check().await.expect("check ok");
        assert!(!report.should_fail_required());
        assert!(report.required_missing().is_empty());
    }

    #[tokio::test]
    async fn check_warn_and_generate_absent_do_not_trip_require() {
        // A catalog with ONLY warn + generate keys, all absent: missing keys are
        // reported, but NONE is error-class, so --strict must NOT fail.
        const WARN_GEN_ONLY: &str = r#"{
          "schema": "catalog",
          "backends": { "b": { "kind": "vault", "addr": "http://127.0.0.1:8200" } },
          "keys": {
            "warn.value": {
              "class": "value", "backend": "b", "engine": "kv2",
              "path": "secret/data/warn/value", "writable": true, "missing": "warn",
              "description": "warn"
            },
            "gen.signer": {
              "class": "asymmetric", "keyType": "ed25519", "backend": "b",
              "path": "gen-signer", "writable": true, "missing": "generate",
              "description": "generate"
            }
          }
        }"#;
        let cat: Catalog = serde_json::from_str(WARN_GEN_ONLY).expect("parses");
        let (backend, _rec) = MockBackend::new(Probe::Absent);
        let mut backends: BTreeMap<String, Box<dyn Backend>> = BTreeMap::new();
        backends.insert("b".into(), Box::new(backend));
        let mgr = BackendManager::new(cat, backends).expect("constructs");

        let report = mgr.check().await.expect("check ok");
        // Both keys absent and reported, but neither is error-class.
        assert_eq!(report.missing().count(), 2);
        assert!(!report.should_fail_required());
        assert!(report.required_missing().is_empty());
    }

    #[tokio::test]
    async fn check_unreachable_backend_is_fatal_not_treated_as_absent() {
        // A down backend must FAIL check (Probe error), never be reported as a
        // clean "missing" that a --strict gate might then wrongly decide.
        let (mgr, _rec) = manager_with(Probe::Unreachable);
        let err = mgr
            .check()
            .await
            .expect_err("an unreachable backend must fail closed");
        match err {
            ReconcileError::Probe { source, .. } => {
                assert!(matches!(source, BackendError::Transport(_)));
            }
            other => panic!("expected Probe (unreachable), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_report_keys_are_in_catalog_name_order() {
        // The report walks the catalog (a BTreeMap) so rows are name-sorted:
        // a stable, diffable order for CI output.
        let (mgr, _rec) = manager_with(Probe::Present);
        let report = mgr.check().await.expect("check ok");
        let names: Vec<&str> = report.keys.iter().map(|k| k.name.as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted);
    }
}
