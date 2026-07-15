// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Signal-driven hot reload of the catalog/policy **generation** (`basil-y3e`).
//!
//! [`reload_generation`] is the single, fail-closed reload engine shared by the
//! SIGHUP handler and (later) the permission-scoped gRPC admin-reload follow-on
//! (`basil-atq`). It re-reads the catalog/policy from the **same on-disk paths**
//! the broker was started with (never from the wire), runs the **full**
//! startup/`check` validation on the candidate, enforces that only reloadable
//! dimensions changed, and (only on success) atomically swaps in a new
//! [`Generation`] with a bumped id. On any failure it does **not** swap: the
//! previous generation keeps serving and the rejection is returned to the caller
//! (the SIGHUP handler audits it). It never panics or exits.
//!
//! # Reloadable vs restart-only
//!
//! The reloadable surface is the **content** the [`Pdp`](crate::catalog::Pdp) and
//! the audit trail consume: the entire policy (rules / roles / name + membership
//! tables) and the per-key *authorization* attributes: `writable`, `labels`,
//! `description`, `missing`. The **routing shape** is restart-only:
//! the [`BackendManager`](crate::manager::BackendManager) and the live backend
//! instances were built from the sealed bundle at startup, so adding/removing a
//! backend, or changing any key's `class`/`backend`/`path`/`engine`/`key_type`/
//! `public_path`, needs a re-unlock and is rejected here (the Nix module routes
//! such edits to `ExecStart`, i.e. a restart). [`routing_shape`] captures exactly
//! the dimensions baked into the manager; a candidate whose shape differs from the
//! running generation is rejected with [`ReloadError::RoutingShapeChanged`].
//!
//! # Non-mutating
//!
//! Reload is **non-mutating**: it validates (and the loader's guardrails run) but
//! it performs **no** backend I/O and **no** CSPRNG side effects: it never
//! reconciles or generates missing material on the signal path. A candidate that
//! adds a `missing:error` key whose material is absent is *accepted* (its routing
//! shape is unchanged by construction, since a new key would change the shape and
//! be rejected anyway); a `missing:error` key that already exists in both
//! generations simply keeps failing closed at use if its material is absent. The
//! routing-shape guard means a reload can only ever change a *pre-existing* key's
//! authorization attributes, never introduce a new key/backend that would demand
//! fresh material, so there is no missing-material decision to make on the signal
//! path beyond what startup reconcile already settled.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

use crate::catalog::loader::LoadError;
use crate::catalog::schema::{BackendKind, Capability, Class, Engine, KeyAlgorithm};
use crate::catalog::{Catalog, Config, ResolvedPolicy};
use crate::configuration::{ConfigOverride, CorpusDocuments, load_bootstrap, load_documents};
use crate::state::{BrokerState, Generation};

/// The on-disk inputs a [`reload_generation`] re-reads.
///
/// Stored on [`BrokerState`] at construction so the reload engine reads from the
/// **same** paths startup used, never from anywhere else, never from the wire.
#[derive(Debug, Clone)]
pub struct ReloadInputs {
    /// Path to the selected schema-3 bootstrap.
    pub config_path: std::path::PathBuf,
    /// Immutable startup overrides reapplied to every candidate.
    pub overrides: Vec<ConfigOverride>,
}

/// The result of a **successful** [`reload_generation`].
///
/// Carries the old → new generation ids plus summary counts so the SIGHUP handler
/// (and the future gRPC admin-reload, `basil-atq`) can log/return what changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReloadOutcome {
    /// The generation id that was serving before the swap.
    pub previous_generation: u64,
    /// The generation id now serving after the atomic swap.
    pub new_generation: u64,
    /// Number of catalog keys in the new generation.
    pub key_count: usize,
    /// Number of resolved policy allow-grants in the new generation.
    pub grant_count: usize,
}

/// Why a [`reload_generation`] was **rejected**. On any of these the previous
/// generation keeps serving (fail closed); none of them swap.
#[derive(Debug, thiserror::Error)]
pub enum ReloadError {
    /// A corpus input could not be fingerprinted during candidate assembly.
    #[error("reading configuration input metadata from {path}: {source}")]
    ReadInput {
        /// The input path that failed.
        path: String,
        /// The underlying IO error.
        source: std::io::Error,
    },

    /// The catalog or policy file changed while reload was reading the pair.
    /// The previous generation keeps serving so the broker never installs a
    /// catalog/policy pair assembled across an observed writer race.
    #[error("catalog/policy reload input changed while reading {path}; retry reload")]
    TornSnapshot {
        /// The path whose fingerprint changed during candidate assembly.
        path: String,
    },

    /// The candidate catalog/policy failed the full startup/`check` validation
    /// (`load`, including the JWT-SVID issuer-alg and `publicPath` guardrails).
    #[error("validating reloaded catalog/policy: {0}")]
    Validate(#[from] LoadError),

    /// The bootstrap or a non-catalog corpus document failed validation.
    #[error("validating reloaded configuration corpus: {0}")]
    Configuration(#[from] crate::configuration::ConfigurationError),

    /// The candidate changed a **restart-only** routing dimension (a backend was
    /// added/removed/repathed, or a key's `backend`/`path`/`engine`/`key_type`/
    /// `public_path` changed). Such an edit needs a re-unlock and is rejected on
    /// the reload path; apply it via a restart instead.
    #[error("reload touches a restart-only routing dimension: {0}")]
    RoutingShapeChanged(String),

    /// The broker was constructed without [`ReloadInputs`] (no configured
    /// catalog/policy paths), so it has nothing to re-read. A reload is a no-op
    /// fail-closed rather than reading from an unknown source.
    #[error("reload unavailable: broker has no configured catalog/policy paths")]
    NoInputs,
}

impl ReloadError {
    /// A short, stable, non-secret reason token for the audit trail.
    #[must_use]
    pub const fn audit_reason(&self) -> &'static str {
        match self {
            Self::ReadInput { .. } => "configuration_read_failed",
            Self::TornSnapshot { .. } => "inputs_changed_during_read",
            Self::Validate(_) | Self::Configuration(_) => "validation_failed",
            Self::RoutingShapeChanged(_) => "routing_shape_changed",
            Self::NoInputs => "no_reload_inputs",
        }
    }
}

/// The restart-only **routing shape** of one backend: everything the
/// [`BackendManager`](crate::manager::BackendManager) and capability check bake in
/// at startup. Two generations may only differ in reloadable content if their
/// routing shapes are equal.
#[derive(Debug, PartialEq, Eq)]
struct BackendShape {
    kind: BackendKind,
    addr: String,
    engines: Vec<Engine>,
    capabilities: Vec<Capability>,
    requires: Vec<Capability>,
}

/// The restart-only routing shape of one key: the dimensions that select a
/// backend instance, a backend-native locator, and the materialize footprint.
/// `writable` is not here (it is reloadable), but `class` selects the op surface,
/// engine inference, and the materialize arm, so it is restart-only shape.
#[derive(Debug, PartialEq, Eq)]
struct KeyShape {
    class: Class,
    key_type: Option<KeyAlgorithm>,
    backend: String,
    engine: Option<Engine>,
    path: String,
    public_path: Option<String>,
}

/// Project a catalog onto its restart-only routing shape: the backend set and,
/// per key, the routing/materialize dimensions. Equal shapes ⇒ the live manager
/// and backends still route the new generation correctly; a differing shape needs
/// a restart.
fn routing_shape(
    catalog: &Catalog,
) -> (BTreeMap<String, BackendShape>, BTreeMap<String, KeyShape>) {
    let backends = catalog
        .backends
        .iter()
        .map(|(name, b)| {
            (
                name.clone(),
                BackendShape {
                    kind: b.kind,
                    addr: b.addr.clone(),
                    engines: b.engines.clone(),
                    capabilities: b.capabilities.clone(),
                    requires: b.requires.clone(),
                },
            )
        })
        .collect();
    let keys = catalog
        .keys
        .iter()
        .map(|(name, k)| {
            (
                name.clone(),
                KeyShape {
                    class: k.class,
                    key_type: k.key_type,
                    backend: k.backend.clone(),
                    engine: k.engine,
                    path: k.path.clone(),
                    public_path: k.public_path.clone(),
                },
            )
        })
        .collect();
    (backends, keys)
}

/// Reject the candidate if it touches any restart-only routing dimension.
///
/// Compares the candidate's routing shape against the **currently serving**
/// generation's catalog. A backend added/removed/repathed, or any key's
/// `class`/`backend`/`path`/`engine`/`key_type`/`public_path` changed (or a key
/// added/removed, which changes the key set, hence the shape), is restart-only.
fn ensure_reloadable(current: &Catalog, candidate: &Catalog) -> Result<(), ReloadError> {
    let (cur_backends, cur_keys) = routing_shape(current);
    let (new_backends, new_keys) = routing_shape(candidate);
    if cur_backends != new_backends {
        return Err(ReloadError::RoutingShapeChanged(
            "the backend set or a backend's kind/addr/engines/capabilities/requires changed"
                .to_string(),
        ));
    }
    if cur_keys != new_keys {
        return Err(ReloadError::RoutingShapeChanged(
            "a key was added/removed or a key's class/backend/path/engine/key_type/public_path changed"
                .to_string(),
        ));
    }
    Ok(())
}

fn spiffe_bundle_publishers(catalog: &Catalog) -> BTreeMap<String, (String, String)> {
    catalog
        .keys
        .iter()
        .filter_map(|(name, entry)| {
            let svid_kind = entry.labels.get("svid_kind")?;
            if !matches!(svid_kind, "jwt" | "x509") {
                return None;
            }
            let trust_domain = entry.labels.get("trust_domain")?;
            Some((
                name.clone(),
                (svid_kind.to_string(), trust_domain.to_string()),
            ))
        })
        .collect()
}

fn bundle_changed_trust_domains(current: &Catalog, candidate: &Catalog) -> Vec<String> {
    let current_publishers = spiffe_bundle_publishers(current);
    let candidate_publishers = spiffe_bundle_publishers(candidate);
    if current_publishers == candidate_publishers {
        return Vec::new();
    }

    current_publishers
        .values()
        .chain(candidate_publishers.values())
        .map(|(_, trust_domain)| trust_domain.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileFingerprint {
    dev: u64,
    ino: u64,
    len: u64,
    mtime_sec: i64,
    mtime_nsec: i64,
    ctime_sec: i64,
    ctime_nsec: i64,
}

#[cfg(unix)]
fn file_fingerprint(path: &Path) -> std::io::Result<FileFingerprint> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::metadata(path)?;
    Ok(FileFingerprint {
        dev: metadata.dev(),
        ino: metadata.ino(),
        len: metadata.len(),
        mtime_sec: metadata.mtime(),
        mtime_nsec: metadata.mtime_nsec(),
        ctime_sec: metadata.ctime(),
        ctime_nsec: metadata.ctime_nsec(),
    })
}

#[cfg(not(unix))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct FileFingerprint {
    len: u64,
    modified: Option<std::time::SystemTime>,
}

#[cfg(not(unix))]
fn file_fingerprint(path: &Path) -> std::io::Result<FileFingerprint> {
    let metadata = std::fs::metadata(path)?;
    Ok(FileFingerprint {
        len: metadata.len(),
        modified: metadata.modified().ok(),
    })
}

fn read_reload_inputs_with_observer(
    inputs: &ReloadInputs,
    observer: impl FnOnce(),
) -> Result<CorpusDocuments, ReloadError> {
    let config_before = fingerprint(&inputs.config_path)?;
    let bootstrap = load_bootstrap(Some(&inputs.config_path), &inputs.overrides)?;
    let mut paths = vec![
        bootstrap.sources.catalog.clone(),
        bootstrap.sources.policy.clone(),
    ];
    paths.extend(bootstrap.sources.compose.values().cloned());
    let before = paths
        .iter()
        .map(|path| fingerprint(path).map(|value| (path.clone(), value)))
        .collect::<Result<Vec<_>, _>>()?;

    observer();
    if config_before != fingerprint(&inputs.config_path)? {
        return Err(ReloadError::TornSnapshot {
            path: inputs.config_path.display().to_string(),
        });
    }
    for (path, expected) in &before {
        if expected != &fingerprint(path)? {
            return Err(ReloadError::TornSnapshot {
                path: path.display().to_string(),
            });
        }
    }
    let documents = load_documents(&bootstrap.sources).map_err(|error| match error {
        crate::configuration::ConfigurationError::Catalog(error) => ReloadError::Validate(error),
        other => ReloadError::Configuration(other),
    })?;

    if config_before != fingerprint(&inputs.config_path)? {
        return Err(ReloadError::TornSnapshot {
            path: inputs.config_path.display().to_string(),
        });
    }
    for (path, expected) in before {
        if expected != fingerprint(&path)? {
            return Err(ReloadError::TornSnapshot {
                path: path.display().to_string(),
            });
        }
    }
    Ok(documents)
}

fn fingerprint(path: &Path) -> Result<FileFingerprint, ReloadError> {
    file_fingerprint(path).map_err(|source| ReloadError::ReadInput {
        path: path.display().to_string(),
        source,
    })
}

fn read_reload_inputs(inputs: &ReloadInputs) -> Result<CorpusDocuments, ReloadError> {
    read_reload_inputs_with_observer(inputs, || {})
}

/// The fully-validated candidate generation produced by [`validate_candidate`]:
/// the loaded surface (ready to install) plus the [`ReloadOutcome`] the swap would
/// report. The dry-run path discards the surface and keeps only the outcome; the
/// real reload installs the surface.
struct ValidatedCandidate {
    catalog: Catalog,
    policy: ResolvedPolicy,
    config: Config,
    outcome: ReloadOutcome,
    bundle_changed_trust_domains: Vec<String>,
}

/// Re-read the configured catalog/policy, run the **full** startup/`check`
/// validation, and enforce that only reloadable dimensions changed, all **without
/// swapping**. This is the single validation path shared by the real reload and
/// the `--check` dry-run, so a dry-run can never diverge from what a real reload
/// would accept (the same anti-divergence discipline the PDP's `decide`/`explain`
/// share).
///
/// It is non-mutating (no backend I/O, no CSPRNG, no generation swap) and never
/// panics. The returned [`ReloadOutcome`] reports the *would-be* generation ids
/// and counts; it is identical to what [`reload_generation`] reports after a
/// successful swap.
///
/// # Errors
///
/// Returns a [`ReloadError`] when the broker has no configured paths
/// ([`ReloadError::NoInputs`]), a file cannot be re-read, the candidate fails
/// validation ([`ReloadError::Validate`]), or it changes a restart-only routing
/// dimension ([`ReloadError::RoutingShapeChanged`]).
fn validate_candidate(state: &BrokerState) -> Result<ValidatedCandidate, ReloadError> {
    let inputs = state.reload_inputs().ok_or(ReloadError::NoInputs)?;
    let CorpusDocuments {
        catalog,
        policy,
        policy_config: config,
        warnings,
        compose: _,
    } = read_reload_inputs(inputs)?;
    for w in &warnings {
        tracing::warn!(warning = %w, "reload: catalog/policy load warning");
    }

    // Pin the currently-serving generation to (a) compare routing shape against,
    // and (b) read the previous id to bump from: one coherent snapshot.
    let current = state.load_generation();
    ensure_reloadable(current.catalog(), &catalog)?;

    let previous_generation = current.id();
    let new_generation = previous_generation.saturating_add(1);
    let bundle_changed_trust_domains = bundle_changed_trust_domains(current.catalog(), &catalog);
    let outcome = ReloadOutcome {
        previous_generation,
        new_generation,
        key_count: catalog.keys.len(),
        grant_count: policy.grant_count(),
    };

    Ok(ValidatedCandidate {
        catalog,
        policy,
        config,
        outcome,
        bundle_changed_trust_domains,
    })
}

/// Validate the candidate catalog/policy **without** swapping (the `--check`
/// dry-run, basil-atq).
///
/// Runs the *identical* validation [`reload_generation`] runs (re-read from disk,
/// full `load()` validation, and the restart-only routing-shape guard) but
/// performs **no** generation swap: the currently-serving generation is untouched.
/// The returned [`ReloadOutcome`] reports what a real reload *would* apply (the
/// would-be new generation id + counts).
///
/// # Errors
///
/// The same [`ReloadError`] set as [`reload_generation`]; on any error the running
/// generation keeps serving (it was never going to change here regardless).
pub fn check_reload(state: &BrokerState) -> Result<ReloadOutcome, ReloadError> {
    validate_candidate(state).map(|c| c.outcome)
}

/// Re-read the configured catalog/policy, validate the candidate, enforce that
/// only reloadable dimensions changed, and on success atomically swap in a new
/// [`Generation`] with a bumped id.
///
/// This is the **one** fail-closed reload code path, shared by the SIGHUP handler
/// and the gRPC admin-reload follow-on (`basil-atq`). It is non-mutating up to the
/// final swap (no backend I/O, no CSPRNG) and never panics. The validation it runs
/// is exactly [`check_reload`]'s (they share [`validate_candidate`]), so a
/// dry-run that passes guarantees the real reload's validation passes too.
///
/// # Errors
///
/// Returns a [`ReloadError`] (without swapping, so the previous generation keeps
/// serving) when the broker has no configured paths ([`ReloadError::NoInputs`]),
/// a file cannot be re-read, the candidate fails validation
/// ([`ReloadError::Validate`]), or the candidate changes a restart-only routing
/// dimension ([`ReloadError::RoutingShapeChanged`]).
pub fn reload_generation(state: &BrokerState) -> Result<ReloadOutcome, ReloadError> {
    // Serialize the whole validate→swap sequence: SIGHUP and the admin RPC can
    // trigger concurrently, and without this two reloads could both pin
    // generation N, both stamp N+1, and let the staler candidate silently
    // overwrite the newer one. A poisoned lock is recovered: it holds no data,
    // it only orders the triggers.
    let _reload_guard = state
        .reload_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let candidate = validate_candidate(state)?;
    let ValidatedCandidate {
        catalog,
        policy,
        config,
        outcome,
        bundle_changed_trust_domains,
    } = candidate;

    let next = Generation::new(outcome.new_generation, Arc::new(catalog), policy, config);
    state.swap_generation(Arc::new(next));
    for trust_domain in bundle_changed_trust_domains {
        state.events().bundle_changed(trust_domain);
    }

    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use async_trait::async_trait;
    use basil_proto::KeyType;

    use super::{
        ReloadError, ReloadInputs, check_reload, read_reload_inputs_with_observer,
        reload_generation,
    };
    use crate::backend::{Backend, BackendError, NewKey};
    use crate::catalog::load;
    use crate::manager::BackendManager;
    use crate::state::{BrokerState, INITIAL_GENERATION_ID};

    /// A no-op backend: reload is non-mutating and never calls the backend, so the
    /// required trait methods all fail closed (the manager only needs them present
    /// to satisfy `Backend`).
    struct NoopBackend;

    #[async_trait]
    impl Backend for NoopBackend {
        fn kind(&self) -> &'static str {
            "noop"
        }
        async fn new_key(&self, _key_type: KeyType) -> Result<NewKey, BackendError> {
            Err(BackendError::Unsupported("new_key"))
        }
        async fn public_key(&self, _key_id: &str) -> Result<Vec<u8>, BackendError> {
            Err(BackendError::Unsupported("public_key"))
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

    /// A one-key, one-backend catalog. `writable` is reloadable; the routing shape
    /// (`backend`/`path`/`engine`/`key_type`) is fixed across the variants below.
    fn catalog_json(writable: bool) -> String {
        format!(
            r#"{{
              "schema": "catalog",
              "backends": {{ "bao": {{ "kind": "vault", "addr": "http://127.0.0.1:8200" }} }},
              "keys": {{
                "web.signer": {{
                  "class": "asymmetric", "keyType": "ed25519", "backend": "bao",
                  "path": "signer", "writable": {writable}, "description": "a signer"
                }}
              }}
            }}"#
        )
    }

    /// A catalog whose key routes to a DIFFERENT path: a restart-only change.
    fn catalog_json_repathed() -> String {
        r#"{
          "schema": "catalog",
          "backends": { "bao": { "kind": "vault", "addr": "http://127.0.0.1:8200" } },
          "keys": {
            "web.signer": {
              "class": "asymmetric", "keyType": "ed25519", "backend": "bao",
              "path": "signer-v2", "writable": true, "description": "a signer"
            }
          }
        }"#
        .to_string()
    }

    fn policy_json(grant_sign: bool) -> String {
        let rules = if grant_sign {
            r#"[ { "id": "r1", "subjects": ["svc.web"], "action": ["op:sign"], "target": ["web.signer"] } ]"#
        } else {
            "[]"
        };
        format!(
            r#"{{
              "schema": "policy",
              "subjects": {{ "svc.web": {{ "allOf": [ {{ "kind": "unix", "uid": 1000 }} ] }} }},
              "roles": {{}},
              "rules": {rules},
              "config": {{}}
            }}"#
        )
    }

    /// Build a [`BrokerState`] from catalog/policy JSON written to temp files, with
    /// the reload inputs pointed at those files so the engine re-reads them.
    fn state_with_files(catalog: &str, policy: &str) -> (Arc<BrokerState>, ReloadInputs) {
        let dir = std::env::temp_dir().join(format!(
            "basil-reload-test-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let catalog_path = dir.join("catalog.json");
        let policy_path = dir.join("policy.json");
        let config_path = dir.join("config.toml");
        std::fs::write(&catalog_path, catalog).expect("write catalog");
        std::fs::write(&policy_path, policy).expect("write policy");
        std::fs::write(
            &config_path,
            "schema = \"agent\"\nschemaVersion = 3\n[config]\ncatalog = \"catalog.json\"\npolicy = \"policy.json\"\nbundle = \"bundle.age\"\n",
        )
        .expect("write config");

        let (cat, pol, cfg, warnings) = load(catalog, policy).expect("fixture loads");
        assert!(warnings.is_empty());
        let mut backends: BTreeMap<String, Box<dyn Backend>> = BTreeMap::new();
        backends.insert("bao".into(), Box::new(NoopBackend));
        let manager = BackendManager::new(cat.clone(), backends).expect("manager builds");
        let inputs = ReloadInputs {
            config_path,
            overrides: Vec::new(),
        };
        let state = Arc::new(
            BrokerState::new(cat, pol, cfg, manager, "noop").with_reload_inputs(inputs.clone()),
        );
        (state, inputs)
    }

    fn write_files(inputs: &ReloadInputs, catalog: &str, policy: &str) {
        let dir = inputs.config_path.parent().expect("config parent");
        std::fs::write(dir.join("catalog.json"), catalog).expect("rewrite catalog");
        std::fs::write(dir.join("policy.json"), policy).expect("rewrite policy");
    }

    /// A valid reload (a reloadable-dimension edit) swaps to a new generation id,
    /// and a guard pinned BEFORE the swap still sees the old generation while a
    /// fresh load sees the new one: the reload-between-two-reads coherence the
    /// pinning plumbing (y3e.1) could not exercise without a trigger.
    #[test]
    fn valid_reload_swaps_generation_and_stays_coherent() {
        let (state, inputs) = state_with_files(&catalog_json(false), &policy_json(false));
        assert_eq!(state.active_generation_id(), INITIAL_GENERATION_ID);

        // An in-flight op pins the current generation BEFORE the reload.
        let pinned = state.load_generation();
        assert_eq!(pinned.id(), INITIAL_GENERATION_ID);

        // Edit a reloadable dimension (flip writable + add a sign grant).
        write_files(&inputs, &catalog_json(true), &policy_json(true));
        let outcome = reload_generation(&state).expect("valid reload applies");

        assert_eq!(outcome.previous_generation, INITIAL_GENERATION_ID);
        assert_eq!(outcome.new_generation, INITIAL_GENERATION_ID + 1);
        assert_eq!(outcome.key_count, 1);
        assert_eq!(outcome.grant_count, 1);

        // The pre-swap pin still sees the OLD generation (coherent in-flight read);
        // a fresh load sees the NEW one.
        assert_eq!(pinned.id(), INITIAL_GENERATION_ID);
        assert_eq!(state.active_generation_id(), INITIAL_GENERATION_ID + 1);
    }

    /// An invalid candidate (malformed policy) is REJECTED, the previous
    /// generation keeps serving, and the engine never panics.
    #[test]
    fn invalid_policy_is_rejected_and_previous_generation_keeps_serving() {
        let (state, inputs) = state_with_files(&catalog_json(true), &policy_json(true));

        // Corrupt the policy: reference a role that is not declared (§5 hard error
        // UnknownRole), the catalog is unchanged, so this isolates a *validation*
        // rejection from the routing-shape guard.
        write_files(
            &inputs,
            &catalog_json(true),
            r#"{ "schema": "policy", "subjects": { "svc.web": { "allOf": [ { "kind": "unix", "uid": 1000 } ] } }, "roles": {}, "rules": [ { "id": "bad", "subjects": ["svc.web"], "action": ["role:nonexistent"], "target": ["web.signer"] } ], "config": {} }"#,
        );

        let err = reload_generation(&state).expect_err("malformed policy rejected");
        assert!(matches!(err, ReloadError::Validate(_)));
        assert_eq!(err.audit_reason(), "validation_failed");
        // Previous generation untouched.
        assert_eq!(state.active_generation_id(), INITIAL_GENERATION_ID);
    }

    #[test]
    fn reload_input_change_during_read_is_rejected() {
        let (state, inputs) = state_with_files(&catalog_json(true), &policy_json(true));

        let err = read_reload_inputs_with_observer(&inputs, || {
            std::fs::write(
                inputs
                    .config_path
                    .parent()
                    .expect("config parent")
                    .join("policy.json"),
                policy_json(true).replace("\"rules\"", "\"rules_changed\""),
            )
            .expect("race policy rewrite");
        })
        .expect_err("changed policy fingerprint rejects torn read");

        assert!(matches!(err, ReloadError::TornSnapshot { .. }));
        assert_eq!(err.audit_reason(), "inputs_changed_during_read");
        assert_eq!(
            state.active_generation_id(),
            INITIAL_GENERATION_ID,
            "helper rejection leaves the serving generation untouched"
        );
    }

    /// A non-profile JWT-SVID issuer candidate is rejected: the loader's fail-closed
    /// issuer-alg guardrail runs on the reload path (validation), so the broker
    /// never swaps in a generation that would mint SPIFFE-rejected tokens.
    #[test]
    fn non_profile_jwt_svid_issuer_is_rejected_on_reload() {
        // Base: an RSA JWT-SVID issuer (loads at startup).
        let base_catalog = r#"{
          "schema": "catalog",
          "backends": { "bao": { "kind": "vault", "addr": "http://127.0.0.1:8200" } },
          "keys": {
            "spiffe.jwt": {
              "class": "asymmetric", "keyType": "rsa-2048", "backend": "bao", "path": "jwt",
              "labels": ["svid_kind=jwt", "trust_domain=example.org"],
              "writable": false, "description": "jwt issuer"
            }
          }
        }"#;
        let (state, inputs) = state_with_files(base_catalog, &policy_json(false));

        // Candidate flips the issuer to ed25519 (EdDSA): a non-profile alg.
        let bad_catalog = base_catalog.replace("rsa-2048", "ed25519");
        write_files(&inputs, &bad_catalog, &policy_json(false));

        let err = reload_generation(&state).expect_err("non-profile jwt issuer rejected");
        // It is caught (either by the alg guardrail in validation, or, since the
        // key_type is part of the routing shape, by the restart-only guard);
        // either way the reload fails closed and the prior generation serves on.
        assert!(matches!(
            err,
            ReloadError::Validate(_) | ReloadError::RoutingShapeChanged(_)
        ));
        assert_eq!(state.active_generation_id(), INITIAL_GENERATION_ID);
    }

    /// A restart-only edit (a key repathed to a different backend locator) is
    /// rejected: the live manager/backends cannot re-route without a restart.
    #[test]
    fn restart_only_routing_change_is_rejected() {
        let (state, inputs) = state_with_files(&catalog_json(true), &policy_json(true));
        write_files(&inputs, &catalog_json_repathed(), &policy_json(true));

        let err = reload_generation(&state).expect_err("repath rejected");
        assert!(matches!(err, ReloadError::RoutingShapeChanged(_)));
        assert_eq!(err.audit_reason(), "routing_shape_changed");
        assert_eq!(state.active_generation_id(), INITIAL_GENERATION_ID);
    }

    /// `check_reload` (the `--check` dry-run) validates the candidate and reports
    /// the would-be outcome WITHOUT swapping: the serving generation id is
    /// unchanged, and a subsequent real reload applies the very same outcome.
    #[test]
    fn check_reload_validates_without_swapping() {
        let (state, inputs) = state_with_files(&catalog_json(false), &policy_json(false));
        assert_eq!(state.active_generation_id(), INITIAL_GENERATION_ID);

        write_files(&inputs, &catalog_json(true), &policy_json(true));
        let dry = check_reload(&state).expect("dry-run validates");
        assert_eq!(dry.previous_generation, INITIAL_GENERATION_ID);
        assert_eq!(dry.new_generation, INITIAL_GENERATION_ID + 1);
        assert_eq!(dry.key_count, 1);
        assert_eq!(dry.grant_count, 1);
        // The serving generation is UNCHANGED by the dry-run.
        assert_eq!(state.active_generation_id(), INITIAL_GENERATION_ID);

        // A real reload now applies exactly what the dry-run previewed.
        let applied = reload_generation(&state).expect("real reload applies");
        assert_eq!(applied, dry);
        assert_eq!(state.active_generation_id(), INITIAL_GENERATION_ID + 1);
    }

    /// A rejected candidate is rejected identically by the dry-run and the real
    /// reload, and neither swaps: the dry-run never diverges from enforcement.
    #[test]
    fn check_reload_rejects_what_real_reload_rejects() {
        let (state, inputs) = state_with_files(&catalog_json(true), &policy_json(true));
        write_files(&inputs, &catalog_json_repathed(), &policy_json(true));

        let dry = check_reload(&state).expect_err("dry-run rejects repath");
        assert!(matches!(dry, ReloadError::RoutingShapeChanged(_)));
        assert_eq!(state.active_generation_id(), INITIAL_GENERATION_ID);

        let real = reload_generation(&state).expect_err("real reload rejects repath");
        assert!(matches!(real, ReloadError::RoutingShapeChanged(_)));
        assert_eq!(state.active_generation_id(), INITIAL_GENERATION_ID);
    }

    /// Concurrent reload triggers (SIGHUP + admin RPC in production; two threads
    /// here) are serialized by the reload lock: both apply, generation ids stay
    /// monotonic with no duplicate stamp, and no candidate is lost.
    #[test]
    fn concurrent_reloads_are_serialized_with_monotonic_generations() {
        let (state, inputs) = state_with_files(&catalog_json(false), &policy_json(false));
        write_files(&inputs, &catalog_json(true), &policy_json(true));

        let outcomes = std::thread::scope(|scope| {
            // Spawn both BEFORE joining either, so the two reloads genuinely
            // overlap (a lazy spawn-then-join iterator would serialize them).
            let first = scope.spawn(|| reload_generation(&state));
            let second = scope.spawn(|| reload_generation(&state));
            [first, second].map(|h| h.join().expect("reload thread panicked"))
        });

        let mut transitions: Vec<(u64, u64)> = outcomes
            .into_iter()
            .map(|o| {
                let o = o.expect("both concurrent reloads apply");
                (o.previous_generation, o.new_generation)
            })
            .collect();
        transitions.sort_unstable();
        // Strictly ordered handoff: N→N+1 then N+1→N+2, never two identical
        // N→N+1 stamps (the lost-update signature).
        assert_eq!(
            transitions,
            vec![
                (INITIAL_GENERATION_ID, INITIAL_GENERATION_ID + 1),
                (INITIAL_GENERATION_ID + 1, INITIAL_GENERATION_ID + 2),
            ]
        );
        assert_eq!(state.active_generation_id(), INITIAL_GENERATION_ID + 2);
    }

    /// A broker with no configured paths fails the reload closed (no-op), never
    /// reading catalog/policy from an unconfigured source.
    #[test]
    fn reload_without_inputs_fails_closed() {
        let (cat, pol, cfg, _) =
            load(&catalog_json(true), &policy_json(true)).expect("fixture loads");
        let mut backends: BTreeMap<String, Box<dyn Backend>> = BTreeMap::new();
        backends.insert("bao".into(), Box::new(NoopBackend));
        let manager = BackendManager::new(cat.clone(), backends).expect("manager builds");
        let state = BrokerState::new(cat, pol, cfg, manager, "noop");

        let err = reload_generation(&state).expect_err("no inputs → fail closed");
        assert!(matches!(err, ReloadError::NoInputs));
        assert_eq!(state.active_generation_id(), INITIAL_GENERATION_ID);
    }
}
