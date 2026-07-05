// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Multi-backend manager + per-key routing (design §2.2, §17.7).
//!
//! The [`BackendManager`] is the layer between the gRPC service adapters and the
//! [`Backend`] implementations.
//! Given a **dotted catalog name** (the wire `key_id`), it resolves the key's
//! [`KeyEntry`] in the catalog routing table, picks the named [`Backend`]
//! instance, and dispatches the op against the key's backend-native `path`.
//!
//! A down backend fails only the ops routed to it. Each key's resolution is
//! independent, and a backend error is surfaced as [`ManagerError::Backend`]
//! without affecting any other key.
//!
//! # Op surface
//!
//! The manager routes `new_key`, `sign`, `verify`, `get_public_key` (with real
//! algorithm + version metadata), `import` (BYOK), `encrypt`/`decrypt`, `rotate`,
//! `get`/`set` (KV-v2 value read/write), and `list` (value-free key metadata),
//! after checking the op is valid for the key's [`Class`] (e.g. `sign` only on
//! `asymmetric`, `get` only on `value`/`public`, `set` only on `value`).

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use age::secrecy::ExposeSecret as _;
use basil_cose::Recipient as _;
use basil_proto::{
    AeadAlgorithm, CatalogEntry as WireCatalogEntry, CatalogKind, CiphertextEnvelope, KeyMaterial,
    KeyType,
};
use rand::RngCore;
use uuid::Uuid;

use zeroize::Zeroizing;

use crate::backend::{
    Backend, BackendError, KvValue, NativeAlgorithm, NewKey, PublicKey, SignOptions,
    X509CertRequest, X509Svid,
};
use crate::catalog::{BackendRef, Catalog, Class, Engine, GenerateSpec, KeyAlgorithm, KeyEntry};
use crate::core::crypto_provider::LocalSoftwareProvider;
use crate::core::crypto_provider::{
    BackendCryptoProvider, CryptoProvider, CryptoProviderId, CustodyMode,
    Envelope as ProviderEnvelope, EnvelopeAlgorithm as ProviderEnvelopeAlgorithm,
    GenerateKey as ProviderGenerateKey, GenerateSealingKey as ProviderGenerateSealingKey,
    KemAlgorithm as ProviderKemAlgorithm, ProviderError, ProviderMetadata, ProviderPolicy,
    SignRequest, SignatureAlgorithm, UnwrapEnvelopeRequest as ProviderUnwrapEnvelopeRequest,
    VerifyRequest, WrapEnvelopeRequest as ProviderWrapEnvelopeRequest, ml_dsa_signature_algorithm,
    select_provider,
};
use crate::ed25519_sign::{self, SignError};
use crate::state::BrokerLimits;
use crate::x25519_seal::{self, SealError, SealedEnvelope};

/// An error from resolving or routing a catalog key. Fails closed; never panics.
#[derive(Debug, thiserror::Error)]
pub enum ManagerError {
    /// The dotted name is not in the catalog's key inventory.
    #[error("unknown key: {0}")]
    UnknownKey(String),

    /// A key entry names a backend instance that was not provided at construction.
    /// Caught at [`BackendManager::new`]; never surfaces at request time.
    #[error("key `{key}` references unknown backend `{backend}`")]
    UnknownBackend {
        /// The offending key name.
        key: String,
        /// The backend name the key references.
        backend: String,
    },

    /// The requested op is not valid for the resolved key's [`Class`]
    /// (e.g. `sign` on a `value` key).
    #[error("op `{op}` is not valid for key `{key}` (class {class:?})")]
    OpNotValidForClass {
        /// The op that was attempted.
        op: &'static str,
        /// The key it was attempted on.
        key: String,
        /// The key's class.
        class: Class,
    },

    /// The backend's static capability preset does not declare support for this
    /// key type on a mint/import/generate path.
    #[error("backend `{backend}` does not declare support for {op} key type `{key_type}`")]
    UnsupportedKeyType {
        /// Backend catalog name.
        backend: String,
        /// Operation that required native key-type support.
        op: &'static str,
        /// Requested wire key type.
        key_type: KeyType,
    },

    /// The op is recognized but its [`Backend`] method does not exist yet
    /// (a later per-op issue + `Backend`-trait expansion backs it).
    #[error("op `{0}` is recognized but not yet backed by a Backend method")]
    Unsupported(&'static str),

    /// An `encrypt` `algorithm` that does not match the key's catalog `keyType`
    /// (e.g. `chacha20-poly1305` against an `aes-256-gcm` key), or an `encrypt`
    /// on a key whose catalog `keyType` is not an AEAD suite. Maps to the wire
    /// `invalid_request` (§4.2).
    #[error("algorithm `{requested}` does not match key `{key}` (catalog type {actual})")]
    AlgorithmMismatch {
        /// The key whose catalog type was consulted.
        key: String,
        /// The requested AEAD suite.
        requested: AeadAlgorithm,
        /// The key's catalog AEAD type (or a note that it is not symmetric).
        actual: &'static str,
    },

    /// A KEM envelope requests an algorithm that does not match the sealing key's
    /// catalog `keyType`.
    #[error("KEM algorithm `{requested}` does not match key `{key}` (catalog type {actual})")]
    KemAlgorithmMismatch {
        /// The key whose catalog type was consulted.
        key: String,
        /// Requested KEM algorithm token.
        requested: &'static str,
        /// Catalog algorithm token.
        actual: &'static str,
    },

    /// `rotate` on a `value` key that has **no** `generate` recipe: there is no
    /// fresh value to write, so rotation is `invalid_request`: use `set` with
    /// out-of-band material instead (§7 / `vault-a2p`).
    #[error("value key `{0}` has no generate recipe; rotate via `set` instead")]
    ValueRotateNeedsSet(String),

    /// A sealing op (wrap/unwrap/`get_public_key`) failed: a malformed
    /// materialized private key, a malformed envelope, or an AEAD authentication
    /// failure. The open-side failure is opaque (no oracle).
    #[error("sealing op failed: {0}")]
    Sealing(SealingFailure),

    /// The caller holds `op:decrypt` on this sealing key, but the key pins an
    /// allowed COSE unseal context (KDF party identities and/or `external_aad`)
    /// that this envelope is not bound to (`basil-2rqj`). A least-privilege
    /// refusal: the grant authorizes only the pinned contexts, never any envelope
    /// addressed to the key. Fails closed as permission-denied. Carries **no**
    /// secret material: the party identities are cleartext header values and the
    /// `external_aad` is caller-supplied.
    #[error("key `{0}` does not authorize this unseal context")]
    UnsealContextNotPermitted(String),

    /// A value-store (`engine=kv2`) Ed25519 materialize-to-sign op
    /// (`sign`/`verify`/`get_public_key`) failed because the materialized seed or a
    /// verify input was malformed (wrong length). Carries no secret material.
    #[error("materialize-to-sign op failed: {0}")]
    Signing(SigningFailure),

    /// A materialize-to-use key (`sealing` / `asymmetric`+`engine=kv2`) was asked
    /// for its public half but carries no `public_path`. A catalog loaded through
    /// [`crate::catalog::load`] always has one (loader guardrail, basil-o86); this
    /// fails closed when the manager was built from an unvalidated catalog rather
    /// than re-deriving the public from the private (which the op surface forbids).
    #[error("key `{0}` has no public_path; its public half cannot be resolved")]
    MissingPublicPath(String),

    /// A provider-dispatched (ML-DSA software-custody) operation failed: an
    /// unsupported algorithm/provider combination, a policy denial of the
    /// local-software provider, or an opaque software-custody crypto failure.
    /// Carries no secret material.
    #[error("provider error: {0}")]
    Provider(#[from] ProviderError),

    /// The resolved backend returned an error for this op.
    #[error("backend error: {0}")]
    Backend(#[from] BackendError),
}

/// Why a sealing operation failed.
///
/// Maps the crypto-core errors onto the manager surface, distinguishing a
/// configuration/input fault (malformed key or envelope) from an authentication
/// failure on open (which stays opaque, no oracle about *why* it failed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SealingFailure {
    /// The materialized private key or an envelope field was the wrong length, or
    /// key derivation/seal failed on otherwise valid inputs.
    #[error("malformed sealing material or envelope")]
    Malformed,

    /// AEAD authentication failed on unwrap: a wrong key, a tampered envelope, or
    /// a mismatched `aad`. Opaque on purpose.
    #[error("unseal authentication failed")]
    OpenFailed,
}

impl SealingFailure {
    /// Project a crypto-core [`SealError`] onto the coarse manager surface,
    /// collapsing every non-authentication fault to [`SealingFailure::Malformed`]
    /// and the AEAD failure to [`SealingFailure::OpenFailed`].
    const fn from_seal(err: SealError) -> Self {
        match err {
            SealError::OpenFailed => Self::OpenFailed,
            SealError::BadKeyLength { .. }
            | SealError::BadNonceLength { .. }
            | SealError::KdfFailed
            | SealError::SealFailed => Self::Malformed,
        }
    }

    const fn from_cose_open(err: &basil_cose::OpenError) -> Self {
        match err {
            basil_cose::OpenError::OpenFailed => Self::OpenFailed,
            basil_cose::OpenError::Decode(_)
            | basil_cose::OpenError::RecipientKeyMismatch
            | basil_cose::OpenError::PartyMismatch
            | basil_cose::OpenError::Provider { .. } => Self::Malformed,
        }
    }
}

const fn nats_curve_error(err: &basil_nats::Error) -> ManagerError {
    let failure = match err {
        basil_nats::Error::XKeyOpenFailed => SealingFailure::OpenFailed,
        basil_nats::Error::BadPublicKeyLen(_)
        | basil_nats::Error::UnsupportedPrefix(_)
        | basil_nats::Error::UnexpectedPrefix { .. }
        | basil_nats::Error::UnexpectedXKeyPrefix(_)
        | basil_nats::Error::BadXKeyVersion
        | basil_nats::Error::BadXKeyCiphertextLen(_)
        | basil_nats::Error::XKeySealFailed
        | basil_nats::Error::Json(_)
        | basil_nats::Error::InvalidClaims(_)
        | basil_nats::Error::MalformedJwt(_)
        | basil_nats::Error::BadSignatureLen(_) => SealingFailure::Malformed,
    };
    ManagerError::Sealing(failure)
}

/// Why a value-store Ed25519 materialize-to-sign op failed.
///
/// The only failure mode is a length/format fault on the materialized seed (a
/// misprovisioned KV value) or on a verify input (`public`/`signature` length).
/// Carries **no** secret material, never a byte of the seed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SigningFailure {
    /// The materialized seed was not 32 bytes, or a verify input was the wrong
    /// length. Maps from the crypto-core [`SignError`].
    #[error("malformed signing seed or verify input")]
    Malformed,
}

impl SigningFailure {
    /// Project a crypto-core [`SignError`] onto the manager surface. Every
    /// `SignError` is a fixed-length validation fault, so all collapse to
    /// [`SigningFailure::Malformed`].
    const fn from_sign(err: SignError) -> Self {
        match err {
            SignError::BadSeedLength { .. } | SignError::BadFieldLength { .. } => Self::Malformed,
        }
    }
}

/// Caller-scoped policy inputs the provider-dispatch (ML-DSA) path needs beyond
/// the catalog labels.
///
/// `local_software_allowed` is the resolved `op:use_software_custody` PDP grant
/// (decided in the service layer from the kernel-attested caller). It feeds
/// [`select_provider`](crate::core::crypto_provider::select_provider): the
/// local-software crypto provider is selectable only when policy explicitly
/// grants its use, so a software-custodied key fails closed for a caller that
/// holds only the bare `op:sign` grant.
#[derive(Debug, Clone, Copy)]
pub struct ProviderGate {
    /// Whether policy grants this caller use of the local-software provider.
    pub local_software_allowed: bool,
}

/// What a provider-dispatched operation selected, surfaced so the service layer
/// can record a [`ProviderAuditEvent`](crate::core::crypto_provider::ProviderAuditEvent)
/// carrying the provider and algorithm.
#[derive(Debug, Clone, Copy)]
pub struct ProviderDispatch {
    /// The provider that executed the operation.
    pub provider: CryptoProviderId,
    /// The algorithm token (e.g. `ml-dsa-65`).
    pub algorithm: &'static str,
    /// The key's custody mode.
    pub custody: CustodyMode,
}

/// Admin-observable provider metadata for one catalog key (`basil-wuj.10`).
///
/// The read side of provider/custody observability: which provider policy and
/// custody mode a key is provisioned under, the recorded provider version, and
/// whether its backend now natively supports the key's algorithm (i.e. a
/// backend-native migration is available). It is built from reserved catalog
/// labels plus the cheap capability probe and carries **no key material**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyProviderDescriptor {
    /// The key's declared provider policy (`crypto_provider_policy`, defaulting to
    /// backend-required).
    pub policy: ProviderPolicy,
    /// The provider named by the `crypto_provider` label, if any.
    pub provider: Option<CryptoProviderId>,
    /// The recorded custody mode (`pqc_custody` label), if any: the **active**
    /// custody for a provisioned key.
    pub custody: Option<CustodyMode>,
    /// The `crypto_provider_version` label, if recorded.
    pub version: Option<String>,
    /// Whether the key's backend now reports native support for its algorithm:
    /// `true` means a backend-native migration is available. Always `false` for a
    /// non-PQC key or a backend without native support.
    pub backend_native_available: bool,
}

/// The wire byte fields of an ML-KEM envelope to unwrap.
///
/// Grouped so the provider-dispatched
/// [`BackendManager::provider_unwrap_envelope`] takes one self-describing input
/// instead of three positional slices.
#[derive(Debug, Clone, Copy)]
pub struct MlKemEnvelopeParts<'a> {
    /// ML-KEM ciphertext / encapsulated shared secret.
    pub encapsulated_key: &'a [u8],
    /// Broker/provider-owned AEAD nonce.
    pub nonce: &'a [u8],
    /// AEAD ciphertext including the authentication tag.
    pub ciphertext: &'a [u8],
}

/// A resolved route: the [`Backend`] instance plus the key's catalog metadata.
///
/// Borrows the [`BackendManager`]; the `path` is the backend-native locator the
/// op is dispatched against (transit key name / KV path), and `engine` is the
/// effective engine (inferred from `class` when the catalog omits it, §2.2).
pub struct Routed<'a> {
    /// The backend instance this key routes to.
    pub backend: &'a dyn Backend,
    /// The key's catalog entry (class, `key_type`, path, …).
    pub entry: &'a KeyEntry,
    /// The backend catalog declaration this key routes through.
    pub backend_ref: &'a BackendRef,
    /// The effective sub-engine (catalog value, or inferred from `class`).
    pub engine: Engine,
}

// `Backend` is not `Debug` (it's a trait object), so `Routed` can't derive it.
// We report the backend by its stable `kind()` name instead.
impl std::fmt::Debug for Routed<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Routed")
            .field("backend", &self.backend.kind())
            .field("entry", &self.entry)
            .field("backend_ref", &self.backend_ref)
            .field("engine", &self.engine)
            .finish()
    }
}

impl Routed<'_> {
    /// The backend-native locator (transit key name / KV path) for this key.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.entry.path
    }

    /// The KV path holding this key's **public** half, when it is a
    /// materialize-to-use key whose public is provisioned out of band (basil-o86).
    /// `None` for every key that uses its backend in place.
    #[must_use]
    pub fn public_path(&self) -> Option<&str> {
        self.entry.public_path.as_deref()
    }

    /// The key's class.
    #[must_use]
    pub const fn class(&self) -> Class {
        self.entry.class
    }

    /// The key's crypto algorithm, if any (absent for `value` keys).
    #[must_use]
    pub const fn key_type(&self) -> Option<KeyAlgorithm> {
        self.entry.key_type
    }

    const fn backend_declares_provides(&self) -> bool {
        !(self.backend_ref.engines.is_empty()
            && self.backend_ref.capabilities.is_empty()
            && self.backend_ref.mint_key_types.is_empty())
    }

    pub(crate) fn require_mint_key_type(
        &self,
        op: &'static str,
        key_type: KeyType,
    ) -> Result<(), ManagerError> {
        let algorithm = KeyAlgorithm::from_wire_key_type(key_type);
        if !self.backend_declares_provides() || self.backend_ref.mint_key_types.contains(&algorithm)
        {
            return Ok(());
        }
        Err(ManagerError::UnsupportedKeyType {
            backend: self.entry.backend.clone(),
            op,
            key_type,
        })
    }
}

/// Routes catalog keys to their declared backend instances.
///
/// Constructed from a validated [`Catalog`] plus a map of already-built backend
/// instances keyed by the catalog `backends` names. Constructing the backends
/// from credentials is out of scope (that is `vault-vh1` / the bin); this layer
/// only routes.
pub struct BackendManager {
    catalog: Arc<Catalog>,
    backends: BTreeMap<String, Box<dyn Backend>>,
}

// `Box<dyn Backend>` is not `Debug`; report the routing table by name only.
impl std::fmt::Debug for BackendManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackendManager")
            .field("backends", &self.backends.keys().collect::<Vec<_>>())
            .field("keys", &self.catalog.keys.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl BackendManager {
    /// Build a manager from a catalog + the named, already-constructed backends.
    ///
    /// Validates that every `catalog.keys[*].backend` names a present backend
    /// instance, failing closed with [`ManagerError::UnknownBackend`] otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError::UnknownBackend`] if a key references a backend
    /// name absent from `backends`.
    pub fn new(
        catalog: Catalog,
        backends: BTreeMap<String, Box<dyn Backend>>,
    ) -> Result<Self, ManagerError> {
        for (name, entry) in &catalog.keys {
            if !backends.contains_key(&entry.backend) {
                return Err(ManagerError::UnknownBackend {
                    key: name.clone(),
                    backend: entry.backend.clone(),
                });
            }
        }
        Ok(Self {
            catalog: Arc::new(catalog),
            backends,
        })
    }

    /// Shared immutable catalog this manager routes against.
    #[must_use]
    pub fn catalog(&self) -> Arc<Catalog> {
        Arc::clone(&self.catalog)
    }

    /// Resolve a dotted catalog name to its backend instance + metadata.
    ///
    /// # Errors
    ///
    /// - [`ManagerError::UnknownKey`] if `key_id` is not in the catalog.
    /// - [`ManagerError::UnknownBackend`] if the key's backend is missing
    ///   (impossible after [`BackendManager::new`] validation, but checked so
    ///   resolution never panics on a missing instance).
    pub fn resolve(&self, key_id: &str) -> Result<Routed<'_>, ManagerError> {
        let entry = self
            .catalog
            .keys
            .get(key_id)
            .ok_or_else(|| ManagerError::UnknownKey(key_id.to_string()))?;
        let backend_ref = self.catalog.backends.get(&entry.backend).ok_or_else(|| {
            ManagerError::UnknownBackend {
                key: key_id.to_string(),
                backend: entry.backend.clone(),
            }
        })?;
        let backend =
            self.backends
                .get(&entry.backend)
                .ok_or_else(|| ManagerError::UnknownBackend {
                    key: key_id.to_string(),
                    backend: entry.backend.clone(),
                })?;
        Ok(Routed {
            backend: backend.as_ref(),
            entry,
            backend_ref,
            engine: effective_engine(entry),
        })
    }

    /// Iterate the catalog's `(dotted name, entry)` pairs, in name order.
    ///
    /// Used by startup reconcile (`vault-zrg`) to walk every key and apply its
    /// `missing` policy; kept `pub(crate)` so reconcile lives in its own module
    /// without exposing the routing table publicly.
    pub(crate) fn keys(&self) -> impl Iterator<Item = (&String, &KeyEntry)> {
        self.catalog.keys.iter()
    }

    /// `new_key` creates a key under catalog name `key_id`.
    ///
    /// Valid for crypto keys (`asymmetric` / `symmetric`). This is the request-time
    /// op, where the backend assigns the on-backend id. Startup reconcile
    /// (`crate::reconcile`) instead creates a `generate`-policy key **at its catalog
    /// `path`** via [`Backend::create_named_key`] / [`Backend::create_named_aead`]
    /// so the named material exists before any op resolves to it.
    ///
    /// # Errors
    ///
    /// [`ManagerError::UnknownKey`], [`ManagerError::OpNotValidForClass`] (for a
    /// `value` / `public` key), or [`ManagerError::Backend`].
    pub async fn new_key(&self, key_id: &str, key_type: KeyType) -> Result<NewKey, ManagerError> {
        let routed = self.resolve(key_id)?;
        require_class(
            "new_key",
            key_id,
            routed.class(),
            &[Class::Asymmetric, Class::Symmetric],
        )?;
        if routed.class() == Class::Asymmetric {
            routed.require_mint_key_type("new_key", key_type)?;
        }
        Ok(routed.backend.new_key(key_type).await?)
    }

    /// `sign` signs `message` with `key_id`.
    ///
    /// Valid only for `asymmetric` keys. Two custody arms by effective engine:
    ///
    /// - **transit** (the default): the backend signs *in place*; the private
    ///   never leaves the vault. This is the strong key-never-leaves guarantee.
    /// - **`kv2`** (an explicit `engine=kv2` Ed25519 signing key): the materialize-
    ///   to-sign arm (design §17.7, `vault-iiz`): the 32-byte Ed25519 seed is
    ///   materialized from KV (`Zeroizing` end-to-end), used for exactly one
    ///   signature, then zeroized. The key-never-leaves guarantee holds for transit
    ///   **only**; the `kv2` arm is the sanctioned trade-off for a backend with no
    ///   in-place sign primitive (e.g. a RAM-constrained device that can't run
    ///   transit). The seed is never returned, logged, or audited.
    ///
    /// # Errors
    ///
    /// [`ManagerError::UnknownKey`], [`ManagerError::OpNotValidForClass`],
    /// [`ManagerError::Signing`] (a malformed materialized seed on the `kv2` arm),
    /// or [`ManagerError::Backend`].
    pub async fn sign(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, ManagerError> {
        let routed = self.resolve(key_id)?;
        require_class("sign", key_id, routed.class(), &[Class::Asymmetric])?;
        if routed.engine == Engine::Kv2 {
            // Materialize-to-sign: the seed lives only in `Zeroizing` and the
            // ed25519-dalek `SigningKey` (ZeroizeOnDrop) inside this scope.
            let seed = self.materialize_signing_seed(key_id, "sign").await?;
            return Ok(ed25519_sign::sign(&seed, message).to_vec());
        }
        Ok(routed
            .backend
            .sign_with_options(
                routed.path(),
                message,
                sign_options_for_key(routed.key_type()),
            )
            .await?)
    }

    /// `verify` verifies `signature` over `message` with `key_id`.
    ///
    /// Valid for `asymmetric` and `public` keys (the public half verifies). For an
    /// `engine=kv2` Ed25519 signing key (`vault-iiz`), verification is a public op:
    /// the public half is derived from the materialized seed and the signature is
    /// checked in-process (the seed is zeroized before this returns).
    ///
    /// # Errors
    ///
    /// [`ManagerError::UnknownKey`], [`ManagerError::OpNotValidForClass`],
    /// [`ManagerError::Signing`] (a malformed seed or `signature` length on the
    /// `kv2` arm), or [`ManagerError::Backend`].
    pub async fn verify(
        &self,
        key_id: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, ManagerError> {
        let routed = self.resolve(key_id)?;
        require_class(
            "verify",
            key_id,
            routed.class(),
            &[Class::Asymmetric, Class::Public],
        )?;
        if routed.class() == Class::Asymmetric && routed.engine == Engine::Kv2 {
            // Public op (basil-o86): read the out-of-band-provisioned public from
            // KV and verify in-process. The seed is NEVER materialized for a
            // verify, only `sign` (the private op) materializes it.
            let public_bytes = self
                .read_public_half(key_id, "verify", &[Class::Asymmetric])
                .await?;
            let public = ed25519_sign::public_from_slice(&public_bytes)
                .map_err(|e| ManagerError::Signing(SigningFailure::from_sign(e)))?;
            return ed25519_sign::verify(&public, message, signature)
                .map_err(|e| ManagerError::Signing(SigningFailure::from_sign(e)));
        }
        Ok(routed
            .backend
            .verify_with_options(
                routed.path(),
                message,
                signature,
                sign_options_for_key(routed.key_type()),
            )
            .await?)
    }

    /// `get_public_key` reads the public half **plus** metadata (real algorithm
    /// + current version) for `key_id`.
    ///
    /// Valid for `asymmetric` and `public` keys, plus **software-custody ML-KEM
    /// sealing keys** (basil-4ybx): for those the public *encapsulation* key was
    /// derived at provisioning time and recorded in the custody record, and is
    /// returned WITHOUT materializing the decapsulation seed (the seed is touched
    /// only by `unwrap`). The returned [`PublicKey`] is what the handler echoes
    /// verbatim, replacing the previous hardcoded `ed25519` / `version 1`
    /// (`vault-k3w`).
    ///
    /// # Errors
    ///
    /// [`ManagerError::UnknownKey`], [`ManagerError::OpNotValidForClass`],
    /// or [`ManagerError::Backend`].
    pub async fn get_public_key(&self, key_id: &str) -> Result<PublicKey, ManagerError> {
        let routed = self.resolve(key_id)?;
        // ML-KEM sealing key (basil-4ybx): a software-custody sealing key whose
        // public *encapsulation* key was derived from the seed at provisioning
        // time and recorded (non-secret) in the custody record. Return it WITHOUT
        // materializing the decapsulation seed: the sealing-class dual of the
        // ML-DSA software-custody read below, and the read path senders use to
        // seal payloads to this recipient. Handled before the asymmetric/public
        // class gate, which is scoped to the signing/value read paths and would
        // otherwise reject a sealing key.
        if routed.class() == Class::Sealing
            && ProviderMetadata::from_key(routed.entry).custody
                == Some(CustodyMode::SoftwareEncrypted)
            && let Some(kem) = routed.key_type().and_then(ml_kem_provider_algorithm)
        {
            let public_key = LocalSoftwareProvider::new(routed.backend)
                .public_key(key_id, routed.path(), kem.token())
                .await?;
            return Ok(PublicKey {
                public_key,
                key_type: ml_kem_wire_key_type(kem),
                // A software-custody record is a single fixed version.
                version: 1,
            });
        }
        require_class(
            "get_public_key",
            key_id,
            routed.class(),
            &[Class::Asymmetric, Class::Public],
        )?;
        // ML-DSA software-custody signing key (basil-a36l): the verifying key was
        // derived from the seed at provisioning time and recorded (non-secret) in
        // the custody record. Return it WITHOUT materializing the private seed: a
        // pure public read, consistent with the `verify` path that also reads the
        // recorded public. The classical transit metadata read below would return
        // garbage for a KV-custodied ML-DSA key (its `path` is a KV path, not a
        // transit key name).
        if ProviderMetadata::from_key(routed.entry).custody == Some(CustodyMode::SoftwareEncrypted)
            && let Some(algorithm) = routed.key_type().and_then(ml_dsa_signature_algorithm)
        {
            let public_key = LocalSoftwareProvider::new(routed.backend)
                .public_key(key_id, routed.path(), algorithm.token())
                .await?;
            return Ok(PublicKey {
                public_key,
                key_type: ml_dsa_wire_key_type(algorithm),
                // A software-custody record is a single fixed version.
                version: 1,
            });
        }
        if routed.class() == Class::Asymmetric && routed.engine == Engine::Kv2 {
            // Public op (basil-o86): read the out-of-band-provisioned public from
            // KV; the seed is NEVER materialized (only `sign` materializes it).
            let public_bytes = self
                .read_public_half(key_id, "get_public_key", &[Class::Asymmetric])
                .await?;
            let public = ed25519_sign::public_from_slice(&public_bytes)
                .map_err(|e| ManagerError::Signing(SigningFailure::from_sign(e)))?;
            return Ok(PublicKey {
                public_key: public.to_vec(),
                key_type: KeyType::Ed25519,
                // A KV-stored seed is a single fixed version (no transit version
                // counter); report version 1.
                version: 1,
            });
        }
        Ok(routed.backend.public_key_with_meta(routed.path()).await?)
    }

    /// The provider [`SignatureAlgorithm`] for an ML-DSA signing key, or `None`
    /// for an unknown key or a classical signing key (which uses the in-place
    /// backend signing path).
    ///
    /// This is the routing signal the signing service uses to choose between the
    /// classical [`Self::sign`]/[`Self::verify`] path and the provider-dispatch
    /// [`Self::provider_sign`]/[`Self::provider_verify`] path.
    #[must_use]
    pub fn ml_dsa_algorithm_for(&self, key_id: &str) -> Option<SignatureAlgorithm> {
        let routed = self.resolve(key_id).ok()?;
        ml_dsa_signature_algorithm(routed.key_type()?)
    }

    /// The provider [`ProviderKemAlgorithm`] for an ML-KEM **sealing** key, or
    /// `None` for an unknown key or any non-ML-KEM key (an X25519 sealing key signs
    /// through the classical sealing path, not provider provisioning).
    ///
    /// The routing signal the signing service uses to dispatch a `new_key` for an
    /// ML-KEM sealing key through [`Self::provider_generate_sealing`].
    #[must_use]
    pub fn ml_kem_algorithm_for(&self, key_id: &str) -> Option<ProviderKemAlgorithm> {
        let routed = self.resolve(key_id).ok()?;
        ml_kem_provider_algorithm(routed.key_type()?)
    }

    /// Describe the provider/custody/version a key is provisioned under, plus
    /// whether its backend now natively supports the key's algorithm: the admin
    /// read seam for observing the **active** custody mode and whether a
    /// backend-native migration is available (`basil-wuj.10`).
    ///
    /// A pure read: it resolves the key, parses its reserved catalog labels, and
    /// runs the cheap capability probe. It never performs a crypto operation,
    /// reads key material, or materializes a seed, so it needs no caller gate.
    ///
    /// # Errors
    ///
    /// [`ManagerError::UnknownKey`] if `key_id` is not in the catalog.
    pub fn describe_provider(&self, key_id: &str) -> Result<KeyProviderDescriptor, ManagerError> {
        let routed = self.resolve(key_id)?;
        let metadata = ProviderMetadata::from_key(routed.entry);
        let native = routed
            .key_type()
            .and_then(ml_dsa_signature_algorithm)
            .and_then(SignatureAlgorithm::native_algorithm);
        let backend_native_available =
            native.is_some_and(|algorithm| routed.backend.supports_native_algorithm(algorithm));
        Ok(KeyProviderDescriptor {
            policy: metadata.policy,
            provider: metadata.provider,
            custody: metadata.custody,
            version: routed
                .entry
                .labels
                .get("crypto_provider_version")
                .map(str::to_owned),
            backend_native_available,
        })
    }

    /// `sign` for an ML-DSA software-custodied key, dispatched through the
    /// provider that [`select_provider`] chooses from the key's catalog
    /// policy/custody labels and the caller's `gate`.
    ///
    /// The signature is produced by the selected [`CryptoProvider`]; the private
    /// seed is materialized **inside the provider** for exactly one signature and
    /// zeroized. It is never returned, logged, or audited. Returns the signature
    /// plus a [`ProviderDispatch`] describing the selected provider/algorithm for
    /// the audit trail.
    ///
    /// # Errors
    ///
    /// [`ManagerError::UnknownKey`], [`ManagerError::OpNotValidForClass`] (a
    /// non-asymmetric key), [`ManagerError::Unsupported`] (not an ML-DSA key), or
    /// [`ManagerError::Provider`] (an unsupported algorithm/provider combination,
    /// a policy denial, or an opaque software-custody crypto failure).
    pub async fn provider_sign(
        &self,
        key_id: &str,
        message: &[u8],
        gate: ProviderGate,
    ) -> Result<(Vec<u8>, ProviderDispatch), ManagerError> {
        let routed = self.resolve(key_id)?;
        require_class("sign", key_id, routed.class(), &[Class::Asymmetric])?;
        let algorithm = require_ml_dsa(key_id, &routed)?;
        let provider = select_provider_for(&routed, algorithm.native_algorithm(), gate, "sign")?;
        let request = SignRequest {
            key_id,
            backend_path: routed.path(),
            algorithm,
            message,
        };
        let signature = match provider {
            CryptoProviderId::VaultTransit => {
                BackendCryptoProvider::new(routed.backend)
                    .sign(request)
                    .await?
            }
            CryptoProviderId::LocalSoftware => {
                LocalSoftwareProvider::new(routed.backend)
                    .sign(request)
                    .await?
            }
        };
        Ok((signature, provider_dispatch(provider, algorithm)))
    }

    /// `verify` for an ML-DSA software-custodied key, dispatched through the
    /// selected provider. Verification needs only the published public key (no
    /// seed is materialized). Returns the validity plus the [`ProviderDispatch`].
    ///
    /// # Errors
    ///
    /// As [`Self::provider_sign`].
    pub async fn provider_verify(
        &self,
        key_id: &str,
        message: &[u8],
        signature: &[u8],
        gate: ProviderGate,
    ) -> Result<(bool, ProviderDispatch), ManagerError> {
        let routed = self.resolve(key_id)?;
        require_class(
            "verify",
            key_id,
            routed.class(),
            &[Class::Asymmetric, Class::Public],
        )?;
        let algorithm = require_ml_dsa(key_id, &routed)?;
        let provider = select_provider_for(&routed, algorithm.native_algorithm(), gate, "verify")?;
        let request = VerifyRequest {
            key_id,
            backend_path: routed.path(),
            algorithm,
            message,
            signature,
        };
        let valid = match provider {
            CryptoProviderId::VaultTransit => {
                BackendCryptoProvider::new(routed.backend)
                    .verify(request)
                    .await?
            }
            CryptoProviderId::LocalSoftware => {
                LocalSoftwareProvider::new(routed.backend)
                    .verify(request)
                    .await?
            }
        };
        Ok((valid, provider_dispatch(provider, algorithm)))
    }

    /// `new_key` for an ML-DSA software-custodied key: generate a keypair, seal
    /// the private seed into an encrypted custody record, and write it to KV, all
    /// inside the selected provider, so the private is never exposed to the
    /// caller. Returns the new key (public half only) plus the [`ProviderDispatch`].
    ///
    /// # Errors
    ///
    /// As [`Self::provider_sign`].
    pub async fn provider_generate(
        &self,
        key_id: &str,
        gate: ProviderGate,
    ) -> Result<(NewKey, ProviderDispatch), ManagerError> {
        let routed = self.resolve(key_id)?;
        require_class("new_key", key_id, routed.class(), &[Class::Asymmetric])?;
        let algorithm = require_ml_dsa(key_id, &routed)?;
        let provider =
            select_provider_for(&routed, algorithm.native_algorithm(), gate, "generate")?;
        let request = ProviderGenerateKey {
            key_id,
            backend_path: routed.path(),
            algorithm,
            storage_key: routed.entry.labels.get("pqc_storage_key"),
        };
        let created = match provider {
            CryptoProviderId::VaultTransit => {
                BackendCryptoProvider::new(routed.backend)
                    .generate_key(request)
                    .await?
            }
            CryptoProviderId::LocalSoftware => {
                LocalSoftwareProvider::new(routed.backend)
                    .generate_key(request)
                    .await?
            }
        };
        Ok((created, provider_dispatch(provider, algorithm)))
    }

    /// `new_key` for an ML-KEM software-custodied **sealing** key, dispatched
    /// through the crypto provider that [`select_provider`] chooses from the key's
    /// catalog policy/custody labels and the caller's `gate`.
    ///
    /// The provider generates a fresh 64-byte ML-KEM seed, seals it under the
    /// catalog `pqc_storage_key` AEAD key, writes the custody record, and returns
    /// the derived encapsulation (public) key plus a [`ProviderDispatch`] for the
    /// audit trail. The seed never leaves the provider; no private material is
    /// returned. The requested `kem` must match the key's catalog `keyType`.
    ///
    /// # Errors
    ///
    /// [`ManagerError::UnknownKey`], [`ManagerError::OpNotValidForClass`] (a
    /// non-sealing key), [`ManagerError::KemAlgorithmMismatch`] (the catalog
    /// `keyType` is not the requested ML-KEM level), or
    /// [`ManagerError::Provider`] (a policy denial or an opaque software-custody
    /// crypto failure).
    pub async fn provider_generate_sealing(
        &self,
        key_id: &str,
        kem: ProviderKemAlgorithm,
        gate: ProviderGate,
    ) -> Result<(NewKey, ProviderDispatch), ManagerError> {
        let routed = self.resolve(key_id)?;
        require_class("new_key", key_id, routed.class(), &[Class::Sealing])?;
        require_ml_kem_sealing_key(key_id, routed.key_type(), kem)?;
        let provider = select_provider_for(&routed, kem.native_algorithm(), gate, "generate")?;
        let request = ProviderGenerateSealingKey {
            key_id,
            backend_path: routed.path(),
            algorithm: kem,
            storage_key: routed.entry.labels.get("pqc_storage_key"),
        };
        let created = match provider {
            CryptoProviderId::VaultTransit => {
                BackendCryptoProvider::new(routed.backend)
                    .generate_sealing_key(request)
                    .await?
            }
            CryptoProviderId::LocalSoftware => {
                LocalSoftwareProvider::new(routed.backend)
                    .generate_sealing_key(request)
                    .await?
            }
        };
        Ok((created, kem_provider_dispatch(provider, kem)))
    }

    /// `import` (BYOK): provision the key `key_id` from caller-supplied material.
    ///
    /// Valid for crypto keys (`asymmetric` / `symmetric`). Write-only: the reply
    /// carries only the public half; the private material is never echoed.
    ///
    /// # Errors
    ///
    /// [`ManagerError::UnknownKey`], [`ManagerError::OpNotValidForClass`], or
    /// [`ManagerError::Backend`] (including an unsupported material variant).
    pub async fn import(
        &self,
        key_id: &str,
        key_type: KeyType,
        material: &KeyMaterial,
    ) -> Result<NewKey, ManagerError> {
        let routed = self.resolve(key_id)?;
        require_class(
            "import",
            key_id,
            routed.class(),
            &[Class::Asymmetric, Class::Symmetric],
        )?;
        // A value-store (`engine=kv2`) crypto key's private is provisioned
        // out-of-band as raw KV bytes, not BYOK-imported through transit. Refuse
        // explicitly rather than let the transit `import` incidentally fail on a
        // KV path.
        if routed.engine == Engine::Kv2 {
            return Err(ManagerError::Unsupported(
                "import: a value-store (kv2) crypto key is provisioned out-of-band, not imported via the broker",
            ));
        }
        if routed.class() == Class::Asymmetric {
            routed.require_mint_key_type("import", key_type)?;
        }
        // Import provisions the key under its catalog backend path, not the
        // backend-assigned id `new_key` uses.
        Ok(routed
            .backend
            .import(routed.path(), key_type, material)
            .await?)
    }

    /// `list` returns value-free key metadata across the catalog (§7).
    ///
    /// Projects the catalog (name + kind + algorithm) into the wire
    /// [`WireCatalogEntry`] shape, filtered by `prefix` and by the `visible`
    /// predicate (the handler passes a PDP-backed closure so a caller only sees
    /// keys it may list/read). The latest version is read from each key's backend
    /// via [`Backend::key_metadata`]; a key whose backend errors is reported with
    /// `latest_version = 0` rather than failing the whole list (one down backend
    /// must not blind the caller to every other key). Never returns key bytes.
    ///
    /// # Errors
    ///
    /// Infallible at the manager layer today: per-key backend failures degrade
    /// to `latest_version = 0`; the [`Result`] is kept for forward-compat.
    pub async fn list(
        &self,
        prefix: Option<&str>,
        visible: impl Fn(&str) -> bool,
    ) -> Result<Vec<WireCatalogEntry>, ManagerError> {
        let mut out = Vec::new();
        for (name, entry) in &self.catalog.keys {
            if let Some(p) = prefix
                && !name.starts_with(p)
            {
                continue;
            }
            if !visible(name) {
                continue;
            }
            // Best-effort version + algorithm from the backend; a resolve or
            // backend failure degrades to the catalog's declared type + version 0
            // rather than failing the whole list.
            let meta = match self.resolve(name) {
                Ok(routed) => routed.backend.key_metadata(routed.path()).await.ok(),
                Err(_) => None,
            };
            let (key_type, latest_version) = meta.map_or_else(
                || (wire_key_type(entry), 0),
                |m| (m.key_type, m.latest_version),
            );
            out.push(WireCatalogEntry {
                name: name.clone(),
                kind: key_kind(entry),
                key_type,
                latest_version,
            });
        }
        Ok(out)
    }

    /// `encrypt` AEAD-encrypts `plaintext` under `key_id`'s latest version.
    ///
    /// Valid only for `symmetric` keys. `algorithm` must match the key's catalog
    /// `keyType` ([`ManagerError::AlgorithmMismatch`] otherwise). The backend owns
    /// the nonce and returns a normalized [`CiphertextEnvelope`].
    ///
    /// # Errors
    ///
    /// [`ManagerError::UnknownKey`], [`ManagerError::OpNotValidForClass`],
    /// [`ManagerError::AlgorithmMismatch`], or [`ManagerError::Backend`].
    pub async fn encrypt(
        &self,
        key_id: &str,
        algorithm: AeadAlgorithm,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<CiphertextEnvelope, ManagerError> {
        let routed = self.resolve(key_id)?;
        require_class("encrypt", key_id, routed.class(), &[Class::Symmetric])?;
        require_aead_match(key_id, routed.key_type(), algorithm)?;
        Ok(routed
            .backend
            .encrypt(routed.path(), algorithm, plaintext, aad)
            .await?)
    }

    /// `decrypt` AEAD-decrypts `envelope` under `key_id`, targeting the version
    /// the envelope names (rotation grace). The envelope `alg` must match the
    /// key's catalog `keyType`.
    ///
    /// Valid only for `symmetric` keys. A tag/AAD/version mismatch surfaces as
    /// [`BackendError::DecryptFailed`] (opaque).
    ///
    /// # Errors
    ///
    /// [`ManagerError::UnknownKey`], [`ManagerError::OpNotValidForClass`],
    /// [`ManagerError::AlgorithmMismatch`], or [`ManagerError::Backend`]
    /// (including the opaque [`BackendError::DecryptFailed`]).
    pub async fn decrypt(
        &self,
        key_id: &str,
        envelope: &CiphertextEnvelope,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, ManagerError> {
        let routed = self.resolve(key_id)?;
        require_class("decrypt", key_id, routed.class(), &[Class::Symmetric])?;
        require_aead_match(key_id, routed.key_type(), envelope.alg)?;
        Ok(routed.backend.decrypt(routed.path(), envelope, aad).await?)
    }

    /// `wrap_envelope` seals `plaintext` to a sealing key as an X25519 sealed box.
    ///
    /// Valid **only** for `sealing` keys. Sealing needs the recipient public key,
    /// which the broker reads from the key's **out-of-band-provisioned**
    /// `public_path` (a non-secret `kv_get`, basil-o86), so wrap is a pure public
    /// op that **never** materializes the long-lived private (that happens only on
    /// `unwrap`, the op that performs the ECDH). A caller can wrap without first
    /// fetching the public half. The returned [`SealedEnvelope`] carries the
    /// ephemeral public (`encapsulated_key`), the nonce, and the ciphertext; `aad`
    /// is bound as AEAD associated data.
    ///
    /// # Errors
    ///
    /// [`ManagerError::UnknownKey`], [`ManagerError::OpNotValidForClass`] (a
    /// non-sealing key), [`ManagerError::MissingPublicPath`] (no `public_path`
    /// configured), [`ManagerError::Sealing`] (malformed stored public / crypto
    /// failure), or [`ManagerError::Backend`].
    pub async fn wrap_envelope(
        &self,
        key_id: &str,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<SealedEnvelope, ManagerError> {
        let routed = self.resolve(key_id)?;
        require_class("wrap_envelope", key_id, routed.class(), &[Class::Sealing])?;
        require_x25519_sealing_key(key_id, routed.key_type())?;
        // Read the recipient public from its out-of-band path; the private is
        // never touched on the wrap path. Wrap uses only the public.
        let public_bytes = self
            .read_public_half(key_id, "wrap_envelope", &[Class::Sealing])
            .await?;
        let recipient_pub = x25519_seal::public_from_slice(&public_bytes)
            .map_err(|e| ManagerError::Sealing(SealingFailure::from_seal(e)))?;
        x25519_seal::seal(&recipient_pub, plaintext, aad)
            .map_err(|e| ManagerError::Sealing(SealingFailure::from_seal(e)))
    }

    /// `unwrap_envelope` opens an X25519 sealed box addressed to a sealing key.
    ///
    /// Valid **only** for `sealing` keys. The X25519 private is materialized from
    /// KV by an **internal** read (NOT the public `get` op, which stays denied for
    /// a sealing key), used for exactly one `ECDH`, and zeroized on every path. A
    /// wrong key, tampered envelope, or mismatched `aad` returns the opaque
    /// [`SealingFailure::OpenFailed`] (no oracle). The recovered plaintext is
    /// returned in a zeroizing buffer.
    ///
    /// **Confidentiality only, NOT sender authentication.** A sealed box is
    /// anonymous: a successful unwrap proves only that the envelope was sealed to
    /// this recipient, never *who* sealed it. Callers MUST NOT treat a successful
    /// unwrap as proof of sender identity. (A low-order `encapsulated_key` is
    /// rejected by the crypto core, but that is not authentication.)
    ///
    /// # Errors
    ///
    /// [`ManagerError::UnknownKey`], [`ManagerError::OpNotValidForClass`] (a
    /// non-sealing key), [`ManagerError::Sealing`] (malformed materialized key,
    /// malformed envelope, or AEAD authentication failure), or
    /// [`ManagerError::Backend`].
    pub async fn unwrap_envelope(
        &self,
        key_id: &str,
        envelope: &SealedEnvelope,
        aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ManagerError> {
        let private = self
            .materialize_sealing_private(key_id, "unwrap_envelope")
            .await?;
        x25519_seal::open(&private, envelope, aad)
            .map_err(|e| ManagerError::Sealing(SealingFailure::from_seal(e)))
    }

    /// Open a strict-profile `COSE_Encrypt` with a custodied X25519 sealing key.
    ///
    /// The exact tagged `COSE_Encrypt` bytes are passed to `basil-cose`
    /// verbatim. The `Enc_structure` AAD covers the serialized protected header
    /// bytes, so callers must not parse and re-encode before this point.
    ///
    /// # Errors
    ///
    /// [`ManagerError::UnknownKey`], [`ManagerError::OpNotValidForClass`],
    /// [`ManagerError::UnsealContextNotPermitted`] when the key pins an allowed
    /// COSE unseal context (KDF parties / `external_aad`, `basil-2rqj`) this
    /// envelope is not bound to, [`ManagerError::Sealing`] for malformed
    /// material/profile input or AEAD authentication failure, or
    /// [`ManagerError::Backend`].
    pub async fn unseal_cose(
        &self,
        key_id: &str,
        cose_encrypt: &[u8],
        external_aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ManagerError> {
        // Catalog pinning (basil-2rqj): when the sealing key pins an allowed
        // unseal context, an `op:decrypt` grant authorizes ONLY envelopes bound to
        // it, not any envelope addressed to the key. The `external_aad` facet is
        // enforced here (it is caller-supplied, never embedded), fail-closed before
        // the private is ever materialized; the KDF-party facet rides into the one
        // COSE open implementation below as `expected_parties`.
        let expected_parties = {
            let routed = self.resolve(key_id)?;
            match routed.entry.sealing_pin.as_ref() {
                None => None,
                Some(pin) => {
                    if !pin.external_aad_allowed(external_aad) {
                        return Err(ManagerError::UnsealContextNotPermitted(key_id.to_string()));
                    }
                    match pin.parties.as_ref() {
                        None => None,
                        Some(parties) => Some(
                            parties
                                .to_kdf_parties()
                                .map_err(|_| ManagerError::Sealing(SealingFailure::Malformed))?,
                        ),
                    }
                }
            }
        };

        let private = self
            .materialize_sealing_private(key_id, "unseal_cose")
            .await?;
        let cose_key_id = basil_cose::KeyId::from_text(key_id)
            .map_err(|_| ManagerError::Sealing(SealingFailure::Malformed))?;
        let recipient = basil_cose::X25519Recipient::new(cose_key_id, private);
        let aad = basil_cose::ExternalAad::from_bytes(external_aad.to_vec());
        let request = basil_cose::OpenRequest {
            cose_encrypt,
            external_aad: &aad,
            expected_parties: expected_parties.as_ref(),
        };
        recipient.open(&request).await.map_err(|e| match e {
            // A pinned-party mismatch is a least-privilege authorization refusal
            // (the parties are cleartext header values, not a secret), surfaced as
            // permission-denied, distinct from the opaque decrypt-failed posture
            // an authentication failure keeps.
            basil_cose::OpenError::PartyMismatch => {
                ManagerError::UnsealContextNotPermitted(key_id.to_string())
            }
            other => ManagerError::Sealing(SealingFailure::from_cose_open(&other)),
        })
    }

    /// Encrypt with a custodied NATS curve xkey.
    ///
    /// This is a materialize-to-use operation: the sender private xkey is read
    /// through the secret KV path, used for one NaCl-compatible authenticated box,
    /// then zeroized. The peer key is a public `X...` nkey supplied by the caller.
    pub async fn encrypt_nats_curve(
        &self,
        key_id: &str,
        recipient_public_xkey: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ManagerError> {
        let private = self
            .materialize_sealing_private(key_id, "encrypt_nats_curve")
            .await?;
        basil_nats::seal_nats_curve(
            &private,
            recipient_public_xkey,
            plaintext,
            &mut rand::thread_rng(),
        )
        .map_err(|e| nats_curve_error(&e))
    }

    /// Decrypt a NATS curve xkey authenticated box with a custodied recipient key.
    ///
    /// A wrong key, wrong sender public key, or tampered ciphertext maps to the
    /// same opaque sealing open failure used by the envelope decrypt path.
    pub async fn decrypt_nats_curve(
        &self,
        key_id: &str,
        sender_public_xkey: &str,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ManagerError> {
        let private = self
            .materialize_sealing_private(key_id, "decrypt_nats_curve")
            .await?;
        basil_nats::open_nats_curve(&private, sender_public_xkey, ciphertext)
            .map_err(|e| nats_curve_error(&e))
    }

    /// `wrap_envelope` for an ML-KEM **sealing** key, dispatched through the crypto
    /// provider (software custody).
    ///
    /// Self-sealing: the provider materializes the custodied 64-byte ML-KEM seed,
    /// derives its public encapsulation key, encapsulates to it, and AEAD-seals the
    /// plaintext under the KEM-derived key, so the broker needs no separately
    /// published encapsulation key. The requested `kem` must name the same ML-KEM
    /// level the key's catalog `keyType` declares; the local-software provider is
    /// selectable only when `gate` carries the caller's explicit
    /// `op:use_software_custody` grant. Returns the self-describing
    /// [`ProviderEnvelope`] (KEM/envelope algorithm, key version, encapsulated key,
    /// nonce, ciphertext) plus a [`ProviderDispatch`] for the audit trail.
    ///
    /// # Errors
    ///
    /// [`ManagerError::UnknownKey`], [`ManagerError::OpNotValidForClass`] (a
    /// non-sealing key), [`ManagerError::KemAlgorithmMismatch`] (a wrong ML-KEM
    /// level), or [`ManagerError::Provider`] (a policy denial or an opaque
    /// software-custody crypto failure).
    pub async fn provider_wrap_envelope(
        &self,
        key_id: &str,
        kem: ProviderKemAlgorithm,
        envelope_algorithm: ProviderEnvelopeAlgorithm,
        plaintext: &[u8],
        aad: &[u8],
        gate: ProviderGate,
    ) -> Result<(ProviderEnvelope, ProviderDispatch), ManagerError> {
        let routed = self.resolve(key_id)?;
        require_class("wrap_envelope", key_id, routed.class(), &[Class::Sealing])?;
        require_ml_kem_sealing_key(key_id, routed.key_type(), kem)?;
        let provider = select_provider_for(&routed, kem.native_algorithm(), gate, "wrap_envelope")?;
        let request = ProviderWrapEnvelopeRequest {
            key_id,
            backend_path: routed.path(),
            kem_algorithm: kem,
            envelope_algorithm,
            plaintext,
            aad: Some(aad),
        };
        let envelope = match provider {
            CryptoProviderId::VaultTransit => {
                BackendCryptoProvider::new(routed.backend)
                    .wrap_envelope(request)
                    .await?
            }
            CryptoProviderId::LocalSoftware => {
                LocalSoftwareProvider::new(routed.backend)
                    .wrap_envelope(request)
                    .await?
            }
        };
        Ok((envelope, kem_provider_dispatch(provider, kem)))
    }

    /// `unwrap_envelope` for an ML-KEM **sealing** key, dispatched through the
    /// crypto provider (software custody).
    ///
    /// The provider materializes the custodied 64-byte ML-KEM seed for exactly one
    /// decapsulation, derives the AEAD key, opens the envelope, and zeroizes the
    /// seed on every path. The requested `kem` must match the key's catalog
    /// `keyType`; the local-software provider requires the caller's explicit
    /// `op:use_software_custody` grant in `gate`. A wrong key, tampered envelope,
    /// or mismatched `aad` returns the opaque
    /// [`ProviderError::CryptoFailed`](crate::core::crypto_provider::ProviderError::CryptoFailed)
    /// (no decrypt oracle). Returns the recovered plaintext plus a
    /// [`ProviderDispatch`] for the audit trail.
    ///
    /// **Confidentiality only, NOT sender authentication.** A successful unwrap
    /// proves only that the payload was sealed to this recipient, never *who*
    /// sealed it.
    ///
    /// # Errors
    ///
    /// As [`Self::provider_wrap_envelope`].
    pub async fn provider_unwrap_envelope(
        &self,
        key_id: &str,
        kem: ProviderKemAlgorithm,
        envelope_algorithm: ProviderEnvelopeAlgorithm,
        parts: MlKemEnvelopeParts<'_>,
        aad: &[u8],
        gate: ProviderGate,
    ) -> Result<(Vec<u8>, ProviderDispatch), ManagerError> {
        let routed = self.resolve(key_id)?;
        require_class("unwrap_envelope", key_id, routed.class(), &[Class::Sealing])?;
        require_ml_kem_sealing_key(key_id, routed.key_type(), kem)?;
        let provider =
            select_provider_for(&routed, kem.native_algorithm(), gate, "unwrap_envelope")?;
        let request = ProviderUnwrapEnvelopeRequest {
            key_id,
            backend_path: routed.path(),
            kem_algorithm: kem,
            envelope_algorithm,
            encapsulated_key: parts.encapsulated_key,
            nonce: parts.nonce,
            ciphertext: parts.ciphertext,
            aad: Some(aad),
        };
        let plaintext = match provider {
            CryptoProviderId::VaultTransit => {
                BackendCryptoProvider::new(routed.backend)
                    .unwrap_envelope(request)
                    .await?
            }
            CryptoProviderId::LocalSoftware => {
                LocalSoftwareProvider::new(routed.backend)
                    .unwrap_envelope(request)
                    .await?
            }
        };
        Ok((plaintext, kem_provider_dispatch(provider, kem)))
    }

    /// `get_public_key` for a **sealing** key: read and return the X25519 public
    /// half from the key's **out-of-band-provisioned** `public_path` (basil-o86).
    /// A pure public op: the long-lived private is **never** materialized here
    /// (that happens only on `unwrap`). Senders use the returned public to seal
    /// enrollment payloads to this recipient.
    ///
    /// # Errors
    ///
    /// [`ManagerError::UnknownKey`], [`ManagerError::OpNotValidForClass`] (a
    /// non-sealing key), [`ManagerError::MissingPublicPath`] (no `public_path`
    /// configured), [`ManagerError::Sealing`] (malformed stored public), or
    /// [`ManagerError::Backend`].
    pub async fn sealing_public_key(
        &self,
        key_id: &str,
    ) -> Result<[u8; x25519_seal::PUBLIC_KEY_LEN], ManagerError> {
        let routed = self.resolve(key_id)?;
        require_class("get_public_key", key_id, routed.class(), &[Class::Sealing])?;
        require_x25519_sealing_key(key_id, routed.key_type())?;
        let public_bytes = self
            .read_public_half(key_id, "get_public_key", &[Class::Sealing])
            .await?;
        x25519_seal::public_from_slice(&public_bytes)
            .map_err(|e| ManagerError::Sealing(SealingFailure::from_seal(e)))
    }

    /// Read and validate a sealing key's X25519 private from KV (the internal
    /// materialize). This is a `pub(crate)`-free private helper: it is reachable
    /// **only** through the sealing `unwrap` path (the one op that performs the
    /// ECDH), never via the public `get` op (which `require_class` rejects for a
    /// sealing key) and, since basil-o86, never for `wrap`/`get_public_key`
    /// either (those read the out-of-band public via [`Self::read_public_half`]).
    async fn materialize_sealing_private(
        &self,
        key_id: &str,
        op: &'static str,
    ) -> Result<Zeroizing<[u8; x25519_seal::PRIVATE_KEY_LEN]>, ManagerError> {
        let routed = self.resolve(key_id)?;
        require_class(op, key_id, routed.class(), &[Class::Sealing])?;
        require_x25519_sealing_key(key_id, routed.key_type())?;
        // SECRET read: the X25519 private stays in `Zeroizing` end-to-end (the
        // `Zeroizing<Vec<u8>>` wipes on drop), never the plain `KvValue`/`Vec`
        // path used for value/public reads.
        let secret = routed.backend.kv_get_secret(routed.path(), None).await?;
        // The stored value is raw X25519 private bytes; copy into a fixed,
        // zeroizing array (fails closed on a wrong length, never indexes). The
        // source `Zeroizing<Vec>` wipes when it drops at the end of this scope.
        x25519_seal::private_from_slice(&secret)
            .map_err(|e| ManagerError::Sealing(SealingFailure::from_seal(e)))
    }

    /// Read the **public** half of a materialize-to-use key from its
    /// out-of-band-provisioned `public_path` (basil-o86) via a non-secret
    /// `kv_get`, enforcing `op`'s class gate (`allowed`). This is the seam that
    /// lets every public op (`wrap`/`get_public_key`/`verify`) resolve the public
    /// **without** materializing the private: the private is touched only on the
    /// op that performs the private crypto (`unwrap`/`sign`).
    ///
    /// The public carries no key material, so the plain `kv_get`/`KvValue` path is
    /// correct here (NOT `kv_get_secret`, which is reserved for the private). The
    /// returned bytes are the raw public; the caller validates the fixed length
    /// through its crypto core (`x25519_seal`/`ed25519_sign`).
    async fn read_public_half(
        &self,
        key_id: &str,
        op: &'static str,
        allowed: &[Class],
    ) -> Result<Vec<u8>, ManagerError> {
        let routed = self.resolve(key_id)?;
        require_class(op, key_id, routed.class(), allowed)?;
        let public_path = routed
            .public_path()
            .ok_or_else(|| ManagerError::MissingPublicPath(key_id.to_string()))?;
        let kv = routed.backend.kv_get(public_path, None).await?;
        Ok(kv.value)
    }

    /// Read and validate an `engine=kv2` Ed25519 signing key's 32-byte seed from KV
    /// (the materialize-to-sign read, `vault-iiz`). The sibling of
    /// [`Self::materialize_sealing_private`]: a `pub(crate)`-free private helper
    /// reachable **only** through the `sign` Kv2 branch (the one op that performs
    /// the private crypto; since basil-o86 `verify`/`get_public_key` read the
    /// out-of-band public via [`Self::read_public_half`] instead), never the public
    /// `get` op (`require_class` rejects `get` for an asymmetric key, so the seed is
    /// structurally un-gettable).
    ///
    /// The returned [`Zeroizing`] seed and any `SigningKey` built from it are wiped
    /// on drop; the bytes never enter a non-zeroizing owner, an error string, a
    /// `Debug`/`Display`, a log, or the audit record.
    async fn materialize_signing_seed(
        &self,
        key_id: &str,
        op: &'static str,
    ) -> Result<Zeroizing<[u8; ed25519_sign::SEED_LEN]>, ManagerError> {
        let routed = self.resolve(key_id)?;
        require_class(op, key_id, routed.class(), &[Class::Asymmetric])?;
        // SECRET read: the Ed25519 seed stays in `Zeroizing` end-to-end (the
        // `Zeroizing<Vec<u8>>` wipes on drop), never the plain `KvValue`/`Vec`
        // path used for value/public reads (the t9a-review leak).
        let secret = routed.backend.kv_get_secret(routed.path(), None).await?;
        // The stored value is the raw 32-byte Ed25519 seed; copy into a fixed,
        // zeroizing array (fails closed on a wrong length, never indexes). The
        // source `Zeroizing<Vec>` wipes when it drops at the end of this scope.
        ed25519_sign::seed_from_slice(&secret)
            .map_err(|e| ManagerError::Signing(SigningFailure::from_sign(e)))
    }

    /// `get` reads the latest (or a specific) KV-v2 value for `key_id`,
    /// returning the value bytes + the version they came from (§7).
    ///
    /// Valid **only** for `value` and `public` keys. A crypto key (`asymmetric` /
    /// `symmetric`) is rejected with [`ManagerError::OpNotValidForClass`] *before*
    /// any backend call: the broker never hands out signing/encryption key
    /// material through `get` (that op-class gate is the security invariant here).
    /// `version = None` reads the latest version.
    ///
    /// # Errors
    ///
    /// [`ManagerError::UnknownKey`], [`ManagerError::OpNotValidForClass`], or
    /// [`ManagerError::Backend`].
    pub async fn get(&self, key_id: &str, version: Option<u32>) -> Result<KvValue, ManagerError> {
        let routed = self.resolve(key_id)?;
        require_class(
            "get",
            key_id,
            routed.class(),
            &[Class::Value, Class::Public],
        )?;
        Ok(routed.backend.kv_get(routed.path(), version).await?)
    }

    /// `set` writes `value` as a fresh KV-v2 version of `key_id`, returning the
    /// new version number (never the value, §7).
    ///
    /// Valid **only** for `value` keys (a `public` key is read-only material, a
    /// crypto key is `import`/`rotate` territory). Rejected with
    /// [`ManagerError::OpNotValidForClass`] otherwise, before any backend call.
    ///
    /// # Errors
    ///
    /// [`ManagerError::UnknownKey`], [`ManagerError::OpNotValidForClass`], or
    /// [`ManagerError::Backend`].
    pub async fn set(&self, key_id: &str, value: &[u8]) -> Result<u32, ManagerError> {
        let routed = self.resolve(key_id)?;
        require_class("set", key_id, routed.class(), &[Class::Value])?;
        Ok(routed.backend.kv_put(routed.path(), value).await?)
    }

    /// `rotate` bumps `key_id` to a fresh version, returning the new version.
    ///
    /// - **Crypto (transit) keys** (`asymmetric`/`symmetric`): a transit key
    ///   version bump. New sign/encrypt uses the newest version; older versions
    ///   stay usable within the grace window, which this method then applies via
    ///   [`Backend::configure_versions`] (raising `min_decryption_version` to
    ///   [`BrokerLimits::grace_floor`]). On compromise, set `grace_versions = 0`
    ///   so only the newest version is honored.
    /// - **Value keys**: a key with a catalog `generate` recipe regenerates a
    ///   fresh value as a new KV-v2 version (`vault-a2p`); a value key *without* a
    ///   recipe is [`ManagerError::ValueRotateNeedsSet`] (use `set`).
    ///
    /// # Errors
    ///
    /// [`ManagerError::UnknownKey`], [`ManagerError::OpNotValidForClass`],
    /// [`ManagerError::ValueRotateNeedsSet`], or [`ManagerError::Backend`].
    pub async fn rotate(&self, key_id: &str, limits: BrokerLimits) -> Result<u32, ManagerError> {
        let routed = self.resolve(key_id)?;
        require_class(
            "rotate",
            key_id,
            routed.class(),
            &[Class::Asymmetric, Class::Symmetric, Class::Value],
        )?;

        // A value-store (`engine=kv2`) crypto key holds its private as raw KV
        // bytes provisioned out-of-band; it is never transit-rotated (mirrors a
        // sealing key, which has no `rotate`). Refuse explicitly rather than let
        // the transit `rotate` incidentally 404 on a KV path. `Value`+kv2 is the
        // normal value key (rotated via its `generate` recipe below), exempt it.
        if routed.engine == Engine::Kv2 && routed.class() != Class::Value {
            return Err(ManagerError::Unsupported(
                "rotate: a value-store (kv2) crypto key is re-provisioned out-of-band, not rotated via the broker",
            ));
        }

        if routed.class() == Class::Value {
            // A value key rotates by generating a fresh value and writing it as a
            // new KV-v2 version. No recipe → nothing to generate → use `set`.
            let Some(spec) = routed.entry.generate.as_ref() else {
                return Err(ManagerError::ValueRotateNeedsSet(key_id.to_string()));
            };
            let writes = self.generated_writes_for_key(key_id, spec).await?;
            let mut rotated_version = None;
            for write in writes {
                let write_route = self.resolve(&write.key_id)?;
                require_class(
                    "rotate",
                    &write.key_id,
                    write_route.class(),
                    &[Class::Value, Class::Public],
                )?;
                let version = write_route
                    .backend
                    .kv_put(write_route.path(), &write.value)
                    .await?;
                if write.key_id == key_id {
                    rotated_version = Some(version);
                }
            }
            return rotated_version.ok_or_else(|| {
                ManagerError::Backend(BackendError::Backend(
                    "generate recipe produced no primary value".into(),
                ))
            });
        }

        // Crypto key: transit version bump, then apply the grace floor so
        // pre-window versions stop decrypting/verifying.
        let new_version = routed.backend.rotate(routed.path()).await?;
        let floor = limits.grace_floor(new_version);
        // Best-effort grace application: a backend that does not support the
        // version-config endpoint (default Unsupported) must not fail the rotate
        // itself: the version bump already succeeded.
        if let Err(e) = routed
            .backend
            .configure_versions(routed.path(), Some(floor), None)
            .await
            && !matches!(e, BackendError::Unsupported(_))
        {
            return Err(ManagerError::Backend(e));
        }
        Ok(new_version)
    }

    /// **Retention sweep** for one crypto key: raise the backend's
    /// `min_available_version` to [`BrokerLimits::retention_floor`], irreversibly
    /// pruning archived key material below the retention window. A no-op when
    /// retention is disabled (`retain_versions = None`) or the key has too few
    /// versions to prune.
    ///
    /// This is the sweep *primitive*. Call it after a rotate, or from the
    /// binary's periodic catalog sweep task, to enforce retention.
    ///
    /// # Errors
    ///
    /// [`ManagerError::UnknownKey`], [`ManagerError::OpNotValidForClass`], or
    /// [`ManagerError::Backend`].
    pub async fn sweep_retention(
        &self,
        key_id: &str,
        limits: BrokerLimits,
    ) -> Result<(), ManagerError> {
        let routed = self.resolve(key_id)?;
        require_class(
            "rotate",
            key_id,
            routed.class(),
            &[Class::Asymmetric, Class::Symmetric],
        )?;
        let latest = routed
            .backend
            .key_metadata(routed.path())
            .await?
            .latest_version;
        let Some(floor) = limits.retention_floor(latest) else {
            return Ok(()); // retention disabled
        };
        routed
            .backend
            .configure_versions(routed.path(), None, Some(floor))
            .await?;
        Ok(())
    }

    /// Apply the configured retention floor to every crypto key in catalog order.
    ///
    /// Value/public keys have no backend key-version retention in Basil and are
    /// skipped. A disabled retention policy is a no-op.
    ///
    /// # Errors
    ///
    /// Returns the first routing/backend error encountered while sweeping.
    pub async fn sweep_all_retention(&self, limits: BrokerLimits) -> Result<(), ManagerError> {
        if limits.retain_versions.is_none() {
            return Ok(());
        }
        let key_ids: Vec<String> = self
            .keys()
            .filter(|(_, entry)| matches!(entry.class, Class::Asymmetric | Class::Symmetric))
            .map(|(name, _)| name.clone())
            .collect();
        for key_id in key_ids {
            self.sweep_retention(&key_id, limits).await?;
        }
        Ok(())
    }

    /// Issue an X.509-SVID from a catalog `engine=pki` issuer key.
    ///
    /// Valid only for asymmetric keys with the explicit PKI engine. The backend
    /// path is a Vault issue endpoint (`pki/issue/<role>`), and the backend
    /// returns DER-normalized certificate chain, leaf key, and bundle material.
    ///
    /// # Errors
    ///
    /// [`ManagerError::UnknownKey`], [`ManagerError::OpNotValidForClass`],
    /// [`ManagerError::Unsupported`] for a non-PKI catalog entry, or
    /// [`ManagerError::Backend`].
    pub async fn issue_x509_svid(
        &self,
        key_id: &str,
        spiffe_id: &str,
        ttl_seconds: u64,
    ) -> Result<X509Svid, ManagerError> {
        let routed = self.resolve(key_id)?;
        require_class(
            "issue_x509_svid",
            key_id,
            routed.class(),
            &[Class::Asymmetric],
        )?;
        if routed.engine != Engine::Pki {
            return Err(ManagerError::Unsupported("issue_x509_svid"));
        }
        Ok(routed
            .backend
            .issue_x509_svid(routed.path(), spiffe_id, ttl_seconds)
            .await?)
    }

    /// Issue a DNS/IP-SAN X.509 leaf (TLS cert) from a catalog `engine=pki` issuer.
    ///
    /// The same issuer-key constraints as [`BackendManager::issue_x509_svid`]
    /// (asymmetric class, explicit PKI engine), but binds DNS/IP SANs instead of a
    /// SPIFFE URI. The issuing CA key stays in the backend; the leaf private key is
    /// returned to the caller.
    ///
    /// # Errors
    ///
    /// [`ManagerError::UnknownKey`], [`ManagerError::OpNotValidForClass`],
    /// [`ManagerError::Unsupported`] for a non-PKI catalog entry, or
    /// [`ManagerError::Backend`].
    pub async fn issue_x509_cert(
        &self,
        key_id: &str,
        request: &X509CertRequest,
    ) -> Result<X509Svid, ManagerError> {
        let routed = self.resolve(key_id)?;
        require_class(
            "issue_x509_cert",
            key_id,
            routed.class(),
            &[Class::Asymmetric],
        )?;
        if routed.engine != Engine::Pki {
            return Err(ManagerError::Unsupported("issue_x509_cert"));
        }
        Ok(routed
            .backend
            .issue_x509_cert(routed.path(), request)
            .await?)
    }

    /// Generate one or more KV writes for a value/public catalog recipe.
    ///
    /// Most recipes produce one write for `key_id`. The test/dev TLS pair recipes
    /// deliberately produce coordinated writes so a certificate and its private
    /// key cannot drift apart during reconcile or value rotation.
    pub(crate) async fn generated_writes_for_key(
        &self,
        key_id: &str,
        spec: &GenerateSpec,
    ) -> Result<Vec<GeneratedWrite>, ManagerError> {
        match spec {
            GenerateSpec::SelfSignedTls {
                common_name,
                validity,
            } => {
                if let Some(pair_key) = self.tls_pair_key_for_cert(key_id) {
                    let existing_key = self.try_existing_value(&pair_key).await?;
                    let material =
                        generate_self_signed_tls(common_name, validity, existing_key.as_deref())?;
                    let mut writes = Vec::new();
                    if existing_key.is_none() {
                        writes.push(GeneratedWrite {
                            key_id: pair_key,
                            value: material.private_key_pem,
                        });
                    }
                    writes.push(GeneratedWrite {
                        key_id: key_id.to_string(),
                        value: material.cert_pem,
                    });
                    Ok(writes)
                } else {
                    Ok(vec![GeneratedWrite {
                        key_id: key_id.to_string(),
                        value: generate_self_signed_tls(common_name, validity, None)?.cert_pem,
                    }])
                }
            }
            GenerateSpec::SelfSignedTlsPairOf { pair_of } => {
                let (common_name, validity) = self.tls_cert_recipe(pair_of)?;
                let material = generate_self_signed_tls(common_name, validity, None)?;
                Ok(vec![
                    GeneratedWrite {
                        key_id: key_id.to_string(),
                        value: material.private_key_pem,
                    },
                    GeneratedWrite {
                        key_id: pair_of.clone(),
                        value: material.cert_pem,
                    },
                ])
            }
            GenerateSpec::AsciiPrintable { .. }
            | GenerateSpec::Base64 { .. }
            | GenerateSpec::Hex { .. }
            | GenerateSpec::AgeX25519 => Ok(vec![GeneratedWrite {
                key_id: key_id.to_string(),
                value: generate_value(spec)?,
            }]),
        }
    }

    fn tls_pair_key_for_cert(&self, cert_key: &str) -> Option<String> {
        self.catalog.keys.iter().find_map(|(name, entry)| {
            matches!(
                entry.generate.as_ref(),
                // ubs false positive: cert_key and pair_of are catalog key names, not secret material
                /* ubs:ignore */
                Some(GenerateSpec::SelfSignedTlsPairOf { pair_of }) if pair_of == cert_key
            )
            .then(|| name.clone())
        })
    }

    fn tls_cert_recipe(&self, cert_key: &str) -> Result<(&str, &str), ManagerError> {
        let entry = self
            .catalog
            .keys
            .get(cert_key)
            .ok_or_else(|| ManagerError::UnknownKey(cert_key.to_string()))?;
        match entry.generate.as_ref() {
            Some(GenerateSpec::SelfSignedTls {
                common_name,
                validity,
            }) => Ok((common_name, validity)),
            _ => Err(ManagerError::Backend(BackendError::Backend(format!(
                "self-signed-tls-pair-of references non-certificate key `{cert_key}`"
            )))),
        }
    }

    async fn try_existing_value(&self, key_id: &str) -> Result<Option<Vec<u8>>, ManagerError> {
        let routed = self.resolve(key_id)?;
        require_class(
            "generate",
            key_id,
            routed.class(),
            &[Class::Value, Class::Public],
        )?;
        match routed.backend.kv_get(routed.path(), None).await {
            Ok(value) => Ok(Some(value.value)),
            Err(BackendError::KeyNotFound(_)) => Ok(None),
            Err(e) => Err(ManagerError::Backend(e)),
        }
    }
}

/// One generated KV write. `key_id` is the catalog key, not the backend path.
pub(crate) struct GeneratedWrite {
    pub(crate) key_id: String,
    pub(crate) value: Vec<u8>,
}

/// Check that `algorithm` matches the key's catalog AEAD `keyType`, returning
/// [`ManagerError::AlgorithmMismatch`] otherwise. A symmetric key always carries
/// an AEAD `KeyAlgorithm`; a key with a non-AEAD (or absent) type cannot encrypt.
fn require_aead_match(
    key_id: &str,
    key_type: Option<KeyAlgorithm>,
    algorithm: AeadAlgorithm,
) -> Result<(), ManagerError> {
    let actual = match key_type {
        Some(KeyAlgorithm::Aes256Gcm) => AeadAlgorithm::Aes256Gcm,
        Some(KeyAlgorithm::ChaCha20Poly1305) => AeadAlgorithm::Chacha20Poly1305,
        // Symmetric keys are always AEAD; a signing/value type here is a
        // misconfigured catalog (or a non-symmetric key slipping past the class
        // check), fail closed as a mismatch.
        _ => {
            return Err(ManagerError::AlgorithmMismatch {
                key: key_id.to_string(),
                requested: algorithm,
                actual: "non-aead",
            });
        }
    };
    if actual == algorithm {
        Ok(())
    } else {
        Err(ManagerError::AlgorithmMismatch {
            key: key_id.to_string(),
            requested: algorithm,
            actual: match actual {
                AeadAlgorithm::Aes256Gcm => "aes-256-gcm",
                AeadAlgorithm::Chacha20Poly1305 => "chacha20-poly1305",
            },
        })
    }
}

const fn sign_options_for_key(key_type: Option<KeyAlgorithm>) -> SignOptions {
    match key_type {
        Some(KeyAlgorithm::Rsa2048) => SignOptions::Rs256Pkcs1v15Sha256,
        Some(KeyAlgorithm::EcdsaP256) => SignOptions::Es256,
        Some(KeyAlgorithm::EcdsaP384) => SignOptions::Es384,
        Some(KeyAlgorithm::EcdsaP521) => SignOptions::Es512,
        _ => SignOptions::Default,
    }
}

/// Resolve the ML-DSA [`SignatureAlgorithm`] for a routed key, failing closed if
/// the key is not an ML-DSA signing key (a routing invariant: the service only
/// dispatches ML-DSA keys here).
fn require_ml_dsa(key_id: &str, routed: &Routed<'_>) -> Result<SignatureAlgorithm, ManagerError> {
    routed
        .key_type()
        .and_then(ml_dsa_signature_algorithm)
        .ok_or_else(|| ManagerError::OpNotValidForClass {
            op: "provider_dispatch",
            key: key_id.to_string(),
            class: routed.class(),
        })
}

/// Choose the crypto provider for a routed PQC key from its catalog
/// policy/custody labels, the caller's gate, and a live backend capability probe
/// (`basil-wuj.10`).
///
/// `native` is the key's backend-native [`NativeAlgorithm`], if any. The backend
/// is asked (cheaply, fail-closed) whether it natively supports that
/// algorithm; the answer drives [`select_provider`]: a `backend-required` key
/// needs native support (else it fails closed), and a `backend-preferred` key
/// uses the backend natively when supported but otherwise falls back to the
/// local-software provider (policy + custody permitting). A key with no
/// `native` mapping (e.g. ML-KEM, which has no native backend target) probes as
/// unsupported and so always routes to the local-software provider.
fn select_provider_for(
    routed: &Routed<'_>,
    native: Option<NativeAlgorithm>,
    gate: ProviderGate,
    op: &'static str,
) -> Result<CryptoProviderId, ProviderError> {
    let metadata = ProviderMetadata::from_key(routed.entry);
    let backend_native_supported =
        native.is_some_and(|algorithm| routed.backend.supports_native_algorithm(algorithm));
    select_provider(
        metadata,
        backend_native_supported,
        gate.local_software_allowed,
        op,
    )
}

/// Build the audit-facing [`ProviderDispatch`] for a completed provider op.
const fn provider_dispatch(
    provider: CryptoProviderId,
    algorithm: SignatureAlgorithm,
) -> ProviderDispatch {
    ProviderDispatch {
        provider,
        algorithm: algorithm.token(),
        custody: provider.custody_mode(),
    }
}

/// Build the audit-facing [`ProviderDispatch`] for a completed ML-KEM
/// envelope (`wrap`/`unwrap`) op.
const fn kem_provider_dispatch(
    provider: CryptoProviderId,
    kem: ProviderKemAlgorithm,
) -> ProviderDispatch {
    ProviderDispatch {
        provider,
        algorithm: kem.token(),
        custody: provider.custody_mode(),
    }
}

/// The printable ASCII alphabet for `ascii-printable` generation: `!`..=`~`
/// (the 94 visible, non-space ASCII characters).
const ASCII_PRINTABLE: &[u8] = b"!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";

/// Generate a fresh `value` from its catalog `generate` recipe (`vault-a2p`
/// rotation path). Implements byte-string formats and in-process age identities.
pub(crate) fn generate_value(spec: &GenerateSpec) -> Result<Vec<u8>, ManagerError> {
    use base64::Engine as _;
    use std::fmt::Write as _;

    let mut rng = rand::thread_rng();
    match spec {
        GenerateSpec::AsciiPrintable { bytes } => {
            let mut out = Vec::with_capacity(*bytes as usize);
            for _ in 0..*bytes {
                // Rejection-free index: ASCII_PRINTABLE has 94 entries; modulo
                // bias over a u32 is negligible and acceptable for a password.
                let idx = (rng.next_u32() as usize) % ASCII_PRINTABLE.len();
                out.push(ASCII_PRINTABLE.get(idx).copied().unwrap_or(b'!'));
            }
            Ok(out)
        }
        GenerateSpec::Base64 { bytes } => {
            let mut raw = vec![0u8; *bytes as usize];
            rng.fill_bytes(&mut raw);
            Ok(base64::engine::general_purpose::STANDARD
                .encode(&raw)
                .into_bytes())
        }
        GenerateSpec::Hex { bytes } => {
            let mut raw = vec![0u8; *bytes as usize];
            rng.fill_bytes(&mut raw);
            let mut out = String::with_capacity(*bytes as usize * 2);
            for b in &raw {
                let _ = write!(out, "{b:02x}");
            }
            Ok(out.into_bytes())
        }
        GenerateSpec::AgeX25519 => Ok(age::x25519::Identity::generate()
            .to_string()
            .expose_secret()
            .as_bytes()
            .to_vec()),
        GenerateSpec::SelfSignedTls {
            common_name,
            validity,
        } => Ok(generate_self_signed_tls(common_name, validity, None)?.cert_pem),
        GenerateSpec::SelfSignedTlsPairOf { .. } => Err(ManagerError::Backend(
            BackendError::Backend("self-signed-tls-pair-of needs catalog pair context".into()),
        )),
    }
}

struct TlsMaterial {
    cert_pem: Vec<u8>,
    private_key_pem: Vec<u8>,
}

fn generate_self_signed_tls(
    common_name: &str,
    validity: &str,
    existing_key_pem: Option<&[u8]>,
) -> Result<TlsMaterial, ManagerError> {
    let dir = std::env::temp_dir().join(format!("basil-self-signed-tls-{}", Uuid::new_v4()));
    std::fs::create_dir(&dir).map_err(|e| {
        ManagerError::Backend(BackendError::Backend(format!(
            "self-signed-tls tempdir create: {e}"
        )))
    })?;

    let result = generate_self_signed_tls_in_dir(&dir, common_name, validity, existing_key_pem);
    let cleanup_result = std::fs::remove_dir_all(&dir);
    match (result, cleanup_result) {
        (Ok(material), Ok(()) | Err(_)) => Ok(material),
        (Err(err), _) => Err(err),
    }
}

fn generate_self_signed_tls_in_dir(
    dir: &Path,
    common_name: &str,
    validity: &str,
    existing_key_pem: Option<&[u8]>,
) -> Result<TlsMaterial, ManagerError> {
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    if let Some(key) = existing_key_pem {
        write_secret_file(&key_path, key)?;
    }

    let mut command = Command::new("step");
    command
        .arg("certificate")
        .arg("create")
        .arg(common_name)
        .arg(&cert_path);
    if existing_key_pem.is_none() {
        command.arg(&key_path);
    }
    command
        .arg("--profile")
        .arg("self-signed")
        .arg("--subtle")
        .arg("--not-after")
        .arg(validity)
        .arg("--force");
    if existing_key_pem.is_some() {
        command.arg("--key").arg(&key_path);
    } else {
        command.arg("--no-password").arg("--insecure");
    }

    let output = command.output().map_err(|e| {
        ManagerError::Backend(BackendError::Backend(format!(
            "self-signed-tls step execution failed: {e}"
        )))
    })?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        return Err(ManagerError::Backend(BackendError::Backend(format!(
            "self-signed-tls step failed: {}",
            detail.trim()
        ))));
    }

    let cert_pem = std::fs::read(&cert_path).map_err(|e| {
        ManagerError::Backend(BackendError::Backend(format!(
            "self-signed-tls read cert: {e}"
        )))
    })?;
    let private_key_pem = std::fs::read(&key_path).map_err(|e| {
        ManagerError::Backend(BackendError::Backend(format!(
            "self-signed-tls read key: {e}"
        )))
    })?;
    Ok(TlsMaterial {
        cert_pem,
        private_key_pem,
    })
}

fn write_secret_file(path: &Path, contents: &[u8]) -> Result<(), ManagerError> {
    use std::io::Write as _;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path).map_err(|e| {
        ManagerError::Backend(BackendError::Backend(format!(
            "self-signed-tls write key: {e}"
        )))
    })?;
    file.write_all(contents).map_err(|e| {
        ManagerError::Backend(BackendError::Backend(format!(
            "self-signed-tls write key: {e}"
        )))
    })
}

/// Map a catalog [`KeyEntry`] onto the wire [`CatalogKind`] reported by `list` (§7):
/// `asymmetric`/`public` → `signing`, `symmetric` → `encryption`, `value` →
/// `value`.
const fn key_kind(entry: &KeyEntry) -> CatalogKind {
    match entry.class {
        Class::Asymmetric | Class::Public => CatalogKind::Signing,
        // A sealing key is a KEM recipient (encryption-shaped) for `list`.
        Class::Symmetric | Class::Sealing => CatalogKind::Encryption,
        Class::Value => CatalogKind::Value,
    }
}

/// The wire [`KeyType`] for a catalog key's algorithm, used as the `list`
/// fallback when the backend is unreachable (the catalog's declared type). Value
/// keys (and symmetric AEAD keys, which have no wire `KeyType`) yield `None`.
const fn wire_key_type(entry: &KeyEntry) -> Option<KeyType> {
    match entry.key_type {
        Some(KeyAlgorithm::Ed25519) => Some(KeyType::Ed25519),
        Some(KeyAlgorithm::Ed25519Nkey) => Some(KeyType::Ed25519Nkey),
        Some(KeyAlgorithm::Rsa2048) => Some(KeyType::Rsa2048),
        Some(KeyAlgorithm::EcdsaP256) => Some(KeyType::EcdsaP256),
        Some(KeyAlgorithm::EcdsaP384) => Some(KeyType::EcdsaP384),
        Some(KeyAlgorithm::EcdsaP521) => Some(KeyType::EcdsaP521),
        // ML-DSA software-custody signing keys carry a wire `KeyType` so `list`
        // reports their parameter level.
        Some(KeyAlgorithm::MlDsa44) => Some(KeyType::MlDsa44),
        Some(KeyAlgorithm::MlDsa65) => Some(KeyType::MlDsa65),
        Some(KeyAlgorithm::MlDsa87) => Some(KeyType::MlDsa87),
        // AEAD suites are an AeadAlgorithm on the wire, not a KeyType; sealing
        // keys (X25519 and ML-KEM alike) have no wire `KeyType`: `list` reports
        // them via the catalog `kind`, not a `KeyType`.
        Some(
            KeyAlgorithm::Aes256Gcm
            | KeyAlgorithm::ChaCha20Poly1305
            | KeyAlgorithm::X25519
            | KeyAlgorithm::MlKem512
            | KeyAlgorithm::MlKem768
            | KeyAlgorithm::MlKem1024,
        )
        | None => None,
    }
}

/// The effective engine for a key: the catalog value, or the §2.2 inference from
/// the key's [`Class`] when the catalog omits it (crypto → transit, stored → kv2).
fn effective_engine(entry: &KeyEntry) -> Engine {
    entry.effective_engine()
}

/// Check that `op` is valid for `class`, returning [`ManagerError::OpNotValidForClass`]
/// otherwise. `allowed` is the set of classes the op is defined on.
fn require_class(
    op: &'static str,
    key_id: &str,
    class: Class,
    allowed: &[Class],
) -> Result<(), ManagerError> {
    if allowed.contains(&class) {
        Ok(())
    } else {
        Err(ManagerError::OpNotValidForClass {
            op,
            key: key_id.to_string(),
            class,
        })
    }
}

fn require_x25519_sealing_key(
    key_id: &str,
    actual: Option<KeyAlgorithm>,
) -> Result<(), ManagerError> {
    match actual {
        Some(KeyAlgorithm::X25519) => Ok(()),
        Some(other) => Err(ManagerError::KemAlgorithmMismatch {
            key: key_id.to_string(),
            requested: "x25519",
            actual: other.token(),
        }),
        None => Err(ManagerError::KemAlgorithmMismatch {
            key: key_id.to_string(),
            requested: "x25519",
            actual: "none",
        }),
    }
}

/// The wire [`KeyType`] for an ML-DSA signing algorithm. Only ever called for an
/// ML-DSA algorithm (the caller filters via [`ml_dsa_signature_algorithm`]); the
/// classical arms are unreachable and present only for exhaustiveness.
const fn ml_dsa_wire_key_type(algorithm: SignatureAlgorithm) -> KeyType {
    match algorithm {
        SignatureAlgorithm::MlDsa44 => KeyType::MlDsa44,
        SignatureAlgorithm::MlDsa65 => KeyType::MlDsa65,
        SignatureAlgorithm::MlDsa87 => KeyType::MlDsa87,
        SignatureAlgorithm::Ed25519
        | SignatureAlgorithm::Ed25519Nkey
        | SignatureAlgorithm::Rs256
        | SignatureAlgorithm::Es256 => KeyType::Ed25519,
    }
}

/// The wire [`KeyType`] for an ML-KEM sealing algorithm: the parameter level a
/// `get_public_key` on a software-custody ML-KEM sealing key reports alongside
/// the encapsulation key (basil-4ybx). The dual of [`ml_dsa_wire_key_type`].
const fn ml_kem_wire_key_type(kem: ProviderKemAlgorithm) -> KeyType {
    match kem {
        ProviderKemAlgorithm::MlKem512 => KeyType::MlKem512,
        ProviderKemAlgorithm::MlKem768 => KeyType::MlKem768,
        ProviderKemAlgorithm::MlKem1024 => KeyType::MlKem1024,
    }
}

/// Map a catalog [`KeyAlgorithm`] to its provider ML-KEM parameter set, or `None`
/// for any non-ML-KEM algorithm. The routing signal for `new_key` on a sealing
/// key (the dual of [`ml_dsa_signature_algorithm`] for signing keys).
const fn ml_kem_provider_algorithm(algorithm: KeyAlgorithm) -> Option<ProviderKemAlgorithm> {
    match algorithm {
        KeyAlgorithm::MlKem512 => Some(ProviderKemAlgorithm::MlKem512),
        KeyAlgorithm::MlKem768 => Some(ProviderKemAlgorithm::MlKem768),
        KeyAlgorithm::MlKem1024 => Some(ProviderKemAlgorithm::MlKem1024),
        KeyAlgorithm::Ed25519
        | KeyAlgorithm::Ed25519Nkey
        | KeyAlgorithm::Rsa2048
        | KeyAlgorithm::EcdsaP256
        | KeyAlgorithm::EcdsaP384
        | KeyAlgorithm::EcdsaP521
        | KeyAlgorithm::Aes256Gcm
        | KeyAlgorithm::ChaCha20Poly1305
        | KeyAlgorithm::X25519
        | KeyAlgorithm::MlDsa44
        | KeyAlgorithm::MlDsa65
        | KeyAlgorithm::MlDsa87 => None,
    }
}

fn require_ml_kem_sealing_key(
    key_id: &str,
    actual: Option<KeyAlgorithm>,
    requested: ProviderKemAlgorithm,
) -> Result<(), ManagerError> {
    let expected = match requested {
        ProviderKemAlgorithm::MlKem512 => KeyAlgorithm::MlKem512,
        ProviderKemAlgorithm::MlKem768 => KeyAlgorithm::MlKem768,
        ProviderKemAlgorithm::MlKem1024 => KeyAlgorithm::MlKem1024,
    };
    match actual {
        Some(found) if found == expected => Ok(()),
        Some(found) => Err(ManagerError::KemAlgorithmMismatch {
            key: key_id.to_string(),
            requested: requested.token(),
            actual: found.token(),
        }),
        None => Err(ManagerError::KemAlgorithmMismatch {
            key: key_id.to_string(),
            requested: requested.token(),
            actual: "none",
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{KeyMetadata, KvValue};
    use crate::core::crypto_provider::{SoftwareCustodyCatalog, encode_record_bytes};
    use crate::ml_kem_envelope;
    use async_trait::async_trait;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A mock backend that records the last `(op, path)` it was dispatched with,
    /// so a test can assert routing reached the right instance + path.
    #[derive(Default)]
    struct MockBackend {
        name: &'static str,
        last_path: std::sync::Mutex<Option<String>>,
        last_spiffe_id: std::sync::Mutex<Option<String>>,
        new_key_calls: AtomicUsize,
        rotate_calls: AtomicUsize,
        kv_put_calls: AtomicUsize,
        /// The `latest_version` the mock reports + bumps on rotate.
        latest_version: AtomicUsize,
        /// The most recent `(min_decryption_version, min_available_version)`
        /// passed to `configure_versions`, so a test can assert the grace/
        /// retention floor the manager computed.
        last_versions_config: std::sync::Mutex<Option<(Option<u32>, Option<u32>)>>,
        /// The last value written via `kv_put` (the regenerated value on rotate).
        last_kv_value: std::sync::Mutex<Option<Vec<u8>>>,
        last_sign_options: std::sync::Mutex<Option<SignOptions>>,
        last_verify_options: std::sync::Mutex<Option<SignOptions>>,
        last_new_key_type: std::sync::Mutex<Option<KeyType>>,
        /// Path-keyed KV store so a test can seed distinct values at distinct
        /// paths (e.g. a sealing key's private at `path` and its out-of-band
        /// public at `public_path`). A `kv_get`/`kv_get_secret` returns the value
        /// stored at the requested path; absent a path-specific seed it falls back
        /// to `last_kv_value` (so the many tests that only set `last_kv_value`
        /// keep working unchanged).
        kv_store: std::sync::Mutex<BTreeMap<String, Vec<u8>>>,
        kv_put_log: std::sync::Mutex<Vec<(String, Vec<u8>)>>,
    }

    impl MockBackend {
        fn new(name: &'static str) -> Arc<Self> {
            Arc::new(Self {
                name,
                last_path: std::sync::Mutex::new(None),
                last_spiffe_id: std::sync::Mutex::new(None),
                new_key_calls: AtomicUsize::new(0),
                rotate_calls: AtomicUsize::new(0),
                kv_put_calls: AtomicUsize::new(0),
                latest_version: AtomicUsize::new(5),
                last_versions_config: std::sync::Mutex::new(None),
                last_kv_value: std::sync::Mutex::new(None),
                last_sign_options: std::sync::Mutex::new(None),
                last_verify_options: std::sync::Mutex::new(None),
                last_new_key_type: std::sync::Mutex::new(None),
                kv_store: std::sync::Mutex::new(BTreeMap::new()),
                kv_put_log: std::sync::Mutex::new(Vec::new()),
            })
        }

        /// Seed a specific KV path with a value (used to provision a sealing
        /// key's out-of-band public separately from its private).
        fn seed_kv(&self, path: &str, value: Vec<u8>) {
            self.kv_store
                .lock()
                .unwrap()
                .insert(path.to_string(), value);
        }

        /// Resolve a KV read: a path-seeded value if present, else the last
        /// `kv_put` value, else a default. Mirrors the read path for both
        /// `kv_get` and `kv_get_secret`.
        fn kv_lookup(&self, path: &str) -> Vec<u8> {
            if let Some(v) = self.kv_store.lock().unwrap().get(path) {
                return v.clone();
            }
            self.last_kv_value
                .lock()
                .unwrap()
                .clone()
                .unwrap_or_else(|| b"stored-value".to_vec())
        }

        fn last_path(&self) -> Option<String> {
            self.last_path.lock().unwrap().clone()
        }

        fn last_versions_config(&self) -> Option<(Option<u32>, Option<u32>)> {
            *self.last_versions_config.lock().unwrap()
        }

        fn last_kv_value(&self) -> Option<Vec<u8>> {
            self.last_kv_value.lock().unwrap().clone()
        }

        fn last_spiffe_id(&self) -> Option<String> {
            self.last_spiffe_id.lock().unwrap().clone()
        }

        fn kv_put_log(&self) -> Vec<(String, Vec<u8>)> {
            self.kv_put_log.lock().unwrap().clone()
        }

        fn last_sign_options(&self) -> Option<SignOptions> {
            *self.last_sign_options.lock().unwrap()
        }

        fn last_verify_options(&self) -> Option<SignOptions> {
            *self.last_verify_options.lock().unwrap()
        }

        fn last_new_key_type(&self) -> Option<KeyType> {
            *self.last_new_key_type.lock().unwrap()
        }
    }

    /// A thin newtype so the same `Arc<MockBackend>` can be both inspected by the
    /// test and boxed into the manager's `Box<dyn Backend>` map.
    struct MockHandle(Arc<MockBackend>);

    #[async_trait]
    impl Backend for MockHandle {
        fn kind(&self) -> &'static str {
            self.0.name
        }

        async fn new_key(&self, key_type: KeyType) -> Result<NewKey, BackendError> {
            self.0.new_key_calls.fetch_add(1, Ordering::SeqCst);
            *self.0.last_new_key_type.lock().unwrap() = Some(key_type);
            Ok(NewKey {
                key_id: format!("{}-newkey", self.0.name),
                public_key: vec![1, 2, 3],
            })
        }

        async fn public_key(&self, key_id: &str) -> Result<Vec<u8>, BackendError> {
            *self.0.last_path.lock().unwrap() = Some(key_id.to_string());
            Ok(vec![9, 9, 9])
        }

        async fn public_key_with_meta(&self, key_id: &str) -> Result<PublicKey, BackendError> {
            *self.0.last_path.lock().unwrap() = Some(key_id.to_string());
            Ok(PublicKey {
                public_key: vec![9, 9, 9],
                // A non-default type+version so a test proves they are plumbed
                // (not the old hardcoded ed25519/1).
                key_type: KeyType::Ed25519Nkey,
                version: 7,
            })
        }

        async fn key_metadata(&self, key_id: &str) -> Result<KeyMetadata, BackendError> {
            *self.0.last_path.lock().unwrap() = Some(key_id.to_string());
            Ok(KeyMetadata {
                key_type: Some(KeyType::Ed25519),
                latest_version: u32::try_from(self.0.latest_version.load(Ordering::SeqCst))
                    .unwrap_or(u32::MAX),
            })
        }

        async fn import(
            &self,
            key_id: &str,
            _key_type: KeyType,
            _material: &KeyMaterial,
        ) -> Result<NewKey, BackendError> {
            *self.0.last_path.lock().unwrap() = Some(key_id.to_string());
            Ok(NewKey {
                key_id: key_id.to_string(),
                public_key: vec![0xEE, 0xEE],
            })
        }

        async fn sign(&self, key_id: &str, _message: &[u8]) -> Result<Vec<u8>, BackendError> {
            *self.0.last_path.lock().unwrap() = Some(key_id.to_string());
            *self.0.last_sign_options.lock().unwrap() = Some(SignOptions::Default);
            Ok(vec![0xAB, 0xCD])
        }

        async fn sign_with_options(
            &self,
            key_id: &str,
            message: &[u8],
            options: SignOptions,
        ) -> Result<Vec<u8>, BackendError> {
            let mut signature = self.sign(key_id, message).await?;
            *self.0.last_sign_options.lock().unwrap() = Some(options);
            if options == SignOptions::Rs256Pkcs1v15Sha256 {
                signature.push(0x52);
            } else if options == SignOptions::Es256 {
                signature.push(0x45);
            } else if options == SignOptions::Es384 {
                signature.push(0x46);
            } else if options == SignOptions::Es512 {
                signature.push(0x47);
            }
            Ok(signature)
        }

        async fn verify(
            &self,
            key_id: &str,
            _message: &[u8],
            _signature: &[u8],
        ) -> Result<bool, BackendError> {
            *self.0.last_path.lock().unwrap() = Some(key_id.to_string());
            *self.0.last_verify_options.lock().unwrap() = Some(SignOptions::Default);
            Ok(true)
        }

        async fn verify_with_options(
            &self,
            key_id: &str,
            message: &[u8],
            signature: &[u8],
            options: SignOptions,
        ) -> Result<bool, BackendError> {
            let valid = self.verify(key_id, message, signature).await?;
            *self.0.last_verify_options.lock().unwrap() = Some(options);
            Ok(valid)
        }

        /// A deterministic stand-in for transit AEAD: the "ciphertext" is the
        /// plaintext X- prefixed with the AAD length + AAD, so `decrypt` can
        /// recover the plaintext and detect an AAD mismatch (returning the opaque
        /// `DecryptFailed`). The broker owns the nonce (here empty, as transit
        /// embeds it). `key_version` is the current latest.
        async fn encrypt(
            &self,
            key_id: &str,
            algorithm: AeadAlgorithm,
            plaintext: &[u8],
            aad: Option<&[u8]>,
        ) -> Result<CiphertextEnvelope, BackendError> {
            *self.0.last_path.lock().unwrap() = Some(key_id.to_string());
            let aad = aad.unwrap_or(&[]);
            let mut ciphertext = Vec::new();
            ciphertext.push(u8::try_from(aad.len()).unwrap_or(u8::MAX));
            ciphertext.extend_from_slice(aad);
            ciphertext.extend_from_slice(plaintext);
            Ok(CiphertextEnvelope {
                alg: algorithm,
                key_version: u32::try_from(self.0.latest_version.load(Ordering::SeqCst))
                    .unwrap_or(u32::MAX),
                nonce: Vec::new(),
                ciphertext,
            })
        }

        async fn decrypt(
            &self,
            key_id: &str,
            envelope: &CiphertextEnvelope,
            aad: Option<&[u8]>,
        ) -> Result<Vec<u8>, BackendError> {
            *self.0.last_path.lock().unwrap() = Some(key_id.to_string());
            let aad = aad.unwrap_or(&[]);
            let ct = &envelope.ciphertext;
            let aad_len = *ct.first().ok_or(BackendError::DecryptFailed)? as usize;
            let bound = ct.get(1..1 + aad_len).ok_or(BackendError::DecryptFailed)?;
            // AAD mismatch -> opaque DecryptFailed (no oracle).
            if bound != aad {
                return Err(BackendError::DecryptFailed);
            }
            Ok(ct
                .get(1 + aad_len..)
                .ok_or(BackendError::DecryptFailed)?
                .to_vec())
        }

        async fn rotate(&self, key_id: &str) -> Result<u32, BackendError> {
            *self.0.last_path.lock().unwrap() = Some(key_id.to_string());
            self.0.rotate_calls.fetch_add(1, Ordering::SeqCst);
            let v = self.0.latest_version.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(u32::try_from(v).unwrap_or(u32::MAX))
        }

        async fn kv_get(
            &self,
            key_id: &str,
            version: Option<u32>,
        ) -> Result<KvValue, BackendError> {
            *self.0.last_path.lock().unwrap() = Some(key_id.to_string());
            // A path-seeded value wins (distinct private/public paths); otherwise
            // fall back to the last `kv_put` value (or a default). The version is
            // the requested one, or the current latest when none was asked.
            let value = self.0.kv_lookup(key_id);
            let version = version.unwrap_or_else(|| {
                u32::try_from(self.0.latest_version.load(Ordering::SeqCst)).unwrap_or(u32::MAX)
            });
            Ok(KvValue { value, version })
        }

        async fn kv_get_secret(
            &self,
            key_id: &str,
            _version: Option<u32>,
        ) -> Result<Zeroizing<Vec<u8>>, BackendError> {
            *self.0.last_path.lock().unwrap() = Some(key_id.to_string());
            Ok(Zeroizing::new(self.0.kv_lookup(key_id)))
        }

        async fn kv_put(&self, key_id: &str, value: &[u8]) -> Result<u32, BackendError> {
            *self.0.last_path.lock().unwrap() = Some(key_id.to_string());
            self.0.kv_put_calls.fetch_add(1, Ordering::SeqCst);
            *self.0.last_kv_value.lock().unwrap() = Some(value.to_vec());
            self.0
                .kv_store
                .lock()
                .unwrap()
                .insert(key_id.to_string(), value.to_vec());
            self.0
                .kv_put_log
                .lock()
                .unwrap()
                .push((key_id.to_string(), value.to_vec()));
            let v = self.0.latest_version.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(u32::try_from(v).unwrap_or(u32::MAX))
        }

        async fn configure_versions(
            &self,
            key_id: &str,
            min_decryption_version: Option<u32>,
            min_available_version: Option<u32>,
        ) -> Result<(), BackendError> {
            *self.0.last_path.lock().unwrap() = Some(key_id.to_string());
            *self.0.last_versions_config.lock().unwrap() =
                Some((min_decryption_version, min_available_version));
            Ok(())
        }

        async fn issue_x509_svid(
            &self,
            key_id: &str,
            spiffe_id: &str,
            _ttl_seconds: u64,
        ) -> Result<X509Svid, BackendError> {
            *self.0.last_path.lock().unwrap() = Some(key_id.to_string());
            *self.0.last_spiffe_id.lock().unwrap() = Some(spiffe_id.to_string());
            Ok(X509Svid {
                cert_chain_der: vec![vec![1, 2, 3]],
                leaf_private_key_der: zeroize::Zeroizing::new(vec![4, 5, 6]),
                bundle_der: vec![vec![7, 8, 9]],
            })
        }

        async fn issue_x509_cert(
            &self,
            key_id: &str,
            request: &X509CertRequest,
        ) -> Result<X509Svid, BackendError> {
            *self.0.last_path.lock().unwrap() = Some(key_id.to_string());
            // Reuse the spiffe-id recording slot to capture the cert subject.
            *self.0.last_spiffe_id.lock().unwrap() = Some(request.common_name.clone());
            Ok(X509Svid {
                cert_chain_der: vec![vec![0xCE, 0x27]],
                leaf_private_key_der: zeroize::Zeroizing::new(vec![0xDE, 0xAD]),
                bundle_der: vec![vec![0xCA, 0xFE]],
            })
        }
    }

    /// Two backends + keys routed to each, exercising every class.
    ///   asym.signer  -> backend "primary", transit key name "signer"
    ///   sym.box      -> backend "secondary", transit key name "box"
    ///   web.value    -> backend "primary",  kv path "secret/data/web/value"
    ///   web.cert     -> backend "secondary", public, kv path "secret/data/web/cert"
    ///
    /// Transit `path`s are the BARE key name (§2.2): the transit backend builds
    /// `transit/<verb>/<name>` from it; a `transit/keys/<name>` path would 404
    /// against a live Vault server (`vault-w3n`).
    const CATALOG: &str = r#"{
      "schemaVersion": 1,
      "backends": {
        "primary":   {
          "kind": "vault", "addr": "https://127.0.0.1:8200",
          "engines": ["transit", "kv2"], "capabilities": [],
          "mintKeyTypes": ["ed25519", "ed25519-nkey", "rsa-2048", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521"]
        },
        "secondary": {
          "kind": "vault", "addr": "https://127.0.0.1:8201",
          "engines": ["transit", "kv2"], "capabilities": [],
          "mintKeyTypes": ["ed25519", "ed25519-nkey", "rsa-2048", "ecdsa-p256"]
        }
      },
      "keys": {
        "asym.signer": {
          "class": "asymmetric", "keyType": "ed25519", "backend": "primary",
          "path": "signer", "writable": true, "missing": "error",
          "description": "a signing key"
        },
        "asym.nkey": {
          "class": "asymmetric", "keyType": "ed25519-nkey", "backend": "primary",
          "path": "nkey-signer", "writable": true, "missing": "error",
          "description": "a NATS nkey signing key"
        },
        "asym.rsa": {
          "class": "asymmetric", "keyType": "rsa-2048", "backend": "primary",
          "path": "rsa-signer", "writable": true, "missing": "error",
          "description": "an RSA signing key"
        },
        "asym.ecdsa": {
          "class": "asymmetric", "keyType": "ecdsa-p256", "backend": "primary",
          "path": "ecdsa-signer", "writable": true, "missing": "error",
          "description": "an ECDSA P-256 signing key"
        },
        "asym.ecdsa384": {
          "class": "asymmetric", "keyType": "ecdsa-p384", "backend": "primary",
          "path": "ecdsa384-signer", "writable": true, "missing": "error",
          "description": "an ECDSA P-384 signing key"
        },
        "asym.ecdsa521": {
          "class": "asymmetric", "keyType": "ecdsa-p521", "backend": "primary",
          "path": "ecdsa521-signer", "writable": true, "missing": "error",
          "description": "an ECDSA P-521 signing key"
        },
        "sym.box": {
          "class": "symmetric", "keyType": "aes-256-gcm", "backend": "secondary",
          "path": "box", "writable": true, "missing": "error",
          "description": "a symmetric key"
        },
        "web.value": {
          "class": "value", "backend": "primary", "engine": "kv2",
          "path": "secret/data/web/value", "writable": true, "missing": "error",
          "description": "an opaque value"
        },
        "gen.value": {
          "class": "value", "backend": "primary", "engine": "kv2",
          "path": "secret/data/gen/value", "writable": true, "missing": "generate",
          "generate": { "format": "ascii-printable", "bytes": 24 },
          "description": "a generate-able value (rotate regenerates)"
        },
        "tls.cert": {
          "class": "public", "backend": "primary", "engine": "kv2",
          "path": "secret/data/tls/cert", "writable": false, "missing": "generate",
          "generate": { "format": "self-signed-tls", "commonName": "example.test", "validity": "1h" },
          "description": "a generated self-signed cert"
        },
        "tls.key": {
          "class": "value", "backend": "primary", "engine": "kv2",
          "path": "secret/data/tls/key", "writable": true, "missing": "generate",
          "generate": { "format": "self-signed-tls-pair-of", "pairOf": "tls.cert" },
          "description": "the private key paired with tls.cert"
        },
        "web.cert": {
          "class": "public", "backend": "secondary", "engine": "kv2",
          "path": "secret/data/web/cert", "writable": false, "missing": "warn",
          "description": "a public cert"
        },
        "spiffe.issuer": {
          "class": "asymmetric", "keyType": "ed25519", "backend": "secondary", "engine": "pki",
          "path": "pki/issue/workload", "writable": false, "missing": "error",
          "description": "a pki issuer role"
        },
        "enroll.sealing": {
          "class": "sealing", "keyType": "x25519", "backend": "primary", "engine": "kv2",
          "path": "secret/data/enroll/x25519",
          "publicPath": "secret/data/enroll/x25519-public",
          "writable": true, "missing": "error",
          "description": "an x25519 enrollment sealing key"
        },
        "enroll.mlkem": {
          "class": "sealing", "keyType": "ml-kem-768", "backend": "primary", "engine": "kv2",
          "path": "secret/data/enroll/ml-kem-768",
          "publicPath": "secret/data/enroll/ml-kem-768-public",
          "labels": [
            "crypto_provider=local-software",
            "crypto_provider_version=1",
            "pqc_algorithm=ml-kem-768",
            "pqc_custody=software-encrypted",
            "crypto_provider_policy=local-software",
            "pqc_storage_key=pqc/storage/wrap"
          ],
          "writable": true, "missing": "error",
          "description": "an ML-KEM enrollment sealing key"
        },
        "kv2.signer": {
          "class": "asymmetric", "keyType": "ed25519", "backend": "primary", "engine": "kv2",
          "path": "secret/data/kv2/signer",
          "publicPath": "secret/data/kv2/signer-public",
          "writable": true, "missing": "error",
          "description": "a value-store Ed25519 materialize-to-sign key"
        }
      }
    }"#;

    fn parse_catalog(json: &str) -> Catalog {
        serde_json::from_str(json).expect("catalog parses")
    }

    /// Build a manager over the fixture catalog, returning the manager plus the
    /// two mock handles so tests can inspect what they were dispatched.
    fn fixture() -> (BackendManager, Arc<MockBackend>, Arc<MockBackend>) {
        let primary = MockBackend::new("primary");
        let secondary = MockBackend::new("secondary");
        let mut backends: BTreeMap<String, Box<dyn Backend>> = BTreeMap::new();
        backends.insert("primary".into(), Box::new(MockHandle(primary.clone())));
        backends.insert("secondary".into(), Box::new(MockHandle(secondary.clone())));
        let mgr = BackendManager::new(parse_catalog(CATALOG), backends)
            .expect("manager constructs cleanly");
        (mgr, primary, secondary)
    }

    #[test]
    fn new_rejects_key_naming_absent_backend() {
        // A catalog whose key references a backend we never provide.
        let mut backends: BTreeMap<String, Box<dyn Backend>> = BTreeMap::new();
        backends.insert(
            "primary".into(),
            Box::new(MockHandle(MockBackend::new("primary"))),
        );
        // "sym.box"/"web.cert" route to "secondary", which is absent here.
        let err = BackendManager::new(parse_catalog(CATALOG), backends)
            .expect_err("missing backend must fail closed");
        match err {
            ManagerError::UnknownBackend { backend, .. } => assert_eq!(backend, "secondary"),
            other => panic!("expected UnknownBackend, got {other:?}"),
        }
    }

    #[test]
    fn resolve_maps_key_to_correct_backend_and_path() {
        let (mgr, _p, _s) = fixture();

        let routed = mgr.resolve("asym.signer").expect("resolves");
        assert_eq!(routed.backend.kind(), "primary");
        assert_eq!(routed.path(), "signer");
        assert_eq!(routed.class(), Class::Asymmetric);
        assert_eq!(routed.engine, Engine::Transit);
        assert_eq!(routed.key_type(), Some(KeyAlgorithm::Ed25519));

        let routed = mgr.resolve("web.cert").expect("resolves");
        assert_eq!(routed.backend.kind(), "secondary");
        assert_eq!(routed.path(), "secret/data/web/cert");
        assert_eq!(routed.class(), Class::Public);
        assert_eq!(routed.engine, Engine::Kv2);

        let routed = mgr.resolve("spiffe.issuer").expect("resolves");
        assert_eq!(routed.backend.kind(), "secondary");
        assert_eq!(routed.path(), "pki/issue/workload");
        assert_eq!(routed.class(), Class::Asymmetric);
        assert_eq!(routed.engine, Engine::Pki);
    }

    #[test]
    fn resolve_infers_engine_when_catalog_omits_it() {
        // asym.signer / sym.box have no explicit `engine` -> inferred Transit.
        let (mgr, _p, _s) = fixture();
        assert_eq!(mgr.resolve("asym.signer").unwrap().engine, Engine::Transit);
        assert_eq!(mgr.resolve("sym.box").unwrap().engine, Engine::Transit);
    }

    #[test]
    fn resolve_unknown_key_errors() {
        let (mgr, _p, _s) = fixture();
        let err = mgr.resolve("does.not.exist").expect_err("unknown key");
        match err {
            ManagerError::UnknownKey(k) => assert_eq!(k, "does.not.exist"),
            other => panic!("expected UnknownKey, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn sign_routes_to_correct_backend_with_path() {
        let (mgr, primary, secondary) = fixture();
        let sig = mgr.sign("asym.signer", &[1, 2, 3]).await.expect("signs");
        assert_eq!(sig, vec![0xAB, 0xCD]);
        // Dispatched to "primary" using the catalog PATH (the bare transit key
        // name), not the dotted name.
        assert_eq!(primary.last_path().as_deref(), Some("signer"));
        assert_eq!(
            secondary.last_path(),
            None,
            "the other backend is untouched"
        );
    }

    #[tokio::test]
    async fn nkey_sign_uses_raw_ed25519_transit_defaults() {
        let (mgr, primary, _secondary) = fixture();
        let sig = mgr.sign("asym.nkey", b"nonce").await.expect("signs nkey");
        assert_eq!(sig, vec![0xAB, 0xCD]);
        assert_eq!(primary.last_path().as_deref(), Some("nkey-signer"));
        assert_eq!(primary.last_sign_options(), Some(SignOptions::Default));
    }

    #[tokio::test]
    async fn rsa_sign_and_verify_use_rs256_transit_options() {
        let (mgr, primary, _secondary) = fixture();
        let sig = mgr.sign("asym.rsa", b"jwt-input").await.expect("signs rsa");
        assert_eq!(sig, vec![0xAB, 0xCD, 0x52]);
        assert_eq!(primary.last_path().as_deref(), Some("rsa-signer"));
        assert_eq!(
            primary.last_sign_options(),
            Some(SignOptions::Rs256Pkcs1v15Sha256)
        );

        let valid = mgr
            .verify("asym.rsa", b"jwt-input", &sig)
            .await
            .expect("verifies rsa");
        assert!(valid);
        assert_eq!(
            primary.last_verify_options(),
            Some(SignOptions::Rs256Pkcs1v15Sha256)
        );
    }

    #[tokio::test]
    async fn ecdsa_sign_and_verify_use_es256_transit_options() {
        let (mgr, primary, _secondary) = fixture();
        let sig = mgr
            .sign("asym.ecdsa", b"jwt-input")
            .await
            .expect("signs ecdsa");
        assert_eq!(sig, vec![0xAB, 0xCD, 0x45]);
        assert_eq!(primary.last_path().as_deref(), Some("ecdsa-signer"));
        assert_eq!(primary.last_sign_options(), Some(SignOptions::Es256));

        let valid = mgr
            .verify("asym.ecdsa", b"jwt-input", &sig)
            .await
            .expect("verifies ecdsa");
        assert!(valid);
        assert_eq!(primary.last_verify_options(), Some(SignOptions::Es256));
    }

    #[tokio::test]
    async fn ecdsa_p384_sign_and_verify_use_es384_transit_options() {
        let (mgr, primary, _secondary) = fixture();
        let sig = mgr
            .sign("asym.ecdsa384", b"jwt-input")
            .await
            .expect("signs ecdsa p384");
        assert_eq!(sig, vec![0xAB, 0xCD, 0x46]);
        assert_eq!(primary.last_path().as_deref(), Some("ecdsa384-signer"));
        assert_eq!(primary.last_sign_options(), Some(SignOptions::Es384));

        let valid = mgr
            .verify("asym.ecdsa384", b"jwt-input", &sig)
            .await
            .expect("verifies ecdsa p384");
        assert!(valid);
        assert_eq!(primary.last_verify_options(), Some(SignOptions::Es384));
    }

    #[tokio::test]
    async fn ecdsa_p521_sign_and_verify_use_es512_transit_options() {
        let (mgr, primary, _secondary) = fixture();
        let sig = mgr
            .sign("asym.ecdsa521", b"jwt-input")
            .await
            .expect("signs ecdsa p521");
        assert_eq!(sig, vec![0xAB, 0xCD, 0x47]);
        assert_eq!(primary.last_path().as_deref(), Some("ecdsa521-signer"));
        assert_eq!(primary.last_sign_options(), Some(SignOptions::Es512));

        let valid = mgr
            .verify("asym.ecdsa521", b"jwt-input", &sig)
            .await
            .expect("verifies ecdsa p521");
        assert!(valid);
        assert_eq!(primary.last_verify_options(), Some(SignOptions::Es512));
    }

    #[tokio::test]
    async fn issue_x509_svid_routes_to_pki_issue_path() {
        let (mgr, _primary, secondary) = fixture();
        let svid = mgr
            .issue_x509_svid("spiffe.issuer", "spiffe://example.test/web", 300)
            .await
            .expect("issues x509 svid");
        assert_eq!(secondary.last_path().as_deref(), Some("pki/issue/workload"));
        assert_eq!(
            secondary.last_spiffe_id().as_deref(),
            Some("spiffe://example.test/web")
        );
        assert_eq!(svid.cert_chain_der, vec![vec![1, 2, 3]]);
        assert_eq!(&*svid.leaf_private_key_der, &[4, 5, 6]);
        assert_eq!(svid.bundle_der, vec![vec![7, 8, 9]]);
    }

    #[tokio::test]
    async fn issue_x509_svid_rejects_non_pki_key() {
        let (mgr, _primary, _secondary) = fixture();
        let err = mgr
            .issue_x509_svid("asym.signer", "spiffe://example.test/web", 300)
            .await
            .expect_err("transit key is not a pki issuer");
        assert!(matches!(err, ManagerError::Unsupported("issue_x509_svid")));
    }

    #[tokio::test]
    async fn issue_x509_cert_routes_to_pki_issue_path_with_sans() {
        let (mgr, _primary, secondary) = fixture();
        let request = X509CertRequest {
            common_name: "web.internal".into(),
            dns_sans: vec!["web.internal".into(), "alt.internal".into()],
            ip_sans: vec!["10.0.0.1".into()],
            ttl_seconds: 3600,
        };
        let issued = mgr
            .issue_x509_cert("spiffe.issuer", &request)
            .await
            .expect("issues x509 cert");
        assert_eq!(secondary.last_path().as_deref(), Some("pki/issue/workload"));
        assert_eq!(secondary.last_spiffe_id().as_deref(), Some("web.internal"));
        assert_eq!(issued.cert_chain_der, vec![vec![0xCE, 0x27]]);
        assert_eq!(&*issued.leaf_private_key_der, &[0xDE, 0xAD]);
    }

    #[tokio::test]
    async fn issue_x509_cert_rejects_non_pki_key() {
        let (mgr, _primary, _secondary) = fixture();
        let request = X509CertRequest {
            common_name: "web.internal".into(),
            ..X509CertRequest::default()
        };
        let err = mgr
            .issue_x509_cert("asym.signer", &request)
            .await
            .expect_err("transit key is not a pki issuer");
        assert!(matches!(err, ManagerError::Unsupported("issue_x509_cert")));
    }

    #[tokio::test]
    async fn new_key_routes_to_correct_backend() {
        let (mgr, primary, secondary) = fixture();
        let nk = mgr
            .new_key("asym.signer", KeyType::Ed25519)
            .await
            .expect("new_key");
        assert_eq!(nk.key_id, "primary-newkey");
        assert_eq!(primary.new_key_calls.load(Ordering::SeqCst), 1);
        assert_eq!(primary.last_new_key_type(), Some(KeyType::Ed25519));
        assert_eq!(secondary.new_key_calls.load(Ordering::SeqCst), 0);

        mgr.new_key("asym.nkey", KeyType::Ed25519Nkey)
            .await
            .expect("new_key nkey");
        assert_eq!(primary.last_new_key_type(), Some(KeyType::Ed25519Nkey));

        mgr.new_key("asym.rsa", KeyType::Rsa2048)
            .await
            .expect("new_key rsa");
        assert_eq!(primary.last_new_key_type(), Some(KeyType::Rsa2048));

        mgr.new_key("asym.ecdsa", KeyType::EcdsaP256)
            .await
            .expect("new_key ecdsa");
        assert_eq!(primary.last_new_key_type(), Some(KeyType::EcdsaP256));

        mgr.new_key("asym.ecdsa384", KeyType::EcdsaP384)
            .await
            .expect("new_key ecdsa p384");
        assert_eq!(primary.last_new_key_type(), Some(KeyType::EcdsaP384));

        mgr.new_key("asym.ecdsa521", KeyType::EcdsaP521)
            .await
            .expect("new_key ecdsa p521");
        assert_eq!(primary.last_new_key_type(), Some(KeyType::EcdsaP521));
    }

    #[tokio::test]
    async fn new_key_rejects_key_type_absent_from_static_backend_preset() {
        let catalog = CATALOG.replace(
            r#""mintKeyTypes": ["ed25519", "ed25519-nkey", "rsa-2048", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521"]"#,
            r#""mintKeyTypes": ["ed25519"]"#,
        );
        let primary = MockBackend::new("primary");
        let secondary = MockBackend::new("secondary");
        let mut backends: BTreeMap<String, Box<dyn Backend>> = BTreeMap::new();
        backends.insert("primary".into(), Box::new(MockHandle(primary.clone())));
        backends.insert("secondary".into(), Box::new(MockHandle(secondary)));
        let mgr = BackendManager::new(parse_catalog(&catalog), backends).expect("manager builds");

        let err = mgr
            .new_key("asym.signer", KeyType::Rsa2048)
            .await
            .expect_err("rsa absent from backend preset");
        assert!(matches!(
            err,
            ManagerError::UnsupportedKeyType {
                backend,
                op: "new_key",
                key_type: KeyType::Rsa2048
            } if backend == "primary"
        ));
        assert_eq!(primary.new_key_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn get_public_key_valid_on_public_class_returns_real_metadata() {
        let (mgr, _p, secondary) = fixture();
        let pk = mgr.get_public_key("web.cert").await.expect("public read");
        assert_eq!(pk.public_key, vec![9, 9, 9]);
        // Real type+version from the backend, NOT the old hardcoded ed25519/1.
        assert_eq!(pk.key_type, KeyType::Ed25519Nkey);
        assert_eq!(pk.version, 7);
        assert_eq!(
            secondary.last_path().as_deref(),
            Some("secret/data/web/cert")
        );
    }

    #[tokio::test]
    async fn import_routes_to_backend_path_and_returns_only_public() {
        let (mgr, primary, _s) = fixture();
        let nk = mgr
            .import(
                "asym.signer",
                KeyType::Ed25519,
                &KeyMaterial::Ed25519Seed(vec![7; 32]),
            )
            .await
            .expect("import");
        // Replies with the public half only; never the seed.
        assert_eq!(nk.public_key, vec![0xEE, 0xEE]);
        // Dispatched to the catalog PATH (bare transit key name), not the dotted name.
        assert_eq!(primary.last_path().as_deref(), Some("signer"));
    }

    #[tokio::test]
    async fn import_rejects_key_type_absent_from_static_backend_preset() {
        let catalog = CATALOG.replace(
            r#""mintKeyTypes": ["ed25519", "ed25519-nkey", "rsa-2048", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521"]"#,
            r#""mintKeyTypes": ["ed25519"]"#,
        );
        let primary = MockBackend::new("primary");
        let secondary = MockBackend::new("secondary");
        let mut backends: BTreeMap<String, Box<dyn Backend>> = BTreeMap::new();
        backends.insert("primary".into(), Box::new(MockHandle(primary.clone())));
        backends.insert("secondary".into(), Box::new(MockHandle(secondary)));
        let mgr = BackendManager::new(parse_catalog(&catalog), backends).expect("manager builds");

        let err = mgr
            .import(
                "asym.signer",
                KeyType::Rsa2048,
                &KeyMaterial::Pkcs8Der(vec![1, 2, 3]),
            )
            .await
            .expect_err("rsa absent from backend preset");
        assert!(matches!(
            err,
            ManagerError::UnsupportedKeyType {
                backend,
                op: "import",
                key_type: KeyType::Rsa2048
            } if backend == "primary"
        ));
        assert!(primary.last_path().is_none());
    }

    #[tokio::test]
    async fn import_on_value_key_is_op_not_valid_for_class() {
        let (mgr, _p, _s) = fixture();
        let err = mgr
            .import(
                "web.value",
                KeyType::Ed25519,
                &KeyMaterial::Ed25519Seed(vec![0; 32]),
            )
            .await
            .expect_err("import on a value key must be rejected");
        assert!(matches!(err, ManagerError::OpNotValidForClass { .. }));
    }

    #[tokio::test]
    async fn list_projects_catalog_value_free_and_respects_visibility() {
        let (mgr, _p, _s) = fixture();
        // Visibility predicate hides web.value (simulating a PDP filter).
        let entries = mgr
            //  ubs false positive: name is not secret material
            /* ubs:ignore */
            .list(None, |name| name != "web.value")
            .await
            .expect("list");
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"asym.signer"));
        assert!(names.contains(&"sym.box"));
        assert!(names.contains(&"web.cert"));
        assert!(
            !names.contains(&"web.value"),
            "invisible key must be filtered"
        );
        // Class -> kind mapping + backend-sourced version, never key bytes.
        let signer = entries.iter().find(|e| e.name == "asym.signer").unwrap();
        assert_eq!(signer.kind, CatalogKind::Signing);
        assert_eq!(signer.key_type, Some(KeyType::Ed25519));
        // The mock reports its current latest_version (5 before any rotate).
        assert_eq!(signer.latest_version, 5);
        let boxx = entries.iter().find(|e| e.name == "sym.box").unwrap();
        assert_eq!(boxx.kind, CatalogKind::Encryption);
        let cert = entries.iter().find(|e| e.name == "web.cert").unwrap();
        assert_eq!(cert.kind, CatalogKind::Signing);
    }

    #[tokio::test]
    async fn list_filters_by_prefix() {
        let (mgr, _p, _s) = fixture();
        let entries = mgr.list(Some("web."), |_| true).await.expect("list");
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["web.cert", "web.value"]);
    }

    #[tokio::test]
    async fn sign_on_value_key_is_op_not_valid_for_class() {
        let (mgr, _p, _s) = fixture();
        let err = mgr
            .sign("web.value", &[1])
            .await
            .expect_err("sign on a value key must be rejected");
        match err {
            ManagerError::OpNotValidForClass { op, key, class } => {
                assert_eq!(op, "sign");
                assert_eq!(key, "web.value");
                assert_eq!(class, Class::Value);
            }
            other => panic!("expected OpNotValidForClass, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn new_key_on_value_key_is_op_not_valid_for_class() {
        let (mgr, _p, _s) = fixture();
        let err = mgr
            .new_key("web.value", KeyType::Ed25519)
            .await
            .expect_err("new_key on a value key must be rejected");
        assert!(matches!(err, ManagerError::OpNotValidForClass { .. }));
    }

    #[tokio::test]
    async fn unbacked_op_still_resolves_first_unknown_key_wins() {
        // A backed op on an unknown key reports UnknownKey before any dispatch.
        let (mgr, _p, _s) = fixture();
        assert!(matches!(
            mgr.encrypt("nope", AeadAlgorithm::Aes256Gcm, &[1], None)
                .await,
            Err(ManagerError::UnknownKey(_))
        ));
    }

    // ---- get / set (KV-v2 value ops, vault-jbr) -----------------------------

    #[tokio::test]
    async fn set_writes_value_and_get_round_trips_it() {
        let (mgr, primary, _s) = fixture();
        // set writes a fresh KV-v2 version of a value key and returns the version.
        let version = mgr.set("web.value", b"super-secret").await.expect("set");
        assert_eq!(primary.kv_put_calls.load(Ordering::SeqCst), 1);
        // web.value starts at latest 5; the write bumps to 6.
        assert_eq!(version, 6);
        // Dispatched to the catalog PATH, not the dotted name.
        assert_eq!(
            primary.last_path().as_deref(),
            Some("secret/data/web/value")
        );

        // get reads the value back + the version (latest when none requested).
        let kv = mgr.get("web.value", None).await.expect("get");
        assert_eq!(kv.value, b"super-secret");
        assert_eq!(kv.version, 6);
    }

    #[tokio::test]
    async fn get_reads_a_specific_version() {
        let (mgr, _p, _s) = fixture();
        // An explicit version is carried through to the backend + echoed.
        let kv = mgr.get("web.value", Some(3)).await.expect("get");
        assert_eq!(kv.version, 3);
    }

    #[tokio::test]
    async fn get_valid_on_public_class_key() {
        let (mgr, _p, secondary) = fixture();
        // get is value/public-class -> a public cert is readable via get.
        let kv = mgr.get("web.cert", None).await.expect("get on public key");
        assert_eq!(kv.value, b"stored-value");
        assert_eq!(
            secondary.last_path().as_deref(),
            Some("secret/data/web/cert")
        );
    }

    #[tokio::test]
    async fn get_on_asymmetric_key_is_op_not_valid_for_class() {
        let (mgr, primary, _s) = fixture();
        // get on a signing key must be rejected BEFORE any backend call: the
        // broker never hands out crypto-key material through get.
        let err = mgr
            .get("asym.signer", None)
            .await
            .expect_err("get on a signing key must be rejected");
        match err {
            ManagerError::OpNotValidForClass { op, key, class } => {
                assert_eq!(op, "get");
                assert_eq!(key, "asym.signer");
                assert_eq!(class, Class::Asymmetric);
            }
            other => panic!("expected OpNotValidForClass, got {other:?}"),
        }
        // No backend dispatch happened (the class gate ran first).
        assert_eq!(primary.last_path(), None);
    }

    #[tokio::test]
    async fn set_on_public_key_is_op_not_valid_for_class() {
        let (mgr, _p, secondary) = fixture();
        // set is value-class only -> a public (read-only) key is rejected.
        let err = mgr
            .set("web.cert", b"x")
            .await
            .expect_err("set on a public key must be rejected");
        assert!(matches!(err, ManagerError::OpNotValidForClass { .. }));
        assert_eq!(secondary.last_path(), None);
    }

    #[tokio::test]
    async fn set_on_asymmetric_key_is_op_not_valid_for_class() {
        let (mgr, _p, _s) = fixture();
        let err = mgr
            .set("asym.signer", b"x")
            .await
            .expect_err("set on a signing key must be rejected");
        assert!(matches!(err, ManagerError::OpNotValidForClass { .. }));
    }

    #[tokio::test]
    async fn get_unknown_key_wins_over_class() {
        // unknown-key beats the class check (resolution runs first).
        let (mgr, _p, _s) = fixture();
        assert!(matches!(
            mgr.get("does.not.exist", None).await,
            Err(ManagerError::UnknownKey(_))
        ));
    }

    // ---- encrypt / decrypt (vault-uo1) --------------------------------------

    #[tokio::test]
    async fn encrypt_then_decrypt_round_trips_with_aad() {
        let (mgr, _p, secondary) = fixture();
        let pt = b"top secret payload";
        let aad = b"context-42";
        let env = mgr
            .encrypt("sym.box", AeadAlgorithm::Aes256Gcm, pt, Some(aad))
            .await
            .expect("encrypt");
        // Broker owns the nonce (empty here: transit embeds it) and echoes alg +
        // the latest key version; routed to the catalog PATH on "secondary".
        assert_eq!(env.alg, AeadAlgorithm::Aes256Gcm);
        assert!(env.nonce.is_empty());
        assert_eq!(secondary.last_path().as_deref(), Some("box"));

        let recovered = mgr
            .decrypt("sym.box", &env, Some(aad))
            .await
            .expect("decrypt");
        assert_eq!(recovered, pt);
    }

    #[tokio::test]
    async fn decrypt_with_wrong_aad_is_opaque_decrypt_failed() {
        let (mgr, _p, _s) = fixture();
        let env = mgr
            .encrypt("sym.box", AeadAlgorithm::Aes256Gcm, b"x", Some(b"good"))
            .await
            .expect("encrypt");
        let err = mgr
            .decrypt("sym.box", &env, Some(b"BAD"))
            .await
            .expect_err("aad mismatch must fail");
        assert!(matches!(
            err,
            ManagerError::Backend(BackendError::DecryptFailed)
        ));
    }

    #[tokio::test]
    async fn encrypt_algorithm_must_match_catalog_key_type() {
        let (mgr, _p, _s) = fixture();
        // sym.box is aes-256-gcm; a chacha20-poly1305 request is a mismatch.
        let err = mgr
            .encrypt("sym.box", AeadAlgorithm::Chacha20Poly1305, b"x", None)
            .await
            .expect_err("algorithm mismatch must be rejected");
        assert!(matches!(err, ManagerError::AlgorithmMismatch { .. }));
    }

    #[tokio::test]
    async fn encrypt_on_non_symmetric_key_is_op_not_valid_for_class() {
        let (mgr, _p, _s) = fixture();
        let err = mgr
            .encrypt("asym.signer", AeadAlgorithm::Aes256Gcm, b"x", None)
            .await
            .expect_err("encrypt on a signing key must be rejected");
        assert!(matches!(err, ManagerError::OpNotValidForClass { .. }));
    }

    #[tokio::test]
    async fn decrypt_targets_the_envelope_key_version() {
        // The envelope's key_version is what reaches the backend (rotation grace);
        // the mock decrypt round-trips regardless of version, but we assert the
        // version is carried through unchanged via a hand-built envelope.
        let (mgr, _p, _s) = fixture();
        let mut env = mgr
            .encrypt("sym.box", AeadAlgorithm::Aes256Gcm, b"data", None)
            .await
            .expect("encrypt");
        env.key_version = 2; // an older version, as a grace-window decrypt would carry
        let recovered = mgr.decrypt("sym.box", &env, None).await.expect("decrypt");
        assert_eq!(recovered, b"data");
    }

    // ---- rotate / grace / retention (vault-xhq) -----------------------------

    #[tokio::test]
    async fn rotate_crypto_key_bumps_version_and_sets_grace_floor() {
        let (mgr, _p, secondary) = fixture();
        // sym.box (latest 5) -> rotate bumps to 6; default grace_versions=1 sets
        // min_decryption_version = 6 - 1 = 5.
        let limits = BrokerLimits::default();
        let new_version = mgr.rotate("sym.box", limits).await.expect("rotate");
        assert_eq!(new_version, 6);
        assert_eq!(secondary.rotate_calls.load(Ordering::SeqCst), 1);
        assert_eq!(secondary.last_versions_config(), Some((Some(5), None)));
    }

    #[tokio::test]
    async fn rotate_grace_zero_floors_at_latest() {
        let (mgr, primary, _s) = fixture();
        // asym.signer (latest 5) with grace 0 -> min_decryption_version = 6 (only
        // the newest version decrypts/verifies; the compromise setting).
        let limits = BrokerLimits {
            grace_versions: 0,
            ..BrokerLimits::default()
        };
        let new_version = mgr.rotate("asym.signer", limits).await.expect("rotate");
        assert_eq!(new_version, 6);
        assert_eq!(primary.last_versions_config(), Some((Some(6), None)));
    }

    #[tokio::test]
    async fn rotate_value_key_with_recipe_regenerates_a_new_version() {
        let (mgr, primary, _s) = fixture();
        // gen.value has an ascii-printable recipe -> rotate generates a fresh
        // value and writes it as a new KV-v2 version (the a2p decision).
        let new_version = mgr
            .rotate("gen.value", BrokerLimits::default())
            .await
            .expect("rotate");
        assert_eq!(primary.kv_put_calls.load(Ordering::SeqCst), 1);
        assert_eq!(new_version, 6);
        // A fresh 24-byte printable value was written (never echoed on the wire).
        let value = primary.last_kv_value().expect("a value was written");
        assert_eq!(value.len(), 24);
        assert!(value.iter().all(|b| (b'!'..=b'~').contains(b)));
    }

    #[tokio::test]
    async fn rotate_tls_pair_key_regenerates_matching_cert_side() {
        if !step_available() {
            return;
        }
        let (mgr, primary, _s) = fixture();
        let new_version = mgr
            .rotate("tls.key", BrokerLimits::default())
            .await
            .expect("rotate tls key");
        assert_eq!(new_version, 6);
        let writes = primary.kv_put_log();
        assert_eq!(writes.len(), 2);
        assert_eq!(writes[0].0, "secret/data/tls/key");
        assert_eq!(writes[1].0, "secret/data/tls/cert");
        assert!(writes[0].1.starts_with(b"-----BEGIN"));
        assert!(
            writes[0]
                .1
                .windows(b"PRIVATE KEY".len())
                .any(|w| w == b"PRIVATE KEY")
        );
        assert!(writes[1].1.starts_with(b"-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn age_x25519_generate_recipe_emits_parseable_identity() {
        let value = generate_value(&GenerateSpec::AgeX25519).expect("age identity generated");
        let identity = String::from_utf8(value).expect("age identity is utf8");
        assert!(identity.starts_with("AGE-SECRET-KEY-"));
        let parsed = identity.parse::<age::x25519::Identity>();
        assert!(parsed.is_ok(), "generated identity must parse");
    }

    fn step_available() -> bool {
        Command::new("step")
            .arg("version")
            .output()
            .is_ok_and(|output| output.status.success())
    }

    #[tokio::test]
    async fn rotate_value_key_without_recipe_is_invalid_request() {
        let (mgr, _p, _s) = fixture();
        // web.value is a value key with NO generate recipe -> rotate is invalid;
        // the caller must `set` new material out of band.
        let err = mgr
            .rotate("web.value", BrokerLimits::default())
            .await
            .expect_err("value rotate without recipe must fail");
        assert!(matches!(err, ManagerError::ValueRotateNeedsSet(_)));
    }

    #[tokio::test]
    async fn sweep_retention_raises_min_available_version() {
        let (mgr, _p, secondary) = fixture();
        // sym.box latest 5, retain 2 -> min_available_version = 5 - 2 = 3.
        let limits = BrokerLimits {
            retain_versions: Some(2),
            ..BrokerLimits::default()
        };
        mgr.sweep_retention("sym.box", limits).await.expect("sweep");
        assert_eq!(secondary.last_versions_config(), Some((None, Some(3))));
    }

    #[tokio::test]
    async fn sweep_all_retention_walks_crypto_keys() {
        let (mgr, primary, secondary) = fixture();
        let limits = BrokerLimits {
            retain_versions: Some(2),
            ..BrokerLimits::default()
        };
        mgr.sweep_all_retention(limits)
            .await
            .expect("catalog sweep");
        assert_eq!(primary.last_versions_config(), Some((None, Some(3))));
        assert_eq!(secondary.last_versions_config(), Some((None, Some(3))));
    }

    #[tokio::test]
    async fn sweep_retention_disabled_is_a_noop() {
        let (mgr, _p, secondary) = fixture();
        // retain_versions=None -> no configure_versions call at all.
        mgr.sweep_retention("sym.box", BrokerLimits::default())
            .await
            .expect("sweep");
        assert_eq!(secondary.last_versions_config(), None);
    }

    // ---- Sealing class (X25519 sealed-box unseal, basil-t9a) -----------------

    /// Provision a fixed X25519 sealing keypair into the `primary` mock out of
    /// band: the private at the catalog `path` (materialized only on `unwrap`) and
    /// the public at the catalog `public_path` (read by `wrap`/`get_public_key`,
    /// basil-o86). Returns the public for sealing payloads to it.
    fn seed_sealing_private(primary: &Arc<MockBackend>) -> [u8; 32] {
        let private = Zeroizing::new([0x11u8; 32]);
        let public = x25519_seal::public_from_private(&private);
        primary.seed_kv("secret/data/enroll/x25519", private.to_vec());
        primary.seed_kv("secret/data/enroll/x25519-public", public.to_vec());
        public
    }
    fn seed_ml_kem_private(primary: &Arc<MockBackend>) -> [u8; ml_kem_envelope::SEED_LEN] {
        let seed = [0x42; ml_kem_envelope::SEED_LEN];
        primary.seed_kv(
            "secret/data/enroll/ml-kem-768",
            ml_kem_record_bytes("enroll.mlkem", &seed, 5),
        );
        primary.seed_kv("secret/data/enroll/ml-kem-768-public", vec![0x7A; 1184]);
        seed
    }
    fn ml_kem_record_bytes(
        key_id: &str,
        seed: &[u8; ml_kem_envelope::SEED_LEN],
        key_version: u32,
    ) -> Vec<u8> {
        // Mirror what the local-software provider reconstructs from enroll.mlkem's
        // catalog labels (software-encrypted ml-kem-768, provider version 1).
        let meta = SoftwareCustodyCatalog {
            key_id,
            algorithm: ml_kem_envelope::KemAlgorithm::MlKem768.token(),
            provider: "local-software",
            provider_version: "1",
            custody: "software-encrypted",
            storage_key: "pqc/storage/wrap",
        };
        let aad = meta.aad(key_version);
        let mut ciphertext = Vec::with_capacity(aad.len() + seed.len() + 1);
        ciphertext.push(u8::try_from(aad.len()).expect("test aad fits mock envelope"));
        ciphertext.extend_from_slice(&aad);
        ciphertext.extend_from_slice(seed);
        serde_json::json!({
            "schemaVersion": 1,
            "keyId": key_id,
            "keyVersion": key_version,
            "publicKey": encode_record_bytes(&[0x7A; 1184]),
            "algorithm": meta.algorithm,
            "provider": meta.provider,
            "providerVersion": meta.provider_version,
            "custody": meta.custody,
            "encryptedPrivateKey": {
                "wrappingKey": meta.storage_key,
                "algorithm": "aes-256-gcm",
                "keyVersion": key_version,
                "nonce": encode_record_bytes(&[]),
                "ciphertext": encode_record_bytes(&ciphertext),
            }
        })
        .to_string()
        .into_bytes()
    }

    #[tokio::test]
    async fn sealing_key_rejects_get_and_set() {
        // INVARIANT 1: the private half is never get-able/set-able through the
        // public KV ops; require_class fails closed before any backend call.
        let (mgr, _p, _s) = fixture();
        let get_err = mgr
            .get("enroll.sealing", None)
            .await
            .expect_err("get must be denied on a sealing key");
        assert!(matches!(
            get_err,
            ManagerError::OpNotValidForClass {
                op: "get",
                class: Class::Sealing,
                ..
            }
        ));
        let set_err = mgr
            .set("enroll.sealing", b"anything")
            .await
            .expect_err("set must be denied on a sealing key");
        assert!(matches!(
            set_err,
            ManagerError::OpNotValidForClass {
                op: "set",
                class: Class::Sealing,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn sealing_key_rejects_sign_and_rotate() {
        // The signing/transit op surface is closed for a sealing key too.
        let (mgr, _p, _s) = fixture();
        assert!(matches!(
            mgr.sign("enroll.sealing", b"m").await,
            Err(ManagerError::OpNotValidForClass { op: "sign", .. })
        ));
        assert!(matches!(
            mgr.rotate("enroll.sealing", BrokerLimits::default()).await,
            Err(ManagerError::OpNotValidForClass { op: "rotate", .. })
        ));
    }

    #[tokio::test]
    async fn sealing_get_public_key_reads_out_of_band_public() {
        // basil-o86: get_public_key returns the out-of-band-provisioned public,
        // read from `public_path`: the private is NEVER materialized for it.
        let (mgr, primary, _s) = fixture();
        let expected_pub = seed_sealing_private(&primary);
        let got = mgr
            .sealing_public_key("enroll.sealing")
            .await
            .expect("reads public");
        assert_eq!(got, expected_pub);
        // The read routed to the PUBLIC path, not the private materialize path.
        assert_eq!(
            primary.last_path().as_deref(),
            Some("secret/data/enroll/x25519-public")
        );
    }

    #[tokio::test]
    async fn sealing_public_ops_never_materialize_private() {
        // basil-o86 PROOF: provision a CORRECT public but a GARBAGE (7-byte)
        // private. If wrap or get_public_key materialized the private they would
        // fail closed (Malformed). They read the out-of-band public instead, so
        // both succeed with the provisioned public. The private is untouched.
        let (mgr, primary, _s) = fixture();
        let private = Zeroizing::new([0x11u8; 32]);
        let public = x25519_seal::public_from_private(&private);
        primary.seed_kv("secret/data/enroll/x25519-public", public.to_vec());
        primary.seed_kv("secret/data/enroll/x25519", vec![0xFF; 7]);

        let got = mgr
            .sealing_public_key("enroll.sealing")
            .await
            .expect("public read despite garbage private");
        assert_eq!(got, public);
        // wrap also resolves only the public, so it succeeds with the garbage private
        // still in place.
        mgr.wrap_envelope("enroll.sealing", b"payload", b"ctx")
            .await
            .expect("wrap reads only the public");
    }

    #[tokio::test]
    async fn sealing_wrap_then_unwrap_round_trips() {
        // INVARIANT 5: server-side wrap (public-only) then unwrap (materialize the
        // private, ECDH, zeroize) recovers the plaintext.
        let (mgr, primary, _s) = fixture();
        seed_sealing_private(&primary);
        let plaintext = b"enrollment-payload";
        let aad = b"enroll-ctx";
        let env = mgr
            .wrap_envelope("enroll.sealing", plaintext, aad)
            .await
            .expect("wrap");
        let recovered = mgr
            .unwrap_envelope("enroll.sealing", &env, aad)
            .await
            .expect("unwrap");
        assert_eq!(recovered.as_slice(), plaintext);
    }

    #[tokio::test]
    async fn kv_get_secret_returns_zeroizing_bytes_and_round_trips() {
        // FIX 1: the SECRET read keeps bytes in `Zeroizing` end-to-end. Functional
        // check: it returns exactly what `kv_put` stored (the wipe itself can't be
        // unit-tested, but the type is `Zeroizing<Vec<u8>>` and the bytes match).
        let backend = MockHandle(MockBackend::new("primary"));
        let stored = vec![0x11u8; 32];
        backend
            .kv_put("secret/data/enroll/x25519", &stored)
            .await
            .expect("put");
        let got: Zeroizing<Vec<u8>> = backend
            .kv_get_secret("secret/data/enroll/x25519", None)
            .await
            .expect("secret read");
        assert_eq!(got.as_slice(), stored.as_slice());
    }

    #[tokio::test]
    async fn sealing_unwrap_opens_externally_sealed_payload() {
        // The realistic flow: a sender seals with ONLY the recipient public key
        // (crypto core, no broker); the broker unwraps with the materialized
        // private. This proves the broker isn't just round-tripping its own wrap.
        let (mgr, primary, _s) = fixture();
        let recipient_pub = seed_sealing_private(&primary);
        let env = x25519_seal::seal(&recipient_pub, b"sealed-by-sender", b"ctx").expect("seal");
        let recovered = mgr
            .unwrap_envelope("enroll.sealing", &env, b"ctx")
            .await
            .expect("unwrap");
        assert_eq!(recovered.as_slice(), b"sealed-by-sender");
    }

    /// Borrow an [`ml_kem_envelope::MlKemEnvelope`]'s wire fields for the
    /// provider-dispatched unwrap path.
    fn ml_kem_parts(env: &ml_kem_envelope::MlKemEnvelope) -> MlKemEnvelopeParts<'_> {
        MlKemEnvelopeParts {
            encapsulated_key: &env.encapsulated_key,
            nonce: &env.nonce,
            ciphertext: &env.ciphertext,
        }
    }
    #[tokio::test]
    async fn ml_kem_provider_wrap_then_unwrap_round_trips() {
        for envelope_algorithm in [
            ProviderEnvelopeAlgorithm::Aes256Gcm,
            ProviderEnvelopeAlgorithm::ChaCha20Poly1305,
        ] {
            let (mgr, primary, _s) = fixture();
            seed_ml_kem_private(&primary);
            let (envelope, dispatch) = mgr
                .provider_wrap_envelope(
                    "enroll.mlkem",
                    ProviderKemAlgorithm::MlKem768,
                    envelope_algorithm,
                    b"top secret",
                    b"ctx",
                    ProviderGate {
                        local_software_allowed: true,
                    },
                )
                .await
                .expect("wrap");
            // Self-describing: KEM level echoed; key version is the custody record's.
            assert_eq!(envelope.kem_algorithm, ProviderKemAlgorithm::MlKem768);
            assert_eq!(envelope.key_version, 5);
            assert_eq!(dispatch.algorithm, "ml-kem-768");
            assert_eq!(dispatch.provider, CryptoProviderId::LocalSoftware);

            let (recovered, _) = mgr
                .provider_unwrap_envelope(
                    "enroll.mlkem",
                    ProviderKemAlgorithm::MlKem768,
                    envelope_algorithm,
                    MlKemEnvelopeParts {
                        encapsulated_key: &envelope.encapsulated_key,
                        nonce: &envelope.nonce,
                        ciphertext: &envelope.ciphertext,
                    },
                    b"ctx",
                    ProviderGate {
                        local_software_allowed: true,
                    },
                )
                .await
                .expect("unwrap");
            assert_eq!(recovered.as_slice(), b"top secret");
        }
    }
    #[tokio::test]
    async fn ml_kem_provider_unwrap_opens_externally_sealed_payload() {
        let (mgr, primary, _s) = fixture();
        let seed = seed_ml_kem_private(&primary);
        // A sender seals with ONLY the seed-derived public (crypto core, no broker);
        // the broker unwraps via the materialized seed, not just its own wrap.
        let env = ml_kem_envelope::seal(
            &seed,
            ml_kem_envelope::KemAlgorithm::MlKem768,
            ml_kem_envelope::EnvelopeAlgorithm::ChaCha20Poly1305,
            b"sealed-by-sender",
            b"ctx",
        )
        .expect("seal");
        let (recovered, _) = mgr
            .provider_unwrap_envelope(
                "enroll.mlkem",
                ProviderKemAlgorithm::MlKem768,
                ProviderEnvelopeAlgorithm::ChaCha20Poly1305,
                ml_kem_parts(&env),
                b"ctx",
                ProviderGate {
                    local_software_allowed: true,
                },
            )
            .await
            .expect("unwrap");
        assert_eq!(recovered.as_slice(), b"sealed-by-sender");
    }

    /// Build a software-custody ML-KEM-768 record with a chosen public
    /// encapsulation key and a chosen (possibly undecryptable) wrapped seed:
    /// lets a `get_public_key` test prove it reads only the recorded public.
    fn ml_kem_record_with(public: &[u8], wrapped_seed: &[u8], key_version: u32) -> Vec<u8> {
        let meta = SoftwareCustodyCatalog {
            key_id: "enroll.mlkem",
            algorithm: ml_kem_envelope::KemAlgorithm::MlKem768.token(),
            provider: "local-software",
            provider_version: "1",
            custody: "software-encrypted",
            storage_key: "pqc/storage/wrap",
        };
        serde_json::json!({
            "schemaVersion": 1,
            "keyId": meta.key_id,
            "keyVersion": key_version,
            "publicKey": encode_record_bytes(public),
            "algorithm": meta.algorithm,
            "provider": meta.provider,
            "providerVersion": meta.provider_version,
            "custody": meta.custody,
            "encryptedPrivateKey": {
                "wrappingKey": meta.storage_key,
                "algorithm": "aes-256-gcm",
                "keyVersion": key_version,
                "nonce": encode_record_bytes(&[]),
                "ciphertext": encode_record_bytes(wrapped_seed),
            }
        })
        .to_string()
        .into_bytes()
    }
    #[tokio::test]
    async fn ml_kem_sealing_get_public_key_returns_encapsulation_key_without_seed() {
        // basil-4ybx: GetPublicKey on a software-custody ML-KEM sealing key returns
        // the public ENCAPSULATION key recorded in the custody record, tagged with
        // its ML-KEM parameter level, and NEVER materializes the decapsulation
        // seed. PROOF (mirrors sealing_public_ops_never_materialize_private): the
        // record carries a CORRECT public but an UNDECRYPTABLE (empty) wrapped
        // seed. If the read materialized the seed it would fail closed
        // (DecryptFailed); it reads only the recorded public, so it succeeds.
        let (mgr, primary, _s) = fixture();
        let encapsulation_key = vec![0xABu8; 1184];
        primary.seed_kv(
            "secret/data/enroll/ml-kem-768",
            // kv_version is the mock's latest (5); the inner key_version must be
            // non-zero. The empty wrapped seed makes any decrypt attempt fail.
            ml_kem_record_with(&encapsulation_key, &[], 5),
        );

        let got = mgr
            .get_public_key("enroll.mlkem")
            .await
            .expect("ML-KEM sealing public-encapsulation-key read");
        assert_eq!(got.public_key, encapsulation_key);
        assert_eq!(got.key_type, KeyType::MlKem768);
        // A software-custody record is a single fixed version.
        assert_eq!(got.version, 1);
        // The read resolved the custody record, never the AEAD storage key (a
        // decrypt would have set last_path to "pqc/storage/wrap").
        assert_eq!(
            primary.last_path().as_deref(),
            Some("secret/data/enroll/ml-kem-768")
        );
    }
    #[tokio::test]
    async fn get_public_key_rejects_non_ml_kem_sealing_and_value_classes() {
        // The sealing read path is narrow to software-custody ML-KEM: an X25519
        // sealing key and a value key are still OpNotValidForClass: the
        // asymmetric/public gate is unchanged for everything but ML-KEM sealing.
        let (mgr, _p, _s) = fixture();
        assert!(matches!(
            mgr.get_public_key("enroll.sealing").await,
            Err(ManagerError::OpNotValidForClass {
                op: "get_public_key",
                class: Class::Sealing,
                ..
            })
        ));
        assert!(matches!(
            mgr.get_public_key("web.value").await,
            Err(ManagerError::OpNotValidForClass {
                op: "get_public_key",
                class: Class::Value,
                ..
            })
        ));
    }
    #[tokio::test]
    async fn ml_kem_provider_unwrap_tampered_ciphertext_fails_opaque() {
        let (mgr, primary, _s) = fixture();
        seed_ml_kem_private(&primary);
        let (mut envelope, _) = mgr
            .provider_wrap_envelope(
                "enroll.mlkem",
                ProviderKemAlgorithm::MlKem768,
                ProviderEnvelopeAlgorithm::Aes256Gcm,
                b"top secret",
                b"ctx",
                ProviderGate {
                    local_software_allowed: true,
                },
            )
            .await
            .expect("wrap");
        if let Some(b) = envelope.ciphertext.first_mut() {
            *b ^= 0xFF;
        }
        let err = mgr
            .provider_unwrap_envelope(
                "enroll.mlkem",
                ProviderKemAlgorithm::MlKem768,
                ProviderEnvelopeAlgorithm::Aes256Gcm,
                MlKemEnvelopeParts {
                    encapsulated_key: &envelope.encapsulated_key,
                    nonce: &envelope.nonce,
                    ciphertext: &envelope.ciphertext,
                },
                b"ctx",
                ProviderGate {
                    local_software_allowed: true,
                },
            )
            .await
            .expect_err("tampered ciphertext must fail opaque");
        assert!(matches!(
            err,
            ManagerError::Provider(ProviderError::CryptoFailed {
                op: "unwrap_envelope",
                ..
            })
        ));
    }
    #[tokio::test]
    async fn ml_kem_provider_unwrap_wrong_aad_fails_opaque() {
        let (mgr, primary, _s) = fixture();
        seed_ml_kem_private(&primary);
        let (envelope, _) = mgr
            .provider_wrap_envelope(
                "enroll.mlkem",
                ProviderKemAlgorithm::MlKem768,
                ProviderEnvelopeAlgorithm::ChaCha20Poly1305,
                b"top secret",
                b"right",
                ProviderGate {
                    local_software_allowed: true,
                },
            )
            .await
            .expect("wrap");
        let err = mgr
            .provider_unwrap_envelope(
                "enroll.mlkem",
                ProviderKemAlgorithm::MlKem768,
                ProviderEnvelopeAlgorithm::ChaCha20Poly1305,
                MlKemEnvelopeParts {
                    encapsulated_key: &envelope.encapsulated_key,
                    nonce: &envelope.nonce,
                    ciphertext: &envelope.ciphertext,
                },
                b"wrong",
                ProviderGate {
                    local_software_allowed: true,
                },
            )
            .await
            .expect_err("wrong aad must fail opaque");
        assert!(matches!(
            err,
            ManagerError::Provider(ProviderError::CryptoFailed { .. })
        ));
    }
    #[tokio::test]
    async fn ml_kem_software_custody_rejects_raw_seed_storage() {
        let (mgr, primary, _s) = fixture();
        let seed = [0x42; ml_kem_envelope::SEED_LEN];
        primary.seed_kv("secret/data/enroll/ml-kem-768", seed.to_vec());
        let env = ml_kem_envelope::seal(
            &seed,
            ml_kem_envelope::KemAlgorithm::MlKem768,
            ml_kem_envelope::EnvelopeAlgorithm::ChaCha20Poly1305,
            b"sealed-by-sender",
            b"ctx",
        )
        .expect("seal");
        let err = mgr
            .provider_unwrap_envelope(
                "enroll.mlkem",
                ProviderKemAlgorithm::MlKem768,
                ProviderEnvelopeAlgorithm::ChaCha20Poly1305,
                ml_kem_parts(&env),
                b"ctx",
                ProviderGate {
                    local_software_allowed: true,
                },
            )
            .await
            .expect_err("raw private seed storage must be rejected");
        assert!(matches!(
            err,
            ManagerError::Provider(ProviderError::CryptoFailed { .. })
        ));
        assert_eq!(
            primary.last_path().as_deref(),
            Some("secret/data/enroll/ml-kem-768")
        );
    }
    #[tokio::test]
    async fn ml_kem_software_custody_rejects_record_metadata_mismatch() {
        let (mgr, primary, _s) = fixture();
        let seed = [0x42; ml_kem_envelope::SEED_LEN];
        // Record declares keyVersion 4, but the mock serves it at version 5.
        primary.seed_kv(
            "secret/data/enroll/ml-kem-768",
            ml_kem_record_bytes("enroll.mlkem", &seed, 4),
        );
        let env = ml_kem_envelope::seal(
            &seed,
            ml_kem_envelope::KemAlgorithm::MlKem768,
            ml_kem_envelope::EnvelopeAlgorithm::ChaCha20Poly1305,
            b"sealed-by-sender",
            b"ctx",
        )
        .expect("seal");
        let err = mgr
            .provider_unwrap_envelope(
                "enroll.mlkem",
                ProviderKemAlgorithm::MlKem768,
                ProviderEnvelopeAlgorithm::ChaCha20Poly1305,
                ml_kem_parts(&env),
                b"ctx",
                ProviderGate {
                    local_software_allowed: true,
                },
            )
            .await
            .expect_err("KV version mismatch must fail before decrypt");
        assert!(matches!(
            err,
            ManagerError::Provider(ProviderError::CryptoFailed { .. })
        ));
        assert_eq!(
            primary.last_path().as_deref(),
            Some("secret/data/enroll/ml-kem-768")
        );
    }

    #[tokio::test]
    async fn ml_kem_unwrap_rejects_wrong_key_type() {
        let (mgr, _primary, _s) = fixture();
        // The keyType cross-check fails before any KV read, so no custody record is
        // provisioned; a bare seed is enough to build a well-formed envelope.
        let seed = [0x42; ml_kem_envelope::SEED_LEN];
        let env = ml_kem_envelope::seal(
            &seed,
            ml_kem_envelope::KemAlgorithm::MlKem768,
            ml_kem_envelope::EnvelopeAlgorithm::ChaCha20Poly1305,
            b"sealed-by-sender",
            b"ctx",
        )
        .expect("seal");
        // enroll.sealing is an X25519 key; it cannot unwrap an ML-KEM envelope.
        // The keyType cross-check fails closed before any provider dispatch.
        let err = mgr
            .provider_unwrap_envelope(
                "enroll.sealing",
                ProviderKemAlgorithm::MlKem768,
                ProviderEnvelopeAlgorithm::ChaCha20Poly1305,
                ml_kem_parts(&env),
                b"ctx",
                ProviderGate {
                    local_software_allowed: true,
                },
            )
            .await
            .expect_err("x25519 key cannot unwrap ML-KEM");
        assert!(matches!(err, ManagerError::KemAlgorithmMismatch { .. }));
    }

    #[tokio::test]
    async fn ml_kem_wrap_rejects_wrong_kem_param_set() {
        let (mgr, _primary, _s) = fixture();
        // enroll.mlkem is ml-kem-768; a request for ml-kem-512 wrap is rejected
        // by the keyType cross-check before any provider dispatch.
        let err = mgr
            .provider_wrap_envelope(
                "enroll.mlkem",
                ProviderKemAlgorithm::MlKem512,
                ProviderEnvelopeAlgorithm::ChaCha20Poly1305,
                b"top secret",
                b"ctx",
                ProviderGate {
                    local_software_allowed: true,
                },
            )
            .await
            .expect_err("wrong KEM param set must be rejected");
        assert!(matches!(err, ManagerError::KemAlgorithmMismatch { .. }));
    }

    #[tokio::test]
    async fn ml_kem_wrap_and_unwrap_without_grant_denied() {
        let (mgr, _primary, _s) = fixture();
        let deny = ProviderGate {
            local_software_allowed: false,
        };
        let wrap_err = mgr
            .provider_wrap_envelope(
                "enroll.mlkem",
                ProviderKemAlgorithm::MlKem768,
                ProviderEnvelopeAlgorithm::ChaCha20Poly1305,
                b"top secret",
                b"ctx",
                deny,
            )
            .await
            .expect_err("wrap denied without local-software grant");
        assert!(matches!(
            wrap_err,
            ManagerError::Provider(ProviderError::PolicyDenied { .. })
        ));
        let unwrap_err = mgr
            .provider_unwrap_envelope(
                "enroll.mlkem",
                ProviderKemAlgorithm::MlKem768,
                ProviderEnvelopeAlgorithm::ChaCha20Poly1305,
                MlKemEnvelopeParts {
                    encapsulated_key: b"x",
                    nonce: &[0u8; 12],
                    ciphertext: b"y",
                },
                b"ctx",
                deny,
            )
            .await
            .expect_err("unwrap denied without local-software grant");
        assert!(matches!(
            unwrap_err,
            ManagerError::Provider(ProviderError::PolicyDenied { .. })
        ));
    }

    #[tokio::test]
    async fn sealing_unwrap_wrong_aad_fails_opaque() {
        let (mgr, primary, _s) = fixture();
        let recipient_pub = seed_sealing_private(&primary);
        let env = x25519_seal::seal(&recipient_pub, b"x", b"right").expect("seal");
        let err = mgr
            .unwrap_envelope("enroll.sealing", &env, b"wrong")
            .await
            .expect_err("aad mismatch must fail");
        assert!(matches!(
            err,
            ManagerError::Sealing(SealingFailure::OpenFailed)
        ));
    }

    #[tokio::test]
    async fn sealing_unwrap_tampered_ciphertext_fails_opaque() {
        let (mgr, primary, _s) = fixture();
        let recipient_pub = seed_sealing_private(&primary);
        let mut env = x25519_seal::seal(&recipient_pub, b"payload", b"aad").expect("seal");
        if let Some(b) = env.ciphertext.first_mut() {
            *b ^= 0xFF;
        }
        assert!(matches!(
            mgr.unwrap_envelope("enroll.sealing", &env, b"aad").await,
            Err(ManagerError::Sealing(SealingFailure::OpenFailed))
        ));
    }

    #[tokio::test]
    async fn sealing_unwrap_malformed_private_fails() {
        // A non-32-byte stored value (corrupt/misprovisioned key) is Malformed, not
        // an opaque open failure; it never reaches the ECDH.
        let (mgr, primary, _s) = fixture();
        *primary.last_kv_value.lock().unwrap() = Some(vec![0u8; 16]);
        let env = SealedEnvelope {
            encapsulated_key: [9u8; 32],
            nonce: [0u8; 12],
            ciphertext: vec![1, 2, 3],
        };
        assert!(matches!(
            mgr.unwrap_envelope("enroll.sealing", &env, b"").await,
            Err(ManagerError::Sealing(SealingFailure::Malformed))
        ));
    }

    #[tokio::test]
    async fn wrap_unwrap_reject_non_sealing_key() {
        // The KEM envelope path is sealing-only: a symmetric key is rejected by
        // require_class before any crypto.
        let (mgr, _p, _s) = fixture();
        assert!(matches!(
            mgr.wrap_envelope("sym.box", b"x", b"").await,
            Err(ManagerError::OpNotValidForClass {
                op: "wrap_envelope",
                ..
            })
        ));
        let env = SealedEnvelope {
            encapsulated_key: [0u8; 32],
            nonce: [0u8; 12],
            ciphertext: vec![],
        };
        assert!(matches!(
            mgr.unwrap_envelope("sym.box", &env, b"").await,
            Err(ManagerError::OpNotValidForClass {
                op: "unwrap_envelope",
                ..
            })
        ));
    }

    // ---- Value-store Ed25519 materialize-to-sign (engine=kv2, vault-iiz) -------

    /// Provision a fixed Ed25519 value-store signing key into the `primary` mock
    /// out of band: the 32-byte seed at the catalog `path` (materialized only on
    /// `sign`) and the public at the catalog `public_path` (read by
    /// `verify`/`get_public_key`, basil-o86). Returns the public.
    fn seed_signing_seed(primary: &Arc<MockBackend>) -> [u8; 32] {
        let seed = Zeroizing::new([0x11u8; 32]);
        let public = ed25519_sign::public_from_seed(&seed);
        primary.seed_kv("secret/data/kv2/signer", seed.to_vec());
        primary.seed_kv("secret/data/kv2/signer-public", public.to_vec());
        public
    }

    #[tokio::test]
    async fn kv2_signer_resolves_as_asymmetric_kv2() {
        let (mgr, _p, _s) = fixture();
        let routed = mgr.resolve("kv2.signer").expect("resolves");
        assert_eq!(routed.class(), Class::Asymmetric);
        assert_eq!(routed.engine, Engine::Kv2);
        assert_eq!(routed.key_type(), Some(KeyAlgorithm::Ed25519));
    }

    #[tokio::test]
    async fn kv2_signer_rejects_get_and_set() {
        // LEAST PRIVILEGE: a value-store signing key inherits the Asymmetric op
        // surface, so its private seed is structurally un-gettable/un-settable:
        // require_class fails closed before any backend call (same class as a
        // transit signer; the seed never leaks through the KV get/set ops).
        let (mgr, _p, _s) = fixture();
        let get_err = mgr
            .get("kv2.signer", None)
            .await
            .expect_err("get must be denied on a value-store signing key");
        assert!(matches!(
            get_err,
            ManagerError::OpNotValidForClass {
                op: "get",
                class: Class::Asymmetric,
                ..
            }
        ));
        let set_err = mgr
            .set("kv2.signer", b"anything")
            .await
            .expect_err("set must be denied on a value-store signing key");
        assert!(matches!(
            set_err,
            ManagerError::OpNotValidForClass {
                op: "set",
                class: Class::Asymmetric,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn kv2_signer_rejects_rotate_and_import() {
        // A value-store (kv2) signing key is re-provisioned out-of-band, never
        // transit-rotated or BYOK-imported through the broker. The refusal is an
        // EXPLICIT guard (not an incidental transit-backend 404 on the KV path),
        // so the op surface stays intentionally {sign, verify, get_public_key}.
        let (mgr, _p, _s) = fixture();
        assert!(matches!(
            mgr.rotate("kv2.signer", BrokerLimits::default()).await,
            Err(ManagerError::Unsupported(m)) if m.starts_with("rotate")
        ));
        assert!(matches!(
            mgr.import(
                "kv2.signer",
                KeyType::Ed25519,
                &KeyMaterial::Ed25519Seed(vec![0; 32]),
            )
            .await,
            Err(ManagerError::Unsupported(m)) if m.starts_with("import")
        ));
    }

    #[tokio::test]
    async fn kv2_signer_materializes_and_signs_matching_in_proc() {
        // ACCEPTANCE: the in-proc Ed25519 sign matches a fresh in-process sign over
        // the same seed+message, and verifies under the derived public.
        let (mgr, primary, _s) = fixture();
        let public = seed_signing_seed(&primary);
        let message = b"sign me with a materialized seed";

        let sig = mgr.sign("kv2.signer", message).await.expect("sign");
        assert_eq!(sig.len(), ed25519_sign::SIGNATURE_LEN);
        // The signature matches the crypto core over the seeded key (deterministic).
        let expected = ed25519_sign::sign(&Zeroizing::new([0x11u8; 32]), message);
        assert_eq!(sig.as_slice(), expected.as_slice());
        // And it verifies under the derived public key.
        assert_eq!(ed25519_sign::verify(&public, message, &sig), Ok(true));
        // The materialize routed to the catalog KV path (a SECRET read), not a
        // transit sign name.
        assert_eq!(
            primary.last_path().as_deref(),
            Some("secret/data/kv2/signer")
        );
    }

    #[tokio::test]
    async fn kv2_signer_verify_round_trips_in_proc() {
        let (mgr, primary, _s) = fixture();
        seed_signing_seed(&primary);
        let message = b"verify me";
        let sig = mgr.sign("kv2.signer", message).await.expect("sign");
        assert!(
            mgr.verify("kv2.signer", message, &sig)
                .await
                .expect("verify")
        );
        // A tampered message fails verification (no panic on attacker bytes).
        assert!(
            !mgr.verify("kv2.signer", b"verify-tampered", &sig)
                .await
                .expect("verify")
        );
    }

    #[tokio::test]
    async fn kv2_signer_get_public_key_reads_out_of_band_public() {
        // basil-o86: get_public_key reads the out-of-band public from `public_path`.
        // The seed is NEVER materialized for it.
        let (mgr, primary, _s) = fixture();
        let expected_pub = seed_signing_seed(&primary);
        let pk = mgr.get_public_key("kv2.signer").await.expect("public");
        assert_eq!(pk.public_key.as_slice(), expected_pub.as_slice());
        assert_eq!(pk.key_type, KeyType::Ed25519);
        // The read routed to the PUBLIC path, not the seed materialize path.
        assert_eq!(
            primary.last_path().as_deref(),
            Some("secret/data/kv2/signer-public")
        );
    }

    #[tokio::test]
    async fn kv2_signer_public_ops_never_materialize_seed() {
        // basil-o86 PROOF (signing sibling): a CORRECT public but a GARBAGE
        // (7-byte) seed. verify + get_public_key read the out-of-band public, so a
        // garbage seed can't break them, proving the seed is untouched. `sign`
        // (the private op) still materializes the seed; here we only drive the
        // public ops.
        let (mgr, primary, _s) = fixture();
        let seed = Zeroizing::new([0x11u8; 32]);
        let public = ed25519_sign::public_from_seed(&seed);
        primary.seed_kv("secret/data/kv2/signer-public", public.to_vec());
        primary.seed_kv("secret/data/kv2/signer", vec![0xFF; 7]);

        let pk = mgr
            .get_public_key("kv2.signer")
            .await
            .expect("public read despite garbage seed");
        assert_eq!(pk.public_key.as_slice(), public.as_slice());
        // A signature made offline under the real seed verifies through the broker
        // (which reads only the out-of-band public).
        let sig = ed25519_sign::sign(&seed, b"m");
        assert!(
            mgr.verify("kv2.signer", b"m", &sig)
                .await
                .expect("verify reads only the public")
        );
    }

    #[tokio::test]
    async fn materialize_public_op_without_public_path_fails_closed() {
        // The loader REQUIRES a publicPath on a materialize-to-use key; this guards
        // a manager built from an UNVALIDATED catalog (serde-direct, bypassing
        // `load`). A public op then fails closed with MissingPublicPath rather than
        // re-deriving the public from the private (which the op surface forbids).
        const NO_PUB: &str = r#"{
          "schemaVersion": 1,
          "backends": { "primary": { "kind": "vault", "addr": "https://127.0.0.1:8200" } },
          "keys": {
            "enroll.sealing": {
              "class": "sealing", "keyType": "x25519", "backend": "primary", "engine": "kv2",
              "path": "secret/data/enroll/x25519", "writable": true, "missing": "error",
              "description": "a sealing key missing its publicPath"
            }
          }
        }"#;
        let primary = MockBackend::new("primary");
        let mut backends: BTreeMap<String, Box<dyn Backend>> = BTreeMap::new();
        backends.insert("primary".into(), Box::new(MockHandle(primary)));
        let mgr = BackendManager::new(parse_catalog(NO_PUB), backends).expect("constructs");

        assert!(matches!(
            mgr.sealing_public_key("enroll.sealing").await,
            Err(ManagerError::MissingPublicPath(k)) if k == "enroll.sealing"
        ));
        assert!(matches!(
            mgr.wrap_envelope("enroll.sealing", b"x", b"a").await,
            Err(ManagerError::MissingPublicPath(_))
        ));
    }

    #[tokio::test]
    async fn kv2_signer_malformed_seed_is_signing_failure_not_panic() {
        // A non-32-byte stored value (corrupt/misprovisioned seed) fails closed with
        // a Signing(Malformed); it never indexes/panics on the KV bytes.
        let (mgr, primary, _s) = fixture();
        *primary.last_kv_value.lock().unwrap() = Some(vec![0u8; 16]);
        assert!(matches!(
            mgr.sign("kv2.signer", b"m").await,
            Err(ManagerError::Signing(SigningFailure::Malformed))
        ));
    }

    #[tokio::test]
    async fn kv2_signer_verify_rejects_wrong_length_signature_opaquely() {
        // A wrong-length signature is a malformed verify input (Signing), not a
        // crash: the conversion fails closed.
        let (mgr, primary, _s) = fixture();
        seed_signing_seed(&primary);
        assert!(matches!(
            mgr.verify("kv2.signer", b"m", &[0u8; 10]).await,
            Err(ManagerError::Signing(SigningFailure::Malformed))
        ));
    }

    #[tokio::test]
    async fn transit_signer_still_uses_backend_sign_in_place() {
        // The transit arm is unchanged: asym.signer (engine inferred Transit) routes
        // to the backend's in-place sign, NOT the materialize path.
        let (mgr, primary, _s) = fixture();
        let sig = mgr.sign("asym.signer", b"m").await.expect("sign");
        // The mock transit sign returns the fixed [0xAB, 0xCD]; the materialize path
        // would have returned a 64-byte ed25519 signature instead.
        assert_eq!(sig, vec![0xAB, 0xCD]);
        assert_eq!(primary.last_path().as_deref(), Some("signer"));
    }
}

#[cfg(test)]
mod pqc_dispatch_tests {
    use std::collections::{BTreeMap, HashMap};
    use std::sync::Mutex;

    use async_trait::async_trait;

    use super::{
        BackendManager, Catalog, CryptoProviderId, CustodyMode, KeyProviderDescriptor,
        ManagerError, ProviderError, ProviderGate, ProviderPolicy,
    };
    use crate::backend::{Backend, BackendError, KvValue, NativeAlgorithm, NewKey};
    use crate::core::crypto_provider::{ProviderAuditEvent, ProviderAuditOutcome};
    use crate::core::ml_dsa_sign::{self, MlDsaAlgorithm};
    use basil_proto::{AeadAlgorithm, CiphertextEnvelope, KeyType};

    /// A stateful in-memory backend for the ML-DSA provider-dispatch round trip.
    /// `encrypt` length-prefixes the AAD ahead of the plaintext so `decrypt` can
    /// authenticate it (a faithful AAD check without a real AEAD); `kv_put`/`kv_get`
    /// keep records at a fixed version 1, matching a freshly provisioned key.
    #[derive(Default)]
    struct PqcBackend {
        store: Mutex<HashMap<String, Vec<u8>>>,
    }

    #[async_trait]
    impl Backend for PqcBackend {
        fn kind(&self) -> &'static str {
            "pqc-dispatch-test"
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

        async fn encrypt(
            &self,
            _key_id: &str,
            algorithm: AeadAlgorithm,
            plaintext: &[u8],
            aad: Option<&[u8]>,
        ) -> Result<CiphertextEnvelope, BackendError> {
            let aad = aad.unwrap_or(&[]);
            let mut ciphertext = vec![u8::try_from(aad.len()).unwrap_or(u8::MAX)];
            ciphertext.extend_from_slice(aad);
            ciphertext.extend_from_slice(plaintext);
            Ok(CiphertextEnvelope {
                alg: algorithm,
                key_version: 1,
                nonce: Vec::new(),
                ciphertext,
            })
        }

        async fn decrypt(
            &self,
            _key_id: &str,
            envelope: &CiphertextEnvelope,
            aad: Option<&[u8]>,
        ) -> Result<Vec<u8>, BackendError> {
            let aad = aad.unwrap_or(&[]);
            let ct = &envelope.ciphertext;
            let aad_len = *ct.first().ok_or(BackendError::DecryptFailed)? as usize;
            let bound = ct.get(1..1 + aad_len).ok_or(BackendError::DecryptFailed)?;
            if bound != aad {
                return Err(BackendError::DecryptFailed);
            }
            Ok(ct
                .get(1 + aad_len..)
                .ok_or(BackendError::DecryptFailed)?
                .to_vec())
        }

        async fn kv_put(&self, key_id: &str, value: &[u8]) -> Result<u32, BackendError> {
            self.store
                .lock()
                .map_err(|_| BackendError::Unsupported("kv_put"))?
                .insert(key_id.to_string(), value.to_vec());
            Ok(1)
        }

        async fn kv_get(
            &self,
            key_id: &str,
            _version: Option<u32>,
        ) -> Result<KvValue, BackendError> {
            let value = self
                .store
                .lock()
                .map_err(|_| BackendError::Unsupported("kv_get"))?
                .get(key_id)
                .cloned();
            value
                .map(|value| KvValue { value, version: 1 })
                .ok_or(BackendError::Unsupported("kv_get"))
        }
    }

    /// A fake **backend-native** ML-DSA backend for the migration tests.
    ///
    /// It reports native ML-DSA support and performs generate/sign/verify *in
    /// place* (the seed is held inside the backend and never returned), modeling
    /// a future Vault/OpenBao with native ML-DSA transit. It also custodies
    /// software records (`encrypt`/`decrypt`/`kv_*`, mirroring [`PqcBackend`]) so a
    /// software-pinned key on the same backend still round-trips, which is exactly
    /// what the "probe must not re-route an existing software key" test needs.
    #[derive(Default)]
    struct NativePqcBackend {
        seeds: Mutex<HashMap<String, [u8; 32]>>,
        store: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl NativePqcBackend {
        const fn dsa(native: NativeAlgorithm) -> MlDsaAlgorithm {
            match native {
                NativeAlgorithm::MlDsa44 => MlDsaAlgorithm::MlDsa44,
                NativeAlgorithm::MlDsa65 => MlDsaAlgorithm::MlDsa65,
                NativeAlgorithm::MlDsa87 => MlDsaAlgorithm::MlDsa87,
            }
        }

        /// A deterministic in-backend seed for `key_id` (test custody: the seed
        /// never leaves the backend, exactly as a native transit key would not).
        fn seed_for(key_id: &str) -> [u8; 32] {
            let mut seed = [7u8; 32];
            for (slot, byte) in seed.iter_mut().zip(key_id.bytes()) {
                *slot = byte;
            }
            seed
        }
    }

    #[async_trait]
    impl Backend for NativePqcBackend {
        fn kind(&self) -> &'static str {
            "pqc-native-test"
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

        fn supports_native_algorithm(&self, algorithm: NativeAlgorithm) -> bool {
            matches!(
                algorithm,
                NativeAlgorithm::MlDsa44 | NativeAlgorithm::MlDsa65 | NativeAlgorithm::MlDsa87
            )
        }

        async fn create_named_pqc_key(
            &self,
            key_id: &str,
            algorithm: NativeAlgorithm,
        ) -> Result<NewKey, BackendError> {
            let seed = Self::seed_for(key_id);
            let public = ml_dsa_sign::public_from_seed(Self::dsa(algorithm), &seed)
                .map_err(|_| BackendError::Unsupported("create_named_pqc_key"))?;
            self.seeds
                .lock()
                .map_err(|_| BackendError::Unsupported("create_named_pqc_key"))?
                .insert(key_id.to_string(), seed);
            Ok(NewKey {
                key_id: key_id.to_string(),
                public_key: public,
            })
        }

        async fn sign_pqc(
            &self,
            key_id: &str,
            message: &[u8],
            algorithm: NativeAlgorithm,
        ) -> Result<Vec<u8>, BackendError> {
            let seed = self
                .seeds
                .lock()
                .map_err(|_| BackendError::Unsupported("sign_pqc"))?
                .get(key_id)
                .copied()
                .ok_or_else(|| BackendError::KeyNotFound(key_id.to_string()))?;
            ml_dsa_sign::sign(Self::dsa(algorithm), &seed, message)
                .map_err(|_| BackendError::Unsupported("sign_pqc"))
        }

        async fn verify_pqc(
            &self,
            key_id: &str,
            message: &[u8],
            signature: &[u8],
            algorithm: NativeAlgorithm,
        ) -> Result<bool, BackendError> {
            let seed = self
                .seeds
                .lock()
                .map_err(|_| BackendError::Unsupported("verify_pqc"))?
                .get(key_id)
                .copied()
                .ok_or_else(|| BackendError::KeyNotFound(key_id.to_string()))?;
            let public = ml_dsa_sign::public_from_seed(Self::dsa(algorithm), &seed)
                .map_err(|_| BackendError::Unsupported("verify_pqc"))?;
            ml_dsa_sign::verify(Self::dsa(algorithm), &public, message, signature)
                .map_err(|_| BackendError::Unsupported("verify_pqc"))
        }

        async fn encrypt(
            &self,
            _key_id: &str,
            algorithm: AeadAlgorithm,
            plaintext: &[u8],
            aad: Option<&[u8]>,
        ) -> Result<CiphertextEnvelope, BackendError> {
            let aad = aad.unwrap_or(&[]);
            let mut ciphertext = vec![u8::try_from(aad.len()).unwrap_or(u8::MAX)];
            ciphertext.extend_from_slice(aad);
            ciphertext.extend_from_slice(plaintext);
            Ok(CiphertextEnvelope {
                alg: algorithm,
                key_version: 1,
                nonce: Vec::new(),
                ciphertext,
            })
        }

        async fn decrypt(
            &self,
            _key_id: &str,
            envelope: &CiphertextEnvelope,
            aad: Option<&[u8]>,
        ) -> Result<Vec<u8>, BackendError> {
            let aad = aad.unwrap_or(&[]);
            let ct = &envelope.ciphertext;
            let aad_len = *ct.first().ok_or(BackendError::DecryptFailed)? as usize;
            let bound = ct.get(1..1 + aad_len).ok_or(BackendError::DecryptFailed)?;
            if bound != aad {
                return Err(BackendError::DecryptFailed);
            }
            Ok(ct
                .get(1 + aad_len..)
                .ok_or(BackendError::DecryptFailed)?
                .to_vec())
        }

        async fn kv_put(&self, key_id: &str, value: &[u8]) -> Result<u32, BackendError> {
            self.store
                .lock()
                .map_err(|_| BackendError::Unsupported("kv_put"))?
                .insert(key_id.to_string(), value.to_vec());
            Ok(1)
        }

        async fn kv_get(
            &self,
            key_id: &str,
            _version: Option<u32>,
        ) -> Result<KvValue, BackendError> {
            let value = self
                .store
                .lock()
                .map_err(|_| BackendError::Unsupported("kv_get"))?
                .get(key_id)
                .cloned();
            value
                .map(|value| KvValue { value, version: 1 })
                .ok_or(BackendError::Unsupported("kv_get"))
        }
    }

    const PQC_CATALOG: &str = r#"{
      "schemaVersion": 1,
      "backends": { "primary": { "kind": "vault", "addr": "https://127.0.0.1:8200" } },
      "keys": {
        "pqc.signer44": {
          "class": "asymmetric", "keyType": "ml-dsa-44", "backend": "primary",
          "path": "secret/data/pqc/44", "writable": true, "missing": "error",
          "labels": ["crypto_provider=local-software", "crypto_provider_policy=local-software",
                     "pqc_custody=software-encrypted", "pqc_storage_key=pqc/aead",
                     "crypto_provider_version=1"],
          "description": "ml-dsa-44 software-custodied signer"
        },
        "pqc.signer65": {
          "class": "asymmetric", "keyType": "ml-dsa-65", "backend": "primary",
          "path": "secret/data/pqc/65", "writable": true, "missing": "error",
          "labels": ["crypto_provider=local-software", "crypto_provider_policy=local-software",
                     "pqc_custody=software-encrypted", "pqc_storage_key=pqc/aead",
                     "crypto_provider_version=1"],
          "description": "ml-dsa-65 software-custodied signer"
        },
        "pqc.signer87": {
          "class": "asymmetric", "keyType": "ml-dsa-87", "backend": "primary",
          "path": "secret/data/pqc/87", "writable": true, "missing": "error",
          "labels": ["crypto_provider=local-software", "crypto_provider_policy=local-software",
                     "pqc_custody=software-encrypted", "pqc_storage_key=pqc/aead",
                     "crypto_provider_version=1"],
          "description": "ml-dsa-87 software-custodied signer"
        },
        "pqc.backendreq": {
          "class": "asymmetric", "keyType": "ml-dsa-65", "backend": "primary",
          "path": "secret/data/pqc/breq", "writable": true, "missing": "error",
          "labels": ["crypto_provider_policy=backend-required", "pqc_custody=software-encrypted"],
          "description": "backend-required ml-dsa signer (no native provider)"
        },
        "pqc.preferred_native": {
          "class": "asymmetric", "keyType": "ml-dsa-65", "backend": "primary",
          "path": "pqc/native65", "writable": true, "missing": "error",
          "labels": ["crypto_provider_policy=backend-preferred", "crypto_provider_version=1"],
          "description": "backend-preferred ml-dsa signer (native when the backend supports it)"
        },
        "pqc.preferred_software": {
          "class": "asymmetric", "keyType": "ml-dsa-65", "backend": "primary",
          "path": "secret/data/pqc/pref-sw", "writable": true, "missing": "error",
          "labels": ["crypto_provider_policy=backend-preferred", "pqc_custody=software-encrypted",
                     "pqc_storage_key=pqc/aead", "crypto_provider_version=1"],
          "description": "backend-preferred ml-dsa signer pinned to software custody"
        },
        "pqc.backendreq_native": {
          "class": "asymmetric", "keyType": "ml-dsa-65", "backend": "primary",
          "path": "pqc/breq-native", "writable": true, "missing": "error",
          "labels": ["crypto_provider_policy=backend-required", "crypto_provider_version=1"],
          "description": "backend-required ml-dsa signer served by a native backend"
        }
      }
    }"#;

    fn manager() -> BackendManager {
        let catalog: Catalog = serde_json::from_str(PQC_CATALOG).expect("catalog parses");
        let mut backends: BTreeMap<String, Box<dyn Backend>> = BTreeMap::new();
        backends.insert("primary".into(), Box::new(PqcBackend::default()));
        BackendManager::new(catalog, backends).expect("manager builds")
    }

    /// The same catalog as [`manager`], but served by a backend that reports
    /// native ML-DSA support (the migration target).
    fn native_manager() -> BackendManager {
        let catalog: Catalog = serde_json::from_str(PQC_CATALOG).expect("catalog parses");
        let mut backends: BTreeMap<String, Box<dyn Backend>> = BTreeMap::new();
        backends.insert("primary".into(), Box::new(NativePqcBackend::default()));
        BackendManager::new(catalog, backends).expect("manager builds")
    }

    const fn allowed() -> ProviderGate {
        ProviderGate {
            local_software_allowed: true,
        }
    }

    #[tokio::test]
    async fn generate_sign_verify_round_trip_all_levels() {
        let cases = [
            ("pqc.signer44", MlDsaAlgorithm::MlDsa44, "ml-dsa-44"),
            ("pqc.signer65", MlDsaAlgorithm::MlDsa65, "ml-dsa-65"),
            ("pqc.signer87", MlDsaAlgorithm::MlDsa87, "ml-dsa-87"),
        ];
        for (key_id, dsa, token) in cases {
            let mgr = manager();
            let message = b"basil ml-dsa dispatch";

            let (created, gen_dispatch) = mgr
                .provider_generate(key_id, allowed())
                .await
                .expect("generate");
            assert_eq!(gen_dispatch.provider, CryptoProviderId::LocalSoftware);
            assert_eq!(gen_dispatch.algorithm, token);
            assert!(!created.public_key.is_empty(), "{token} public");

            let (signature, sign_dispatch) = mgr
                .provider_sign(key_id, message, allowed())
                .await
                .expect("sign");
            assert_eq!(sign_dispatch.provider, CryptoProviderId::LocalSoftware);
            assert_eq!(sign_dispatch.algorithm, token);
            assert_eq!(sign_dispatch.custody, CustodyMode::SoftwareEncrypted);

            let (valid, _) = mgr
                .provider_verify(key_id, message, &signature, allowed())
                .await
                .expect("verify");
            assert!(valid, "{token} verifies through the broker");

            // The returned public verifies the broker-produced signature directly.
            assert!(
                ml_dsa_sign::verify(dsa, &created.public_key, message, &signature).expect("core"),
                "{token} verifies under returned public",
            );

            // A tampered message must not verify.
            let (bad, _) = mgr
                .provider_verify(key_id, b"tampered", &signature, allowed())
                .await
                .expect("verify");
            assert!(!bad, "{token} rejects a tampered message");
        }
    }

    #[tokio::test]
    async fn backend_required_ml_dsa_fails_closed() {
        let mgr = manager();
        // No backend-native ML-DSA provider exists, so a backend-required key
        // fails closed at provider selection, before any custody read.
        let err = mgr
            .provider_sign("pqc.backendreq", b"m", allowed())
            .await
            .expect_err("backend-required ml-dsa is unsupported");
        assert!(matches!(
            err,
            ManagerError::Provider(ProviderError::Unsupported { .. })
        ));
        let gen_err = mgr
            .provider_generate("pqc.backendreq", allowed())
            .await
            .expect_err("backend-required ml-dsa generate is unsupported");
        assert!(matches!(
            gen_err,
            ManagerError::Provider(ProviderError::Unsupported { .. })
        ));
    }

    #[tokio::test]
    async fn local_software_without_policy_grant_is_denied() {
        let mgr = manager();
        let denied = ProviderGate {
            local_software_allowed: false,
        };
        for outcome in [
            mgr.provider_sign("pqc.signer65", b"m", denied).await,
            mgr.provider_generate("pqc.signer65", denied)
                .await
                .map(|(key, dispatch)| (key.public_key, dispatch)),
        ] {
            let err = outcome.expect_err("local software requires an explicit policy grant");
            assert!(matches!(
                err,
                ManagerError::Provider(ProviderError::PolicyDenied { .. })
            ));
        }
    }

    #[tokio::test]
    async fn dispatch_feeds_a_secret_free_provider_audit_event() {
        let mgr = manager();
        mgr.provider_generate("pqc.signer87", allowed())
            .await
            .expect("generate");
        let (_signature, dispatch) = mgr
            .provider_sign("pqc.signer87", b"m", allowed())
            .await
            .expect("sign");
        // The service builds the audit event from the dispatch; it must carry the
        // provider and algorithm and never any key/signature bytes.
        let event = ProviderAuditEvent {
            op: "sign",
            key_id: "pqc.signer87",
            key_version: None,
            algorithm: dispatch.algorithm,
            provider: dispatch.provider,
            custody: dispatch.custody,
            caller_uid: 4242,
            outcome: ProviderAuditOutcome::Success,
            reason: "ok",
        };
        let value = event.to_json_value();
        assert_eq!(value["provider"], "local-software");
        assert_eq!(value["algorithm"], "ml-dsa-87");
        assert_eq!(value["op"], "sign");
        assert_eq!(value["caller_uid"], 4242);
        assert!(value.get("signature").is_none());
        assert!(value.get("private_key").is_none());
    }

    #[tokio::test]
    async fn backend_preferred_routes_to_native_when_backend_supports_it() {
        // A backend-preferred key with NO declared software custody, served by a
        // backend that natively supports ML-DSA: provisioning + ops transparently
        // route to the backend-native provider and round-trip in place.
        let mgr = native_manager();
        let key_id = "pqc.preferred_native";
        let message = b"basil native ml-dsa";

        let (created, gen_dispatch) = mgr
            .provider_generate(key_id, allowed())
            .await
            .expect("generate");
        assert_eq!(gen_dispatch.provider, CryptoProviderId::VaultTransit);
        assert_eq!(gen_dispatch.custody, CustodyMode::BackendNative);
        assert!(!created.public_key.is_empty(), "native public");

        let (signature, sign_dispatch) = mgr
            .provider_sign(key_id, message, allowed())
            .await
            .expect("sign");
        assert_eq!(sign_dispatch.provider, CryptoProviderId::VaultTransit);
        assert_eq!(sign_dispatch.custody, CustodyMode::BackendNative);

        let (valid, _) = mgr
            .provider_verify(key_id, message, &signature, allowed())
            .await
            .expect("verify");
        assert!(valid, "native signature verifies through the broker");

        let (bad, _) = mgr
            .provider_verify(key_id, b"tampered", &signature, allowed())
            .await
            .expect("verify");
        assert!(!bad, "native verify rejects a tampered message");
    }

    #[tokio::test]
    async fn backend_required_routes_to_native_when_backend_supports_it() {
        // The capability probe also unblocks a backend-required key: with a native
        // backend it provisions + signs natively instead of failing closed (the
        // non-native fail-closed case is `backend_required_ml_dsa_fails_closed`).
        let mgr = native_manager();
        let key_id = "pqc.backendreq_native";

        let (_created, gen_dispatch) = mgr
            .provider_generate(key_id, allowed())
            .await
            .expect("generate");
        assert_eq!(gen_dispatch.provider, CryptoProviderId::VaultTransit);

        let (signature, sign_dispatch) = mgr
            .provider_sign(key_id, b"m", allowed())
            .await
            .expect("sign");
        assert_eq!(sign_dispatch.provider, CryptoProviderId::VaultTransit);
        let (valid, _) = mgr
            .provider_verify(key_id, b"m", &signature, allowed())
            .await
            .expect("verify");
        assert!(valid);
    }

    #[tokio::test]
    async fn backend_preferred_falls_back_to_software_without_native_support() {
        // The same backend-preferred software-custodied key on a backend WITHOUT
        // native ML-DSA support falls back to the local-software provider.
        let mgr = manager();
        let key_id = "pqc.preferred_software";

        let (_created, gen_dispatch) = mgr
            .provider_generate(key_id, allowed())
            .await
            .expect("generate");
        assert_eq!(gen_dispatch.provider, CryptoProviderId::LocalSoftware);
        assert_eq!(gen_dispatch.custody, CustodyMode::SoftwareEncrypted);

        let (signature, sign_dispatch) = mgr
            .provider_sign(key_id, b"m", allowed())
            .await
            .expect("sign");
        assert_eq!(sign_dispatch.provider, CryptoProviderId::LocalSoftware);
        let (valid, _) = mgr
            .provider_verify(key_id, b"m", &signature, allowed())
            .await
            .expect("verify");
        assert!(valid);
    }

    #[tokio::test]
    async fn software_custodied_key_is_not_rerouted_by_native_probe() {
        // The migration invariant: an already-software-custodied key keeps using
        // the local-software provider even when the backend NOW reports native
        // support. The probe flipping to "supported" must never silently re-route
        // a key whose private seed lives software-encrypted in KV.
        let mgr = native_manager();
        let key_id = "pqc.preferred_software";

        let (_created, gen_dispatch) = mgr
            .provider_generate(key_id, allowed())
            .await
            .expect("generate");
        assert_eq!(
            gen_dispatch.provider,
            CryptoProviderId::LocalSoftware,
            "software-custodied key stays local-software despite native support",
        );

        let (_signature, sign_dispatch) = mgr
            .provider_sign(key_id, b"m", allowed())
            .await
            .expect("sign");
        assert_eq!(sign_dispatch.provider, CryptoProviderId::LocalSoftware);
        assert_eq!(sign_dispatch.custody, CustodyMode::SoftwareEncrypted);
    }

    #[tokio::test]
    async fn describe_provider_surfaces_active_custody_and_migration_availability() {
        // The admin read seam: which provider/custody/version a key is under, and
        // whether a backend-native migration is now available.
        let native = native_manager();

        let software = native
            .describe_provider("pqc.preferred_software")
            .expect("describe");
        let expected_software = KeyProviderDescriptor {
            policy: ProviderPolicy::BackendPreferred,
            provider: None,
            custody: Some(CustodyMode::SoftwareEncrypted),
            version: Some("1".to_string()),
            backend_native_available: true,
        };
        assert_eq!(
            software, expected_software,
            "an admin sees software custody AND that a native migration is available",
        );

        let preferred = native
            .describe_provider("pqc.preferred_native")
            .expect("describe");
        assert_eq!(preferred.custody, None);
        assert!(preferred.backend_native_available);

        // The same software key on a non-native backend reports no migration.
        let classical = manager();
        let no_native = classical
            .describe_provider("pqc.preferred_software")
            .expect("describe");
        assert!(!no_native.backend_native_available);

        assert!(matches!(
            classical.describe_provider("does.not.exist"),
            Err(ManagerError::UnknownKey(_))
        ));
    }
}
