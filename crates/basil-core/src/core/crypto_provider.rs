// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Provider-neutral crypto operation dispatch.
//!
//! This layer sits below `service::*` and above concrete backends. It describes
//! algorithm-provider capabilities without exposing provider internals or private
//! key material to callers.

use super::{ml_dsa_sign, ml_kem_envelope};
use crate::audit::timestamp;
use crate::backend::{Backend, BackendError, NativeAlgorithm, NewKey, SignOptions};
use crate::catalog::schema::KeyEntry;
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use basil_proto::{AeadAlgorithm, CiphertextEnvelope};
use basil_proto::{KeyMaterial, KeyType};
use serde::{Deserialize, Serialize};
use serde_json::json;
use zeroize::Zeroizing;

/// Supported signing algorithm families for provider dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// Plain Ed25519.
    Ed25519,
    /// Ed25519 used as a NATS `NKey`.
    Ed25519Nkey,
    /// JWS `RS256`.
    Rs256,
    /// JWS `ES256`.
    Es256,
    /// ML-DSA parameter level 44.
    MlDsa44,
    /// ML-DSA parameter level 65.
    MlDsa65,
    /// ML-DSA parameter level 87.
    MlDsa87,
}

impl SignatureAlgorithm {
    /// Whether this is a post-quantum ML-DSA signing algorithm (the family routed
    /// through the local-software crypto provider).
    #[must_use]
    pub const fn is_ml_dsa(self) -> bool {
        matches!(self, Self::MlDsa44 | Self::MlDsa65 | Self::MlDsa87)
    }

    /// The stable kebab-case token for this algorithm (used in audit + diagnostics).
    #[must_use]
    pub const fn token(self) -> &'static str {
        signature_algorithm_name(self)
    }

    /// The backend-native [`NativeAlgorithm`] this signing algorithm maps to, for
    /// the capability probe ([`Backend::supports_native_algorithm`]). `Some` only
    /// for the ML-DSA family: classical signing algorithms always custody in
    /// place and never consult the PQC native probe.
    #[must_use]
    pub const fn native_algorithm(self) -> Option<NativeAlgorithm> {
        match self {
            Self::MlDsa44 => Some(NativeAlgorithm::MlDsa44),
            Self::MlDsa65 => Some(NativeAlgorithm::MlDsa65),
            Self::MlDsa87 => Some(NativeAlgorithm::MlDsa87),
            Self::Ed25519 | Self::Ed25519Nkey | Self::Rs256 | Self::Es256 => None,
        }
    }
}

/// Map a catalog signing [`KeyAlgorithm`](crate::catalog::KeyAlgorithm) to the
/// provider [`SignatureAlgorithm`], returning `Some` only for the ML-DSA family.
///
/// This is the routing signal the manager uses to send a key down the
/// provider-dispatch path: a `Some` result means the key is an ML-DSA signing key
/// whose private is software-custodied, so `sign`/`verify`/`new_key` go through
/// [`select_provider`] and a [`CryptoProvider`] rather than the in-place backend
/// signing path. Classical signing algorithms return `None`.
#[must_use]
pub const fn ml_dsa_signature_algorithm(
    key_type: crate::catalog::KeyAlgorithm,
) -> Option<SignatureAlgorithm> {
    use crate::catalog::KeyAlgorithm;
    match key_type {
        KeyAlgorithm::MlDsa44 => Some(SignatureAlgorithm::MlDsa44),
        KeyAlgorithm::MlDsa65 => Some(SignatureAlgorithm::MlDsa65),
        KeyAlgorithm::MlDsa87 => Some(SignatureAlgorithm::MlDsa87),
        KeyAlgorithm::Ed25519
        | KeyAlgorithm::Ed25519Nkey
        | KeyAlgorithm::Rsa2048
        | KeyAlgorithm::EcdsaP256
        | KeyAlgorithm::EcdsaP384
        | KeyAlgorithm::EcdsaP521
        | KeyAlgorithm::Aes256Gcm
        | KeyAlgorithm::ChaCha20Poly1305
        | KeyAlgorithm::X25519
        | KeyAlgorithm::MlKem512
        | KeyAlgorithm::MlKem768
        | KeyAlgorithm::MlKem1024 => None,
    }
}

/// Supported KEM algorithm families for provider dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemAlgorithm {
    /// ML-KEM parameter level 512.
    MlKem512,
    /// ML-KEM parameter level 768.
    MlKem768,
    /// ML-KEM parameter level 1024.
    MlKem1024,
}

impl KemAlgorithm {
    /// The kebab-case token used in catalog labels, audit records, and provider
    /// dispatch (`ml-kem-512` / `ml-kem-768` / `ml-kem-1024`).
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::MlKem512 => "ml-kem-512",
            Self::MlKem768 => "ml-kem-768",
            Self::MlKem1024 => "ml-kem-1024",
        }
    }

    /// The backend-native [`NativeAlgorithm`] this KEM maps to, for the capability
    /// probe. Always `None`: no shipping backend exposes native ML-KEM transit, so
    /// ML-KEM keys always remain software-custodied and never route to a
    /// backend-native provider. When a backend gains native ML-KEM, add the
    /// variants both here and to [`BackendCryptoProvider`]'s envelope dispatch.
    #[must_use]
    pub const fn native_algorithm(self) -> Option<NativeAlgorithm> {
        match self {
            Self::MlKem512 | Self::MlKem768 | Self::MlKem1024 => None,
        }
    }
}

/// Symmetric envelope algorithm used after KEM shared-secret derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeAlgorithm {
    /// AES-256-GCM envelope encryption.
    Aes256Gcm,
    /// ChaCha20-Poly1305 envelope encryption.
    ChaCha20Poly1305,
}

/// Provider implementation selected for a key operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoProviderId {
    /// Backend-native Vault transit support (`HashiCorp` Vault or `OpenBao`).
    VaultTransit,
    /// Basil local software provider for software-custodied PQC keys.
    LocalSoftware,
}

/// Catalog provider policy for one key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderPolicy {
    /// Backend-native support is mandatory.
    BackendRequired,
    /// Backend-native support wins; local software is an explicit fallback.
    BackendPreferred,
    /// Local software is mandatory.
    LocalSoftware,
}

/// Custody mode recorded in key metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyMode {
    /// Private material stays backend-native.
    BackendNative,
    /// Private material is stored encrypted and unwrapped locally per operation.
    SoftwareEncrypted,
}

impl CustodyMode {
    const fn token(self) -> &'static str {
        match self {
            Self::BackendNative => "backend-native",
            Self::SoftwareEncrypted => "software-encrypted",
        }
    }
}

impl CryptoProviderId {
    const fn token(self) -> &'static str {
        match self {
            Self::VaultTransit => "vault-transit",
            Self::LocalSoftware => "local-software",
        }
    }

    /// The key-custody mode implied by this provider: backend-native keeps the
    /// private in place; the local-software provider unwraps a software-encrypted
    /// seed per operation.
    #[must_use]
    pub const fn custody_mode(self) -> CustodyMode {
        match self {
            Self::VaultTransit => CustodyMode::BackendNative,
            Self::LocalSoftware => CustodyMode::SoftwareEncrypted,
        }
    }
}

/// Provider metadata derived from reserved catalog labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderMetadata {
    /// Explicit provider, if the catalog labels name one.
    pub provider: Option<CryptoProviderId>,
    /// Provider policy, defaulting to backend-required.
    pub policy: ProviderPolicy,
    /// Custody mode, if declared.
    pub custody: Option<CustodyMode>,
}

impl ProviderMetadata {
    /// Parse provider metadata from validated catalog labels.
    #[must_use]
    pub fn from_key(entry: &KeyEntry) -> Self {
        let provider = match entry.labels.get("crypto_provider") {
            Some("vault-transit") => Some(CryptoProviderId::VaultTransit),
            Some("local-software") => Some(CryptoProviderId::LocalSoftware),
            _ => None,
        };
        let policy = match entry.labels.get("crypto_provider_policy") {
            Some("backend-preferred") => ProviderPolicy::BackendPreferred,
            Some("local-software") => ProviderPolicy::LocalSoftware,
            _ => ProviderPolicy::BackendRequired,
        };
        let custody = match entry.labels.get("pqc_custody") {
            Some("backend-native") => Some(CustodyMode::BackendNative),
            Some("software-encrypted") => Some(CustodyMode::SoftwareEncrypted),
            _ => None,
        };
        Self {
            provider,
            policy,
            custody,
        }
    }
}

/// Errors raised before or inside a provider operation.
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    /// The selected provider does not implement this operation/algorithm.
    #[error("provider {provider:?} does not support {op} for {algorithm}")]
    Unsupported {
        /// Provider that rejected the operation.
        provider: CryptoProviderId,
        /// Operation name.
        op: &'static str,
        /// Algorithm name.
        algorithm: &'static str,
    },

    /// Policy or custody labels forbid the requested provider.
    #[error("provider policy denied {op}: {reason}")]
    PolicyDenied {
        /// Operation name.
        op: &'static str,
        /// Stable reason.
        reason: &'static str,
    },

    /// A software-custody crypto or record operation failed: a malformed
    /// custody record, wrong key material, or a decapsulation/verification/seal
    /// failure. The message is opaque: it never contains seed, key, plaintext,
    /// signature, or shared-secret bytes (no decrypt oracle).
    #[error("provider {provider:?} {op} failed for {algorithm}: {reason}")]
    CryptoFailed {
        /// Provider that failed.
        provider: CryptoProviderId,
        /// Operation name.
        op: &'static str,
        /// Algorithm name.
        algorithm: &'static str,
        /// Stable, secret-free reason token.
        reason: &'static str,
    },

    /// Concrete backend error.
    #[error(transparent)]
    Backend(#[from] BackendError),
}

/// Stable metadata copied from a software-custodied key's catalog labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SoftwareCustodyCatalog<'a> {
    /// Catalog key id.
    pub key_id: &'a str,
    /// PQC algorithm token.
    pub algorithm: &'a str,
    /// Provider id token.
    pub provider: &'a str,
    /// Provider implementation version token.
    pub provider_version: &'a str,
    /// Custody mode token.
    pub custody: &'a str,
    /// Backend AEAD key used to unwrap the encrypted private record.
    pub storage_key: &'a str,
}
impl SoftwareCustodyCatalog<'_> {
    pub(crate) fn aad(&self, key_version: u32) -> Vec<u8> {
        format!(
            "basil:pqc-software-custody:v1\nkey_id={}\nkey_version={key_version}\nalgorithm={}\nprovider={}\nprovider_version={}\ncustody={}\nstorage_key={}\n",
            self.key_id,
            self.algorithm,
            self.provider,
            self.provider_version,
            self.custody,
            self.storage_key,
        )
        .into_bytes()
    }
}

/// An encrypted local-software private key record stored in KV.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SoftwareCustodyKeyRecord {
    schema_version: u32,
    key_id: String,
    key_version: u32,
    public_key: String,
    algorithm: String,
    provider: String,
    provider_version: String,
    custody: String,
    encrypted_private_key: EncryptedPrivateKey,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EncryptedPrivateKey {
    wrapping_key: String,
    algorithm: String,
    key_version: u32,
    nonce: String,
    ciphertext: String,
}
impl SoftwareCustodyKeyRecord {
    const SCHEMA_VERSION: u32 = 1;

    /// The AAD that must be supplied to the backend AEAD decrypt operation.
    #[must_use]
    pub(crate) fn aad(&self, catalog: &SoftwareCustodyCatalog<'_>) -> Vec<u8> {
        catalog.aad(self.key_version)
    }

    /// Convert the encrypted private-key fields to the backend ciphertext type.
    pub(crate) fn encrypted_private_key(
        &self,
    ) -> Result<CiphertextEnvelope, SoftwareCustodyRecordError> {
        Ok(CiphertextEnvelope {
            alg: parse_storage_aead(&self.encrypted_private_key.algorithm)?,
            key_version: self.encrypted_private_key.key_version,
            nonce: decode_b64(&self.encrypted_private_key.nonce)?,
            ciphertext: decode_b64(&self.encrypted_private_key.ciphertext)?,
        })
    }

    fn validate_metadata(
        &self,
        catalog: &SoftwareCustodyCatalog<'_>,
        kv_version: u32,
    ) -> Result<(), SoftwareCustodyRecordError> {
        if self.schema_version != Self::SCHEMA_VERSION {
            return Err(SoftwareCustodyRecordError::MetadataMismatch(
                "schema_version",
            ));
        }
        if self.key_id != catalog.key_id {
            return Err(SoftwareCustodyRecordError::MetadataMismatch("key_id"));
        }
        if self.key_version != kv_version {
            return Err(SoftwareCustodyRecordError::MetadataMismatch("key_version"));
        }
        if self.algorithm != catalog.algorithm {
            return Err(SoftwareCustodyRecordError::MetadataMismatch("algorithm"));
        }
        if self.provider != catalog.provider {
            return Err(SoftwareCustodyRecordError::MetadataMismatch("provider"));
        }
        if self.provider_version != catalog.provider_version {
            return Err(SoftwareCustodyRecordError::MetadataMismatch(
                "provider_version",
            ));
        }
        if self.custody != catalog.custody {
            return Err(SoftwareCustodyRecordError::MetadataMismatch("custody"));
        }
        if self.public_key.is_empty() || decode_b64(&self.public_key).is_err() {
            return Err(SoftwareCustodyRecordError::Malformed);
        }
        if self.encrypted_private_key.wrapping_key != catalog.storage_key {
            return Err(SoftwareCustodyRecordError::MetadataMismatch("wrapping_key"));
        }
        if self.encrypted_private_key.key_version == 0 {
            return Err(SoftwareCustodyRecordError::MetadataMismatch(
                "encrypted_private_key.key_version",
            ));
        }
        Ok(())
    }
}

/// Materialized, validated software-custody fields the local-software provider
/// needs for one operation: the AEAD ciphertext + AAD to decrypt the private
/// seed, the backend AEAD key name, the published public key, and the version.
pub(crate) struct LocalSoftwareMaterial {
    /// AEAD-wrapped private seed to hand to [`Backend::decrypt`].
    pub(crate) ciphertext: CiphertextEnvelope,
    /// Associated data bound to the wrapped seed.
    pub(crate) aad: Vec<u8>,
    /// Backend AEAD key name that unwraps the seed.
    pub(crate) storage_key: String,
    /// Published public-key bytes (verifying key / encapsulation key).
    pub(crate) public_key: Vec<u8>,
    /// KV record version (also the envelope key version).
    pub(crate) key_version: u32,
}
impl SoftwareCustodyKeyRecord {
    /// Parse and validate a software-custody record for the local-software
    /// provider, cross-checking it against the requested key id, algorithm, the
    /// provider's own version, and the **catalog-declared** storage AEAD key
    /// (`storage_key`, the `pqc_storage_key` label): a record whose
    /// self-declared `wrapping_key` disagrees is rejected, so a swapped or
    /// re-wrapped record cannot redirect the seed unwrap to an AEAD key the
    /// catalog never authorized. The returned material carries the catalog key,
    /// and the AAD binds it.
    ///
    /// # Errors
    ///
    /// [`SoftwareCustodyRecordError`] for malformed JSON, a metadata mismatch,
    /// or a bad base64 field.
    pub(crate) fn parse_for_local_software(
        bytes: &[u8],
        key_id: &str,
        algorithm: &str,
        provider_version: &str,
        kv_version: u32,
        storage_key: &str,
    ) -> Result<LocalSoftwareMaterial, SoftwareCustodyRecordError> {
        let record: Self =
            serde_json::from_slice(bytes).map_err(|_| SoftwareCustodyRecordError::Malformed)?;
        let catalog = SoftwareCustodyCatalog {
            key_id,
            algorithm,
            provider: CryptoProviderId::LocalSoftware.token(),
            provider_version,
            custody: CustodyMode::SoftwareEncrypted.token(),
            storage_key,
        };
        record.validate_metadata(&catalog, kv_version)?;
        let ciphertext = record.encrypted_private_key()?;
        let aad = record.aad(&catalog);
        let public_key = decode_b64(&record.public_key)?;
        Ok(LocalSoftwareMaterial {
            ciphertext,
            aad,
            storage_key: storage_key.to_string(),
            public_key,
            key_version: kv_version,
        })
    }
}

/// Errors from encrypted software-custody record parsing and validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum SoftwareCustodyRecordError {
    /// The record is not valid JSON, has unknown fields, or has malformed base64.
    #[error("malformed software-custody key record")]
    Malformed,
    /// Record metadata disagrees with catalog/request metadata.
    #[error("software-custody key record metadata mismatch: {0}")]
    MetadataMismatch(&'static str),
    /// The record names an unsupported storage AEAD.
    #[error("unsupported software-custody storage AEAD")]
    UnsupportedStorageAead,
}
fn parse_storage_aead(token: &str) -> Result<AeadAlgorithm, SoftwareCustodyRecordError> {
    match token {
        "aes-256-gcm" => Ok(AeadAlgorithm::Aes256Gcm),
        "chacha20-poly1305" => Ok(AeadAlgorithm::Chacha20Poly1305),
        _ => Err(SoftwareCustodyRecordError::UnsupportedStorageAead),
    }
}
fn decode_b64(value: &str) -> Result<Vec<u8>, SoftwareCustodyRecordError> {
    B64.decode(value)
        .map_err(|_| SoftwareCustodyRecordError::Malformed)
}

/// Encode bytes for a software-custody JSON record.
#[cfg(test)]
pub(crate) fn encode_record_bytes(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

/// Outcome for a PQC provider audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderAuditOutcome {
    /// Provider operation was permitted.
    Allow,
    /// Provider operation was denied before private material use.
    Deny,
    /// Provider operation completed successfully.
    Success,
    /// Provider operation failed.
    Failure,
}

impl ProviderAuditOutcome {
    const fn token(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Success => "success",
            Self::Failure => "failure",
        }
    }
}

/// Secret-free audit event for software-custodied PQC provider operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderAuditEvent<'a> {
    /// Operation name.
    pub op: &'static str,
    /// Catalog key id.
    pub key_id: &'a str,
    /// Catalog/backend key version, when known.
    pub key_version: Option<u32>,
    /// Algorithm token.
    pub algorithm: &'static str,
    /// Selected provider.
    pub provider: CryptoProviderId,
    /// Key custody mode.
    pub custody: CustodyMode,
    /// Kernel-attested caller uid.
    pub caller_uid: u32,
    /// Outcome.
    pub outcome: ProviderAuditOutcome,
    /// Stable reason token.
    pub reason: &'static str,
}

impl ProviderAuditEvent<'_> {
    /// Convert to JSON without including payloads, keys, signatures, ciphertexts,
    /// encapsulated keys, shared secrets, or any other secret bytes.
    #[must_use]
    pub fn to_json_value(&self) -> serde_json::Value {
        json!({
            "event": {
                "kind": "basil.audit.provider_operation",
                "version": 1,
            },
            "occurred_at": timestamp(),
            "op": self.op,
            "actor": {
                "kind": "unix_uid",
                "id": self.caller_uid.to_string(),
            },
            "target": {
                "kind": "catalog_key",
                "id": self.key_id,
                "version": self.key_version,
            },
            "key_version": self.key_version,
            "algorithm": self.algorithm,
            "provider": self.provider.token(),
            "custody": self.custody.token(),
            "caller_uid": self.caller_uid,
            "outcome": self.outcome.token(),
            "reason": self.reason,
        })
    }
}

/// Generate-key request.
pub struct GenerateKey<'a> {
    /// Catalog key id.
    pub key_id: &'a str,
    /// Backend-native locator (transit key name, or, for a software-custodied
    /// key, the KV path the encrypted custody record is written to).
    pub backend_path: &'a str,
    /// Algorithm to generate.
    pub algorithm: SignatureAlgorithm,
    /// Backend AEAD key name that wraps a software-custodied private seed.
    /// Required by the local-software provider; ignored by backend-native
    /// providers, which custody the private in place.
    pub storage_key: Option<&'a str>,
}

/// Generate-sealing-key request: provision a software-custodied ML-KEM recipient.
///
/// Unlike [`GenerateKey`] (signing), a sealing key has no signing semantics; the
/// published half is the KEM encapsulation key derived from the seed.
pub struct GenerateSealingKey<'a> {
    /// Catalog key id.
    pub key_id: &'a str,
    /// KV path the encrypted custody record is written to.
    pub backend_path: &'a str,
    /// KEM parameter set to generate.
    pub algorithm: KemAlgorithm,
    /// Backend AEAD key name that wraps the software-custodied private seed.
    /// Required by the local-software provider.
    pub storage_key: Option<&'a str>,
}

/// Import-key request.
pub struct ImportKey<'a> {
    /// Catalog key id.
    pub key_id: &'a str,
    /// Backend-native locator.
    pub backend_path: &'a str,
    /// Algorithm to import.
    pub algorithm: SignatureAlgorithm,
    /// Caller-provided material.
    pub material: &'a KeyMaterial,
}

/// Sign request.
pub struct SignRequest<'a> {
    /// Catalog key id.
    pub key_id: &'a str,
    /// Backend-native locator.
    pub backend_path: &'a str,
    /// Signing algorithm.
    pub algorithm: SignatureAlgorithm,
    /// The raw message to sign (signed as-is, not a precomputed digest).
    pub message: &'a [u8],
    /// Catalog-declared AEAD key that wraps a software-custodied private seed;
    /// the custody record must agree. Required by the local-software provider;
    /// ignored by backend-native providers.
    pub storage_key: Option<&'a str>,
}

/// Verify request.
pub struct VerifyRequest<'a> {
    /// Catalog key id.
    pub key_id: &'a str,
    /// Backend-native locator.
    pub backend_path: &'a str,
    /// Signing algorithm.
    pub algorithm: SignatureAlgorithm,
    /// The raw signed message (the same bytes passed to sign).
    pub message: &'a [u8],
    /// Signature bytes.
    pub signature: &'a [u8],
    /// Catalog-declared AEAD key that wraps a software-custodied private seed;
    /// the custody record must agree. Required by the local-software provider;
    /// ignored by backend-native providers.
    pub storage_key: Option<&'a str>,
}

/// Encapsulate request.
pub struct EncapsulateRequest<'a> {
    /// Catalog key id.
    pub key_id: &'a str,
    /// Backend-native locator.
    pub backend_path: &'a str,
    /// KEM algorithm.
    pub algorithm: KemAlgorithm,
    /// Catalog-declared AEAD key that wraps a software-custodied private seed;
    /// the custody record must agree. Required by the local-software provider;
    /// ignored by backend-native providers.
    pub storage_key: Option<&'a str>,
}

/// Decapsulate request.
pub struct DecapsulateRequest<'a> {
    /// Catalog key id.
    pub key_id: &'a str,
    /// Backend-native locator.
    pub backend_path: &'a str,
    /// KEM algorithm.
    pub algorithm: KemAlgorithm,
    /// Encapsulated shared-secret material.
    pub encapsulated_key: &'a [u8],
    /// Catalog-declared AEAD key that wraps a software-custodied private seed;
    /// the custody record must agree. Required by the local-software provider;
    /// ignored by backend-native providers.
    pub storage_key: Option<&'a str>,
}

/// KEM ciphertext and shared-secret output.
pub struct Encapsulation {
    /// Encapsulated key bytes safe to return to a caller.
    pub encapsulated_key: Vec<u8>,
    /// Shared secret retained for immediate envelope encryption.
    pub shared_secret: Zeroizing<Vec<u8>>,
}

/// KEM/envelope wrap request.
pub struct WrapEnvelopeRequest<'a> {
    /// Catalog key id.
    pub key_id: &'a str,
    /// Backend-native locator.
    pub backend_path: &'a str,
    /// KEM algorithm.
    pub kem_algorithm: KemAlgorithm,
    /// Envelope AEAD algorithm.
    pub envelope_algorithm: EnvelopeAlgorithm,
    /// Plaintext to wrap.
    pub plaintext: &'a [u8],
    /// Optional associated data.
    pub aad: Option<&'a [u8]>,
    /// Catalog-declared AEAD key that wraps a software-custodied private seed;
    /// the custody record must agree. Required by the local-software provider;
    /// ignored by backend-native providers.
    pub storage_key: Option<&'a str>,
}

/// KEM/envelope unwrap request.
pub struct UnwrapEnvelopeRequest<'a> {
    /// Catalog key id.
    pub key_id: &'a str,
    /// Backend-native locator.
    pub backend_path: &'a str,
    /// KEM algorithm.
    pub kem_algorithm: KemAlgorithm,
    /// Envelope AEAD algorithm.
    pub envelope_algorithm: EnvelopeAlgorithm,
    /// Encapsulated key bytes.
    pub encapsulated_key: &'a [u8],
    /// Nonce bytes.
    pub nonce: &'a [u8],
    /// Ciphertext bytes.
    pub ciphertext: &'a [u8],
    /// Optional associated data.
    pub aad: Option<&'a [u8]>,
    /// Catalog-declared AEAD key that wraps a software-custodied private seed;
    /// the custody record must agree. Required by the local-software provider;
    /// ignored by backend-native providers.
    pub storage_key: Option<&'a str>,
}

/// KEM/envelope output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// KEM algorithm.
    pub kem_algorithm: KemAlgorithm,
    /// Envelope AEAD algorithm.
    pub envelope_algorithm: EnvelopeAlgorithm,
    /// Key version used by the provider.
    pub key_version: u32,
    /// Encapsulated key bytes.
    pub encapsulated_key: Vec<u8>,
    /// Broker/provider-owned nonce bytes.
    pub nonce: Vec<u8>,
    /// Ciphertext bytes.
    pub ciphertext: Vec<u8>,
}

/// Provider-neutral crypto operations.
#[async_trait]
pub trait CryptoProvider: Send + Sync {
    /// Stable provider identifier.
    fn provider_id(&self) -> CryptoProviderId;

    /// Generate a new provider-native signing key.
    async fn generate_key(&self, request: GenerateKey<'_>) -> Result<NewKey, ProviderError>;

    /// Generate a new provider-native KEM **sealing** (recipient) key.
    async fn generate_sealing_key(
        &self,
        request: GenerateSealingKey<'_>,
    ) -> Result<NewKey, ProviderError>;

    /// Import caller-provided key material.
    async fn import_key(&self, request: ImportKey<'_>) -> Result<NewKey, ProviderError>;

    /// Sign in place.
    async fn sign(&self, request: SignRequest<'_>) -> Result<Vec<u8>, ProviderError>;

    /// Verify with provider-held public material.
    async fn verify(&self, request: VerifyRequest<'_>) -> Result<bool, ProviderError>;

    /// KEM encapsulation.
    async fn encapsulate(
        &self,
        request: EncapsulateRequest<'_>,
    ) -> Result<Encapsulation, ProviderError>;

    /// KEM decapsulation.
    async fn decapsulate(
        &self,
        request: DecapsulateRequest<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, ProviderError>;

    /// KEM plus envelope encryption.
    async fn wrap_envelope(
        &self,
        request: WrapEnvelopeRequest<'_>,
    ) -> Result<Envelope, ProviderError>;

    /// KEM plus envelope decryption.
    async fn unwrap_envelope(
        &self,
        request: UnwrapEnvelopeRequest<'_>,
    ) -> Result<Vec<u8>, ProviderError>;
}

/// Adapter exposing an existing backend as the backend-native crypto provider.
pub struct BackendCryptoProvider<'a> {
    backend: &'a dyn Backend,
}

impl<'a> BackendCryptoProvider<'a> {
    /// Build a provider adapter over an existing backend.
    #[must_use]
    pub const fn new(backend: &'a dyn Backend) -> Self {
        Self { backend }
    }
}

#[async_trait]
impl CryptoProvider for BackendCryptoProvider<'_> {
    fn provider_id(&self) -> CryptoProviderId {
        CryptoProviderId::VaultTransit
    }

    async fn generate_key(&self, request: GenerateKey<'_>) -> Result<NewKey, ProviderError> {
        // ML-DSA provisions through the backend's native PQC seam; the seed is
        // generated and custodied in place and only the public half returns.
        if let Some(native) = request.algorithm.native_algorithm() {
            return self
                .backend
                .create_named_pqc_key(request.backend_path, native)
                .await
                .map_err(ProviderError::Backend);
        }
        let key_type = key_type_for_signature(request.algorithm).ok_or_else(|| {
            unsupported(
                self.provider_id(),
                "generate_key",
                signature_algorithm_name(request.algorithm),
            )
        })?;
        self.backend
            .create_named_key(request.backend_path, key_type)
            .await
            .map_err(ProviderError::Backend)
    }

    async fn generate_sealing_key(
        &self,
        request: GenerateSealingKey<'_>,
    ) -> Result<NewKey, ProviderError> {
        // No backend natively generates an ML-KEM recipient key; sealing keys are
        // software-custodied. Fail closed.
        Err(unsupported(
            self.provider_id(),
            "generate_sealing_key",
            kem_algorithm_name(request.algorithm),
        ))
    }

    async fn import_key(&self, request: ImportKey<'_>) -> Result<NewKey, ProviderError> {
        let key_type = key_type_for_signature(request.algorithm).ok_or_else(|| {
            unsupported(
                self.provider_id(),
                "import_key",
                signature_algorithm_name(request.algorithm),
            )
        })?;
        self.backend
            .import(request.backend_path, key_type, request.material)
            .await
            .map_err(ProviderError::Backend)
    }

    async fn sign(&self, request: SignRequest<'_>) -> Result<Vec<u8>, ProviderError> {
        // ML-DSA signs in place through the backend's native PQC seam.
        if let Some(native) = request.algorithm.native_algorithm() {
            return self
                .backend
                .sign_pqc(request.backend_path, request.message, native)
                .await
                .map_err(ProviderError::Backend);
        }
        let options = sign_options(request.algorithm).ok_or_else(|| {
            unsupported(
                self.provider_id(),
                "sign",
                signature_algorithm_name(request.algorithm),
            )
        })?;
        self.backend
            .sign_with_options(request.backend_path, request.message, options)
            .await
            .map_err(ProviderError::Backend)
    }

    async fn verify(&self, request: VerifyRequest<'_>) -> Result<bool, ProviderError> {
        // ML-DSA verifies through the backend's native PQC seam.
        if let Some(native) = request.algorithm.native_algorithm() {
            return self
                .backend
                .verify_pqc(
                    request.backend_path,
                    request.message,
                    request.signature,
                    native,
                )
                .await
                .map_err(ProviderError::Backend);
        }
        let options = sign_options(request.algorithm).ok_or_else(|| {
            unsupported(
                self.provider_id(),
                "verify",
                signature_algorithm_name(request.algorithm),
            )
        })?;
        self.backend
            .verify_with_options(
                request.backend_path,
                request.message,
                request.signature,
                options,
            )
            .await
            .map_err(ProviderError::Backend)
    }

    async fn encapsulate(
        &self,
        request: EncapsulateRequest<'_>,
    ) -> Result<Encapsulation, ProviderError> {
        Err(unsupported(
            self.provider_id(),
            "encapsulate",
            kem_algorithm_name(request.algorithm),
        ))
    }

    async fn decapsulate(
        &self,
        request: DecapsulateRequest<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
        Err(unsupported(
            self.provider_id(),
            "decapsulate",
            kem_algorithm_name(request.algorithm),
        ))
    }

    async fn wrap_envelope(
        &self,
        request: WrapEnvelopeRequest<'_>,
    ) -> Result<Envelope, ProviderError> {
        Err(unsupported(
            self.provider_id(),
            "wrap_envelope",
            kem_algorithm_name(request.kem_algorithm),
        ))
    }

    async fn unwrap_envelope(
        &self,
        request: UnwrapEnvelopeRequest<'_>,
    ) -> Result<Vec<u8>, ProviderError> {
        Err(unsupported(
            self.provider_id(),
            "unwrap_envelope",
            kem_algorithm_name(request.kem_algorithm),
        ))
    }
}

/// Basil's local-software PQC provider: ML-DSA signing/verification and ML-KEM
/// encapsulation/decapsulation/envelope over software-custodied keys.
///
/// Private keys are custodied as encrypted [`SoftwareCustodyKeyRecord`]s in the
/// backend KV store. For each private-key operation the provider reads the
/// record, validates its non-secret metadata, AEAD-decrypts the seed into a
/// [`Zeroizing`] buffer, runs the PQC math, and drops the seed: it never holds
/// standing private material. ML-DSA math lives in [`ml_dsa_sign`]; ML-KEM math
/// and the envelope sealing live in [`ml_kem_envelope`].
///
/// Provisioning ([`Self::generate_key`] for ML-DSA, [`Self::generate_sealing_key`]
/// for ML-KEM) generates a fresh seed, seals it under the catalog `storage_key`
/// AEAD key with the custody-binding AAD, and writes the record; the seed never
/// leaves a [`Zeroizing`] buffer and only the public half is returned. BYOK
/// [`Self::import_key`] remains unsupported (custody records are broker-sealed).
pub struct LocalSoftwareProvider<'a> {
    backend: &'a dyn Backend,
    provider_version: &'static str,
}
impl<'a> LocalSoftwareProvider<'a> {
    /// Stable provider-implementation version token. It is recorded in the
    /// `crypto_provider_version` catalog label and bound into the custody-record
    /// AAD, so a record provisioned for a different version fails closed.
    pub const PROVIDER_VERSION: &'static str = "1";

    /// Build a provider over the backend that custodies the encrypted records.
    #[must_use]
    pub const fn new(backend: &'a dyn Backend) -> Self {
        Self {
            backend,
            provider_version: Self::PROVIDER_VERSION,
        }
    }

    /// Read + validate the custody record for one operation.
    ///
    /// `storage_key` is the catalog-declared AEAD key (the `pqc_storage_key`
    /// label): it is the trust anchor the record's self-declared `wrapping_key`
    /// is checked against, so it is required on every use path exactly as on
    /// the generate path.
    async fn material(
        &self,
        key_id: &str,
        backend_path: &str,
        storage_key: Option<&str>,
        op: &'static str,
        algorithm: &'static str,
    ) -> Result<LocalSoftwareMaterial, ProviderError> {
        let storage_key = storage_key.ok_or_else(|| {
            crypto_failed(
                CryptoProviderId::LocalSoftware,
                op,
                algorithm,
                "software-custody key is missing its storage AEAD key",
            )
        })?;
        let kv = self.backend.kv_get(backend_path, None).await?;
        SoftwareCustodyKeyRecord::parse_for_local_software(
            &kv.value,
            key_id,
            algorithm,
            self.provider_version,
            kv.version,
            storage_key,
        )
        .map_err(|_| {
            crypto_failed(
                CryptoProviderId::LocalSoftware,
                op,
                algorithm,
                "malformed software-custody record",
            )
        })
    }

    /// Materialize the private seed: AEAD-decrypt it into a [`Zeroizing`] buffer
    /// that wipes on drop. Reachable only after [`Self::material`] validated the
    /// record's metadata.
    async fn materialize_seed(
        &self,
        material: &LocalSoftwareMaterial,
    ) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
        let plaintext = self
            .backend
            .decrypt(
                &material.storage_key,
                &material.ciphertext,
                Some(&material.aad),
            )
            .await?;
        Ok(Zeroizing::new(plaintext))
    }

    /// Read the published public half (verifying / encapsulation key) from the
    /// custody record **without** materializing the private seed: the public-key
    /// read path for `get_public_key`. The record's public half was derived from
    /// the seed and recorded at provisioning time.
    pub(crate) async fn public_key(
        &self,
        key_id: &str,
        backend_path: &str,
        storage_key: Option<&str>,
        algorithm: &'static str,
    ) -> Result<Vec<u8>, ProviderError> {
        let material = self
            .material(
                key_id,
                backend_path,
                storage_key,
                "get_public_key",
                algorithm,
            )
            .await?;
        Ok(material.public_key)
    }

    /// Seal a freshly generated `seed` under the catalog `storage_key` AEAD key
    /// (binding the custody AAD), build the [`SoftwareCustodyKeyRecord`], and write
    /// it to KV at `backend_path`. Shared by the ML-DSA and ML-KEM generate paths;
    /// the seed stays in caller-owned [`Zeroizing`] storage and never leaves.
    /// Returns only the non-secret public half.
    async fn seal_and_store(
        &self,
        params: SealParams<'_>,
        seed: &[u8],
        public_key: Vec<u8>,
    ) -> Result<NewKey, ProviderError> {
        // The fresh record is the key's first version; the use path validates the
        // KV record version equals this on read.
        const RECORD_VERSION: u32 = 1;

        let custody = SoftwareCustodyCatalog {
            key_id: params.key_id,
            algorithm: params.algorithm_token,
            provider: CryptoProviderId::LocalSoftware.token(),
            provider_version: self.provider_version,
            custody: CustodyMode::SoftwareEncrypted.token(),
            storage_key: params.storage_key,
        };
        let aad = custody.aad(RECORD_VERSION);
        let envelope = self
            .backend
            .encrypt(
                params.storage_key,
                AeadAlgorithm::Aes256Gcm,
                seed,
                Some(&aad),
            )
            .await?;
        let record = SoftwareCustodyKeyRecord {
            schema_version: SoftwareCustodyKeyRecord::SCHEMA_VERSION,
            key_id: params.key_id.to_string(),
            key_version: RECORD_VERSION,
            public_key: B64.encode(&public_key),
            algorithm: params.algorithm_token.to_string(),
            provider: CryptoProviderId::LocalSoftware.token().to_string(),
            provider_version: self.provider_version.to_string(),
            custody: CustodyMode::SoftwareEncrypted.token().to_string(),
            encrypted_private_key: EncryptedPrivateKey {
                wrapping_key: params.storage_key.to_string(),
                algorithm: aead_token(envelope.alg).to_string(),
                key_version: envelope.key_version,
                nonce: B64.encode(&envelope.nonce),
                ciphertext: B64.encode(&envelope.ciphertext),
            },
        };
        let bytes = serde_json::to_vec(&record).map_err(|_| {
            crypto_failed(
                CryptoProviderId::LocalSoftware,
                params.op,
                params.algorithm_token,
                "software-custody record serialization failed",
            )
        })?;
        self.backend.kv_put(params.backend_path, &bytes).await?;
        Ok(NewKey {
            key_id: params.key_id.to_string(),
            public_key,
        })
    }
}

/// Inputs to [`LocalSoftwareProvider::seal_and_store`] for one software-custody
/// provisioning write (grouped to keep the seal path's argument count small).
struct SealParams<'a> {
    /// Audit/error op token (`generate_key` or `generate_sealing_key`).
    op: &'static str,
    /// Catalog key id.
    key_id: &'a str,
    /// KV path the custody record is written to.
    backend_path: &'a str,
    /// Algorithm token recorded in the custody record and AAD.
    algorithm_token: &'static str,
    /// Backend AEAD key name that wraps the seed.
    storage_key: &'a str,
}
#[async_trait]
impl CryptoProvider for LocalSoftwareProvider<'_> {
    fn provider_id(&self) -> CryptoProviderId {
        CryptoProviderId::LocalSoftware
    }

    async fn generate_key(&self, request: GenerateKey<'_>) -> Result<NewKey, ProviderError> {
        use rand::RngCore as _;
        use rand::rngs::OsRng;

        let algorithm = ml_dsa_algorithm(request.algorithm).ok_or_else(|| {
            unsupported(
                CryptoProviderId::LocalSoftware,
                "generate_key",
                signature_algorithm_name(request.algorithm),
            )
        })?;
        let algorithm_token = algorithm.token();
        let storage_key = request.storage_key.ok_or_else(|| {
            crypto_failed(
                CryptoProviderId::LocalSoftware,
                "generate_key",
                algorithm_token,
                "software-custody key is missing its storage AEAD key",
            )
        })?;

        // Fresh seed = the private key; it stays in a zeroizing buffer that wipes
        // on drop and is never returned, logged, or audited.
        let mut seed = Zeroizing::new([0u8; ml_dsa_sign::SEED_LEN]);
        OsRng.fill_bytes(seed.as_mut_slice());
        let public_key =
            ml_dsa_sign::public_from_seed(algorithm, seed.as_slice()).map_err(|_| {
                crypto_failed(
                    CryptoProviderId::LocalSoftware,
                    "generate_key",
                    algorithm_token,
                    "ml-dsa key generation failed",
                )
            })?;

        self.seal_and_store(
            SealParams {
                op: "generate_key",
                key_id: request.key_id,
                backend_path: request.backend_path,
                algorithm_token,
                storage_key,
            },
            seed.as_slice(),
            public_key,
        )
        .await
    }

    async fn generate_sealing_key(
        &self,
        request: GenerateSealingKey<'_>,
    ) -> Result<NewKey, ProviderError> {
        use rand::RngCore as _;
        use rand::rngs::OsRng;

        let kem = request.algorithm;
        let algorithm_token = kem.token();
        let storage_key = request.storage_key.ok_or_else(|| {
            crypto_failed(
                CryptoProviderId::LocalSoftware,
                "generate_sealing_key",
                algorithm_token,
                "software-custody key is missing its storage AEAD key",
            )
        })?;

        // ML-KEM seeds are 64 bytes (`d ‖ z`, FIPS 203). The seed is the private
        // key and stays in a zeroizing buffer; only the derived encapsulation
        // (public) key is returned.
        let mut seed = Zeroizing::new([0u8; ml_kem_envelope::SEED_LEN]);
        OsRng.fill_bytes(seed.as_mut_slice());
        let public_key = ml_kem_envelope::public_from_seed(seed.as_slice(), kem_to_core(kem))
            .map_err(|_| {
                crypto_failed(
                    CryptoProviderId::LocalSoftware,
                    "generate_sealing_key",
                    algorithm_token,
                    "ml-kem key generation failed",
                )
            })?;

        self.seal_and_store(
            SealParams {
                op: "generate_sealing_key",
                key_id: request.key_id,
                backend_path: request.backend_path,
                algorithm_token,
                storage_key,
            },
            seed.as_slice(),
            public_key,
        )
        .await
    }

    async fn import_key(&self, request: ImportKey<'_>) -> Result<NewKey, ProviderError> {
        Err(unsupported(
            CryptoProviderId::LocalSoftware,
            "import_key",
            signature_algorithm_name(request.algorithm),
        ))
    }

    async fn sign(&self, request: SignRequest<'_>) -> Result<Vec<u8>, ProviderError> {
        let algorithm = ml_dsa_algorithm(request.algorithm).ok_or_else(|| {
            unsupported(
                CryptoProviderId::LocalSoftware,
                "sign",
                signature_algorithm_name(request.algorithm),
            )
        })?;
        let material = self
            .material(
                request.key_id,
                request.backend_path,
                request.storage_key,
                "sign",
                algorithm.token(),
            )
            .await?;
        let seed = self.materialize_seed(&material).await?;
        ml_dsa_sign::sign(algorithm, &seed, request.message).map_err(|_| {
            crypto_failed(
                CryptoProviderId::LocalSoftware,
                "sign",
                algorithm.token(),
                "ml-dsa signing failed",
            )
        })
    }

    async fn verify(&self, request: VerifyRequest<'_>) -> Result<bool, ProviderError> {
        let algorithm = ml_dsa_algorithm(request.algorithm).ok_or_else(|| {
            unsupported(
                CryptoProviderId::LocalSoftware,
                "verify",
                signature_algorithm_name(request.algorithm),
            )
        })?;
        // Verification needs only the published public key. No seed materialized.
        let material = self
            .material(
                request.key_id,
                request.backend_path,
                request.storage_key,
                "verify",
                algorithm.token(),
            )
            .await?;
        ml_dsa_sign::verify(
            algorithm,
            &material.public_key,
            request.message,
            request.signature,
        )
        .map_err(|_| {
            crypto_failed(
                CryptoProviderId::LocalSoftware,
                "verify",
                algorithm.token(),
                "malformed verification input",
            )
        })
    }

    async fn encapsulate(
        &self,
        request: EncapsulateRequest<'_>,
    ) -> Result<Encapsulation, ProviderError> {
        let material = self
            .material(
                request.key_id,
                request.backend_path,
                request.storage_key,
                "encapsulate",
                kem_algorithm_name(request.algorithm),
            )
            .await?;
        let seed = self.materialize_seed(&material).await?;
        let (encapsulated_key, shared_secret) =
            ml_kem_envelope::encapsulate(&seed, kem_to_core(request.algorithm)).map_err(|_| {
                crypto_failed(
                    CryptoProviderId::LocalSoftware,
                    "encapsulate",
                    kem_algorithm_name(request.algorithm),
                    "ml-kem encapsulation failed",
                )
            })?;
        Ok(Encapsulation {
            encapsulated_key,
            shared_secret,
        })
    }

    async fn decapsulate(
        &self,
        request: DecapsulateRequest<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
        let material = self
            .material(
                request.key_id,
                request.backend_path,
                request.storage_key,
                "decapsulate",
                kem_algorithm_name(request.algorithm),
            )
            .await?;
        let seed = self.materialize_seed(&material).await?;
        ml_kem_envelope::decapsulate(
            &seed,
            kem_to_core(request.algorithm),
            request.encapsulated_key,
        )
        .map_err(|_| {
            crypto_failed(
                CryptoProviderId::LocalSoftware,
                "decapsulate",
                kem_algorithm_name(request.algorithm),
                "ml-kem decapsulation failed",
            )
        })
    }

    async fn wrap_envelope(
        &self,
        request: WrapEnvelopeRequest<'_>,
    ) -> Result<Envelope, ProviderError> {
        let material = self
            .material(
                request.key_id,
                request.backend_path,
                request.storage_key,
                "wrap_envelope",
                kem_algorithm_name(request.kem_algorithm),
            )
            .await?;
        let seed = self.materialize_seed(&material).await?;
        let sealed = ml_kem_envelope::seal(
            &seed,
            kem_to_core(request.kem_algorithm),
            envelope_to_core(request.envelope_algorithm),
            request.plaintext,
            request.aad.unwrap_or_default(),
        )
        .map_err(|_| {
            crypto_failed(
                CryptoProviderId::LocalSoftware,
                "wrap_envelope",
                kem_algorithm_name(request.kem_algorithm),
                "ml-kem envelope seal failed",
            )
        })?;
        Ok(Envelope {
            kem_algorithm: request.kem_algorithm,
            envelope_algorithm: request.envelope_algorithm,
            key_version: material.key_version,
            encapsulated_key: sealed.encapsulated_key,
            nonce: sealed.nonce.to_vec(),
            ciphertext: sealed.ciphertext,
        })
    }

    async fn unwrap_envelope(
        &self,
        request: UnwrapEnvelopeRequest<'_>,
    ) -> Result<Vec<u8>, ProviderError> {
        let material = self
            .material(
                request.key_id,
                request.backend_path,
                request.storage_key,
                "unwrap_envelope",
                kem_algorithm_name(request.kem_algorithm),
            )
            .await?;
        let seed = self.materialize_seed(&material).await?;
        let envelope = ml_kem_envelope::envelope_from_parts(
            kem_to_core(request.kem_algorithm),
            envelope_to_core(request.envelope_algorithm),
            request.encapsulated_key,
            request.nonce,
            request.ciphertext,
        )
        .map_err(|_| {
            crypto_failed(
                CryptoProviderId::LocalSoftware,
                "unwrap_envelope",
                kem_algorithm_name(request.kem_algorithm),
                "malformed ml-kem envelope",
            )
        })?;
        let plaintext = ml_kem_envelope::open(&seed, &envelope, request.aad.unwrap_or_default())
            .map_err(|_| {
                crypto_failed(
                    CryptoProviderId::LocalSoftware,
                    "unwrap_envelope",
                    kem_algorithm_name(request.kem_algorithm),
                    "ml-kem envelope open failed",
                )
            })?;
        Ok(plaintext.to_vec())
    }
}
const fn ml_dsa_algorithm(algorithm: SignatureAlgorithm) -> Option<ml_dsa_sign::MlDsaAlgorithm> {
    match algorithm {
        SignatureAlgorithm::MlDsa44 => Some(ml_dsa_sign::MlDsaAlgorithm::MlDsa44),
        SignatureAlgorithm::MlDsa65 => Some(ml_dsa_sign::MlDsaAlgorithm::MlDsa65),
        SignatureAlgorithm::MlDsa87 => Some(ml_dsa_sign::MlDsaAlgorithm::MlDsa87),
        SignatureAlgorithm::Ed25519
        | SignatureAlgorithm::Ed25519Nkey
        | SignatureAlgorithm::Rs256
        | SignatureAlgorithm::Es256 => None,
    }
}
const fn kem_to_core(algorithm: KemAlgorithm) -> ml_kem_envelope::KemAlgorithm {
    match algorithm {
        KemAlgorithm::MlKem512 => ml_kem_envelope::KemAlgorithm::MlKem512,
        KemAlgorithm::MlKem768 => ml_kem_envelope::KemAlgorithm::MlKem768,
        KemAlgorithm::MlKem1024 => ml_kem_envelope::KemAlgorithm::MlKem1024,
    }
}
const fn envelope_to_core(algorithm: EnvelopeAlgorithm) -> ml_kem_envelope::EnvelopeAlgorithm {
    match algorithm {
        EnvelopeAlgorithm::Aes256Gcm => ml_kem_envelope::EnvelopeAlgorithm::Aes256Gcm,
        EnvelopeAlgorithm::ChaCha20Poly1305 => ml_kem_envelope::EnvelopeAlgorithm::ChaCha20Poly1305,
    }
}

/// Select a provider from catalog metadata and backend capability.
///
/// `backend_native_supported` is the caller's capability probe for the requested
/// algorithm and operation.
pub fn select_provider(
    metadata: ProviderMetadata,
    backend_native_supported: bool,
    local_software_allowed: bool,
    op: &'static str,
) -> Result<CryptoProviderId, ProviderError> {
    match metadata.policy {
        ProviderPolicy::BackendRequired => select_backend_required(backend_native_supported, op),
        ProviderPolicy::BackendPreferred => select_backend_preferred(
            metadata.custody,
            backend_native_supported,
            local_software_allowed,
            op,
        ),
        ProviderPolicy::LocalSoftware => {
            select_local_software(metadata.custody, local_software_allowed, op)
        }
    }
}

const fn select_backend_required(
    backend_native_supported: bool,
    op: &'static str,
) -> Result<CryptoProviderId, ProviderError> {
    if backend_native_supported {
        return Ok(CryptoProviderId::VaultTransit);
    }
    Err(unsupported(
        CryptoProviderId::VaultTransit,
        op,
        "backend-native",
    ))
}

fn select_backend_preferred(
    custody: Option<CustodyMode>,
    backend_native_supported: bool,
    local_software_allowed: bool,
    op: &'static str,
) -> Result<CryptoProviderId, ProviderError> {
    // A key already provisioned under software custody stays software-custodied:
    // its private seed lives software-encrypted in KV, so a capability probe that
    // newly reports native backend support must NOT re-route the key to the
    // backend (which holds no material for it). Migrating a software key to
    // backend-native is an explicit re-key (`basil-wuj.10`), never an implicit
    // side effect of the probe flipping. This pin also honors an operator who
    // explicitly declared software custody on a `backend-preferred` key.
    if custody == Some(CustodyMode::SoftwareEncrypted) {
        require_local_software_allowed(local_software_allowed, op)?;
        return Ok(CryptoProviderId::LocalSoftware);
    }
    if backend_native_supported {
        return Ok(CryptoProviderId::VaultTransit);
    }
    require_local_software_allowed(local_software_allowed, op)?;
    require_software_custody(
        custody,
        op,
        "local software fallback requires software-encrypted custody",
    )?;
    Ok(CryptoProviderId::LocalSoftware)
}

fn select_local_software(
    custody: Option<CustodyMode>,
    local_software_allowed: bool,
    op: &'static str,
) -> Result<CryptoProviderId, ProviderError> {
    require_local_software_allowed(local_software_allowed, op)?;
    require_software_custody(
        custody,
        op,
        "local software provider requires software-encrypted custody",
    )?;
    Ok(CryptoProviderId::LocalSoftware)
}

const fn require_local_software_allowed(
    local_software_allowed: bool,
    op: &'static str,
) -> Result<(), ProviderError> {
    if local_software_allowed {
        return Ok(());
    }
    Err(ProviderError::PolicyDenied {
        op,
        reason: "local software custody requires caller policy grant",
    })
}

fn require_software_custody(
    custody: Option<CustodyMode>,
    op: &'static str,
    reason: &'static str,
) -> Result<(), ProviderError> {
    if custody == Some(CustodyMode::SoftwareEncrypted) {
        return Ok(());
    }
    Err(ProviderError::PolicyDenied { op, reason })
}

const fn key_type_for_signature(algorithm: SignatureAlgorithm) -> Option<KeyType> {
    match algorithm {
        SignatureAlgorithm::Ed25519 => Some(KeyType::Ed25519),
        SignatureAlgorithm::Ed25519Nkey => Some(KeyType::Ed25519Nkey),
        SignatureAlgorithm::Rs256 => Some(KeyType::Rsa2048),
        SignatureAlgorithm::Es256 => Some(KeyType::EcdsaP256),
        SignatureAlgorithm::MlDsa44 | SignatureAlgorithm::MlDsa65 | SignatureAlgorithm::MlDsa87 => {
            None
        }
    }
}

const fn sign_options(algorithm: SignatureAlgorithm) -> Option<SignOptions> {
    match algorithm {
        SignatureAlgorithm::Ed25519 | SignatureAlgorithm::Ed25519Nkey => Some(SignOptions::Default),
        SignatureAlgorithm::Rs256 => Some(SignOptions::Rs256Pkcs1v15Sha256),
        SignatureAlgorithm::Es256 => Some(SignOptions::Es256),
        SignatureAlgorithm::MlDsa44 | SignatureAlgorithm::MlDsa65 | SignatureAlgorithm::MlDsa87 => {
            None
        }
    }
}

const fn signature_algorithm_name(algorithm: SignatureAlgorithm) -> &'static str {
    match algorithm {
        SignatureAlgorithm::Ed25519 => "ed25519",
        SignatureAlgorithm::Ed25519Nkey => "ed25519-nkey",
        SignatureAlgorithm::Rs256 => "rs256",
        SignatureAlgorithm::Es256 => "es256",
        SignatureAlgorithm::MlDsa44 => "ml-dsa-44",
        SignatureAlgorithm::MlDsa65 => "ml-dsa-65",
        SignatureAlgorithm::MlDsa87 => "ml-dsa-87",
    }
}

const fn kem_algorithm_name(algorithm: KemAlgorithm) -> &'static str {
    algorithm.token()
}

const fn unsupported(
    provider: CryptoProviderId,
    op: &'static str,
    algorithm: &'static str,
) -> ProviderError {
    ProviderError::Unsupported {
        provider,
        op,
        algorithm,
    }
}
const fn crypto_failed(
    provider: CryptoProviderId,
    op: &'static str,
    algorithm: &'static str,
    reason: &'static str,
) -> ProviderError {
    ProviderError::CryptoFailed {
        provider,
        op,
        algorithm,
        reason,
    }
}

/// The storage-AEAD token written into a software-custody record. The inverse of
/// [`parse_storage_aead`], so a generated record round-trips on read.
const fn aead_token(alg: AeadAlgorithm) -> &'static str {
    match alg {
        AeadAlgorithm::Aes256Gcm => "aes-256-gcm",
        AeadAlgorithm::Chacha20Poly1305 => "chacha20-poly1305",
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;

    use super::*;
    use crate::backend::{BackendError, NewKey};
    use crate::catalog::schema::Labels;

    struct RecordingBackend;

    #[async_trait]
    impl Backend for RecordingBackend {
        fn kind(&self) -> &'static str {
            "recording"
        }

        async fn new_key(&self, key_type: KeyType) -> Result<NewKey, BackendError> {
            let _ = key_type;
            Err(BackendError::Unsupported("new_key"))
        }

        async fn create_named_key(
            &self,
            key_id: &str,
            key_type: KeyType,
        ) -> Result<NewKey, BackendError> {
            Ok(NewKey {
                key_id: format!("{key_id}:{key_type}"),
                public_key: vec![1, 2, 3],
            })
        }

        async fn public_key(&self, key_id: &str) -> Result<Vec<u8>, BackendError> {
            let _ = key_id;
            Ok(vec![1, 2, 3])
        }

        async fn sign(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, BackendError> {
            Ok([key_id.as_bytes(), message].concat())
        }

        async fn sign_with_options(
            &self,
            key_id: &str,
            message: &[u8],
            options: SignOptions,
        ) -> Result<Vec<u8>, BackendError> {
            let mut out = self.sign(key_id, message).await?;
            // ubs false positive: options is not secret material
            /* ubs:ignore */
            if options == SignOptions::Rs256Pkcs1v15Sha256 {
                out.extend_from_slice(b":rs256");
            } else if options == SignOptions::Es256 {
                out.extend_from_slice(b":es256");
            }
            Ok(out)
        }

        async fn verify(
            &self,
            key_id: &str,
            message: &[u8],
            signature: &[u8],
        ) -> Result<bool, BackendError> {
            // ubs false positive: test, unrealistic comparison
            /* ubs:ignore */
            Ok(signature == [key_id.as_bytes(), message].concat())
        }
    }

    fn key_entry_with_labels(labels: &[&str]) -> KeyEntry {
        KeyEntry {
            class: crate::catalog::schema::Class::Asymmetric,
            key_type: Some(crate::catalog::schema::KeyAlgorithm::Ed25519),
            backend: "bao".to_string(),
            engine: None,
            path: "issuer".to_string(),
            public_path: None,
            writable: true,
            missing: crate::catalog::schema::MissingPolicy::Error,
            generate: None,
            sealing_pin: None,
            labels: Labels(labels.iter().map(ToString::to_string).collect()),
            description: "issuer".to_string(),
        }
    }

    #[test]
    fn provider_metadata_defaults_to_backend_required() {
        let entry = key_entry_with_labels(&[]);
        assert_eq!(
            ProviderMetadata::from_key(&entry),
            ProviderMetadata {
                provider: None,
                policy: ProviderPolicy::BackendRequired,
                custody: None
            }
        );
    }

    #[test]
    fn provider_metadata_parses_reserved_labels() {
        let entry = key_entry_with_labels(&[
            "crypto_provider=local-software",
            "crypto_provider_policy=backend-preferred",
            "pqc_custody=software-encrypted",
        ]);
        assert_eq!(
            ProviderMetadata::from_key(&entry),
            ProviderMetadata {
                provider: Some(CryptoProviderId::LocalSoftware),
                policy: ProviderPolicy::BackendPreferred,
                custody: Some(CustodyMode::SoftwareEncrypted)
            }
        );
    }

    #[test]
    fn provider_selection_honors_backend_required() {
        let selected = select_provider(
            ProviderMetadata {
                provider: None,
                policy: ProviderPolicy::BackendRequired,
                custody: None,
            },
            true,
            false,
            "sign",
        )
        .expect("backend-native selected");
        assert_eq!(selected, CryptoProviderId::VaultTransit);

        assert!(matches!(
            select_provider(
                ProviderMetadata {
                    provider: None,
                    policy: ProviderPolicy::BackendRequired,
                    custody: None,
                },
                false,
                false,
                "sign",
            ),
            Err(ProviderError::Unsupported { .. })
        ));
    }

    #[test]
    fn provider_selection_honors_local_software_custody_gate() {
        let denied = select_provider(
            ProviderMetadata {
                provider: None,
                policy: ProviderPolicy::BackendPreferred,
                custody: Some(CustodyMode::BackendNative),
            },
            false,
            true,
            "sign",
        )
        .expect_err("backend fallback needs software custody");
        assert!(matches!(denied, ProviderError::PolicyDenied { .. }));

        let denied = select_provider(
            ProviderMetadata {
                provider: None,
                policy: ProviderPolicy::BackendPreferred,
                custody: Some(CustodyMode::SoftwareEncrypted),
            },
            false,
            false,
            "sign",
        )
        .expect_err("local software needs caller policy");
        assert!(matches!(
            denied,
            ProviderError::PolicyDenied {
                reason: "local software custody requires caller policy grant",
                ..
            }
        ));

        let selected = select_provider(
            ProviderMetadata {
                provider: None,
                policy: ProviderPolicy::BackendPreferred,
                custody: Some(CustodyMode::SoftwareEncrypted),
            },
            false,
            true,
            "sign",
        )
        .expect("local fallback selected");
        assert_eq!(selected, CryptoProviderId::LocalSoftware);
    }

    #[test]
    fn backend_preferred_software_custody_pins_despite_native_support() {
        // The migration invariant (`basil-wuj.10`): a backend-preferred key already
        // under software custody stays on the local-software provider even when the
        // backend NOW reports native support: the probe must not silently re-route
        // an already-provisioned software key to the backend.
        let pinned = select_provider(
            ProviderMetadata {
                provider: None,
                policy: ProviderPolicy::BackendPreferred,
                custody: Some(CustodyMode::SoftwareEncrypted),
            },
            true,
            true,
            "sign",
        )
        .expect("software-custodied key stays local-software");
        assert_eq!(pinned, CryptoProviderId::LocalSoftware);

        // A backend-preferred key with NO recorded software custody DOES take the
        // backend natively when the probe reports support (the new-key path).
        let native = select_provider(
            ProviderMetadata {
                provider: None,
                policy: ProviderPolicy::BackendPreferred,
                custody: None,
            },
            true,
            true,
            "sign",
        )
        .expect("no-custody preferred key routes to native");
        assert_eq!(native, CryptoProviderId::VaultTransit);

        // The pin still honors the caller policy grant: a software-custodied key
        // with native support but no grant is denied, never routed to the backend.
        let denied = select_provider(
            ProviderMetadata {
                provider: None,
                policy: ProviderPolicy::BackendPreferred,
                custody: Some(CustodyMode::SoftwareEncrypted),
            },
            true,
            false,
            "sign",
        )
        .expect_err("local software still needs the caller grant");
        assert!(matches!(denied, ProviderError::PolicyDenied { .. }));
    }

    #[test]
    fn provider_selection_honors_local_software_policy_mode() {
        let selected = select_provider(
            ProviderMetadata {
                provider: Some(CryptoProviderId::LocalSoftware),
                policy: ProviderPolicy::LocalSoftware,
                custody: Some(CustodyMode::SoftwareEncrypted),
            },
            true,
            true,
            "decapsulate",
        )
        .expect("explicit local software selected");
        assert_eq!(selected, CryptoProviderId::LocalSoftware);

        let denied = select_provider(
            ProviderMetadata {
                provider: Some(CryptoProviderId::LocalSoftware),
                policy: ProviderPolicy::LocalSoftware,
                custody: Some(CustodyMode::SoftwareEncrypted),
            },
            true,
            false,
            "decapsulate",
        )
        .expect_err("caller grant required");
        assert!(matches!(
            denied,
            ProviderError::PolicyDenied {
                reason: "local software custody requires caller policy grant",
                ..
            }
        ));
    }

    #[test]
    fn provider_audit_event_is_secret_free() {
        let event = ProviderAuditEvent {
            op: "decapsulate",
            key_id: "pqc.kem",
            key_version: Some(7),
            algorithm: "ml-kem-768",
            provider: CryptoProviderId::LocalSoftware,
            custody: CustodyMode::SoftwareEncrypted,
            caller_uid: 9100,
            outcome: ProviderAuditOutcome::Success,
            reason: "ok",
        };
        let value = event.to_json_value();
        assert_eq!(value["event"]["kind"], "basil.audit.provider_operation");
        assert_eq!(value["event"]["version"], 1);
        assert_eq!(value["actor"]["kind"], "unix_uid");
        assert_eq!(value["actor"]["id"], "9100");
        assert_eq!(value["target"]["kind"], "catalog_key");
        assert_eq!(value["target"]["id"], "pqc.kem");
        assert_eq!(value["target"]["version"], 7);
        assert!(value["occurred_at"].as_str().is_some());
        assert_eq!(value["op"], "decapsulate");
        assert_eq!(value["key_version"], 7);
        assert_eq!(value["algorithm"], "ml-kem-768");
        assert_eq!(value["provider"], "local-software");
        assert_eq!(value["custody"], "software-encrypted");
        assert_eq!(value["caller_uid"], 9100);
        assert_eq!(value["outcome"], "success");
        assert!(value.get("private_key").is_none());
        assert!(value.get("plaintext").is_none());
        assert!(value.get("ciphertext").is_none());
        assert!(value.get("signature").is_none());
        assert!(value.get("shared_secret").is_none());
    }

    #[tokio::test]
    async fn backend_provider_delegates_legacy_signing() {
        let backend = RecordingBackend;
        let provider = BackendCryptoProvider::new(&backend);
        let signature = provider
            .sign(SignRequest {
                key_id: "catalog.issuer",
                backend_path: "issuer",
                algorithm: SignatureAlgorithm::Rs256,
                message: b"digest",
                storage_key: None,
            })
            .await
            .expect("signs");
        assert_eq!(signature, b"issuerdigest:rs256");
    }

    #[tokio::test]
    async fn backend_provider_rejects_pqc_without_native_support() {
        // ML-DSA now dispatches to the backend's native PQC seam. A backend that
        // does not implement it (the default `sign_pqc`) fails closed with a
        // backend `Unsupported`, so a `backend-required` ML-DSA key over a
        // non-native backend still cannot sign.
        let backend = RecordingBackend;
        let provider = BackendCryptoProvider::new(&backend);
        assert!(!backend.supports_native_algorithm(NativeAlgorithm::MlDsa65));
        let err = provider
            .sign(SignRequest {
                key_id: "catalog.issuer",
                backend_path: "issuer",
                algorithm: SignatureAlgorithm::MlDsa65,
                message: b"digest",
                storage_key: None,
            })
            .await
            .expect_err("ML-DSA unsupported");
        assert!(matches!(
            err,
            ProviderError::Backend(BackendError::Unsupported("sign_pqc"))
        ));
    }
}

#[cfg(test)]
mod pqc_provider_tests {
    use std::collections::HashMap;

    use async_trait::async_trait;
    use basil_proto::{CiphertextEnvelope, KeyType};

    use super::*;
    use crate::backend::{Backend, BackendError, KvValue, NewKey, SignOptions};
    use crate::core::{ml_dsa_sign, ml_kem_envelope};

    const STORAGE_KEY: &str = "pqc-storage-aead";
    const KEY_ID: &str = "pqc.example";
    const PATH: &str = "kv/pqc/example";

    /// In-memory backend simulating out-of-band custody provisioning: it serves a
    /// pre-written `SoftwareCustodyKeyRecord` from `kv_get` and returns the raw
    /// seed from `decrypt` (the test does not exercise the real AEAD).
    struct CustodyBackend {
        records: HashMap<String, Vec<u8>>,
        secrets: HashMap<String, Vec<u8>>,
    }

    impl CustodyBackend {
        fn single(record: Vec<u8>, seed: &[u8]) -> Self {
            Self {
                records: HashMap::from([(PATH.to_string(), record)]),
                secrets: HashMap::from([(STORAGE_KEY.to_string(), seed.to_vec())]),
            }
        }
    }

    #[async_trait]
    impl Backend for CustodyBackend {
        fn kind(&self) -> &'static str {
            "custody-test"
        }

        async fn new_key(&self, _key_type: KeyType) -> Result<NewKey, BackendError> {
            Err(BackendError::Unsupported("new_key"))
        }

        async fn create_named_key(
            &self,
            _key_id: &str,
            _key_type: KeyType,
        ) -> Result<NewKey, BackendError> {
            Err(BackendError::Unsupported("create_named_key"))
        }

        async fn public_key(&self, _key_id: &str) -> Result<Vec<u8>, BackendError> {
            Err(BackendError::Unsupported("public_key"))
        }

        async fn sign(&self, _key_id: &str, _message: &[u8]) -> Result<Vec<u8>, BackendError> {
            Err(BackendError::Unsupported("sign"))
        }

        async fn sign_with_options(
            &self,
            _key_id: &str,
            _message: &[u8],
            _options: SignOptions,
        ) -> Result<Vec<u8>, BackendError> {
            Err(BackendError::Unsupported("sign_with_options"))
        }

        async fn verify(
            &self,
            _key_id: &str,
            _message: &[u8],
            _signature: &[u8],
        ) -> Result<bool, BackendError> {
            Err(BackendError::Unsupported("verify"))
        }

        async fn kv_get(
            &self,
            key_id: &str,
            _version: Option<u32>,
        ) -> Result<KvValue, BackendError> {
            let value = self
                .records
                .get(key_id)
                .cloned()
                .ok_or(BackendError::Unsupported("kv_get"))?;
            Ok(KvValue { value, version: 1 })
        }

        async fn decrypt(
            &self,
            key_id: &str,
            _envelope: &CiphertextEnvelope,
            _aad: Option<&[u8]>,
        ) -> Result<Vec<u8>, BackendError> {
            self.secrets
                .get(key_id)
                .cloned()
                .ok_or(BackendError::Unsupported("decrypt"))
        }
    }

    /// Build a valid software-custody record JSON for one key.
    fn custody_record(algorithm: &str, public_key: &[u8], provider_version: &str) -> Vec<u8> {
        let record = SoftwareCustodyKeyRecord {
            schema_version: SoftwareCustodyKeyRecord::SCHEMA_VERSION,
            key_id: KEY_ID.to_string(),
            key_version: 1,
            public_key: encode_record_bytes(public_key),
            algorithm: algorithm.to_string(),
            provider: CryptoProviderId::LocalSoftware.token().to_string(),
            provider_version: provider_version.to_string(),
            custody: CustodyMode::SoftwareEncrypted.token().to_string(),
            encrypted_private_key: EncryptedPrivateKey {
                wrapping_key: STORAGE_KEY.to_string(),
                algorithm: "aes-256-gcm".to_string(),
                key_version: 1,
                nonce: encode_record_bytes(&[0u8; 12]),
                ciphertext: encode_record_bytes(&[0u8; 16]),
            },
        };
        serde_json::to_vec(&record).expect("serialize record")
    }

    const DSA_LEVELS: [(SignatureAlgorithm, ml_dsa_sign::MlDsaAlgorithm); 3] = [
        (
            SignatureAlgorithm::MlDsa44,
            ml_dsa_sign::MlDsaAlgorithm::MlDsa44,
        ),
        (
            SignatureAlgorithm::MlDsa65,
            ml_dsa_sign::MlDsaAlgorithm::MlDsa65,
        ),
        (
            SignatureAlgorithm::MlDsa87,
            ml_dsa_sign::MlDsaAlgorithm::MlDsa87,
        ),
    ];

    const KEM_LEVELS: [KemAlgorithm; 3] = [
        KemAlgorithm::MlKem512,
        KemAlgorithm::MlKem768,
        KemAlgorithm::MlKem1024,
    ];

    #[tokio::test]
    async fn signs_and_verifies_every_ml_dsa_level() {
        for (sig_algorithm, dsa_algorithm) in DSA_LEVELS {
            let seed = [0x11u8; ml_dsa_sign::SEED_LEN];
            let public = ml_dsa_sign::public_from_seed(dsa_algorithm, &seed).expect("public");
            let record = custody_record(
                dsa_algorithm.token(),
                &public,
                LocalSoftwareProvider::PROVIDER_VERSION,
            );
            let backend = CustodyBackend::single(record, &seed);
            let provider = LocalSoftwareProvider::new(&backend);

            let signature = provider
                .sign(SignRequest {
                    key_id: KEY_ID,
                    backend_path: PATH,
                    algorithm: sig_algorithm,
                    message: b"basil pqc payload",
                    storage_key: Some(STORAGE_KEY),
                })
                .await
                .expect("sign");
            assert!(
                provider
                    .verify(VerifyRequest {
                        key_id: KEY_ID,
                        backend_path: PATH,
                        algorithm: sig_algorithm,
                        message: b"basil pqc payload",
                        signature: &signature,
                        storage_key: Some(STORAGE_KEY),
                    })
                    .await
                    .expect("verify"),
                "{} verifies",
                dsa_algorithm.token()
            );
            assert!(
                !provider
                    .verify(VerifyRequest {
                        key_id: KEY_ID,
                        backend_path: PATH,
                        algorithm: sig_algorithm,
                        message: b"tampered payload",
                        signature: &signature,
                        storage_key: Some(STORAGE_KEY),
                    })
                    .await
                    .expect("verify"),
                "{} rejects wrong message",
                dsa_algorithm.token()
            );
        }
    }

    #[tokio::test]
    async fn encapsulate_decapsulate_every_ml_kem_level() {
        for kem in KEM_LEVELS {
            let seed = [0x42u8; ml_kem_envelope::SEED_LEN];
            let record = custody_record(
                kem_algorithm_name(kem),
                &[7u8; 32],
                LocalSoftwareProvider::PROVIDER_VERSION,
            );
            let backend = CustodyBackend::single(record, &seed);
            let provider = LocalSoftwareProvider::new(&backend);

            let encapsulation = provider
                .encapsulate(EncapsulateRequest {
                    key_id: KEY_ID,
                    backend_path: PATH,
                    algorithm: kem,
                    storage_key: Some(STORAGE_KEY),
                })
                .await
                .expect("encapsulate");
            let shared = provider
                .decapsulate(DecapsulateRequest {
                    key_id: KEY_ID,
                    backend_path: PATH,
                    algorithm: kem,
                    encapsulated_key: &encapsulation.encapsulated_key,
                    storage_key: Some(STORAGE_KEY),
                })
                .await
                .expect("decapsulate");
            assert_eq!(
                encapsulation.shared_secret.as_slice(),
                shared.as_slice(),
                "{} shared secret matches",
                kem_algorithm_name(kem)
            );
        }
    }

    #[tokio::test]
    async fn wrap_unwrap_envelope_every_ml_kem_level() {
        for kem in KEM_LEVELS {
            for envelope_algorithm in [
                EnvelopeAlgorithm::Aes256Gcm,
                EnvelopeAlgorithm::ChaCha20Poly1305,
            ] {
                let seed = [0x42u8; ml_kem_envelope::SEED_LEN];
                let record = custody_record(
                    kem_algorithm_name(kem),
                    &[7u8; 32],
                    LocalSoftwareProvider::PROVIDER_VERSION,
                );
                let backend = CustodyBackend::single(record, &seed);
                let provider = LocalSoftwareProvider::new(&backend);

                let envelope = provider
                    .wrap_envelope(WrapEnvelopeRequest {
                        key_id: KEY_ID,
                        backend_path: PATH,
                        kem_algorithm: kem,
                        envelope_algorithm,
                        plaintext: b"top secret",
                        aad: Some(b"context"),
                        storage_key: Some(STORAGE_KEY),
                    })
                    .await
                    .expect("wrap");
                assert_eq!(envelope.key_version, 1);
                let plaintext = provider
                    .unwrap_envelope(UnwrapEnvelopeRequest {
                        key_id: KEY_ID,
                        backend_path: PATH,
                        kem_algorithm: kem,
                        envelope_algorithm,
                        encapsulated_key: &envelope.encapsulated_key,
                        nonce: &envelope.nonce,
                        ciphertext: &envelope.ciphertext,
                        aad: Some(b"context"),
                        storage_key: Some(STORAGE_KEY),
                    })
                    .await
                    .expect("unwrap");
                assert_eq!(plaintext, b"top secret");

                let wrong_aad = provider
                    .unwrap_envelope(UnwrapEnvelopeRequest {
                        key_id: KEY_ID,
                        backend_path: PATH,
                        kem_algorithm: kem,
                        envelope_algorithm,
                        encapsulated_key: &envelope.encapsulated_key,
                        nonce: &envelope.nonce,
                        ciphertext: &envelope.ciphertext,
                        aad: Some(b"wrong"),
                        storage_key: Some(STORAGE_KEY),
                    })
                    .await
                    .expect_err("wrong aad fails");
                assert!(matches!(
                    wrong_aad,
                    ProviderError::CryptoFailed {
                        op: "unwrap_envelope",
                        ..
                    }
                ));
            }
        }
    }

    #[tokio::test]
    async fn rejects_non_pqc_signature_algorithm() {
        let backend = CustodyBackend::single(Vec::new(), &[]);
        let provider = LocalSoftwareProvider::new(&backend);
        let err = provider
            .sign(SignRequest {
                key_id: KEY_ID,
                backend_path: PATH,
                algorithm: SignatureAlgorithm::Ed25519,
                message: b"m",
                storage_key: Some(STORAGE_KEY),
            })
            .await
            .expect_err("non-pqc rejected");
        assert!(matches!(
            err,
            ProviderError::Unsupported {
                provider: CryptoProviderId::LocalSoftware,
                op: "sign",
                algorithm: "ed25519"
            }
        ));
    }

    #[tokio::test]
    async fn malformed_record_fails_closed() {
        let backend = CustodyBackend::single(b"not a record".to_vec(), &[0u8; 32]);
        let provider = LocalSoftwareProvider::new(&backend);
        let err = provider
            .sign(SignRequest {
                key_id: KEY_ID,
                backend_path: PATH,
                algorithm: SignatureAlgorithm::MlDsa44,
                message: b"m",
                storage_key: Some(STORAGE_KEY),
            })
            .await
            .expect_err("malformed record");
        assert!(matches!(
            err,
            ProviderError::CryptoFailed {
                provider: CryptoProviderId::LocalSoftware,
                op: "sign",
                algorithm: "ml-dsa-44",
                reason: "malformed software-custody record"
            }
        ));
    }

    #[tokio::test]
    async fn wrong_provider_version_record_fails_closed() {
        let seed = [0x11u8; ml_dsa_sign::SEED_LEN];
        let public =
            ml_dsa_sign::public_from_seed(ml_dsa_sign::MlDsaAlgorithm::MlDsa65, &seed).expect("pk");
        // Record provisioned for a different provider version than the provider
        // advertises: metadata cross-check must reject it before any decrypt.
        let record = custody_record("ml-dsa-65", &public, "99");
        let backend = CustodyBackend::single(record, &seed);
        let provider = LocalSoftwareProvider::new(&backend);
        let err = provider
            .sign(SignRequest {
                key_id: KEY_ID,
                backend_path: PATH,
                algorithm: SignatureAlgorithm::MlDsa65,
                message: b"m",
                storage_key: Some(STORAGE_KEY),
            })
            .await
            .expect_err("version mismatch");
        assert!(matches!(err, ProviderError::CryptoFailed { .. }));
    }

    #[tokio::test]
    async fn record_wrapping_key_must_match_the_catalog_storage_key() {
        let seed = [0x11u8; ml_dsa_sign::SEED_LEN];
        let public =
            ml_dsa_sign::public_from_seed(ml_dsa_sign::MlDsaAlgorithm::MlDsa65, &seed).expect("pk");
        let record = custody_record(
            "ml-dsa-65",
            &public,
            LocalSoftwareProvider::PROVIDER_VERSION,
        );
        let backend = CustodyBackend::single(record, &seed);
        let provider = LocalSoftwareProvider::new(&backend);
        // The record self-declares STORAGE_KEY; the catalog declares another
        // AEAD key. The cross-check must reject the record before any unwrap,
        // so a swapped/re-wrapped record cannot pick its own wrapping key.
        let err = provider
            .sign(SignRequest {
                key_id: KEY_ID,
                backend_path: PATH,
                algorithm: SignatureAlgorithm::MlDsa65,
                message: b"m",
                storage_key: Some("other-storage-aead"),
            })
            .await
            .expect_err("wrapping-key mismatch");
        assert!(matches!(
            err,
            ProviderError::CryptoFailed {
                op: "sign",
                reason: "malformed software-custody record",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn use_path_without_a_catalog_storage_key_fails_closed() {
        let seed = [0x11u8; ml_dsa_sign::SEED_LEN];
        let public =
            ml_dsa_sign::public_from_seed(ml_dsa_sign::MlDsaAlgorithm::MlDsa65, &seed).expect("pk");
        let record = custody_record(
            "ml-dsa-65",
            &public,
            LocalSoftwareProvider::PROVIDER_VERSION,
        );
        let backend = CustodyBackend::single(record, &seed);
        let provider = LocalSoftwareProvider::new(&backend);
        // Without the catalog-declared storage key there is no trust anchor to
        // validate the record's wrapping key against: refuse, exactly like the
        // generate path.
        let err = provider
            .sign(SignRequest {
                key_id: KEY_ID,
                backend_path: PATH,
                algorithm: SignatureAlgorithm::MlDsa65,
                message: b"m",
                storage_key: None,
            })
            .await
            .expect_err("missing storage key");
        assert!(matches!(
            err,
            ProviderError::CryptoFailed {
                op: "sign",
                reason: "software-custody key is missing its storage AEAD key",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn generate_without_storage_key_and_import_fail_closed() {
        let backend = CustodyBackend::single(Vec::new(), &[]);
        let provider = LocalSoftwareProvider::new(&backend);
        let material = basil_proto::KeyMaterial::Ed25519Seed(vec![0u8; 32]);
        // Generate is now supported, but it must have a storage AEAD key to seal
        // the seed; without one it fails closed before touching the backend.
        assert!(matches!(
            provider
                .generate_key(GenerateKey {
                    key_id: KEY_ID,
                    backend_path: PATH,
                    algorithm: SignatureAlgorithm::MlDsa87,
                    storage_key: None,
                })
                .await,
            Err(ProviderError::CryptoFailed {
                op: "generate_key",
                ..
            })
        ));
        // Import (BYOK) is still unsupported for software custody.
        assert!(matches!(
            provider
                .import_key(ImportKey {
                    key_id: KEY_ID,
                    backend_path: PATH,
                    algorithm: SignatureAlgorithm::MlDsa87,
                    material: &material,
                })
                .await,
            Err(ProviderError::Unsupported {
                op: "import_key",
                ..
            })
        ));
    }

    /// A stateful in-memory backend that performs a faithful generate → seal →
    /// write → read → unseal → sign round trip: `encrypt` keeps the seed bytes
    /// (identity envelope, the test exercises the provider wiring, not the AEAD),
    /// `kv_put` stores the record, `kv_get` serves it at version 1, and `decrypt`
    /// returns the sealed bytes.
    struct RoundTripBackend {
        records: std::sync::Mutex<HashMap<String, Vec<u8>>>,
    }

    impl RoundTripBackend {
        fn new() -> Self {
            Self {
                records: std::sync::Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl Backend for RoundTripBackend {
        fn kind(&self) -> &'static str {
            "round-trip-custody-test"
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
            algorithm: basil_proto::AeadAlgorithm,
            plaintext: &[u8],
            _aad: Option<&[u8]>,
        ) -> Result<CiphertextEnvelope, BackendError> {
            Ok(CiphertextEnvelope {
                alg: algorithm,
                key_version: 1,
                nonce: vec![0u8; 12],
                ciphertext: plaintext.to_vec(),
            })
        }

        async fn decrypt(
            &self,
            _key_id: &str,
            envelope: &CiphertextEnvelope,
            _aad: Option<&[u8]>,
        ) -> Result<Vec<u8>, BackendError> {
            Ok(envelope.ciphertext.clone())
        }

        async fn kv_put(&self, key_id: &str, value: &[u8]) -> Result<u32, BackendError> {
            self.records
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
                .records
                .lock()
                .map_err(|_| BackendError::Unsupported("kv_get"))?
                .get(key_id)
                .cloned();
            value
                .map(|value| KvValue { value, version: 1 })
                .ok_or(BackendError::Unsupported("kv_get"))
        }
    }

    #[tokio::test]
    async fn generate_then_sign_verify_round_trip_every_level() {
        for (sig_algorithm, dsa_algorithm) in DSA_LEVELS {
            let backend = RoundTripBackend::new();
            let provider = LocalSoftwareProvider::new(&backend);
            let created = provider
                .generate_key(GenerateKey {
                    key_id: KEY_ID,
                    backend_path: PATH,
                    algorithm: sig_algorithm,
                    storage_key: Some(STORAGE_KEY),
                })
                .await
                .expect("generate");
            // The returned public matches what the seed derives.
            assert!(
                !created.public_key.is_empty(),
                "{} public",
                dsa_algorithm.token()
            );

            let signature = provider
                .sign(SignRequest {
                    key_id: KEY_ID,
                    backend_path: PATH,
                    algorithm: sig_algorithm,
                    message: b"provisioned payload",
                    storage_key: Some(STORAGE_KEY),
                })
                .await
                .expect("sign");
            assert!(
                provider
                    .verify(VerifyRequest {
                        key_id: KEY_ID,
                        backend_path: PATH,
                        algorithm: sig_algorithm,
                        message: b"provisioned payload",
                        signature: &signature,
                        storage_key: Some(STORAGE_KEY),
                    })
                    .await
                    .expect("verify"),
                "{} round trip verifies",
                dsa_algorithm.token()
            );
            assert!(
                ml_dsa_sign::verify(
                    dsa_algorithm,
                    &created.public_key,
                    b"provisioned payload",
                    &signature,
                )
                .expect("core verify"),
                "{} verifies under returned public",
                dsa_algorithm.token()
            );
        }
    }
}
