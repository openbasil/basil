//! Async gRPC client for the basil broker.

use std::time::Duration;

use basil_proto::broker::v1 as pb;
use basil_proto::broker::v1::admin_service_client::AdminServiceClient;
use basil_proto::broker::v1::aead_service_client::AeadServiceClient;
use basil_proto::broker::v1::minting_service_client::MintingServiceClient;
use basil_proto::broker::v1::nats_service_client::NatsServiceClient;
use basil_proto::broker::v1::secret_service_client::SecretServiceClient;
use basil_proto::broker::v1::signing_service_client::SigningServiceClient;
use hyper_util::rt::TokioIo;
use prost::Message;
use prost_types::{Duration as ProtoDuration, Struct, Timestamp, Value as ProtoValue};
use tokio::net::UnixStream;
use tokio::time::timeout;
use tonic::transport::{Channel, Endpoint};
use tonic::{Status, transport::Uri};
use tower::service_fn;
use tracing::{error, trace};

use crate::constants::DEFAULT_CONN_TIMEOUT;
use crate::error::{Error, Result};
use crate::proto::{AeadAlgorithm, CiphertextEnvelope, KeyMaterial, KeyType};

/// A key created or imported in the broker catalog, returned by
/// [`Client::new_key`], [`Client::import`], and [`Client::import_set`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyHandle {
    /// Catalog name the key is stored under.
    pub key_id: String,
    /// The key's public half (raw bytes; empty for value/symmetric keys).
    pub public_key: Vec<u8>,
}

/// One key to import in an [`Client::import_set`] batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportEntry {
    /// Catalog name to store the key under.
    pub key_id: String,
    /// The key's type.
    pub key_type: KeyType,
    /// The caller-provided key material (write-only; never returned).
    pub material: KeyMaterial,
}

/// Options for [`Client::sign_nats_jwt`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignNatsJwtOptions {
    /// Optional assertion against `claims.nats.type`.
    pub expected_type: Option<pb::NatsJwtType>,
    /// Relative lifetime in seconds. Mutually exclusive with
    /// [`expires_at`](Self::expires_at).
    pub ttl_secs: Option<u64>,
    /// Absolute expiry as a Unix timestamp. Mutually exclusive with
    /// [`ttl_secs`](Self::ttl_secs).
    pub expires_at: Option<u64>,
    /// Issued-at Unix timestamp; absent lets the broker use its clock unless the
    /// claims already carry `iat`.
    pub issued_at: Option<u64>,
    /// Replace a supplied stale/mismatched `jti` with the computed NATS value.
    pub rewrite_jti: bool,
}

/// One candidate signer to trust when validating a presented NATS JWT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowedNatsSigner {
    /// Catalog key name; Basil resolves the public `NKey` and authorizes access.
    KeyId(String),
    /// Raw public `NKey` (`U...`, `A...`, `O...`, etc.).
    NatsPublicKey(String),
}

impl AllowedNatsSigner {
    /// Trust a signer by catalog key name.
    #[must_use]
    pub fn key_id(key_id: impl Into<String>) -> Self {
        Self::KeyId(key_id.into())
    }

    /// Trust a signer by raw public `NKey`.
    #[must_use]
    pub fn nats_public_key(public_key: impl Into<String>) -> Self {
        Self::NatsPublicKey(public_key.into())
    }

    fn into_proto(self) -> pb::AllowedNatsSigner {
        let signer = match self {
            Self::KeyId(key_id) => pb::allowed_nats_signer::Signer::KeyId(key_id),
            Self::NatsPublicKey(public_key) => {
                pb::allowed_nats_signer::Signer::NatsPublicKey(public_key)
            }
        };
        pb::AllowedNatsSigner {
            signer: Some(signer),
        }
    }
}

/// Machine-readable result of NATS JWT validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatsJwtValidationReason {
    /// Token is valid under the supplied candidate signer set.
    Valid,
    /// Compact JWT syntax, header, claims, issuer, or signature encoding is malformed.
    Malformed,
    /// The signer matched, but the Ed25519 signature is invalid.
    BadSignature,
    /// No supplied candidate signer matched the token's embedded `iss`.
    UnknownSigner,
    /// The token is expired.
    Expired,
    /// The token's `nbf` is in the future.
    NotYetValid,
    /// The token's `nats.type` does not match the caller assertion.
    WrongType,
    /// The broker returned an unknown future reason.
    Unknown,
}

impl NatsJwtValidationReason {
    const fn from_proto(reason: pb::NatsJwtValidationReason) -> Self {
        match reason {
            pb::NatsJwtValidationReason::Valid => Self::Valid,
            pb::NatsJwtValidationReason::Malformed => Self::Malformed,
            pb::NatsJwtValidationReason::BadSignature => Self::BadSignature,
            pb::NatsJwtValidationReason::UnknownSigner => Self::UnknownSigner,
            pb::NatsJwtValidationReason::Expired => Self::Expired,
            pb::NatsJwtValidationReason::NotYetValid => Self::NotYetValid,
            pb::NatsJwtValidationReason::WrongType => Self::WrongType,
            pb::NatsJwtValidationReason::Unspecified => Self::Unknown,
        }
    }
}

/// Parsed validation result for a presented NATS JWT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatsJwtValidation {
    /// True only when `reason` is [`NatsJwtValidationReason::Valid`].
    pub valid: bool,
    /// Machine-readable validation result.
    pub reason: NatsJwtValidationReason,
    /// Extracted `sub`, when the token was parseable.
    pub subject: String,
    /// Extracted `iss`, when the token was parseable.
    pub issuer: String,
    /// Catalog key id that matched, when the matching candidate was a key id.
    pub matched_signer_key_id: Option<String>,
    /// Extracted `nats.type`.
    pub jwt_type: pb::NatsJwtType,
    /// Extracted `exp`, when present.
    pub expires_at: Option<u64>,
    /// Extracted `iat`, when present.
    pub issued_at: Option<u64>,
}

/// Publish/subscribe permissions for a minted NATS user JWT.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NatsUserPermissions {
    /// Subjects the user may publish to. Empty means unrestricted.
    pub pub_allow: Vec<String>,
    /// Subjects the user may not publish to.
    pub pub_deny: Vec<String>,
    /// Subjects the user may subscribe to. Empty means unrestricted.
    pub sub_allow: Vec<String>,
    /// Subjects the user may not subscribe to.
    pub sub_deny: Vec<String>,
}

/// A secret payload and the catalog version it was read from, returned by
/// [`Client::get_secret`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretValue {
    /// Raw secret bytes.
    pub value: Vec<u8>,
    /// Catalog version this value was read from.
    pub version: u32,
}

/// A minted JWT credential and its expiry, returned by [`Client::mint_jwt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintedJwt {
    /// The compact JWS token.
    pub token: String,
    /// Unix expiry in seconds, when the credential is time-bounded.
    pub expires_at: Option<u64>,
}

/// An issued X.509 leaf certificate with its private key and trust chain,
/// returned by [`Client::issue_certificate`].
///
/// The leaf private key is released to the caller because a TLS server needs it
/// to terminate connections; the issuing CA key never leaves the backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedCertificate {
    /// DER leaf certificate, followed by any intermediate issuer certificates.
    pub cert_chain_der: Vec<Vec<u8>>,
    /// DER PKCS#8 leaf private key (released to the caller).
    pub private_key_der: Vec<u8>,
    /// DER issuing-CA / trust-bundle certificates.
    pub ca_chain_der: Vec<Vec<u8>>,
}

/// Broker identity and protocol information, returned by [`Client::status`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentStatus {
    /// Backend identifier the broker is running against (e.g. `vault`).
    pub backend: String,
    /// Broker build version string.
    pub version: String,
    /// Wire protocol version number.
    pub protocol: u32,
}

/// Broker liveness, returned by [`Client::health`]. A returned value means the
/// daemon is up and serving the socket; no backend I/O is performed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentHealth {
    /// Whether the broker process is alive (always `true` for a returned value).
    pub alive: bool,
    /// Broker build version string.
    pub version: String,
}

/// Why the broker is not ready to serve (a coarse, non-secret category).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadinessReason {
    /// The broker can serve: every backend reachable, no `missing=error` key absent.
    Ready,
    /// At least one backend was unreachable (or rejecting) while probing.
    BackendUnreachable,
    /// At least one `missing=error` key's material is absent (ops fail closed).
    RequiredKeyMissing,
    /// The broker returned a reason this client build does not recognize.
    Unknown,
}

impl ReadinessReason {
    /// Map the wire reason enum onto this client-facing category.
    const fn from_proto(reason: pb::ReadinessReason) -> Self {
        match reason {
            pb::ReadinessReason::Ready => Self::Ready,
            pb::ReadinessReason::BackendUnreachable => Self::BackendUnreachable,
            pb::ReadinessReason::RequiredKeyMissing => Self::RequiredKeyMissing,
            pb::ReadinessReason::Unspecified => Self::Unknown,
        }
    }
}

impl std::fmt::Display for ReadinessReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Ready => "ready",
            Self::BackendUnreachable => "backend_unreachable",
            Self::RequiredKeyMissing => "required_key_missing",
            Self::Unknown => "unknown",
        })
    }
}

/// Broker readiness: a non-secret operational summary.
///
/// Returned by [`Client::readiness`]. Never carries key names, key material, or
/// the catalog inventory: only counts, a coarse reason, and the active
/// generation id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentReadiness {
    /// Whether the broker can serve (serving would not fail closed for any key).
    pub ready: bool,
    /// The dominant reason readiness was decided.
    pub reason: ReadinessReason,
    /// The currently serving policy/catalog generation id (bumped on hot reload).
    pub generation: u64,
    /// Total number of catalog keys probed.
    pub keys_total: u32,
    /// Keys whose material is present in its backend.
    pub keys_present: u32,
    /// Absent `missing=error` keys (ops fail closed; non-zero ⇒ not ready).
    pub keys_required_missing: u32,
    /// Absent `warn`/`generate` keys (reported, do not block readiness).
    pub keys_optional_missing: u32,
}

/// Why an admin [`Client::reload`] candidate was rejected. On a rejection the
/// previous generation keeps serving; the reason is a stable non-secret token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReloadRejection {
    /// A stable, non-secret reason token (e.g. `validation_failed`,
    /// `routing_shape_changed`, `catalog_read_failed`, `no_reload_inputs`).
    pub reason: String,
    /// A human-readable, non-secret message describing the rejection.
    pub message: String,
}

/// The outcome of an admin [`Client::reload`].
///
/// A successful reload (`applied = true`) reports the old → new generation ids and
/// the candidate's key/grant counts. A dry-run (`checked = true`) reports the
/// *would-be* outcome without swapping. A rejected candidate carries a
/// [`ReloadRejection`] and leaves `previous_generation == new_generation` (the
/// running generation keeps serving). Permission-denied does not reach here. It
/// surfaces as an [`Error::Status`] with code `PermissionDenied`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentReload {
    /// Whether a real swap occurred (`true` only for an applied, non-dry-run reload).
    pub applied: bool,
    /// Whether this was a dry-run (`--check`): validated, never swapped.
    pub checked: bool,
    /// The generation serving before this call (still serving on a dry-run/rejection).
    pub previous_generation: u64,
    /// The generation now serving (applied) or the would-be one (dry-run); equals
    /// `previous_generation` on a rejection.
    pub new_generation: u64,
    /// Catalog key count in the validated candidate generation.
    pub key_count: u32,
    /// Resolved policy allow-grant count in the validated candidate generation.
    pub grant_count: u32,
    /// Set only when the candidate was rejected (the previous generation serves on).
    pub rejection: Option<ReloadRejection>,
}

/// Result of a live JWT-SVID revocation, returned by [`Client::revoke`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRevocation {
    /// SPIFFE trust domain revoked.
    pub trust_domain: String,
    /// JWT ID revoked.
    pub jti: String,
    /// Unix expiry stored for the deny-list entry.
    pub expires_at_unix: u64,
    /// Whether the revocation was persisted to the configured backing store.
    pub persisted: bool,
}

impl AgentReload {
    /// Whether the broker accepted the candidate: an applied reload, or a dry-run
    /// that validated cleanly. `false` iff a [`ReloadRejection`] is present.
    #[must_use]
    pub const fn succeeded(&self) -> bool {
        self.rejection.is_none()
    }
}

/// Rule provenance returned by [`Client::explain`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedRule {
    /// Policy rule id that matched.
    pub rule: String,
    /// Scope that matched (`user`, `group:<gid>`, `any_principal`, `public_class`).
    pub via: String,
    /// Action token that matched.
    pub action: String,
    /// Target glob that matched.
    pub target: String,
    /// Matched policy subject.
    pub subject: String,
}

/// A live policy explanation from the currently serving broker generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentExplanation {
    /// Subject evaluated.
    pub subject: String,
    /// Operation token evaluated.
    pub op: String,
    /// Catalog key/target evaluated.
    pub key: String,
    /// `allow` or `deny`.
    pub decision: String,
    /// Allow scope; empty on deny.
    pub via: String,
    /// Deny reason token; empty on allow.
    pub reason: String,
    /// Rule provenance for rule-based allows.
    pub matched_rule: Option<MatchedRule>,
}

/// An async client for Basil's broker gRPC services over a Unix socket.
#[derive(Clone)]
pub struct Client {
    signing: SigningServiceClient<Channel>,
    aead: AeadServiceClient<Channel>,
    secrets: SecretServiceClient<Channel>,
    minting: MintingServiceClient<Channel>,
    nats: NatsServiceClient<Channel>,
    admin: AdminServiceClient<Channel>,
    default_timeout: u64,
}

impl Client {
    /// Connect to the broker listening at `path`.
    pub async fn connect(path: &str) -> Result<Self> {
        Self::connect_with_timeout(path, DEFAULT_CONN_TIMEOUT).await
    }

    /// Connect with an explicit default per-request timeout in seconds.
    pub async fn connect_with_timeout(path: &str, default_timeout: u64) -> Result<Self> {
        trace!(%path, "connecting to broker gRPC socket");
        let channel = uds_channel(path, default_timeout).await?;
        Ok(Self {
            signing: SigningServiceClient::new(channel.clone()),
            aead: AeadServiceClient::new(channel.clone()),
            secrets: SecretServiceClient::new(channel.clone()),
            minting: MintingServiceClient::new(channel.clone()),
            nats: NatsServiceClient::new(channel.clone()),
            admin: AdminServiceClient::new(channel),
            default_timeout,
        })
    }

    async fn bounded<T>(
        timeout_secs: u64,
        fut: impl std::future::Future<Output = std::result::Result<T, Status>>,
    ) -> Result<T> {
        timeout(Duration::from_secs(timeout_secs), fut)
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|status| status_error(&status))
    }

    /// Create a key under catalog name `key_id`.
    ///
    /// Classical types are generated/imported in place by the backend. The
    /// post-quantum types, `MlDsa44`/`MlDsa65`/`MlDsa87` (signing) and
    /// `MlKem512`/`MlKem768`/`MlKem1024` (sealing), provision a software-custodied
    /// key against the operator-declared catalog entry: the broker generates the
    /// seed, seals it, writes the custody record, and returns only the public half
    /// (and the catalog id). Custody and storage are operator-controlled via the
    /// catalog, never chosen by the caller. Requires the `op:use_software_custody`
    /// grant in addition to `op:new_key`.
    pub async fn new_key(&mut self, key_id: &str, key_type: KeyType) -> Result<KeyHandle> {
        let response = Self::bounded(
            self.default_timeout,
            self.signing.new_key(pb::NewKeyRequest {
                key_id: key_id.to_string(),
                key_type: proto_key_type(key_type),
            }),
        )
        .await?;
        let body = response.into_inner();
        Ok(KeyHandle {
            key_id: body.key_id,
            public_key: body.public_key,
        })
    }

    /// Import caller-provided key material.
    pub async fn import(
        &mut self,
        key_id: &str,
        key_type: KeyType,
        material: KeyMaterial,
    ) -> Result<KeyHandle> {
        let response = Self::bounded(
            self.default_timeout,
            self.signing.import(pb::ImportRequest {
                key_id: key_id.to_string(),
                key_type: proto_key_type(key_type),
                material: Some(proto_key_material(material)),
            }),
        )
        .await?;
        let body = response.into_inner();
        Ok(KeyHandle {
            key_id: body.key_id,
            public_key: body.public_key,
        })
    }

    /// Import several keys in one call (e.g. an `nsc`-init bundle: operator + SYS
    /// account + SYS user, or account + account-signing-key). Authorization is
    /// all-or-nothing; the imports themselves are sequential. Returns one
    /// [`KeyHandle`] per imported key, in request order.
    pub async fn import_set(&mut self, entries: Vec<ImportEntry>) -> Result<Vec<KeyHandle>> {
        let entries = entries
            .into_iter()
            .map(|entry| pb::ImportEntry {
                key_id: entry.key_id,
                key_type: proto_key_type(entry.key_type),
                material: Some(proto_key_material(entry.material)),
            })
            .collect();
        let response = Self::bounded(
            self.default_timeout,
            self.signing.import_set(pb::ImportSetRequest { entries }),
        )
        .await?;
        Ok(response
            .into_inner()
            .keys
            .into_iter()
            .map(|key| KeyHandle {
                key_id: key.key_id,
                public_key: key.public_key,
            })
            .collect())
    }

    /// Sign `message` with `key_id`, returning the raw signature.
    ///
    /// `message` is the raw bytes to be signed, **not** a precomputed digest:
    /// Basil signs the input as-is (the broker does no client-directed
    /// prehashing). A NATS caller can pass either a server nonce verbatim or
    /// the complete JWT signing input for a caller-built rich claim, then append
    /// the returned raw signature with `basil_nats::assemble`.
    pub async fn sign(&mut self, key_id: &str, message: &[u8]) -> Result<Vec<u8>> {
        self.sign_with_algorithm(key_id, message, pb::SigningAlgorithm::Unspecified)
            .await
    }

    /// Sign with an explicit gRPC signing algorithm. Use
    /// [`SigningAlgorithm::Ed25519Nkey`](basil_proto::broker::v1::SigningAlgorithm::Ed25519Nkey)
    /// for NATS nonce or JWT signing-input bytes. See [`sign`](Self::sign) for
    /// the meaning of `message`.
    pub async fn sign_with_algorithm(
        &mut self,
        key_id: &str,
        message: &[u8],
        algorithm: pb::SigningAlgorithm,
    ) -> Result<Vec<u8>> {
        let response = Self::bounded(
            self.default_timeout,
            self.signing.sign(pb::SignRequest {
                key_id: key_id.to_string(),
                message: message.to_vec(),
                algorithm: algorithm.into(),
            }),
        )
        .await?;
        Ok(response.into_inner().signature)
    }

    /// Verify `signature` over `message` with `key_id`. `message` is the raw
    /// signed bytes (see [`sign`](Self::sign)).
    pub async fn verify(&mut self, key_id: &str, message: &[u8], signature: &[u8]) -> Result<bool> {
        self.verify_with_algorithm(
            key_id,
            message,
            signature,
            pb::SigningAlgorithm::Unspecified,
        )
        .await
    }

    /// Verify with an explicit gRPC signing algorithm.
    pub async fn verify_with_algorithm(
        &mut self,
        key_id: &str,
        message: &[u8],
        signature: &[u8],
        algorithm: pb::SigningAlgorithm,
    ) -> Result<bool> {
        let response = Self::bounded(
            self.default_timeout,
            self.signing.verify(pb::VerifyRequest {
                key_id: key_id.to_string(),
                message: message.to_vec(),
                signature: signature.to_vec(),
                algorithm: algorithm.into(),
            }),
        )
        .await?;
        Ok(response.into_inner().valid)
    }

    /// Fetch a public key by catalog name and optional version.
    pub async fn get_public_key(
        &mut self,
        key_id: &str,
        version: Option<u32>,
    ) -> Result<pb::GetPublicKeyResponse> {
        let response = Self::bounded(
            self.default_timeout,
            self.signing.get_public_key(pb::GetPublicKeyRequest {
                key_id: key_id.to_string(),
                version,
            }),
        )
        .await?;
        Ok(response.into_inner())
    }

    /// Encrypt plaintext. Basil owns nonce generation.
    pub async fn encrypt(
        &mut self,
        key_id: &str,
        algorithm: AeadAlgorithm,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<CiphertextEnvelope> {
        let response = Self::bounded(
            self.default_timeout,
            self.aead.encrypt(pb::EncryptRequest {
                key_id: key_id.to_string(),
                algorithm: proto_aead_algorithm(algorithm),
                plaintext: plaintext.to_vec(),
                aad: aad.map(<[u8]>::to_vec),
            }),
        )
        .await?;
        let envelope = response
            .into_inner()
            .envelope
            .ok_or_else(|| missing_field("encrypt", "envelope"))?;
        Ok(basil_ciphertext_envelope(envelope))
    }

    /// Decrypt a Basil ciphertext envelope.
    pub async fn decrypt(
        &mut self,
        key_id: &str,
        envelope: CiphertextEnvelope,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let response = Self::bounded(
            self.default_timeout,
            self.aead.decrypt(pb::DecryptRequest {
                key_id: key_id.to_string(),
                envelope: Some(proto_ciphertext_envelope(envelope)),
                aad: aad.map(<[u8]>::to_vec),
            }),
        )
        .await?;
        Ok(response.into_inner().plaintext)
    }

    /// Wrap plaintext with a KEM/envelope operation.
    pub async fn wrap_envelope(
        &mut self,
        key_id: &str,
        kem_algorithm: pb::KemAlgorithm,
        envelope_algorithm: pb::EnvelopeAlgorithm,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<pb::KemEnvelope> {
        let response = Self::bounded(
            self.default_timeout,
            self.aead.wrap_envelope(pb::WrapEnvelopeRequest {
                key_id: key_id.to_string(),
                kem_algorithm: kem_algorithm.into(),
                envelope_algorithm: envelope_algorithm.into(),
                plaintext: plaintext.to_vec(),
                aad: aad.map(<[u8]>::to_vec),
            }),
        )
        .await?;
        response
            .into_inner()
            .envelope
            .ok_or_else(|| missing_field("wrap_envelope", "envelope"))
    }

    /// Unwrap a KEM/envelope ciphertext.
    pub async fn unwrap_envelope(
        &mut self,
        key_id: &str,
        envelope: pb::KemEnvelope,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let response = Self::bounded(
            self.default_timeout,
            self.aead.unwrap_envelope(pb::UnwrapEnvelopeRequest {
                key_id: key_id.to_string(),
                envelope: Some(envelope),
                aad: aad.map(<[u8]>::to_vec),
            }),
        )
        .await?;
        Ok(response.into_inner().plaintext)
    }

    /// Open a tagged `COSE_Encrypt` message through the broker.
    ///
    /// The `cose_encrypt` bytes are forwarded verbatim; COSE AEAD
    /// authentication binds the exact protected-header bytes, so callers must
    /// not parse and re-encode them before passing them here.
    pub async fn unseal_cose(
        &mut self,
        key_id: &str,
        cose_encrypt: &[u8],
        external_aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let response = Self::bounded(
            self.default_timeout,
            self.aead.unseal_cose(pb::UnsealCoseRequest {
                key_id: key_id.to_string(),
                cose_encrypt: cose_encrypt.to_vec(),
                external_aad: external_aad.map(<[u8]>::to_vec),
            }),
        )
        .await?;
        Ok(response.into_inner().plaintext)
    }

    /// Fetch a secret payload.
    pub async fn get_secret(
        &mut self,
        secret_id: &str,
        version: Option<u32>,
    ) -> Result<SecretValue> {
        let response = Self::bounded(
            self.default_timeout,
            self.secrets.get_secret(pb::GetSecretRequest {
                secret_id: secret_id.to_string(),
                version,
            }),
        )
        .await?;
        let body = response.into_inner();
        Ok(SecretValue {
            value: body.value,
            version: body.version,
        })
    }

    /// Store a secret payload, returning the new version.
    pub async fn set_secret(&mut self, secret_id: &str, value: &[u8]) -> Result<u32> {
        let response = Self::bounded(
            self.default_timeout,
            self.secrets.set_secret(pb::SetSecretRequest {
                secret_id: secret_id.to_string(),
                value: value.to_vec(),
            }),
        )
        .await?;
        Ok(response.into_inner().version)
    }

    /// Rotate a secret, returning the new version.
    pub async fn rotate_secret(&mut self, secret_id: &str) -> Result<u32> {
        let response = Self::bounded(
            self.default_timeout,
            self.secrets.rotate_secret(pb::RotateSecretRequest {
                secret_id: secret_id.to_string(),
            }),
        )
        .await?;
        Ok(response.into_inner().version)
    }

    /// List visible catalog entries, optionally filtered by prefix.
    pub async fn list_catalog(&mut self, prefix: Option<&str>) -> Result<Vec<pb::CatalogEntry>> {
        let response = Self::bounded(
            self.default_timeout,
            self.secrets.list_catalog(pb::ListCatalogRequest {
                prefix: prefix.map(ToString::to_string),
            }),
        )
        .await?;
        let mut stream = response.into_inner();
        let mut keys = Vec::new();
        loop {
            match Self::bounded(self.default_timeout, stream.message()).await? {
                Some(key) => keys.push(key),
                None => return Ok(keys),
            }
        }
    }

    /// Mint a generic JWT credential.
    pub async fn mint_jwt(
        &mut self,
        key_id: &str,
        sub: &str,
        ttl_secs: Option<u64>,
        claims: serde_json::Value,
    ) -> Result<MintedJwt> {
        let response = Self::bounded(
            self.default_timeout,
            self.minting.mint_jwt(pb::MintJwtRequest {
                key_id: key_id.to_string(),
                subject: Some(sub.to_string()),
                ttl: ttl_secs.map(proto_duration),
                claims: Some(json_struct(claims)),
            }),
        )
        .await?;
        let body = response.into_inner();
        Ok(MintedJwt {
            token: body.token,
            expires_at: body.expires_at.map(timestamp_secs),
        })
    }

    /// Mint a NATS user JWT signed by an account key held by Basil.
    ///
    /// `issuer_account` is the owning account's identity public `NKey` (`A…`). It
    /// is **required** when `key_id` is an account *signing* key (not the account
    /// identity key): it sets the `nats.issuer_account` claim so nats-server can
    /// bind the user to its account. Pass `None` when `key_id` is the account
    /// identity key itself.
    pub async fn mint_nats_user(
        &mut self,
        key_id: &str,
        subject_user_nkey: &str,
        issuer_account: Option<&str>,
        name: &str,
        ttl_secs: Option<u64>,
        permissions: NatsUserPermissions,
    ) -> Result<String> {
        let response = Self::bounded(
            self.default_timeout,
            self.nats.mint_nats_user(pb::MintNatsUserRequest {
                key_id: key_id.to_string(),
                subject_user_nkey: subject_user_nkey.to_string(),
                issuer_account: issuer_account.map(str::to_string),
                name: name.to_string(),
                ttl: ttl_secs.map(proto_duration),
                pub_allow: permissions.pub_allow,
                pub_deny: permissions.pub_deny,
                sub_allow: permissions.sub_allow,
                sub_deny: permissions.sub_deny,
            }),
        )
        .await?;
        Ok(response.into_inner().token)
    }

    /// Mint a NATS account JWT signed by an operator key (or self-signed) held by Basil.
    pub async fn mint_nats_account(
        &mut self,
        signing_key_id: &str,
        subject_account_nkey: &str,
        name: &str,
        signing_keys: &[String],
        expires_in_secs: Option<u64>,
    ) -> Result<String> {
        let response = Self::bounded(
            self.default_timeout,
            self.nats.mint_nats_account(pb::MintNatsAccountRequest {
                key_id: signing_key_id.to_string(),
                subject_account_nkey: subject_account_nkey.to_string(),
                name: name.to_string(),
                ttl: expires_in_secs.map(proto_duration),
                signing_keys: signing_keys.to_vec(),
            }),
        )
        .await?;
        Ok(response.into_inner().token)
    }

    /// Mint a NATS operator JWT. With `subject_operator_nkey` set to `None` the issuer self-signs.
    #[allow(clippy::too_many_arguments)]
    pub async fn mint_nats_operator(
        &mut self,
        signing_key_id: &str,
        subject_operator_nkey: Option<&str>,
        name: &str,
        signing_keys: &[String],
        account_server_url: Option<&str>,
        system_account: Option<&str>,
        expires_in_secs: Option<u64>,
    ) -> Result<String> {
        let response = Self::bounded(
            self.default_timeout,
            self.nats.mint_nats_operator(pb::MintNatsOperatorRequest {
                key_id: signing_key_id.to_string(),
                subject_operator_nkey: subject_operator_nkey.map(ToString::to_string),
                name: name.to_string(),
                ttl: expires_in_secs.map(proto_duration),
                signing_keys: signing_keys.to_vec(),
                account_server_url: account_server_url.map(ToString::to_string),
                system_account: system_account.map(ToString::to_string),
            }),
        )
        .await?;
        Ok(response.into_inner().token)
    }

    /// Mint a NATS account-signing-key JWT (subject is an `N`-prefixed signer nkey).
    pub async fn mint_nats_signer(
        &mut self,
        signing_key_id: &str,
        subject_nkey: &str,
        name: &str,
        expires_in_secs: Option<u64>,
    ) -> Result<String> {
        let response = Self::bounded(
            self.default_timeout,
            self.nats.mint_nats_signer(pb::MintNatsSignerRequest {
                key_id: signing_key_id.to_string(),
                subject_nkey: subject_nkey.to_string(),
                name: name.to_string(),
                ttl: expires_in_secs.map(proto_duration),
            }),
        )
        .await?;
        Ok(response.into_inner().token)
    }

    /// Mint a NATS server JWT (subject is an `N`-prefixed server nkey).
    pub async fn mint_nats_server(
        &mut self,
        signing_key_id: &str,
        subject_server_nkey: &str,
        name: &str,
        expires_in_secs: Option<u64>,
    ) -> Result<String> {
        let response = Self::bounded(
            self.default_timeout,
            self.nats.mint_nats_server(pb::MintNatsServerRequest {
                key_id: signing_key_id.to_string(),
                subject_server_nkey: subject_server_nkey.to_string(),
                name: name.to_string(),
                ttl: expires_in_secs.map(proto_duration),
            }),
        )
        .await?;
        Ok(response.into_inner().token)
    }

    /// Mint a NATS curve (x25519) JWT (subject is an `X`-prefixed curve nkey).
    pub async fn mint_nats_curve(
        &mut self,
        signing_key_id: &str,
        subject_curve_nkey: &str,
        name: &str,
        expires_in_secs: Option<u64>,
    ) -> Result<String> {
        let response = Self::bounded(
            self.default_timeout,
            self.nats.mint_nats_curve(pb::MintNatsCurveRequest {
                key_id: signing_key_id.to_string(),
                subject_curve_nkey: subject_curve_nkey.to_string(),
                name: name.to_string(),
                ttl: expires_in_secs.map(proto_duration),
            }),
        )
        .await?;
        Ok(response.into_inner().token)
    }

    /// Encrypt with a custodied NATS curve xkey to a recipient public xkey.
    pub async fn encrypt_nats_curve(
        &mut self,
        key_id: &str,
        recipient_public_xkey: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let response = Self::bounded(
            self.default_timeout,
            self.nats.encrypt_nats_curve(pb::EncryptNatsCurveRequest {
                key_id: key_id.to_string(),
                recipient_public_xkey: recipient_public_xkey.to_string(),
                plaintext: plaintext.to_vec(),
            }),
        )
        .await?;
        Ok(response.into_inner().ciphertext)
    }

    /// Decrypt a NATS curve xkey box from a sender public xkey.
    pub async fn decrypt_nats_curve(
        &mut self,
        key_id: &str,
        sender_public_xkey: &str,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let response = Self::bounded(
            self.default_timeout,
            self.nats.decrypt_nats_curve(pb::DecryptNatsCurveRequest {
                key_id: key_id.to_string(),
                sender_public_xkey: sender_public_xkey.to_string(),
                ciphertext: ciphertext.to_vec(),
            }),
        )
        .await?;
        Ok(response.into_inner().plaintext)
    }

    /// Validate and sign a caller-supplied NATS JWT claim document.
    pub async fn sign_nats_jwt(
        &mut self,
        key_id: &str,
        claims: impl serde::Serialize,
        options: SignNatsJwtOptions,
    ) -> Result<MintedJwt> {
        let claims_json = serde_json::to_vec(&claims)?;
        self.sign_nats_jwt_json(key_id, claims_json, options).await
    }

    /// Validate and sign a pre-encoded NATS JWT claim document.
    pub async fn sign_nats_jwt_json(
        &mut self,
        key_id: &str,
        claims_json: impl Into<Vec<u8>>,
        options: SignNatsJwtOptions,
    ) -> Result<MintedJwt> {
        let response = Self::bounded(
            self.default_timeout,
            self.nats.sign_nats_jwt(pb::SignNatsJwtRequest {
                key_id: key_id.to_string(),
                claims_json: claims_json.into(),
                expected_type: options.expected_type.unwrap_or_default().into(),
                ttl: options.ttl_secs.map(proto_duration),
                expires_at: options.expires_at.map(proto_timestamp),
                issued_at: options.issued_at.map(proto_timestamp),
                jti_mode: if options.rewrite_jti {
                    pb::NatsJtiMode::Rewrite.into()
                } else {
                    pb::NatsJtiMode::RequireValid.into()
                },
            }),
        )
        .await?;
        let body = response.into_inner();
        Ok(MintedJwt {
            token: body.token,
            expires_at: body.expires_at.map(timestamp_secs),
        })
    }

    /// Validate a presented NATS JWT against candidate catalog keys or public `NKeys`.
    pub async fn validate_nats_jwt(
        &mut self,
        jwt: &str,
        allowed_signers: impl IntoIterator<Item = AllowedNatsSigner>,
        expected_type: Option<pb::NatsJwtType>,
    ) -> Result<NatsJwtValidation> {
        let response = Self::bounded(
            self.default_timeout,
            self.nats.validate_nats_jwt(pb::ValidateNatsJwtRequest {
                jwt: jwt.to_string(),
                allowed_signers: allowed_signers
                    .into_iter()
                    .map(AllowedNatsSigner::into_proto)
                    .collect(),
                expected_type: expected_type.unwrap_or_default().into(),
            }),
        )
        .await?;
        let body = response.into_inner();
        let reason = NatsJwtValidationReason::from_proto(body.reason());
        let jwt_type = body.jwt_type();
        Ok(NatsJwtValidation {
            valid: body.valid,
            reason,
            subject: body.subject,
            issuer: body.issuer,
            jwt_type,
            matched_signer_key_id: non_empty(body.matched_signer_key_id),
            expires_at: non_zero(body.expires_at_unix),
            issued_at: non_zero(body.issued_at_unix),
        })
    }

    /// Issue a DNS/IP-SAN X.509 leaf (TLS cert) signed by a CA the broker holds in
    /// the backend PKI engine. The leaf private key is released to the caller (a
    /// TLS server needs it); the issuing CA key never leaves the backend.
    pub async fn issue_certificate(
        &mut self,
        issuer_key_id: &str,
        common_name: &str,
        dns_sans: &[String],
        ip_sans: &[String],
        ttl_secs: u64,
    ) -> Result<IssuedCertificate> {
        let response = Self::bounded(
            self.default_timeout,
            self.minting.issue_certificate(pb::IssueCertificateRequest {
                issuer_key_id: issuer_key_id.to_string(),
                common_name: common_name.to_string(),
                dns_sans: dns_sans.to_vec(),
                ip_sans: ip_sans.to_vec(),
                ttl: Some(proto_duration(ttl_secs)),
            }),
        )
        .await?;
        let body = response.into_inner();
        Ok(IssuedCertificate {
            cert_chain_der: body.cert_chain_der,
            private_key_der: body.private_key_der,
            ca_chain_der: body.ca_chain_der,
        })
    }

    /// The broker's backend identifier, build version, and wire protocol version.
    pub async fn status(&mut self) -> Result<AgentStatus> {
        let response = Self::bounded(
            self.default_timeout,
            self.admin.status(pb::StatusRequest {}),
        )
        .await?;
        let body = response.into_inner();
        Ok(AgentStatus {
            backend: body.backend,
            version: body.version,
            protocol: body.protocol,
        })
    }

    /// Broker liveness: is the daemon up and serving the socket? Cheap; the
    /// broker performs no backend I/O. Use this for a process-health probe (e.g.
    /// systemd `WatchdogSec` companion or a container liveness check).
    pub async fn health(&mut self) -> Result<AgentHealth> {
        let response = Self::bounded(
            self.default_timeout,
            self.admin.health(pb::HealthRequest {}),
        )
        .await?;
        let body = response.into_inner();
        Ok(AgentHealth {
            alive: body.alive,
            version: body.version,
        })
    }

    /// Broker readiness: can the broker actually serve? The broker probes every
    /// backend and catalog key (bounded by the connect timeout) and returns a
    /// non-secret summary: counts, a coarse reason, and the active generation id.
    /// Use this for a readiness/startup gate (systemd `ExecStartPost`, container
    /// `HEALTHCHECK`, k8s readiness probe).
    pub async fn readiness(&mut self) -> Result<AgentReadiness> {
        let response = Self::bounded(
            self.default_timeout,
            self.admin.readiness(pb::ReadinessRequest {}),
        )
        .await?;
        let body = response.into_inner();
        Ok(AgentReadiness {
            ready: body.ready,
            reason: ReadinessReason::from_proto(body.reason()),
            generation: body.generation,
            keys_total: body.keys_total,
            keys_present: body.keys_present,
            keys_required_missing: body.keys_required_missing,
            keys_optional_missing: body.keys_optional_missing,
        })
    }

    /// Trigger a permission-gated catalog/policy **hot reload** from disk
    /// (`basil-atq`). The broker re-reads the catalog/policy from its configured
    /// on-disk paths (never from the wire: this call carries no config), validates
    /// the candidate, and, unless `check`, atomically swaps in a new generation.
    ///
    /// `check = true` is a **dry-run**: it validates and reports the would-be
    /// outcome without swapping. The returned [`AgentReload`] carries the old → new
    /// generation ids and counts on success, or a [`ReloadRejection`] (with the
    /// previous generation still serving) on a validation/routing rejection. A
    /// caller lacking the `reload` permission gets an [`Error::Status`] with code
    /// `PermissionDenied` instead.
    pub async fn reload(&mut self, check: bool) -> Result<AgentReload> {
        let response = Self::bounded(
            self.default_timeout,
            self.admin.reload(pb::ReloadRequest { check }),
        )
        .await?;
        let body = response.into_inner();
        Ok(AgentReload {
            applied: body.applied,
            checked: body.checked,
            previous_generation: body.previous_generation,
            new_generation: body.new_generation,
            key_count: body.key_count,
            grant_count: body.grant_count,
            rejection: body.rejection.map(|r| ReloadRejection {
                reason: r.reason,
                message: r.message,
            }),
        })
    }

    /// Explain a policy decision against the broker's currently serving
    /// generation. This is a permission-gated admin RPC; the caller needs the
    /// dedicated `explain` permission over `broker.explain`.
    pub async fn explain(
        &mut self,
        subject: &str,
        op: &str,
        key: &str,
    ) -> Result<AgentExplanation> {
        let response = Self::bounded(
            self.default_timeout,
            self.admin.explain(pb::ExplainRequest {
                subject: subject.to_string(),
                op: op.to_string(),
                key: key.to_string(),
            }),
        )
        .await?;
        let body = response.into_inner();
        Ok(AgentExplanation {
            subject: body.subject,
            op: body.op,
            key: body.key,
            decision: body.decision,
            via: body.via,
            reason: body.reason,
            matched_rule: body.matched_rule.map(|m| MatchedRule {
                rule: m.rule,
                via: m.via,
                action: m.action,
                target: m.target,
                subject: m.subject,
            }),
        })
    }

    /// Revoke a JWT-SVID by trust-domain/`jti` tuple. This is a permission-gated
    /// admin RPC; the caller needs the dedicated `revoke` permission over
    /// `broker.revoke`, and the broker requires a configured persistent
    /// `revocation_store=jwt-svid` value key.
    pub async fn revoke(
        &mut self,
        trust_domain: &str,
        jti: &str,
        expires_at_unix: u64,
    ) -> Result<AgentRevocation> {
        let response = Self::bounded(
            self.default_timeout,
            self.admin.revoke(pb::RevokeRequest {
                trust_domain: trust_domain.to_string(),
                jti: jti.to_string(),
                expires_at_unix,
            }),
        )
        .await?;
        let body = response.into_inner();
        Ok(AgentRevocation {
            trust_domain: body.trust_domain,
            jti: body.jti,
            expires_at_unix: body.expires_at_unix,
            persisted: body.persisted,
        })
    }
}

async fn uds_channel(path: &str, timeout_secs: u64) -> Result<Channel> {
    let path = path.to_string();
    let endpoint =
        Endpoint::try_from("http://[::]:50051")?.connect_timeout(Duration::from_secs(timeout_secs));
    endpoint
        .connect_with_connector(service_fn(move |_: Uri| {
            let path = path.clone();
            async move {
                UnixStream::connect(path)
                    .await
                    .map(TokioIo::new)
                    .inspect_err(|e| error!(?e, "unix socket connect failed"))
            }
        }))
        .await
        .map_err(Error::Endpoint)
}

fn status_error(status: &Status) -> Error {
    let (reason, op) = broker_error_info(status).unwrap_or_else(|| (String::new(), String::new()));
    Error::Status {
        code: status.code(),
        reason,
        op,
        message: status.message().to_string(),
    }
}

fn broker_error_info(status: &Status) -> Option<(String, String)> {
    let rpc_status = basil_proto::google::rpc::Status::decode(status.details()).ok()?;
    rpc_status.details.into_iter().find_map(|detail| {
        if detail.type_url == "type.googleapis.com/basil.broker.v1.BrokerErrorInfo" {
            pb::BrokerErrorInfo::decode(detail.value.as_slice())
                .ok()
                .map(|info| (info.reason, info.op))
        } else {
            None
        }
    })
}

fn missing_field(op: &'static str, field: &'static str) -> Error {
    Error::Status {
        code: tonic::Code::Internal,
        reason: "MISSING_FIELD".to_string(),
        op: op.to_string(),
        message: format!("broker response omitted {field}"),
    }
}

fn proto_key_type(value: KeyType) -> i32 {
    match value {
        KeyType::Ed25519 => pb::KeyType::Ed25519,
        KeyType::Ed25519Nkey => pb::KeyType::Ed25519Nkey,
        KeyType::Rsa2048 => pb::KeyType::Rsa2048,
        KeyType::EcdsaP256 => pb::KeyType::EcdsaP256,
        KeyType::EcdsaP384 => pb::KeyType::EcdsaP384,
        KeyType::EcdsaP521 => pb::KeyType::EcdsaP521,
        KeyType::MlDsa44 => pb::KeyType::MlDsa44,
        KeyType::MlDsa65 => pb::KeyType::MlDsa65,
        KeyType::MlDsa87 => pb::KeyType::MlDsa87,
        KeyType::MlKem512 => pb::KeyType::MlKem512,
        KeyType::MlKem768 => pb::KeyType::MlKem768,
        KeyType::MlKem1024 => pb::KeyType::MlKem1024,
    }
    .into()
}

fn proto_aead_algorithm(value: AeadAlgorithm) -> i32 {
    match value {
        AeadAlgorithm::Chacha20Poly1305 => pb::AeadAlgorithm::Chacha20Poly1305,
        AeadAlgorithm::Aes256Gcm => pb::AeadAlgorithm::Aes256Gcm,
    }
    .into()
}

fn basil_aead_algorithm(value: i32) -> AeadAlgorithm {
    match pb::AeadAlgorithm::try_from(value).unwrap_or(pb::AeadAlgorithm::Aes256Gcm) {
        pb::AeadAlgorithm::Chacha20Poly1305 => AeadAlgorithm::Chacha20Poly1305,
        pb::AeadAlgorithm::Unspecified | pb::AeadAlgorithm::Aes256Gcm => AeadAlgorithm::Aes256Gcm,
    }
}

fn proto_key_material(value: KeyMaterial) -> pb::KeyMaterial {
    let material = match value {
        KeyMaterial::Ed25519Seed(seed) => pb::key_material::Material::Ed25519Seed(seed),
        KeyMaterial::Pkcs8Der(der) => pb::key_material::Material::Pkcs8Der(der),
    };
    pb::KeyMaterial {
        material: Some(material),
    }
}

fn proto_ciphertext_envelope(value: CiphertextEnvelope) -> pb::CiphertextEnvelope {
    pb::CiphertextEnvelope {
        alg: proto_aead_algorithm(value.alg),
        key_version: value.key_version,
        nonce: value.nonce,
        ciphertext: value.ciphertext,
    }
}

fn basil_ciphertext_envelope(value: pb::CiphertextEnvelope) -> CiphertextEnvelope {
    CiphertextEnvelope {
        alg: basil_aead_algorithm(value.alg),
        key_version: value.key_version,
        nonce: value.nonce,
        ciphertext: value.ciphertext,
    }
}

fn proto_duration(secs: u64) -> ProtoDuration {
    ProtoDuration {
        seconds: i64::try_from(secs).unwrap_or(i64::MAX),
        nanos: 0,
    }
}

fn proto_timestamp(secs: u64) -> Timestamp {
    Timestamp {
        seconds: i64::try_from(secs).unwrap_or(i64::MAX),
        nanos: 0,
    }
}

fn timestamp_secs(value: Timestamp) -> u64 {
    u64::try_from(value.seconds).unwrap_or(0)
}

fn non_empty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

fn non_zero(value: u64) -> Option<u64> {
    (value != 0).then_some(value)
}

fn json_struct(value: serde_json::Value) -> Struct {
    let serde_json::Value::Object(fields) = value else {
        return Struct::default();
    };
    Struct {
        fields: fields
            .into_iter()
            .map(|(key, value)| (key, json_value(value)))
            .collect(),
    }
}

fn json_value(value: serde_json::Value) -> ProtoValue {
    let kind = match value {
        serde_json::Value::Null => prost_types::value::Kind::NullValue(0),
        serde_json::Value::Bool(value) => prost_types::value::Kind::BoolValue(value),
        serde_json::Value::Number(value) => {
            prost_types::value::Kind::NumberValue(value.as_f64().unwrap_or(0.0))
        }
        serde_json::Value::String(value) => prost_types::value::Kind::StringValue(value),
        serde_json::Value::Array(values) => {
            prost_types::value::Kind::ListValue(prost_types::ListValue {
                values: values.into_iter().map(json_value).collect(),
            })
        }
        serde_json::Value::Object(_) => prost_types::value::Kind::StructValue(json_struct(value)),
    };
    ProtoValue { kind: Some(kind) }
}

#[cfg(test)]
mod nats_client_tests {
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    use tokio::net::UnixListener;
    use tokio::sync::oneshot;
    use tokio_stream::wrappers::UnixListenerStream;
    use tonic::transport::Server;
    use tonic::{Request, Response, Status};

    use super::*;
    use basil_proto::broker::v1::nats_service_server::{NatsService, NatsServiceServer};

    #[derive(Clone, Default)]
    struct FakeNatsService {
        last_sign: Arc<Mutex<Option<pb::SignNatsJwtRequest>>>,
        last_validate: Arc<Mutex<Option<pb::ValidateNatsJwtRequest>>>,
    }

    #[tonic::async_trait]
    impl NatsService for FakeNatsService {
        async fn mint_nats_user(
            &self,
            _request: Request<pb::MintNatsUserRequest>,
        ) -> std::result::Result<Response<pb::CredentialResponse>, Status> {
            Err(Status::unimplemented("mint_nats_user"))
        }

        async fn mint_nats_account(
            &self,
            _request: Request<pb::MintNatsAccountRequest>,
        ) -> std::result::Result<Response<pb::CredentialResponse>, Status> {
            Err(Status::unimplemented("mint_nats_account"))
        }

        async fn mint_nats_operator(
            &self,
            _request: Request<pb::MintNatsOperatorRequest>,
        ) -> std::result::Result<Response<pb::CredentialResponse>, Status> {
            Err(Status::unimplemented("mint_nats_operator"))
        }

        async fn mint_nats_signer(
            &self,
            _request: Request<pb::MintNatsSignerRequest>,
        ) -> std::result::Result<Response<pb::CredentialResponse>, Status> {
            Err(Status::unimplemented("mint_nats_signer"))
        }

        async fn mint_nats_server(
            &self,
            _request: Request<pb::MintNatsServerRequest>,
        ) -> std::result::Result<Response<pb::CredentialResponse>, Status> {
            Err(Status::unimplemented("mint_nats_server"))
        }

        async fn mint_nats_curve(
            &self,
            _request: Request<pb::MintNatsCurveRequest>,
        ) -> std::result::Result<Response<pb::CredentialResponse>, Status> {
            Err(Status::unimplemented("mint_nats_curve"))
        }

        async fn encrypt_nats_curve(
            &self,
            _request: Request<pb::EncryptNatsCurveRequest>,
        ) -> std::result::Result<Response<pb::EncryptNatsCurveResponse>, Status> {
            Err(Status::unimplemented("encrypt_nats_curve"))
        }

        async fn decrypt_nats_curve(
            &self,
            _request: Request<pb::DecryptNatsCurveRequest>,
        ) -> std::result::Result<Response<pb::DecryptNatsCurveResponse>, Status> {
            Err(Status::unimplemented("decrypt_nats_curve"))
        }

        async fn sign_nats_jwt(
            &self,
            request: Request<pb::SignNatsJwtRequest>,
        ) -> std::result::Result<Response<pb::CredentialResponse>, Status> {
            *self.last_sign.lock().expect("request lock") = Some(request.into_inner());
            Ok(Response::new(pb::CredentialResponse {
                token: "nats.jwt".to_string(),
                expires_at: None,
            }))
        }

        async fn validate_nats_jwt(
            &self,
            request: Request<pb::ValidateNatsJwtRequest>,
        ) -> std::result::Result<Response<pb::ValidateNatsJwtResponse>, Status> {
            *self.last_validate.lock().expect("request lock") = Some(request.into_inner());
            Ok(Response::new(pb::ValidateNatsJwtResponse {
                valid: true,
                reason: pb::NatsJwtValidationReason::Valid.into(),
                subject: "UDVCJ4FZLS".to_string(),
                issuer: "ADVCJ4FZLS".to_string(),
                matched_signer_key_id: "issuer.account".to_string(),
                jwt_type: pb::NatsJwtType::User.into(),
                expires_at_unix: 42,
                issued_at_unix: 7,
            }))
        }
    }

    #[tokio::test]
    async fn sign_nats_jwt_sends_raw_json_claims() {
        let service = FakeNatsService::default();
        let last_sign = Arc::clone(&service.last_sign);
        let path = unique_socket_path();
        let listener = UnixListener::bind(&path).expect("bind unix socket");
        let incoming = UnixListenerStream::new(listener);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            Server::builder()
                .add_service(NatsServiceServer::new(service))
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let claims = serde_json::json!({
            "sub": "UABC",
            "iat": 9_007_199_254_740_993_u64,
            "nats": { "type": "user", "version": 2 }
        });
        let response = {
            let mut client = Client::connect(path.to_str().expect("socket path"))
                .await
                .expect("connect");
            client
                .sign_nats_jwt(
                    "issuer.account",
                    claims,
                    SignNatsJwtOptions {
                        expected_type: Some(pb::NatsJwtType::User),
                        rewrite_jti: true,
                        ..SignNatsJwtOptions::default()
                    },
                )
                .await
                .expect("sign")
        };

        assert_eq!(response.token, "nats.jwt");
        let request = last_sign
            .lock()
            .expect("request lock")
            .clone()
            .expect("sign request");
        assert_eq!(request.key_id, "issuer.account");
        assert_eq!(request.expected_type, i32::from(pb::NatsJwtType::User));
        assert_eq!(request.jti_mode, i32::from(pb::NatsJtiMode::Rewrite));
        let claims: serde_json::Value =
            serde_json::from_slice(&request.claims_json).expect("claims json");
        assert_eq!(claims["iat"], 9_007_199_254_740_993_u64);

        shutdown_tx.send(()).expect("shutdown server");
        server.await.expect("join server").expect("server");
        std::fs::remove_file(path).expect("remove socket");
    }

    #[tokio::test]
    async fn sign_nats_jwt_json_sends_preencoded_claim_bytes() {
        let service = FakeNatsService::default();
        let last_sign = Arc::clone(&service.last_sign);
        let path = unique_socket_path();
        let listener = UnixListener::bind(&path).expect("bind unix socket");
        let incoming = UnixListenerStream::new(listener);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            Server::builder()
                .add_service(NatsServiceServer::new(service))
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let claims_json =
            br#"{"sub":"UABC","iat":9007199254740993,"nats":{"type":"user","version":2}}"#;
        let response = {
            let mut client = Client::connect(path.to_str().expect("socket path"))
                .await
                .expect("connect");
            client
                .sign_nats_jwt_json(
                    "issuer.account",
                    claims_json.to_vec(),
                    SignNatsJwtOptions {
                        expected_type: Some(pb::NatsJwtType::User),
                        ..SignNatsJwtOptions::default()
                    },
                )
                .await
                .expect("sign")
        };

        assert_eq!(response.token, "nats.jwt");
        let request = last_sign
            .lock()
            .expect("request lock")
            .clone()
            .expect("sign request");
        assert_eq!(request.claims_json, claims_json);
        assert_eq!(request.expected_type, i32::from(pb::NatsJwtType::User));

        shutdown_tx.send(()).expect("shutdown server");
        server.await.expect("join server").expect("server");
        std::fs::remove_file(path).expect("remove socket");
    }

    #[tokio::test]
    async fn validate_nats_jwt_builds_request_and_maps_response() {
        let service = FakeNatsService::default();
        let last_validate = Arc::clone(&service.last_validate);
        let path = unique_socket_path();
        let listener = UnixListener::bind(&path).expect("bind unix socket");
        let incoming = UnixListenerStream::new(listener);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            Server::builder()
                .add_service(NatsServiceServer::new(service))
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let response = {
            let mut client = Client::connect(path.to_str().expect("socket path"))
                .await
                .expect("connect");
            client
                .validate_nats_jwt(
                    "header.body.sig",
                    [
                        AllowedNatsSigner::key_id("issuer.account"),
                        AllowedNatsSigner::nats_public_key("ADVCJ4FZLS"),
                    ],
                    Some(pb::NatsJwtType::User),
                )
                .await
                .expect("validate")
        };

        assert!(response.valid);
        assert_eq!(response.reason, NatsJwtValidationReason::Valid);
        assert_eq!(response.subject, "UDVCJ4FZLS");
        assert_eq!(response.issuer, "ADVCJ4FZLS");
        assert_eq!(
            response.matched_signer_key_id.as_deref(),
            Some("issuer.account")
        );
        assert_eq!(response.jwt_type, pb::NatsJwtType::User);
        assert_eq!(response.expires_at, Some(42));
        assert_eq!(response.issued_at, Some(7));

        let request = last_validate
            .lock()
            .expect("request lock")
            .clone()
            .expect("validate request");
        assert_eq!(request.jwt, "header.body.sig");
        assert_eq!(request.expected_type, i32::from(pb::NatsJwtType::User));
        assert_eq!(
            request.allowed_signers[0].signer,
            Some(pb::allowed_nats_signer::Signer::KeyId(
                "issuer.account".to_string()
            ))
        );
        assert_eq!(
            request.allowed_signers[1].signer,
            Some(pb::allowed_nats_signer::Signer::NatsPublicKey(
                "ADVCJ4FZLS".to_string()
            ))
        );

        shutdown_tx.send(()).expect("shutdown server");
        server.await.expect("join server").expect("server");
        std::fs::remove_file(path).expect("remove socket");
    }

    fn unique_socket_path() -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!("basil-client-{nanos}.sock"))
    }
}

#[cfg(test)]
mod tests {
    use super::{broker_error_info, json_struct, status_error};
    use basil_proto::broker::v1::BrokerErrorInfo;
    use prost::Message;
    use tonic::Code;

    #[test]
    fn status_error_extracts_broker_reason() {
        let info = BrokerErrorInfo {
            reason: "UNAUTHORIZED".into(),
            op: "sign".into(),
        };
        let detail = prost_types::Any {
            type_url: "type.googleapis.com/basil.broker.v1.BrokerErrorInfo".into(),
            value: info.encode_to_vec(),
        };
        let rpc_status = basil_proto::google::rpc::Status {
            code: Code::PermissionDenied as i32,
            message: "not authorized".into(),
            details: vec![detail],
        };
        let status = tonic::Status::with_details(
            Code::PermissionDenied,
            "not authorized",
            rpc_status.encode_to_vec().into(),
        );

        assert_eq!(
            broker_error_info(&status),
            Some(("UNAUTHORIZED".into(), "sign".into()))
        );
        let error = status_error(&status);
        match error {
            crate::Error::Status {
                code, reason, op, ..
            } => {
                assert_eq!(code, Code::PermissionDenied);
                assert_eq!(reason, "UNAUTHORIZED");
                assert_eq!(op, "sign");
            }
            other => assert!(matches!(
                other,
                crate::Error::Status {
                    code: Code::PermissionDenied,
                    ..
                }
            )),
        }
    }

    #[test]
    fn json_struct_ignores_non_object_root() {
        assert!(
            json_struct(serde_json::json!("not-an-object"))
                .fields
                .is_empty()
        );
    }

    #[test]
    fn proto_key_type_maps_post_quantum_families() {
        use super::proto_key_type;
        use crate::proto::KeyType;
        use basil_proto::broker::v1 as pb;

        // Classical and post-quantum types alike round-trip to the wire enum, so
        // a client can name an ML-DSA signing or ML-KEM sealing key in `new_key`.
        for (domain, wire) in [
            (KeyType::Ed25519, pb::KeyType::Ed25519),
            (KeyType::MlDsa44, pb::KeyType::MlDsa44),
            (KeyType::MlDsa65, pb::KeyType::MlDsa65),
            (KeyType::MlDsa87, pb::KeyType::MlDsa87),
            (KeyType::MlKem512, pb::KeyType::MlKem512),
            (KeyType::MlKem768, pb::KeyType::MlKem768),
            (KeyType::MlKem1024, pb::KeyType::MlKem1024),
        ] {
            assert_eq!(proto_key_type(domain), wire as i32);
        }
    }
}
