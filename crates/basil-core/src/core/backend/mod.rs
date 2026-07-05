//! Pluggable signing / key-store backends.
//!
//! The agent is a *proxy*: incoming `NEW_KEY` / `SIGN` / `VERIFY` messages are
//! dispatched to a [`Backend`] trait object. v1 ships a single implementation,
//! [`vault::VaultBackend`] (a Vault-compatible transit engine: `HashiCorp` Vault or `OpenBao`),
//! but the trait is deliberately backend-agnostic so additional stores
//! (db-keystore, 1Password, cloud KMS, an internal TPM-backed signer, …) can be
//! added later without touching the protocol or the connection handler.

use async_trait::async_trait;
use basil_proto::{AeadAlgorithm, CiphertextEnvelope, KeyMaterial, KeyType};
use zeroize::Zeroizing;

#[cfg(feature = "aws-kms")]
pub mod aws_kms;
#[cfg(feature = "gcp-kms")]
pub mod gcp_kms;
#[cfg(feature = "keystore-backend")]
pub mod keystore;
pub mod spiffe;
pub mod vault;

mod kms_common;
mod pki;
mod svid;
mod transit;

/// A newly created (or imported) key.
#[derive(Debug, Clone)]
pub struct NewKey {
    /// Backend-assigned identifier for the key.
    pub key_id: String,
    /// Raw public key bytes (for Ed25519, the 32-byte public key).
    pub public_key: Vec<u8>,
}

/// A KV-v2 value read: the stored bytes plus the version they came from.
///
/// Returned by [`Backend::kv_get`] for a `value`/`public`-class key. The `value`
/// is the opaque byte string the broker stored under the `value` field (the
/// lossless round-trip half of [`Backend::kv_put`]); `version` is the KV-v2
/// version actually read (the requested one, or the latest when none was asked).
#[derive(Debug, Clone)]
pub struct KvValue {
    /// The raw stored value bytes (never key-crypto material).
    pub value: Vec<u8>,
    /// The KV-v2 version these bytes were read from.
    pub version: u32,
}

/// A post-quantum algorithm a [`Backend`] may natively custody and operate on
/// **in place**: the private seed never leaves the backend.
///
/// This is the type the capability probe ([`Backend::supports_native_algorithm`])
/// and the native PQC operation methods speak. It lives in the backend layer (not
/// the provider layer) so the [`Backend`] trait carries no dependency on
/// [`crypto_provider`](crate::core::crypto_provider): the provider layer maps its
/// `SignatureAlgorithm` onto this enum, never the reverse. Only the ML-DSA family
/// is modelled today: no shipping backend exposes native ML-KEM transit, so
/// ML-KEM keys always remain software-custodied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeAlgorithm {
    /// ML-DSA (FIPS 204) signature parameter level 44.
    MlDsa44,
    /// ML-DSA (FIPS 204) signature parameter level 65.
    MlDsa65,
    /// ML-DSA (FIPS 204) signature parameter level 87.
    MlDsa87,
}

/// A key's public material plus the metadata `get_public_key` echoes back.
///
/// This is what a `get_public_key` reply needs beyond the raw bytes: the real
/// algorithm and the current key version (so the handler no longer hardcodes
/// `ed25519` / `version 1`, the `vault-k3w` OFI).
#[derive(Debug, Clone)]
pub struct PublicKey {
    /// Raw public key bytes (for Ed25519, the 32-byte public key).
    pub public_key: Vec<u8>,
    /// The key's algorithm, as the wire reports it.
    pub key_type: KeyType,
    /// The latest key version (transit version count).
    pub version: u32,
}

/// Value-free metadata for one key, returned by `list`.
///
/// Leak-proof: the algorithm and a version *count* only, never the public or
/// private key bytes (use `get_public_key` for the public half explicitly).
#[derive(Debug, Clone)]
pub struct KeyMetadata {
    /// The key's algorithm, if the backend reports one.
    pub key_type: Option<KeyType>,
    /// The latest key version (transit version count).
    pub latest_version: u32,
}

/// Backend signing mode for operations whose wire format fixes an algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SignOptions {
    /// Backend default signing behavior.
    #[default]
    Default,
    /// JWS `RS256`: RSASSA-PKCS1-v1_5 over SHA-256.
    Rs256Pkcs1v15Sha256,
    /// JWS `ES256`: ECDSA P-256 over SHA-256.
    Es256,
    /// JWS `ES384`: ECDSA P-384 over SHA-384.
    Es384,
    /// JWS `ES512`: ECDSA P-521 over SHA-512.
    Es512,
}

/// An issued X.509-SVID leaf set from a PKI backend.
#[derive(Debug, Clone)]
pub struct X509Svid {
    /// DER-encoded leaf certificate followed by any issuer certificates.
    pub cert_chain_der: Vec<Vec<u8>>,
    /// DER-encoded unencrypted PKCS#8 leaf private key.
    pub leaf_private_key_der: Zeroizing<Vec<u8>>,
    /// DER-encoded trust-domain bundle certificates.
    pub bundle_der: Vec<Vec<u8>>,
}

/// Parameters for a DNS/IP-SAN X.509 leaf issuance (a TLS cert, not a SPIFFE
/// SVID). Mirrors [`Backend::issue_x509_svid`] but binds DNS/IP SANs and a common
/// name instead of a SPIFFE URI SAN.
#[derive(Debug, Clone, Default)]
pub struct X509CertRequest {
    /// Certificate common name (and implicit first DNS SAN, per the PKI role).
    pub common_name: String,
    /// Additional DNS subject alternative names.
    pub dns_sans: Vec<String>,
    /// IP subject alternative names.
    pub ip_sans: Vec<String>,
    /// Requested validity in seconds.
    pub ttl_seconds: u64,
}

/// Trust-domain X.509 bundle material, ready for Workload API response assembly.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct X509Bundle {
    /// DER-encoded trust-domain CA certificates.
    pub bundle_der: Vec<Vec<u8>>,
    /// DER-encoded CRL bytes, empty when the backend has no CRL to publish.
    pub crl_der: Vec<u8>,
}

/// Errors a backend may return. Service adapters map these to canonical gRPC
/// statuses.
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("unsupported key type: {0}")]
    UnsupportedKeyType(KeyType),

    #[error("key not found: {0}")]
    KeyNotFound(String),

    /// The op (e.g. `import`/`list`/`key_metadata`) is not supported by this
    /// backend kind. Distinct from [`BackendError::UnsupportedKeyType`]: the
    /// *operation* itself has no implementation here.
    #[error("operation not supported by this backend: {0}")]
    Unsupported(&'static str),

    /// AEAD authentication failed on `decrypt`: a wrong tag, a wrong key
    /// version, or mismatched AAD. Deliberately **opaque**: it carries no detail
    /// distinguishing the cause (no padding/AAD oracle), and the handler maps it
    /// to the single `decrypt_failed` wire code.
    #[error("decrypt failed")]
    DecryptFailed,

    /// The request's algorithm does not match the key's catalog `keyType`
    /// (e.g. a `chacha20-poly1305` request against an `aes-256-gcm` key), or the
    /// AEAD suite is otherwise not usable for this key. Maps to the wire
    /// `unsupported_algorithm` / `invalid_request` per the call site.
    #[error("unsupported AEAD algorithm: {0}")]
    UnsupportedAlgorithm(AeadAlgorithm),

    /// Transport / HTTP failure talking to the backend.
    #[error("backend transport error: {0}")]
    Transport(String),

    /// The backend was reachable but rejected or failed the operation.
    #[error("backend error: {0}")]
    Backend(String),

    /// A response from the backend could not be understood.
    #[error("malformed backend response: {0}")]
    Protocol(String),
}

/// A pluggable key-store + signing backend.
///
/// Implementations must be cheap to share across connections (the agent holds
/// a single `Arc<dyn Backend>` and clones it into every spawned handler).
#[async_trait]
pub trait Backend: Send + Sync {
    /// Short, stable name for this backend (e.g. `"vault"`), used in `STATUS`.
    fn kind(&self) -> &'static str;

    /// `NEW_KEY` creates a new key of `key_type` and returns its id + public key.
    async fn new_key(&self, key_type: KeyType) -> Result<NewKey, BackendError>;

    /// Create an **asymmetric** crypto key at a **named path** (`key_id` = the
    /// catalog transit key name) rather than the server-assigned id [`new_key`]
    /// uses. This is the startup-reconcile (`vault-zrg`) `generate` path: the key
    /// must exist at the exact catalog `path` so a later `sign`/`get_public_key`
    /// resolves to it.
    ///
    /// The default returns [`BackendError::Unsupported`]; [`vault`] overrides it.
    async fn create_named_key(
        &self,
        key_id: &str,
        key_type: KeyType,
    ) -> Result<NewKey, BackendError> {
        let _ = (key_id, key_type);
        Err(BackendError::Unsupported("create_named_key"))
    }

    /// Create a **symmetric AEAD** crypto key at a **named path**. AEAD suites are
    /// not wire [`KeyType`]s, so the reconcile `generate` path passes `aead`, the
    /// catalog algorithm. There is no public half to return; `Ok(())` means the
    /// key now exists at `key_id`.
    ///
    /// The default returns [`BackendError::Unsupported`]; [`vault`] overrides it.
    async fn create_named_aead(
        &self,
        key_id: &str,
        aead: AeadAlgorithm,
    ) -> Result<(), BackendError> {
        let _ = (key_id, aead);
        Err(BackendError::Unsupported("create_named_aead"))
    }

    /// Read the raw public key bytes for `key_id` (for Ed25519, 32 bytes).
    /// Used by credential minters (e.g. to derive a NATS issuer `NKey`).
    async fn public_key(&self, key_id: &str) -> Result<Vec<u8>, BackendError>;

    /// `GET_PUBLIC_KEY`: read the public half **plus** its metadata (algorithm +
    /// current version) for `key_id`.
    ///
    /// The default returns [`BackendError::Unsupported`] so a backend that only
    /// signs need not implement metadata; [`vault`] overrides it.
    async fn public_key_with_meta(&self, key_id: &str) -> Result<PublicKey, BackendError> {
        let _ = key_id;
        Err(BackendError::Unsupported("get_public_key"))
    }

    /// Read value-free metadata (algorithm + latest version) for `key_id`.
    /// Used by `list` to populate each [`basil_proto::KeyEntry`] without
    /// ever reading key material.
    ///
    /// The default returns [`BackendError::Unsupported`]; [`vault`] overrides it.
    async fn key_metadata(&self, key_id: &str) -> Result<KeyMetadata, BackendError> {
        let _ = key_id;
        Err(BackendError::Unsupported("list"))
    }

    /// Read **every live version's public key** for `key_id`, keyed by version
    /// number. For a transit key this is the `data.keys` map, each archived (and
    /// the latest) version's public half, which is the natural multi-version
    /// source for a rotation/grace-aware JWKS (`basil-uce.2`): the shared
    /// generator emits one JWK per version still inside the grace window.
    ///
    /// **Public material only**, never any private/secret bytes (the same
    /// guarantee as [`Backend::public_key`]). The default degrades safely to the
    /// single latest version (so non-transit backends that only know "the current
    /// public key" still publish a valid one-key set); [`vault`]/[`spiffe`]
    /// override it to return the whole version map.
    async fn public_keys(
        &self,
        key_id: &str,
    ) -> Result<std::collections::BTreeMap<u32, Vec<u8>>, BackendError> {
        // Fall back to the single latest public key. Probe `key_metadata` for the
        // version, but a backend that does not implement it (only signs) still
        // reports a valid set at version 1 rather than failing closed.
        let version = match self.key_metadata(key_id).await {
            Ok(meta) => meta.latest_version,
            Err(BackendError::Unsupported(_)) => 1,
            Err(e) => return Err(e),
        };
        let public = self.public_key(key_id).await?;
        Ok(std::collections::BTreeMap::from([(version, public)]))
    }

    /// `IMPORT` (BYOK) creates the key `key_id` from caller-supplied `material`.
    ///
    /// Write-only: the private material is consumed to provision the key and the
    /// reply carries only the public half (never the seed/private bytes). The
    /// material variant must agree with `key_type`.
    ///
    /// The default returns [`BackendError::Unsupported`]; [`vault`] overrides it.
    async fn import(
        &self,
        key_id: &str,
        key_type: KeyType,
        material: &KeyMaterial,
    ) -> Result<NewKey, BackendError> {
        let _ = (key_id, key_type, material);
        Err(BackendError::Unsupported("import"))
    }

    /// `SIGN` signs `message` with `key_id`, returning the raw signature bytes.
    ///
    /// For Ed25519 / ed25519-nkey keys the argument is the **raw message**, signed
    /// directly (`EdDSA` is not pre-hashed): the backend MUST NOT pre-hash it. This is
    /// what lets a NATS client hand Basil the server-issued nonce verbatim and use
    /// the returned signature as its connect response (an `async-nats` remote-signer
    /// callback), so the user seed never leaves the vault.
    async fn sign(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, BackendError>;

    /// `SIGN` with backend-specific algorithm options.
    ///
    /// The default mode preserves the normal [`Backend::sign`] behavior. Non-
    /// default modes fail closed unless a backend explicitly implements them.
    async fn sign_with_options(
        &self,
        key_id: &str,
        message: &[u8],
        options: SignOptions,
    ) -> Result<Vec<u8>, BackendError> {
        match options {
            SignOptions::Default => self.sign(key_id, message).await,
            SignOptions::Rs256Pkcs1v15Sha256 => {
                let _ = (key_id, message);
                Err(BackendError::Unsupported("sign rs256_pkcs1v15_sha256"))
            }
            SignOptions::Es256 => {
                let _ = (key_id, message);
                Err(BackendError::Unsupported("sign es256"))
            }
            SignOptions::Es384 => {
                let _ = (key_id, message);
                Err(BackendError::Unsupported("sign es384"))
            }
            SignOptions::Es512 => {
                let _ = (key_id, message);
                Err(BackendError::Unsupported("sign es512"))
            }
        }
    }

    /// `VERIFY` verifies `signature` over `message` with `key_id`.
    async fn verify(
        &self,
        key_id: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, BackendError>;

    /// `VERIFY` with backend-specific algorithm options.
    ///
    /// The default mode preserves the normal [`Backend::verify`] behavior. Non-
    /// default modes fail closed unless a backend explicitly implements them.
    async fn verify_with_options(
        &self,
        key_id: &str,
        message: &[u8],
        signature: &[u8],
        options: SignOptions,
    ) -> Result<bool, BackendError> {
        match options {
            SignOptions::Default => self.verify(key_id, message, signature).await,
            SignOptions::Rs256Pkcs1v15Sha256 => {
                let _ = (key_id, message, signature);
                Err(BackendError::Unsupported("verify rs256_pkcs1v15_sha256"))
            }
            SignOptions::Es256 => {
                let _ = (key_id, message, signature);
                Err(BackendError::Unsupported("verify es256"))
            }
            SignOptions::Es384 => {
                let _ = (key_id, message, signature);
                Err(BackendError::Unsupported("verify es384"))
            }
            SignOptions::Es512 => {
                let _ = (key_id, message, signature);
                Err(BackendError::Unsupported("verify es512"))
            }
        }
    }

    /// Whether this backend can perform `algorithm` **natively in place**:
    /// custody the private key inside the backend and run the operation without
    /// ever materializing the seed locally.
    ///
    /// This is the capability probe behind the `backend-preferred` /
    /// `backend-required` provider policy (`basil-wuj.10`). It is **cheap,
    /// synchronous, and fails closed**: the default, and any backend that does
    /// not override it (every shipping Vault/OpenBao transit engine today, none
    /// of which has ML-DSA transit), returns `false`, so an unknown or
    /// unsupported capability never routes key material to a backend that cannot
    /// custody it. A backend that returns `true` here MUST implement the matching
    /// native operation methods ([`Self::sign_pqc`], [`Self::verify_pqc`],
    /// [`Self::create_named_pqc_key`]).
    fn supports_native_algorithm(&self, algorithm: NativeAlgorithm) -> bool {
        let _ = algorithm;
        false
    }

    /// Provision a new **backend-native** ML-DSA key at the named `key_id`,
    /// returning only its public half. The private seed is generated and kept
    /// inside the backend and is never returned. Invoked by the backend-native
    /// crypto provider when [`Self::supports_native_algorithm`] reports support.
    ///
    /// The default returns [`BackendError::Unsupported`]; a backend with native
    /// ML-DSA transit overrides it.
    async fn create_named_pqc_key(
        &self,
        key_id: &str,
        algorithm: NativeAlgorithm,
    ) -> Result<NewKey, BackendError> {
        let _ = (key_id, algorithm);
        Err(BackendError::Unsupported("create_named_pqc_key"))
    }

    /// `SIGN` `message` with a **backend-native** ML-DSA key, returning the raw
    /// signature bytes. The private seed never leaves the backend.
    ///
    /// The default returns [`BackendError::Unsupported`]; a backend with native
    /// ML-DSA transit overrides it.
    async fn sign_pqc(
        &self,
        key_id: &str,
        message: &[u8],
        algorithm: NativeAlgorithm,
    ) -> Result<Vec<u8>, BackendError> {
        let _ = (key_id, message, algorithm);
        Err(BackendError::Unsupported("sign_pqc"))
    }

    /// `VERIFY` `signature` over `message` with a **backend-native** ML-DSA key,
    /// using only the public half.
    ///
    /// The default returns [`BackendError::Unsupported`]; a backend with native
    /// ML-DSA transit overrides it.
    async fn verify_pqc(
        &self,
        key_id: &str,
        message: &[u8],
        signature: &[u8],
        algorithm: NativeAlgorithm,
    ) -> Result<bool, BackendError> {
        let _ = (key_id, message, signature, algorithm);
        Err(BackendError::Unsupported("verify_pqc"))
    }

    /// `ENCRYPT`: AEAD-encrypt `plaintext` under `key_id`'s **latest** version,
    /// binding `aad` if present, and return a normalized [`CiphertextEnvelope`].
    ///
    /// The broker **never** takes a caller nonce: the backend (transit) generates
    /// a fresh nonce per call. `algorithm` must match the key's catalog `keyType`
    /// (the manager enforces that before dispatch); the envelope echoes it.
    ///
    /// The default returns [`BackendError::Unsupported`]; [`transit`] overrides it.
    async fn encrypt(
        &self,
        key_id: &str,
        algorithm: AeadAlgorithm,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<CiphertextEnvelope, BackendError> {
        let _ = (key_id, algorithm, plaintext, aad);
        Err(BackendError::Unsupported("encrypt"))
    }

    /// `DECRYPT`: AEAD-decrypt `envelope` under `key_id`, binding `aad` if
    /// present, and return the recovered plaintext.
    ///
    /// The envelope's `key_version` targets the version that produced it (so a
    /// ciphertext made before a rotation still decrypts during the grace window).
    /// A tag/AAD/version mismatch is [`BackendError::DecryptFailed`]: opaque, no
    /// oracle.
    ///
    /// The default returns [`BackendError::Unsupported`]; [`transit`] overrides it.
    async fn decrypt(
        &self,
        key_id: &str,
        envelope: &CiphertextEnvelope,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, BackendError> {
        let _ = (key_id, envelope, aad);
        Err(BackendError::Unsupported("decrypt"))
    }

    /// `ROTATE`: bump `key_id` to a fresh **transit key version**, returning the
    /// new (now-latest) version number. New encrypt/sign always uses the newest
    /// version; older versions remain decryptable/verifiable within the grace
    /// window (see [`Backend::configure_versions`]).
    ///
    /// The default returns [`BackendError::Unsupported`]; [`transit`] overrides it.
    async fn rotate(&self, key_id: &str) -> Result<u32, BackendError> {
        let _ = key_id;
        Err(BackendError::Unsupported("rotate"))
    }

    /// Read a **KV-v2 value** for `key_id`: the stored bytes plus the version they
    /// came from. `version = None` reads the latest version; `Some(v)` reads that
    /// specific version. This is the residual value-returning `get` path (§7) and
    /// is only ever routed to a `value`/`public`-class key by the manager. It
    /// **never** reads transit (crypto-key) material.
    ///
    /// The default returns [`BackendError::Unsupported`]; [`transit`] overrides it.
    async fn kv_get(&self, key_id: &str, version: Option<u32>) -> Result<KvValue, BackendError> {
        let _ = (key_id, version);
        Err(BackendError::Unsupported("get"))
    }

    /// Read a **KV-v2 value as a SECRET**: the stored bytes wrapped in
    /// [`Zeroizing`] end-to-end, never landing in a non-zeroizing owner that drops
    /// un-wiped. Distinct from [`Backend::kv_get`], which returns a plain
    /// [`KvValue`] for value/public reads, this path is used **only** by the
    /// sealing materialize (`materialize_sealing_private`), where the bytes are an
    /// X25519 private key. The returned buffer wipes on drop.
    ///
    /// The default returns [`BackendError::Unsupported`]; [`transit`] overrides it.
    async fn kv_get_secret(
        &self,
        key_id: &str,
        version: Option<u32>,
    ) -> Result<Zeroizing<Vec<u8>>, BackendError> {
        let _ = (key_id, version);
        Err(BackendError::Unsupported("kv_get_secret"))
    }

    /// Write `value` as a fresh **KV-v2 version** of `key_id`, returning the new
    /// version number (never the value). Used to rotate a *value* key that has a
    /// catalog `generate` recipe: the broker generates a fresh value and stores it
    /// as the next version (the `vault-a2p` decision), and to back the `set` op.
    ///
    /// The default returns [`BackendError::Unsupported`]; [`transit`] overrides it.
    async fn kv_put(&self, key_id: &str, value: &[u8]) -> Result<u32, BackendError> {
        let _ = (key_id, value);
        Err(BackendError::Unsupported("rotate"))
    }

    /// Set the transit version window for `key_id`: `min_decryption_version`
    /// bounds the **grace period** (the oldest version `decrypt`/`verify` may
    /// still target: `0`/`1` honors all live versions, a higher value rejects
    /// pre-window ciphertexts), and `min_available_version` is the **retention**
    /// floor (transit deletes archived key material below it, irreversibly
    /// pruning expired versions). Both are optional; `None` leaves that field
    /// untouched.
    ///
    /// The default returns [`BackendError::Unsupported`]; [`transit`] overrides it.
    async fn configure_versions(
        &self,
        key_id: &str,
        min_decryption_version: Option<u32>,
        min_available_version: Option<u32>,
    ) -> Result<(), BackendError> {
        let _ = (key_id, min_decryption_version, min_available_version);
        Err(BackendError::Unsupported("configure_versions"))
    }

    /// Issue an X.509-SVID leaf from a provider-native PKI role.
    ///
    /// `key_id` is the backend-native issue endpoint from the catalog. For
    /// Vault PKI this is an absolute path such as `pki/issue/web`, not a
    /// transit key name. The private key is scoped to this operation and carried
    /// in a zeroizing buffer until the Workload API response is assembled.
    async fn issue_x509_svid(
        &self,
        key_id: &str,
        spiffe_id: &str,
        ttl_seconds: u64,
    ) -> Result<X509Svid, BackendError> {
        let _ = (key_id, spiffe_id, ttl_seconds);
        Err(BackendError::Unsupported("issue_x509_svid"))
    }

    /// Issue a DNS/IP-SAN X.509 leaf (a TLS cert) from a provider-native PKI role.
    ///
    /// `key_id` is the backend-native issue endpoint from the catalog (for
    /// Vault PKI, an absolute path such as `pki/issue/web`). Like
    /// [`Backend::issue_x509_svid`] the issuing CA key never leaves the backend;
    /// unlike an SVID the leaf is bound to DNS/IP SANs, and the leaf private key is
    /// returned to the caller (a TLS server needs it) in a zeroizing buffer.
    async fn issue_x509_cert(
        &self,
        key_id: &str,
        request: &X509CertRequest,
    ) -> Result<X509Svid, BackendError> {
        let _ = (key_id, request);
        Err(BackendError::Unsupported("issue_x509_cert"))
    }

    /// Read trust-domain X.509 bundle material from a provider-native PKI
    /// issuer path.
    ///
    /// `key_id` is the same backend-native locator used by
    /// [`Backend::issue_x509_svid`]. For Vault PKI this is an issue path such
    /// as `pki/issue/web`; the backend derives the PKI mount and reads that
    /// mount's CA bundle and CRL.
    async fn x509_bundle(&self, key_id: &str) -> Result<X509Bundle, BackendError> {
        let _ = key_id;
        Err(BackendError::Unsupported("x509_bundle"))
    }
}
