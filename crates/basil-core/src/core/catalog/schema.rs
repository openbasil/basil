//! Catalog schema types: the key inventory + backend routing table (design §2).
//!
//! These are `serde`-derived and deserialized from the **exported JSON** the
//! broker loads at startup. JSON keys are camelCase (the mechanical projection of
//! the authored Nix, §2.3); enum string values are kebab-case (`ed25519-nkey`,
//! `ascii-printable`, …).

use std::collections::BTreeMap;

use basil_proto::KeyType;
use serde::{Deserialize, Serialize};

/// The catalog: one document, per-generation immutable.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Catalog {
    /// Schema version of this document.
    pub schema_version: u32,
    /// Backend instances, keyed by the name a [`KeyEntry::backend`] references.
    pub backends: BTreeMap<String, BackendRef>,
    /// Key inventory, keyed by dotted-lowercase key name.
    pub keys: BTreeMap<String, KeyEntry>,
}

/// A backend instance the catalog routes keys to.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BackendRef {
    /// Which kind of backend this is.
    pub kind: BackendKind,
    /// Backend address (e.g. a Vault URL).
    pub addr: String,
    /// Secrets engines this backend instance **provides** (its server capability,
    /// in nix supplied by a version preset). Empty means *undeclared*:
    /// capability enforcement is skipped for this backend (`core::capability`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub engines: Vec<Engine>,
    /// Fine-grained features this backend instance **provides** (the rest of the
    /// version preset). Empty + empty `engines` = undeclared (see `engines`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<Capability>,
    /// Asymmetric transit key algorithms this backend can mint/import natively.
    ///
    /// This is a static version-preset declaration, not a live backend query. An
    /// empty set on an otherwise-declared backend means no key type is declared
    /// mintable; the manager fails closed before dispatching generate/import.
    #[serde(
        default,
        rename = "mintKeyTypes",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub mint_key_types: Vec<KeyAlgorithm>,
    /// Capabilities this deployment **explicitly requires** of the backend,
    /// beyond what the routed keys already imply (the derived set). For
    /// non-key-derivable needs such as `byok-import`. Unioned with the derived
    /// requirements during enforcement.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<Capability>,
}

/// The kind of a [`BackendRef`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum BackendKind {
    /// A Vault-compatible backend: `HashiCorp` Vault or `OpenBao` (one wire API).
    #[serde(rename = "vault")]
    Vault,
    /// A key-store backend that materializes keys in Basil for one operation.
    #[serde(rename = "keystore")]
    Keystore,
    /// An AWS KMS in-place transit backend: the key never leaves KMS; Basil
    /// brokers `sign`/`verify`/`encrypt`/`decrypt` against the remote service.
    #[serde(rename = "aws-kms")]
    AwsKms,
    /// A GCP Cloud KMS in-place transit backend: the key never leaves Cloud KMS;
    /// Basil brokers `sign`/`verify`/`encrypt`/`decrypt` against the remote service.
    #[serde(rename = "gcp-kms")]
    GcpKms,
}

/// Key class: selects the default op surface and whether a public half exists.
/// Never grants on its own; policy is always authoritative (§2.4.1, §3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Class {
    /// Sign / verify / mint / `get_public_key`; requires a `key_type`.
    Asymmetric,
    /// Encrypt / decrypt payload; requires a `key_type`.
    Symmetric,
    /// An opaque config value (get / set / rotate); no `key_type`.
    Value,
    /// The public half (get / `get_public_key`); world-readable for reads (§3.5).
    Public,
    /// A KEM sealed-box recipient key (`unwrap` / `get_public_key`); the private
    /// half lives encrypted in KV and is **never** get-able. The broker
    /// materializes it in-process for one decapsulation, then zeroizes it (the
    /// §17.7 materialize-to-use local-custody arm). Requires a supported KEM
    /// `key_type`.
    Sealing,
}

/// The sub-engine within a backend. Inferred from [`Class`] when omitted (§2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Engine {
    /// Vault transit (sign-in-place crypto keys).
    Transit,
    /// Vault KV v2 (stored values / public material).
    Kv2,
    /// Vault PKI issue endpoint for X.509-SVID leaves.
    Pki,
}

impl Engine {
    /// The kebab-case token (the catalog wire value) for this engine.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Transit => "transit",
            Self::Kv2 => "kv2",
            Self::Pki => "pki",
        }
    }
}

impl std::fmt::Display for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.token())
    }
}

/// A fine-grained backend **capability**: a feature flag used purely for the
/// declarative `required ⊆ provided` capability check (`core::capability`).
///
/// **Open / extensible.** A known feature maps to a typed variant; any other
/// string is preserved as [`Capability::Other`], so a catalog can name a
/// capability a newer `HashiCorp` Vault / `OpenBao` release introduced *without*
/// a Basil rebuild. Enforcement compares by string token, so the agent needn't
/// *understand* a capability to check it, and a typo can only ever
/// over-restrict (fail closed), never silently grant.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(from = "String", into = "String")]
pub enum Capability {
    /// Transit BYOK key import (`transit/wrapping_key` + `keys/<k>/import`).
    ByokImport,
    /// Transit prehashed-signature options (the RS256 sign path).
    PrehashSign,
    /// Post-quantum algorithms in transit (ML-DSA / ML-KEM / SLH-DSA).
    PqcTransit,
    /// PKI CRL endpoint (`<mount>/crl/pem`).
    PkiCrl,
    /// JWT auth method (`auth/<mount>/login`): the SPIFFE/JWT-SVID backend.
    JwtAuth,
    /// `AppRole` auth method (`auth/approle/login`): broker bootstrap.
    ApproleAuth,
    /// A capability string this Basil build does not recognize, carried opaque
    /// so a catalog can name a feature a newer engine release added.
    Other(String),
}

impl Capability {
    /// The kebab-case token for this capability (round-trips through [`From`]).
    #[must_use]
    pub const fn token(&self) -> &str {
        match self {
            Self::ByokImport => "byok-import",
            Self::PrehashSign => "prehash-sign",
            Self::PqcTransit => "pqc-transit",
            Self::PkiCrl => "pki-crl",
            Self::JwtAuth => "jwt-auth",
            Self::ApproleAuth => "approle-auth",
            Self::Other(s) => s.as_str(),
        }
    }

    /// Whether this Basil build recognizes the capability (vs an opaque
    /// [`Capability::Other`] forwarded from config for a newer engine release).
    #[must_use]
    pub const fn is_known(&self) -> bool {
        !matches!(self, Self::Other(_))
    }
}

impl From<String> for Capability {
    fn from(s: String) -> Self {
        match s.as_str() {
            "byok-import" => Self::ByokImport,
            "prehash-sign" => Self::PrehashSign,
            "pqc-transit" => Self::PqcTransit,
            "pki-crl" => Self::PkiCrl,
            "jwt-auth" => Self::JwtAuth,
            "approle-auth" => Self::ApproleAuth,
            _ => Self::Other(s),
        }
    }
}

impl From<Capability> for String {
    fn from(c: Capability) -> Self {
        c.token().to_string()
    }
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.token())
    }
}

/// The crypto algorithm of a key: the union across asymmetric + symmetric keys (§2.4.1).
///
/// This is the catalog's own enum; the wire layer (`vault-9j9`) splits it by op
/// into its own `KeyType` / `AeadAlgorithm`. Do not conflate with [`Class`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub enum KeyAlgorithm {
    /// Plain Ed25519 (signing).
    #[serde(rename = "ed25519")]
    Ed25519,
    /// Ed25519 used as a NATS `NKey` (needs a `nats_type` label, §2.6).
    #[serde(rename = "ed25519-nkey")]
    Ed25519Nkey,
    /// RSA-2048 (signing).
    #[serde(rename = "rsa-2048")]
    Rsa2048,
    /// ECDSA P-256 (signing).
    #[serde(rename = "ecdsa-p256")]
    EcdsaP256,
    /// ECDSA P-384 (signing).
    #[serde(rename = "ecdsa-p384")]
    EcdsaP384,
    /// ECDSA P-521 (signing).
    #[serde(rename = "ecdsa-p521")]
    EcdsaP521,
    /// AES-256-GCM (AEAD).
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
    /// ChaCha20-Poly1305 (AEAD).
    #[serde(rename = "chacha20-poly1305")]
    ChaCha20Poly1305,
    /// X25519 (sealed-box KEM recipient key, `Class::Sealing`).
    #[serde(rename = "x25519")]
    X25519,
    /// ML-KEM-512 (sealed-box KEM recipient key, `Class::Sealing`).
    #[serde(rename = "ml-kem-512")]
    MlKem512,
    /// ML-KEM-768 (sealed-box KEM recipient key, `Class::Sealing`).
    #[serde(rename = "ml-kem-768")]
    MlKem768,
    /// ML-KEM-1024 (sealed-box KEM recipient key, `Class::Sealing`).
    #[serde(rename = "ml-kem-1024")]
    MlKem1024,
    /// ML-DSA-44 software-custodied signing key (`Class::Asymmetric`, routed
    /// through the local-software crypto provider).
    #[serde(rename = "ml-dsa-44")]
    MlDsa44,
    /// ML-DSA-65 software-custodied signing key (`Class::Asymmetric`).
    #[serde(rename = "ml-dsa-65")]
    MlDsa65,
    /// ML-DSA-87 software-custodied signing key (`Class::Asymmetric`).
    #[serde(rename = "ml-dsa-87")]
    MlDsa87,
}

/// What to do when a key's material is absent at startup reconcile (§3.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MissingPolicy {
    /// Hard error (the default).
    #[default]
    Error,
    /// Log a warning and continue; ops fail until the key exists.
    Warn,
    /// Create material (crypto keys from `key_type`; value/public from `generate`).
    Generate,
}

/// Optional COSE unseal-context pinning for a [`Class::Sealing`] key
/// (`basil-2rqj`).
///
/// Without a pin, an `op:decrypt` grant on a sealing key is a decrypt oracle for
/// *any* `COSE_Encrypt` addressed to the key (the `AeadService.UnsealCose` path).
/// A pin narrows that authority (least privilege) to envelopes bound to a
/// specific protocol context: the KDF party identities (`PartyU`/`PartyV`) and/or
/// the encryption-layer `external_aad`. At least one facet must be set; an
/// all-empty pin is a no-op that would read as configured intent and is rejected
/// by the loader. Absent entirely = unchanged (any envelope addressed to the
/// key). Forbidden on non-sealing keys (loader-enforced).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealingPin {
    /// Pinned KDF `PartyU`/`PartyV` identities. When set, an envelope's KDF
    /// parties must exactly equal this pin (both slots), else the unseal is
    /// refused. `None` = this facet is not pinned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parties: Option<PinnedParties>,
    /// Allowed encryption-layer `external_aad` values (each a UTF-8 string whose
    /// bytes are the binding). When non-empty, the caller-supplied `external_aad`
    /// must byte-match exactly one entry, else the unseal is refused. Empty = this
    /// facet is not pinned (a single `""` entry pins the empty-AAD default).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub external_aad: Vec<String>,
}

impl SealingPin {
    /// Whether this pin actually constrains anything (at least one facet set).
    /// An all-empty pin is meaningless and is rejected by the loader.
    #[must_use]
    pub const fn is_configured(&self) -> bool {
        self.parties.is_some() || !self.external_aad.is_empty()
    }

    /// Whether a caller-supplied `external_aad` is permitted by this pin. When no
    /// `external_aad` values are pinned, this facet imposes no restriction
    /// (returns `true`); otherwise the AAD must byte-match one pinned value.
    #[must_use]
    pub fn external_aad_allowed(&self, aad: &[u8]) -> bool {
        self.external_aad.is_empty()
            || self
                .external_aad
                .iter()
                .any(|allowed| allowed.as_bytes() == aad)
    }
}

/// The pinned KDF party identities of a [`SealingPin`] (RFC 9053 §5.1).
///
/// Each slot is either a concrete UTF-8 identity or nil (the anonymous slot),
/// expressed by omitting the field, never by an empty string (loader-rejected).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PinnedParties {
    /// `PartyU` (message sender) identity; absent = the nil (anonymous) slot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub party_u: Option<String>,
    /// `PartyV` (recipient) identity; absent = the nil (anonymous) slot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub party_v: Option<String>,
}

impl PinnedParties {
    /// Convert to the `basil-cose` KDF party pin. A present slot becomes a
    /// concrete [`basil_cose::PartyIdentity`]; an absent slot becomes nil.
    ///
    /// # Errors
    ///
    /// [`basil_cose::ProfileError::EmptyPartyIdentity`] if a present slot is the
    /// empty string. The loader rejects that at load, so this is unreachable for a
    /// validated catalog: the method stays fallible so the conversion never
    /// panics on an unvalidated one.
    pub fn to_kdf_parties(&self) -> Result<basil_cose::KdfParties, basil_cose::ProfileError> {
        Ok(basil_cose::KdfParties {
            party_u: Self::slot(self.party_u.as_deref())?,
            party_v: Self::slot(self.party_v.as_deref())?,
        })
    }

    fn slot(identity: Option<&str>) -> Result<basil_cose::PartyIdentity, basil_cose::ProfileError> {
        identity.map_or_else(
            || Ok(basil_cose::PartyIdentity::nil()),
            |id| basil_cose::PartyIdentity::from_bytes(id.as_bytes().to_vec()),
        )
    }
}

/// One catalog key (§2.4).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyEntry {
    /// Key class (§2.4.1).
    pub class: Class,
    /// Crypto algorithm; required for asym/sym, `None` for value, optional for public.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_type: Option<KeyAlgorithm>,
    /// Names a [`Catalog::backends`] entry. Exactly one.
    pub backend: String,
    /// Sub-engine within the backend; inferred from `class` when `None` (§2.2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine: Option<Engine>,
    /// Backend-native locator (transit key name / KV path); opaque to policy.
    pub path: String,
    /// KV path holding the **public** half of a materialize-to-use key
    /// (`sealing` X25519, or `asymmetric`+`engine=kv2` Ed25519), provisioned out
    /// of band alongside the private (basil-o86). Public ops (`wrap`,
    /// `get_public_key`, `verify`) read the public from here via a non-secret
    /// `kv_get`, so the private at [`path`](Self::path) is materialized **only**
    /// on the op that performs the private crypto (unwrap / sign). Required for
    /// those two key kinds, forbidden on every other key (loader-enforced).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_path: Option<String>,
    /// Catalog-level hard cap on broker-mediated writes (§2.4.2).
    pub writable: bool,
    /// Behavior when the material is absent at reconcile (default `Error`, §3.7).
    #[serde(default)]
    pub missing: MissingPolicy,
    /// Generation recipe (value/public material only, §2.5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generate: Option<GenerateSpec>,
    /// Optional COSE unseal-context pinning for a [`Class::Sealing`] key
    /// (`basil-2rqj`): narrows the `UnsealCose` decrypt oracle to envelopes bound
    /// to pinned KDF parties and/or `external_aad`. Forbidden on non-sealing keys
    /// (loader-enforced); absent = any envelope addressed to the key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealing_pin: Option<SealingPin>,
    /// Free-form tags (§2.6); defaults to empty.
    #[serde(default, skip_serializing_if = "Labels::is_empty")]
    pub labels: Labels,
    /// Human note for the lint CLI and audit; validated non-empty (§2.4).
    pub description: String,
}

impl KeyEntry {
    /// The effective sub-engine: the catalog value, or the §2.2 inference from
    /// [`Class`] when omitted (crypto → transit, stored → kv2).
    #[must_use]
    pub fn effective_engine(&self) -> Engine {
        self.engine.unwrap_or(match self.class {
            Class::Asymmetric | Class::Symmetric => Engine::Transit,
            // Sealing private material is stored (encrypted) in KV and
            // materialized in-process: it is a KV-backed key, not transit.
            Class::Value | Class::Public | Class::Sealing => Engine::Kv2,
        })
    }

    /// Whether this key is a **materialize-to-use** key (design §17.7): its
    /// private half lives in KV and is materialized in-process for exactly one
    /// crypto op, then zeroized. Two arms: a `sealing` X25519 key (unseal ECDH)
    /// and an `asymmetric`+`engine=kv2` Ed25519 key (sign). These are the keys
    /// that carry a [`public_path`](Self::public_path) (basil-o86): every other
    /// key uses its backend in place and has no materialize footprint.
    #[must_use]
    pub fn is_materialize_to_use(&self) -> bool {
        match self.class {
            Class::Sealing => true,
            Class::Asymmetric => self.effective_engine() == Engine::Kv2,
            Class::Symmetric | Class::Value | Class::Public => false,
        }
    }
}

impl KeyAlgorithm {
    /// Map a wire [`KeyType`] to the catalog algorithm token for static backend
    /// capability checks.
    #[must_use]
    pub const fn from_wire_key_type(key_type: KeyType) -> Self {
        match key_type {
            KeyType::Ed25519 => Self::Ed25519,
            KeyType::Ed25519Nkey => Self::Ed25519Nkey,
            KeyType::Rsa2048 => Self::Rsa2048,
            KeyType::EcdsaP256 => Self::EcdsaP256,
            KeyType::EcdsaP384 => Self::EcdsaP384,
            KeyType::EcdsaP521 => Self::EcdsaP521,
            KeyType::MlDsa44 => Self::MlDsa44,
            KeyType::MlDsa65 => Self::MlDsa65,
            KeyType::MlDsa87 => Self::MlDsa87,
            KeyType::MlKem512 => Self::MlKem512,
            KeyType::MlKem768 => Self::MlKem768,
            KeyType::MlKem1024 => Self::MlKem1024,
        }
    }

    /// The kebab-case catalog wire token for this algorithm (matches the serde
    /// `rename`s above; used in diagnostics).
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::Ed25519Nkey => "ed25519-nkey",
            Self::Rsa2048 => "rsa-2048",
            Self::EcdsaP256 => "ecdsa-p256",
            Self::EcdsaP384 => "ecdsa-p384",
            Self::EcdsaP521 => "ecdsa-p521",
            Self::Aes256Gcm => "aes-256-gcm",
            Self::ChaCha20Poly1305 => "chacha20-poly1305",
            Self::X25519 => "x25519",
            Self::MlKem512 => "ml-kem-512",
            Self::MlKem768 => "ml-kem-768",
            Self::MlKem1024 => "ml-kem-1024",
            Self::MlDsa44 => "ml-dsa-44",
            Self::MlDsa65 => "ml-dsa-65",
            Self::MlDsa87 => "ml-dsa-87",
        }
    }

    /// Whether this algorithm is in the SPIFFE JWT-SVID profile signature set
    /// (the `RS*`/`ES*`/`PS*` families → `rsa-*`/`ec-*`).
    ///
    /// A `svid_kind=jwt` issuer **must** resolve to one of these: a standard
    /// SPIFFE client (e.g. `rust-spiffe`) rejects any other `alg` (notably
    /// `EdDSA`/`ed25519`) with `UnsupportedAlgorithm`. The broker therefore
    /// fails closed at boot/check on a JWT-SVID issuer outside this set rather
    /// than minting tokens no conforming client will accept.
    ///
    /// The match is exhaustive so a newly added algorithm forces an explicit
    /// allow/deny decision here (fail-closed by default: unknown → not allowed).
    #[must_use]
    pub const fn is_spiffe_jwt_svid_profile(self) -> bool {
        match self {
            // RSA → RS*, EC → ES*. This build represents RSA-2048/RS256,
            // ECDSA P-256/ES256, and ECDSA P-384/ES384. ECDSA P-521 is
            // backend-native for generic signing, but not a JWT-SVID issuer
            // because the Rust verifier stack cannot validate ES512.
            Self::Rsa2048 | Self::EcdsaP256 | Self::EcdsaP384 => true,
            // EdDSA (ed25519), the AEAD algorithms, and X25519 (a KEM key, not a
            // signing key) are not JWT-SVID signing algorithms in the profile.
            Self::Ed25519
            | Self::Ed25519Nkey
            | Self::EcdsaP521
            | Self::Aes256Gcm
            | Self::ChaCha20Poly1305
            | Self::X25519
            | Self::MlKem512
            | Self::MlKem768
            | Self::MlKem1024
            // ML-DSA is a post-quantum signature scheme outside the SPIFFE
            // JWT-SVID profile (RS*/ES* only); a conforming client would reject it.
            | Self::MlDsa44
            | Self::MlDsa65
            | Self::MlDsa87 => false,
        }
    }

    /// The backend [`Capability`] this algorithm requires, if any.
    ///
    /// Classical algorithms need only base transit support (`None`). When
    /// post-quantum algorithms are added they return `Some(Capability::PqcTransit)`:
    /// the exhaustive match makes that a compile-time obligation, so a new
    /// algorithm can't silently skip its capability requirement.
    #[must_use]
    pub const fn required_capability(self) -> Option<Capability> {
        match self {
            Self::Ed25519
            | Self::Ed25519Nkey
            | Self::Rsa2048
            | Self::EcdsaP256
            | Self::EcdsaP384
            | Self::EcdsaP521
            | Self::Aes256Gcm
            | Self::ChaCha20Poly1305
            // Sealing keys use the in-process crypto core, not a transit
            // capability: no backend feature flag is required.
            | Self::X25519
            | Self::MlKem512
            | Self::MlKem768
            | Self::MlKem1024
            // ML-DSA software-custodied signing keys run the signature in
            // process over a materialized seed, so they need no backend
            // transit capability (the backend only custodies the encrypted seed).
            | Self::MlDsa44
            | Self::MlDsa65
            | Self::MlDsa87 => None,
        }
    }
}

/// A generation recipe for `value` / `public` material (§2.5). Crypto keys
/// generate from `key_type` and carry no recipe.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "format", rename_all = "kebab-case")]
pub enum GenerateSpec {
    /// Random printable password of `bytes` length.
    AsciiPrintable {
        /// Number of bytes.
        bytes: u32,
    },
    /// Random bytes, base64-encoded.
    Base64 {
        /// Number of bytes.
        bytes: u32,
    },
    /// Random bytes, hex-encoded.
    Hex {
        /// Number of bytes.
        bytes: u32,
    },
    /// An age identity (x25519), stored as a `value`.
    AgeX25519,
    /// A self-signed cert via `step-cli`: test/dev only, feature-gated.
    #[serde(rename_all = "camelCase")]
    SelfSignedTls {
        /// Certificate common name.
        common_name: String,
        /// Validity window (e.g. `8760h`).
        validity: String,
    },
    /// A key paired with a `self-signed-tls` cert: test/dev only.
    #[serde(rename_all = "camelCase")]
    SelfSignedTlsPairOf {
        /// The other key name this is paired with.
        pair_of: String,
    },
}

/// Parsed free-form labels (§2.6). Each entry is `name=value` or a bare slug.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Labels(pub Vec<String>);

impl Labels {
    /// Whether there are no labels (drives `skip_serializing_if` so a scaffold
    /// emits no empty `labels` array).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Look up a `name=value` label, returning its value if present.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0
            .iter()
            .filter_map(|l| l.split_once('='))
            .find_map(|(k, v)| (k == key).then_some(v))
    }

    /// The reserved `nats_type` accessor: the issuer's [`NkeyType`] role (§2.6).
    ///
    /// The label stores the single `NKey` prefix letter (e.g. `nats_type=A`).
    /// Returns the parsed role for a well-formed label, `None` if the label is
    /// absent or is not a single valid `NKey` prefix letter.
    #[must_use]
    pub fn nats_type(&self) -> Option<basil_nats::NkeyType> {
        let value = self.get("nats_type")?;
        let mut chars = value.chars();
        let letter = chars.next()?;
        if chars.next().is_some() {
            return None; // more than one character
        }
        basil_nats::NkeyType::from_letter(letter)
    }

    /// Whether the labels carry a (well-formed) `nats_type` letter.
    #[must_use]
    pub fn has_nats_type(&self) -> bool {
        self.nats_type().is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_get_parses_name_value() {
        let labels = Labels(vec![
            "nats_type=A".into(),
            "tier=prod".into(),
            "bare".into(),
        ]);
        assert_eq!(labels.get("nats_type"), Some("A"));
        assert_eq!(labels.get("tier"), Some("prod"));
        assert_eq!(labels.get("bare"), None); // bare slug, no `=`
        assert_eq!(labels.get("absent"), None);
    }

    #[test]
    fn nats_type_returns_single_valid_letter() {
        for letter in ['A', 'O', 'U', 'N', 'C', 'X'] {
            let labels = Labels(vec![format!("nats_type={letter}")]);
            assert_eq!(
                labels.nats_type(),
                basil_nats::NkeyType::from_letter(letter),
                "letter {letter}"
            );
            assert!(labels.has_nats_type());
        }
    }

    #[test]
    fn nats_type_rejects_invalid_or_multichar() {
        assert_eq!(Labels(vec!["nats_type=Z".into()]).nats_type(), None);
        assert_eq!(Labels(vec!["nats_type=AB".into()]).nats_type(), None);
        assert_eq!(Labels(vec!["nats_type=".into()]).nats_type(), None);
        assert_eq!(Labels(vec!["nats_type=account".into()]).nats_type(), None);
        assert_eq!(Labels(vec![]).nats_type(), None);
        assert!(!Labels(vec!["nats_type=Z".into()]).has_nats_type());
    }

    #[test]
    fn enums_deserialize_kebab_case() {
        assert_eq!(
            serde_json::from_str::<KeyAlgorithm>("\"ed25519-nkey\"").unwrap(),
            KeyAlgorithm::Ed25519Nkey
        );
        assert_eq!(
            serde_json::from_str::<KeyAlgorithm>("\"aes-256-gcm\"").unwrap(),
            KeyAlgorithm::Aes256Gcm
        );
        assert_eq!(
            serde_json::from_str::<KeyAlgorithm>("\"chacha20-poly1305\"").unwrap(),
            KeyAlgorithm::ChaCha20Poly1305
        );
        assert_eq!(
            serde_json::from_str::<Class>("\"public\"").unwrap(),
            Class::Public
        );
        assert_eq!(
            serde_json::from_str::<Engine>("\"kv2\"").unwrap(),
            Engine::Kv2
        );
        assert_eq!(
            serde_json::from_str::<Engine>("\"pki\"").unwrap(),
            Engine::Pki
        );
        assert_eq!(
            serde_json::from_str::<BackendKind>("\"vault\"").unwrap(),
            BackendKind::Vault
        );
    }

    #[test]
    fn missing_policy_defaults_to_error() {
        assert_eq!(MissingPolicy::default(), MissingPolicy::Error);
        assert_eq!(
            serde_json::from_str::<MissingPolicy>("\"generate\"").unwrap(),
            MissingPolicy::Generate
        );
    }

    #[test]
    fn generate_spec_is_tagged_by_format() {
        let g: GenerateSpec =
            serde_json::from_str(r#"{"format":"ascii-printable","bytes":24}"#).unwrap();
        assert_eq!(g, GenerateSpec::AsciiPrintable { bytes: 24 });

        let g: GenerateSpec = serde_json::from_str(
            r#"{"format":"self-signed-tls","commonName":"x","validity":"1h"}"#,
        )
        .unwrap();
        assert_eq!(
            g,
            GenerateSpec::SelfSignedTls {
                common_name: "x".into(),
                validity: "1h".into()
            }
        );

        let g: GenerateSpec =
            serde_json::from_str(r#"{"format":"self-signed-tls-pair-of","pairOf":"web.key"}"#)
                .unwrap();
        assert_eq!(
            g,
            GenerateSpec::SelfSignedTlsPairOf {
                pair_of: "web.key".into()
            }
        );

        let g: GenerateSpec = serde_json::from_str(r#"{"format":"age-x25519"}"#).unwrap();
        assert_eq!(g, GenerateSpec::AgeX25519);
    }

    #[test]
    fn spiffe_jwt_svid_profile_allows_only_profile_family() {
        // RSA/RS256, P-256/ES256, and P-384/ES384 are in the supported
        // SPIFFE JWT-SVID profile. P-521/ES512 is a backend-native generic
        // signing key type, but the Rust validation stack cannot verify ES512,
        // so it stays out of the issuer profile.
        assert!(KeyAlgorithm::Rsa2048.is_spiffe_jwt_svid_profile());
        assert!(KeyAlgorithm::EcdsaP256.is_spiffe_jwt_svid_profile());
        assert!(KeyAlgorithm::EcdsaP384.is_spiffe_jwt_svid_profile());
        assert!(!KeyAlgorithm::EcdsaP521.is_spiffe_jwt_svid_profile());
        assert!(!KeyAlgorithm::Ed25519.is_spiffe_jwt_svid_profile());
        assert!(!KeyAlgorithm::Ed25519Nkey.is_spiffe_jwt_svid_profile());
        assert!(!KeyAlgorithm::Aes256Gcm.is_spiffe_jwt_svid_profile());
        assert!(!KeyAlgorithm::ChaCha20Poly1305.is_spiffe_jwt_svid_profile());
        assert!(!KeyAlgorithm::X25519.is_spiffe_jwt_svid_profile());
        assert!(!KeyAlgorithm::MlKem512.is_spiffe_jwt_svid_profile());
        assert!(!KeyAlgorithm::MlKem768.is_spiffe_jwt_svid_profile());
        assert!(!KeyAlgorithm::MlKem1024.is_spiffe_jwt_svid_profile());
        assert!(!KeyAlgorithm::MlDsa44.is_spiffe_jwt_svid_profile());
        assert!(!KeyAlgorithm::MlDsa65.is_spiffe_jwt_svid_profile());
        assert!(!KeyAlgorithm::MlDsa87.is_spiffe_jwt_svid_profile());
    }

    #[test]
    fn sealing_class_and_kem_algorithms_deserialize() {
        assert_eq!(
            serde_json::from_str::<Class>("\"sealing\"").unwrap(),
            Class::Sealing
        );
        assert_eq!(
            serde_json::from_str::<KeyAlgorithm>("\"x25519\"").unwrap(),
            KeyAlgorithm::X25519
        );
        assert_eq!(
            serde_json::from_str::<KeyAlgorithm>("\"ml-kem-768\"").unwrap(),
            KeyAlgorithm::MlKem768
        );
    }

    #[test]
    fn sealing_class_infers_kv2_engine() {
        // A sealing key's private lives in KV; engine inference must pick Kv2.
        let entry: KeyEntry = serde_json::from_str(
            r#"{
              "class": "sealing", "keyType": "x25519", "backend": "bao",
              "path": "secret/data/enroll/x25519", "writable": true,
              "missing": "error", "description": "enrollment sealing key"
            }"#,
        )
        .unwrap();
        assert_eq!(entry.effective_engine(), Engine::Kv2);
    }

    #[test]
    fn key_algorithm_token_round_trips_through_serde() {
        for alg in [
            KeyAlgorithm::Ed25519,
            KeyAlgorithm::Ed25519Nkey,
            KeyAlgorithm::Rsa2048,
            KeyAlgorithm::EcdsaP256,
            KeyAlgorithm::Aes256Gcm,
            KeyAlgorithm::ChaCha20Poly1305,
            KeyAlgorithm::X25519,
            KeyAlgorithm::MlKem512,
            KeyAlgorithm::MlKem768,
            KeyAlgorithm::MlKem1024,
            KeyAlgorithm::MlDsa44,
            KeyAlgorithm::MlDsa65,
            KeyAlgorithm::MlDsa87,
        ] {
            let json = format!("\"{}\"", alg.token());
            let parsed: KeyAlgorithm = serde_json::from_str(&json).expect("token deserializes");
            assert_eq!(parsed, alg);
        }
    }
}
