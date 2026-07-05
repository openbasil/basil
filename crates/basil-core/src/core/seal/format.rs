//! Sealed-bundle on-disk container (§2.2 of `designs/unlock-and-bundle.html`).
//!
//! Layout: a fixed ASCII magic + `u16` `format_version` (cleartext framing,
//! checkable before any JSON parse), then a JSON body holding the header, the
//! slot table, and the sealed payload. Binary fields are **base64 no-pad**
//! (`URL_SAFE_NO_PAD`, the alphabet `basil-nats` uses).
//!
//! The **header is bound as AAD** over the payload AEAD and every slot's
//! KEK-wrap. To sidestep JSON non-canonicalization the AAD is the **literal
//! header bytes**: the header object is serialized once at seal time and those
//! exact bytes are stored (base64-nopad) in `header_b64`; the opener feeds the
//! decoded bytes straight to the AEAD and never re-serializes the header.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::{Deserialize, Serialize};

use super::SealError;

/// Fixed framing magic (9 bytes, includes the trailing NUL).
pub const MAGIC: &[u8] = b"BASILBDL\x00";
/// The only suite/format this build understands.
pub const FORMAT_VERSION: u16 = 1;

/// Container suite ids (§2.5). Refused if unknown so a future v2 can change a
/// primitive without ambiguity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Suite {
    /// Container encoding id.
    pub container: ContainerId,
    /// Payload AEAD id.
    pub payload_aead: AeadId,
    /// KEK-wrap AEAD id.
    pub kek_wrap_aead: AeadId,
}

impl Suite {
    /// The `format_version = 1` suite.
    #[must_use]
    pub const fn v1() -> Self {
        Self {
            container: ContainerId::Json,
            payload_aead: AeadId::Aes256Gcm,
            kek_wrap_aead: AeadId::Aes256Gcm,
        }
    }
}

/// Container encoding id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContainerId {
    /// ASCII magic + `u16` version + JSON body, binary fields base64-nopad.
    Json,
}

/// AEAD primitive id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename = "aes-256-gcm")]
pub enum AeadId {
    /// AES-256-GCM (12-byte nonce).
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
}

/// The header object. Its **exact serialized bytes** are the AAD.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    /// Must equal [`FORMAT_VERSION`].
    pub format_version: u16,
    /// Suite ids for this version.
    pub suite: Suite,
    /// 16-byte random bundle id (base64-nopad).
    #[serde(with = "b64_array_16")]
    pub bundle_id: [u8; 16],
    /// Bundle creation time (unix seconds).
    pub created_unix: u64,
    /// Monotonic anti-rollback counter, bumped on every content change (§6.4).
    pub epoch: u64,
}

impl Header {
    /// Serialize the header to its canonical AAD bytes.
    ///
    /// # Errors
    /// Returns [`SealError::Format`] if serialization fails (unexpected).
    pub fn to_aad_bytes(&self) -> Result<Vec<u8>, SealError> {
        serde_json::to_vec(self).map_err(|e| SealError::Format(format!("header serialize: {e}")))
    }
}

/// A base64-nopad blob (nonce, ciphertext, salt) carried in JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct B64Bytes(pub Vec<u8>);

impl Serialize for B64Bytes {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for B64Bytes {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        B64.decode(s.as_bytes())
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

/// One unlock slot (§2.4). Wraps the same master KEK via a method-specific key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Slot {
    /// Stable id for add/remove/CLI reference.
    pub slot_id: u32,
    /// Which unlock method backs this slot.
    pub method: MethodKind,
    /// Operator-facing label.
    pub label: String,
    /// Slot creation time (unix seconds).
    pub created_unix: u64,
    /// Non-secret method params needed to reconstruct the slot key.
    pub params: MethodParams,
    /// How the master KEK is wrapped for this method.
    pub wrap: KekWrap,
}

/// Tagged unlock-method kind (§2.6). `Tpm` is reserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MethodKind {
    /// age + age-plugin-yubikey (operator presence).
    AgeYubikey,
    /// 24-word BIP39 phrase → Argon2id (break-glass).
    Bip39,
    /// Passphrase read from a file and KDF'd with Argon2id.
    Passphrase,
    /// Reserved; fail-closed until the TPM slot lands.
    Tpm,
}

impl std::fmt::Display for MethodKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::AgeYubikey => "age-yubikey",
            Self::Bip39 => "bip39",
            Self::Passphrase => "passphrase",
            Self::Tpm => "tpm",
        };
        f.write_str(s)
    }
}

/// Non-secret, method-specific public material (§2.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum MethodParams {
    /// age recipient string (public).
    AgeYubikey {
        /// The age recipient the KEK is wrapped to.
        recipient: String,
    },
    /// Argon2id salt + params for a phrase-derived slot key.
    Bip39 {
        /// 16-byte KDF salt (base64-nopad).
        salt: B64Bytes,
        /// Argon2id parameters.
        argon2: Argon2Params,
    },
    /// Salt and KDF params for a file-sourced passphrase slot key.
    Passphrase {
        /// 16-byte KDF salt (base64-nopad).
        salt: B64Bytes,
        /// Argon2id parameters.
        argon2: Argon2Params,
    },
    /// TPM2 sealed-object slot (feature `unlock-tpm`, §3.1 / §9).
    ///
    /// All fields are **non-secret** and safe at rest. The 32-byte slot key that
    /// AES-256-GCM-wraps the master KEK (in [`KekWrap`]) is sealed *inside* the
    /// TPM keyed-hash object; it never leaves the chip except transiently during
    /// `TPM2_Unseal` under the matching PCR policy. `private` is encrypted to the
    /// SRK and is meaningless off the originating TPM.
    Tpm {
        /// Marshalled `TPM2B_PUBLIC` of the sealed object (the keyed-hash public
        /// area), base64-nopad.
        public: B64Bytes,
        /// Marshalled `TPM2B_PRIVATE` of the sealed object: SRK-encrypted,
        /// base64-nopad. Safe at rest; only the originating TPM can load it.
        private: B64Bytes,
        /// The PCR selection the seal is bound to (`PolicyPCR`).
        pcrs: TpmPcrSelection,
        /// Object name hash algorithm, e.g. `"sha256"`.
        name_alg: String,
        /// Identifier of the fixed, deterministic SRK template used as the
        /// parent, so recovery regenerates the identical primary key (e.g.
        /// `"ecc-p256-srk-v1"`).
        srk_template: String,
    },
}

/// A TPM PCR selection: which bank and which PCR indices a seal is bound to.
///
/// Non-secret. Stored verbatim in a [`MethodParams::Tpm`] slot so recovery can
/// rebuild the exact `TPML_PCR_SELECTION` used to compute the seal's
/// `authPolicy`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TpmPcrSelection {
    /// PCR bank hash algorithm, e.g. `"sha256"`.
    pub bank: String,
    /// Selected PCR indices, ascending (e.g. `[0, 2, 4, 7]`).
    pub pcrs: Vec<u32>,
}

/// Argon2id cost parameters (mem in KiB, time, parallelism) (§8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2Params {
    /// Memory cost in KiB.
    pub m_cost_kib: u32,
    /// Time cost (iterations).
    pub t_cost: u32,
    /// Parallelism.
    pub p_cost: u32,
}

impl Argon2Params {
    /// Ratified production profile: mem = 64 MiB, t = 3, p = 1 (§8.2).
    pub const PRODUCTION: Self = Self {
        m_cost_kib: 64 * 1024,
        t_cost: 3,
        p_cost: 1,
    };
}

/// How a slot wraps the master KEK (§2.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KekWrap {
    /// AEAD nonce (base64-nopad). For `age` slots this is unused/empty (age
    /// manages its own framing).
    pub nonce: B64Bytes,
    /// Wrapped master KEK + tag (or the age stanza for the yubikey slot).
    pub ciphertext: B64Bytes,
}

/// The sealed payload (§2.3): AES-256-GCM over the JSON cred map.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedPayload {
    /// 12-byte AEAD nonce (base64-nopad).
    pub nonce: B64Bytes,
    /// Ciphertext + 16-byte GCM tag (base64-nopad).
    pub ciphertext: B64Bytes,
}

/// One append-only credential deposit record.
///
/// The metadata is intentionally cleartext so operators can review pending
/// records without an unlock secret. The credential itself is an X25519 sealed
/// box and the signature authenticates the canonical deposit fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositRecord {
    /// Backend id this credential should overlay after authorization.
    pub backend_id: String,
    /// Bundle epoch this deposit targets.
    pub epoch: u64,
    /// Monotonic sequence per `(contributor_key_id, backend_id)`.
    pub seq: u64,
    /// Sealed-payload contributor id.
    pub contributor_key_id: String,
    /// X25519 sealed credential.
    pub sealed_cred: DepositSealedCred,
    /// Ed25519 signature over [`deposit_signing_bytes`].
    pub signature: B64Bytes,
}

/// X25519 sealed-box fields for a serialized `BackendCred`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositSealedCred {
    /// Sender ephemeral X25519 public key.
    pub encapsulated_key: B64Bytes,
    /// AEAD nonce.
    pub nonce: B64Bytes,
    /// Ciphertext plus tag.
    pub ciphertext: B64Bytes,
}

/// The full JSON body (header + slots + payload).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleBody {
    /// The **literal** header bytes used as AAD (base64-nopad). The opener feeds
    /// these straight to the AEAD and never re-serializes the header.
    pub header_b64: B64Bytes,
    /// The parsed header (informational; AAD always comes from `header_b64`).
    pub header: Header,
    /// One entry per unlock method.
    pub slots: Vec<Slot>,
    /// The sealed cred map.
    pub payload: SealedPayload,
    /// Append-only credential deposits outside the payload AEAD.
    #[serde(default)]
    pub deposits: Vec<DepositRecord>,
}

/// A parsed bundle file: framing + body.
#[derive(Debug, Clone)]
pub struct ParsedBundle {
    /// The JSON body.
    pub body: BundleBody,
}

impl ParsedBundle {
    /// The AAD = literal on-disk header bytes (decoded `header_b64`).
    #[must_use]
    pub fn header_aad(&self) -> &[u8] {
        &self.body.header_b64.0
    }
}

/// Encode a full bundle file (framing prefix + JSON body).
///
/// `header_aad` MUST be the exact bytes returned by [`Header::to_aad_bytes`] for
/// `header`: the same bytes the payload/slots were sealed under.
///
/// # Errors
/// Returns [`SealError::Format`] on JSON serialization failure.
pub fn encode(
    header: &Header,
    header_aad: &[u8],
    slots: Vec<Slot>,
    payload: SealedPayload,
) -> Result<Vec<u8>, SealError> {
    encode_with_deposits(header, header_aad, slots, payload, Vec::new())
}

/// Encode a full bundle file while preserving or setting the deposit log.
///
/// # Errors
/// Returns [`SealError::Format`] on JSON serialization failure.
pub fn encode_with_deposits(
    header: &Header,
    header_aad: &[u8],
    slots: Vec<Slot>,
    payload: SealedPayload,
    deposits: Vec<DepositRecord>,
) -> Result<Vec<u8>, SealError> {
    let body = BundleBody {
        header_b64: B64Bytes(header_aad.to_vec()),
        header: header.clone(),
        slots,
        payload,
        deposits,
    };
    let body_json =
        serde_json::to_vec(&body).map_err(|e| SealError::Format(format!("body serialize: {e}")))?;

    let mut out = Vec::with_capacity(MAGIC.len() + 2 + body_json.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    out.extend_from_slice(&body_json);
    Ok(out)
}

/// Canonical bytes signed by a deposit contributor.
///
/// The `sealed_cred` field is signed as the exact serialized X25519 envelope
/// fields, but the enclosing signature is omitted. `serde_json` emits struct
/// fields in declaration order, giving us stable bytes for this v1 JSON
/// container without relying on map ordering.
///
/// # Errors
/// Returns [`SealError::Format`] on JSON serialization failure.
pub fn deposit_signing_bytes(record: &DepositRecord) -> Result<Vec<u8>, SealError> {
    #[derive(Serialize)]
    struct Signed<'a> {
        backend_id: &'a str,
        epoch: u64,
        seq: u64,
        contributor_key_id: &'a str,
        sealed_cred: &'a DepositSealedCred,
    }

    serde_json::to_vec(&Signed {
        backend_id: &record.backend_id,
        epoch: record.epoch,
        seq: record.seq,
        contributor_key_id: &record.contributor_key_id,
        sealed_cred: &record.sealed_cred,
    })
    .map_err(|e| SealError::Format(format!("deposit canonical serialize: {e}")))
}

/// Decode + validate a bundle file: check magic + version *before* JSON parse,
/// then parse the body and verify the embedded header round-trips.
///
/// # Errors
/// Returns [`SealError::Format`] for a bad magic / unknown version / malformed
/// JSON / mismatched header, all fail-closed (no panic, §1.3).
pub fn decode(bytes: &[u8]) -> Result<ParsedBundle, SealError> {
    let rest = bytes
        .strip_prefix(MAGIC)
        .ok_or_else(|| SealError::Format("bad magic (not a sealed bundle)".into()))?;
    let (ver_bytes, body_bytes) = rest
        .split_at_checked(2)
        .ok_or_else(|| SealError::Format("truncated version field".into()))?;
    let version = u16::from_be_bytes(
        <[u8; 2]>::try_from(ver_bytes)
            .map_err(|_| SealError::Format("truncated version field".into()))?,
    );
    if version != FORMAT_VERSION {
        return Err(SealError::Format(format!(
            "unsupported format_version {version} (this build understands {FORMAT_VERSION})"
        )));
    }

    let body: BundleBody = serde_json::from_slice(body_bytes)
        .map_err(|e| SealError::Format(format!("body parse: {e}")))?;

    // The header inside the body must match the AAD bytes that were embedded:
    // a mismatch means the file was edited inconsistently. We compare the
    // re-parsed header from the AAD bytes to the structured `header` field; the
    // AAD always remains the literal `header_b64` bytes for the AEAD.
    let header_from_aad: Header = serde_json::from_slice(&body.header_b64.0)
        .map_err(|e| SealError::Format(format!("header (aad) parse: {e}")))?;
    if header_from_aad != body.header {
        return Err(SealError::Format(
            "header / header_b64 mismatch (tampered container)".into(),
        ));
    }
    if body.header.format_version != FORMAT_VERSION {
        return Err(SealError::Format(
            "header.format_version disagrees with framing".into(),
        ));
    }
    if body.header.suite != Suite::v1() {
        return Err(SealError::Format("unknown suite ids".into()));
    }

    Ok(ParsedBundle { body })
}

/// serde helper: a `[u8; 16]` as a base64-nopad string.
mod b64_array_16 {
    use super::B64;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
        let s = String::deserialize(d)?;
        let v = B64.decode(s.as_bytes()).map_err(serde::de::Error::custom)?;
        <[u8; 16]>::try_from(v.as_slice())
            .map_err(|_| serde::de::Error::custom("bundle_id must be 16 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header() -> Header {
        Header {
            format_version: FORMAT_VERSION,
            suite: Suite::v1(),
            bundle_id: [7u8; 16],
            created_unix: 1_700_000_000,
            epoch: 1,
        }
    }

    #[test]
    fn encode_decode_round_trip() {
        let header = sample_header();
        let aad = header.to_aad_bytes().unwrap();
        let payload = SealedPayload {
            nonce: B64Bytes(vec![1; 12]),
            ciphertext: B64Bytes(vec![2; 48]),
        };
        let file = encode(&header, &aad, vec![], payload).unwrap();
        assert!(file.starts_with(MAGIC));
        let parsed = decode(&file).unwrap();
        assert_eq!(parsed.body.header, header);
        assert_eq!(parsed.header_aad(), aad.as_slice());
    }

    #[test]
    fn bad_magic_fails() {
        let err = decode(b"not a bundle at all").unwrap_err();
        assert!(matches!(err, SealError::Format(_)));
    }

    #[test]
    fn wrong_version_fails_before_parse() {
        let mut file = Vec::new();
        file.extend_from_slice(MAGIC);
        file.extend_from_slice(&2u16.to_be_bytes());
        file.extend_from_slice(b"{}");
        let err = decode(&file).unwrap_err();
        assert!(matches!(err, SealError::Format(m) if m.contains("unsupported format_version")));
    }

    #[test]
    fn aead_id_serializes_to_spec_string() {
        let v = serde_json::to_value(AeadId::Aes256Gcm).unwrap();
        assert_eq!(v, serde_json::json!("aes-256-gcm"));
    }
}
