//! The codec seam: the in-tree deterministic COSE profile encoder/decoder
//! over `minicbor`. This in-tree encoder is the primary and only path).
//!
//! This is the only module that names `minicbor` types. Encoding emits the
//! RFC 8949 §4.2 deterministic form by construction (definite lengths,
//! minimal integer heads from `minicbor`, canonical map-key order fixed by
//! the profile). Strict decoding walks the exact profile shape and then
//! **re-encodes the parsed semantics and requires byte equality with the
//! input**: the determinism check runs on every decode, release builds
//! included.

pub mod precheck;

use alloc::string::String;
use alloc::vec::Vec;

use minicbor::data::Type;
use minicbor::{Decoder, Encoder};

use crate::alg::{ContentAlgorithm, SignatureAlgorithm};
use crate::claims::{Claims, ProtectedHeaders};
use crate::error::DecodeError;
use crate::hash::RequestHash;
use crate::kdf::{KdfParties, PartyIdentity};
use crate::label::{self, canonical_sort_key};
use crate::types::{ContentType, KeyId, MessageId, ResponseSubject, Subject, UnixTime};

/// Internal encode failure. Statically unreachable for profile-valid input
/// (encoding into a `Vec` cannot fail); kept so no build path can panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodecError;

/// COSE tag for `COSE_Sign1`.
pub const TAG_SIGN1: u64 = 18;
/// COSE tag for `COSE_Encrypt`.
pub const TAG_ENCRYPT: u64 = 96;

/// AEAD nonce length (bytes).
pub const NONCE_LEN: usize = 12;
/// X25519 public key length (bytes).
pub const X25519_LEN: usize = 32;

/// Labels that constitute claims; finding one in an unprotected header is
/// [`DecodeError::ClaimsInUnprotected`].
const CLAIM_LABELS: [i64; 6] = [
    label::HDR_CWT_CLAIMS,
    label::IN_REPLY_TO,
    label::REQUEST_HASH,
    label::SENDER_KEY_ID,
    label::RESPONSE_KEY_ID,
    label::RESPONSE_SUBJECT,
];

type EncResult = Result<(), minicbor::encode::Error<core::convert::Infallible>>;

// ---------------------------------------------------------------------------
// Encoding (canonical by construction)
// ---------------------------------------------------------------------------

fn encode_with(
    f: impl FnOnce(&mut Encoder<&mut Vec<u8>>) -> EncResult,
) -> Result<Vec<u8>, CodecError> {
    let mut out = Vec::new();
    let mut e = Encoder::new(&mut out);
    f(&mut e).map_err(|_| CodecError)?;
    Ok(out)
}

/// The basil private labels present in a claim set, in canonical order.
fn basil_labels(claims: &Claims) -> Vec<i64> {
    let mut labels = Vec::new();
    if claims.in_reply_to.is_some() {
        labels.push(label::IN_REPLY_TO);
    }
    if claims.request_hash.is_some() {
        labels.push(label::REQUEST_HASH);
    }
    if claims.sender_key_id.is_some() {
        labels.push(label::SENDER_KEY_ID);
    }
    if claims.response_key_id.is_some() {
        labels.push(label::RESPONSE_KEY_ID);
    }
    if claims.response_subject.is_some() {
        labels.push(label::RESPONSE_SUBJECT);
    }
    labels
}

/// The `crit` contents for a claims-capable protected header: content type
/// (3), the CWT map (15) when claims are present, and every basil label
/// present, in canonical order.
fn crit_labels(claims: Option<&Claims>, protected_headers: Option<&ProtectedHeaders>) -> Vec<i64> {
    let mut crit = alloc::vec![label::HDR_CONTENT_TYPE];
    if let Some(c) = claims {
        crit.push(label::HDR_CWT_CLAIMS);
        crit.extend(basil_labels(c));
    }
    if protected_headers.is_some_and(|headers| !headers.signer_certificates_jwt.is_empty()) {
        crit.push(label::SIGNER_CERTIFICATES_JWT);
    }
    crit
}

/// Write the CWT claims map (header 15 value).
fn write_cwt_map(e: &mut Encoder<&mut Vec<u8>>, claims: &Claims) -> EncResult {
    let mut n = 2; // iat + cti
    n += u64::from(claims.issuer.is_some());
    n += u64::from(claims.audience.is_some());
    n += u64::from(claims.expires_at.is_some());
    e.map(n)?;
    if let Some(iss) = &claims.issuer {
        e.i64(label::CWT_ISS)?.str(iss.as_str())?;
    }
    if let Some(aud) = &claims.audience {
        e.i64(label::CWT_AUD)?.str(aud.as_str())?;
    }
    if let Some(UnixTime(exp)) = claims.expires_at {
        e.i64(label::CWT_EXP)?.i64(exp)?;
    }
    e.i64(label::CWT_IAT)?.i64(claims.issued_at.0)?;
    e.i64(label::CWT_CTI)?.bytes(claims.message_id.as_bytes())?;
    Ok(())
}

/// Write the crit array (2) and content type (3) plus, when claims are
/// present, the CWT map (15) and the basil labels: the shared tail of every
/// claims-capable protected header.
fn write_claims_capable_tail(
    e: &mut Encoder<&mut Vec<u8>>,
    content_type: &ContentType,
    claims: Option<&Claims>,
    protected_headers: Option<&ProtectedHeaders>,
    kid: Option<&KeyId>,
) -> EncResult {
    let crit = crit_labels(claims, protected_headers);
    e.i64(label::HDR_CRIT)?.array(crit.len() as u64)?;
    for l in &crit {
        e.i64(*l)?;
    }
    e.i64(label::HDR_CONTENT_TYPE)?.str(content_type.as_str())?;
    if let Some(kid) = kid {
        e.i64(label::HDR_KID)?.bytes(kid.as_bytes())?;
    }
    if let Some(c) = claims {
        e.i64(label::HDR_CWT_CLAIMS)?;
        write_cwt_map(e, c)?;
        if let Some(v) = &c.in_reply_to {
            e.i64(label::IN_REPLY_TO)?.bytes(v.as_bytes())?;
        }
        if let Some(RequestHash(h)) = &c.request_hash {
            e.i64(label::REQUEST_HASH)?.bytes(h)?;
        }
        if let Some(v) = &c.sender_key_id {
            e.i64(label::SENDER_KEY_ID)?.bytes(v.as_bytes())?;
        }
        if let Some(v) = &c.response_key_id {
            // `-70004` is a tstr; the build entry points reject non-UTF-8
            // response key ids before reaching the codec.
            match v.as_catalog_name() {
                Some(name) => e.i64(label::RESPONSE_KEY_ID)?.str(name)?,
                None => return Err(minicbor::encode::Error::message("response kid not text")),
            };
        }
        if let Some(v) = &c.response_subject {
            e.i64(label::RESPONSE_SUBJECT)?.str(v.as_str())?;
        }
    }
    if let Some(headers) = protected_headers
        && !headers.signer_certificates_jwt.is_empty()
    {
        e.i64(label::SIGNER_CERTIFICATES_JWT)?
            .array(headers.signer_certificates_jwt.len() as u64)?;
        for jwt in &headers.signer_certificates_jwt {
            e.str(jwt)?;
        }
    }
    Ok(())
}

/// How many map entries the claims-capable tail contributes (crit + content
/// type + claims map + basil labels).
fn claims_capable_tail_len(
    claims: Option<&Claims>,
    protected_headers: Option<&ProtectedHeaders>,
) -> u64 {
    2 + claims.map_or(0, |c| 1 + basil_labels(c).len() as u64)
        + u64::from(
            protected_headers.is_some_and(|headers| !headers.signer_certificates_jwt.is_empty()),
        )
}

/// Serialize the protected header of a bare (signed) `COSE_Sign1` with
/// additional critical protected headers. `algorithm` is the signer's
/// signature algorithm (its codepoint is the `alg` header value).
pub fn encode_sign1_protected_bare_with_headers(
    algorithm: SignatureAlgorithm,
    kid: &KeyId,
    content_type: &ContentType,
    claims: Option<&Claims>,
    protected_headers: Option<&ProtectedHeaders>,
) -> Result<Vec<u8>, CodecError> {
    encode_with(|e| {
        e.map(2 + claims_capable_tail_len(claims, protected_headers))?;
        e.i64(label::HDR_ALG)?.i64(algorithm.codepoint())?;
        write_claims_capable_tail(e, content_type, claims, protected_headers, Some(kid))
    })
}

/// Serialize the protected header of a sealed-construction outer
/// `COSE_Sign1` (exactly `alg` + `kid`).
pub fn encode_sign1_protected_sealed_outer(
    algorithm: SignatureAlgorithm,
    kid: &KeyId,
) -> Result<Vec<u8>, CodecError> {
    encode_with(|e| {
        e.map(2)?;
        e.i64(label::HDR_ALG)?.i64(algorithm.codepoint())?;
        e.i64(label::HDR_KID)?.bytes(kid.as_bytes())?;
        Ok(())
    })
}

/// Serialize the content-layer protected header of a `COSE_Encrypt`.
pub fn encode_encrypt_protected(
    content_algorithm: ContentAlgorithm,
    content_type: &ContentType,
    claims: Option<&Claims>,
) -> Result<Vec<u8>, CodecError> {
    encode_with(|e| {
        e.map(1 + claims_capable_tail_len(claims, None))?;
        e.i64(label::HDR_ALG)?.i64(content_algorithm.codepoint())?;
        write_claims_capable_tail(e, content_type, claims, None, None)
    })
}

/// The party-identity labels present, in canonical order.
fn party_labels(parties: &KdfParties) -> Vec<i64> {
    let mut labels = Vec::new();
    if parties.party_u.as_bytes().is_some() {
        labels.push(label::HDR_PARTY_U_IDENTITY);
    }
    if parties.party_v.as_bytes().is_some() {
        labels.push(label::HDR_PARTY_V_IDENTITY);
    }
    labels
}

/// Serialize the recipient-layer protected header: the key-agreement
/// algorithm plus any KDF party identities (`-21`/`-24`), which are listed
/// in that layer's `crit` when present (design §4.3).
pub fn encode_recipient_protected(parties: &KdfParties) -> Result<Vec<u8>, CodecError> {
    encode_with(|e| {
        let party = party_labels(parties);
        let n = 1 + u64::from(!party.is_empty()) + party.len() as u64;
        e.map(n)?;
        e.i64(label::HDR_ALG)?
            .i64(crate::alg::KeyAgreementAlgorithm::EcdhEsHkdf256.codepoint())?;
        if !party.is_empty() {
            e.i64(label::HDR_CRIT)?.array(party.len() as u64)?;
            for l in &party {
                e.i64(*l)?;
            }
        }
        if let Some(id) = parties.party_u.as_bytes() {
            e.i64(label::HDR_PARTY_U_IDENTITY)?.bytes(id)?;
        }
        if let Some(id) = parties.party_v.as_bytes() {
            e.i64(label::HDR_PARTY_V_IDENTITY)?.bytes(id)?;
        }
        Ok(())
    })
}

/// Assemble a complete tagged `COSE_Sign1`.
pub fn assemble_sign1(
    protected: &[u8],
    payload: &[u8],
    signature: &[u8],
) -> Result<Vec<u8>, CodecError> {
    encode_with(|e| {
        e.tag(minicbor::data::Tag::new(TAG_SIGN1))?;
        e.array(4)?;
        e.bytes(protected)?;
        e.map(0)?;
        e.bytes(payload)?;
        e.bytes(signature)?;
        Ok(())
    })
}

/// The pieces of a `COSE_Encrypt` to assemble.
pub struct EncryptAssembly<'a> {
    /// Content-layer protected header bytes.
    pub protected: &'a [u8],
    /// The AEAD nonce.
    pub iv: &'a [u8; NONCE_LEN],
    /// The AEAD ciphertext (including the tag).
    pub ciphertext: &'a [u8],
    /// Recipient-layer protected header bytes.
    pub recipient_protected: &'a [u8],
    /// The recipient static key id.
    pub recipient_kid: &'a KeyId,
    /// The sender's ephemeral X25519 public key.
    pub ephemeral_x: &'a [u8; X25519_LEN],
}

/// Assemble a complete tagged single-recipient `COSE_Encrypt`.
pub fn assemble_encrypt(a: &EncryptAssembly<'_>) -> Result<Vec<u8>, CodecError> {
    encode_with(|e| {
        e.tag(minicbor::data::Tag::new(TAG_ENCRYPT))?;
        e.array(4)?;
        e.bytes(a.protected)?;
        // Content unprotected: {5: iv}.
        e.map(1)?;
        e.i64(label::HDR_IV)?.bytes(a.iv)?;
        e.bytes(a.ciphertext)?;
        // recipients: [[protected, {4: kid, -1: ephemeral OKP key}, null]]
        e.array(1)?;
        e.array(3)?;
        e.bytes(a.recipient_protected)?;
        e.map(2)?;
        e.i64(label::HDR_KID)?.bytes(a.recipient_kid.as_bytes())?;
        e.i64(label::HDR_EPHEMERAL_KEY)?;
        e.map(3)?;
        e.i64(1)?.i64(1)?; // kty: OKP
        e.i64(-1)?.i64(4)?; // crv: X25519
        e.i64(-2)?.bytes(a.ephemeral_x)?; // x
        e.null()?;
        Ok(())
    })
}

/// Build the `Sig_structure` (`["Signature1", protected, external_aad,
/// payload]`) that is signed/verified.
pub fn sig_structure(
    protected: &[u8],
    external_aad: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, CodecError> {
    encode_with(|e| {
        e.array(4)?;
        e.str("Signature1")?;
        e.bytes(protected)?;
        e.bytes(external_aad)?;
        e.bytes(payload)?;
        Ok(())
    })
}

/// Build the `Enc_structure` (`["Encrypt", protected, external_aad]`) used
/// as the AEAD associated data. `protected` is the exact serialized
/// content-layer protected header bytes.
pub fn enc_structure(protected: &[u8], external_aad: &[u8]) -> Result<Vec<u8>, CodecError> {
    encode_with(|e| {
        e.array(3)?;
        e.str("Encrypt")?;
        e.bytes(protected)?;
        e.bytes(external_aad)?;
        Ok(())
    })
}

/// Build the RFC 9053 §5.2 `COSE_KDF_Context` used as the HKDF info:
/// `[alg, [PartyU identity, nil, nil], [PartyV identity, nil, nil],
/// [256, recipient_protected]]`.
pub fn kdf_context(
    content_algorithm: ContentAlgorithm,
    parties: &KdfParties,
    recipient_protected: &[u8],
) -> Result<Vec<u8>, CodecError> {
    encode_with(|e| {
        e.array(4)?;
        e.i64(content_algorithm.codepoint())?;
        for identity in [&parties.party_u, &parties.party_v] {
            e.array(3)?;
            match identity.as_bytes() {
                Some(id) => e.bytes(id)?,
                None => e.null()?,
            };
            e.null()?;
            e.null()?;
        }
        e.array(2)?;
        e.u64(8 * content_algorithm.key_len() as u64)?;
        e.bytes(recipient_protected)?;
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Strict decoding
// ---------------------------------------------------------------------------

/// Whether a claims-capable layer must or must not carry claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimsExpectation {
    /// Claims must be present (the sealed embedded `COSE_Encrypt`).
    Required,
    /// Claims must be absent (the seal-only `COSE_Encrypt`).
    Forbidden,
    /// Claims may be present (the bare signed `COSE_Sign1`).
    Optional,
}

/// Which `COSE_Sign1` layer shape to demand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sign1Layer {
    /// Bare signed construction: content type in the protected header,
    /// claims optional.
    Bare,
    /// Sealed-construction outer layer: exactly `alg` + `kid`.
    SealedOuter,
}

/// A strictly decoded `COSE_Sign1`.
#[derive(Debug, Clone)]
pub struct DecodedSign1 {
    /// Exact protected header bytes (feeds `Sig_structure`).
    pub protected: Vec<u8>,
    /// The signature algorithm from the `alg` protected header.
    pub algorithm: SignatureAlgorithm,
    /// The signer key id from the protected header.
    pub kid: KeyId,
    /// The content type (present iff the layer is [`Sign1Layer::Bare`]).
    pub content_type: Option<ContentType>,
    /// Claims, when present (only on [`Sign1Layer::Bare`]).
    pub claims: Option<Claims>,
    /// Additional protected headers, when present.
    pub protected_headers: ProtectedHeaders,
    /// The payload bytes.
    pub payload: Vec<u8>,
    /// The raw signature bytes.
    pub signature: Vec<u8>,
}

/// A strictly decoded single-recipient `COSE_Encrypt`.
#[derive(Debug, Clone)]
pub struct DecodedEncrypt {
    /// Exact content-layer protected header bytes (feeds `Enc_structure`).
    pub protected: Vec<u8>,
    /// The content-encryption algorithm.
    pub content_algorithm: ContentAlgorithm,
    /// The content type.
    pub content_type: ContentType,
    /// Claims, when the layer carries them.
    pub claims: Option<Claims>,
    /// The AEAD nonce.
    pub iv: [u8; NONCE_LEN],
    /// The AEAD ciphertext (including the tag).
    pub ciphertext: Vec<u8>,
    /// Exact recipient-layer protected header bytes (feeds the KDF context).
    pub recipient_protected: Vec<u8>,
    /// The recipient static key id.
    pub recipient_kid: KeyId,
    /// The sender's ephemeral X25519 public key.
    pub ephemeral_x: [u8; X25519_LEN],
    /// The KDF party identities from the recipient protected header.
    pub parties: KdfParties,
}

fn dt(d: &Decoder<'_>) -> Result<Type, DecodeError> {
    d.datatype().map_err(|_| DecodeError::Malformed)
}

const fn is_int(t: Type) -> bool {
    matches!(
        t,
        Type::U8
            | Type::U16
            | Type::U32
            | Type::U64
            | Type::I8
            | Type::I16
            | Type::I32
            | Type::I64
            | Type::Int
    )
}

/// Read an integer map label; text labels are outside the profile.
fn read_label(d: &mut Decoder<'_>) -> Result<i64, DecodeError> {
    let t = dt(d)?;
    if matches!(t, Type::String | Type::StringIndef) {
        return Err(DecodeError::TextLabel);
    }
    if !is_int(t) {
        return Err(DecodeError::Malformed);
    }
    d.i64().map_err(|_| DecodeError::Malformed)
}

fn read_bytes(d: &mut Decoder<'_>, l: i64) -> Result<Vec<u8>, DecodeError> {
    if dt(d)? != Type::Bytes {
        return Err(DecodeError::WrongType { label: l });
    }
    Ok(d.bytes().map_err(|_| DecodeError::Malformed)?.to_vec())
}

fn read_str(d: &mut Decoder<'_>, l: i64) -> Result<String, DecodeError> {
    if dt(d)? != Type::String {
        return Err(DecodeError::WrongType { label: l });
    }
    Ok(String::from(d.str().map_err(|_| DecodeError::Malformed)?))
}

fn read_string_array(d: &mut Decoder<'_>, l: i64) -> Result<Vec<String>, DecodeError> {
    let n = read_array_len(d)?;
    let mut out = Vec::new();
    for _ in 0..n {
        out.push(read_str(d, l)?);
    }
    Ok(out)
}

fn read_int(d: &mut Decoder<'_>, l: i64) -> Result<i64, DecodeError> {
    if !is_int(dt(d)?) {
        return Err(DecodeError::WrongType { label: l });
    }
    d.i64().map_err(|_| DecodeError::Malformed)
}

/// Read a CWT time value: whole seconds only.
fn read_time(d: &mut Decoder<'_>, l: i64) -> Result<i64, DecodeError> {
    let t = dt(d)?;
    if matches!(t, Type::F16 | Type::F32 | Type::F64) {
        return Err(DecodeError::FractionalTime);
    }
    if !is_int(t) {
        return Err(DecodeError::WrongType { label: l });
    }
    d.i64().map_err(|_| DecodeError::Malformed)
}

/// Read a definite map head.
fn read_map_len(d: &mut Decoder<'_>) -> Result<u64, DecodeError> {
    if dt(d)? != Type::Map {
        return Err(DecodeError::Malformed);
    }
    d.map()
        .map_err(|_| DecodeError::Malformed)?
        .ok_or(DecodeError::IndefiniteLength)
}

/// Read a definite array head.
fn read_array_len(d: &mut Decoder<'_>) -> Result<u64, DecodeError> {
    if dt(d)? != Type::Array {
        return Err(DecodeError::Malformed);
    }
    d.array()
        .map_err(|_| DecodeError::Malformed)?
        .ok_or(DecodeError::IndefiniteLength)
}

/// Enforce strictly ascending canonical label order within one map.
fn check_order(prev: Option<i64>, current: i64) -> Result<(), DecodeError> {
    prev.map_or(Ok(()), |p| {
        match canonical_sort_key(p).cmp(&canonical_sort_key(current)) {
            core::cmp::Ordering::Less => Ok(()),
            core::cmp::Ordering::Equal => Err(DecodeError::DuplicateLabel),
            core::cmp::Ordering::Greater => Err(DecodeError::NonDeterministicEncoding),
        }
    })
}

/// Parsed CWT claims map plus basil labels, before assembly into [`Claims`].
#[derive(Debug, Default)]
struct ClaimsParts {
    issuer: Option<Subject>,
    audience: Option<Subject>,
    expires_at: Option<UnixTime>,
    issued_at: Option<UnixTime>,
    message_id: Option<MessageId>,
    in_reply_to: Option<MessageId>,
    request_hash: Option<RequestHash>,
    sender_key_id: Option<KeyId>,
    response_key_id: Option<KeyId>,
    response_subject: Option<ResponseSubject>,
    cwt_present: bool,
    basil_present: bool,
}

impl ClaimsParts {
    fn into_claims(self) -> Result<Option<Claims>, DecodeError> {
        if !self.cwt_present {
            if self.basil_present {
                // Basil labels must be accompanied by the CWT map.
                return Err(DecodeError::MissingHeader {
                    label: label::HDR_CWT_CLAIMS,
                });
            }
            return Ok(None);
        }
        let issued_at = self.issued_at.ok_or(DecodeError::MissingClaim {
            claim: label::CWT_IAT,
        })?;
        let message_id = self.message_id.ok_or(DecodeError::MissingClaim {
            claim: label::CWT_CTI,
        })?;
        Ok(Some(Claims {
            issuer: self.issuer,
            audience: self.audience,
            expires_at: self.expires_at,
            issued_at,
            message_id,
            sender_key_id: self.sender_key_id,
            response_key_id: self.response_key_id,
            response_subject: self.response_subject,
            in_reply_to: self.in_reply_to,
            request_hash: self.request_hash,
        }))
    }
}

/// Parse the CWT claims map (header 15 value).
fn parse_cwt_map(d: &mut Decoder<'_>, parts: &mut ClaimsParts) -> Result<(), DecodeError> {
    let n = read_map_len(d)?;
    let mut prev = None;
    for _ in 0..n {
        let key = read_label(d)?;
        check_order(prev, key)?;
        prev = Some(key);
        match key {
            label::CWT_ISS => {
                parts.issuer = Some(Subject::new(read_str(d, key)?)?);
            }
            label::CWT_AUD => {
                parts.audience = Some(Subject::new(read_str(d, key)?)?);
            }
            label::CWT_EXP => {
                parts.expires_at = Some(UnixTime(read_time(d, key)?));
            }
            label::CWT_IAT => {
                parts.issued_at = Some(UnixTime(read_time(d, key)?));
            }
            label::CWT_CTI => {
                parts.message_id = Some(MessageId::from_bytes(read_bytes(d, key)?)?);
            }
            other => return Err(DecodeError::UnknownClaim { claim: other }),
        }
    }
    parts.cwt_present = true;
    Ok(())
}

/// Parse one basil private label into the claim parts. Returns `false` when
/// the label is not a basil label.
fn parse_basil_label(
    d: &mut Decoder<'_>,
    l: i64,
    parts: &mut ClaimsParts,
) -> Result<bool, DecodeError> {
    match l {
        label::IN_REPLY_TO => {
            parts.in_reply_to = Some(MessageId::from_bytes(read_bytes(d, l)?)?);
        }
        label::REQUEST_HASH => {
            let raw = read_bytes(d, l)?;
            let arr: [u8; 32] =
                raw.as_slice()
                    .try_into()
                    .map_err(|_| DecodeError::InvalidLength {
                        label: l,
                        expected: 32,
                        actual: raw.len(),
                    })?;
            parts.request_hash = Some(RequestHash(arr));
        }
        label::SENDER_KEY_ID => {
            parts.sender_key_id = Some(KeyId::from_bytes(read_bytes(d, l)?)?);
        }
        label::RESPONSE_KEY_ID => {
            parts.response_key_id = Some(KeyId::from_text(&read_str(d, l)?)?);
        }
        label::RESPONSE_SUBJECT => {
            parts.response_subject = Some(ResponseSubject::new(read_str(d, l)?)?);
        }
        _ => return Ok(false),
    }
    parts.basil_present = true;
    Ok(true)
}

/// Parse the crit array into a label list. RFC 9052 §3.1: the array must
/// have at least one entry.
fn parse_crit(d: &mut Decoder<'_>) -> Result<Vec<i64>, DecodeError> {
    let n = read_array_len(d)?;
    if n == 0 {
        return Err(DecodeError::WrongType {
            label: label::HDR_CRIT,
        });
    }
    let mut out = Vec::new();
    for _ in 0..n {
        out.push(read_label(d)?);
    }
    Ok(out)
}

/// Check the crit list against the profile expectation for this header.
fn check_crit(actual: Option<&Vec<i64>>, expected: &[i64]) -> Result<(), DecodeError> {
    let Some(actual) = actual else {
        return Err(DecodeError::CritMissing);
    };
    if actual.as_slice() == expected {
        return Ok(());
    }
    // Diagnose: a listed-but-unexpected label, an expected-but-unlisted
    // label, or (same sets) a non-canonical ordering.
    for l in actual {
        if !expected.contains(l) {
            return Err(DecodeError::CritUnexpected { label: *l });
        }
    }
    for l in expected {
        if !actual.contains(l) {
            return Err(DecodeError::CritIncomplete { label: *l });
        }
    }
    Err(DecodeError::NonDeterministicEncoding)
}

/// Fields shared by the claims-capable protected headers (bare `COSE_Sign1`
/// and the `COSE_Encrypt` content layer).
#[derive(Debug)]
struct ClaimsCapableHeader {
    alg: i64,
    crit: Option<Vec<i64>>,
    content_type: Option<ContentType>,
    kid: Option<KeyId>,
    claims: Option<Claims>,
    protected_headers: ProtectedHeaders,
}

/// Parse a claims-capable protected header map. `allow_kid` distinguishes
/// the bare `COSE_Sign1` header (kid required) from the encrypt content
/// layer (kid forbidden).
fn parse_claims_capable_header(
    bytes: &[u8],
    allow_kid: bool,
) -> Result<ClaimsCapableHeader, DecodeError> {
    if bytes.is_empty() {
        return Err(DecodeError::MissingHeader {
            label: label::HDR_ALG,
        });
    }
    precheck::scan(bytes)?;
    let mut d = Decoder::new(bytes);
    let n = read_map_len(&mut d)?;
    let mut prev = None;
    let mut alg = None;
    let mut crit = None;
    let mut content_type = None;
    let mut kid = None;
    let mut parts = ClaimsParts::default();
    let mut protected_headers = ProtectedHeaders::default();
    for _ in 0..n {
        let l = read_label(&mut d)?;
        check_order(prev, l)?;
        prev = Some(l);
        match l {
            label::HDR_ALG => alg = Some(read_int(&mut d, l)?),
            label::HDR_CRIT => crit = Some(parse_crit(&mut d)?),
            label::HDR_CONTENT_TYPE => {
                content_type = Some(ContentType::new(read_str(&mut d, l)?)?);
            }
            label::HDR_KID if allow_kid => {
                kid = Some(KeyId::from_bytes(read_bytes(&mut d, l)?)?);
            }
            label::HDR_CWT_CLAIMS => parse_cwt_map(&mut d, &mut parts)?,
            label::SIGNER_CERTIFICATES_JWT if allow_kid => {
                protected_headers.signer_certificates_jwt = read_string_array(&mut d, l)?;
            }
            other => {
                if !parse_basil_label(&mut d, other, &mut parts)? {
                    return Err(DecodeError::UnknownLabel { label: other });
                }
            }
        }
    }
    let alg = alg.ok_or(DecodeError::MissingHeader {
        label: label::HDR_ALG,
    })?;
    let claims = parts.into_claims()?;
    Ok(ClaimsCapableHeader {
        alg,
        crit,
        content_type,
        kid,
        claims,
        protected_headers,
    })
}

/// Validate a claims-capable header against the profile: content type
/// required, crit exact, claims per expectation.
fn finish_claims_capable(
    h: &ClaimsCapableHeader,
    expectation: ClaimsExpectation,
) -> Result<(), DecodeError> {
    if h.content_type.is_none() {
        return Err(DecodeError::MissingHeader {
            label: label::HDR_CONTENT_TYPE,
        });
    }
    match (expectation, &h.claims) {
        (ClaimsExpectation::Required, None) => {
            return Err(DecodeError::MissingHeader {
                label: label::HDR_CWT_CLAIMS,
            });
        }
        (ClaimsExpectation::Forbidden, Some(_)) => {
            return Err(DecodeError::UnknownLabel {
                label: label::HDR_CWT_CLAIMS,
            });
        }
        _ => {}
    }
    check_crit(
        h.crit.as_ref(),
        &crit_labels(h.claims.as_ref(), Some(&h.protected_headers)),
    )
}

/// Parse an unprotected header map that the profile requires to hold exactly
/// `allowed` (label, kind) entries. Claims labels are always rejected as
/// [`DecodeError::ClaimsInUnprotected`].
fn parse_unprotected<'b>(
    d: &mut Decoder<'b>,
    mut on_entry: impl FnMut(&mut Decoder<'b>, i64) -> Result<bool, DecodeError>,
) -> Result<(), DecodeError> {
    let n = read_map_len(d)?;
    let mut prev = None;
    for _ in 0..n {
        let l = read_label(d)?;
        check_order(prev, l)?;
        prev = Some(l);
        if CLAIM_LABELS.contains(&l) {
            return Err(DecodeError::ClaimsInUnprotected);
        }
        if !on_entry(d, l)? {
            return Err(DecodeError::UnknownLabel { label: l });
        }
    }
    Ok(())
}

/// Check the top-level tag from the precheck scan.
const fn check_tag(scan: precheck::Scan, expected: u64) -> Result<(), DecodeError> {
    match scan.top_tag {
        None => Err(DecodeError::NotTagged),
        Some(t) if t == expected => Ok(()),
        Some(t) => Err(DecodeError::WrongTag {
            expected,
            actual: t,
        }),
    }
}

/// Strictly decode a tagged `COSE_Sign1`, including the re-encode
/// determinism check.
pub fn decode_sign1_strict(bytes: &[u8], layer: Sign1Layer) -> Result<DecodedSign1, DecodeError> {
    check_tag(precheck::scan(bytes)?, TAG_SIGN1)?;
    let mut d = Decoder::new(bytes);
    d.tag().map_err(|_| DecodeError::Malformed)?;
    if read_array_len(&mut d)? != 4 {
        return Err(DecodeError::Malformed);
    }
    if dt(&d)? != Type::Bytes {
        return Err(DecodeError::Malformed);
    }
    let protected = d.bytes().map_err(|_| DecodeError::Malformed)?.to_vec();

    // Unprotected: must be empty for both Sign1 layers.
    parse_unprotected(&mut d, |_, _| Ok(false))?;

    let payload = match dt(&d)? {
        Type::Bytes => d.bytes().map_err(|_| DecodeError::Malformed)?.to_vec(),
        Type::Null => return Err(DecodeError::MissingPayload),
        _ => return Err(DecodeError::Malformed),
    };
    let signature = read_bytes(&mut d, 0).map_err(|_| DecodeError::Malformed)?;
    if signature.is_empty() {
        return Err(DecodeError::Malformed);
    }

    let (algorithm, kid, content_type, claims, protected_headers, rebuilt_protected) = match layer {
        Sign1Layer::Bare => {
            let h = parse_claims_capable_header(&protected, true)?;
            let algorithm = SignatureAlgorithm::from_codepoint(h.alg)
                .ok_or(DecodeError::UnknownAlgorithm { alg: h.alg })?;
            finish_claims_capable(&h, ClaimsExpectation::Optional)?;
            let kid = h.kid.ok_or(DecodeError::MissingHeader {
                label: label::HDR_KID,
            })?;
            let Some(content_type) = h.content_type else {
                return Err(DecodeError::MissingHeader {
                    label: label::HDR_CONTENT_TYPE,
                });
            };
            let rebuilt = encode_sign1_protected_bare_with_headers(
                algorithm,
                &kid,
                &content_type,
                h.claims.as_ref(),
                Some(&h.protected_headers),
            )
            .map_err(|CodecError| DecodeError::NonDeterministicEncoding)?;
            (
                algorithm,
                kid,
                Some(content_type),
                h.claims,
                h.protected_headers,
                rebuilt,
            )
        }
        Sign1Layer::SealedOuter => {
            let (algorithm, kid) = parse_sealed_outer_protected(&protected)?;
            let rebuilt = encode_sign1_protected_sealed_outer(algorithm, &kid)
                .map_err(|CodecError| DecodeError::NonDeterministicEncoding)?;
            (
                algorithm,
                kid,
                None,
                None,
                ProtectedHeaders::default(),
                rebuilt,
            )
        }
    };

    let rebuilt = assemble_sign1(&rebuilt_protected, &payload, &signature)
        .map_err(|CodecError| DecodeError::NonDeterministicEncoding)?;
    if rebuilt != bytes {
        return Err(DecodeError::NonDeterministicEncoding);
    }

    Ok(DecodedSign1 {
        protected,
        algorithm,
        kid,
        content_type,
        claims,
        protected_headers,
        payload,
        signature,
    })
}

/// Parse the sealed-outer protected header: exactly `{1: alg, 4: kid}`, where
/// `alg` is a profile signature algorithm. Returns the algorithm and key id.
fn parse_sealed_outer_protected(bytes: &[u8]) -> Result<(SignatureAlgorithm, KeyId), DecodeError> {
    if bytes.is_empty() {
        return Err(DecodeError::MissingHeader {
            label: label::HDR_ALG,
        });
    }
    precheck::scan(bytes)?;
    let mut d = Decoder::new(bytes);
    let n = read_map_len(&mut d)?;
    let mut prev = None;
    let mut alg = None;
    let mut kid = None;
    for _ in 0..n {
        let l = read_label(&mut d)?;
        check_order(prev, l)?;
        prev = Some(l);
        match l {
            label::HDR_ALG => alg = Some(read_int(&mut d, l)?),
            label::HDR_KID => kid = Some(KeyId::from_bytes(read_bytes(&mut d, l)?)?),
            other => return Err(DecodeError::UnknownLabel { label: other }),
        }
    }
    let alg = alg.ok_or(DecodeError::MissingHeader {
        label: label::HDR_ALG,
    })?;
    let algorithm =
        SignatureAlgorithm::from_codepoint(alg).ok_or(DecodeError::UnknownAlgorithm { alg })?;
    let kid = kid.ok_or(DecodeError::MissingHeader {
        label: label::HDR_KID,
    })?;
    Ok((algorithm, kid))
}

/// Parse the recipient protected header:
/// `{1: -25, ?2: crit, ?-21: bstr, ?-24: bstr}`, where `crit` must list
/// exactly the party-identity labels present.
fn parse_recipient_protected(bytes: &[u8]) -> Result<KdfParties, DecodeError> {
    if bytes.is_empty() {
        return Err(DecodeError::MissingHeader {
            label: label::HDR_ALG,
        });
    }
    precheck::scan(bytes)?;
    let mut d = Decoder::new(bytes);
    let n = read_map_len(&mut d)?;
    let mut prev = None;
    let mut alg = None;
    let mut crit = None;
    let mut party_u = PartyIdentity::nil();
    let mut party_v = PartyIdentity::nil();
    for _ in 0..n {
        let l = read_label(&mut d)?;
        check_order(prev, l)?;
        prev = Some(l);
        match l {
            label::HDR_ALG => alg = Some(read_int(&mut d, l)?),
            label::HDR_CRIT => crit = Some(parse_crit(&mut d)?),
            label::HDR_PARTY_U_IDENTITY => {
                party_u = PartyIdentity::from_bytes(read_bytes(&mut d, l)?)?;
            }
            label::HDR_PARTY_V_IDENTITY => {
                party_v = PartyIdentity::from_bytes(read_bytes(&mut d, l)?)?;
            }
            other => return Err(DecodeError::UnknownLabel { label: other }),
        }
    }
    let alg = alg.ok_or(DecodeError::MissingHeader {
        label: label::HDR_ALG,
    })?;
    if crate::alg::KeyAgreementAlgorithm::from_codepoint(alg).is_none() {
        return Err(DecodeError::UnknownAlgorithm { alg });
    }
    let parties = KdfParties { party_u, party_v };
    let expected = party_labels(&parties);
    if expected.is_empty() {
        if let Some(crit) = crit {
            // parse_crit rejects empty arrays, so an entry exists; the
            // fallback keeps this arm panic-free regardless.
            let l = crit.first().copied().unwrap_or(label::HDR_CRIT);
            return Err(DecodeError::CritUnexpected { label: l });
        }
    } else {
        check_crit(crit.as_ref(), &expected)?;
    }
    Ok(parties)
}

/// Parse the ephemeral OKP/X25519 key map: exactly
/// `{1: 1, -1: 4, -2: bstr(32)}`.
fn parse_ephemeral_key(d: &mut Decoder<'_>) -> Result<[u8; X25519_LEN], DecodeError> {
    if dt(d)? != Type::Map {
        return Err(DecodeError::EphemeralKeyShape);
    }
    let n = d
        .map()
        .map_err(|_| DecodeError::Malformed)?
        .ok_or(DecodeError::IndefiniteLength)?;
    if n != 3 {
        return Err(DecodeError::EphemeralKeyShape);
    }
    let mut prev = None;
    let mut x: Option<[u8; X25519_LEN]> = None;
    let mut kty_ok = false;
    let mut crv_ok = false;
    for _ in 0..n {
        let l = read_label(d)?;
        check_order(prev, l)?;
        prev = Some(l);
        match l {
            1 => kty_ok = read_int(d, l)? == 1,
            -1 => crv_ok = read_int(d, l)? == 4,
            -2 => {
                let raw = read_bytes(d, l)?;
                x = Some(
                    raw.as_slice()
                        .try_into()
                        .map_err(|_| DecodeError::EphemeralKeyShape)?,
                );
            }
            _ => return Err(DecodeError::EphemeralKeyShape),
        }
    }
    if !kty_ok || !crv_ok {
        return Err(DecodeError::EphemeralKeyShape);
    }
    x.ok_or(DecodeError::EphemeralKeyShape)
}

/// Strictly decode a tagged single-recipient `COSE_Encrypt`, including the
/// re-encode determinism check.
// One linear walk over the fixed profile shape; splitting it into stages
// would scatter the strictness invariants this function is proving.
#[allow(clippy::too_many_lines)]
pub fn decode_encrypt_strict(
    bytes: &[u8],
    expectation: ClaimsExpectation,
) -> Result<DecodedEncrypt, DecodeError> {
    check_tag(precheck::scan(bytes)?, TAG_ENCRYPT)?;
    let mut d = Decoder::new(bytes);
    d.tag().map_err(|_| DecodeError::Malformed)?;
    if read_array_len(&mut d)? != 4 {
        return Err(DecodeError::Malformed);
    }
    if dt(&d)? != Type::Bytes {
        return Err(DecodeError::Malformed);
    }
    let protected = d.bytes().map_err(|_| DecodeError::Malformed)?.to_vec();

    // Content unprotected: exactly {5: iv(12)}.
    let mut iv: Option<[u8; NONCE_LEN]> = None;
    parse_unprotected(&mut d, |d, l| {
        if l != label::HDR_IV {
            return Ok(false);
        }
        let raw = read_bytes(d, l)?;
        let arr: [u8; NONCE_LEN] =
            raw.as_slice()
                .try_into()
                .map_err(|_| DecodeError::InvalidLength {
                    label: l,
                    expected: NONCE_LEN,
                    actual: raw.len(),
                })?;
        iv = Some(arr);
        Ok(true)
    })?;
    let iv = iv.ok_or(DecodeError::MissingHeader {
        label: label::HDR_IV,
    })?;

    let ciphertext = match dt(&d)? {
        Type::Bytes => d.bytes().map_err(|_| DecodeError::Malformed)?.to_vec(),
        Type::Null => return Err(DecodeError::MissingPayload),
        _ => return Err(DecodeError::Malformed),
    };

    let recipient_count = read_array_len(&mut d)?;
    if recipient_count != 1 {
        return Err(DecodeError::RecipientCount {
            count: usize::try_from(recipient_count).unwrap_or(usize::MAX),
        });
    }
    let recipient_len = read_array_len(&mut d)?;
    if recipient_len == 4 {
        return Err(DecodeError::NestedRecipients);
    }
    if recipient_len != 3 {
        return Err(DecodeError::Malformed);
    }
    if dt(&d)? != Type::Bytes {
        return Err(DecodeError::Malformed);
    }
    let recipient_protected = d.bytes().map_err(|_| DecodeError::Malformed)?.to_vec();

    // Recipient unprotected: exactly {4: kid, -1: ephemeral key}.
    let mut recipient_kid: Option<KeyId> = None;
    let mut ephemeral_x: Option<[u8; X25519_LEN]> = None;
    parse_unprotected(&mut d, |d, l| match l {
        label::HDR_KID => {
            recipient_kid = Some(KeyId::from_bytes(read_bytes(d, l)?)?);
            Ok(true)
        }
        label::HDR_EPHEMERAL_KEY => {
            ephemeral_x = Some(parse_ephemeral_key(d)?);
            Ok(true)
        }
        _ => Ok(false),
    })?;
    let recipient_kid = recipient_kid.ok_or(DecodeError::MissingHeader {
        label: label::HDR_KID,
    })?;
    let ephemeral_x = ephemeral_x.ok_or(DecodeError::MissingHeader {
        label: label::HDR_EPHEMERAL_KEY,
    })?;

    // Recipient ciphertext: nil for direct key agreement.
    match dt(&d)? {
        Type::Null => d.null().map_err(|_| DecodeError::Malformed)?,
        _ => return Err(DecodeError::RecipientCiphertextPresent),
    }

    // Content protected header.
    let h = parse_claims_capable_header(&protected, false)?;
    let Some(content_algorithm) = ContentAlgorithm::from_codepoint(h.alg) else {
        return Err(DecodeError::UnknownAlgorithm { alg: h.alg });
    };
    finish_claims_capable(&h, expectation)?;
    let Some(content_type) = h.content_type.clone() else {
        return Err(DecodeError::MissingHeader {
            label: label::HDR_CONTENT_TYPE,
        });
    };

    // Recipient protected header.
    let parties = parse_recipient_protected(&recipient_protected)?;

    // Determinism: rebuild from parsed semantics, require byte equality.
    let rebuilt_protected =
        encode_encrypt_protected(content_algorithm, &content_type, h.claims.as_ref())
            .map_err(|CodecError| DecodeError::NonDeterministicEncoding)?;
    let rebuilt_recipient_protected = encode_recipient_protected(&parties)
        .map_err(|CodecError| DecodeError::NonDeterministicEncoding)?;
    let rebuilt = assemble_encrypt(&EncryptAssembly {
        protected: &rebuilt_protected,
        iv: &iv,
        ciphertext: &ciphertext,
        recipient_protected: &rebuilt_recipient_protected,
        recipient_kid: &recipient_kid,
        ephemeral_x: &ephemeral_x,
    })
    .map_err(|CodecError| DecodeError::NonDeterministicEncoding)?;
    if rebuilt != bytes {
        return Err(DecodeError::NonDeterministicEncoding);
    }

    Ok(DecodedEncrypt {
        protected,
        content_algorithm,
        content_type,
        claims: h.claims,
        iv,
        ciphertext,
        recipient_protected,
        recipient_kid,
        ephemeral_x,
        parties,
    })
}
