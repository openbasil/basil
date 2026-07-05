// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! `basil-nats`: build NATS JWTs (the `ed25519-nkey` JWS profile) **without
//! holding the signing key**.
//!
//! NATS credentials (`nsc`-style) are JWTs signed by an Ed25519 `NKey`. This crate
//! produces the exact wire bytes a NATS server expects, but *splits signing out*:
//! you build the **signing input**, hand it to whatever holds the key (an HSM, a
//! `nkeys::KeyPair`, or a Vault transit engine) to produce a raw 64-byte
//! Ed25519 signature, then [`assemble`] the final token. The key never has to
//! enter this process, which is the whole point of using it from a broker.
//!
//! Wire format (matches `nats-io/jwt` v2 / `nsc`):
//! - header: `{"typ":"JWT","alg":"ed25519-nkey"}`
//! - `jti`: base32 (no pad) of **SHA-512/256** over the *standard* claims only
//!   (`aud,exp,jti="",iat,iss,name,nbf,sub`). The `nats` object is excluded.
//! - header & claims: `base64url` no-pad; signing input is `header.claims`.
//! - signature: raw 64-byte Ed25519, `base64url` no-pad, appended as the 3rd part.
//!
//! Claim *field order* does not affect validity (servers parse JSON), but the
//! `jti` hash is order-sensitive, so the hash struct mirrors `nats-io/jwt`.

// Index/slice in test code is fine (fixed test vectors); the no-panic
// `indexing_slicing` gate has no test-allow config option, unlike unwrap/expect.
#![cfg_attr(test, allow(clippy::indexing_slicing))]

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use crypto_secretbox::aead::{Aead, KeyInit};
use crypto_secretbox::{Key as SecretboxKey, Nonce as SecretboxNonce, XSalsa20Poly1305};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::RngCore;
use salsa20::cipher::consts::{U10, U16};
use salsa20::hsalsa;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha512_256};
use std::collections::BTreeMap;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// The fixed JWS header for NATS tokens (`typ` before `alg`, as `nsc` emits).
const HEADER_JSON: &str = r#"{"typ":"JWT","alg":"ed25519-nkey"}"#;
const XKEY_VERSION_V1: &[u8; 4] = b"xkv1";
const XKEY_NONCE_LEN: usize = 24;
const XKEY_TAG_LEN: usize = 16;

/// The role of a public NATS `NKey`, identified by its single base32 prefix
/// letter (the first character of an encoded key string).
///
/// # Wire derivation
///
/// A public key's wire form is `prefix_byte || 32-byte key || crc16`, base32
/// encoded. base32 packs 5 bits per output character, so the first character is
/// exactly the top 5 bits of `prefix_byte`. NATS chooses the role value so that
/// first character *is* the role letter: `prefix_byte = base32_index(letter) << 3`,
/// which lands the letter's 5-bit alphabet index in the high 5 bits and leaves
/// the low 3 bits zero. Those 3 bits just roll into the *second* base32 character
/// with the top 2 bits of the key. (base32 alphabet
/// `ABCDEFGHIJKLMNOPQRSTUVWXYZ234567`: A=0 C=2 N=13 O=14 U=20 X=23.)
///
/// (SEED keys look different, `SU`/`SA`/`SO`, because a seed is *not*
/// `role << 3`: it OR-packs an `S` marker with the role and spills the role's low
/// bits into a second header byte. Only *public* keys are encoded here, so the
/// simple `role << 3` form holds.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NkeyType {
    /// Account key (`A…`).
    Account,
    /// Cluster key (`C…`).
    Cluster,
    /// Server key (`N…`).
    Server,
    /// Operator key (`O…`).
    Operator,
    /// User key (`U…`).
    User,
    /// Curve / x25519 (`xkey`) key (`X…`); also NATS's catch-all role.
    Curve,
}

impl NkeyType {
    /// Every supported public role, in prefix-letter order: the lookup table
    /// backing the letter/byte conversions.
    const ALL: [Self; 6] = [
        Self::Account,
        Self::Cluster,
        Self::Server,
        Self::Operator,
        Self::User,
        Self::Curve,
    ];

    /// The role's `NKey` prefix letter (the first character of an encoded key).
    #[must_use]
    pub const fn letter(self) -> char {
        match self {
            Self::Account => 'A',
            Self::Cluster => 'C',
            Self::Server => 'N',
            Self::Operator => 'O',
            Self::User => 'U',
            Self::Curve => 'X',
        }
    }

    /// The wire prefix byte (`base32_index(letter) << 3`) this role encodes to.
    #[must_use]
    pub const fn prefix_byte(self) -> u8 {
        // base32 index of `letter`, shifted into the high 5 bits (low 3 zero).
        match self {
            Self::Account => 0,        // 'A' (index 0; 0 << 3 == 0)
            Self::Cluster => 2 << 3,   // 'C'
            Self::Server => 13 << 3,   // 'N'
            Self::Operator => 14 << 3, // 'O'
            Self::User => 20 << 3,     // 'U'
            Self::Curve => 23 << 3,    // 'X'
        }
    }

    /// Parse a role from its prefix letter, or `None` if `letter` is not one of
    /// the supported public roles (`A`/`C`/`N`/`O`/`U`/`X`).
    #[must_use]
    pub fn from_letter(letter: char) -> Option<Self> {
        Self::ALL.into_iter().find(|role| role.letter() == letter)
    }

    /// Parse a role from a decoded wire prefix byte, or `None` if it is not a
    /// known public role prefix.
    #[must_use]
    fn from_prefix_byte(byte: u8) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|role| role.prefix_byte() == byte)
    }
}

impl std::fmt::Display for NkeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.letter())
    }
}

#[derive(Debug)]
pub enum Error {
    /// A public key was not the expected 32 bytes.
    BadPublicKeyLen(usize),
    /// A decoded `NKey` carried a prefix letter that is not a known public
    /// role. The supported public-key roles are `A` account, `C` cluster, `N`
    /// server, `O` operator, `U` user, and `X` curve/x25519.
    UnsupportedPrefix(char),
    /// A public `NKey` decoded cleanly, but its [`NkeyType`] did not match the
    /// role required for the claim shape being minted.
    UnexpectedPrefix {
        expected: NkeyType,
        actual: NkeyType,
    },
    /// JSON serialization failed (should not happen for these types).
    Json(serde_json::Error),
    /// A caller-supplied claim document is not a NATS JWT claim object.
    InvalidClaims(String),
    /// A compact JWT was not a valid NATS JWT.
    MalformedJwt(String),
    /// A compact JWT signature segment did not decode to a 64-byte Ed25519
    /// signature.
    BadSignatureLen(usize),
    /// A NATS xkey operation was given a non-curve public `NKey`.
    UnexpectedXKeyPrefix(NkeyType),
    /// A NATS xkey ciphertext did not carry the `xkv1` version prefix.
    BadXKeyVersion,
    /// A NATS xkey ciphertext was too short to contain version, nonce, and tag.
    BadXKeyCiphertextLen(usize),
    /// NATS xkey encryption failed.
    XKeySealFailed,
    /// NATS xkey authentication failed on open.
    XKeyOpenFailed,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadPublicKeyLen(n) => write!(f, "expected a 32-byte Ed25519 public key, got {n}"),
            Self::UnsupportedPrefix(c) => write!(f, "unsupported NKey prefix letter: {c}"),
            Self::UnexpectedPrefix { expected, actual } => {
                write!(f, "expected NKey role {expected}, got {actual}")
            }
            Self::Json(e) => write!(f, "json error: {e}"),
            Self::InvalidClaims(message) | Self::MalformedJwt(message) => f.write_str(message),
            Self::BadSignatureLen(n) => write!(f, "expected a 64-byte Ed25519 signature, got {n}"),
            Self::UnexpectedXKeyPrefix(actual) => {
                write!(f, "expected curve xkey prefix X, got {actual}")
            }
            Self::BadXKeyVersion => f.write_str("NATS xkey ciphertext has unsupported version"),
            Self::BadXKeyCiphertextLen(n) => {
                write!(f, "NATS xkey ciphertext is too short: {n} bytes")
            }
            Self::XKeySealFailed => f.write_str("NATS xkey seal failed"),
            Self::XKeyOpenFailed => f.write_str("NATS xkey open failed"),
        }
    }
}
impl std::error::Error for Error {}
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

// ---------------------------------------------------------------------------
// NKey encoding
// ---------------------------------------------------------------------------

/// CRC-16/XMODEM (poly `0x1021`, init `0x0000`), the checksum NATS `NKeys` use.
fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in data {
        crc ^= u16::from(b) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

fn encode_nkey(prefix: u8, public: &[u8]) -> Result<String, Error> {
    if public.len() != 32 {
        return Err(Error::BadPublicKeyLen(public.len()));
    }
    let mut raw = Vec::with_capacity(1 + 32 + 2);
    raw.push(prefix);
    raw.extend_from_slice(public);
    let crc = crc16(&raw);
    raw.push((crc & 0xff) as u8); // little-endian
    raw.push((crc >> 8) as u8);
    Ok(data_encoding::BASE32_NOPAD.encode(&raw))
}

/// Encode a raw 32-byte public key as the public `NKey` for `role`.
///
/// This is the catalog-driven path: an issuer key's `nats_type` label maps to an
/// [`NkeyType`], and the broker encodes its backend public half accordingly. The
/// bytes are encoded as-is. For [`NkeyType::Curve`] the caller is responsible
/// for the key actually being an x25519/curve key (the role only sets the prefix
/// letter, not the algorithm).
///
/// # Errors
///
/// [`Error::BadPublicKeyLen`] if `public` is not 32 bytes.
pub fn encode_public(role: NkeyType, public: &[u8]) -> Result<String, Error> {
    encode_nkey(role.prefix_byte(), public)
}

/// Decode any public `NKey` string back to its [`NkeyType`] role and raw 32-byte
/// Ed25519 key, verifying the CRC.
///
/// # Errors
///
/// - [`Error::BadPublicKeyLen`] if `nkey` is not a valid public `NKey` payload
///   (bad base32, wrong length, or CRC mismatch).
/// - [`Error::UnsupportedPrefix`] if the decoded prefix is not a known public
///   role.
pub fn decode_public(nkey: &str) -> Result<(NkeyType, [u8; 32]), Error> {
    let raw = data_encoding::BASE32_NOPAD
        .decode(nkey.as_bytes())
        .map_err(|_| Error::BadPublicKeyLen(0))?;
    // Destructure the 35-byte layout (1 prefix + 32 key + 2 CRC) into
    // fixed-size chunks. `split_at_checked` proves each length to the compiler
    // so no slice index can panic; the CRC covers prefix+key (`body`).
    let Some((body, crc_bytes)) = raw.split_at_checked(33) else {
        return Err(Error::BadPublicKeyLen(raw.len()));
    };
    let (Ok(crc_bytes), Some((&prefix, key))) =
        (<[u8; 2]>::try_from(crc_bytes), body.split_first())
    else {
        return Err(Error::BadPublicKeyLen(raw.len()));
    };
    let Ok(key) = <[u8; 32]>::try_from(key) else {
        return Err(Error::BadPublicKeyLen(raw.len()));
    };
    let crc = u16::from_le_bytes(crc_bytes);
    if crc != crc16(body) {
        return Err(Error::BadPublicKeyLen(raw.len()));
    }
    let role = NkeyType::from_prefix_byte(prefix)
        .ok_or_else(|| Error::UnsupportedPrefix(nkey.chars().next().unwrap_or('?')))?;
    Ok((role, key))
}

/// Decode a public `NKey` and require a specific [`NkeyType`] role.
///
/// # Errors
///
/// - [`Error::BadPublicKeyLen`] if `nkey` is not a valid public `NKey` payload.
/// - [`Error::UnsupportedPrefix`] if its prefix is not a supported public role.
/// - [`Error::UnexpectedPrefix`] if the key is valid but has the wrong role.
pub fn require_public_prefix(nkey: &str, expected: NkeyType) -> Result<[u8; 32], Error> {
    let (actual, key) = decode_public(nkey)?;
    if actual != expected {
        return Err(Error::UnexpectedPrefix { expected, actual });
    }
    Ok(key)
}

/// Verify a raw Ed25519 signature against a public `NKey`.
///
/// This is the sealed-invocation trust-anchor path: policy stores the public
/// `NKey`, the caller supplies the signed transcript bytes and raw 64-byte
/// signature, and Basil verifies without parsing a JWT.
///
/// # Errors
///
/// Returns [`Error`] when `nkey` is malformed or `signature` is not a 64-byte
/// Ed25519 signature.
pub fn verify_public_signature(
    nkey: &str,
    message: &[u8],
    signature: &[u8],
) -> Result<bool, Error> {
    let (_, public_key) = decode_public(nkey)?;
    let signature =
        <[u8; 64]>::try_from(signature).map_err(|_| Error::BadSignatureLen(signature.len()))?;
    Ok(verify_ed25519(&public_key, message, &signature))
}

/// Derive a public xkey from raw 32-byte X25519 private material.
#[must_use]
pub fn xkey_public_from_private(private: &Zeroizing<[u8; 32]>) -> [u8; 32] {
    let secret = StaticSecret::from(**private);
    X25519PublicKey::from(&secret).to_bytes()
}

/// Encrypt a small payload using the NATS xkey authenticated box format.
///
/// The wire format matches `nats-io/nkeys`: `xkv1 || 24-byte nonce ||
/// XSalsa20-Poly1305 ciphertext`. The sender private is materialized by the
/// caller and zeroized there; this function keeps ECDH and derived-key
/// intermediates in zeroizing buffers.
///
/// # Errors
///
/// Returns [`Error::UnexpectedXKeyPrefix`] when `recipient_public_xkey` is not an
/// `X...` public key, [`Error::BadPublicKeyLen`] for malformed nkeys, or
/// [`Error::XKeySealFailed`] for low-order keys or an AEAD failure.
pub fn seal_nats_curve(
    sender_private: &Zeroizing<[u8; 32]>,
    recipient_public_xkey: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let recipient_public = decode_xkey_public(recipient_public_xkey)?;
    let mut nonce = [0u8; XKEY_NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ciphertext = box_crypt(
        sender_private,
        &recipient_public,
        &nonce,
        plaintext,
        BoxMode::Seal,
    )?;
    let mut out = Vec::with_capacity(XKEY_VERSION_V1.len() + nonce.len() + ciphertext.len());
    out.extend_from_slice(XKEY_VERSION_V1);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a NATS xkey authenticated box.
///
/// # Errors
///
/// Returns [`Error::BadXKeyVersion`] / [`Error::BadXKeyCiphertextLen`] for
/// malformed wire bytes, [`Error::UnexpectedXKeyPrefix`] for a non-`X...` sender
/// key, or [`Error::XKeyOpenFailed`] for authentication failure.
pub fn open_nats_curve(
    recipient_private: &Zeroizing<[u8; 32]>,
    sender_public_xkey: &str,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let sender_public = decode_xkey_public(sender_public_xkey)?;
    let Some(rest) = ciphertext.strip_prefix(XKEY_VERSION_V1) else {
        return Err(Error::BadXKeyVersion);
    };
    if rest.len() <= XKEY_NONCE_LEN + XKEY_TAG_LEN {
        return Err(Error::BadXKeyCiphertextLen(ciphertext.len()));
    }
    let Some((nonce, body)) = rest.split_at_checked(XKEY_NONCE_LEN) else {
        return Err(Error::BadXKeyCiphertextLen(ciphertext.len()));
    };
    let nonce: [u8; XKEY_NONCE_LEN] = nonce
        .try_into()
        .map_err(|_| Error::BadXKeyCiphertextLen(ciphertext.len()))?;
    box_crypt(
        recipient_private,
        &sender_public,
        &nonce,
        body,
        BoxMode::Open,
    )
    .map(Zeroizing::new)
}

fn decode_xkey_public(nkey: &str) -> Result<[u8; 32], Error> {
    let (actual, key) = decode_public(nkey)?;
    if actual != NkeyType::Curve {
        return Err(Error::UnexpectedXKeyPrefix(actual));
    }
    Ok(key)
}

#[derive(Clone, Copy)]
enum BoxMode {
    Seal,
    Open,
}

fn box_crypt(
    private: &Zeroizing<[u8; 32]>,
    peer_public: &[u8; 32],
    nonce: &[u8; XKEY_NONCE_LEN],
    input: &[u8],
    mode: BoxMode,
) -> Result<Vec<u8>, Error> {
    let private = StaticSecret::from(**private);
    let peer = X25519PublicKey::from(*peer_public);
    let shared_secret = private.diffie_hellman(&peer);
    if !shared_secret.was_contributory() {
        return match mode {
            BoxMode::Seal => Err(Error::XKeySealFailed),
            BoxMode::Open => Err(Error::XKeyOpenFailed),
        };
    }
    let shared = Zeroizing::new(shared_secret.to_bytes());
    let key = nats_box_key(&shared);
    let cipher = XSalsa20Poly1305::new(&key);
    let nonce = SecretboxNonce::from(*nonce);
    match mode {
        BoxMode::Seal => cipher
            .encrypt(&nonce, input)
            .map_err(|_| Error::XKeySealFailed),
        BoxMode::Open => cipher
            .decrypt(&nonce, input)
            .map_err(|_| Error::XKeyOpenFailed),
    }
}

#[allow(deprecated)]
fn nats_box_key(shared: &Zeroizing<[u8; 32]>) -> Zeroizing<SecretboxKey> {
    let input = crypto_secretbox::aead::generic_array::GenericArray::<u8, U16>::default();
    let key = SecretboxKey::clone_from_slice(shared.as_slice());
    Zeroizing::new(hsalsa::<U10>(&key, &input))
}

// ---------------------------------------------------------------------------
// NATS JWT decoding and verification
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CompactHeader {
    typ: String,
    alg: String,
}

#[derive(Deserialize)]
struct CompactClaims {
    iss: String,
    sub: String,
    #[serde(default)]
    iat: Option<u64>,
    #[serde(default)]
    exp: Option<u64>,
    #[serde(default)]
    nbf: Option<u64>,
    #[serde(default)]
    nats: Option<CompactNatsClaims>,
}

#[derive(Deserialize)]
struct CompactNatsClaims {
    #[serde(rename = "type")]
    kind: Option<String>,
}

/// Standard claims extracted from a decoded NATS JWT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatsJwtClaims {
    /// The `iss` claim. This is the public `NKey` whose Ed25519 key signed the
    /// token.
    pub issuer: String,
    /// The `sub` claim. This is the public `NKey` the token describes.
    pub subject: String,
    /// Issued-at time (`iat`), Unix seconds.
    pub issued_at: Option<u64>,
    /// Expiry time (`exp`), Unix seconds.
    pub expires_at: Option<u64>,
    /// Not-before time (`nbf`), Unix seconds.
    pub not_before: Option<u64>,
    /// The `nats.type` claim, if present.
    pub nats_type: Option<String>,
    /// Full JSON claim object for callers that need fields outside the standard
    /// broker validation surface.
    pub raw: Value,
}

/// A decoded compact NATS JWT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedNatsJwt {
    signing_input: String,
    signature: [u8; 64],
    claims: NatsJwtClaims,
    issuer_role: NkeyType,
    issuer_public_key: [u8; 32],
}

impl DecodedNatsJwt {
    /// The literal `header.payload` bytes that were signed.
    #[must_use]
    pub fn signing_input(&self) -> &str {
        &self.signing_input
    }

    /// The decoded raw Ed25519 signature.
    #[must_use]
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// Extracted NATS JWT claims.
    #[must_use]
    pub const fn claims(&self) -> &NatsJwtClaims {
        &self.claims
    }

    /// The role prefix carried by the embedded issuer `NKey`.
    #[must_use]
    pub const fn issuer_role(&self) -> NkeyType {
        self.issuer_role
    }

    /// Raw 32-byte Ed25519 public key decoded from the embedded issuer `NKey`.
    #[must_use]
    pub const fn issuer_public_key(&self) -> &[u8; 32] {
        &self.issuer_public_key
    }

    /// Verify the signature with an already-resolved Ed25519 public key.
    #[must_use]
    pub fn verify_signature(&self, public_key: &[u8; 32]) -> bool {
        verify_ed25519(public_key, self.signing_input.as_bytes(), &self.signature)
    }

    /// Validate this token against the supplied candidate signer set.
    ///
    /// The candidate set is the trust boundary: the token's `iss` is
    /// self-asserted, so at least one candidate must match it before the
    /// signature and time claims are authoritative.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when a caller-supplied candidate public `NKey` is
    /// malformed.
    pub fn verify_with_candidates<'a, I>(
        &self,
        candidates: I,
        now_unix: u64,
    ) -> Result<NatsJwtValidation, Error>
    where
        I: IntoIterator<Item = CandidateSigner<'a>>,
    {
        for candidate in candidates {
            let resolved = self.resolve_candidate(candidate)?;
            if let Some(matched) = resolved {
                return Ok(self.validation_for_match(matched, now_unix));
            }
        }
        Ok(NatsJwtValidation {
            reason: NatsJwtValidationReason::UnknownSigner,
            matched_signer: None,
        })
    }

    fn resolve_candidate(
        &self,
        candidate: CandidateSigner<'_>,
    ) -> Result<Option<MatchedNatsSigner>, Error> {
        match candidate {
            CandidateSigner::Nkey(nkey) => {
                let (role, public_key) = decode_public(nkey)?;
                if role == self.issuer_role && public_key == self.issuer_public_key {
                    Ok(Some(MatchedNatsSigner {
                        role: Some(role),
                        public_key,
                    }))
                } else {
                    Ok(None)
                }
            }
            CandidateSigner::RawPublicKey(public_key) => {
                if public_key == &self.issuer_public_key {
                    Ok(Some(MatchedNatsSigner {
                        role: None,
                        public_key: *public_key,
                    }))
                } else {
                    Ok(None)
                }
            }
        }
    }

    fn validation_for_match(
        &self,
        matched_signer: MatchedNatsSigner,
        now_unix: u64,
    ) -> NatsJwtValidation {
        if !self.verify_signature(&matched_signer.public_key) {
            return NatsJwtValidation {
                reason: NatsJwtValidationReason::BadSignature,
                matched_signer: Some(matched_signer),
            };
        }
        if let Some(exp) = self.claims.expires_at
            && exp <= now_unix
        {
            return NatsJwtValidation {
                reason: NatsJwtValidationReason::Expired,
                matched_signer: Some(matched_signer),
            };
        }
        if let Some(nbf) = self.claims.not_before
            && nbf > now_unix
        {
            return NatsJwtValidation {
                reason: NatsJwtValidationReason::NotYetValid,
                matched_signer: Some(matched_signer),
            };
        }
        NatsJwtValidation {
            reason: NatsJwtValidationReason::Valid,
            matched_signer: Some(matched_signer),
        }
    }
}

/// A caller-supplied signer candidate for NATS JWT validation.
#[derive(Debug, Clone, Copy)]
pub enum CandidateSigner<'a> {
    /// Public `NKey` string (`A…`, `O…`, `U…`, or another supported public role).
    Nkey(&'a str),
    /// Raw 32-byte Ed25519 public key.
    RawPublicKey(&'a [u8; 32]),
}

/// The signer that matched a token's embedded `iss`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatchedNatsSigner {
    /// The public `NKey` role, if the caller supplied this candidate as an
    /// encoded `NKey`. Raw public-key candidates have no role prefix.
    pub role: Option<NkeyType>,
    /// Raw 32-byte Ed25519 public key used for verification.
    pub public_key: [u8; 32],
}

/// Result of validating a NATS JWT against a candidate signer set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NatsJwtValidation {
    /// Machine-readable validation result.
    pub reason: NatsJwtValidationReason,
    /// The matched signer, when the candidate set contained the embedded issuer.
    pub matched_signer: Option<MatchedNatsSigner>,
}

/// Authoritative validation result for a decoded NATS JWT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatsJwtValidationReason {
    /// Signature and time claims are valid.
    Valid,
    /// No supplied signer matched the token's embedded `iss`.
    UnknownSigner,
    /// The signer matched, but the Ed25519 signature did not verify over the
    /// literal compact-JWT `header.payload` bytes.
    BadSignature,
    /// The token's `exp` is at or before the supplied validation time.
    Expired,
    /// The token's `nbf` is after the supplied validation time.
    NotYetValid,
}

/// Decode a compact NATS JWT and expose its claims plus literal signing input.
///
/// # Errors
///
/// Returns [`Error::MalformedJwt`] for malformed compact JWTs, invalid base64url
/// segments, non-JSON header/claims, missing required claims, unsupported NATS
/// JWS header values, or invalid issuer `NKey`; returns
/// [`Error::BadSignatureLen`] when the signature segment is not 64 bytes.
pub fn decode_nats_jwt(token: &str) -> Result<DecodedNatsJwt, Error> {
    let mut parts = token.split('.');
    let Some(header_segment) = parts.next() else {
        return Err(Error::MalformedJwt("jwt is empty".into()));
    };
    let Some(claims_segment) = parts.next() else {
        return Err(Error::MalformedJwt(
            "jwt must contain header, claims, and signature".into(),
        ));
    };
    let Some(signature_segment) = parts.next() else {
        return Err(Error::MalformedJwt(
            "jwt must contain header, claims, and signature".into(),
        ));
    };
    if parts.next().is_some() {
        return Err(Error::MalformedJwt(
            "jwt must contain exactly three segments".into(),
        ));
    }

    let header: CompactHeader = decode_url_json(header_segment, "header")?;
    if header.typ != "JWT" || header.alg != "ed25519-nkey" {
        return Err(Error::MalformedJwt(
            "jwt header must be typ=JWT and alg=ed25519-nkey".into(),
        ));
    }

    let claims_raw = decode_url_bytes(claims_segment, "claims")?;
    let claims_value: Value = serde_json::from_slice(&claims_raw)
        .map_err(|e| Error::MalformedJwt(format!("invalid jwt claims json: {e}")))?;
    let claims: CompactClaims = serde_json::from_value(claims_value.clone())
        .map_err(|e| Error::MalformedJwt(format!("invalid jwt claims: {e}")))?;
    let (issuer_role, issuer_public_key) = decode_public(&claims.iss)
        .map_err(|e| Error::MalformedJwt(format!("invalid jwt issuer nkey: {e}")))?;

    let signature = decode_url_bytes(signature_segment, "signature")?;
    let signature_len = signature.len();
    let Ok(signature) = <[u8; 64]>::try_from(signature) else {
        return Err(Error::BadSignatureLen(signature_len));
    };

    Ok(DecodedNatsJwt {
        signing_input: format!("{header_segment}.{claims_segment}"),
        signature,
        claims: NatsJwtClaims {
            issuer: claims.iss,
            subject: claims.sub,
            issued_at: claims.iat,
            expires_at: claims.exp,
            not_before: claims.nbf,
            nats_type: claims.nats.and_then(|nats| nats.kind),
            raw: claims_value,
        },
        issuer_role,
        issuer_public_key,
    })
}

fn decode_url_json<T>(segment: &str, name: &str) -> Result<T, Error>
where
    T: DeserializeOwned,
{
    let bytes = decode_url_bytes(segment, name)?;
    serde_json::from_slice(&bytes)
        .map_err(|e| Error::MalformedJwt(format!("invalid jwt {name} json: {e}")))
}

fn decode_url_bytes(segment: &str, name: &str) -> Result<Vec<u8>, Error> {
    URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|e| Error::MalformedJwt(format!("invalid jwt {name} base64url: {e}")))
}

fn verify_ed25519(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let signature = Signature::from_bytes(signature);
    VerifyingKey::from_bytes(public_key).is_ok_and(|key| key.verify(message, &signature).is_ok())
}

// ---------------------------------------------------------------------------
// Claim shapes (mirrors nats-io/jwt v2)
// ---------------------------------------------------------------------------

/// A subject allow/deny list for one direction (publish or subscribe). An empty
/// `allow` means "no allow restriction"; `deny` always subtracts.
#[derive(Serialize, Default, Clone)]
pub struct Permission {
    /// Subjects explicitly permitted (empty = unrestricted for this direction).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    /// Subjects explicitly denied (subtracted from whatever `allow` permits).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
}

#[derive(Serialize)]
struct NatsUser {
    #[serde(rename = "pub")]
    publish: Permission,
    sub: Permission,
    subs: i64,
    data: i64,
    payload: i64,
    // The owning account identity when the token is issued by an account signing
    // key (mirrors `nats-io/jwt`'s `User.issuer_account`, `omitempty`).
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer_account: Option<String>,
    #[serde(rename = "type")]
    kind: &'static str,
    version: i64,
}

/// Claims hashed to produce `jti`: the standard claims only, in `nats-io/jwt`
/// `ClaimsData` field order, with `omitempty` semantics (and `jti` always empty
/// so it is omitted).
#[derive(Serialize)]
struct ClaimsHash<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    jti: Option<&'a str>,
    iat: u64,
    iss: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nbf: Option<u64>,
    sub: &'a str,
}

/// A pub/sub permission pair as the account `default_permissions` block carries
/// it (`{"pub":{…},"sub":{…}}`).
#[derive(Serialize, Default, Clone)]
pub struct Permissions {
    /// Publish permissions (serialized as `pub`).
    #[serde(rename = "pub")]
    pub publish: Permission,
    /// Subscribe permissions.
    pub sub: Permission,
    /// Optional limit on auto-generated response-subject permissions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resp: Option<ResponsePermission>,
}

/// Bounds on the implicit reply-subject permissions a request grants its
/// responder.
#[derive(Serialize, Clone)]
pub struct ResponsePermission {
    /// Maximum number of responses allowed.
    pub max: i64,
    /// How long (nanoseconds) the response permission stays valid.
    pub ttl: i64,
}

/// Whether an import/export is a one-way `stream` or a request/reply `service`.
#[derive(Serialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum ExportType {
    /// One-way publish stream.
    Stream,
    /// Request/reply service.
    Service,
}

/// An account-level import of another account's stream or service.
#[derive(Serialize, Clone)]
pub struct AccountImport {
    /// Human-readable import name.
    #[serde(skip_serializing_if = "str::is_empty")]
    pub name: String,
    /// Exported subject being imported.
    #[serde(skip_serializing_if = "str::is_empty")]
    pub subject: String,
    /// Public `NKey` (`A…`) of the exporting account.
    #[serde(skip_serializing_if = "str::is_empty")]
    pub account: String,
    /// Activation token for a token-gated export (empty if not required).
    #[serde(skip_serializing_if = "str::is_empty")]
    pub token: String,
    /// Local subject the import is remapped *to* (legacy `to` form).
    #[serde(skip_serializing_if = "str::is_empty")]
    pub to: String,
    /// Local subject the import is remapped to (with `$N` capture groups).
    #[serde(skip_serializing_if = "str::is_empty")]
    pub local_subject: String,
    /// Whether this imports a `stream` or a `service` (serialized as `type`).
    #[serde(rename = "type")]
    pub kind: ExportType,
    /// Whether latency/connection info may be shared with the exporter.
    #[serde(skip_serializing_if = "is_false")]
    pub share: bool,
    /// Whether message-trace propagation is allowed across this import.
    #[serde(skip_serializing_if = "is_false")]
    pub allow_trace: bool,
}

/// Latency-sampling configuration for an exported service.
#[derive(Serialize, Clone)]
pub struct ServiceLatency {
    /// Sampling rate (`headers` or a percentage).
    pub sampling: SamplingRate,
    /// Subject latency measurements are published to.
    pub results: String,
}

/// How often an exported service samples latency.
#[derive(Clone)]
pub enum SamplingRate {
    /// Sample only when the request carries the latency header (serialized as
    /// the string `"headers"`).
    Headers,
    /// Sample this percentage (1–100) of requests.
    Percent(u8),
}

impl Serialize for SamplingRate {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Headers => serializer.serialize_str("headers"),
            Self::Percent(percent) => serializer.serialize_u8(*percent),
        }
    }
}

/// An account-level export of a stream or service that other accounts may
/// import.
#[derive(Serialize, Clone)]
pub struct AccountExport {
    /// Human-readable export name.
    #[serde(skip_serializing_if = "str::is_empty")]
    pub name: String,
    /// Subject (with wildcards) being exported.
    #[serde(skip_serializing_if = "str::is_empty")]
    pub subject: String,
    /// Whether this exports a `stream` or a `service` (serialized as `type`).
    #[serde(rename = "type")]
    pub kind: ExportType,
    /// Whether importers need an activation token (private export).
    #[serde(skip_serializing_if = "is_false")]
    pub token_req: bool,
    /// Revoked activation tokens, keyed by account public key → revocation time.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub revocations: BTreeMap<String, i64>,
    /// Reply cardinality for a service export (`singleton`/`stream`/`chunked`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_type: Option<ResponseType>,
    /// Latency-tracking response threshold (nanoseconds).
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub response_threshold: i64,
    /// Optional latency-sampling configuration for a service export.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_latency: Option<ServiceLatency>,
    /// Token position for a dynamically-named (templated) export subject.
    #[serde(skip_serializing_if = "is_zero_u32")]
    pub account_token_position: u32,
    /// Whether the export is advertised to other accounts.
    #[serde(skip_serializing_if = "is_false")]
    pub advertise: bool,
    /// Whether message-trace propagation is allowed across this export.
    #[serde(skip_serializing_if = "is_false")]
    pub allow_trace: bool,
    /// Free-form description.
    #[serde(skip_serializing_if = "str::is_empty")]
    pub description: String,
    /// URL with more information about the export.
    #[serde(skip_serializing_if = "str::is_empty")]
    pub info_url: String,
}

/// Reply cardinality of a service export.
#[derive(Serialize, Clone)]
pub enum ResponseType {
    /// Exactly one reply per request.
    Singleton,
    /// A stream of replies per request.
    Stream,
    /// A chunked single logical reply.
    Chunked,
}

/// Per-connection NATS limits (a `-1` value means unlimited).
#[derive(Serialize, Default, Clone)]
pub struct NatsLimits {
    /// Maximum subscriptions.
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub subs: i64,
    /// Maximum data in bytes.
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub data: i64,
    /// Maximum message payload in bytes.
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub payload: i64,
}

/// Account-wide limits (a `-1` value means unlimited).
#[derive(Serialize, Default, Clone)]
pub struct AccountLimits {
    /// Maximum number of imports.
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub imports: i64,
    /// Maximum number of exports.
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub exports: i64,
    /// Whether wildcard export subjects are allowed.
    #[serde(skip_serializing_if = "is_false")]
    pub wildcards: bool,
    /// Whether bearer (non-`NKey`) user tokens are disallowed.
    #[serde(skip_serializing_if = "is_false")]
    pub disallow_bearer: bool,
    /// Maximum active client connections.
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub conn: i64,
    /// Maximum leaf-node connections.
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub leaf: i64,
}

/// `JetStream` resource limits for an account or a named tier (a `-1` value
/// means unlimited).
#[derive(Serialize, Default, Clone)]
pub struct JetStreamLimits {
    /// Maximum in-memory storage in bytes.
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub mem_storage: i64,
    /// Maximum on-disk storage in bytes.
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub disk_storage: i64,
    /// Maximum number of streams.
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub streams: i64,
    /// Maximum number of consumers.
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub consumer: i64,
    /// Maximum unacknowledged messages per consumer.
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub max_ack_pending: i64,
    /// Maximum bytes for a single memory stream.
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub mem_max_stream_bytes: i64,
    /// Maximum bytes for a single disk stream.
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub disk_max_stream_bytes: i64,
    /// Whether streams must declare a maximum byte size.
    #[serde(skip_serializing_if = "is_false")]
    pub max_bytes_required: bool,
}

/// The full operator-limits block on an account JWT: the `nats`, `account`, and
/// `jetstream` limit groups (flattened into one JSON object) plus per-tier
/// `JetStream` limits.
#[derive(Serialize, Default, Clone)]
pub struct OperatorLimits {
    /// Per-connection NATS limits.
    #[serde(flatten)]
    pub nats: NatsLimits,
    /// Account-wide limits.
    #[serde(flatten)]
    pub account: AccountLimits,
    /// Default-tier `JetStream` limits.
    #[serde(flatten)]
    pub jetstream: JetStreamLimits,
    /// `JetStream` limits per named tier (`R1`, `R3`, …).
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub tiered_limits: BTreeMap<String, JetStreamLimits>,
}

impl OperatorLimits {
    /// Standard **unlimited** operator limits for an account, matching what
    /// `nsc` writes for a default account: every per-connection and account-wide
    /// limit is `-1` (unlimited) and wildcard exports are allowed. `JetStream`
    /// limits stay `0` (disabled); enabling `JetStream` is a separate, explicit
    /// grant.
    ///
    /// A minted account JWT **must** carry a limits block: `nats-server` reads a
    /// zero connection/subscription limit as **deny-all** (only `-1` is
    /// unlimited), so an account with no limits rejects every connection.
    #[must_use]
    pub fn unlimited() -> Self {
        Self {
            nats: NatsLimits {
                subs: -1,
                data: -1,
                payload: -1,
            },
            account: AccountLimits {
                imports: -1,
                exports: -1,
                wildcards: true,
                conn: -1,
                leaf: -1,
                ..AccountLimits::default()
            },
            ..Self::default()
        }
    }
}

/// One weighted target in a subject mapping (for traffic splitting / canaries).
#[derive(Serialize, Clone)]
pub struct WeightedMapping {
    /// Destination subject.
    pub subject: String,
    /// Weight 0–100; the share of traffic routed to `subject`.
    #[serde(skip_serializing_if = "is_zero_u8")]
    pub weight: u8,
    /// Restrict this mapping to a named cluster (empty = all clusters).
    #[serde(skip_serializing_if = "str::is_empty")]
    pub cluster: String,
}

/// External (delegated) authorization config for an account: auth is performed
/// by an external service rather than by per-user `NKey`s.
#[derive(Serialize, Default, Clone)]
pub struct ExternalAuthorization {
    /// User public `NKey`s (`U…`) the external auth callout runs as.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub auth_users: Vec<String>,
    /// Account public `NKey`s (`A…`) the callout may place users into.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allowed_accounts: Vec<String>,
    /// Curve (`X…`) xkey used to encrypt the auth-callout request (empty = none).
    #[serde(skip_serializing_if = "str::is_empty")]
    pub xkey: String,
}

/// Message-trace configuration: where traced messages are reported and how
/// often they are sampled.
#[derive(Serialize, Clone)]
pub struct MsgTrace {
    /// Subject trace events are delivered to.
    #[serde(skip_serializing_if = "str::is_empty")]
    pub dest: String,
    /// Sampling percentage (1–100).
    #[serde(skip_serializing_if = "is_zero_u8")]
    pub sampling: u8,
}

/// Which account a cluster's system traffic is attributed to.
#[derive(Serialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum ClusterTraffic {
    /// The system account.
    System,
    /// The owning account.
    Owner,
}

/// Account-specific fields inside a NATS account JWT (the `nats` claim block for
/// `type=account`). All fields are optional; empty ones are omitted from the
/// serialized claims.
#[derive(Serialize, Default, Clone)]
pub struct AccountClaims {
    /// Streams/services this account imports from others.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub imports: Vec<AccountImport>,
    /// Streams/services this account exports to others.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub exports: Vec<AccountExport>,
    /// Resource limits applied to the account.
    #[serde(skip_serializing_if = "operator_limits_is_empty")]
    pub limits: OperatorLimits,
    /// Account signing keys (`A…`) authorized to sign on the account's behalf.
    /// If left empty, [`AccountJwt::signing_keys`] is used.
    #[serde(rename = "signing_keys", skip_serializing_if = "Vec::is_empty")]
    pub signing_keys: Vec<String>,
    /// Revoked user keys, keyed by user public key → revocation time.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub revocations: BTreeMap<String, i64>,
    /// Default pub/sub permissions applied to users lacking their own.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_permissions: Option<Permissions>,
    /// Subject mappings, keyed by source subject → weighted destinations.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub mappings: BTreeMap<String, Vec<WeightedMapping>>,
    /// External (delegated) authorization configuration.
    #[serde(skip_serializing_if = "external_authorization_is_empty")]
    pub authorization: ExternalAuthorization,
    /// Account-level message-trace configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace: Option<MsgTrace>,
    /// Which account this account's cluster traffic is attributed to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster_traffic: Option<ClusterTraffic>,
}

#[derive(Serialize)]
struct NatsAccount {
    #[serde(flatten)]
    claims: AccountClaims,
    #[serde(rename = "type")]
    kind: &'static str,
    version: i64,
}

/// Operator-specific fields inside a NATS operator JWT (the `nats` claim block
/// for `type=operator`). All fields are optional; empty ones are omitted.
#[derive(Serialize, Default, Clone)]
pub struct OperatorClaims {
    /// Operator signing keys (`O…`) authorized to sign accounts. If left empty,
    /// [`OperatorJwt::signing_keys`] is used.
    #[serde(rename = "signing_keys", skip_serializing_if = "Vec::is_empty")]
    pub signing_keys: Vec<String>,
    /// Account-resolver / account-server URL. If empty,
    /// [`OperatorJwt::account_server_url`] is used.
    #[serde(rename = "account_server_url", skip_serializing_if = "str::is_empty")]
    pub account_server_url: String,
    /// Advertised operator service (NATS) URLs.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub operator_service_urls: Vec<String>,
    /// System account public `NKey` (`A…`). If empty,
    /// [`OperatorJwt::system_account`] is used.
    #[serde(rename = "system_account", skip_serializing_if = "str::is_empty")]
    pub system_account: String,
    /// Minimum NATS server version this operator asserts (empty = none).
    #[serde(skip_serializing_if = "str::is_empty")]
    pub assert_server_version: String,
    /// Whether accounts must be signed by a dedicated signing key (not the
    /// operator identity key).
    #[serde(skip_serializing_if = "is_false")]
    pub strict_signing_key_usage: bool,
}

#[derive(Serialize)]
struct NatsOperator {
    #[serde(flatten)]
    claims: OperatorClaims,
    #[serde(rename = "type")]
    kind: &'static str,
    version: i64,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_false(value: &bool) -> bool {
    !*value
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_zero_i64(value: &i64) -> bool {
    *value == 0
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_zero_u32(value: &u32) -> bool {
    *value == 0
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_zero_u8(value: &u8) -> bool {
    *value == 0
}

fn external_authorization_is_empty(value: &ExternalAuthorization) -> bool {
    value.auth_users.is_empty() && value.allowed_accounts.is_empty() && value.xkey.is_empty()
}

fn operator_limits_is_empty(value: &OperatorLimits) -> bool {
    value.nats.subs == 0
        && value.nats.data == 0
        && value.nats.payload == 0
        && value.account.imports == 0
        && value.account.exports == 0
        && !value.account.wildcards
        && !value.account.disallow_bearer
        && value.account.conn == 0
        && value.account.leaf == 0
        && value.jetstream.mem_storage == 0
        && value.jetstream.disk_storage == 0
        && value.jetstream.streams == 0
        && value.jetstream.consumer == 0
        && value.jetstream.max_ack_pending == 0
        && value.jetstream.mem_max_stream_bytes == 0
        && value.jetstream.disk_max_stream_bytes == 0
        && !value.jetstream.max_bytes_required
        && value.tiered_limits.is_empty()
}

/// Minimal NATS claim block for role tokens that do not have additional
/// modeled fields in the broker API yet.
#[derive(Serialize)]
struct NatsRole {
    #[serde(rename = "type")]
    kind: &'static str,
    version: i64,
}

/// Generic token claims parameterized over the `nats` block type, so the
/// account and operator builders share the standard-claim envelope + `jti`
/// hashing with the user builder.
#[derive(Serialize)]
struct TokenClaimsGeneric<'a, N>
where
    N: Serialize,
{
    jti: String,
    iat: u64,
    iss: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nbf: Option<u64>,
    nats: N,
    sub: &'a str,
}

/// Compute the `jti` (base32-nopad SHA-512/256 over the standard claims, with
/// `jti=""` excluded) shared by every NATS JWT shape, and encode the
/// `header.claims` signing input. The `nats` block is excluded from the hash by
/// construction (same as `nats-io/jwt`).
fn build_signing_input<N: Serialize>(
    iss: &str,
    sub: &str,
    name: &str,
    iat: u64,
    exp: Option<u64>,
    nats: N,
) -> Result<String, Error> {
    let jti = jti_for_standard_claims(iss, sub, Some(name), iat, exp, None, None)?;

    let claims = TokenClaimsGeneric {
        jti,
        iat,
        iss,
        name,
        exp,
        nbf: None,
        nats,
        sub,
    };
    let header = URL_SAFE_NO_PAD.encode(HEADER_JSON.as_bytes());
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
    Ok(format!("{header}.{payload}"))
}

/// Compute the NATS JWT `jti`: base32-nopad SHA-512/256 over the standard
/// claims with `jti` itself omitted.
///
/// This is public for callers that accept a rich NATS claim document and need to
/// validate or refresh `jti` before signing.
///
/// # Errors
///
/// [`Error::Json`] if the standard-claim hash input cannot be serialized.
pub fn jti_for_standard_claims(
    iss: &str,
    sub: &str,
    name: Option<&str>,
    iat: u64,
    exp: Option<u64>,
    aud: Option<&str>,
    nbf: Option<u64>,
) -> Result<String, Error> {
    let hash_src = ClaimsHash {
        aud: aud.filter(|value| !value.is_empty()),
        exp: exp.filter(|value| *value != 0),
        jti: None,
        iat,
        iss,
        name: name.filter(|value| !value.is_empty()),
        nbf: nbf.filter(|value| *value != 0),
        sub,
    };
    let mut hasher = Sha512_256::new();
    hasher.update(serde_json::to_vec(&hash_src)?);
    Ok(data_encoding::BASE32_NOPAD.encode(&hasher.finalize()))
}

/// Build the NATS JWS signing input from a fully validated claim document.
///
/// The claim document must be a JSON object. This function only applies the
/// NATS fixed header and serialization; semantic checks for `iss`, `sub`, and
/// the `nats` block belong at the authorization boundary.
///
/// # Errors
///
/// [`Error::InvalidClaims`] if `claims` is not an object, or [`Error::Json`] if
/// serialization fails.
pub fn signing_input_from_claims(claims: &Value) -> Result<String, Error> {
    if !claims.is_object() {
        return Err(Error::InvalidClaims(
            "nats jwt claims must be a JSON object".into(),
        ));
    }
    let header = URL_SAFE_NO_PAD.encode(HEADER_JSON.as_bytes());
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?);
    Ok(format!("{header}.{payload}"))
}

// ---------------------------------------------------------------------------
// User JWT builder
// ---------------------------------------------------------------------------

/// Publish / subscribe permission lists for a user (empty = unrestricted within
/// the account).
#[derive(Default, Clone)]
pub struct UserPermissions {
    /// Subjects the user may publish to (empty = all).
    pub pub_allow: Vec<String>,
    /// Subjects the user may not publish to.
    pub pub_deny: Vec<String>,
    /// Subjects the user may subscribe to (empty = all).
    pub sub_allow: Vec<String>,
    /// Subjects the user may not subscribe to.
    pub sub_deny: Vec<String>,
}

/// A NATS user JWT to be signed by its issuing account key.
pub struct UserJwt {
    /// Issuer (`iss`) = the public `NKey` (`A…`) of the key that signs the token:
    /// either the account identity key or an account signing key.
    pub issuer: String,
    /// `nats.issuer_account` = the owning account's identity public `NKey` (`A…`).
    /// Set this when [`issuer`](Self::issuer) is an account *signing* key, so
    /// `nats-server` can bind the user to its account; leave `None` when `issuer`
    /// is the account identity key itself.
    pub issuer_account: Option<String>,
    /// Subject = the user public `NKey` (`U…`) the credential is for.
    pub subject_user: String,
    /// Human-readable user name (the `name` claim).
    pub name: String,
    /// Issued-at time (`iat`), Unix seconds.
    pub issued_at: u64,
    /// Optional expiry (`exp`), Unix seconds; `None` mints a non-expiring token.
    pub expires: Option<u64>,
    /// Publish/subscribe permissions embedded in the user claims.
    pub permissions: UserPermissions,
}

impl UserJwt {
    /// Produce the JWS **signing input** (`base64url(header).base64url(claims)`).
    /// Hand the bytes to the key holder, then pass the resulting 64-byte
    /// signature to [`assemble`].
    pub fn signing_input(&self) -> Result<String, Error> {
        let nats = NatsUser {
            publish: Permission {
                allow: self.permissions.pub_allow.clone(),
                deny: self.permissions.pub_deny.clone(),
            },
            sub: Permission {
                allow: self.permissions.sub_allow.clone(),
                deny: self.permissions.sub_deny.clone(),
            },
            subs: -1,
            data: -1,
            payload: -1,
            issuer_account: self.issuer_account.clone(),
            kind: "user",
            version: 2,
        };
        build_signing_input(
            &self.issuer,
            &self.subject_user,
            &self.name,
            self.issued_at,
            self.expires,
            nats,
        )
    }
}

// ---------------------------------------------------------------------------
// Account JWT builder
// ---------------------------------------------------------------------------

/// A NATS **account** JWT to be signed by its issuing operator key.
///
/// Uses the same [`signing_input`](AccountJwt::signing_input) / [`assemble`]
/// split as [`UserJwt`]: the operator (or operator-signing) key signs the input
/// in the vault and the seed never materializes.
pub struct AccountJwt {
    /// Issuer = the operator (or operator-signing) public `NKey` (`O…`) signing.
    pub issuer: String,
    /// Subject = the account public `NKey` (`A…`) the JWT is for.
    pub subject_account: String,
    /// Human-readable account name (the `name` claim).
    pub name: String,
    /// Issued-at time (`iat`), Unix seconds.
    pub issued_at: u64,
    /// Optional expiry (`exp`), Unix seconds; `None` mints a non-expiring token.
    pub expires: Option<u64>,
    /// Account signing keys (`A…`) authorized to sign on behalf of the account.
    /// Used only when [`AccountClaims::signing_keys`] is empty.
    pub signing_keys: Vec<String>,
    /// Additional account claim fields from `nats-io/jwt` v2.
    pub claims: AccountClaims,
}

impl AccountJwt {
    /// Produce the JWS **signing input** (`base64url(header).base64url(claims)`).
    ///
    /// # Errors
    ///
    /// [`Error::Json`] if claim serialization fails (does not happen for these
    /// types in practice).
    pub fn signing_input(&self) -> Result<String, Error> {
        let nats = NatsAccount {
            claims: {
                let mut claims = self.claims.clone();
                if claims.signing_keys.is_empty() {
                    claims.signing_keys.clone_from(&self.signing_keys);
                }
                claims
            },
            kind: "account",
            version: 2,
        };
        build_signing_input(
            &self.issuer,
            &self.subject_account,
            &self.name,
            self.issued_at,
            self.expires,
            nats,
        )
    }
}

// ---------------------------------------------------------------------------
// Operator JWT builder
// ---------------------------------------------------------------------------

/// A NATS **operator** JWT to be signed by its operator key (usually
/// self-signed: `iss == sub`). Same `signing_input`/[`assemble`] split as the
/// others.
pub struct OperatorJwt {
    /// Issuer = the operator public `NKey` (`O…`) signing the token.
    pub issuer: String,
    /// Subject = the operator public `NKey` (`O…`) the JWT describes (self-signed
    /// operators set this equal to `issuer`).
    pub subject_operator: String,
    /// Human-readable operator name (the `name` claim).
    pub name: String,
    /// Issued-at time (`iat`), Unix seconds.
    pub issued_at: u64,
    /// Optional expiry (`exp`), Unix seconds; `None` mints a non-expiring token.
    pub expires: Option<u64>,
    /// Operator signing keys (`O…`). Used only when
    /// [`OperatorClaims::signing_keys`] is empty.
    pub signing_keys: Vec<String>,
    /// The account-resolver / account-server URL (empty = omitted). Used only
    /// when [`OperatorClaims::account_server_url`] is empty.
    pub account_server_url: String,
    /// The system account public `NKey` (`A…`, empty = omitted). Used only when
    /// [`OperatorClaims::system_account`] is empty.
    pub system_account: String,
    /// Additional operator claim fields from `nats-io/jwt` v2.
    pub claims: OperatorClaims,
}

impl OperatorJwt {
    /// Produce the JWS **signing input** (`base64url(header).base64url(claims)`).
    ///
    /// # Errors
    ///
    /// [`Error::Json`] if claim serialization fails.
    pub fn signing_input(&self) -> Result<String, Error> {
        let nats = NatsOperator {
            claims: {
                let mut claims = self.claims.clone();
                if claims.signing_keys.is_empty() {
                    claims.signing_keys.clone_from(&self.signing_keys);
                }
                if claims.account_server_url.is_empty() {
                    claims
                        .account_server_url
                        .clone_from(&self.account_server_url);
                }
                if claims.system_account.is_empty() {
                    claims.system_account.clone_from(&self.system_account);
                }
                claims
            },
            kind: "operator",
            version: 2,
        };
        build_signing_input(
            &self.issuer,
            &self.subject_operator,
            &self.name,
            self.issued_at,
            self.expires,
            nats,
        )
    }
}

// ---------------------------------------------------------------------------
// Minimal role JWT builder
// ---------------------------------------------------------------------------

/// The `nats.type` claim of a minimal role JWT minted via [`RoleJwt`]. These are
/// the roles the broker mints through the generic role path; account, user, and
/// operator have their own dedicated builders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleKind {
    /// A NATS server JWT (`type=server`).
    Server,
    /// A NATS curve / x25519 xkey JWT (`type=curve`).
    Curve,
    /// An account- or operator-signing-key JWT (`type=signer`).
    Signer,
}

impl RoleKind {
    /// The `nats.type` claim string for this role.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Curve => "curve",
            Self::Signer => "signer",
        }
    }
}

impl std::fmt::Display for RoleKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A minimal NATS JWT for a role whose current broker RPC carries only issuer,
/// subject, name, and expiry (`server`, `curve`, account-`signer`). The `nats`
/// claim block is just `{type, version}`.
pub struct RoleJwt {
    /// Issuer = the public `NKey` of the signing key.
    pub issuer: String,
    /// Subject = the public `NKey` the credential is for.
    pub subject: String,
    /// Human-readable name (the `name` claim).
    pub name: String,
    /// Issued-at time (`iat`), Unix seconds.
    pub issued_at: u64,
    /// Optional expiry (`exp`), Unix seconds; `None` mints a non-expiring token.
    pub expires: Option<u64>,
    /// The role this token is for, setting its `nats.type` claim.
    pub kind: RoleKind,
}

impl RoleJwt {
    /// Produce the JWS **signing input** (`base64url(header).base64url(claims)`).
    ///
    /// # Errors
    ///
    /// [`Error::Json`] if claim serialization fails.
    pub fn signing_input(&self) -> Result<String, Error> {
        let nats = NatsRole {
            kind: self.kind.as_str(),
            version: 2,
        };
        build_signing_input(
            &self.issuer,
            &self.subject,
            &self.name,
            self.issued_at,
            self.expires,
            nats,
        )
    }
}

/// Append a raw 64-byte Ed25519 `signature` to a `signing_input`, producing the
/// final compact JWT.
#[must_use]
pub fn assemble(signing_input: &str, signature: &[u8]) -> String {
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

/// Render a `nsc`-style `NATS` user `.creds` document from a compact user JWT
/// and user `NKey` seed.
///
/// The result embeds the seed and must be handled as a secret by callers. Inputs
/// are trimmed and must each fit on one line.
///
/// # Errors
///
/// Returns [`Error::InvalidClaims`] when `jwt` or `seed` is empty or contains an
/// embedded line break.
pub fn format_user_creds(jwt: &str, seed: &str) -> Result<String, Error> {
    let jwt = single_line_creds_field("NATS user JWT", jwt)?;
    let seed = single_line_creds_field("NATS user NKey seed", seed)?;
    Ok(format!(
        "-----BEGIN NATS USER JWT-----\n{jwt}\n------END NATS USER JWT------\n\n************************* IMPORTANT *************************\nNKEY Seed printed below can be used to sign and prove identity.\nNKEYs are sensitive and should be treated as secrets.\n\n-----BEGIN USER NKEY SEED-----\n{seed}\n------END USER NKEY SEED------\n\n*************************************************************\n"
    ))
}

fn single_line_creds_field<'a>(name: &str, value: &'a str) -> Result<&'a str, Error> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Error::InvalidClaims(format!("{name} must not be empty")));
    }
    if trimmed.contains('\n') || trimmed.contains('\r') {
        return Err(Error::InvalidClaims(format!(
            "{name} must be a single line"
        )));
    }
    Ok(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nkeys::{KeyPair, XKey};
    use serde_json::json;

    fn signed_token(signing_input: &str, signer: &KeyPair) -> String {
        let signature = signer.sign(signing_input.as_bytes()).expect("sign");
        assemble(signing_input, &signature)
    }

    #[test]
    fn format_user_creds_renders_canonical_nsc_document() {
        let creds = format_user_creds(" jwt.token.sig ", " SUUSERSEED ")
            .expect("credentials document must render");
        assert_eq!(
            creds,
            "-----BEGIN NATS USER JWT-----\njwt.token.sig\n------END NATS USER JWT------\n\n************************* IMPORTANT *************************\nNKEY Seed printed below can be used to sign and prove identity.\nNKEYs are sensitive and should be treated as secrets.\n\n-----BEGIN USER NKEY SEED-----\nSUUSERSEED\n------END USER NKEY SEED------\n\n*************************************************************\n"
        );
    }

    #[test]
    fn format_user_creds_rejects_empty_or_multiline_fields() {
        assert!(format_user_creds("", "SUUSERSEED").is_err());
        assert!(format_user_creds("jwt.token.sig", "").is_err());
        assert!(format_user_creds("jwt\nsecond", "SUUSERSEED").is_err());
        assert!(format_user_creds("jwt.token.sig", "SU\nseed").is_err());
    }

    fn assert_valid_token(token: &str, signer: &KeyPair, expected_kind: &str) {
        let signer_public = signer.public_key();
        let decoded = decode_nats_jwt(token).expect("decode jwt");
        assert_eq!(decoded.claims().issuer, signer_public);
        assert_eq!(decoded.claims().nats_type.as_deref(), Some(expected_kind));
        assert!(decoded.verify_signature(decoded.issuer_public_key()));

        let validation = decoded
            .verify_with_candidates(
                [CandidateSigner::Nkey(&signer_public)],
                decoded.claims().issued_at.unwrap_or_default(),
            )
            .expect("validate");
        assert_eq!(validation.reason, NatsJwtValidationReason::Valid);

        let raw_validation = decoded
            .verify_with_candidates(
                [CandidateSigner::RawPublicKey(decoded.issuer_public_key())],
                decoded.claims().issued_at.unwrap_or_default(),
            )
            .expect("validate raw");
        assert_eq!(raw_validation.reason, NatsJwtValidationReason::Valid);
    }

    #[test]
    fn account_nkey_encoding_matches_nkeys() {
        // A real account public from nkeys, decoded to raw bytes, must re-encode
        // identically through our encoder, proving prefix byte + CRC + base32.
        let account = KeyPair::new_account();
        let expected = account.public_key(); // "A..."
        let (role, raw) = decode_public(&expected).expect("decode");
        assert_eq!(role, NkeyType::Account);
        assert_eq!(encode_public(NkeyType::Account, &raw).unwrap(), expected);
    }

    #[test]
    fn user_jwt_verifies_under_issuer_account_key() {
        // Build a user JWT issued by an account key, sign it with that key
        // (standing in for the vault), then verify the signature decodes from
        // the `iss` NKey, i.e. the token is a valid NATS JWT.
        let account = KeyPair::new_account();
        let user = KeyPair::new_user();

        let jwt = UserJwt {
            issuer: account.public_key(),
            issuer_account: None,
            subject_user: user.public_key(),
            name: "bob".into(),
            issued_at: 1_782_000_000,
            expires: None,
            permissions: UserPermissions::default(),
        };

        let signing_input = jwt.signing_input().expect("signing input");
        let signature = account.sign(signing_input.as_bytes()).expect("sign");
        let token = assemble(&signing_input, &signature);

        // Three compact-JWT segments.
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);

        // Header is exactly the NATS header.
        let header = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        assert_eq!(header, HEADER_JSON.as_bytes());

        // Claims carry the expected iss/sub/nats.type.
        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["iss"], account.public_key());
        assert_eq!(claims["sub"], user.public_key());
        assert_eq!(claims["nats"]["type"], "user");
        assert_eq!(claims["nats"]["version"], 2);
        assert!(claims["jti"].as_str().unwrap().len() >= 52);

        // The signature verifies under the issuer account NKey, exactly what a
        // NATS server checks.
        let issuer = KeyPair::from_public_key(claims["iss"].as_str().unwrap()).unwrap();
        issuer
            .verify(signing_input.as_bytes(), &signature)
            .expect("signature must verify under iss account key");
    }

    #[test]
    fn user_jwt_sets_nats_issuer_account_when_signing_key() {
        // A user issued by an account *signing* key: `iss` is the signing key and
        // `nats.issuer_account` names the owning account identity so nats-server
        // can bind the user to its account.
        let signing = KeyPair::new_account();
        let account_identity = KeyPair::new_account();
        let user = KeyPair::new_user();

        let jwt = UserJwt {
            issuer: signing.public_key(),
            issuer_account: Some(account_identity.public_key()),
            subject_user: user.public_key(),
            name: "svc".into(),
            issued_at: 1_782_000_000,
            expires: None,
            permissions: UserPermissions::default(),
        };
        let signing_input = jwt.signing_input().expect("signing input");
        let parts: Vec<&str> = signing_input.split('.').collect();
        assert_eq!(parts.len(), 2);
        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["iss"], signing.public_key());
        assert_eq!(
            claims["nats"]["issuer_account"],
            account_identity.public_key()
        );

        // With no issuer_account the claim is omitted entirely.
        let plain = UserJwt {
            issuer: signing.public_key(),
            issuer_account: None,
            subject_user: user.public_key(),
            name: "svc".into(),
            issued_at: 1_782_000_000,
            expires: None,
            permissions: UserPermissions::default(),
        };
        let plain_input = plain.signing_input().expect("signing input");
        let plain_parts: Vec<&str> = plain_input.split('.').collect();
        let plain_claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(plain_parts[1]).unwrap()).unwrap();
        assert!(plain_claims["nats"].get("issuer_account").is_none());
    }

    #[test]
    fn encode_public_round_trips_each_role() {
        // Each role encodes to a key string starting with its prefix letter, and
        // decode_public recovers the same role and raw bytes.
        let account = KeyPair::new_account();
        let (_, raw) = decode_public(&account.public_key()).unwrap();
        for role in [
            NkeyType::Account,
            NkeyType::Cluster,
            NkeyType::Server,
            NkeyType::Operator,
            NkeyType::User,
            NkeyType::Curve,
        ] {
            let encoded = encode_public(role, &raw).unwrap();
            assert!(
                encoded.starts_with(role.letter()),
                "{role} key should start with {}, got {encoded}",
                role.letter()
            );
            let (decoded_role, decoded_raw) = decode_public(&encoded).unwrap();
            assert_eq!(decoded_role, role);
            assert_eq!(decoded_raw, raw);
        }
    }

    #[test]
    fn nats_curve_box_round_trips_and_validates_wire_shape() {
        let sender_private = Zeroizing::new([0x11; 32]);
        let receiver_private = Zeroizing::new([0x22; 32]);
        let sender_public =
            encode_public(NkeyType::Curve, &xkey_public_from_private(&sender_private))
                .expect("sender xkey encodes");
        let receiver_public = encode_public(
            NkeyType::Curve,
            &xkey_public_from_private(&receiver_private),
        )
        .expect("receiver xkey encodes");

        let boxed =
            seal_nats_curve(&sender_private, &receiver_public, b"payload").expect("seal succeeds");
        assert!(boxed.starts_with(XKEY_VERSION_V1));
        assert_eq!(
            boxed.len(),
            XKEY_VERSION_V1.len() + XKEY_NONCE_LEN + XKEY_TAG_LEN + b"payload".len()
        );

        let opened =
            open_nats_curve(&receiver_private, &sender_public, &boxed).expect("open succeeds");
        assert_eq!(opened.as_slice(), b"payload");

        let mut tampered = boxed;
        if let Some(byte) = tampered.last_mut() {
            *byte ^= 0x80;
        }
        assert!(matches!(
            open_nats_curve(&receiver_private, &sender_public, &tampered),
            Err(Error::XKeyOpenFailed)
        ));
    }

    #[test]
    fn nats_curve_box_interops_with_nkeys_xkey_both_directions() {
        let sender_private = Zeroizing::new([0x33; 32]);
        let receiver_private = Zeroizing::new([0x44; 32]);
        let sender = XKey::new_from_raw(*sender_private);
        let receiver = XKey::new_from_raw(*receiver_private);

        let basil_box = seal_nats_curve(&sender_private, &receiver.public_key(), b"from basil")
            .expect("basil seal succeeds");
        let nkeys_opened = receiver
            .open(&basil_box, &sender)
            .expect("nkeys opens basil box");
        assert_eq!(nkeys_opened, b"from basil");

        let nkeys_box = sender
            .seal(b"from nkeys", &receiver)
            .expect("nkeys seal succeeds");
        let basil_opened = open_nats_curve(&receiver_private, &sender.public_key(), &nkeys_box)
            .expect("basil opens nkeys box");
        assert_eq!(basil_opened.as_slice(), b"from nkeys");
    }

    #[test]
    fn nkey_type_letter_round_trips() {
        for role in NkeyType::ALL {
            assert_eq!(NkeyType::from_letter(role.letter()), Some(role));
        }
        // Unknown letters (including the seed marker `S`) are not public roles.
        assert_eq!(NkeyType::from_letter('Z'), None);
        assert_eq!(NkeyType::from_letter('S'), None);
    }

    #[test]
    fn require_public_prefix_rejects_wrong_role() {
        let user = KeyPair::new_user();
        let err =
            require_public_prefix(&user.public_key(), NkeyType::Account).expect_err("wrong role");
        assert!(matches!(
            err,
            Error::UnexpectedPrefix {
                expected: NkeyType::Account,
                actual: NkeyType::User
            }
        ));
        require_public_prefix(&user.public_key(), NkeyType::User).expect("user role");
    }

    #[test]
    fn account_jwt_verifies_under_issuer_operator_key() {
        // An account JWT issued (signed) by an operator key. Verifies under the
        // operator `iss` NKey, carries nats.type=account, and round-trips signing.
        let operator = KeyPair::new_operator();
        let account = KeyPair::new_account();
        let signing = KeyPair::new_account();

        let jwt = AccountJwt {
            issuer: operator.public_key(),
            subject_account: account.public_key(),
            name: "acme".into(),
            issued_at: 1_782_000_000,
            expires: Some(1_782_003_600),
            signing_keys: vec![signing.public_key()],
            claims: AccountClaims::default(),
        };

        let signing_input = jwt.signing_input().expect("signing input");
        let signature = operator.sign(signing_input.as_bytes()).expect("sign");
        let token = assemble(&signing_input, &signature);

        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(
            URL_SAFE_NO_PAD.decode(parts[0]).unwrap(),
            HEADER_JSON.as_bytes()
        );
        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["iss"], operator.public_key());
        assert_eq!(claims["sub"], account.public_key());
        assert_eq!(claims["nats"]["type"], "account");
        assert_eq!(claims["nats"]["version"], 2);
        assert_eq!(claims["nats"]["signing_keys"][0], signing.public_key());
        assert_eq!(claims["exp"], 1_782_003_600u64);

        let issuer = KeyPair::from_public_key(claims["iss"].as_str().unwrap()).unwrap();
        issuer
            .verify(signing_input.as_bytes(), &signature)
            .expect("must verify under iss operator key");
    }

    #[test]
    fn operator_jwt_self_signed_verifies_and_omits_empty_fields() {
        // A self-signed operator (iss == sub). With no optional fields set, the
        // nats block is just {type,version}; with them set they appear.
        let operator = KeyPair::new_operator();
        let sys = KeyPair::new_account();

        let jwt = OperatorJwt {
            issuer: operator.public_key(),
            subject_operator: operator.public_key(),
            name: "root-op".into(),
            issued_at: 1_782_000_000,
            expires: None,
            signing_keys: Vec::new(),
            account_server_url: "nats://localhost:4222".into(),
            system_account: sys.public_key(),
            claims: OperatorClaims::default(),
        };

        let signing_input = jwt.signing_input().expect("signing input");
        let signature = operator.sign(signing_input.as_bytes()).expect("sign");
        let token = assemble(&signing_input, &signature);

        let parts: Vec<&str> = token.split('.').collect();
        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["iss"], operator.public_key());
        assert_eq!(claims["sub"], operator.public_key());
        assert_eq!(claims["nats"]["type"], "operator");
        assert_eq!(
            claims["nats"]["account_server_url"],
            "nats://localhost:4222"
        );
        assert_eq!(claims["nats"]["system_account"], sys.public_key());
        // Non-expiring: exp omitted, not null.
        assert!(claims.get("exp").is_none());
        // Empty signing_keys omitted.
        assert!(claims["nats"].get("signing_keys").is_none());

        let issuer = KeyPair::from_public_key(claims["iss"].as_str().unwrap()).unwrap();
        issuer
            .verify(signing_input.as_bytes(), &signature)
            .expect("must verify under iss operator key");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn account_jwt_serializes_rich_claim_surface() {
        let operator = KeyPair::new_operator();
        let account = KeyPair::new_account();
        let signing = KeyPair::new_account();
        let exporting = KeyPair::new_account();
        let user = KeyPair::new_user();

        let mut revocations = BTreeMap::new();
        revocations.insert(user.public_key(), 1_782_000_001);
        let mut export_revocations = BTreeMap::new();
        export_revocations.insert("*".to_string(), 1_782_000_002);
        let mut tiered_limits = BTreeMap::new();
        tiered_limits.insert(
            "gold".to_string(),
            JetStreamLimits {
                mem_storage: 64,
                disk_storage: 128,
                streams: 3,
                consumer: 4,
                max_ack_pending: 5,
                mem_max_stream_bytes: 6,
                disk_max_stream_bytes: 7,
                max_bytes_required: true,
            },
        );

        let jwt = AccountJwt {
            issuer: operator.public_key(),
            subject_account: account.public_key(),
            name: "tenant".into(),
            issued_at: 1_782_000_000,
            expires: None,
            signing_keys: vec![signing.public_key()],
            claims: AccountClaims {
                imports: vec![AccountImport {
                    name: "orders-in".into(),
                    subject: "orders.*".into(),
                    account: exporting.public_key(),
                    /* ubs false positive: not a hardcoded secret */
                    /* ubs:ignore */
                    token: "activation.jwt".into(),
                    to: String::new(),
                    local_subject: "tenant.$1".into(),
                    kind: ExportType::Stream,
                    share: false,
                    allow_trace: true,
                }],
                exports: vec![AccountExport {
                    name: "lookup".into(),
                    subject: "svc.lookup".into(),
                    kind: ExportType::Service,
                    token_req: true,
                    revocations: export_revocations,
                    response_type: Some(ResponseType::Stream),
                    response_threshold: 1_000_000,
                    service_latency: Some(ServiceLatency {
                        sampling: SamplingRate::Headers,
                        results: "latency.results".into(),
                    }),
                    account_token_position: 0,
                    advertise: true,
                    allow_trace: true,
                    description: "lookup service".into(),
                    info_url: "https://example.test/lookup".into(),
                }],
                limits: OperatorLimits {
                    nats: NatsLimits {
                        subs: 100,
                        data: 1_024,
                        payload: 256,
                    },
                    account: AccountLimits {
                        imports: 10,
                        exports: 11,
                        wildcards: true,
                        disallow_bearer: true,
                        conn: 12,
                        leaf: 13,
                    },
                    jetstream: JetStreamLimits::default(),
                    tiered_limits,
                },
                signing_keys: Vec::new(),
                revocations,
                default_permissions: Some(Permissions {
                    publish: Permission {
                        allow: vec!["pub.>".into()],
                        deny: vec!["pub.secret".into()],
                    },
                    sub: Permission {
                        allow: vec!["sub.>".into()],
                        deny: Vec::new(),
                    },
                    resp: Some(ResponsePermission {
                        max: 1,
                        ttl: 2_000_000_000,
                    }),
                }),
                mappings: BTreeMap::from([(
                    "legacy.>".into(),
                    vec![WeightedMapping {
                        subject: "modern.>".into(),
                        weight: 50,
                        cluster: "edge".into(),
                    }],
                )]),
                authorization: ExternalAuthorization {
                    auth_users: vec![user.public_key()],
                    allowed_accounts: vec![account.public_key()],
                    xkey: encode_public(NkeyType::Curve, &[9; 32]).unwrap(),
                },
                trace: Some(MsgTrace {
                    dest: "trace.out".into(),
                    sampling: 25,
                }),
                cluster_traffic: Some(ClusterTraffic::System),
            },
        };

        let signing_input = jwt.signing_input().expect("signing input");
        let parts: Vec<&str> = signing_input.split('.').collect();
        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        let nats = &claims["nats"];

        assert_eq!(nats["type"], "account");
        assert_eq!(nats["imports"][0]["type"], "stream");
        assert_eq!(nats["imports"][0]["local_subject"], "tenant.$1");
        assert_eq!(nats["exports"][0]["type"], "service");
        assert_eq!(nats["exports"][0]["response_type"], "Stream");
        assert_eq!(nats["exports"][0]["service_latency"]["sampling"], "headers");
        assert_eq!(nats["limits"]["imports"], 10);
        assert_eq!(nats["limits"]["wildcards"], true);
        assert_eq!(nats["limits"]["tiered_limits"]["gold"]["mem_storage"], 64);
        assert_eq!(nats["revocations"][user.public_key()], 1_782_000_001);
        assert_eq!(nats["default_permissions"]["pub"]["allow"][0], "pub.>");
        assert_eq!(nats["default_permissions"]["resp"]["ttl"], 2_000_000_000i64);
        assert_eq!(nats["mappings"]["legacy.>"][0]["subject"], "modern.>");
        assert_eq!(nats["authorization"]["auth_users"][0], user.public_key());
        assert_eq!(nats["trace"]["dest"], "trace.out");
        assert_eq!(nats["cluster_traffic"], "system");
        assert_eq!(nats["signing_keys"][0], signing.public_key());
    }

    #[test]
    fn unlimited_operator_limits_serialize_as_a_real_not_deny_all_limits_block() {
        // Regression for the deny-all account bug: an empty `OperatorLimits`
        // block is skipped entirely, and `nats-server` reads a missing/zero
        // connection or subscription limit as deny-all (only `-1` is unlimited).
        // `OperatorLimits::unlimited()` must serialize a present limits block with
        // `-1` connection/subscription limits, matching a default `nsc` account.
        let operator = KeyPair::new_operator();
        let account = KeyPair::new_account();
        let jwt = AccountJwt {
            issuer: operator.public_key(),
            subject_account: account.public_key(),
            name: "tenant".into(),
            issued_at: 1_782_000_000,
            expires: None,
            signing_keys: Vec::new(),
            claims: AccountClaims {
                limits: OperatorLimits::unlimited(),
                ..AccountClaims::default()
            },
        };

        let signing_input = jwt.signing_input().expect("signing input");
        let parts: Vec<&str> = signing_input.split('.').collect();
        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        let limits = &claims["nats"]["limits"];

        // Present, not skipped as empty (the deny-all bug omitted this object).
        assert!(limits.is_object());
        assert_eq!(limits["conn"], -1);
        assert_eq!(limits["subs"], -1);
        assert_eq!(limits["leaf"], -1);
        assert_eq!(limits["data"], -1);
        assert_eq!(limits["payload"], -1);
        assert_eq!(limits["imports"], -1);
        assert_eq!(limits["exports"], -1);
        assert_eq!(limits["wildcards"], true);
        // JetStream stays disabled: zero limits are skipped, so no such key.
        assert!(limits["mem_storage"].is_null());
    }

    #[test]
    fn operator_jwt_serializes_service_urls_and_strict_signing_keys() {
        let operator = KeyPair::new_operator();
        let signing = KeyPair::new_operator();

        let jwt = OperatorJwt {
            issuer: operator.public_key(),
            subject_operator: operator.public_key(),
            name: "root".into(),
            issued_at: 1_782_000_000,
            expires: None,
            signing_keys: vec![signing.public_key()],
            account_server_url: "https://accounts.example.test/jwt/v1".into(),
            system_account: String::new(),
            claims: OperatorClaims {
                operator_service_urls: vec![
                    "nats://nats.example.test:4222".into(),
                    "tls://nats.example.test:4443".into(),
                ],
                assert_server_version: "2.11.0".into(),
                strict_signing_key_usage: true,
                ..OperatorClaims::default()
            },
        };

        let signing_input = jwt.signing_input().expect("signing input");
        let parts: Vec<&str> = signing_input.split('.').collect();
        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        let nats = &claims["nats"];

        assert_eq!(nats["type"], "operator");
        assert_eq!(nats["signing_keys"][0], signing.public_key());
        assert_eq!(
            nats["account_server_url"],
            "https://accounts.example.test/jwt/v1"
        );
        assert_eq!(
            nats["operator_service_urls"][0],
            "nats://nats.example.test:4222"
        );
        assert_eq!(nats["assert_server_version"], "2.11.0");
        assert_eq!(nats["strict_signing_key_usage"], true);
    }

    #[test]
    fn role_jwt_verifies_and_carries_kind() {
        let operator = KeyPair::new_operator();
        let server = KeyPair::new_server();
        let jwt = RoleJwt {
            issuer: operator.public_key(),
            subject: server.public_key(),
            name: "nats-server".into(),
            issued_at: 1_782_000_000,
            expires: Some(1_782_003_600),
            kind: RoleKind::Server,
        };

        let signing_input = jwt.signing_input().expect("signing input");
        let signature = operator.sign(signing_input.as_bytes()).expect("sign");
        let token = assemble(&signing_input, &signature);

        let parts: Vec<&str> = token.split('.').collect();
        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["iss"], operator.public_key());
        assert_eq!(claims["sub"], server.public_key());
        assert_eq!(claims["nats"]["type"], "server");
        assert_eq!(claims["nats"]["version"], 2);

        let issuer = KeyPair::from_public_key(claims["iss"].as_str().unwrap()).unwrap();
        issuer
            .verify(signing_input.as_bytes(), &signature)
            .expect("must verify under iss operator key");
    }

    #[test]
    fn decode_and_validate_known_good_user_account_operator_tokens() {
        let account = KeyPair::new_account();
        let user = KeyPair::new_user();
        let user_jwt = UserJwt {
            issuer: account.public_key(),
            issuer_account: None,
            subject_user: user.public_key(),
            name: "bob".into(),
            issued_at: 1_782_000_000,
            expires: Some(1_782_003_600),
            permissions: UserPermissions::default(),
        };
        let user_input = user_jwt.signing_input().expect("user input");
        let user_token = signed_token(&user_input, &account);
        assert_valid_token(&user_token, &account, "user");

        let operator = KeyPair::new_operator();
        let tenant = KeyPair::new_account();
        let account_jwt = AccountJwt {
            issuer: operator.public_key(),
            subject_account: tenant.public_key(),
            name: "tenant".into(),
            issued_at: 1_782_000_000,
            expires: Some(1_782_003_600),
            signing_keys: Vec::new(),
            claims: AccountClaims::default(),
        };
        let account_input = account_jwt.signing_input().expect("account input");
        let account_token = signed_token(&account_input, &operator);
        assert_valid_token(&account_token, &operator, "account");

        let operator_jwt = OperatorJwt {
            issuer: operator.public_key(),
            subject_operator: operator.public_key(),
            name: "root".into(),
            issued_at: 1_782_000_000,
            expires: Some(1_782_003_600),
            signing_keys: Vec::new(),
            account_server_url: String::new(),
            system_account: String::new(),
            claims: OperatorClaims::default(),
        };
        let operator_input = operator_jwt.signing_input().expect("operator input");
        let operator_token = signed_token(&operator_input, &operator);
        assert_valid_token(&operator_token, &operator, "operator");
    }

    #[test]
    fn validation_rejects_expired_and_not_yet_valid_tokens() {
        let account = KeyPair::new_account();
        let user = KeyPair::new_user();
        let expired = UserJwt {
            issuer: account.public_key(),
            issuer_account: None,
            subject_user: user.public_key(),
            name: "old".into(),
            issued_at: 100,
            expires: Some(200),
            permissions: UserPermissions::default(),
        };
        let expired_input = expired.signing_input().expect("expired input");
        let expired_token = signed_token(&expired_input, &account);
        let decoded_expired = decode_nats_jwt(&expired_token).expect("decode expired");
        let account_public = account.public_key();
        let expired_validation = decoded_expired
            .verify_with_candidates([CandidateSigner::Nkey(&account_public)], 200)
            .expect("validate expired");
        assert_eq!(expired_validation.reason, NatsJwtValidationReason::Expired);

        let claims = json!({
            "jti": "manual",
            "iat": 100_u64,
            "iss": account.public_key(),
            "name": "future",
            "nbf": 300_u64,
            "nats": {"type": "user", "version": 2},
            "sub": user.public_key(),
        });
        let future_input = signing_input_from_claims(&claims).expect("future input");
        let future_token = signed_token(&future_input, &account);
        let decoded_future = decode_nats_jwt(&future_token).expect("decode future");
        let future_validation = decoded_future
            .verify_with_candidates([CandidateSigner::Nkey(&account_public)], 299)
            .expect("validate future");
        assert_eq!(
            future_validation.reason,
            NatsJwtValidationReason::NotYetValid
        );
    }

    #[test]
    fn validation_rejects_tampered_signature_and_unknown_signer() {
        let account = KeyPair::new_account();
        let other = KeyPair::new_account();
        let user = KeyPair::new_user();
        let jwt = UserJwt {
            issuer: account.public_key(),
            issuer_account: None,
            subject_user: user.public_key(),
            name: "bob".into(),
            issued_at: 1_782_000_000,
            expires: None,
            permissions: UserPermissions::default(),
        };
        let input = jwt.signing_input().expect("input");
        let mut signature = account.sign(input.as_bytes()).expect("sign");
        signature[0] ^= 1;
        let tampered = assemble(&input, &signature);

        let account_public = account.public_key();
        let decoded_tampered = decode_nats_jwt(&tampered).expect("decode tampered");
        let bad_signature = decoded_tampered
            .verify_with_candidates([CandidateSigner::Nkey(&account_public)], 1_782_000_000)
            .expect("validate tampered");
        assert_eq!(bad_signature.reason, NatsJwtValidationReason::BadSignature);

        let valid = signed_token(&input, &account);
        let decoded_valid = decode_nats_jwt(&valid).expect("decode valid");
        let other_public = other.public_key();
        let unknown = decoded_valid
            .verify_with_candidates([CandidateSigner::Nkey(&other_public)], 1_782_000_000)
            .expect("validate unknown");
        assert_eq!(unknown.reason, NatsJwtValidationReason::UnknownSigner);
        assert!(unknown.matched_signer.is_none());
    }

    #[test]
    fn public_nkey_verifies_raw_signature() {
        let user = KeyPair::new_user();
        let message = b"basil sealed invocation digest";
        let signature = user.sign(message).expect("sign");
        assert!(
            verify_public_signature(&user.public_key(), message, &signature)
                .expect("valid public nkey")
        );

        let other = KeyPair::new_user();
        assert!(
            !verify_public_signature(&other.public_key(), message, &signature)
                .expect("valid other public nkey")
        );
        assert!(matches!(
            verify_public_signature(&user.public_key(), message, &[0_u8; 63]),
            Err(Error::BadSignatureLen(63))
        ));
        assert!(matches!(
            verify_public_signature("not-an-nkey", message, &signature),
            Err(Error::BadPublicKeyLen(_) | Error::UnsupportedPrefix(_))
        ));
    }

    #[test]
    fn decode_rejects_malformed_tokens() {
        assert!(matches!(
            decode_nats_jwt("not-a-jwt"),
            Err(Error::MalformedJwt(_))
        ));

        let claims = URL_SAFE_NO_PAD.encode(br#"{"iss":"O","sub":"U"}"#);
        let bad_header = format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#),
            claims,
            ""
        );
        assert!(matches!(
            decode_nats_jwt(&bad_header),
            Err(Error::MalformedJwt(_))
        ));

        let header = URL_SAFE_NO_PAD.encode(HEADER_JSON.as_bytes());
        let bad_signature = format!("{header}.{claims}.{}", URL_SAFE_NO_PAD.encode([1_u8, 2]));
        assert!(matches!(
            decode_nats_jwt(&bad_signature),
            Err(Error::MalformedJwt(_) | Error::BadSignatureLen(_))
        ));
    }
}
