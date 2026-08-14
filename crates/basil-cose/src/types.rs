// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Validated identifier newtypes and byte-carrying parameter structs.
//!
//! Everything a caller passes is a named struct or a closed enum: no bare
//! `&[u8]`/`&str` in public positions. Constructors validate; decoded wire
//! values pass through the same constructors, so an in-range value is an
//! invariant of the type.

use alloc::string::String;
use alloc::vec::Vec;

use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::ProfileError;

/// COSE `kid` (bstr, 1..=128 bytes). Basil catalog names are UTF-8; other
/// consumers may use raw byte ids.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId(Vec<u8>);

impl KeyId {
    /// Build a key id from the UTF-8 bytes of a catalog name.
    ///
    /// # Errors
    /// [`ProfileError::KeyIdLength`] if the name is empty or longer than 128
    /// bytes.
    pub fn from_text(id: &str) -> Result<Self, ProfileError> {
        Self::from_bytes(id.as_bytes().to_vec())
    }

    /// Build a key id from raw bytes.
    ///
    /// # Errors
    /// [`ProfileError::KeyIdLength`] if not 1..=128 bytes.
    pub fn from_bytes(id: Vec<u8>) -> Result<Self, ProfileError> {
        if id.is_empty() || id.len() > 128 {
            return Err(ProfileError::KeyIdLength { actual: id.len() });
        }
        Ok(Self(id))
    }

    /// The catalog name, when the id is valid UTF-8.
    #[must_use]
    pub fn as_catalog_name(&self) -> Option<&str> {
        core::str::from_utf8(&self.0).ok()
    }

    /// The raw id bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// CWT `cti` (bstr, 1..=64 bytes, sender-unique inside the replay window).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessageId(Vec<u8>);

impl MessageId {
    /// Build a message id from raw bytes.
    ///
    /// # Errors
    /// [`ProfileError::MessageIdLength`] if not 1..=64 bytes.
    pub fn from_bytes(id: Vec<u8>) -> Result<Self, ProfileError> {
        if id.is_empty() || id.len() > 64 {
            return Err(ProfileError::MessageIdLength { actual: id.len() });
        }
        Ok(Self(id))
    }

    /// The raw id bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// CWT `iss`/`aud` subject (tstr, non-empty).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Subject(String);

impl Subject {
    /// Build a subject string.
    ///
    /// # Errors
    /// [`ProfileError::EmptySubject`] if the string is empty.
    pub fn new(subject: String) -> Result<Self, ProfileError> {
        if subject.is_empty() {
            return Err(ProfileError::EmptySubject);
        }
        Ok(Self(subject))
    }

    /// The subject string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The `-70005` response subject (tstr, non-empty).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResponseSubject(String);

impl ResponseSubject {
    /// Build a response subject string.
    ///
    /// # Errors
    /// [`ProfileError::EmptySubject`] if the string is empty.
    pub fn new(subject: String) -> Result<Self, ProfileError> {
        if subject.is_empty() {
            return Err(ProfileError::EmptySubject);
        }
        Ok(Self(subject))
    }

    /// The subject string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Content type (COSE header 3, tstr media type of `type/subtype` form).
///
/// Registry values for basil live in `basil-proto` (for example
/// `application/basil.sign-request`); clients can register their own strings. The
/// tstr content type is a media type per RFC 9052, so the profile requires
/// the `type/subtype` shape with no surrounding whitespace.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentType(String);

impl ContentType {
    /// Build a content type.
    ///
    /// # Errors
    /// [`ProfileError::ContentTypeForm`] unless the string is non-empty,
    /// contains exactly one `/`, and has no leading/trailing whitespace.
    pub fn new(content_type: String) -> Result<Self, ProfileError> {
        if content_type.is_empty()
            || content_type.trim() != content_type
            || content_type.matches('/').count() != 1
        {
            return Err(ProfileError::ContentTypeForm);
        }
        Ok(Self(content_type))
    }

    /// The content-type string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The `-70008` server-issued single-use freshness challenge (bstr, 32 bytes).
///
/// The value is a 16-byte issuing-instance ID prefix followed by 16 CSPRNG
/// bytes, issued by the broker's `GetInvocationChallenge` and consumed
/// exactly once. Requests only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FreshnessChallenge([u8; 32]);

impl FreshnessChallenge {
    /// Wrap an already-sized 32-byte challenge.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Build a freshness challenge from raw bytes.
    ///
    /// # Errors
    /// [`ProfileError::FreshnessChallengeLength`] unless exactly 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProfileError> {
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| ProfileError::FreshnessChallengeLength {
                actual: bytes.len(),
            })
    }

    /// The raw challenge bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The `-70009` ephemeral response public key.
///
/// The protected value is the exact deterministic 40-byte X25519
/// `COSE_Key` encoding `{1: 1, -1: 4, -2: x}`. Construction rejects the
/// noncanonical high-bit alias and every non-contributory public key before
/// the value can enter a claim set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct X25519ResponsePublicKey([u8; 32]);

impl X25519ResponsePublicKey {
    /// Exact deterministic `COSE_Key` prefix preceding the 32 public bytes.
    pub const COSE_KEY_PREFIX: [u8; 8] = [0xa3, 0x01, 0x01, 0x20, 0x04, 0x21, 0x58, 0x20];

    /// Validate raw X25519 public-key bytes.
    ///
    /// # Errors
    /// [`ProfileError::ResponsePublicKeyHighBitAlias`] when the unused high
    /// bit is set, or [`ProfileError::ResponsePublicKeyNonContributory`] for
    /// a low-order public key.
    pub fn from_public_bytes(public: [u8; 32]) -> Result<Self, ProfileError> {
        if public.last().is_some_and(|last| last & 0x80 != 0) {
            return Err(ProfileError::ResponsePublicKeyHighBitAlias);
        }
        // A fixed nonzero scalar is sufficient to detect the X25519
        // all-zero shared-secret condition for every low-order input.
        let probe = StaticSecret::from([0x5a; 32]);
        let shared = probe.diffie_hellman(&PublicKey::from(public)).to_bytes();
        if shared.iter().all(|byte| *byte == 0) {
            return Err(ProfileError::ResponsePublicKeyNonContributory);
        }
        Ok(Self(public))
    }

    /// Decode and validate the exact deterministic 40-byte `COSE_Key`.
    ///
    /// # Errors
    /// [`ProfileError::ResponsePublicKeyCoseShape`] for any alternate shape,
    /// member, ordering, integer encoding, length encoding, or trailing byte;
    /// the raw-key errors from [`Self::from_public_bytes`] also apply.
    pub fn from_cose_key_bytes(bytes: &[u8]) -> Result<Self, ProfileError> {
        let public = bytes
            .strip_prefix(&Self::COSE_KEY_PREFIX)
            .ok_or(ProfileError::ResponsePublicKeyCoseShape)?;
        let public: [u8; 32] = public
            .try_into()
            .map_err(|_| ProfileError::ResponsePublicKeyCoseShape)?;
        Self::from_public_bytes(public)
    }

    /// Return the raw 32-byte X25519 public key.
    #[must_use]
    pub const fn as_public_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Return the exact deterministic 40-byte `COSE_Key` encoding.
    #[must_use]
    pub fn to_cose_key_bytes(self) -> [u8; 40] {
        let mut encoded = [0u8; 40];
        for (output, input) in encoded
            .iter_mut()
            .zip(Self::COSE_KEY_PREFIX.into_iter().chain(self.0))
        {
            *output = input;
        }
        encoded
    }

    /// Return the exact 43-character unpadded base64url RFC 7638 thumbprint.
    ///
    /// The digest input is the canonical JWK member string
    /// `{"crv":"X25519","kty":"OKP","x":"<base64url-public>"}`.
    #[must_use]
    pub fn thumbprint(&self) -> String {
        let x = base64url_no_pad(&self.0);
        let mut jwk = String::from("{\"crv\":\"X25519\",\"kty\":\"OKP\",\"x\":\"");
        jwk.push_str(&x);
        jwk.push_str("\"}");
        base64url_no_pad(&Sha256::digest(jwk.as_bytes()))
    }
}

fn base64url_no_pad(bytes: &[u8]) -> String {
    fn alphabet(value: u8) -> char {
        char::from(match value {
            0..=25 => b'A' + value,
            26..=51 => b'a' + (value - 26),
            52..=61 => b'0' + (value - 52),
            62 => b'-',
            _ => b'_',
        })
    }

    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut chunks = bytes.chunks_exact(3);
    for chunk in &mut chunks {
        let &[a, b, c] = chunk else {
            continue;
        };
        output.push(alphabet(a >> 2));
        output.push(alphabet(((a & 0x03) << 4) | (b >> 4)));
        output.push(alphabet(((b & 0x0f) << 2) | (c >> 6)));
        output.push(alphabet(c & 0x3f));
    }
    match chunks.remainder() {
        [a] => {
            output.push(alphabet(a >> 2));
            output.push(alphabet((a & 0x03) << 4));
        }
        [a, b] => {
            output.push(alphabet(a >> 2));
            output.push(alphabet(((a & 0x03) << 4) | (b >> 4)));
            output.push(alphabet((b & 0x0f) << 2));
        }
        _ => {}
    }
    output
}

/// Seconds since the Unix epoch (CWT `iat`/`exp`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnixTime(pub i64);

/// Caller-supplied `external_aad` for exactly one COSE layer. Empty is the
/// explicit default, not an implicit one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalAad(Vec<u8>);

impl ExternalAad {
    /// No external AAD for this layer.
    #[must_use]
    pub const fn empty() -> Self {
        Self(Vec::new())
    }

    /// External AAD from protocol-bound bytes.
    #[must_use]
    pub const fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The AAD bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Per-layer AAD for the sealed (two-layer) construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedAad {
    /// Fed to the `Sig_structure` of the outer `COSE_Sign1`.
    pub signature: ExternalAad,
    /// Fed to the `Enc_structure` of the embedded `COSE_Encrypt`.
    pub encryption: ExternalAad,
}

impl SealedAad {
    /// Empty AAD on both layers (the basil invocation default).
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            signature: ExternalAad::empty(),
            encryption: ExternalAad::empty(),
        }
    }
}

/// A raw signature over `Sig_structure` bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature(Vec<u8>);

impl Signature {
    /// Wrap signature bytes.
    ///
    /// # Errors
    /// [`ProfileError::EmptySignature`] if the bytes are empty.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, ProfileError> {
        if bytes.is_empty() {
            return Err(ProfileError::EmptySignature);
        }
        Ok(Self(bytes))
    }

    /// The raw signature bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Complete tagged COSE bytes: the output of every build entry point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoseBytes(Vec<u8>);

impl CoseBytes {
    pub(crate) const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The complete tagged COSE bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume into the raw byte vector.
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

impl AsRef<[u8]> for CoseBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOW_ORDER_ENCODINGS: [[u8; 32]; 7] = [
        [0; 32],
        [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ],
        [
            0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
            0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
            0x5f, 0x49, 0xb8, 0x00,
        ],
        [
            0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83,
            0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd,
            0xd0, 0x9f, 0x11, 0x57,
        ],
        [
            0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
        [
            0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
        [
            0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
    ];

    fn basepoint() -> [u8; 32] {
        let mut public = [0; 32];
        public[0] = 9;
        public
    }

    #[test]
    fn response_public_key_exact_encoding_and_thumbprint_vector() {
        let key = X25519ResponsePublicKey::from_public_bytes(basepoint()).unwrap();
        let mut expected = X25519ResponsePublicKey::COSE_KEY_PREFIX.to_vec();
        expected.extend_from_slice(&basepoint());
        assert_eq!(key.to_cose_key_bytes().as_slice(), expected);
        assert_eq!(expected.len(), 40);
        assert_eq!(
            key.thumbprint(),
            "mtr3IeKcdvsDY_Jfv9EL0n01w9Nw7T36mUSLv_VMdv4"
        );
        assert_eq!(key.thumbprint().len(), 43);
        assert!(!key.thumbprint().contains('='));
        assert_eq!(
            X25519ResponsePublicKey::from_cose_key_bytes(&expected),
            Ok(key)
        );
    }

    #[test]
    fn response_public_key_rejects_all_low_order_encodings_and_high_bit_alias() {
        for public in LOW_ORDER_ENCODINGS {
            assert_eq!(
                X25519ResponsePublicKey::from_public_bytes(public),
                Err(ProfileError::ResponsePublicKeyNonContributory)
            );
        }
        let mut alias = basepoint();
        alias[31] = 0x80;
        assert_eq!(
            X25519ResponsePublicKey::from_public_bytes(alias),
            Err(ProfileError::ResponsePublicKeyHighBitAlias)
        );
    }

    #[test]
    fn response_public_key_rejects_every_nonexact_cose_shape() {
        let mut canonical = X25519ResponsePublicKey::COSE_KEY_PREFIX.to_vec();
        canonical.extend_from_slice(&basepoint());

        let mut wrong_order = canonical.clone();
        wrong_order.swap(1, 3);
        let mut wrong_curve = canonical.clone();
        wrong_curve[4] = 5;
        let mut nonminimal_integer = canonical.clone();
        nonminimal_integer.splice(1..2, [0x18, 0x01]);
        let mut nonminimal_length = canonical.clone();
        nonminimal_length.splice(6..8, [0x59, 0x00, 0x20]);
        let mut unknown_member = canonical.clone();
        unknown_member[0] = 0xa4;
        unknown_member.extend_from_slice(&[0x02, 0x00]);
        let mut duplicate_member = canonical.clone();
        duplicate_member[0] = 0xa4;
        duplicate_member.extend_from_slice(&[0x01, 0x01]);
        let mut trailing = canonical.clone();
        trailing.push(0);

        for malformed in [
            wrong_order,
            wrong_curve,
            nonminimal_integer,
            nonminimal_length,
            unknown_member,
            duplicate_member,
            trailing,
            canonical[..39].to_vec(),
        ] {
            assert_eq!(
                X25519ResponsePublicKey::from_cose_key_bytes(&malformed),
                Err(ProfileError::ResponsePublicKeyCoseShape)
            );
        }
    }
}
