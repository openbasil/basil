//! Validated identifier newtypes and byte-carrying parameter structs.
//!
//! Everything a caller passes is a named struct or a closed enum: no bare
//! `&[u8]`/`&str` in public positions. Constructors validate; decoded wire
//! values pass through the same constructors, so an in-range value is an
//! invariant of the type.

use alloc::string::String;
use alloc::vec::Vec;

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
