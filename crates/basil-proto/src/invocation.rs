// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Sealed-invocation plaintext body schemas and the basil content-type
//! registry.
//!
//! Envelope canonicalization moved to the `basil-cose` strict COSE profile;
//! this module owns what stays basil-specific: the registered COSE content
//! types (RFC 9052 protected header 3) that select a plaintext body schema,
//! the deterministic CBOR body codecs, and [`InvocationStatus`].

use std::fmt;

/// The only supported sealed-invocation envelope version.
pub const SECURE_MESSAGE_VERSION: u32 = 1;
/// Default signed request TTL when `expires_at_unix` is absent.
pub const DEFAULT_EXPIRES_AFTER_SECS: u32 = 60;

/// COSE content type for [`SignInvocationRequest`] plaintext bodies.
///
/// Registry values are media-type-shaped (`type/subtype`) because the
/// `basil-cose` profile enforces RFC 9052 tstr content-type semantics; bare
/// names such as `basil.sign-request` are rejected by its strict decoder.
pub const CONTENT_TYPE_SIGN_REQUEST: &str = "application/basil.sign-request";
/// COSE content type for [`SignInvocationResponse`] plaintext bodies.
pub const CONTENT_TYPE_SIGN_RESPONSE: &str = "application/basil.sign-response";
/// COSE content type for [`MintJwtInvocationRequest`] plaintext bodies.
pub const CONTENT_TYPE_MINT_JWT_REQUEST: &str = "application/basil.mint-jwt-request";
/// COSE content type for [`MintJwtInvocationResponse`] plaintext bodies.
pub const CONTENT_TYPE_MINT_JWT_RESPONSE: &str = "application/basil.mint-jwt-response";
/// COSE content type for [`MintNatsUserInvocationRequest`] plaintext bodies.
pub const CONTENT_TYPE_MINT_NATS_USER_REQUEST: &str = "application/basil.mint-nats-user-request";
/// COSE content type for [`MintNatsUserInvocationResponse`] plaintext bodies.
pub const CONTENT_TYPE_MINT_NATS_USER_RESPONSE: &str = "application/basil.mint-nats-user-response";

/// Every registered basil invocation content type, request/response pairs in
/// registry order.
pub const INVOCATION_CONTENT_TYPES: [&str; 6] = [
    CONTENT_TYPE_SIGN_REQUEST,
    CONTENT_TYPE_SIGN_RESPONSE,
    CONTENT_TYPE_MINT_JWT_REQUEST,
    CONTENT_TYPE_MINT_JWT_RESPONSE,
    CONTENT_TYPE_MINT_NATS_USER_REQUEST,
    CONTENT_TYPE_MINT_NATS_USER_RESPONSE,
];

/// Errors returned while validating or canonicalizing sealed invocation data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvocationError {
    /// A required header field was absent or empty.
    MissingField(&'static str),
    /// A CBOR plaintext body did not match its declared schema.
    InvalidBody(&'static str),
}

impl fmt::Display for InvocationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingField(field) => write!(f, "missing required header field `{field}`"),
            Self::InvalidBody(reason) => write!(f, "invalid invocation body: {reason}"),
        }
    }
}

impl std::error::Error for InvocationError {}

/// Status code carried inside encrypted invocation response bodies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvocationStatusCode {
    /// Operation succeeded.
    Ok = 1,
    /// Policy denied the operation.
    Denied = 2,
    /// The request body or operation fields were invalid.
    InvalidRequest = 3,
    /// The broker hit an internal operation error.
    InternalError = 4,
}

impl InvocationStatusCode {
    /// Convert a CBOR integer status code into a typed value.
    #[must_use]
    pub const fn from_u64(value: u64) -> Option<Self> {
        match value {
            1 => Some(Self::Ok),
            2 => Some(Self::Denied),
            3 => Some(Self::InvalidRequest),
            4 => Some(Self::InternalError),
            _ => None,
        }
    }
}

/// Status carried inside encrypted invocation response bodies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvocationStatus {
    /// Machine-readable status code.
    pub code: InvocationStatusCode,
    /// Stable sanitized reason token.
    pub reason: String,
    /// Optional sanitized diagnostic.
    pub message: Option<String>,
    /// Whether the caller may retry unchanged.
    pub retryable: bool,
}

impl InvocationStatus {
    /// Successful operation status.
    #[must_use]
    pub fn ok() -> Self {
        Self {
            code: InvocationStatusCode::Ok,
            reason: "OK".to_string(),
            message: None,
            retryable: false,
        }
    }

    /// Policy-denied operation status.
    #[must_use]
    pub fn denied() -> Self {
        Self {
            code: InvocationStatusCode::Denied,
            reason: "UNAUTHORIZED".to_string(),
            message: Some("not authorized".to_string()),
            retryable: false,
        }
    }

    /// Invalid-request operation status.
    #[must_use]
    pub fn invalid_request(reason: impl Into<String>) -> Self {
        Self {
            code: InvocationStatusCode::InvalidRequest,
            reason: reason.into(),
            message: None,
            retryable: false,
        }
    }

    /// Internal-error operation status.
    #[must_use]
    pub fn internal_error() -> Self {
        Self {
            code: InvocationStatusCode::InternalError,
            reason: "INTERNAL_ERROR".to_string(),
            message: None,
            retryable: true,
        }
    }

    fn encode_cbor(&self, out: &mut Vec<u8>) {
        cbor_map(out, 4);
        cbor_u64(out, 1);
        cbor_u64(out, self.code as u64);
        cbor_u64(out, 2);
        cbor_text(out, &self.reason);
        cbor_u64(out, 3);
        cbor_optional_text(out, self.message.as_deref());
        cbor_u64(out, 4);
        cbor_bool(out, self.retryable);
    }
}

/// CBOR body selected by [`CONTENT_TYPE_SIGN_REQUEST`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignInvocationRequest {
    /// Catalog signing key id.
    pub key_id: String,
    /// Raw message to sign.
    pub message: Vec<u8>,
    /// `SigningAlgorithm` integer value from the protobuf schema.
    pub algorithm: i32,
}

impl SignInvocationRequest {
    /// Encode this body as deterministic CBOR.
    #[must_use]
    pub fn to_cbor_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        cbor_map(&mut out, 3);
        cbor_u64(&mut out, 1);
        cbor_text(&mut out, &self.key_id);
        cbor_u64(&mut out, 2);
        cbor_bytes(&mut out, &self.message);
        cbor_u64(&mut out, 3);
        cbor_i64(&mut out, i64::from(self.algorithm));
        out
    }

    /// Decode a deterministic CBOR `SignInvocationRequest`.
    ///
    /// # Errors
    ///
    /// Returns [`InvocationError`] when the body does not match the v1 schema.
    pub fn from_cbor_bytes(bytes: &[u8]) -> Result<Self, InvocationError> {
        let mut decoder = CborDecoder::new(bytes);
        decoder.map_len(3, "SignInvocationRequest")?;
        decoder.key(1)?;
        let key_id = decoder.text("key_id")?;
        decoder.key(2)?;
        let message = decoder.bytes("message")?;
        decoder.key(3)?;
        let algorithm = decoder.i64("algorithm")?;
        decoder.finish()?;
        let algorithm = i32::try_from(algorithm)
            .map_err(|_| InvocationError::InvalidBody("algorithm out of range"))?;
        Ok(Self {
            key_id,
            message,
            algorithm,
        })
    }
}

/// CBOR body selected by [`CONTENT_TYPE_SIGN_RESPONSE`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignInvocationResponse {
    /// Trusted operation status.
    pub status: InvocationStatus,
    /// Policy generation used for the operation decision.
    pub policy_generation: u64,
    /// Raw signature bytes.
    pub signature: Option<Vec<u8>>,
}

impl SignInvocationResponse {
    /// Encode this body as deterministic CBOR.
    #[must_use]
    pub fn to_cbor_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        cbor_map(&mut out, 3);
        cbor_u64(&mut out, 1);
        self.status.encode_cbor(&mut out);
        cbor_u64(&mut out, 2);
        cbor_u64(&mut out, self.policy_generation);
        cbor_u64(&mut out, 3);
        cbor_optional_bytes(&mut out, self.signature.as_deref());
        out
    }

    /// Decode a deterministic CBOR `SignInvocationResponse`.
    ///
    /// # Errors
    ///
    /// Returns [`InvocationError`] when the body does not match the v1 schema.
    pub fn from_cbor_bytes(bytes: &[u8]) -> Result<Self, InvocationError> {
        let mut decoder = CborDecoder::new(bytes);
        decoder.map_len(3, "SignInvocationResponse")?;
        decoder.key(1)?;
        let status = decoder.status()?;
        decoder.key(2)?;
        let policy_generation = decoder.u64("policy_generation")?;
        decoder.key(3)?;
        let signature = decoder.optional_bytes("signature")?;
        decoder.finish()?;
        if status.code == InvocationStatusCode::Ok && signature.is_none() {
            return Err(InvocationError::InvalidBody(
                "successful sign response missing signature",
            ));
        }
        if status.code != InvocationStatusCode::Ok && signature.is_some() {
            return Err(InvocationError::InvalidBody(
                "non-success sign response carries signature",
            ));
        }
        Ok(Self {
            status,
            policy_generation,
            signature,
        })
    }
}

/// CBOR body selected by [`CONTENT_TYPE_MINT_JWT_RESPONSE`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintJwtInvocationResponse {
    /// Trusted operation status.
    pub status: InvocationStatus,
    /// Policy generation used for the operation decision.
    pub policy_generation: u64,
    /// Minted JWT when status is [`InvocationStatusCode::Ok`].
    pub jwt: Option<String>,
    /// JWT expiry when known.
    pub expires_at_unix: Option<u64>,
}

impl MintJwtInvocationResponse {
    /// Encode this body as deterministic CBOR.
    #[must_use]
    pub fn to_cbor_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        cbor_map(&mut out, 4);
        cbor_u64(&mut out, 1);
        self.status.encode_cbor(&mut out);
        cbor_u64(&mut out, 2);
        cbor_u64(&mut out, self.policy_generation);
        cbor_u64(&mut out, 3);
        cbor_optional_text(&mut out, self.jwt.as_deref());
        cbor_u64(&mut out, 4);
        cbor_optional_u64(&mut out, self.expires_at_unix);
        out
    }
}

/// CBOR body selected by [`CONTENT_TYPE_MINT_NATS_USER_RESPONSE`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintNatsUserInvocationResponse {
    /// Trusted operation status.
    pub status: InvocationStatus,
    /// Policy generation used for the operation decision.
    pub policy_generation: u64,
    /// Minted NATS JWT when status is [`InvocationStatusCode::Ok`].
    pub jwt: Option<String>,
    /// JWT expiry when known.
    pub expires_at_unix: Option<u64>,
}

impl MintNatsUserInvocationResponse {
    /// Encode this body as deterministic CBOR.
    #[must_use]
    pub fn to_cbor_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        cbor_map(&mut out, 4);
        cbor_u64(&mut out, 1);
        self.status.encode_cbor(&mut out);
        cbor_u64(&mut out, 2);
        cbor_u64(&mut out, self.policy_generation);
        cbor_u64(&mut out, 3);
        cbor_optional_text(&mut out, self.jwt.as_deref());
        cbor_u64(&mut out, 4);
        cbor_optional_u64(&mut out, self.expires_at_unix);
        out
    }
}

/// CBOR body selected by [`CONTENT_TYPE_MINT_JWT_REQUEST`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintJwtInvocationRequest {
    /// Catalog signing key id.
    pub key_id: String,
    /// JWT subject.
    pub subject: Option<String>,
    /// TTL in whole seconds.
    pub ttl_secs: Option<u64>,
    /// Canonical JSON bytes for additional claims.
    pub claims_json: Vec<u8>,
}

impl MintJwtInvocationRequest {
    /// Encode this body as deterministic CBOR.
    #[must_use]
    pub fn to_cbor_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        cbor_map(&mut out, 4);
        cbor_u64(&mut out, 1);
        cbor_text(&mut out, &self.key_id);
        cbor_u64(&mut out, 2);
        cbor_optional_text(&mut out, self.subject.as_deref());
        cbor_u64(&mut out, 3);
        cbor_optional_u64(&mut out, self.ttl_secs);
        cbor_u64(&mut out, 4);
        cbor_bytes(&mut out, &self.claims_json);
        out
    }
}

/// CBOR body selected by [`CONTENT_TYPE_MINT_NATS_USER_REQUEST`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintNatsUserInvocationRequest {
    /// Account signing key id.
    pub account_key_id: String,
    /// User public `NKey`.
    pub user_nkey: String,
    /// User name.
    pub name: String,
    /// TTL in whole seconds.
    pub ttl_secs: Option<u64>,
    /// Owning account identity, populated when `account_key_id` is a signing
    /// key rather than the account identity itself. Becomes the minted user
    /// JWT's `nats.issuer_account` claim.
    pub issuer_account: Option<String>,
}

impl MintNatsUserInvocationRequest {
    /// Encode this body as deterministic CBOR.
    #[must_use]
    pub fn to_cbor_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        cbor_map(&mut out, 5);
        cbor_u64(&mut out, 1);
        cbor_text(&mut out, &self.account_key_id);
        cbor_u64(&mut out, 2);
        cbor_text(&mut out, &self.user_nkey);
        cbor_u64(&mut out, 3);
        cbor_text(&mut out, &self.name);
        cbor_u64(&mut out, 4);
        cbor_optional_u64(&mut out, self.ttl_secs);
        cbor_u64(&mut out, 5);
        cbor_optional_text(&mut out, self.issuer_account.as_deref());
        out
    }

    /// Decode a deterministic CBOR `MintNatsUserInvocationRequest`.
    ///
    /// # Errors
    ///
    /// Returns [`InvocationError`] when the body does not match the v1 schema.
    pub fn from_cbor_bytes(bytes: &[u8]) -> Result<Self, InvocationError> {
        let mut decoder = CborDecoder::new(bytes);
        decoder.map_len(5, "MintNatsUserInvocationRequest")?;
        decoder.key(1)?;
        let account_key_id = decoder.text("account_key_id")?;
        decoder.key(2)?;
        let user_nkey = decoder.text("user_nkey")?;
        decoder.key(3)?;
        let name = decoder.text("name")?;
        decoder.key(4)?;
        let ttl_secs = decoder.optional_u64("ttl_secs")?;
        decoder.key(5)?;
        let issuer_account = decoder.optional_text("issuer_account")?;
        decoder.finish()?;
        Ok(Self {
            account_key_id,
            user_nkey,
            name,
            ttl_secs,
            issuer_account,
        })
    }
}

fn cbor_map(out: &mut Vec<u8>, len: u64) {
    cbor_type_len(out, 5, len);
}

fn cbor_text(out: &mut Vec<u8>, value: &str) {
    cbor_type_len(out, 3, u64::try_from(value.len()).unwrap_or(u64::MAX));
    out.extend_from_slice(value.as_bytes());
}

fn cbor_bytes(out: &mut Vec<u8>, value: &[u8]) {
    cbor_type_len(out, 2, u64::try_from(value.len()).unwrap_or(u64::MAX));
    out.extend_from_slice(value);
}

fn cbor_optional_text(out: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => cbor_text(out, value),
        None => cbor_null(out),
    }
}

fn cbor_optional_bytes(out: &mut Vec<u8>, value: Option<&[u8]>) {
    match value {
        Some(value) => cbor_bytes(out, value),
        None => cbor_null(out),
    }
}

fn cbor_optional_u64(out: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => cbor_u64(out, value),
        None => cbor_null(out),
    }
}

fn cbor_bool(out: &mut Vec<u8>, value: bool) {
    out.push(if value { 0xf5 } else { 0xf4 });
}

fn cbor_null(out: &mut Vec<u8>) {
    out.push(0xf6);
}

fn cbor_i64(out: &mut Vec<u8>, value: i64) {
    if value >= 0 {
        cbor_u64(out, value.unsigned_abs());
    } else {
        cbor_type_len(out, 1, value.unsigned_abs() - 1);
    }
}

fn cbor_u64(out: &mut Vec<u8>, value: u64) {
    cbor_type_len(out, 0, value);
}

fn cbor_type_len(out: &mut Vec<u8>, major: u8, value: u64) {
    let head = major << 5;
    if value <= 23 {
        out.push(head | u8::try_from(value).unwrap_or(23));
    } else if let Ok(v) = u8::try_from(value) {
        out.extend_from_slice(&[head | 0x18, v]);
    } else if let Ok(v) = u16::try_from(value) {
        out.push(head | 0x19);
        out.extend_from_slice(&v.to_be_bytes());
    } else if let Ok(v) = u32::try_from(value) {
        out.push(head | 0x1a);
        out.extend_from_slice(&v.to_be_bytes());
    } else {
        out.push(head | 0x1b);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

#[derive(Debug)]
struct CborDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> CborDecoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    const fn finish(&self) -> Result<(), InvocationError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(InvocationError::InvalidBody("trailing CBOR bytes"))
        }
    }

    fn map_len(&mut self, expected: u64, schema: &'static str) -> Result<(), InvocationError> {
        let len = self.type_len(5, schema)?;
        if len == expected {
            Ok(())
        } else {
            Err(InvocationError::InvalidBody("unexpected CBOR map length"))
        }
    }

    fn key(&mut self, expected: u64) -> Result<(), InvocationError> {
        let actual = self.u64("map key")?;
        if actual == expected {
            Ok(())
        } else {
            Err(InvocationError::InvalidBody("unexpected CBOR map key"))
        }
    }

    fn status(&mut self) -> Result<InvocationStatus, InvocationError> {
        self.map_len(4, "InvocationStatus")?;
        self.key(1)?;
        let code = self.u64("status.code")?;
        let code = InvocationStatusCode::from_u64(code).ok_or(InvocationError::InvalidBody(
            "invalid invocation status code",
        ))?;
        self.key(2)?;
        let reason = self.text("status.reason")?;
        if reason.is_empty() {
            return Err(InvocationError::InvalidBody(
                "empty invocation status reason",
            ));
        }
        self.key(3)?;
        let message = self.optional_text("status.message")?;
        self.key(4)?;
        let retryable = self.bool("status.retryable")?;
        Ok(InvocationStatus {
            code,
            reason,
            message,
            retryable,
        })
    }

    fn u64(&mut self, field: &'static str) -> Result<u64, InvocationError> {
        self.type_len(0, field)
    }

    fn i64(&mut self, field: &'static str) -> Result<i64, InvocationError> {
        let initial = self.take(field)?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        let value = self.len_value(additional, field)?;
        match major {
            0 => i64::try_from(value)
                .map_err(|_| InvocationError::InvalidBody("positive integer out of range")),
            1 => {
                let magnitude = i64::try_from(value)
                    .map_err(|_| InvocationError::InvalidBody("negative integer out of range"))?;
                Ok(-1 - magnitude)
            }
            _ => Err(InvocationError::InvalidBody("expected CBOR integer")),
        }
    }

    fn text(&mut self, field: &'static str) -> Result<String, InvocationError> {
        let len = self.type_len(3, field)?;
        let bytes = self.take_n(len, field)?;
        std::str::from_utf8(bytes)
            .map(str::to_string)
            .map_err(|_| InvocationError::InvalidBody("invalid UTF-8 text"))
    }

    fn optional_text(&mut self, field: &'static str) -> Result<Option<String>, InvocationError> {
        if self.peek() == Some(0xf6) {
            self.offset += 1;
            return Ok(None);
        }
        self.text(field).map(Some)
    }

    fn bytes(&mut self, field: &'static str) -> Result<Vec<u8>, InvocationError> {
        let len = self.type_len(2, field)?;
        Ok(self.take_n(len, field)?.to_vec())
    }

    fn optional_bytes(&mut self, field: &'static str) -> Result<Option<Vec<u8>>, InvocationError> {
        if self.peek() == Some(0xf6) {
            self.offset += 1;
            return Ok(None);
        }
        self.bytes(field).map(Some)
    }

    fn optional_u64(&mut self, field: &'static str) -> Result<Option<u64>, InvocationError> {
        if self.peek() == Some(0xf6) {
            self.offset += 1;
            return Ok(None);
        }
        self.u64(field).map(Some)
    }

    fn bool(&mut self, field: &'static str) -> Result<bool, InvocationError> {
        match self.take(field)? {
            0xf4 => Ok(false),
            0xf5 => Ok(true),
            _ => Err(InvocationError::InvalidBody("expected CBOR bool")),
        }
    }

    fn type_len(
        &mut self,
        expected_major: u8,
        field: &'static str,
    ) -> Result<u64, InvocationError> {
        let initial = self.take(field)?;
        let major = initial >> 5;
        if major != expected_major {
            return Err(InvocationError::InvalidBody("unexpected CBOR type"));
        }
        self.len_value(initial & 0x1f, field)
    }

    fn len_value(&mut self, additional: u8, field: &'static str) -> Result<u64, InvocationError> {
        match additional {
            value @ 0..=23 => Ok(u64::from(value)),
            24 => self.take(field).map(u64::from),
            25 => self
                .take_array::<2>(field)
                .map(u16::from_be_bytes)
                .map(u64::from),
            26 => self
                .take_array::<4>(field)
                .map(u32::from_be_bytes)
                .map(u64::from),
            27 => self.take_array::<8>(field).map(u64::from_be_bytes),
            _ => Err(InvocationError::InvalidBody(
                "unsupported CBOR additional info",
            )),
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.offset).copied()
    }

    fn take(&mut self, field: &'static str) -> Result<u8, InvocationError> {
        let byte = self
            .bytes
            .get(self.offset)
            .copied()
            .ok_or(InvocationError::InvalidBody(field))?;
        self.offset += 1;
        Ok(byte)
    }

    fn take_array<const N: usize>(
        &mut self,
        field: &'static str,
    ) -> Result<[u8; N], InvocationError> {
        self.take_n(u64::try_from(N).unwrap_or(u64::MAX), field)?
            .try_into()
            .map_err(|_| InvocationError::InvalidBody("short CBOR integer"))
    }

    fn take_n(&mut self, len: u64, field: &'static str) -> Result<&'a [u8], InvocationError> {
        let len = usize::try_from(len)
            .map_err(|_| InvocationError::InvalidBody("CBOR length out of range"))?;
        let end = self
            .offset
            .checked_add(len)
            .ok_or(InvocationError::InvalidBody("CBOR length overflow"))?;
        let out = self
            .bytes
            .get(self.offset..end)
            .ok_or(InvocationError::InvalidBody(field))?;
        self.offset = end;
        Ok(out)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(hex_nibble(byte >> 4));
            out.push(hex_nibble(byte & 0x0f));
        }
        out
    }

    const fn hex_nibble(nibble: u8) -> char {
        match nibble {
            0 => '0',
            1 => '1',
            2 => '2',
            3 => '3',
            4 => '4',
            5 => '5',
            6 => '6',
            7 => '7',
            8 => '8',
            9 => '9',
            10 => 'a',
            11 => 'b',
            12 => 'c',
            13 => 'd',
            14 => 'e',
            15 => 'f',
            _ => '?',
        }
    }

    #[test]
    fn content_type_registry_values_are_media_type_shaped() {
        for value in INVOCATION_CONTENT_TYPES {
            let (kind, subtype) = value.split_once('/').unwrap();
            assert_eq!(kind, "application", "{value}");
            assert!(subtype.starts_with("basil."), "{value}");
            assert!(!subtype.contains('/'), "{value}");
            assert_eq!(value.trim(), value, "{value}");
        }
    }

    #[test]
    fn request_bodies_have_deterministic_cbor() {
        let request = SignInvocationRequest {
            key_id: "publisher.signing.2026q3".to_string(),
            message: b"payload".to_vec(),
            algorithm: 1,
        };
        assert_eq!(
            SignInvocationRequest::from_cbor_bytes(&request.to_cbor_bytes()).unwrap(),
            request
        );
        assert_eq!(
            hex(&request.to_cbor_bytes()),
            "a30178187075626c69736865722e7369676e696e672e32303236713302477061796c6f61640301"
        );

        let response = SignInvocationResponse {
            status: InvocationStatus::ok(),
            policy_generation: 42,
            signature: Some(vec![0xAB; 64]),
        };
        assert_eq!(
            SignInvocationResponse::from_cbor_bytes(&response.to_cbor_bytes()).unwrap(),
            response
        );
        assert_eq!(
            hex(&response.to_cbor_bytes()),
            "a301a4010102624f4b03f604f402182a035840abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab"
        );

        let denied = SignInvocationResponse {
            status: InvocationStatus::denied(),
            policy_generation: 42,
            signature: None,
        };
        assert_eq!(
            SignInvocationResponse::from_cbor_bytes(&denied.to_cbor_bytes()).unwrap(),
            denied
        );
    }

    #[test]
    fn mint_nats_user_request_carries_issuer_account() {
        let with_issuer = MintNatsUserInvocationRequest {
            account_key_id: "nats.account.signing".to_string(),
            user_nkey: "UDXU4RCSJNZOIQHZNWXHXORDPRTGNJAHAHFRGZNEEJCPQTT2M7NLCNF4".to_string(),
            name: "svc-a".to_string(),
            ttl_secs: Some(300),
            issuer_account: Some(
                "ADXU4RCSJNZOIQHZNWXHXORDPRTGNJAHAHFRGZNEEJCPQTT2M7NLCNF4".to_string(),
            ),
        };
        let decoded =
            MintNatsUserInvocationRequest::from_cbor_bytes(&with_issuer.to_cbor_bytes()).unwrap();
        assert_eq!(decoded, with_issuer);
        assert_eq!(
            decoded.issuer_account.as_deref(),
            Some("ADXU4RCSJNZOIQHZNWXHXORDPRTGNJAHAHFRGZNEEJCPQTT2M7NLCNF4")
        );

        // The account-identity path omits the claim; it must round-trip as absent.
        let without_issuer = MintNatsUserInvocationRequest {
            issuer_account: None,
            ..with_issuer
        };
        let decoded =
            MintNatsUserInvocationRequest::from_cbor_bytes(&without_issuer.to_cbor_bytes())
                .unwrap();
        assert_eq!(decoded, without_issuer);
        assert_eq!(decoded.issuer_account, None);
    }
}
