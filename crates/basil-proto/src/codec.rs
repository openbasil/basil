// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Strict protobuf codec for the purpose-specific Nix cache service.

use std::marker::PhantomData;

use prost::Message;
use tonic::Status;
use tonic::codec::{BufferSettings, Codec, DecodeBuf, Decoder, EncodeBuf, Encoder};

use crate::broker::v1::{
    DescribeNixCacheKeyRequest, DescribeNixCacheKeyResponse, EnrollNixCacheKeyRequest,
    EnrollNixCacheKeyResponse, SignNixCacheFingerprintRequest, SignNixCacheFingerprintResponse,
};

/// Maximum encoded size of a Nix key description request.
pub const DESCRIBE_NIX_CACHE_KEY_REQUEST_MAX: usize = 295;
/// Maximum encoded size of a Nix key description response.
pub const DESCRIBE_NIX_CACHE_KEY_RESPONSE_MAX: usize = 203;
/// Maximum encoded size of a Nix key enrollment request.
pub const ENROLL_NIX_CACHE_KEY_REQUEST_MAX: usize = 295;
/// Maximum encoded size of a Nix key enrollment response.
pub const ENROLL_NIX_CACHE_KEY_RESPONSE_MAX: usize = 205;
/// Maximum encoded size of a Nix fingerprint signing request.
pub const SIGN_NIX_CACHE_FINGERPRINT_REQUEST_MAX: usize = 524_939;
/// Maximum encoded size of a Nix fingerprint signing response.
pub const SIGN_NIX_CACHE_FINGERPRINT_RESPONSE_MAX: usize = 269;

const KEY_ID_MAX: usize = 256;
const KEY_NAME_MAX: usize = 128;
const FINGERPRINT_MAX: usize = 524_626;
const PROFILE: &[u8] = b"PATH_INFO_V1";

/// A protobuf codec that preflights Nix cache messages before `prost` decoding.
///
/// The generated Nix service selects this codec exclusively. Other Basil APIs
/// retain ordinary protobuf forward compatibility.
#[derive(Debug, Clone)]
pub struct StrictProstCodec<T, U> {
    marker: PhantomData<(T, U)>,
}

impl<T, U> Default for StrictProstCodec<T, U> {
    fn default() -> Self {
        Self {
            marker: PhantomData,
        }
    }
}

impl<T, U> Codec for StrictProstCodec<T, U>
where
    T: Message + Send + 'static,
    U: StrictMessage + Send + 'static,
{
    type Encode = T;
    type Decode = U;
    type Encoder = StrictProstEncoder<T>;
    type Decoder = StrictProstDecoder<U>;

    fn encoder(&mut self) -> Self::Encoder {
        StrictProstEncoder::default()
    }

    fn decoder(&mut self) -> Self::Decoder {
        StrictProstDecoder::default()
    }
}

/// Encoder half of [`StrictProstCodec`].
#[derive(Debug, Clone)]
pub struct StrictProstEncoder<T> {
    marker: PhantomData<T>,
}

impl<T> Default for StrictProstEncoder<T> {
    fn default() -> Self {
        Self {
            marker: PhantomData,
        }
    }
}

impl<T: Message> Encoder for StrictProstEncoder<T> {
    type Item = T;
    type Error = Status;

    fn encode(
        &mut self,
        item: Self::Item,
        destination: &mut EncodeBuf<'_>,
    ) -> Result<(), Self::Error> {
        item.encode(destination)
            .map_err(|error| Status::internal(error.to_string()))
    }

    fn buffer_settings(&self) -> BufferSettings {
        BufferSettings::default()
    }
}

/// Decoder half of [`StrictProstCodec`].
#[derive(Debug, Clone)]
pub struct StrictProstDecoder<U> {
    marker: PhantomData<U>,
}

impl<U> Default for StrictProstDecoder<U> {
    fn default() -> Self {
        Self {
            marker: PhantomData,
        }
    }
}

impl<U: StrictMessage> Decoder for StrictProstDecoder<U> {
    type Item = U;
    type Error = Status;

    fn decode(&mut self, source: &mut DecodeBuf<'_>) -> Result<Option<Self::Item>, Self::Error> {
        use prost::bytes::Buf as _;

        let raw = source.copy_to_bytes(source.remaining());
        preflight::<U>(&raw).map_err(U::status)?;
        U::decode(raw)
            .map(Some)
            .map_err(|error| U::status(format!("invalid protobuf: {error}")))
    }

    fn buffer_settings(&self) -> BufferSettings {
        BufferSettings::default()
    }
}

#[derive(Debug, Clone, Copy)]
#[doc(hidden)]
pub enum LengthKind {
    KeyId,
    KeyName,
    PublicKey,
    Identifier,
    Profile,
    Fingerprint,
    Signature,
}

#[derive(Debug, Clone, Copy)]
#[doc(hidden)]
pub enum FieldRule {
    LengthDelimited(LengthKind),
    ExactVarint(u64),
    EnrollmentDisposition,
}

/// Sealed message-schema contract used by [`StrictProstCodec`].
#[doc(hidden)]
pub trait StrictMessage: Message + Default + Sized {
    /// Largest permitted serialized message.
    const MAX_ENCODED_LEN: usize;
    /// Number of required fields.
    const FIELD_COUNT: usize;
    /// Whether malformed input came from a server response.
    const IS_RESPONSE: bool;

    /// Return the rule for one field number.
    fn field_rule(number: u32) -> Option<FieldRule>;

    #[must_use]
    fn status(message: String) -> Status {
        if Self::IS_RESPONSE {
            Status::data_loss(message)
        } else {
            Status::invalid_argument(message)
        }
    }
}

fn preflight<M: StrictMessage>(raw: &[u8]) -> Result<(), String> {
    if raw.len() > M::MAX_ENCODED_LEN {
        return Err(format!(
            "Nix cache protobuf is {} bytes; maximum is {}",
            raw.len(),
            M::MAX_ENCODED_LEN
        ));
    }

    let mut cursor = 0;
    let mut seen = 0_u64;
    while cursor < raw.len() {
        let key = read_varint(raw, &mut cursor)?;
        let number = u32::try_from(key >> 3).map_err(|_| "field number overflows u32")?;
        if number == 0 || number > 63 {
            return Err(format!("unknown field {number}"));
        }
        let bit = 1_u64 << (number - 1);
        if seen & bit != 0 {
            return Err(format!("duplicate field {number}"));
        }
        let rule = M::field_rule(number).ok_or_else(|| format!("unknown field {number}"))?;
        let wire_type = u8::try_from(key & 0x07).map_err(|_| "wire type overflows u8")?;
        match rule {
            FieldRule::LengthDelimited(kind) => {
                if wire_type != 2 {
                    return Err(format!(
                        "field {number} has wire type {wire_type}; expected 2"
                    ));
                }
                let length = usize::try_from(read_varint(raw, &mut cursor)?)
                    .map_err(|_| format!("field {number} length overflows usize"))?;
                let end = cursor
                    .checked_add(length)
                    .ok_or_else(|| format!("field {number} length overflows"))?;
                let value = raw
                    .get(cursor..end)
                    .ok_or_else(|| format!("field {number} is truncated"))?;
                validate_length_value(number, kind, value)?;
                cursor = end;
            }
            FieldRule::ExactVarint(expected) => {
                if wire_type != 0 {
                    return Err(format!(
                        "field {number} has wire type {wire_type}; expected 0"
                    ));
                }
                let value = read_varint(raw, &mut cursor)?;
                if value != expected {
                    return Err(format!("field {number} must equal {expected}"));
                }
            }
            FieldRule::EnrollmentDisposition => {
                if wire_type != 0 {
                    return Err(format!(
                        "field {number} has wire type {wire_type}; expected 0"
                    ));
                }
                let value = read_varint(raw, &mut cursor)?;
                if !matches!(value, 1 | 2) {
                    return Err(format!("field {number} has invalid enum value {value}"));
                }
            }
        }
        seen |= bit;
    }

    let required = if M::FIELD_COUNT == 64 {
        u64::MAX
    } else {
        (1_u64 << M::FIELD_COUNT) - 1
    };
    if seen != required {
        let missing = (1..=M::FIELD_COUNT)
            .filter(|number| seen & (1_u64 << (number - 1)) == 0)
            .map(|number| number.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!("missing required field(s): {missing}"));
    }
    Ok(())
}

fn read_varint(raw: &[u8], cursor: &mut usize) -> Result<u64, String> {
    let mut value = 0_u64;
    for shift in (0..70).step_by(7) {
        let byte = *raw
            .get(*cursor)
            .ok_or_else(|| "truncated protobuf varint".to_string())?;
        *cursor += 1;
        if shift == 63 && byte > 1 {
            return Err("protobuf varint overflows u64".to_string());
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err("protobuf varint is too long".to_string())
}

fn validate_length_value(number: u32, kind: LengthKind, value: &[u8]) -> Result<(), String> {
    match kind {
        LengthKind::KeyId => {
            require_length(number, value, 1, KEY_ID_MAX)?;
            let text = std::str::from_utf8(value)
                .map_err(|_| format!("field {number} is not valid UTF-8"))?;
            if text.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
                return Err(format!("field {number} contains a control byte"));
            }
        }
        LengthKind::KeyName => {
            require_length(number, value, 1, KEY_NAME_MAX)?;
            if !is_valid_key_name(value) {
                return Err(format!("field {number} is not a valid Nix key name"));
            }
        }
        LengthKind::PublicKey => require_length(number, value, 32, 32)?,
        LengthKind::Identifier => {
            require_length(number, value, 16, 16)?;
            if value.iter().all(|byte| *byte == 0) {
                return Err(format!("field {number} must not be all zero"));
            }
        }
        LengthKind::Profile => {
            if value != PROFILE {
                return Err(format!("field {number} must equal `PATH_INFO_V1`"));
            }
        }
        LengthKind::Fingerprint => require_length(number, value, 1, FINGERPRINT_MAX)?,
        LengthKind::Signature => require_length(number, value, 64, 64)?,
    }
    Ok(())
}

fn require_length(number: u32, value: &[u8], minimum: usize, maximum: usize) -> Result<(), String> {
    if !(minimum..=maximum).contains(&value.len()) {
        return Err(format!(
            "field {number} is {} bytes; expected {minimum}..={maximum}",
            value.len()
        ));
    }
    Ok(())
}

fn is_valid_key_name(value: &[u8]) -> bool {
    value.first().is_some_and(u8::is_ascii_alphanumeric)
        && value
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

macro_rules! strict_message {
    ($type:ty, $max:expr, $fields:expr, $response:expr, {$($number:literal => $rule:expr),+ $(,)?}) => {
        impl StrictMessage for $type {
            const MAX_ENCODED_LEN: usize = $max;
            const FIELD_COUNT: usize = $fields;
            const IS_RESPONSE: bool = $response;

            fn field_rule(number: u32) -> Option<FieldRule> {
                match number {
                    $($number => Some($rule),)+
                    _ => None,
                }
            }
        }
    };
}

strict_message!(DescribeNixCacheKeyRequest, DESCRIBE_NIX_CACHE_KEY_REQUEST_MAX, 3, false, {
    1 => FieldRule::LengthDelimited(LengthKind::KeyId),
    2 => FieldRule::LengthDelimited(LengthKind::Identifier),
    3 => FieldRule::LengthDelimited(LengthKind::Identifier),
});
strict_message!(DescribeNixCacheKeyResponse, DESCRIBE_NIX_CACHE_KEY_RESPONSE_MAX, 5, true, {
    1 => FieldRule::LengthDelimited(LengthKind::KeyName),
    2 => FieldRule::LengthDelimited(LengthKind::PublicKey),
    3 => FieldRule::ExactVarint(1),
    4 => FieldRule::LengthDelimited(LengthKind::Identifier),
    5 => FieldRule::LengthDelimited(LengthKind::Identifier),
});
strict_message!(EnrollNixCacheKeyRequest, ENROLL_NIX_CACHE_KEY_REQUEST_MAX, 3, false, {
    1 => FieldRule::LengthDelimited(LengthKind::KeyId),
    2 => FieldRule::LengthDelimited(LengthKind::Identifier),
    3 => FieldRule::LengthDelimited(LengthKind::Identifier),
});
strict_message!(EnrollNixCacheKeyResponse, ENROLL_NIX_CACHE_KEY_RESPONSE_MAX, 6, true, {
    1 => FieldRule::LengthDelimited(LengthKind::KeyName),
    2 => FieldRule::LengthDelimited(LengthKind::PublicKey),
    3 => FieldRule::ExactVarint(1),
    4 => FieldRule::EnrollmentDisposition,
    5 => FieldRule::LengthDelimited(LengthKind::Identifier),
    6 => FieldRule::LengthDelimited(LengthKind::Identifier),
});
strict_message!(SignNixCacheFingerprintRequest, SIGN_NIX_CACHE_FINGERPRINT_REQUEST_MAX, 5, false, {
    1 => FieldRule::LengthDelimited(LengthKind::KeyId),
    2 => FieldRule::LengthDelimited(LengthKind::Profile),
    3 => FieldRule::LengthDelimited(LengthKind::Fingerprint),
    4 => FieldRule::LengthDelimited(LengthKind::Identifier),
    5 => FieldRule::LengthDelimited(LengthKind::Identifier),
});
strict_message!(SignNixCacheFingerprintResponse, SIGN_NIX_CACHE_FINGERPRINT_RESPONSE_MAX, 6, true, {
    1 => FieldRule::LengthDelimited(LengthKind::KeyName),
    2 => FieldRule::LengthDelimited(LengthKind::PublicKey),
    3 => FieldRule::ExactVarint(1),
    4 => FieldRule::LengthDelimited(LengthKind::Signature),
    5 => FieldRule::LengthDelimited(LengthKind::Identifier),
    6 => FieldRule::LengthDelimited(LengthKind::Identifier),
});

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::v1::NixCacheEnrollmentDisposition;

    const ID: [u8; 16] = [1; 16];

    fn describe_request() -> DescribeNixCacheKeyRequest {
        DescribeNixCacheKeyRequest {
            key_id: "k".repeat(KEY_ID_MAX),
            batch_id: ID.to_vec(),
            request_id: ID.to_vec(),
        }
    }

    #[test]
    fn derived_maxima_match_encoded_messages() {
        let describe_request = describe_request();
        assert_eq!(
            describe_request.encoded_len(),
            DESCRIBE_NIX_CACHE_KEY_REQUEST_MAX
        );
        assert_eq!(
            EnrollNixCacheKeyRequest {
                key_id: describe_request.key_id,
                batch_id: ID.to_vec(),
                request_id: ID.to_vec(),
            }
            .encoded_len(),
            ENROLL_NIX_CACHE_KEY_REQUEST_MAX
        );
        assert_eq!(
            DescribeNixCacheKeyResponse {
                key_name: "k".repeat(KEY_NAME_MAX),
                public_key: vec![1; 32],
                backend_version: 1,
                batch_id: ID.to_vec(),
                request_id: ID.to_vec(),
            }
            .encoded_len(),
            DESCRIBE_NIX_CACHE_KEY_RESPONSE_MAX
        );
        assert_eq!(
            EnrollNixCacheKeyResponse {
                key_name: "k".repeat(KEY_NAME_MAX),
                public_key: vec![1; 32],
                backend_version: 1,
                disposition: NixCacheEnrollmentDisposition::Created.into(),
                batch_id: ID.to_vec(),
                request_id: ID.to_vec(),
            }
            .encoded_len(),
            ENROLL_NIX_CACHE_KEY_RESPONSE_MAX
        );
        assert_eq!(
            SignNixCacheFingerprintRequest {
                key_id: "k".repeat(KEY_ID_MAX),
                profile: "PATH_INFO_V1".to_string(),
                fingerprint: vec![b'x'; FINGERPRINT_MAX],
                batch_id: ID.to_vec(),
                request_id: ID.to_vec(),
            }
            .encoded_len(),
            SIGN_NIX_CACHE_FINGERPRINT_REQUEST_MAX
        );
        assert_eq!(
            SignNixCacheFingerprintResponse {
                key_name: "k".repeat(KEY_NAME_MAX),
                public_key: vec![1; 32],
                backend_version: 1,
                signature: vec![1; 64],
                batch_id: ID.to_vec(),
                request_id: ID.to_vec(),
            }
            .encoded_len(),
            SIGN_NIX_CACHE_FINGERPRINT_RESPONSE_MAX
        );
    }

    #[test]
    fn request_preflight_rejects_unknown_duplicate_missing_and_wrong_wire_fields() {
        let valid = DescribeNixCacheKeyRequest {
            key_id: "k".to_string(),
            batch_id: ID.to_vec(),
            request_id: ID.to_vec(),
        }
        .encode_to_vec();
        assert!(preflight::<DescribeNixCacheKeyRequest>(&valid).is_ok());

        let mut unknown = valid.clone();
        unknown.extend_from_slice(&[0x20, 0x01]);
        assert!(
            preflight::<DescribeNixCacheKeyRequest>(&unknown)
                .unwrap_err()
                .contains("unknown field 4")
        );

        let mut duplicate = valid.clone();
        duplicate.extend_from_slice(&[0x12, 0x10]);
        duplicate.extend_from_slice(&ID);
        assert!(
            preflight::<DescribeNixCacheKeyRequest>(&duplicate)
                .unwrap_err()
                .contains("duplicate field 2")
        );

        let missing = DescribeNixCacheKeyRequest {
            request_id: Vec::new(),
            ..describe_request()
        }
        .encode_to_vec();
        assert!(
            preflight::<DescribeNixCacheKeyRequest>(&missing)
                .unwrap_err()
                .contains("missing required field(s): 3")
        );

        let mut wrong_wire = valid;
        assert_eq!(wrong_wire.first(), Some(&0x0a));
        if let Some(first) = wrong_wire.first_mut() {
            *first = 0x08;
        }
        assert!(
            preflight::<DescribeNixCacheKeyRequest>(&wrong_wire)
                .unwrap_err()
                .contains("expected 2")
        );
    }

    #[test]
    fn response_preflight_rejects_invalid_enum_and_identifier() {
        let response = EnrollNixCacheKeyResponse {
            key_name: "cache.example-1".to_string(),
            public_key: vec![1; 32],
            backend_version: 1,
            disposition: 3,
            batch_id: ID.to_vec(),
            request_id: ID.to_vec(),
        };
        assert!(
            preflight::<EnrollNixCacheKeyResponse>(&response.encode_to_vec())
                .unwrap_err()
                .contains("invalid enum value 3")
        );

        let response = DescribeNixCacheKeyResponse {
            key_name: "cache.example-1".to_string(),
            public_key: vec![1; 32],
            backend_version: 1,
            batch_id: vec![0; 16],
            request_id: ID.to_vec(),
        };
        assert!(
            preflight::<DescribeNixCacheKeyResponse>(&response.encode_to_vec())
                .unwrap_err()
                .contains("must not be all zero")
        );
    }
}
