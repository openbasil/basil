// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Closed, diagnostic error enums.
//!
//! Every enum here is closed (no `Unknown`/catch-all arms for wire values) and
//! never echoes secret bytes: arms carry labels, lengths, and codepoints only.

use alloc::string::String;
use core::fmt;

/// An identifier newtype was constructed from out-of-range input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileError {
    /// A key id must be 1..=128 bytes.
    KeyIdLength {
        /// The length actually supplied.
        actual: usize,
    },
    /// A message id (CWT `cti`) must be 1..=64 bytes.
    MessageIdLength {
        /// The length actually supplied.
        actual: usize,
    },
    /// A subject / audience / response-subject string must be non-empty.
    EmptySubject,
    /// A content type must be of `type/subtype` form with no surrounding
    /// whitespace (RFC 9052 tstr content type carries a media type).
    ContentTypeForm,
    /// A KDF party identity must be non-empty when present.
    EmptyPartyIdentity,
    /// A signature must be non-empty.
    EmptySignature,
}

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyIdLength { actual } => {
                write!(f, "key id must be 1..=128 bytes, got {actual}")
            }
            Self::MessageIdLength { actual } => {
                write!(f, "message id must be 1..=64 bytes, got {actual}")
            }
            Self::EmptySubject => write!(f, "subject string must be non-empty"),
            Self::ContentTypeForm => write!(
                f,
                "content type must be of type/subtype form without surrounding whitespace"
            ),
            Self::EmptyPartyIdentity => write!(f, "party identity must be non-empty when present"),
            Self::EmptySignature => write!(f, "signature must be non-empty"),
        }
    }
}

impl core::error::Error for ProfileError {}

/// Strict-decode rejection reasons.
///
/// The strict decoder rejects anything outside the profile: wrong or missing
/// tags, indefinite lengths, non-deterministic encodings (RFC 8949 §4.2),
/// duplicate or unknown labels, claims in unprotected headers, unknown
/// codepoints, and malformed structure shapes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// The input is not well-formed CBOR (truncated, trailing garbage, or a
    /// structurally invalid item).
    Malformed,
    /// The top-level item is not tagged.
    NotTagged,
    /// The top-level tag is not the expected COSE tag.
    WrongTag {
        /// The tag the profile requires here (18 or 96).
        expected: u64,
        /// The tag actually present.
        actual: u64,
    },
    /// An indefinite-length item was encountered (forbidden by RFC 8949 §4.2).
    IndefiniteLength,
    /// An integer/length header was not minimally encoded (RFC 8949 §4.2).
    NonMinimalEncoding,
    /// Re-encoding the decoded message did not reproduce the input bytes:
    /// the encoding is not the profile's deterministic encoding.
    NonDeterministicEncoding,
    /// A map carried the same label twice.
    DuplicateLabel,
    /// A label appeared somewhere the profile does not allow it.
    UnknownLabel {
        /// The offending label.
        label: i64,
    },
    /// A text label was used; the profile is integer-labelled throughout.
    TextLabel,
    /// A known label carried the wrong CBOR type.
    WrongType {
        /// The label whose value had the wrong type.
        label: i64,
    },
    /// A required header parameter is absent.
    MissingHeader {
        /// The absent label.
        label: i64,
    },
    /// An algorithm codepoint outside the profile allow-set.
    UnknownAlgorithm {
        /// The offending codepoint.
        alg: i64,
    },
    /// The `crit` header is absent on a layer that requires it.
    CritMissing,
    /// A profile label is present but not listed in `crit`.
    CritIncomplete {
        /// The unlisted label.
        label: i64,
    },
    /// `crit` lists a label the profile does not place on this layer.
    CritUnexpected {
        /// The offending label.
        label: i64,
    },
    /// A claim was found in an unprotected header.
    ClaimsInUnprotected,
    /// An unknown key appeared inside the CWT claims map.
    UnknownClaim {
        /// The offending CWT claim key.
        claim: i64,
    },
    /// A CWT timestamp was fractional; the profile requires whole seconds.
    FractionalTime,
    /// A required CWT claim is absent (`iat` = 6, `cti` = 7).
    MissingClaim {
        /// The absent CWT claim key.
        claim: i64,
    },
    /// The recipients array length is not exactly one.
    RecipientCount {
        /// The number of recipients actually present.
        count: usize,
    },
    /// The recipient structure carries nested recipients.
    NestedRecipients,
    /// The recipient ciphertext is not `nil`; ECDH-ES direct key agreement
    /// carries no recipient ciphertext.
    RecipientCiphertextPresent,
    /// The signed payload is absent (`nil`); detached payloads are not part
    /// of this profile.
    MissingPayload,
    /// A sealed message's payload is not a tagged `COSE_Encrypt`.
    EmbeddedNotEncrypt,
    /// The ephemeral key is not an OKP/X25519 public key of the exact
    /// profile shape.
    EphemeralKeyShape,
    /// A fixed-length field (ephemeral key, nonce, request hash) had the
    /// wrong length.
    InvalidLength {
        /// The label or field the length belongs to.
        label: i64,
        /// The required length in bytes.
        expected: usize,
        /// The length actually supplied.
        actual: usize,
    },
    /// An identifier failed its newtype validation while decoding.
    Identifier(ProfileError),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => write!(f, "malformed CBOR input"),
            Self::NotTagged => write!(f, "top-level item is not tagged"),
            Self::WrongTag { expected, actual } => {
                write!(f, "wrong COSE tag: expected {expected}, got {actual}")
            }
            Self::IndefiniteLength => write!(f, "indefinite-length item"),
            Self::NonMinimalEncoding => write!(f, "non-minimal integer encoding"),
            Self::NonDeterministicEncoding => write!(f, "non-deterministic encoding"),
            Self::DuplicateLabel => write!(f, "duplicate map label"),
            Self::UnknownLabel { label } => write!(f, "unknown label {label}"),
            Self::TextLabel => write!(f, "text label outside the integer-labelled profile"),
            Self::WrongType { label } => write!(f, "wrong CBOR type for label {label}"),
            Self::MissingHeader { label } => write!(f, "missing required header {label}"),
            Self::UnknownAlgorithm { alg } => write!(f, "algorithm {alg} outside the profile"),
            Self::CritMissing => write!(f, "missing crit header"),
            Self::CritIncomplete { label } => write!(f, "label {label} not listed in crit"),
            Self::CritUnexpected { label } => write!(f, "unexpected crit entry {label}"),
            Self::ClaimsInUnprotected => write!(f, "claims in unprotected header"),
            Self::UnknownClaim { claim } => write!(f, "unknown CWT claim {claim}"),
            Self::FractionalTime => write!(f, "fractional CWT timestamp"),
            Self::MissingClaim { claim } => write!(f, "missing required CWT claim {claim}"),
            Self::RecipientCount { count } => {
                write!(f, "expected exactly one recipient, got {count}")
            }
            Self::NestedRecipients => write!(f, "nested recipients are not in the profile"),
            Self::RecipientCiphertextPresent => {
                write!(
                    f,
                    "recipient ciphertext must be nil for direct key agreement"
                )
            }
            Self::MissingPayload => write!(f, "payload is absent"),
            Self::EmbeddedNotEncrypt => {
                write!(f, "sealed payload is not a tagged COSE_Encrypt")
            }
            Self::EphemeralKeyShape => {
                write!(f, "ephemeral key is not the profile OKP/X25519 shape")
            }
            Self::InvalidLength {
                label,
                expected,
                actual,
            } => write!(f, "field {label} must be {expected} bytes, got {actual}"),
            Self::Identifier(e) => write!(f, "invalid identifier: {e}"),
        }
    }
}

impl core::error::Error for DecodeError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Identifier(e) => Some(e),
            _ => None,
        }
    }
}

impl From<ProfileError> for DecodeError {
    fn from(e: ProfileError) -> Self {
        Self::Identifier(e)
    }
}

/// Claim-set validation failures (temporal, audience, and role shape).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimsError {
    /// `iat` is further in the future than the allowed clock skew.
    IssuedInFuture,
    /// The message is past its effective expiry (with skew allowance).
    Expired,
    /// The explicit `exp` span exceeds the configured maximum TTL.
    TtlTooLong {
        /// The explicit span in seconds.
        seconds: i64,
    },
    /// The explicit `exp` is not after `iat`.
    NonPositiveTtl,
    /// A present `aud` is not in the allowed audience set.
    AudienceRejected,
    /// A claim the role requires is absent (basil private label).
    MissingClaim {
        /// The absent label.
        label: i64,
    },
    /// A claim the role forbids is present (basil private label).
    ForbiddenClaim {
        /// The offending label.
        label: i64,
    },
}

impl fmt::Display for ClaimsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IssuedInFuture => write!(f, "issued-at is in the future beyond allowed skew"),
            Self::Expired => write!(f, "message expired"),
            Self::TtlTooLong { seconds } => {
                write!(f, "explicit ttl of {seconds}s exceeds the maximum")
            }
            Self::NonPositiveTtl => write!(f, "expiry is not after issued-at"),
            Self::AudienceRejected => write!(f, "audience not allowed"),
            Self::MissingClaim { label } => write!(f, "role requires claim {label}"),
            Self::ForbiddenClaim { label } => write!(f, "role forbids claim {label}"),
        }
    }
}

impl core::error::Error for ClaimsError {}

/// Why producing a signature failed.
///
/// The shipped local signer is infallible; this exists for remote
/// (broker-backed) implementations whose signing operation can fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignError {
    /// The signer does not support the requested algorithm.
    AlgorithmUnsupported,
    /// The backing provider (for example an RPC-backed signer) failed. The
    /// message is diagnostic transport/provider detail, never key material.
    Provider {
        /// Human-readable provider failure detail.
        message: String,
    },
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlgorithmUnsupported => write!(f, "signer does not support the algorithm"),
            Self::Provider { message } => write!(f, "signing provider failed: {message}"),
        }
    }
}

impl core::error::Error for SignError {}

/// Why building a message failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildError {
    /// The claims' `sender_key_id` does not equal the signer's key id.
    SenderKeyMismatch,
    /// The claims do not satisfy the declared message role shape.
    RoleShape(ClaimsError),
    /// A `response_key_id` must be UTF-8: the `-70004` header is a tstr.
    ResponseKeyNotText,
    /// Randomness was unavailable (nonce / ephemeral generation).
    Rng,
    /// The AEAD seal operation failed (crypto-internal; should not occur for
    /// in-range inputs) or the key agreement was non-contributory.
    SealFailed,
    /// The signer failed.
    Sign(SignError),
    /// Internal structure encoding failed (crypto-internal; should not occur
    /// for profile-valid inputs).
    Codec,
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SenderKeyMismatch => {
                write!(f, "claims sender key id does not match the signer key id")
            }
            Self::RoleShape(e) => write!(f, "claims do not fit the message role: {e}"),
            Self::ResponseKeyNotText => write!(f, "response key id must be UTF-8"),
            Self::Rng => write!(f, "randomness unavailable"),
            Self::SealFailed => write!(f, "seal failed"),
            Self::Sign(e) => write!(f, "signing failed: {e}"),
            Self::Codec => write!(f, "structure encoding failed"),
        }
    }
}

impl core::error::Error for BuildError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::RoleShape(e) => Some(e),
            Self::Sign(e) => Some(e),
            _ => None,
        }
    }
}

impl From<SignError> for BuildError {
    fn from(e: SignError) -> Self {
        Self::Sign(e)
    }
}

/// Why verification failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// Strict decode rejected the message.
    Decode(DecodeError),
    /// The signature did not verify.
    SignatureInvalid,
    /// The verifier does not know the signing key id.
    UnknownKeyId,
    /// The wire algorithm disagrees with the verifier's pinned expectation.
    AlgorithmMismatch,
    /// The `-70003` sender key id does not equal the outer `kid`.
    SenderKeyMismatch,
    /// Claim validation failed.
    Claims(ClaimsError),
    /// Claims were present but no validation parameters were supplied, or
    /// validation parameters were supplied and no claims were present.
    ClaimsPresenceMismatch,
    /// The backing provider (for example an RPC-backed verifier) failed. The
    /// message is diagnostic transport/provider detail, never key material.
    Provider {
        /// Human-readable provider failure detail.
        message: String,
    },
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "strict decode failed: {e}"),
            Self::SignatureInvalid => write!(f, "signature verification failed"),
            Self::UnknownKeyId => write!(f, "unknown signing key id"),
            Self::AlgorithmMismatch => write!(f, "algorithm does not match the pinned key"),
            Self::SenderKeyMismatch => {
                write!(f, "sender key id claim does not match the outer kid")
            }
            Self::Claims(e) => write!(f, "claim validation failed: {e}"),
            Self::ClaimsPresenceMismatch => write!(
                f,
                "claims presence does not match the validation expectation"
            ),
            Self::Provider { message } => write!(f, "verification provider failed: {message}"),
        }
    }
}

impl core::error::Error for VerifyError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Decode(e) => Some(e),
            Self::Claims(e) => Some(e),
            _ => None,
        }
    }
}

impl From<DecodeError> for VerifyError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}

impl From<ClaimsError> for VerifyError {
    fn from(e: ClaimsError) -> Self {
        Self::Claims(e)
    }
}

/// Why opening (decrypting) a message failed.
///
/// Authentication failures are deliberately opaque: a wrong key, tampered
/// ciphertext, mismatched external AAD, and a low-order ephemeral all surface
/// as the single [`OpenError::OpenFailed`] arm (no oracle).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenError {
    /// Strict decode rejected the message.
    Decode(DecodeError),
    /// The message is addressed to a different recipient key id.
    RecipientKeyMismatch,
    /// The KDF party identities on the wire do not match the pinned
    /// expectation.
    PartyMismatch,
    /// AEAD authentication failed: wrong key, tampered ciphertext or headers,
    /// mismatched external AAD, or a degenerate (low-order) ephemeral.
    /// Opaque on purpose.
    OpenFailed,
    /// The backing provider (for example the broker unseal RPC) failed. The
    /// message is diagnostic transport/provider detail, never key material.
    Provider {
        /// Human-readable provider failure detail.
        message: String,
    },
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "strict decode failed: {e}"),
            Self::RecipientKeyMismatch => write!(f, "message is for a different recipient key"),
            Self::PartyMismatch => write!(f, "KDF party identities do not match expectation"),
            Self::OpenFailed => write!(f, "open failed"),
            Self::Provider { message } => write!(f, "open provider failed: {message}"),
        }
    }
}

impl core::error::Error for OpenError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Decode(e) => Some(e),
            _ => None,
        }
    }
}

impl From<DecodeError> for OpenError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}
