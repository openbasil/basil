// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Closed algorithm enums and their COSE codepoints.
//!
//! Decode of any codepoint outside these enums is a
//! [`DecodeError::UnknownAlgorithm`](crate::DecodeError::UnknownAlgorithm).
//! There are no forward-compatible `Unknown` arms.

/// Signature algorithms in the profile allow-set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureAlgorithm {
    /// `EdDSA` (COSE codepoint -8), Ed25519 keys.
    EdDsa,
    /// `ES256` (COSE codepoint -7): ECDSA with NIST P-256 and SHA-256.
    Es256,
}

impl SignatureAlgorithm {
    /// The COSE algorithm codepoint.
    #[must_use]
    pub const fn codepoint(self) -> i64 {
        match self {
            Self::EdDsa => -8,
            Self::Es256 => -7,
        }
    }

    /// Look a codepoint up in the allow-set.
    #[must_use]
    pub const fn from_codepoint(alg: i64) -> Option<Self> {
        match alg {
            -8 => Some(Self::EdDsa),
            -7 => Some(Self::Es256),
            _ => None,
        }
    }
}

/// Key-agreement algorithms in the profile allow-set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyAgreementAlgorithm {
    /// ECDH-ES + HKDF-256 (COSE codepoint -25), X25519 keys.
    EcdhEsHkdf256,
}

impl KeyAgreementAlgorithm {
    /// The COSE algorithm codepoint.
    #[must_use]
    pub const fn codepoint(self) -> i64 {
        match self {
            Self::EcdhEsHkdf256 => -25,
        }
    }

    /// Look a codepoint up in the allow-set.
    #[must_use]
    pub const fn from_codepoint(alg: i64) -> Option<Self> {
        match alg {
            -25 => Some(Self::EcdhEsHkdf256),
            _ => None,
        }
    }
}

/// Content-encryption algorithms in the profile allow-set.
///
/// A parameter of every encrypting entry point: basil invocation v1 passes
/// [`ContentAlgorithm::A256Gcm`]; clients may use
/// [`ContentAlgorithm::ChaCha20Poly1305`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContentAlgorithm {
    /// AES-256-GCM (COSE codepoint 3).
    A256Gcm,
    /// `ChaCha20`-`Poly1305` (COSE codepoint 24).
    ChaCha20Poly1305,
}

impl ContentAlgorithm {
    /// The COSE algorithm codepoint.
    #[must_use]
    pub const fn codepoint(self) -> i64 {
        match self {
            Self::A256Gcm => 3,
            Self::ChaCha20Poly1305 => 24,
        }
    }

    /// Look a codepoint up in the allow-set.
    #[must_use]
    pub const fn from_codepoint(alg: i64) -> Option<Self> {
        match alg {
            3 => Some(Self::A256Gcm),
            24 => Some(Self::ChaCha20Poly1305),
            _ => None,
        }
    }

    /// The content-encryption key length in bytes (256 bits for both).
    #[must_use]
    pub const fn key_len(self) -> usize {
        32
    }
}
