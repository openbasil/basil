// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Ed25519 materialize-to-sign: the value-store signing crypto core.
//!
//! The self-contained primitive for the materialize-to-sign arm (vault-iiz,
//! design §17.7: the materialize-to-use local-custody arm; sibling of
//! [`crate::core::x25519_seal`]).
//!
//! `OpenBao`/Vault transit signs an Ed25519 key *in place*: the private never
//! leaves the backend. But a backend engine with no in-place sign primitive (a
//! plain value store, KV v2) can only hand back the raw private bytes. For that
//! one sanctioned case the design (secrets-vault §17.7) answer is to
//! **materialize** the 32-byte Ed25519 seed from KV in-process, perform the one
//! signature, then **zeroize** it. This module is the crypto core for that path:
//! it takes raw seed bytes and has **no** backend/Bao dependency, so the
//! construction is unit-testable fully offline.
//!
//! # Custody discipline
//!
//! - The materialized seed is held only in a [`Zeroizing`] fixed array, wiped on
//!   drop on the success **and** error paths.
//! - The ed25519-dalek `SigningKey` built from it zeroizes its own secret scalar
//!   on drop (the `zeroize` feature gives it `ZeroizeOnDrop`).
//! - No plaintext seed copy ever escapes into a non-zeroizing owner, an error
//!   string, a `Debug`/`Display`, a log, or the audit record. There is no type in
//!   this module that derives `Debug` over secret bytes.
//!
//! # Verification is a public op
//!
//! [`verify`] and [`public_from_seed`] need only the public half. As of
//! basil-o86 the broker reads the **out-of-band-provisioned** public (via
//! [`public_from_slice`]) for `verify`/`get_public_key`, so the seed is
//! materialized **only** on `sign`: the one op that performs the private crypto.
//! [`public_from_seed`] remains the canonical seed→public derivation used to
//! provision that out-of-band public and to anchor the KAT round-trip tests.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use zeroize::Zeroizing;

/// Length of an Ed25519 seed / private (bytes). The seed is the 32-byte input to
/// the key expansion; ed25519-dalek's `SigningKey` is built directly from it.
pub const SEED_LEN: usize = 32;
/// Length of an Ed25519 public / verifying key (bytes).
pub const PUBLIC_KEY_LEN: usize = 32;
/// Length of an Ed25519 signature (bytes).
pub const SIGNATURE_LEN: usize = 64;

/// Why a materialize-to-sign helper rejected its input.
///
/// Deliberately carries **no** secret material: the only failure modes are
/// fixed-length validation faults, each reporting the lengths involved (never any
/// byte of the seed, signature, or message).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SignError {
    /// The materialized seed slice was not exactly [`SEED_LEN`] bytes, a
    /// misprovisioned KV value. Fails closed before any key construction.
    #[error("invalid seed length: expected {expected} bytes, got {actual}")]
    BadSeedLength {
        /// The required length.
        expected: usize,
        /// The length actually supplied.
        actual: usize,
    },

    /// A public key or signature slice was the wrong length on the verify path:
    /// attacker-influenced bytes, validated before any crypto.
    #[error("invalid {what} length: expected {expected} bytes, got {actual}")]
    BadFieldLength {
        /// Which field (`"public key"` / `"signature"`).
        what: &'static str,
        /// The required length.
        expected: usize,
        /// The length actually supplied.
        actual: usize,
    },
}

/// Wrap a raw seed byte slice into the zeroizing fixed array the sign/derive path
/// expects, failing closed (never indexing/`unwrap`-ing) on a wrong length.
///
/// Used by the manager when it materializes the seed bytes out of KV.
///
/// # Errors
///
/// [`SignError::BadSeedLength`] if `bytes` is not exactly [`SEED_LEN`].
pub fn seed_from_slice(bytes: &[u8]) -> Result<Zeroizing<[u8; SEED_LEN]>, SignError> {
    let seed: [u8; SEED_LEN] = bytes.try_into().map_err(|_| SignError::BadSeedLength {
        expected: SEED_LEN,
        actual: bytes.len(),
    })?;
    Ok(Zeroizing::new(seed))
}

/// Build the ed25519-dalek `SigningKey` from a materialized seed. The returned
/// key zeroizes its secret scalar on drop (the `zeroize` feature). Kept private so
/// the secret-bearing key never crosses the module boundary.
fn signing_key(seed: &Zeroizing<[u8; SEED_LEN]>) -> SigningKey {
    SigningKey::from_bytes(seed)
}

/// Sign `message` with a materialized Ed25519 `seed`, returning the 64-byte
/// signature.
///
/// The `SigningKey` is built from the seed, used for exactly one signature, and
/// dropped (zeroized) before this returns. The signature bytes carry no secret
/// material. This is infallible for a valid 32-byte seed: ed25519 signing cannot
/// fail on in-range inputs, so there is no error path that could leak detail.
#[must_use]
pub fn sign(seed: &Zeroizing<[u8; SEED_LEN]>, message: &[u8]) -> [u8; SIGNATURE_LEN] {
    let key = signing_key(seed);
    key.sign(message).to_bytes()
}

/// Derive the Ed25519 **public** (verifying) key from a materialized seed.
///
/// The public half is derived from the seed and only the public bytes are
/// returned; the seed is never serialized. As of basil-o86 the broker no longer
/// calls this on the per-op `verify`/`get_public_key` paths (they read the
/// out-of-band public via [`public_from_slice`] without materializing the seed).
/// It is the canonical seed→public derivation used to **provision** that
/// out-of-band public and to anchor the RFC 8032 KAT round-trip tests.
#[must_use]
pub fn public_from_seed(seed: &Zeroizing<[u8; SEED_LEN]>) -> [u8; PUBLIC_KEY_LEN] {
    signing_key(seed).verifying_key().to_bytes()
}

/// Validate a raw 32-byte **public** (verifying) key slice into a fixed array,
/// failing closed (never indexing) on a wrong length.
///
/// Used by the manager when it reads the signing key's public, provisioned out
/// of band (basil-o86), from KV for `verify`/`get_public_key`, so the seed is
/// **never** materialized for those public ops. The public carries no secret, so
/// the array is a plain `[u8; 32]` (not `Zeroizing`).
///
/// # Errors
///
/// [`SignError::BadFieldLength`] if `bytes` is not exactly [`PUBLIC_KEY_LEN`].
pub fn public_from_slice(bytes: &[u8]) -> Result<[u8; PUBLIC_KEY_LEN], SignError> {
    bytes.try_into().map_err(|_| SignError::BadFieldLength {
        what: "public key",
        expected: PUBLIC_KEY_LEN,
        actual: bytes.len(),
    })
}

/// Verify `signature` over `message` against an Ed25519 `public` key.
///
/// A **public** operation: it never needs the seed. Returns `Ok(true)` on a valid
/// signature, `Ok(false)` on an authentication failure (wrong key / tampered
/// signature or message), and an error only on a malformed (wrong-length or
/// non-canonical) public key, validated before any crypto, never indexing into
/// attacker bytes.
///
/// # Errors
///
/// [`SignError::BadFieldLength`] if `public` or `signature` is the wrong length.
pub fn verify(
    public: &[u8; PUBLIC_KEY_LEN],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, SignError> {
    // Reject a wrong-length signature before constructing anything. The dalek
    // `Signature` is a fixed [u8;64], so convert fail-closed (no index/unwrap).
    let sig_bytes: [u8; SIGNATURE_LEN] =
        signature
            .try_into()
            .map_err(|_| SignError::BadFieldLength {
                what: "signature",
                expected: SIGNATURE_LEN,
                actual: signature.len(),
            })?;
    // A non-canonical / invalid public key point is not an oracle: treat it as a
    // failed verification (`Ok(false)`), not a distinct error, so a caller cannot
    // distinguish "bad key encoding" from "bad signature".
    let Ok(verifying_key) = VerifyingKey::from_bytes(public) else {
        return Ok(false);
    };
    let sig = Signature::from_bytes(&sig_bytes);
    Ok(verifying_key.verify(message, &sig).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8032 §7.1 Test 1: the empty-message vector. The 32-byte secret seed,
    /// the derived public, and the expected signature are the published vectors,
    /// a known-answer test that pins our seed→key expansion + signing to the
    /// standard (not just to a self-consistent round-trip).
    const RFC8032_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    const RFC8032_PUBLIC: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];
    const RFC8032_SIG: [u8; 64] = [
        0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82,
        0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49,
        0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c,
        0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43,
        0x8e, 0x7a, 0x10, 0x0b,
    ];

    #[test]
    fn sign_matches_rfc8032_known_answer() {
        let seed = Zeroizing::new(RFC8032_SEED);
        assert_eq!(public_from_seed(&seed), RFC8032_PUBLIC);
        // Empty message vector.
        assert_eq!(sign(&seed, b""), RFC8032_SIG);
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let seed = Zeroizing::new([7u8; 32]);
        let public = public_from_seed(&seed);
        let message = b"materialize-to-sign payload";
        let sig = sign(&seed, message);
        assert_eq!(verify(&public, message, &sig), Ok(true));
    }

    #[test]
    fn sign_is_deterministic() {
        // Ed25519 is deterministic: the same seed + message yields the same sig.
        let seed = Zeroizing::new([3u8; 32]);
        assert_eq!(sign(&seed, b"m"), sign(&seed, b"m"));
    }

    #[test]
    fn public_from_seed_is_deterministic() {
        let seed = Zeroizing::new([5u8; 32]);
        assert_eq!(public_from_seed(&seed), public_from_seed(&seed));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let seed = Zeroizing::new([7u8; 32]);
        let other_public = public_from_seed(&Zeroizing::new([42u8; 32]));
        let sig = sign(&seed, b"payload");
        // A signature under one key never verifies under a different public key.
        assert_eq!(verify(&other_public, b"payload", &sig), Ok(false));
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let seed = Zeroizing::new([7u8; 32]);
        let public = public_from_seed(&seed);
        let mut sig = sign(&seed, b"payload");
        sig[0] ^= 0xFF;
        assert_eq!(verify(&public, b"payload", &sig), Ok(false));
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let seed = Zeroizing::new([7u8; 32]);
        let public = public_from_seed(&seed);
        let sig = sign(&seed, b"payload");
        assert_eq!(verify(&public, b"payload-tampered", &sig), Ok(false));
    }

    #[test]
    fn verify_rejects_wrong_length_signature() {
        let seed = Zeroizing::new([7u8; 32]);
        let public = public_from_seed(&seed);
        assert!(matches!(
            verify(&public, b"m", &[0u8; 63]),
            Err(SignError::BadFieldLength {
                what: "signature",
                ..
            })
        ));
        assert!(matches!(
            verify(&public, b"m", &[0u8; 65]),
            Err(SignError::BadFieldLength { .. })
        ));
    }

    #[test]
    fn verify_treats_bad_public_key_as_failed_not_an_oracle() {
        // An all-FF public key is not a canonical Ed25519 point. verify must report
        // a plain `Ok(false)` (no oracle distinguishing it from a bad signature).
        let seed = Zeroizing::new([7u8; 32]);
        let sig = sign(&seed, b"m");
        assert_eq!(verify(&[0xFFu8; 32], b"m", &sig), Ok(false));
    }

    #[test]
    fn seed_from_slice_rejects_wrong_length() {
        assert!(matches!(
            seed_from_slice(&[0u8; 31]),
            Err(SignError::BadSeedLength { .. })
        ));
        assert!(matches!(
            seed_from_slice(&[0u8; 33]),
            Err(SignError::BadSeedLength { .. })
        ));
        assert!(seed_from_slice(&[0u8; 32]).is_ok());
    }

    #[test]
    fn public_from_slice_validates_length_and_verifies() {
        // The out-of-band public read (basil-o86) validates the stored bytes into a
        // fixed array, failing closed on a wrong length and never indexing.
        assert!(matches!(
            public_from_slice(&[0u8; 31]),
            Err(SignError::BadFieldLength {
                what: "public key",
                ..
            })
        ));
        assert!(matches!(
            public_from_slice(&[0u8; 33]),
            Err(SignError::BadFieldLength { .. })
        ));
        // A valid 32-byte public verifies a signature exactly like the in-array
        // public derived from the seed.
        let seed = Zeroizing::new([7u8; 32]);
        let public = public_from_seed(&seed);
        let from_slice = public_from_slice(&public).expect("32-byte public");
        assert_eq!(from_slice, public);
        let sig = sign(&seed, b"from-out-of-band-public");
        assert_eq!(
            verify(&from_slice, b"from-out-of-band-public", &sig),
            Ok(true)
        );
    }

    #[test]
    fn seed_from_slice_round_trips_through_sign() {
        // The realistic materialize path: a KV byte slice -> fixed seed -> sign.
        let stored = vec![0x11u8; 32];
        let seed = seed_from_slice(&stored).expect("valid seed");
        let public = public_from_seed(&seed);
        let sig = sign(&seed, b"from-kv");
        assert_eq!(verify(&public, b"from-kv", &sig), Ok(true));
    }
}
