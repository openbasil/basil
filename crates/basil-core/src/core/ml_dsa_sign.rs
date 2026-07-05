// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! ML-DSA (FIPS 204) software signing core for the local-software PQC provider.
//!
//! Pure, backend-free ML-DSA: deterministic key generation from a 32-byte seed
//! (`ML-DSA.KeyGen_internal`, FIPS 204 Algorithm 6), signing, and verification,
//! for the three NIST parameter sets ML-DSA-44/65/87. Higher layers materialize
//! the software-custodied seed and call in here; the seed is copied into an
//! [`ml_dsa::SigningKey`] that wipes its key schedule on drop (`ZeroizeOnDrop`),
//! and the transient seed array is zeroized as soon as the key is derived.
//!
//! Names are the NIST standard ML-DSA names, never the pre-standard Dilithium
//! names, in every public surface.

use ml_dsa::signature::{Keypair, Signer, Verifier};
use ml_dsa::{
    B32, EncodedVerifyingKey, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, Signature, SigningKey,
    VerifyingKey,
};
use zeroize::Zeroize;

/// Length of the stored ML-DSA seed (private key), constant across all levels.
pub const SEED_LEN: usize = 32;

/// Supported ML-DSA parameter sets, named per FIPS 204 (not Dilithium).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlDsaAlgorithm {
    /// ML-DSA-44 (NIST security category 2).
    MlDsa44,
    /// ML-DSA-65 (NIST security category 3).
    MlDsa65,
    /// ML-DSA-87 (NIST security category 5).
    MlDsa87,
}

impl MlDsaAlgorithm {
    /// The kebab-case token used in catalog labels and diagnostics.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::MlDsa44 => "ml-dsa-44",
            Self::MlDsa65 => "ml-dsa-65",
            Self::MlDsa87 => "ml-dsa-87",
        }
    }
}

/// Why an ML-DSA operation failed. Every arm is opaque: it never echoes seed,
/// key, message, or signature bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MlDsaError {
    /// The seed was not exactly [`SEED_LEN`] bytes.
    #[error("invalid ML-DSA seed length: expected {expected} bytes, got {actual}")]
    BadSeedLength {
        /// Required length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },

    /// The public (verifying) key was not the parameter set's encoded length.
    #[error("invalid ML-DSA public key length")]
    BadPublicKeyLength,

    /// The signature was not the parameter set's encoded length, or failed to
    /// decode into a structurally valid signature.
    #[error("invalid ML-DSA signature encoding")]
    BadSignatureEncoding,

    /// Signing failed inside the ML-DSA implementation.
    #[error("ML-DSA signing failed")]
    SignFailed,
}

/// Derive the ML-DSA verifying (public) key bytes from a software-custodied seed.
///
/// The returned bytes are the FIPS 204 fixed-size verifying-key encoding for the
/// parameter set and are safe to publish.
///
/// # Errors
///
/// [`MlDsaError::BadSeedLength`] if `seed` is not [`SEED_LEN`] bytes.
pub fn public_from_seed(algorithm: MlDsaAlgorithm, seed: &[u8]) -> Result<Vec<u8>, MlDsaError> {
    match algorithm {
        MlDsaAlgorithm::MlDsa44 => public_for::<MlDsa44>(seed),
        MlDsaAlgorithm::MlDsa65 => public_for::<MlDsa65>(seed),
        MlDsaAlgorithm::MlDsa87 => public_for::<MlDsa87>(seed),
    }
}

/// Sign `message` with the ML-DSA key derived from a software-custodied seed.
///
/// The whole `message` is signed as-is (ML-DSA hashes internally); callers must
/// not pre-hash. The signature uses the deterministic ML-DSA variant, so the
/// same seed and message always yield the same signature bytes.
///
/// # Errors
///
/// [`MlDsaError::BadSeedLength`] for a malformed seed, or
/// [`MlDsaError::SignFailed`] if the implementation rejects the operation.
pub fn sign(algorithm: MlDsaAlgorithm, seed: &[u8], message: &[u8]) -> Result<Vec<u8>, MlDsaError> {
    match algorithm {
        MlDsaAlgorithm::MlDsa44 => sign_for::<MlDsa44>(seed, message),
        MlDsaAlgorithm::MlDsa65 => sign_for::<MlDsa65>(seed, message),
        MlDsaAlgorithm::MlDsa87 => sign_for::<MlDsa87>(seed, message),
    }
}

/// Verify an ML-DSA `signature` over `message` against a published public key.
///
/// Returns `Ok(true)` for a valid signature and `Ok(false)` for a
/// well-formed-but-wrong signature. Structurally malformed inputs fail closed
/// with an error rather than a silent `false`.
///
/// # Errors
///
/// [`MlDsaError::BadPublicKeyLength`] if `public_key` is the wrong length, or
/// [`MlDsaError::BadSignatureEncoding`] if `signature` does not decode.
pub fn verify(
    algorithm: MlDsaAlgorithm,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, MlDsaError> {
    match algorithm {
        MlDsaAlgorithm::MlDsa44 => verify_for::<MlDsa44>(public_key, message, signature),
        MlDsaAlgorithm::MlDsa65 => verify_for::<MlDsa65>(public_key, message, signature),
        MlDsaAlgorithm::MlDsa87 => verify_for::<MlDsa87>(public_key, message, signature),
    }
}

fn public_for<P: MlDsaParams>(seed: &[u8]) -> Result<Vec<u8>, MlDsaError> {
    let key = signing_key_from_seed::<P>(seed)?;
    Ok(encoded_bytes(&key.verifying_key().encode()))
}

fn sign_for<P: MlDsaParams>(seed: &[u8], message: &[u8]) -> Result<Vec<u8>, MlDsaError> {
    let key = signing_key_from_seed::<P>(seed)?;
    let signature = key.try_sign(message).map_err(|_| MlDsaError::SignFailed)?;
    Ok(encoded_bytes(&signature.encode()))
}

fn verify_for<P: MlDsaParams>(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, MlDsaError> {
    let encoded_vk = EncodedVerifyingKey::<P>::try_from(public_key)
        .map_err(|_| MlDsaError::BadPublicKeyLength)?;
    let verifying_key = VerifyingKey::<P>::decode(&encoded_vk);
    let Ok(signature) = Signature::<P>::try_from(signature) else {
        return Err(MlDsaError::BadSignatureEncoding);
    };
    Ok(verifying_key.verify(message, &signature).is_ok())
}

/// Derive a `SigningKey` from a 32-byte seed, wiping the transient seed array as
/// soon as the key schedule is built. The returned key zeroizes on drop.
fn signing_key_from_seed<P: MlDsaParams>(seed: &[u8]) -> Result<SigningKey<P>, MlDsaError> {
    let mut seed_array = B32::try_from(seed).map_err(|_| MlDsaError::BadSeedLength {
        expected: SEED_LEN,
        actual: seed.len(),
    })?;
    let key = SigningKey::<P>::from_seed(&seed_array);
    seed_array.zeroize();
    Ok(key)
}

/// Copy a fixed-size encoded crypto value (`Array<u8, _>`) into an owned `Vec`.
/// The `impl AsRef<[u8]>` bound disambiguates the encoded type's `AsRef` impls.
fn encoded_bytes(value: &impl AsRef<[u8]>) -> Vec<u8> {
    value.as_ref().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; SEED_LEN] = [0x24; SEED_LEN];
    const ALL: [MlDsaAlgorithm; 3] = [
        MlDsaAlgorithm::MlDsa44,
        MlDsaAlgorithm::MlDsa65,
        MlDsaAlgorithm::MlDsa87,
    ];

    #[test]
    fn all_levels_sign_verify_round_trip() {
        for algorithm in ALL {
            let public = public_from_seed(algorithm, &SEED).expect("public");
            let signature = sign(algorithm, &SEED, b"basil-pqc-message").expect("sign");
            assert!(
                verify(algorithm, &public, b"basil-pqc-message", &signature).expect("verify"),
                "{} round trip",
                algorithm.token()
            );
        }
    }

    #[test]
    fn signing_is_deterministic_per_seed_and_message() {
        for algorithm in ALL {
            let first = sign(algorithm, &SEED, b"determinism").expect("sign");
            let second = sign(algorithm, &SEED, b"determinism").expect("sign");
            assert_eq!(first, second, "{} deterministic", algorithm.token());
        }
    }

    #[test]
    fn public_key_is_stable_per_seed() {
        for algorithm in ALL {
            let first = public_from_seed(algorithm, &SEED).expect("public");
            let second = public_from_seed(algorithm, &SEED).expect("public");
            assert_eq!(first, second, "{} stable public", algorithm.token());
        }
    }

    #[test]
    fn wrong_message_fails_verification() {
        for algorithm in ALL {
            let public = public_from_seed(algorithm, &SEED).expect("public");
            let signature = sign(algorithm, &SEED, b"right").expect("sign");
            assert!(
                !verify(algorithm, &public, b"wrong", &signature).expect("verify"),
                "{} wrong message",
                algorithm.token()
            );
        }
    }

    #[test]
    fn wrong_key_fails_verification() {
        for algorithm in ALL {
            let public = public_from_seed(algorithm, &[0x55; SEED_LEN]).expect("public");
            let signature = sign(algorithm, &SEED, b"payload").expect("sign");
            assert!(
                !verify(algorithm, &public, b"payload", &signature).expect("verify"),
                "{} wrong key",
                algorithm.token()
            );
        }
    }

    #[test]
    fn bad_seed_length_fails_closed() {
        assert!(matches!(
            sign(MlDsaAlgorithm::MlDsa65, &[0u8; SEED_LEN - 1], b"m"),
            Err(MlDsaError::BadSeedLength { .. })
        ));
        assert!(matches!(
            public_from_seed(MlDsaAlgorithm::MlDsa44, &[0u8; SEED_LEN + 1]),
            Err(MlDsaError::BadSeedLength { .. })
        ));
    }

    #[test]
    fn malformed_public_key_and_signature_fail_closed() {
        let public = public_from_seed(MlDsaAlgorithm::MlDsa87, &SEED).expect("public");
        let signature = sign(MlDsaAlgorithm::MlDsa87, &SEED, b"m").expect("sign");
        assert_eq!(
            verify(MlDsaAlgorithm::MlDsa87, b"short", b"m", &signature),
            Err(MlDsaError::BadPublicKeyLength)
        );
        assert_eq!(
            verify(MlDsaAlgorithm::MlDsa87, &public, b"m", b"short"),
            Err(MlDsaError::BadSignatureEncoding)
        );
    }

    /// Deterministic known-answer vectors for ML-DSA-44/65/87.
    ///
    /// FIPS 204 `KeyGen_internal` and the default (deterministic) signer make the
    /// public key and signature byte-stable for a fixed seed and message, so we
    /// pin the encoded lengths plus a SHA-256 digest of the public key and the
    /// signature. A bump in the `ml-dsa` crate that changes the encoding, or a
    /// miswired parameter set, breaks these. No NIST ACVP KAT files are bundled;
    /// these golden values were produced by this implementation and must only be
    /// regenerated deliberately when the upstream encoding intentionally changes.
    #[test]
    fn known_answer_vectors_are_stable() {
        use sha2::{Digest, Sha256};

        struct Vector {
            algorithm: MlDsaAlgorithm,
            public_len: usize,
            public_sha256: &'static str,
            signature_len: usize,
            signature_sha256: &'static str,
        }

        const MESSAGE: &[u8] = b"basil-pqc-kat";
        let vectors = [
            Vector {
                algorithm: MlDsaAlgorithm::MlDsa44,
                public_len: 1312,
                public_sha256: "8f281f3e8a0e9cc4e3c2534be15485f1f4f343966218ec232ff8e0a69999734c",
                signature_len: 2420,
                signature_sha256: "bbae011ee58b80500a3daf6181654c27b3be9721192d9f2b68126160e2e4a880",
            },
            Vector {
                algorithm: MlDsaAlgorithm::MlDsa65,
                public_len: 1952,
                public_sha256: "a840920f30f6acb0cbf68e91fc532da5bbc805521a7704cbef71201a5aba7ff8",
                signature_len: 3309,
                signature_sha256: "ef2830800d7ff9bfa64b9a1c8cd6b6b377de91f652c857614109f8dd9d25526f",
            },
            Vector {
                algorithm: MlDsaAlgorithm::MlDsa87,
                public_len: 2592,
                public_sha256: "ae56b8d0ffd4bf6d09a2fdd32af657aba242265d96aeee358d5d3100587fcdc5",
                signature_len: 4627,
                signature_sha256: "c43ffc5347284883a1556575ba0ac1b608b4f0a0172d34deb5b76250cbf1ddcc",
            },
        ];

        let hex = |bytes: &[u8]| {
            use core::fmt::Write as _;
            bytes.iter().fold(String::new(), |mut acc, byte| {
                let _ = write!(acc, "{byte:02x}");
                acc
            })
        };
        for vector in vectors {
            let token = vector.algorithm.token();
            let public = public_from_seed(vector.algorithm, &SEED).expect("public");
            let signature = sign(vector.algorithm, &SEED, MESSAGE).expect("sign");
            assert_eq!(public.len(), vector.public_len, "{token} public length");
            assert_eq!(
                signature.len(),
                vector.signature_len,
                "{token} signature length"
            );
            assert_eq!(
                hex(&Sha256::digest(&public)),
                vector.public_sha256,
                "{token} public digest"
            );
            assert_eq!(
                hex(&Sha256::digest(&signature)),
                vector.signature_sha256,
                "{token} signature digest"
            );
            // The pinned material must verify, and tampering must be rejected.
            assert!(
                verify(vector.algorithm, &public, MESSAGE, &signature).expect("verify"),
                "{token} known-answer verifies"
            );
            assert!(
                !verify(vector.algorithm, &public, b"tampered", &signature).expect("verify"),
                "{token} tampered message rejected"
            );
        }
    }

    #[test]
    fn level_signatures_are_not_cross_verifiable() {
        let public = public_from_seed(MlDsaAlgorithm::MlDsa44, &SEED).expect("public");
        let signature = sign(MlDsaAlgorithm::MlDsa44, &SEED, b"m").expect("sign");
        // A 44 signature is the wrong length for an 87 verifying key/signature.
        assert!(matches!(
            verify(MlDsaAlgorithm::MlDsa87, &public, b"m", &signature),
            Err(MlDsaError::BadPublicKeyLength | MlDsaError::BadSignatureEncoding)
        ));
    }
}
