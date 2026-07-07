// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Optional materialize-to-use key-store support for [Basil](https://github.com/openbasil/basil).
//!
//! To use within basil, the basil-bin crate needs to be compiled
//! with either `db-keystore` or `onepassword` features.
//! see [Backends & custody](https://docs.openbasil.org/introduction/backends-and-custody/)
//!
//! This crate holds the storage adapters and local crypto needed when Basil is
//! backed by a key/value store rather than an in-place transit engine. Secret
//! bytes are returned in [`Zeroizing`] owners and local crypto materializes a key
//! for exactly one operation.

#![forbid(unsafe_code)]

use aes_gcm::aead::{Aead as _, KeyInit as _, Payload};
use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use basil::proto::{AeadAlgorithm, CiphertextEnvelope};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use rand::RngCore as _;
use zeroize::Zeroizing;

#[cfg(feature = "onepassword")]
mod onepassword;
pub mod store;

pub use store::{SecretStore, StoreConfig, StoreError};

const KEY_LEN: usize = 32;
const ED25519_SIG_LEN: usize = 64;
const NONCE_LEN: usize = 12;
const KEYSTORE_VERSION: u32 = 1;

/// Local materialize-to-use crypto failure.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// The stored key material had the wrong fixed length.
    #[error("invalid key length: expected {expected} bytes, got {actual}")]
    BadKeyLength {
        /// Required length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },
    /// The signature had the wrong fixed length.
    #[error("invalid signature length: expected {expected} bytes, got {actual}")]
    BadSignatureLength {
        /// Required length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },
    /// The AEAD envelope nonce had the wrong fixed length.
    #[error("invalid nonce length: expected {expected} bytes, got {actual}")]
    BadNonceLength {
        /// Required length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },
    /// The requested AEAD suite is not supported for this operation.
    #[error("unsupported AEAD algorithm: {0}")]
    UnsupportedAlgorithm(AeadAlgorithm),
    /// AEAD encryption failed.
    #[error("encrypt failed")]
    EncryptFailed,
    /// AEAD authentication failed.
    #[error("decrypt failed")]
    DecryptFailed,
}

fn key_from_slice(bytes: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
    let key = bytes.try_into().map_err(|_| CryptoError::BadKeyLength {
        expected: KEY_LEN,
        actual: bytes.len(),
    })?;
    Ok(Zeroizing::new(key))
}

/// Sign `message` as raw Ed25519 using a materialized 32-byte seed.
///
/// # Errors
///
/// Returns [`CryptoError::BadKeyLength`] when `seed` is not 32 bytes.
pub fn sign_ed25519(seed: &[u8], message: &[u8]) -> Result<[u8; ED25519_SIG_LEN], CryptoError> {
    let seed = key_from_slice(seed)?;
    let key = SigningKey::from_bytes(&seed);
    Ok(key.sign(message).to_bytes())
}

/// Derive the Ed25519 public key from a materialized 32-byte seed.
///
/// # Errors
///
/// Returns [`CryptoError::BadKeyLength`] when `seed` is not 32 bytes.
pub fn public_ed25519(seed: &[u8]) -> Result<[u8; KEY_LEN], CryptoError> {
    let seed = key_from_slice(seed)?;
    let key = SigningKey::from_bytes(&seed);
    Ok(key.verifying_key().to_bytes())
}

/// Verify an Ed25519 signature with public bytes.
///
/// # Errors
///
/// Returns a length error when `public` or `signature` has the wrong fixed
/// length. Non-canonical public keys return `Ok(false)` to avoid an oracle.
pub fn verify_ed25519(
    public: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, CryptoError> {
    let public: [u8; KEY_LEN] = public.try_into().map_err(|_| CryptoError::BadKeyLength {
        expected: KEY_LEN,
        actual: public.len(),
    })?;
    let signature: [u8; ED25519_SIG_LEN] =
        signature
            .try_into()
            .map_err(|_| CryptoError::BadSignatureLength {
                expected: ED25519_SIG_LEN,
                actual: signature.len(),
            })?;
    let Ok(verifying_key) = VerifyingKey::from_bytes(&public) else {
        return Ok(false);
    };
    let signature = Signature::from_bytes(&signature);
    Ok(verifying_key.verify(message, &signature).is_ok())
}

/// Encrypt with a materialized 32-byte AEAD key. Basil owns the nonce.
///
/// # Nonce bounds
///
/// Each call draws a fresh random 96-bit nonce; nothing tracks how many
/// messages a key has protected. With random 96-bit nonces the collision
/// probability stays below the customary 2^-32 target only while a single key
/// version protects fewer than about 2^32 messages (NIST SP 800-38D section
/// 8.3). This module does not enforce that bound: operators of high-volume
/// keys must rotate the backing secret (bumping the envelope `key_version`)
/// well before a key version approaches 2^32 encryptions.
///
/// # Errors
///
/// Returns a length error for non-32-byte key material, or
/// [`CryptoError::EncryptFailed`] if the AEAD implementation rejects the input.
pub fn encrypt_aead(
    key: &[u8],
    algorithm: AeadAlgorithm,
    plaintext: &[u8],
    aad: Option<&[u8]>,
) -> Result<CiphertextEnvelope, CryptoError> {
    let key = key_from_slice(key)?;
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let aad = aad.unwrap_or_default();
    let ciphertext = match algorithm {
        AeadAlgorithm::Aes256Gcm => Aes256Gcm::new_from_slice(key.as_slice())
            .map_err(|_| CryptoError::EncryptFailed)?
            .encrypt(
                &AesNonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::EncryptFailed)?,
        AeadAlgorithm::Chacha20Poly1305 => ChaCha20Poly1305::new_from_slice(key.as_slice())
            .map_err(|_| CryptoError::EncryptFailed)?
            .encrypt(
                &ChaChaNonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::EncryptFailed)?,
    };
    Ok(CiphertextEnvelope {
        alg: algorithm,
        key_version: KEYSTORE_VERSION,
        nonce: nonce.to_vec(),
        ciphertext,
    })
}

/// Decrypt with a materialized 32-byte AEAD key.
///
/// # Errors
///
/// Returns [`CryptoError::DecryptFailed`] for any AEAD authentication failure.
pub fn decrypt_aead(
    key: &[u8],
    envelope: &CiphertextEnvelope,
    aad: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let key = key_from_slice(key)?;
    let nonce: [u8; NONCE_LEN] =
        envelope
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::BadNonceLength {
                expected: NONCE_LEN,
                actual: envelope.nonce.len(),
            })?;
    let aad = aad.unwrap_or_default();
    let plaintext = match envelope.alg {
        AeadAlgorithm::Aes256Gcm => Aes256Gcm::new_from_slice(key.as_slice())
            .map_err(|_| CryptoError::DecryptFailed)?
            .decrypt(
                &AesNonce::from(nonce),
                Payload {
                    msg: envelope.ciphertext.as_slice(),
                    aad,
                },
            )
            .map_err(|_| CryptoError::DecryptFailed)?,
        AeadAlgorithm::Chacha20Poly1305 => ChaCha20Poly1305::new_from_slice(key.as_slice())
            .map_err(|_| CryptoError::DecryptFailed)?
            .decrypt(
                &ChaChaNonce::from(nonce),
                Payload {
                    msg: envelope.ciphertext.as_slice(),
                    aad,
                },
            )
            .map_err(|_| CryptoError::DecryptFailed)?,
    };
    Ok(Zeroizing::new(plaintext))
}

/// Generate fresh 32-byte key material for key-store-backed keys.
#[must_use]
pub fn generate_key_material() -> Zeroizing<[u8; KEY_LEN]> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    rand::thread_rng().fill_bytes(key.as_mut_slice());
    key
}

/// Key-store-backed crypto uses a fixed single version.
#[must_use]
pub const fn keystore_version() -> u32 {
    KEYSTORE_VERSION
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]

    use super::{
        AeadAlgorithm, CryptoError, decrypt_aead, encrypt_aead, generate_key_material,
        public_ed25519, sign_ed25519, verify_ed25519,
    };

    /// A deterministic non-trivial 32-byte key for round-trip assertions.
    const KEY_A: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    /// A different 32-byte key, used for the wrong-key fail-closed cases.
    const KEY_B: [u8; 32] = [0xa5; 32];

    const BOTH_ALGS: [AeadAlgorithm; 2] =
        [AeadAlgorithm::Aes256Gcm, AeadAlgorithm::Chacha20Poly1305];

    #[test]
    fn ed25519_sign_verify_round_trip() {
        let message = b"materialize-to-use ed25519 round trip";
        let signature = sign_ed25519(&KEY_A, message).unwrap();
        let public = public_ed25519(&KEY_A).unwrap();
        assert!(
            verify_ed25519(&public, message, &signature).unwrap(),
            "a signature must verify under the seed's own public"
        );
    }

    #[test]
    fn ed25519_verify_rejects_wrong_key() {
        let message = b"authentic message";
        let signature = sign_ed25519(&KEY_A, message).unwrap();
        // Public of a DIFFERENT seed must not accept the signature.
        let wrong_public = public_ed25519(&KEY_B).unwrap();
        assert!(
            !verify_ed25519(&wrong_public, message, &signature).unwrap(),
            "a signature must fail closed under a foreign public key"
        );
    }

    #[test]
    fn ed25519_verify_rejects_tampered_message() {
        let signature = sign_ed25519(&KEY_A, b"original message").unwrap();
        let public = public_ed25519(&KEY_A).unwrap();
        assert!(
            !verify_ed25519(&public, b"tampered message", &signature).unwrap(),
            "a signature must not verify over a different message"
        );
    }

    #[test]
    fn ed25519_verify_rejects_tampered_signature() {
        let message = b"a message to sign";
        let mut signature = sign_ed25519(&KEY_A, message).unwrap();
        let public = public_ed25519(&KEY_A).unwrap();
        signature[0] ^= 0x01;
        assert!(
            !verify_ed25519(&public, message, &signature).unwrap(),
            "a flipped signature bit must fail closed"
        );
    }

    #[test]
    fn ed25519_is_deterministic() {
        let message = b"determinism check";
        let first = sign_ed25519(&KEY_A, message).unwrap();
        let second = sign_ed25519(&KEY_A, message).unwrap();
        assert_eq!(first, second, "Ed25519 signatures are deterministic");
    }

    #[test]
    fn ed25519_sign_bad_seed_length() {
        let err = sign_ed25519(&[0u8; 31], b"x").unwrap_err();
        assert!(matches!(
            err,
            CryptoError::BadKeyLength {
                expected: 32,
                actual: 31
            }
        ));
    }

    #[test]
    fn public_ed25519_bad_seed_length() {
        let err = public_ed25519(&[0u8; 33]).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::BadKeyLength {
                expected: 32,
                actual: 33
            }
        ));
    }

    #[test]
    fn verify_ed25519_bad_lengths() {
        let signature = sign_ed25519(&KEY_A, b"x").unwrap();
        let public = public_ed25519(&KEY_A).unwrap();
        assert!(matches!(
            verify_ed25519(&public[..31], b"x", &signature),
            Err(CryptoError::BadKeyLength { expected: 32, .. })
        ));
        assert!(matches!(
            verify_ed25519(&public, b"x", &signature[..63]),
            Err(CryptoError::BadSignatureLength { expected: 64, .. })
        ));
    }

    #[test]
    fn verify_ed25519_non_canonical_public_is_false_not_error() {
        // An all-0xFF public is not a canonical Ed25519 point; the API returns
        // Ok(false) rather than surfacing an oracle-shaped error.
        let signature = sign_ed25519(&KEY_A, b"x").unwrap();
        assert!(
            !verify_ed25519(&[0xff; 32], b"x", &signature).unwrap(),
            "a non-canonical public verifies false, not Err"
        );
    }

    #[test]
    fn aead_round_trip_both_algorithms() {
        let plaintext = b"broker-owned-nonce AEAD round trip";
        for alg in BOTH_ALGS {
            let envelope = encrypt_aead(&KEY_A, alg, plaintext, None).unwrap();
            assert_eq!(envelope.alg, alg);
            assert_eq!(envelope.nonce.len(), 12, "Basil owns a 12-byte nonce");
            assert_ne!(
                envelope.ciphertext.as_slice(),
                plaintext.as_slice(),
                "ciphertext must not equal plaintext"
            );
            let recovered = decrypt_aead(&KEY_A, &envelope, None).unwrap();
            assert_eq!(recovered.as_slice(), plaintext.as_slice());
        }
    }

    #[test]
    fn aead_round_trip_with_aad() {
        let plaintext = b"payload";
        let aad = b"bound associated data";
        for alg in BOTH_ALGS {
            let envelope = encrypt_aead(&KEY_A, alg, plaintext, Some(aad)).unwrap();
            let recovered = decrypt_aead(&KEY_A, &envelope, Some(aad)).unwrap();
            assert_eq!(recovered.as_slice(), plaintext.as_slice());
        }
    }

    #[test]
    fn aead_wrong_key_fails_closed() {
        let plaintext = b"secret";
        for alg in BOTH_ALGS {
            let envelope = encrypt_aead(&KEY_A, alg, plaintext, None).unwrap();
            let err = decrypt_aead(&KEY_B, &envelope, None).unwrap_err();
            assert!(matches!(err, CryptoError::DecryptFailed));
        }
    }

    #[test]
    fn aead_tampered_ciphertext_fails_closed() {
        let plaintext = b"secret";
        for alg in BOTH_ALGS {
            let mut envelope = encrypt_aead(&KEY_A, alg, plaintext, None).unwrap();
            envelope.ciphertext[0] ^= 0x01;
            let err = decrypt_aead(&KEY_A, &envelope, None).unwrap_err();
            assert!(matches!(err, CryptoError::DecryptFailed));
        }
    }

    #[test]
    fn aead_wrong_aad_fails_closed() {
        let plaintext = b"secret";
        for alg in BOTH_ALGS {
            let envelope = encrypt_aead(&KEY_A, alg, plaintext, Some(b"aad-one")).unwrap();
            // Right key, wrong AAD -> authentication fails.
            let err = decrypt_aead(&KEY_A, &envelope, Some(b"aad-two")).unwrap_err();
            assert!(matches!(err, CryptoError::DecryptFailed));
            // Right key, AAD dropped entirely -> also fails.
            let err = decrypt_aead(&KEY_A, &envelope, None).unwrap_err();
            assert!(matches!(err, CryptoError::DecryptFailed));
        }
    }

    #[test]
    fn aead_nonce_is_fresh_per_encrypt() {
        let plaintext = b"same plaintext";
        let first = encrypt_aead(&KEY_A, AeadAlgorithm::Aes256Gcm, plaintext, None).unwrap();
        let second = encrypt_aead(&KEY_A, AeadAlgorithm::Aes256Gcm, plaintext, None).unwrap();
        assert_ne!(
            first.nonce, second.nonce,
            "each encrypt must draw a fresh broker-owned nonce"
        );
        assert_ne!(
            first.ciphertext, second.ciphertext,
            "a fresh nonce yields distinct ciphertext for identical plaintext"
        );
    }

    #[test]
    fn encrypt_bad_key_length_fails() {
        let err = encrypt_aead(&[0u8; 16], AeadAlgorithm::Aes256Gcm, b"x", None).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::BadKeyLength {
                expected: 32,
                actual: 16
            }
        ));
    }

    #[test]
    fn decrypt_bad_nonce_length_fails() {
        let mut envelope =
            encrypt_aead(&KEY_A, AeadAlgorithm::Aes256Gcm, b"payload", None).unwrap();
        envelope.nonce.truncate(11);
        let err = decrypt_aead(&KEY_A, &envelope, None).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::BadNonceLength {
                expected: 12,
                actual: 11
            }
        ));
    }

    #[test]
    fn cross_algorithm_ciphertext_does_not_decrypt() {
        // An AES-GCM envelope opened as ChaCha (its alg field flipped) must fail
        // closed rather than returning garbage.
        let mut envelope =
            encrypt_aead(&KEY_A, AeadAlgorithm::Aes256Gcm, b"payload", None).unwrap();
        envelope.alg = AeadAlgorithm::Chacha20Poly1305;
        let err = decrypt_aead(&KEY_A, &envelope, None).unwrap_err();
        assert!(matches!(err, CryptoError::DecryptFailed));
    }

    #[test]
    fn generate_key_material_is_random_32_bytes() {
        let a = generate_key_material();
        let b = generate_key_material();
        assert_eq!(a.len(), 32);
        assert_ne!(
            a.as_slice(),
            b.as_slice(),
            "fresh key material must not repeat"
        );
    }
}
