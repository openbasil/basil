// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! ML-KEM envelope open/seal core for software-custodied sealing keys.
//!
//! Basil stores ML-KEM decapsulation keys as the crate-native 64-byte seed. The
//! broker materializes that seed from KV for one `UnwrapEnvelope` operation,
//! decapsulates the caller-supplied ciphertext, derives an AEAD key with
//! `HKDF`-`SHA256`, and zeroizes the secret material on every path.

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate, FromSeed, KeyExport};
use ml_kem::{MlKem512, MlKem768, MlKem1024};
use sha2::Sha256;
use zeroize::Zeroizing;

/// Length of the stored ML-KEM seed / decapsulation key material.
pub const SEED_LEN: usize = 64;
/// Length of the broker/provider-owned AEAD nonce.
pub const NONCE_LEN: usize = 12;
const AEAD_KEY_LEN: usize = 32;
const HKDF_LABEL: &[u8] = b"basil-ml-kem-envelope-v1";

/// Supported ML-KEM parameter sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemAlgorithm {
    /// ML-KEM-512.
    MlKem512,
    /// ML-KEM-768.
    MlKem768,
    /// ML-KEM-1024.
    MlKem1024,
}

impl KemAlgorithm {
    /// The kebab-case token used in catalog and diagnostics.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::MlKem512 => "ml-kem-512",
            Self::MlKem768 => "ml-kem-768",
            Self::MlKem1024 => "ml-kem-1024",
        }
    }
}

/// Symmetric envelope AEAD used after KEM shared-secret derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeAlgorithm {
    /// AES-256-GCM.
    Aes256Gcm,
    /// ChaCha20-Poly1305.
    ChaCha20Poly1305,
}

impl EnvelopeAlgorithm {
    const fn token(self) -> &'static str {
        match self {
            Self::Aes256Gcm => "aes-256-gcm",
            Self::ChaCha20Poly1305 => "chacha20-poly1305",
        }
    }
}

/// Public ML-KEM envelope fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlKemEnvelope {
    /// ML-KEM parameter set.
    pub kem_algorithm: KemAlgorithm,
    /// Envelope AEAD algorithm.
    pub envelope_algorithm: EnvelopeAlgorithm,
    /// ML-KEM ciphertext / encapsulated shared secret.
    pub encapsulated_key: Vec<u8>,
    /// AEAD nonce.
    pub nonce: [u8; NONCE_LEN],
    /// AEAD ciphertext including tag.
    pub ciphertext: Vec<u8>,
}

/// Why an ML-KEM envelope operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MlKemEnvelopeError {
    /// The stored seed was not exactly 64 bytes.
    #[error("invalid ML-KEM seed length: expected {expected} bytes, got {actual}")]
    BadSeedLength {
        /// Required length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },

    /// The encapsulated key was not the parameter set's ciphertext length.
    #[error("invalid ML-KEM ciphertext length")]
    BadCiphertextLength,

    /// The nonce was not exactly [`NONCE_LEN`] bytes.
    #[error("invalid nonce length: expected {expected} bytes, got {actual}")]
    BadNonceLength {
        /// Required length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },

    /// HKDF expansion failed.
    #[error("key derivation failed")]
    KdfFailed,

    /// AEAD sealing failed.
    #[error("seal failed")]
    SealFailed,

    /// AEAD authentication failed on open.
    #[error("open failed")]
    OpenFailed,
}

/// Reconstruct an ML-KEM envelope from wire fields, validating fixed-size fields.
///
/// # Errors
///
/// [`MlKemEnvelopeError::BadNonceLength`] if `nonce` has the wrong length.
pub fn envelope_from_parts(
    kem_algorithm: KemAlgorithm,
    envelope_algorithm: EnvelopeAlgorithm,
    encapsulated_key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<MlKemEnvelope, MlKemEnvelopeError> {
    let nonce: [u8; NONCE_LEN] =
        nonce
            .try_into()
            .map_err(|_| MlKemEnvelopeError::BadNonceLength {
                expected: NONCE_LEN,
                actual: nonce.len(),
            })?;
    Ok(MlKemEnvelope {
        kem_algorithm,
        envelope_algorithm,
        encapsulated_key: encapsulated_key.to_vec(),
        nonce,
        ciphertext: ciphertext.to_vec(),
    })
}

/// Open an ML-KEM envelope with a materialized 64-byte decapsulation seed.
///
/// # Errors
///
/// Returns [`MlKemEnvelopeError::BadSeedLength`] for malformed key material,
/// [`MlKemEnvelopeError::BadCiphertextLength`] for malformed encapsulated bytes,
/// and [`MlKemEnvelopeError::OpenFailed`] for a wrong key, tampered envelope, or
/// mismatched `aad`.
pub fn open(
    seed: &[u8],
    envelope: &MlKemEnvelope,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, MlKemEnvelopeError> {
    let seed = seed_from_slice(seed)?;
    match envelope.kem_algorithm {
        KemAlgorithm::MlKem512 => open_for::<MlKem512>(&seed, envelope, aad),
        KemAlgorithm::MlKem768 => open_for::<MlKem768>(&seed, envelope, aad),
        KemAlgorithm::MlKem1024 => open_for::<MlKem1024>(&seed, envelope, aad),
    }
}

/// Seal with a materialized seed's public half. Used by tests and external
/// senders that provision from the same seed format.
///
/// # Errors
///
/// Returns [`MlKemEnvelopeError::BadSeedLength`] for malformed seed material.
pub fn seal(
    seed: &[u8],
    kem_algorithm: KemAlgorithm,
    envelope_algorithm: EnvelopeAlgorithm,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<MlKemEnvelope, MlKemEnvelopeError> {
    let seed = seed_from_slice(seed)?;
    match kem_algorithm {
        KemAlgorithm::MlKem512 => seal_for::<MlKem512>(
            &seed,
            KemAlgorithm::MlKem512,
            envelope_algorithm,
            plaintext,
            aad,
        ),
        KemAlgorithm::MlKem768 => seal_for::<MlKem768>(
            &seed,
            KemAlgorithm::MlKem768,
            envelope_algorithm,
            plaintext,
            aad,
        ),
        KemAlgorithm::MlKem1024 => seal_for::<MlKem1024>(
            &seed,
            KemAlgorithm::MlKem1024,
            envelope_algorithm,
            plaintext,
            aad,
        ),
    }
}

/// Derive the published ML-KEM encapsulation (public) key bytes from a
/// software-custodied 64-byte seed.
///
/// The encapsulation key is non-secret: it is what an external sender would
/// encapsulate against. Used at provisioning time to record/return the public
/// half without exposing the seed.
///
/// # Errors
///
/// Returns [`MlKemEnvelopeError::BadSeedLength`] for malformed seed material.
pub fn public_from_seed(
    seed: &[u8],
    algorithm: KemAlgorithm,
) -> Result<Vec<u8>, MlKemEnvelopeError> {
    let seed = seed_from_slice(seed)?;
    Ok(match algorithm {
        KemAlgorithm::MlKem512 => public_from_seed_for::<MlKem512>(&seed),
        KemAlgorithm::MlKem768 => public_from_seed_for::<MlKem768>(&seed),
        KemAlgorithm::MlKem1024 => public_from_seed_for::<MlKem1024>(&seed),
    })
}

/// Raw ML-KEM encapsulation against a software-custodied seed's public half.
///
/// Returns the encapsulated key (safe to publish) and the shared secret (kept
/// in [`Zeroizing`]). This is the KEM primitive without the AEAD envelope that
/// [`seal`] adds.
///
/// # Errors
///
/// Returns [`MlKemEnvelopeError::BadSeedLength`] for malformed seed material.
pub fn encapsulate(
    seed: &[u8],
    algorithm: KemAlgorithm,
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), MlKemEnvelopeError> {
    let seed = seed_from_slice(seed)?;
    Ok(match algorithm {
        KemAlgorithm::MlKem512 => encapsulate_for::<MlKem512>(&seed),
        KemAlgorithm::MlKem768 => encapsulate_for::<MlKem768>(&seed),
        KemAlgorithm::MlKem1024 => encapsulate_for::<MlKem1024>(&seed),
    })
}

/// Raw ML-KEM decapsulation with a materialized 64-byte seed.
///
/// Recovers the shared secret from an encapsulated key: the KEM primitive
/// without the AEAD envelope that [`open`] adds.
///
/// # Errors
///
/// Returns [`MlKemEnvelopeError::BadSeedLength`] for malformed key material and
/// [`MlKemEnvelopeError::BadCiphertextLength`] for a malformed encapsulated key.
pub fn decapsulate(
    seed: &[u8],
    algorithm: KemAlgorithm,
    encapsulated_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, MlKemEnvelopeError> {
    let seed = seed_from_slice(seed)?;
    match algorithm {
        KemAlgorithm::MlKem512 => decapsulate_for::<MlKem512>(&seed, encapsulated_key),
        KemAlgorithm::MlKem768 => decapsulate_for::<MlKem768>(&seed, encapsulated_key),
        KemAlgorithm::MlKem1024 => decapsulate_for::<MlKem1024>(&seed, encapsulated_key),
    }
}

fn public_from_seed_for<K>(seed: &ml_kem::Seed) -> Vec<u8>
where
    K: ml_kem::kem::Kem + FromSeed<SeedSize = ml_kem::array::sizes::U64>,
    K::EncapsulationKey: KeyExport,
{
    let (_decapsulation_key, encapsulation_key) = K::from_seed(seed);
    <_ as AsRef<[u8]>>::as_ref(&encapsulation_key.to_bytes()).to_vec()
}

fn encapsulate_for<K>(seed: &ml_kem::Seed) -> (Vec<u8>, Zeroizing<Vec<u8>>)
where
    K: ml_kem::kem::Kem + FromSeed<SeedSize = ml_kem::array::sizes::U64>,
    K::EncapsulationKey: Encapsulate<Kem = K>,
{
    let (_decapsulation_key, encapsulation_key) = K::from_seed(seed);
    let (encapsulated_key, shared_secret) = encapsulation_key.encapsulate();
    let encapsulated_key = <_ as AsRef<[u8]>>::as_ref(&encapsulated_key).to_vec();
    let shared_secret = Zeroizing::new(<_ as AsRef<[u8]>>::as_ref(&shared_secret).to_vec());
    (encapsulated_key, shared_secret)
}

fn decapsulate_for<K>(
    seed: &ml_kem::Seed,
    encapsulated_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, MlKemEnvelopeError>
where
    K: ml_kem::kem::Kem + FromSeed<SeedSize = ml_kem::array::sizes::U64>,
    K::DecapsulationKey: Decapsulate<Kem = K>,
{
    let (decapsulation_key, _encapsulation_key) = K::from_seed(seed);
    let shared_secret = decapsulation_key
        .decapsulate_slice(encapsulated_key)
        .map_err(|_| MlKemEnvelopeError::BadCiphertextLength)?;
    Ok(Zeroizing::new(
        <_ as AsRef<[u8]>>::as_ref(&shared_secret).to_vec(),
    ))
}

fn seed_from_slice(seed: &[u8]) -> Result<Zeroizing<ml_kem::Seed>, MlKemEnvelopeError> {
    let seed = seed
        .try_into()
        .map_err(|_| MlKemEnvelopeError::BadSeedLength {
            expected: SEED_LEN,
            actual: seed.len(),
        })?;
    Ok(Zeroizing::new(seed))
}

fn open_for<K>(
    seed: &ml_kem::Seed,
    envelope: &MlKemEnvelope,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, MlKemEnvelopeError>
where
    K: ml_kem::kem::Kem + FromSeed<SeedSize = ml_kem::array::sizes::U64>,
    K::DecapsulationKey: Decapsulate<Kem = K>,
    K::EncapsulationKey: KeyExport,
{
    let (decapsulation_key, encapsulation_key) = K::from_seed(seed);
    let shared_secret = decapsulation_key
        .decapsulate_slice(&envelope.encapsulated_key)
        .map_err(|_| MlKemEnvelopeError::BadCiphertextLength)?;
    let public_key = encapsulation_key.to_bytes();
    let aead_key = derive_aead_key(
        envelope.kem_algorithm,
        envelope.envelope_algorithm,
        shared_secret.as_ref(),
        &envelope.encapsulated_key,
        public_key.as_ref(),
    )?;
    decrypt(
        envelope.envelope_algorithm,
        &aead_key,
        &envelope.nonce,
        &envelope.ciphertext,
        aad,
    )
}

fn seal_for<K>(
    seed: &ml_kem::Seed,
    kem_algorithm: KemAlgorithm,
    envelope_algorithm: EnvelopeAlgorithm,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<MlKemEnvelope, MlKemEnvelopeError>
where
    K: ml_kem::kem::Kem + FromSeed<SeedSize = ml_kem::array::sizes::U64>,
    K::EncapsulationKey: Encapsulate<Kem = K> + KeyExport,
{
    let (_decapsulation_key, encapsulation_key) = K::from_seed(seed);
    let (encapsulated_key, shared_secret) = encapsulation_key.encapsulate();
    let public_key = encapsulation_key.to_bytes();
    let encapsulated_key = <_ as AsRef<[u8]>>::as_ref(&encapsulated_key).to_vec();
    let aead_key = derive_aead_key(
        kem_algorithm,
        envelope_algorithm,
        shared_secret.as_ref(),
        &encapsulated_key,
        public_key.as_ref(),
    )?;
    let mut nonce = [0u8; NONCE_LEN];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
    let ciphertext = encrypt(envelope_algorithm, &aead_key, &nonce, plaintext, aad)?;
    Ok(MlKemEnvelope {
        kem_algorithm,
        envelope_algorithm,
        encapsulated_key,
        nonce,
        ciphertext,
    })
}

fn derive_aead_key(
    kem_algorithm: KemAlgorithm,
    envelope_algorithm: EnvelopeAlgorithm,
    shared_secret: &[u8],
    encapsulated_key: &[u8],
    public_key: &[u8],
) -> Result<Zeroizing<[u8; AEAD_KEY_LEN]>, MlKemEnvelopeError> {
    let mut info = Vec::with_capacity(
        HKDF_LABEL.len()
            + kem_algorithm.token().len()
            + envelope_algorithm.token().len()
            + encapsulated_key.len()
            + public_key.len(),
    );
    info.extend_from_slice(HKDF_LABEL);
    info.extend_from_slice(kem_algorithm.token().as_bytes());
    info.extend_from_slice(envelope_algorithm.token().as_bytes());
    info.extend_from_slice(encapsulated_key);
    info.extend_from_slice(public_key);

    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = Zeroizing::new([0u8; AEAD_KEY_LEN]);
    hk.expand(&info, okm.as_mut_slice())
        .map_err(|_| MlKemEnvelopeError::KdfFailed)?;
    Ok(okm)
}

fn encrypt(
    envelope_algorithm: EnvelopeAlgorithm,
    key: &Zeroizing<[u8; AEAD_KEY_LEN]>,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, MlKemEnvelopeError> {
    match envelope_algorithm {
        EnvelopeAlgorithm::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key.as_slice())
                .map_err(|_| MlKemEnvelopeError::SealFailed)?;
            let nonce = aes_gcm::Nonce::from(*nonce);
            cipher
                .encrypt(
                    &nonce,
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| MlKemEnvelopeError::SealFailed)
        }
        EnvelopeAlgorithm::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key.as_slice())
                .map_err(|_| MlKemEnvelopeError::SealFailed)?;
            let nonce = Nonce::from(*nonce);
            cipher
                .encrypt(
                    &nonce,
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| MlKemEnvelopeError::SealFailed)
        }
    }
}

fn decrypt(
    envelope_algorithm: EnvelopeAlgorithm,
    key: &Zeroizing<[u8; AEAD_KEY_LEN]>,
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, MlKemEnvelopeError> {
    let plaintext = match envelope_algorithm {
        EnvelopeAlgorithm::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key.as_slice())
                .map_err(|_| MlKemEnvelopeError::SealFailed)?;
            let nonce = aes_gcm::Nonce::from(*nonce);
            cipher.decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
        }
        EnvelopeAlgorithm::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key.as_slice())
                .map_err(|_| MlKemEnvelopeError::SealFailed)?;
            let nonce = Nonce::from(*nonce);
            cipher.decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
        }
    }
    .map_err(|_| MlKemEnvelopeError::OpenFailed)?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; SEED_LEN] = [0x42; SEED_LEN];

    #[test]
    fn all_parameter_sets_round_trip() {
        for algorithm in [
            KemAlgorithm::MlKem512,
            KemAlgorithm::MlKem768,
            KemAlgorithm::MlKem1024,
        ] {
            let envelope = seal(
                &SEED,
                algorithm,
                EnvelopeAlgorithm::ChaCha20Poly1305,
                b"payload",
                b"aad",
            )
            .expect("seal");
            let recovered = open(&SEED, &envelope, b"aad").expect("open");
            assert_eq!(recovered.as_slice(), b"payload");
        }
    }

    #[test]
    fn aes_gcm_round_trips() {
        let envelope = seal(
            &SEED,
            KemAlgorithm::MlKem768,
            EnvelopeAlgorithm::Aes256Gcm,
            b"payload",
            b"aad",
        )
        .expect("seal");
        let recovered = open(&SEED, &envelope, b"aad").expect("open");
        assert_eq!(recovered.as_slice(), b"payload");
    }

    #[test]
    fn wrong_aad_and_tampering_fail_opaque() {
        let mut envelope = seal(
            &SEED,
            KemAlgorithm::MlKem768,
            EnvelopeAlgorithm::ChaCha20Poly1305,
            b"payload",
            b"right",
        )
        .expect("seal");
        assert_eq!(
            open(&SEED, &envelope, b"wrong"),
            Err(MlKemEnvelopeError::OpenFailed)
        );
        if let Some(byte) = envelope.ciphertext.first_mut() {
            *byte ^= 0xFF;
        }
        assert_eq!(
            open(&SEED, &envelope, b"right"),
            Err(MlKemEnvelopeError::OpenFailed)
        );
    }

    #[test]
    fn bad_seed_and_ciphertext_lengths_fail_closed() {
        let envelope = seal(
            &SEED,
            KemAlgorithm::MlKem768,
            EnvelopeAlgorithm::ChaCha20Poly1305,
            b"payload",
            b"aad",
        )
        .expect("seal");
        assert!(matches!(
            open(&[0u8; SEED_LEN - 1], &envelope, b"aad"),
            Err(MlKemEnvelopeError::BadSeedLength { .. })
        ));

        let malformed = MlKemEnvelope {
            encapsulated_key: vec![0u8; 7],
            ..envelope
        };
        assert_eq!(
            open(&SEED, &malformed, b"aad"),
            Err(MlKemEnvelopeError::BadCiphertextLength)
        );
    }

    #[test]
    fn public_from_seed_is_deterministic_and_sized_per_param_set() {
        // FIPS 203 ML-KEM encapsulation-key sizes: 512 → 800, 768 → 1184,
        // 1024 → 1568 bytes. The derivation is deterministic from the seed.
        for (algorithm, len) in [
            (KemAlgorithm::MlKem512, 800usize),
            (KemAlgorithm::MlKem768, 1184),
            (KemAlgorithm::MlKem1024, 1568),
        ] {
            let public = public_from_seed(&SEED, algorithm).expect("derive public");
            assert_eq!(public.len(), len);
            assert_eq!(
                public,
                public_from_seed(&SEED, algorithm).expect("derive again")
            );
        }
        assert!(matches!(
            public_from_seed(&[0u8; SEED_LEN - 1], KemAlgorithm::MlKem768),
            Err(MlKemEnvelopeError::BadSeedLength { .. })
        ));
    }

    #[test]
    fn raw_encapsulate_decapsulate_shared_secret_matches() {
        for algorithm in [
            KemAlgorithm::MlKem512,
            KemAlgorithm::MlKem768,
            KemAlgorithm::MlKem1024,
        ] {
            let (encapsulated, sender_secret) = encapsulate(&SEED, algorithm).expect("encapsulate");
            let receiver_secret =
                decapsulate(&SEED, algorithm, &encapsulated).expect("decapsulate");
            assert_eq!(sender_secret.as_slice(), receiver_secret.as_slice());
            assert!(!sender_secret.is_empty());
        }
    }

    #[test]
    fn raw_decapsulate_fails_closed_on_bad_lengths() {
        let (encapsulated, _) = encapsulate(&SEED, KemAlgorithm::MlKem768).expect("encapsulate");
        assert!(matches!(
            encapsulate(&[0u8; SEED_LEN - 1], KemAlgorithm::MlKem768),
            Err(MlKemEnvelopeError::BadSeedLength { .. })
        ));
        assert_eq!(
            decapsulate(
                &SEED,
                KemAlgorithm::MlKem768,
                &encapsulated[..encapsulated.len() - 1]
            ),
            Err(MlKemEnvelopeError::BadCiphertextLength)
        );
    }

    #[test]
    fn envelope_from_parts_validates_nonce_length() {
        assert!(matches!(
            envelope_from_parts(
                KemAlgorithm::MlKem768,
                EnvelopeAlgorithm::ChaCha20Poly1305,
                b"ct",
                &[0u8; NONCE_LEN - 1],
                b"body"
            ),
            Err(MlKemEnvelopeError::BadNonceLength { .. })
        ));
    }
}
