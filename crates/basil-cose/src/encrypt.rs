// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The seal-only construction: a bare `COSE_Encrypt` (ECDH-ES + HKDF-256 to
//! one X25519 recipient, AEAD content encryption).
//!
//! Tamper evidence comes from the AEAD only; there is no sender identity
//! here (see the sealed construction for signed messages). Claims are not
//! part of the seal-only construction in v1.

use alloc::vec::Vec;

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305 as ChaChaCipher;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::alg::ContentAlgorithm;
use crate::claims::Claims;
use crate::codec::{self, ClaimsExpectation, NONCE_LEN};
use crate::error::{BuildError, DecodeError, OpenError};
use crate::kdf::{self, KdfParties};
use crate::keys::X25519RecipientPublic;
use crate::traits::{OpenRequest, Recipient};
use crate::types::{ContentType, CoseBytes, ExternalAad, KeyId};

/// Parameters for [`build_encrypted`].
#[derive(Debug, Clone)]
pub struct EncryptParams<'a> {
    /// The plaintext content type (protected header 3).
    pub content_type: ContentType,
    /// The plaintext to seal.
    pub plaintext: &'a [u8],
    /// The recipient's static X25519 public key.
    pub recipient: X25519RecipientPublic,
    /// The content-encryption algorithm.
    pub content_algorithm: ContentAlgorithm,
    /// The `Enc_structure` external AAD.
    pub external_aad: ExternalAad,
    /// KDF party identities (ride in the recipient protected header).
    pub kdf_parties: KdfParties,
}

/// Deterministic parts for fixture builds: the ephemeral private key and the
/// AEAD nonce that production builds generate randomly.
#[cfg(feature = "fixtures")]
#[derive(Debug)]
pub struct SealParts {
    /// The ephemeral X25519 private key bytes.
    pub ephemeral_private: Zeroizing<[u8; 32]>,
    /// The AEAD nonce.
    pub nonce: [u8; NONCE_LEN],
}

/// Fill a fixed-size buffer with OS randomness.
pub fn random_array<const N: usize>() -> Result<Zeroizing<[u8; N]>, BuildError> {
    let mut buf = Zeroizing::new([0u8; N]);
    getrandom::fill(buf.as_mut_slice()).map_err(|_| BuildError::Rng)?;
    Ok(buf)
}

/// AEAD-seal `plaintext` under `key`/`nonce`, binding `aad`.
pub fn aead_seal(
    alg: ContentAlgorithm,
    key: &Zeroizing<[u8; 32]>,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, BuildError> {
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    match alg {
        ContentAlgorithm::A256Gcm => Aes256Gcm::new_from_slice(key.as_slice())
            .map_err(|_| BuildError::SealFailed)?
            .encrypt(aes_gcm::Nonce::from_slice(nonce), payload)
            .map_err(|_| BuildError::SealFailed),
        ContentAlgorithm::ChaCha20Poly1305 => ChaChaCipher::new_from_slice(key.as_slice())
            .map_err(|_| BuildError::SealFailed)?
            .encrypt(chacha20poly1305::Nonce::from_slice(nonce), payload)
            .map_err(|_| BuildError::SealFailed),
    }
}

/// AEAD-open `ciphertext` under `key`/`nonce`, binding `aad`. All
/// authentication failures are the single opaque [`OpenError::OpenFailed`].
pub fn aead_open(
    alg: ContentAlgorithm,
    key: &Zeroizing<[u8; 32]>,
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, OpenError> {
    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    let plaintext = match alg {
        ContentAlgorithm::A256Gcm => Aes256Gcm::new_from_slice(key.as_slice())
            .map_err(|_| OpenError::OpenFailed)?
            .decrypt(aes_gcm::Nonce::from_slice(nonce), payload)
            .map_err(|_| OpenError::OpenFailed)?,
        ContentAlgorithm::ChaCha20Poly1305 => ChaChaCipher::new_from_slice(key.as_slice())
            .map_err(|_| OpenError::OpenFailed)?
            .decrypt(chacha20poly1305::Nonce::from_slice(nonce), payload)
            .map_err(|_| OpenError::OpenFailed)?,
    };
    Ok(Zeroizing::new(plaintext))
}

/// Everything the encrypt core needs; shared by the seal-only and sealed
/// constructions.
pub struct EncryptCore<'a> {
    /// The content-encryption algorithm.
    pub content_algorithm: ContentAlgorithm,
    /// The plaintext content type.
    pub content_type: &'a ContentType,
    /// Claims for the content protected header (sealed construction only).
    pub claims: Option<&'a Claims>,
    /// The plaintext.
    pub plaintext: &'a [u8],
    /// The recipient's static public key.
    pub recipient: &'a X25519RecipientPublic,
    /// The `Enc_structure` external AAD.
    pub external_aad: &'a ExternalAad,
    /// KDF party identities.
    pub kdf_parties: &'a KdfParties,
}

/// Build the complete tagged `COSE_Encrypt` bytes from explicit ephemeral
/// and nonce material. Production paths generate both randomly.
pub fn build_encrypt_core(
    core: &EncryptCore<'_>,
    ephemeral_private: &Zeroizing<[u8; 32]>,
    nonce: [u8; NONCE_LEN],
) -> Result<Vec<u8>, BuildError> {
    let ephemeral_secret = StaticSecret::from(**ephemeral_private);
    let ephemeral_pub = PublicKey::from(&ephemeral_secret).to_bytes();

    let recipient_pub = PublicKey::from(core.recipient.public);
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_pub);
    // Reject a low-order / all-zero shared secret before deriving: a
    // degenerate recipient public would force a known AEAD key.
    if !shared_secret.was_contributory() {
        return Err(BuildError::SealFailed);
    }
    let shared = Zeroizing::new(shared_secret.to_bytes());

    let recipient_protected = codec::encode_recipient_protected(core.kdf_parties)
        .map_err(|codec::CodecError| BuildError::Codec)?;
    let info = codec::kdf_context(
        core.content_algorithm,
        core.kdf_parties,
        &recipient_protected,
    )
    .map_err(|codec::CodecError| BuildError::Codec)?;
    let cek = kdf::derive_cek(&shared, &info).map_err(|kdf::KdfFailed| BuildError::SealFailed)?;

    let protected =
        codec::encode_encrypt_protected(core.content_algorithm, core.content_type, core.claims)
            .map_err(|codec::CodecError| BuildError::Codec)?;
    let aad = codec::enc_structure(&protected, core.external_aad.as_bytes())
        .map_err(|codec::CodecError| BuildError::Codec)?;
    let ciphertext = aead_seal(core.content_algorithm, &cek, &nonce, core.plaintext, &aad)?;

    codec::assemble_encrypt(&codec::EncryptAssembly {
        protected: &protected,
        iv: &nonce,
        ciphertext: &ciphertext,
        recipient_protected: &recipient_protected,
        recipient_kid: &core.recipient.key_id,
        ephemeral_x: &ephemeral_pub,
    })
    .map_err(|codec::CodecError| BuildError::Codec)
}

impl EncryptParams<'_> {
    const fn core(&self) -> EncryptCore<'_> {
        EncryptCore {
            content_algorithm: self.content_algorithm,
            content_type: &self.content_type,
            claims: None,
            plaintext: self.plaintext,
            recipient: &self.recipient,
            external_aad: &self.external_aad,
            kdf_parties: &self.kdf_parties,
        }
    }
}

/// Seal `plaintext` to one X25519 recipient as a bare tagged `COSE_Encrypt`.
///
/// Fully local and synchronous: sealing needs only the recipient public key,
/// no signer and no broker. The library generates the 12-byte nonce and
/// the ephemeral X25519 keypair internally (fresh per message, zeroized);
/// there is no caller-supplied-nonce path in the public API.
///
/// # Errors
/// [`BuildError::Rng`] when OS randomness is unavailable;
/// [`BuildError::SealFailed`]/[`BuildError::Codec`] on crypto-internal
/// failures that should not occur for in-range inputs.
pub fn build_encrypted(params: &EncryptParams<'_>) -> Result<CoseBytes, BuildError> {
    let ephemeral = random_array::<32>()?;
    let nonce = random_array::<NONCE_LEN>()?;
    build_encrypt_core(&params.core(), &ephemeral, *nonce).map(CoseBytes::new)
}

/// [`build_encrypted`] with caller-supplied ephemeral/nonce parts, for
/// deterministic test vectors only.
///
/// # Errors
/// As [`build_encrypted`], minus [`BuildError::Rng`].
#[cfg(feature = "fixtures")]
pub fn build_encrypted_with_parts(
    params: &EncryptParams<'_>,
    parts: &SealParts,
) -> Result<CoseBytes, BuildError> {
    build_encrypt_core(&params.core(), &parts.ephemeral_private, parts.nonce).map(CoseBytes::new)
}

/// A strictly decoded (not yet opened) seal-only message.
#[derive(Debug, Clone)]
pub struct EncryptedMessage {
    /// The plaintext content type from the protected header.
    pub content_type: ContentType,
    /// The recipient static key id this message is sealed to.
    pub recipient_key_id: KeyId,
    /// The content-encryption algorithm.
    pub content_algorithm: ContentAlgorithm,
    /// The KDF party identities from the recipient protected header.
    pub parties: KdfParties,
    /// The exact tagged bytes (the `Enc_structure` binds the exact protected
    /// header serialization, so openers always work from these).
    bytes: Vec<u8>,
}

/// Strict-decode a seal-only tagged `COSE_Encrypt` (no opening, no claims).
///
/// # Errors
/// Any [`DecodeError`] the strict profile decoder emits; claims labels in a
/// seal-only message are rejected.
pub fn decode_encrypted(bytes: &[u8]) -> Result<EncryptedMessage, DecodeError> {
    let decoded = codec::decode_encrypt_strict(bytes, ClaimsExpectation::Forbidden)?;
    Ok(EncryptedMessage {
        content_type: decoded.content_type,
        recipient_key_id: decoded.recipient_kid,
        content_algorithm: decoded.content_algorithm,
        parties: decoded.parties,
        bytes: bytes.to_vec(),
    })
}

/// An opened (decrypted) message.
#[derive(Debug)]
pub struct Opened {
    /// The recovered plaintext, in a zeroizing buffer.
    pub plaintext: Zeroizing<Vec<u8>>,
    /// The plaintext content type.
    pub content_type: ContentType,
}

impl EncryptedMessage {
    /// Open this message with `recipient`, binding `aad`, optionally pinning
    /// the KDF party identities.
    ///
    /// # Errors
    /// [`OpenError::RecipientKeyMismatch`] when the message is addressed to
    /// a different key; [`OpenError::PartyMismatch`] when pinned parties
    /// disagree with the wire; [`OpenError::OpenFailed`] (opaque) on any
    /// authentication failure.
    pub async fn open<R: Recipient>(
        &self,
        recipient: &R,
        aad: &ExternalAad,
        expected_parties: Option<&KdfParties>,
    ) -> Result<Opened, OpenError> {
        if recipient.key_id() != &self.recipient_key_id {
            return Err(OpenError::RecipientKeyMismatch);
        }
        if let Some(expected) = expected_parties
            && *expected != self.parties
        {
            return Err(OpenError::PartyMismatch);
        }
        let request = OpenRequest {
            cose_encrypt: &self.bytes,
            external_aad: aad,
            expected_parties,
        };
        let plaintext = recipient.open(&request).await?;
        Ok(Opened {
            plaintext,
            content_type: self.content_type.clone(),
        })
    }
}
