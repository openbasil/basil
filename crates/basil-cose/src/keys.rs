// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Shipped local key implementations of the [`Signer`], [`Verifier`], and
//! [`Recipient`] traits.
//!
//! Broker-backed implementations live in the basil client crate; these local
//! ones hold key material directly, with every secret in a `Zeroizing`
//! wrapper (or a `ZeroizeOnDrop` dalek type) on success and error paths.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{
    Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::alg::SignatureAlgorithm;
use crate::codec;
use crate::error::{OpenError, SignError, VerifyError};
use crate::kdf;
use crate::traits::{OpenRequest, Recipient, Signer, Verifier};
use crate::types::{KeyId, Signature};

/// A local Ed25519 signer: a `SigningKey` (`ZeroizeOnDrop`) plus its key id.
pub struct Ed25519Signer {
    key: SigningKey,
    key_id: KeyId,
}

impl Ed25519Signer {
    /// Build a signer from the 32 secret seed bytes.
    #[must_use]
    pub fn from_secret_bytes(key_id: KeyId, secret: &Zeroizing<[u8; 32]>) -> Self {
        Self {
            key: SigningKey::from_bytes(secret),
            key_id,
        }
    }

    /// The Ed25519 public key bytes for this signer.
    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
}

impl Signer for Ed25519Signer {
    fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::EdDsa
    }

    async fn sign(&self, sig_structure: &[u8]) -> Result<Signature, SignError> {
        let sig = self.key.sign(sig_structure);
        Signature::from_bytes(sig.to_bytes().to_vec()).map_err(|_| SignError::Provider {
            message: alloc::string::String::from("empty signature"),
        })
    }
}

/// A local Ed25519 verifier over one or more pinned public keys, looked up
/// by key id.
pub struct Ed25519Verifier {
    keys: BTreeMap<KeyId, VerifyingKey>,
}

/// Why constructing a local key failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// The bytes are not a valid public key for the key type.
    InvalidPublicKey,
    /// The bytes are not a valid private key (scalar) for the key type.
    InvalidPrivateKey,
}

impl core::fmt::Display for KeyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidPublicKey => write!(f, "invalid public key"),
            Self::InvalidPrivateKey => write!(f, "invalid private key"),
        }
    }
}

impl core::error::Error for KeyError {}

impl Ed25519Verifier {
    /// A verifier pinned to a single key.
    ///
    /// # Errors
    /// [`KeyError::InvalidPublicKey`] if the bytes are not a valid point.
    pub fn from_key(key_id: KeyId, public: &[u8; 32]) -> Result<Self, KeyError> {
        let mut keys = BTreeMap::new();
        keys.insert(
            key_id,
            VerifyingKey::from_bytes(public).map_err(|_| KeyError::InvalidPublicKey)?,
        );
        Ok(Self { keys })
    }

    /// Pin an additional key.
    ///
    /// # Errors
    /// [`KeyError::InvalidPublicKey`] if the bytes are not a valid point.
    pub fn add_key(&mut self, key_id: KeyId, public: &[u8; 32]) -> Result<(), KeyError> {
        self.keys.insert(
            key_id,
            VerifyingKey::from_bytes(public).map_err(|_| KeyError::InvalidPublicKey)?,
        );
        Ok(())
    }
}

impl Verifier for Ed25519Verifier {
    async fn verify(
        &self,
        key_id: &KeyId,
        algorithm: SignatureAlgorithm,
        _protected_headers: &crate::claims::ProtectedHeaders,
        sig_structure: &[u8],
        signature: &Signature,
    ) -> Result<(), VerifyError> {
        if algorithm != SignatureAlgorithm::EdDsa {
            return Err(VerifyError::AlgorithmMismatch);
        }
        let key = self.keys.get(key_id).ok_or(VerifyError::UnknownKeyId)?;
        let sig_bytes: [u8; 64] = signature
            .as_bytes()
            .try_into()
            .map_err(|_| VerifyError::SignatureInvalid)?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        // verify_strict rejects small-order/mixed-order components.
        key.verify_strict(sig_structure, &sig)
            .map_err(|_| VerifyError::SignatureInvalid)
    }
}

/// A local `ES256` signer: a P-256 `SigningKey` plus its key id.
///
/// Signing is deterministic (RFC 6979) and low-`S` normalized, so re-signing
/// the same `Sig_structure` yields byte-identical output: the profile's
/// determinism guarantee holds for `ES256` as it does for `EdDSA`.
pub struct Es256Signer {
    key: P256SigningKey,
    key_id: KeyId,
}

impl Es256Signer {
    /// Build a signer from the 32 secret scalar bytes (big-endian).
    ///
    /// # Errors
    /// [`KeyError::InvalidPrivateKey`] if the bytes are not a valid non-zero
    /// P-256 scalar.
    pub fn from_secret_bytes(
        key_id: KeyId,
        secret: &Zeroizing<[u8; 32]>,
    ) -> Result<Self, KeyError> {
        let key = P256SigningKey::from_slice(secret.as_slice())
            .map_err(|_| KeyError::InvalidPrivateKey)?;
        Ok(Self { key, key_id })
    }

    /// The uncompressed SEC1 public key bytes (`0x04 || X || Y`, 65 bytes) for
    /// this signer.
    #[must_use]
    pub fn public_key_sec1(&self) -> Vec<u8> {
        self.key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }
}

impl Signer for Es256Signer {
    fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Es256
    }

    async fn sign(&self, sig_structure: &[u8]) -> Result<Signature, SignError> {
        // `try_sign` is the fallible, no-panic entry; the `ecdsa` crate hashes
        // with SHA-256 and derives the nonce with RFC 6979 (no RNG).
        let sig: P256Signature =
            self.key
                .try_sign(sig_structure)
                .map_err(|_| SignError::Provider {
                    message: alloc::string::String::from("ecdsa signing failed"),
                })?;
        let sig = sig.normalize_s().unwrap_or(sig);
        Signature::from_bytes(sig.to_bytes().to_vec()).map_err(|_| SignError::Provider {
            message: alloc::string::String::from("empty signature"),
        })
    }
}

/// A local `ES256` verifier over one or more pinned P-256 public keys, looked
/// up by key id.
pub struct P256Verifier {
    keys: BTreeMap<KeyId, P256VerifyingKey>,
}

impl P256Verifier {
    /// A verifier pinned to a single key, from SEC1 public key bytes
    /// (compressed or uncompressed).
    ///
    /// # Errors
    /// [`KeyError::InvalidPublicKey`] if the bytes are not a valid P-256 point.
    pub fn from_sec1(key_id: KeyId, public: &[u8]) -> Result<Self, KeyError> {
        let mut keys = BTreeMap::new();
        keys.insert(
            key_id,
            P256VerifyingKey::from_sec1_bytes(public).map_err(|_| KeyError::InvalidPublicKey)?,
        );
        Ok(Self { keys })
    }

    /// Pin an additional key from SEC1 public key bytes.
    ///
    /// # Errors
    /// [`KeyError::InvalidPublicKey`] if the bytes are not a valid P-256 point.
    pub fn add_key(&mut self, key_id: KeyId, public: &[u8]) -> Result<(), KeyError> {
        self.keys.insert(
            key_id,
            P256VerifyingKey::from_sec1_bytes(public).map_err(|_| KeyError::InvalidPublicKey)?,
        );
        Ok(())
    }
}

impl Verifier for P256Verifier {
    async fn verify(
        &self,
        key_id: &KeyId,
        algorithm: SignatureAlgorithm,
        _protected_headers: &crate::claims::ProtectedHeaders,
        sig_structure: &[u8],
        signature: &Signature,
    ) -> Result<(), VerifyError> {
        if algorithm != SignatureAlgorithm::Es256 {
            return Err(VerifyError::AlgorithmMismatch);
        }
        let key = self.keys.get(key_id).ok_or(VerifyError::UnknownKeyId)?;
        // `from_slice` requires the fixed 64-byte `r || s` COSE form; a DER or
        // wrong-length signature is rejected here.
        let sig = P256Signature::from_slice(signature.as_bytes())
            .map_err(|_| VerifyError::SignatureInvalid)?;
        if sig.normalize_s().is_some() {
            return Err(VerifyError::SignatureInvalid);
        }
        key.verify(sig_structure, &sig)
            .map_err(|_| VerifyError::SignatureInvalid)
    }
}

/// A recipient's static X25519 **public** key: the seal target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X25519RecipientPublic {
    /// The recipient key id (becomes the recipient `kid`).
    pub key_id: KeyId,
    /// The static X25519 public key bytes.
    pub public: [u8; 32],
}

/// A local X25519 recipient: the materialized static private key
/// (`Zeroizing`) plus its key id.
pub struct X25519Recipient {
    private: Zeroizing<[u8; 32]>,
    key_id: KeyId,
}

impl X25519Recipient {
    /// Build a recipient from the 32 private key bytes.
    #[must_use]
    pub const fn new(key_id: KeyId, private: Zeroizing<[u8; 32]>) -> Self {
        Self { private, key_id }
    }

    /// Wrap a raw private key slice, failing closed (never indexing) on a
    /// wrong length. The caller should hand the slice from a `Zeroizing`
    /// buffer; the copy taken here is itself `Zeroizing`.
    ///
    /// # Errors
    /// [`KeyLengthError`] if `bytes` is not exactly 32 bytes.
    pub fn from_private_slice(key_id: KeyId, bytes: &[u8]) -> Result<Self, KeyLengthError> {
        let arr: [u8; 32] = bytes.try_into().map_err(|_| KeyLengthError {
            actual: bytes.len(),
        })?;
        Ok(Self::new(key_id, Zeroizing::new(arr)))
    }

    /// The corresponding public half (derived; the private never leaves).
    #[must_use]
    pub fn public(&self) -> X25519RecipientPublic {
        let secret = StaticSecret::from(*self.private);
        X25519RecipientPublic {
            key_id: self.key_id.clone(),
            public: PublicKey::from(&secret).to_bytes(),
        }
    }
}

/// A private key slice was not exactly 32 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyLengthError {
    /// The length actually supplied.
    pub actual: usize,
}

impl core::fmt::Display for KeyLengthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "X25519 private key must be 32 bytes, got {}",
            self.actual
        )
    }
}

impl core::error::Error for KeyLengthError {}

impl Recipient for X25519Recipient {
    fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    async fn open(&self, request: &OpenRequest<'_>) -> Result<Zeroizing<Vec<u8>>, OpenError> {
        open_local(self, request)
    }
}

/// The synchronous local open: strict decode, party pinning, contributory
/// ECDH, `COSE_KDF_Context` HKDF, AEAD open with the exact protected bytes.
fn open_local(
    recipient: &X25519Recipient,
    request: &OpenRequest<'_>,
) -> Result<Zeroizing<Vec<u8>>, OpenError> {
    // The bytes may arrive from a caller that has not pre-validated them
    // (the trait is bytes-in for remote-forwarding symmetry), so strict
    // decode here as well. Claims may or may not be present: both the
    // sealed embedded layer and the seal-only layer route here.
    let decoded = decode_any_encrypt(request.cose_encrypt)?;

    if decoded.recipient_kid != recipient.key_id {
        return Err(OpenError::RecipientKeyMismatch);
    }
    if let Some(expected) = request.expected_parties
        && *expected != decoded.parties
    {
        return Err(OpenError::PartyMismatch);
    }

    let secret = StaticSecret::from(*recipient.private);
    let ephemeral = PublicKey::from(decoded.ephemeral_x);
    let shared_secret = secret.diffie_hellman(&ephemeral);
    // Reject a low-order / all-zero shared secret: an attacker-supplied
    // small-order ephemeral would force a known AEAD key -> a forgeable
    // message this would otherwise ACCEPT. Fail closed BEFORE deriving,
    // with the same opaque error as any other authentication failure.
    if !shared_secret.was_contributory() {
        return Err(OpenError::OpenFailed);
    }
    let shared = Zeroizing::new(shared_secret.to_bytes());

    let info = codec::kdf_context(
        decoded.content_algorithm,
        &decoded.parties,
        &decoded.recipient_protected,
    )
    .map_err(|codec::CodecError| OpenError::OpenFailed)?;
    let cek = kdf::derive_cek(&shared, &info).map_err(|kdf::KdfFailed| OpenError::OpenFailed)?;

    let aad = codec::enc_structure(&decoded.protected, request.external_aad.as_bytes())
        .map_err(|codec::CodecError| OpenError::OpenFailed)?;

    crate::encrypt::aead_open(
        decoded.content_algorithm,
        &cek,
        &decoded.iv,
        &decoded.ciphertext,
        &aad,
    )
}

/// Strict-decode a `COSE_Encrypt` accepting either claims posture (the
/// recipient does not decide the construction; the calling entry point
/// already did).
fn decode_any_encrypt(bytes: &[u8]) -> Result<codec::DecodedEncrypt, OpenError> {
    match codec::decode_encrypt_strict(bytes, codec::ClaimsExpectation::Optional) {
        Ok(d) => Ok(d),
        Err(e) => Err(OpenError::Decode(e)),
    }
}
