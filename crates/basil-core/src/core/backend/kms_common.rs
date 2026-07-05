// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Shared helpers for the cloud KMS transit backends (`aws_kms`, `gcp_kms`):
//! public-key parsing and caller-`aad` binding. No SDK dependency lives here.

#![cfg_attr(not(any(feature = "aws-kms", feature = "gcp-kms")), allow(dead_code))]

use base64::Engine as _;
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use p256::pkcs8::DecodePublicKey as _;
use p384::ecdsa::{Signature as P384Signature, VerifyingKey as P384VerifyingKey};
use p521::ecdsa::{Signature as P521Signature, VerifyingKey as P521VerifyingKey};
use sha2::{Digest as _, Sha256, Sha384, Sha512};

use super::{BackendError, SignOptions};

/// The fixed 12-byte DER `SubjectPublicKeyInfo` prefix for an `Ed25519` public
/// key (RFC 8410): `SEQUENCE { SEQUENCE { OID id-Ed25519 }, BIT STRING }`. The
/// raw 32-byte key follows.
pub const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
/// Total length of an `Ed25519` SPKI (12-byte prefix + 32-byte key).
pub const ED25519_SPKI_LEN: usize = 44;

/// Extract the raw 32-byte `Ed25519` public key from a DER `SubjectPublicKeyInfo`.
///
/// # Errors
///
/// [`BackendError::Protocol`] when `der` is not a well-formed `Ed25519` SPKI.
pub fn ed25519_public_from_spki(der: &[u8]) -> Result<Vec<u8>, BackendError> {
    if der.len() == ED25519_SPKI_LEN
        && let (Some(head), Some(key)) = (der.get(..12), der.get(12..ED25519_SPKI_LEN))
        && head == ED25519_SPKI_PREFIX
    {
        return Ok(key.to_vec());
    }
    Err(BackendError::Protocol(
        "kms public key is not an Ed25519 SPKI".to_owned(),
    ))
}

/// Extract a raw SEC1 uncompressed P-256 public point from SPKI DER.
///
/// # Errors
///
/// [`BackendError::Protocol`] when `der` is not a P-256 public-key SPKI.
pub fn p256_sec1_from_spki(der: &[u8]) -> Result<Vec<u8>, BackendError> {
    p256::PublicKey::from_public_key_der(der)
        .map(|key| key.to_encoded_point(false).as_bytes().to_vec())
        .map_err(|e| BackendError::Protocol(format!("P-256 public key SPKI is malformed: {e}")))
}

/// Extract a raw SEC1 uncompressed P-384 public point from SPKI DER.
///
/// # Errors
///
/// [`BackendError::Protocol`] when `der` is not a P-384 public-key SPKI.
pub fn p384_sec1_from_spki(der: &[u8]) -> Result<Vec<u8>, BackendError> {
    p384::PublicKey::from_public_key_der(der)
        .map(|key| key.to_encoded_point(false).as_bytes().to_vec())
        .map_err(|e| BackendError::Protocol(format!("P-384 public key SPKI is malformed: {e}")))
}

/// Extract a raw SEC1 uncompressed P-521 public point from SPKI DER.
///
/// # Errors
///
/// [`BackendError::Protocol`] when `der` is not a P-521 public-key SPKI.
pub fn p521_sec1_from_spki(der: &[u8]) -> Result<Vec<u8>, BackendError> {
    p521::PublicKey::from_public_key_der(der)
        .map(|key| key.to_encoded_point(false).as_bytes().to_vec())
        .map_err(|e| BackendError::Protocol(format!("P-521 public key SPKI is malformed: {e}")))
}

/// Return the digest KMS needs for an ECDSA signing option.
///
/// # Errors
///
/// [`BackendError::Unsupported`] when `options` is not an `ES*` ECDSA mode.
pub fn ecdsa_digest(message: &[u8], options: SignOptions) -> Result<Vec<u8>, BackendError> {
    match options {
        SignOptions::Es256 => Ok(Sha256::digest(message).to_vec()),
        SignOptions::Es384 => Ok(Sha384::digest(message).to_vec()),
        SignOptions::Es512 => Ok(Sha512::digest(message).to_vec()),
        SignOptions::Default | SignOptions::Rs256Pkcs1v15Sha256 => {
            Err(BackendError::Unsupported("ecdsa digest"))
        }
    }
}

/// Convert a backend DER ECDSA signature to the fixed-width raw `r || s` form
/// required by JWS `ES256`/`ES384`/`ES512`.
///
/// # Errors
///
/// [`BackendError::Protocol`] when the DER signature is malformed for `options`.
pub fn ecdsa_der_to_raw(signature: &[u8], options: SignOptions) -> Result<Vec<u8>, BackendError> {
    match options {
        SignOptions::Es256 => {
            let sig = P256Signature::from_der(signature).map_err(|e| {
                BackendError::Protocol(format!("ECDSA P-256 signature DER is malformed: {e}"))
            })?;
            Ok(sig.to_bytes().to_vec())
        }
        SignOptions::Es384 => {
            let sig = P384Signature::from_der(signature).map_err(|e| {
                BackendError::Protocol(format!("ECDSA P-384 signature DER is malformed: {e}"))
            })?;
            Ok(sig.to_bytes().to_vec())
        }
        SignOptions::Es512 => {
            let sig = P521Signature::from_der(signature).map_err(|e| {
                BackendError::Protocol(format!("ECDSA P-521 signature DER is malformed: {e}"))
            })?;
            Ok(sig.to_bytes().to_vec())
        }
        SignOptions::Default | SignOptions::Rs256Pkcs1v15Sha256 => Ok(signature.to_vec()),
    }
}

/// Convert a JWS fixed-width raw `r || s` ECDSA signature to DER for backends
/// whose verify APIs expect ASN.1 DER.
///
/// # Errors
///
/// [`BackendError::Protocol`] when the raw signature width does not match
/// `options`.
pub fn ecdsa_raw_to_der(signature: &[u8], options: SignOptions) -> Result<Vec<u8>, BackendError> {
    match options {
        SignOptions::Es256 => {
            let sig = P256Signature::from_slice(signature).map_err(|e| {
                BackendError::Protocol(format!("ES256 signature must be 64 raw bytes: {e}"))
            })?;
            Ok(sig.to_der().as_bytes().to_vec())
        }
        SignOptions::Es384 => {
            let sig = P384Signature::from_slice(signature).map_err(|e| {
                BackendError::Protocol(format!("ES384 signature must be 96 raw bytes: {e}"))
            })?;
            Ok(sig.to_der().as_bytes().to_vec())
        }
        SignOptions::Es512 => {
            let sig = P521Signature::from_slice(signature).map_err(|e| {
                BackendError::Protocol(format!("ES512 signature must be 132 raw bytes: {e}"))
            })?;
            Ok(sig.to_der().as_bytes().to_vec())
        }
        SignOptions::Default | SignOptions::Rs256Pkcs1v15Sha256 => Ok(signature.to_vec()),
    }
}

/// Verify a JWS fixed-width raw `r || s` ECDSA signature against a SEC1 public
/// point.
///
/// # Errors
///
/// [`BackendError::Protocol`] when the public key or signature encoding is
/// malformed for `options`.
pub fn verify_ecdsa_raw(
    public_sec1: &[u8],
    message: &[u8],
    signature: &[u8],
    options: SignOptions,
) -> Result<bool, BackendError> {
    match options {
        SignOptions::Es256 => {
            use p256::ecdsa::signature::Verifier as _;
            let key = P256VerifyingKey::from_sec1_bytes(public_sec1).map_err(|e| {
                BackendError::Protocol(format!("P-256 public key SEC1 is malformed: {e}"))
            })?;
            let sig = P256Signature::from_slice(signature).map_err(|e| {
                BackendError::Protocol(format!("ES256 signature must be 64 raw bytes: {e}"))
            })?;
            Ok(key.verify(message, &sig).is_ok())
        }
        SignOptions::Es384 => {
            use p384::ecdsa::signature::Verifier as _;
            let key = P384VerifyingKey::from_sec1_bytes(public_sec1).map_err(|e| {
                BackendError::Protocol(format!("P-384 public key SEC1 is malformed: {e}"))
            })?;
            let sig = P384Signature::from_slice(signature).map_err(|e| {
                BackendError::Protocol(format!("ES384 signature must be 96 raw bytes: {e}"))
            })?;
            Ok(key.verify(message, &sig).is_ok())
        }
        SignOptions::Es512 => {
            use p521::ecdsa::signature::Verifier as _;
            let key = P521VerifyingKey::from_sec1_bytes(public_sec1).map_err(|e| {
                BackendError::Protocol(format!("P-521 public key SEC1 is malformed: {e}"))
            })?;
            let sig = P521Signature::from_slice(signature).map_err(|e| {
                BackendError::Protocol(format!("ES512 signature must be 132 raw bytes: {e}"))
            })?;
            Ok(key.verify(message, &sig).is_ok())
        }
        SignOptions::Default | SignOptions::Rs256Pkcs1v15Sha256 => {
            Err(BackendError::Unsupported("verify ecdsa raw"))
        }
    }
}

/// Decode a PEM-armored `SubjectPublicKeyInfo` (as GCP Cloud KMS returns) to DER.
///
/// # Errors
///
/// [`BackendError::Protocol`] when the armor is missing or the body is not valid
/// base64.
pub fn pem_to_der(pem: &str) -> Result<Vec<u8>, BackendError> {
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    if body.is_empty() {
        return Err(BackendError::Protocol(
            "kms public key PEM is empty".to_owned(),
        ));
    }
    base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .map_err(|_| BackendError::Protocol("kms public key PEM is not valid base64".to_owned()))
}

/// Base64-encode caller `aad` for use as a KMS additional-authenticated-data /
/// encryption-context value. Both clouds bind AAD, but AWS KMS contexts are
/// UTF-8 `key=value` pairs, so arbitrary bytes are encoded to round-trip
/// identically on decrypt.
#[must_use]
pub fn aad_context(aad: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(aad)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
    use super::{
        ED25519_SPKI_LEN, ED25519_SPKI_PREFIX, aad_context, ecdsa_der_to_raw, ecdsa_digest,
        ecdsa_raw_to_der, ed25519_public_from_spki, p256_sec1_from_spki, pem_to_der,
        verify_ecdsa_raw,
    };
    use base64::Engine as _;
    use p256::ecdsa::signature::Signer as _;
    use p256::pkcs8::EncodePublicKey as _;

    use crate::backend::SignOptions;

    #[test]
    fn ed25519_spki_extracts_raw_key() {
        let mut der = ED25519_SPKI_PREFIX.to_vec();
        let key: Vec<u8> = (0u8..32).collect();
        der.extend_from_slice(&key);
        assert_eq!(der.len(), ED25519_SPKI_LEN);
        assert_eq!(ed25519_public_from_spki(&der).unwrap(), key);
    }

    #[test]
    fn ed25519_spki_rejects_wrong_length_and_prefix() {
        assert!(ed25519_public_from_spki(&[0u8; 43]).is_err());
        assert!(ed25519_public_from_spki(&[0u8; 45]).is_err());
        assert!(ed25519_public_from_spki(&[]).is_err());
        let mut der = vec![0u8; ED25519_SPKI_LEN];
        der[0] = 0x30;
        assert!(ed25519_public_from_spki(&der).is_err());
    }

    #[test]
    fn pem_round_trips_to_der() {
        let mut der = ED25519_SPKI_PREFIX.to_vec();
        der.extend_from_slice(&(0u8..32).collect::<Vec<u8>>());
        let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
        let pem = format!("-----BEGIN PUBLIC KEY-----\n{b64}\n-----END PUBLIC KEY-----\n");
        assert_eq!(pem_to_der(&pem).unwrap(), der);
        // And the parsed DER feeds the SPKI extractor.
        assert_eq!(
            ed25519_public_from_spki(&pem_to_der(&pem).unwrap())
                .unwrap()
                .len(),
            32
        );
    }

    #[test]
    fn pem_rejects_empty_and_garbage() {
        assert!(pem_to_der("-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----").is_err());
        assert!(pem_to_der("-----BEGIN X-----\n!!!not base64!!!\n-----END X-----").is_err());
    }

    #[test]
    fn aad_context_is_stable_base64() {
        assert_eq!(aad_context(b""), "");
        assert_eq!(aad_context(b"hello"), "aGVsbG8=");
    }

    #[test]
    fn p256_spki_extracts_uncompressed_sec1() {
        let signing_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let public = signing_key.verifying_key();
        let der = public.to_public_key_der().unwrap();
        let sec1 = p256_sec1_from_spki(der.as_bytes()).unwrap();
        assert_eq!(sec1, public.to_encoded_point(false).as_bytes());
    }

    #[test]
    fn ecdsa_es256_converts_between_der_and_raw() {
        let signing_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let der_signature: p256::ecdsa::Signature = signing_key.sign(b"jwt-input");
        let der = der_signature.to_der();
        let raw = ecdsa_der_to_raw(der.as_bytes(), SignOptions::Es256).unwrap();
        assert_eq!(raw.len(), 64);
        let restored = ecdsa_raw_to_der(&raw, SignOptions::Es256).unwrap();
        assert_eq!(restored, der.as_bytes());
    }

    #[test]
    fn ecdsa_es256_raw_verifies_with_sec1_public_key() {
        let signing_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let public = signing_key.verifying_key().to_encoded_point(false);
        let signature: p256::ecdsa::Signature = signing_key.sign(b"jwt-input");
        let raw = signature.to_bytes();

        assert!(
            verify_ecdsa_raw(public.as_bytes(), b"jwt-input", &raw, SignOptions::Es256).unwrap()
        );
        assert!(!verify_ecdsa_raw(public.as_bytes(), b"other", &raw, SignOptions::Es256).unwrap());
    }

    #[test]
    fn ecdsa_digest_width_matches_sign_option() {
        assert_eq!(ecdsa_digest(b"m", SignOptions::Es256).unwrap().len(), 32);
        assert_eq!(ecdsa_digest(b"m", SignOptions::Es384).unwrap().len(), 48);
        assert_eq!(ecdsa_digest(b"m", SignOptions::Es512).unwrap().len(), 64);
    }
}
