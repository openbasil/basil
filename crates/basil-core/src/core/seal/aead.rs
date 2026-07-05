//! AES-256-GCM helpers for the sealed bundle (vault-vh1).
//!
//! Both the payload encryption and every slot's KEK-wrap use AES-256-GCM with a
//! fresh **12-byte CSPRNG nonce** and the literal on-disk header bytes as AAD
//! (§2.3 / §2.4 of `designs/unlock-and-bundle.html`). Every call returns a
//! `Result`; there is no `unwrap`/`expect`/panicking index on any path (§1.3).

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use zeroize::Zeroizing;

use super::SealError;

/// Length of an AES-256 key in bytes.
pub const KEY_LEN: usize = 32;
/// Length of the AES-GCM nonce in bytes (96-bit, broker-owned, CSPRNG).
pub const NONCE_LEN: usize = 12;

/// Draw `NONCE_LEN` fresh bytes from the OS CSPRNG for a single AEAD nonce.
///
/// The nonce is broker-owned (no caller-supplied path); a random 96-bit nonce is
/// collision-safe at the bundle's rare re-seal frequency (§2.3).
#[must_use]
pub fn fresh_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Draw `KEY_LEN` fresh bytes from the OS CSPRNG (a new master KEK / slot key).
#[must_use]
pub fn fresh_key() -> Zeroizing<[u8; KEY_LEN]> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    rand::rngs::OsRng.fill_bytes(key.as_mut());
    key
}

/// AES-256-GCM seal `plaintext` under `key`, binding `aad`, returning the
/// ciphertext (with the 16-byte GCM tag appended by the AEAD).
///
/// # Errors
/// Returns [`SealError::Crypto`] if the AEAD fails (e.g. message too large).
pub fn seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, SealError> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from(*nonce);
    cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| SealError::Crypto("aes-256-gcm seal failed".into()))
}

/// AES-256-GCM open `ciphertext` under `key`, verifying `aad`.
///
/// The plaintext is returned in a [`Zeroizing`] buffer so it is wiped on drop;
/// callers that need to keep it should move it into the appropriate owner.
///
/// # Errors
/// Returns [`SealError::AuthFailed`] on any authentication failure (tampered
/// header/AAD, wrong key, truncated ciphertext): fail closed, never panic.
pub fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SealError> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from(*nonce);
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| SealError::AuthFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = fresh_key();
        let nonce = fresh_nonce();
        let aad = b"header-bytes";
        let msg = b"the master kek or cred map";
        let ct = seal(&key, &nonce, aad, msg).unwrap();
        let pt = open(&key, &nonce, aad, &ct).unwrap();
        assert_eq!(pt.as_slice(), msg);
    }

    #[test]
    fn wrong_aad_fails_closed() {
        let key = fresh_key();
        let nonce = fresh_nonce();
        let ct = seal(&key, &nonce, b"aad-a", b"msg").unwrap();
        // A different AAD (e.g. a tampered header) must fail authentication.
        let err = open(&key, &nonce, b"aad-b", &ct).unwrap_err();
        assert!(matches!(err, SealError::AuthFailed));
    }

    #[test]
    fn wrong_key_fails_closed() {
        let key = fresh_key();
        let other = fresh_key();
        let nonce = fresh_nonce();
        let ct = seal(&key, &nonce, b"aad", b"msg").unwrap();
        assert!(matches!(
            open(&other, &nonce, b"aad", &ct),
            Err(SealError::AuthFailed)
        ));
    }
}
