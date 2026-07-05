// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! X25519 sealed-box: the self-contained crypto core for enrollment unseal
//! (basil-t9a, design §17.7: the materialize-to-use local-custody arm).
//!
//! `OpenBao`/Vault transit has no X25519 key type and no `ECDH` primitive, so an
//! X25519 private key cannot be used *in place* the way an Ed25519 signing key or
//! an AES transit key is. The design-sanctioned answer (secrets-vault §17.7) is to
//! **materialize** the private from encrypted KV in-process, perform the one
//! `ECDH`, then **zeroize** it. This module is the crypto core for that path: it
//! takes raw key bytes and has **no** backend/Bao dependency, so the construction
//! is unit-testable fully offline.
//!
//! # Construction (sealed box, libsodium-style, X25519 + `HKDF` + AEAD)
//!
//! - **KEM**: X25519 `ECDH`. The sender generates a fresh **ephemeral** X25519
//!   keypair; the shared secret is `ECDH(ephemeral_priv, recipient_pub)`. The
//!   envelope carries the ephemeral **public** key as `encapsulated_key`.
//! - **KDF**: `HKDF`-`SHA256` over that shared secret. The info string binds a
//!   fixed domain-separation label **and both public keys**
//!   (`label || ephemeral_pub || recipient_pub`), so a derived key can never be
//!   reused across a different sender/recipient pairing (identity misbinding).
//!   The 32-byte output is the AEAD key.
//! - **AEAD**: `ChaCha20`-`Poly1305`, a fresh random 96-bit nonce per seal carried
//!   in the envelope, and the caller-supplied `aad` as associated data.
//! - **Zeroize**: the materialized recipient private, the ephemeral private, the
//!   `ECDH` shared secret, and the derived AEAD key are all wrapped so every secret
//!   byte is wiped on drop, on the success **and** error paths.
//!
//! The recipient never needs the private to *receive*: [`open`] is what runs after
//! the broker materializes the private from KV; [`seal`] needs only the recipient
//! **public** and is used by `wrap_envelope` and the round-trip tests.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
#[cfg_attr(not(doc), allow(unused_imports))]
use x25519_dalek::SharedSecret;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Length of an X25519 public key / `encapsulated_key` (bytes).
pub const PUBLIC_KEY_LEN: usize = 32;
/// Length of an X25519 private key (bytes).
pub const PRIVATE_KEY_LEN: usize = 32;
/// Length of the `ChaCha20`-`Poly1305` nonce (bytes).
pub const NONCE_LEN: usize = 12;
/// Length of the derived AEAD key (bytes).
const AEAD_KEY_LEN: usize = 32;

/// Domain-separation label bound into the `HKDF` info (versioned: a construction
/// change bumps this so old and new derivations never collide).
const HKDF_LABEL: &[u8] = b"basil-x25519-seal-v1";

/// A sealed envelope: the public output of [`seal`], the input of [`open`].
///
/// Every field is attacker-visible ciphertext/public material, there is no secret
/// byte here. It maps directly onto the wire `KemEnvelope`: `encapsulated_key` is
/// the ephemeral X25519 public key, `nonce` is the AEAD nonce, and `ciphertext`
/// carries the `Poly1305` tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedEnvelope {
    /// The sender's ephemeral X25519 public key (32 bytes).
    pub encapsulated_key: [u8; PUBLIC_KEY_LEN],
    /// The AEAD nonce (12 bytes), random per seal.
    pub nonce: [u8; NONCE_LEN],
    /// The AEAD ciphertext including the authentication tag.
    pub ciphertext: Vec<u8>,
}

/// Why a seal/open operation failed.
///
/// Deliberately coarse on the open path: a failed AEAD authentication is a single
/// opaque [`SealError::OpenFailed`] with no detail distinguishing a wrong key, a
/// tampered ciphertext/nonce, or a bad `aad` (no padding/identity oracle).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SealError {
    /// A key or `encapsulated_key` byte slice was not exactly 32 bytes.
    #[error("invalid key length: expected {expected} bytes, got {actual}")]
    BadKeyLength {
        /// The required length.
        expected: usize,
        /// The length actually supplied.
        actual: usize,
    },

    /// The nonce was not exactly [`NONCE_LEN`] bytes.
    #[error("invalid nonce length: expected {expected} bytes, got {actual}")]
    BadNonceLength {
        /// The required length.
        expected: usize,
        /// The length actually supplied.
        actual: usize,
    },

    /// `HKDF` expansion failed (only on an out-of-range output length, never for
    /// our fixed 32-byte key; kept so the construction can't `unwrap`).
    #[error("key derivation failed")]
    KdfFailed,

    /// AEAD sealing failed (should not happen for in-range inputs).
    #[error("seal failed")]
    SealFailed,

    /// AEAD authentication failed on open: wrong key, tampered envelope, or a
    /// mismatched `aad`. Opaque on purpose: it carries no oracle.
    #[error("open failed")]
    OpenFailed,
}

/// Convert an arbitrary-length byte slice into a fixed 32-byte key, failing closed
/// (never indexing/`unwrap`-ing) on a wrong length.
fn array32(bytes: &[u8]) -> Result<[u8; PUBLIC_KEY_LEN], SealError> {
    bytes.try_into().map_err(|_| SealError::BadKeyLength {
        expected: PUBLIC_KEY_LEN,
        actual: bytes.len(),
    })
}

/// Derive the recipient's X25519 **public** key from a materialized private.
///
/// The public half is derived from the private and only the public bytes are
/// returned; the private is never serialized. As of basil-o86 the broker no
/// longer calls this on the per-op `wrap`/`get_public_key` paths (they read the
/// out-of-band public via [`public_from_slice`] without materializing the
/// private): it is the canonical seed→public derivation used to **provision**
/// that out-of-band public and to anchor the round-trip tests.
#[must_use]
pub fn public_from_private(private: &Zeroizing<[u8; PRIVATE_KEY_LEN]>) -> [u8; PUBLIC_KEY_LEN] {
    let secret = StaticSecret::from(**private);
    PublicKey::from(&secret).to_bytes()
}

/// Derive the AEAD key from the `ECDH` shared secret, binding both public keys into
/// the `HKDF` info for domain separation + identity binding.
fn derive_aead_key(
    shared: &Zeroizing<[u8; 32]>,
    ephemeral_pub: &[u8; PUBLIC_KEY_LEN],
    recipient_pub: &[u8; PUBLIC_KEY_LEN],
) -> Result<Zeroizing<[u8; AEAD_KEY_LEN]>, SealError> {
    // info = label || ephemeral_pub || recipient_pub
    let mut info = Vec::with_capacity(HKDF_LABEL.len() + 2 * PUBLIC_KEY_LEN);
    info.extend_from_slice(HKDF_LABEL);
    info.extend_from_slice(ephemeral_pub);
    info.extend_from_slice(recipient_pub);

    let hk = Hkdf::<Sha256>::new(None, shared.as_slice());
    let mut okm = Zeroizing::new([0u8; AEAD_KEY_LEN]);
    hk.expand(&info, okm.as_mut_slice())
        .map_err(|_| SealError::KdfFailed)?;
    Ok(okm)
}

/// Build the AEAD cipher from a derived key, failing closed on the (statically
/// impossible) wrong-length case rather than panicking.
fn cipher_from_key(key: &Zeroizing<[u8; AEAD_KEY_LEN]>) -> Result<ChaCha20Poly1305, SealError> {
    ChaCha20Poly1305::new_from_slice(key.as_slice()).map_err(|_| SealError::SealFailed)
}

/// Seal `plaintext` to `recipient_pub` (an X25519 sealed box), binding `aad`.
///
/// Generates a fresh ephemeral keypair, does the `ECDH`, derives the AEAD key, and
/// AEAD-encrypts under a random nonce. All private intermediates (ephemeral private,
/// shared secret, derived key) are zeroized on drop. Sealing needs **only** the
/// recipient public key. There is no private-key custody here.
///
/// # Errors
///
/// [`SealError::BadKeyLength`] is impossible here (the input is a fixed array);
/// [`SealError::KdfFailed`]/[`SealError::SealFailed`] only on a crypto-internal
/// failure that should not occur for in-range inputs.
pub fn seal(
    recipient_pub: &[u8; PUBLIC_KEY_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<SealedEnvelope, SealError> {
    // Ephemeral keypair (the private is zeroized on drop via StaticSecret's
    // ZeroizeOnDrop under the `zeroize` feature). We build it from random bytes
    // we own so the ephemeral private is never observable.
    let mut eph_bytes = Zeroizing::new([0u8; PRIVATE_KEY_LEN]);
    rand::thread_rng().fill_bytes(eph_bytes.as_mut_slice());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    seal_with_parts(recipient_pub, plaintext, aad, &eph_bytes, nonce_bytes)
}

/// Seal with caller-supplied ephemeral private material and nonce.
///
/// This supports deterministic fixtures and protocols whose associated data
/// must bind the KEM output/nonce. Production callers should normally use
/// [`seal`], which generates both values randomly.
///
/// # Errors
///
/// [`SealError::KdfFailed`]/[`SealError::SealFailed`] on a crypto-internal
/// failure or non-contributory key agreement.
pub fn seal_with_parts(
    recipient_pub: &[u8; PUBLIC_KEY_LEN],
    plaintext: &[u8],
    aad: &[u8],
    ephemeral_private: &Zeroizing<[u8; PRIVATE_KEY_LEN]>,
    nonce_bytes: [u8; NONCE_LEN],
) -> Result<SealedEnvelope, SealError> {
    let ephemeral_secret = StaticSecret::from(**ephemeral_private);
    let ephemeral_pub = PublicKey::from(&ephemeral_secret).to_bytes();

    let recipient = PublicKey::from(*recipient_pub);
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient);
    // Reject a low-order / all-zero shared secret: x25519-dalek does not refuse
    // small-order points, so a degenerate `recipient_pub` would force a known
    // (all-zero) shared secret -> a known AEAD key. Fail closed BEFORE deriving.
    if !shared_secret.was_contributory() {
        return Err(SealError::SealFailed);
    }
    let shared = Zeroizing::new(shared_secret.to_bytes());

    let aead_key = derive_aead_key(&shared, &ephemeral_pub, recipient_pub)?;
    let cipher = cipher_from_key(&aead_key)?;

    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| SealError::SealFailed)?;

    Ok(SealedEnvelope {
        encapsulated_key: ephemeral_pub,
        nonce: nonce_bytes,
        ciphertext,
    })
}

/// Open a [`SealedEnvelope`] with the recipient's **materialized** X25519 private,
/// binding `aad`, returning the recovered plaintext in a zeroizing buffer.
///
/// This is the broker's unseal path: the private is materialized from KV by the
/// caller, handed here, used for exactly one `ECDH`, then dropped (zeroized). The
/// shared secret and derived key are likewise zeroized on every path. A wrong key,
/// a tampered ciphertext/nonce, or a mismatched `aad` all fail with the single
/// opaque [`SealError::OpenFailed`].
///
/// **Confidentiality only, NOT sender authentication.** An X25519 sealed box is
/// *anonymous*: anyone holding the recipient public can seal a valid envelope, and
/// a successful `open` proves only that the envelope was sealed to this recipient
/// (plus integrity of the ciphertext). It does **not** prove who the sender was.
/// Callers MUST NOT treat a successful unseal as proof of sender identity. (A
/// low-order `encapsulated_key` is rejected via [`SharedSecret::was_contributory`],
/// closing the known-key forgery, but that is still not authentication.)
///
/// # Errors
///
/// [`SealError::OpenFailed`] on any authentication failure (no oracle);
/// [`SealError::KdfFailed`]/[`SealError::SealFailed`] only on a crypto-internal
/// failure that should not occur for in-range inputs.
pub fn open(
    recipient_priv: &Zeroizing<[u8; PRIVATE_KEY_LEN]>,
    env: &SealedEnvelope,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SealError> {
    let recipient_secret = StaticSecret::from(**recipient_priv);
    let recipient_pub = PublicKey::from(&recipient_secret).to_bytes();

    let ephemeral_pub = PublicKey::from(env.encapsulated_key);
    let shared_secret = recipient_secret.diffie_hellman(&ephemeral_pub);
    // Reject a low-order / all-zero shared secret: an attacker-supplied small-order
    // `encapsulated_key` would force a known (all-zero) shared secret -> a known
    // AEAD key -> a forgeable envelope this would otherwise ACCEPT. Fail closed
    // BEFORE deriving the key. (Sealed box is anonymous; this is not sender auth.)
    if !shared_secret.was_contributory() {
        return Err(SealError::OpenFailed);
    }
    let shared = Zeroizing::new(shared_secret.to_bytes());

    let aead_key = derive_aead_key(&shared, &env.encapsulated_key, &recipient_pub)?;
    let cipher = cipher_from_key(&aead_key)?;

    let nonce = Nonce::from(env.nonce);
    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &env.ciphertext,
                aad,
            },
        )
        .map_err(|_| SealError::OpenFailed)?;

    Ok(Zeroizing::new(plaintext))
}

/// Wrap a raw 32-byte private key slice into the zeroizing fixed array the
/// open/derive path expects, failing closed (never indexing) on a wrong length.
///
/// Used by the manager when it materializes the private key bytes out of KV.
///
/// # Errors
///
/// [`SealError::BadKeyLength`] if `bytes` is not exactly [`PRIVATE_KEY_LEN`].
pub fn private_from_slice(bytes: &[u8]) -> Result<Zeroizing<[u8; PRIVATE_KEY_LEN]>, SealError> {
    Ok(Zeroizing::new(array32(bytes)?))
}

/// Validate a raw 32-byte **public** key slice into a fixed array, failing closed
/// (never indexing) on a wrong length.
///
/// Used by the manager when it reads the recipient public, provisioned out of
/// band (basil-o86), from KV for `wrap`/`get_public_key`, so the private is
/// **never** materialized for those public ops. The public carries no secret, so
/// the array is a plain `[u8; 32]` (not `Zeroizing`).
///
/// # Errors
///
/// [`SealError::BadKeyLength`] if `bytes` is not exactly [`PUBLIC_KEY_LEN`].
pub fn public_from_slice(bytes: &[u8]) -> Result<[u8; PUBLIC_KEY_LEN], SealError> {
    array32(bytes)
}

/// Reconstruct a [`SealedEnvelope`] from the wire `KemEnvelope` byte fields,
/// validating the fixed-length fields (never indexing into attacker bytes).
///
/// # Errors
///
/// [`SealError::BadKeyLength`] / [`SealError::BadNonceLength`] if the
/// `encapsulated_key` or `nonce` are the wrong length.
pub fn envelope_from_parts(
    encapsulated_key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<SealedEnvelope, SealError> {
    let encapsulated_key = array32(encapsulated_key)?;
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| SealError::BadNonceLength {
        expected: NONCE_LEN,
        actual: nonce.len(),
    })?;
    Ok(SealedEnvelope {
        encapsulated_key,
        nonce,
        ciphertext: ciphertext.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic recipient keypair for the tests (NOT a real key, the seed
    /// is fixed so the round-trip is reproducible).
    fn recipient_keypair() -> (Zeroizing<[u8; 32]>, [u8; 32]) {
        let priv_bytes = Zeroizing::new([7u8; 32]);
        let public = public_from_private(&priv_bytes);
        (priv_bytes, public)
    }

    #[test]
    fn seal_open_round_trips() {
        let (priv_bytes, public) = recipient_keypair();
        let plaintext = b"enrollment-secret-payload";
        let aad = b"enrollment-context";

        let env = seal(&public, plaintext, aad).expect("seal");
        let recovered = open(&priv_bytes, &env, aad).expect("open");
        assert_eq!(recovered.as_slice(), plaintext);
    }

    #[test]
    fn round_trips_with_empty_aad_and_empty_plaintext() {
        let (priv_bytes, public) = recipient_keypair();
        let env = seal(&public, b"", b"").expect("seal");
        let recovered = open(&priv_bytes, &env, b"").expect("open");
        assert!(recovered.is_empty());
    }

    #[test]
    fn each_seal_uses_a_fresh_ephemeral_key_and_nonce() {
        let (_priv, public) = recipient_keypair();
        let a = seal(&public, b"same", b"").expect("seal a");
        let b = seal(&public, b"same", b"").expect("seal b");
        // Fresh ephemeral keypair + fresh nonce per call => different envelopes.
        assert_ne!(a.encapsulated_key, b.encapsulated_key);
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn tampered_ciphertext_fails_to_open() {
        let (priv_bytes, public) = recipient_keypair();
        let mut env = seal(&public, b"payload", b"aad").expect("seal");
        // Flip a ciphertext byte: AEAD authentication must reject it.
        if let Some(byte) = env.ciphertext.first_mut() {
            *byte ^= 0xFF;
        }
        assert_eq!(open(&priv_bytes, &env, b"aad"), Err(SealError::OpenFailed));
    }

    #[test]
    fn tampered_nonce_fails_to_open() {
        let (priv_bytes, public) = recipient_keypair();
        let mut env = seal(&public, b"payload", b"aad").expect("seal");
        env.nonce[0] ^= 0xFF;
        assert_eq!(open(&priv_bytes, &env, b"aad"), Err(SealError::OpenFailed));
    }

    #[test]
    fn tampered_encapsulated_key_fails_to_open() {
        let (priv_bytes, public) = recipient_keypair();
        let mut env = seal(&public, b"payload", b"aad").expect("seal");
        env.encapsulated_key[0] ^= 0xFF;
        assert_eq!(open(&priv_bytes, &env, b"aad"), Err(SealError::OpenFailed));
    }

    #[test]
    fn wrong_aad_fails_to_open() {
        let (priv_bytes, public) = recipient_keypair();
        let env = seal(&public, b"payload", b"right-aad").expect("seal");
        assert_eq!(
            open(&priv_bytes, &env, b"wrong-aad"),
            Err(SealError::OpenFailed)
        );
    }

    #[test]
    fn wrong_recipient_key_fails_to_open() {
        let (_priv, public) = recipient_keypair();
        let env = seal(&public, b"payload", b"aad").expect("seal");
        // A different private key derives a different shared secret => auth fails.
        let other_priv = Zeroizing::new([42u8; 32]);
        assert_eq!(open(&other_priv, &env, b"aad"), Err(SealError::OpenFailed));
    }

    #[test]
    fn low_order_encapsulated_key_is_rejected_on_open() {
        // An all-zero `encapsulated_key` is the canonical low-order point: the
        // ECDH shared secret is non-contributory (all-zero), which forces a known
        // AEAD key. `open` must reject it via the was_contributory check BEFORE the
        // AEAD step, returning the opaque OpenFailed (no known-key forgery accepted).
        let (priv_bytes, _public) = recipient_keypair();
        let env = SealedEnvelope {
            encapsulated_key: [0u8; 32],
            nonce: [0u8; 12],
            // Ciphertext is irrelevant: the contributory check fires before AEAD.
            ciphertext: vec![0u8; 16],
        };
        assert_eq!(open(&priv_bytes, &env, b"aad"), Err(SealError::OpenFailed));
    }

    #[test]
    fn public_from_private_is_deterministic() {
        let priv_bytes = Zeroizing::new([3u8; 32]);
        assert_eq!(
            public_from_private(&priv_bytes),
            public_from_private(&priv_bytes)
        );
    }

    #[test]
    fn private_from_slice_rejects_wrong_length() {
        assert!(private_from_slice(&[0u8; 31]).is_err());
        assert!(private_from_slice(&[0u8; 33]).is_err());
        assert!(private_from_slice(&[0u8; 32]).is_ok());
    }

    #[test]
    fn public_from_slice_validates_length_and_round_trips() {
        // The out-of-band public read (basil-o86) validates the stored bytes into a
        // fixed array, failing closed on a wrong length and never indexing.
        assert!(matches!(
            public_from_slice(&[0u8; 31]),
            Err(SealError::BadKeyLength { .. })
        ));
        assert!(matches!(
            public_from_slice(&[0u8; 33]),
            Err(SealError::BadKeyLength { .. })
        ));
        // A valid 32-byte public seals exactly like the in-array public it mirrors.
        let (priv_bytes, public) = recipient_keypair();
        let from_slice = public_from_slice(&public).expect("32-byte public");
        assert_eq!(from_slice, public);
        let env = seal(&from_slice, b"payload", b"ctx").expect("seal to slice-public");
        assert_eq!(
            open(&priv_bytes, &env, b"ctx").expect("open").as_slice(),
            b"payload"
        );
    }

    #[test]
    fn envelope_from_parts_validates_lengths() {
        let ek = [1u8; 32];
        let nonce = [2u8; 12];
        assert!(envelope_from_parts(&ek, &nonce, b"ct").is_ok());
        // Wrong encapsulated-key length.
        assert!(matches!(
            envelope_from_parts(&[1u8; 31], &nonce, b"ct"),
            Err(SealError::BadKeyLength { .. })
        ));
        // Wrong nonce length.
        assert!(matches!(
            envelope_from_parts(&ek, &[2u8; 11], b"ct"),
            Err(SealError::BadNonceLength { .. })
        ));
    }

    #[test]
    fn envelope_round_trips_through_wire_parts() {
        let (priv_bytes, public) = recipient_keypair();
        let env = seal(&public, b"wire-payload", b"wire-aad").expect("seal");
        // Serialize to wire-shaped parts and back.
        let rebuilt = envelope_from_parts(&env.encapsulated_key, &env.nonce, &env.ciphertext)
            .expect("rebuild");
        assert_eq!(rebuilt, env);
        let recovered = open(&priv_bytes, &rebuilt, b"wire-aad").expect("open");
        assert_eq!(recovered.as_slice(), b"wire-payload");
    }
}
