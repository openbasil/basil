//! BIP39 break-glass unlock slot (§3.1, feature `unlock-bip39`).
//!
//! `recover_kek`: the operator supplies the 24-word phrase on a controlled input
//! (tty / `AskPassword` / agent socket, never argv/env). We validate the BIP39
//! checksum, derive the entropy, run `Argon2id(entropy, salt, params)` to a
//! 32-byte slot key, then AES-256-GCM-unwrap the master KEK.
//!
//! `wrap_kek`: draw a fresh salt, derive the slot key from the phrase, and
//! AES-256-GCM-wrap the given master KEK under it.

use bip39::Mnemonic;
use rand::RngCore;
use zeroize::Zeroizing;

use super::super::MasterKek;
use super::super::aead::{self, NONCE_LEN};
use super::super::format::{Argon2Params, B64Bytes, KekWrap, MethodKind, MethodParams, Slot};
use super::kdf::{derive_slot_key, wrap_aad};
use super::{UnlockError, UnlockMethod};

/// 24-word phrases carry 32 bytes (256 bits) of entropy.
const BIP39_WORD_COUNT: usize = 24;
/// KDF salt length (§2.4).
const SALT_LEN: usize = 16;

/// A BIP39 unlock method holding the operator-supplied recovery phrase.
///
/// The phrase is held in a [`Zeroizing`] string and wiped on drop.
pub struct Bip39Method {
    phrase: Zeroizing<String>,
    argon2: Argon2Params,
}

impl Bip39Method {
    /// Build from an operator-supplied phrase, using the production Argon2id
    /// profile (mem = 64 MiB, t = 3, p = 1).
    #[must_use]
    pub const fn new(phrase: Zeroizing<String>) -> Self {
        Self {
            phrase,
            argon2: Argon2Params::PRODUCTION,
        }
    }

    /// Build with explicit Argon2id params (tests use a small profile for speed).
    #[must_use]
    pub const fn with_params(phrase: Zeroizing<String>, argon2: Argon2Params) -> Self {
        Self { phrase, argon2 }
    }

    /// Generate a fresh 24-word phrase for `init` (displayed once, never stored).
    ///
    /// # Errors
    /// Returns [`UnlockError::Crypto`] if entropy generation fails.
    pub fn generate_phrase() -> Result<Zeroizing<String>, UnlockError> {
        let mut entropy = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(entropy.as_mut());
        let mnemonic = Mnemonic::from_entropy(entropy.as_ref())
            .map_err(|e| UnlockError::Crypto(format!("bip39 generate: {e}")))?;
        Ok(Zeroizing::new(mnemonic.to_string()))
    }

    /// Validate the phrase and derive its 256-bit entropy.
    fn entropy(&self) -> Result<Zeroizing<Vec<u8>>, UnlockError> {
        let mnemonic =
            Mnemonic::parse(self.phrase.as_str()).map_err(|_| UnlockError::AuthFailed)?;
        if mnemonic.word_count() != BIP39_WORD_COUNT {
            return Err(UnlockError::AuthFailed);
        }
        Ok(Zeroizing::new(mnemonic.to_entropy()))
    }
}

impl UnlockMethod for Bip39Method {
    fn kind(&self) -> MethodKind {
        MethodKind::Bip39
    }

    fn available(&self) -> bool {
        // The phrase was supplied at construction; the slot is openable.
        !self.phrase.is_empty()
    }

    fn recover_kek(&self, slot: &Slot, header_aad: &[u8]) -> Result<MasterKek, UnlockError> {
        let MethodParams::Bip39 { salt, argon2 } = &slot.params else {
            return Err(UnlockError::ParamsMismatch("expected bip39 params".into()));
        };
        let entropy = self.entropy()?;
        let slot_key = derive_slot_key(&entropy, &salt.0, *argon2)?;

        let nonce: [u8; NONCE_LEN] = slot
            .wrap
            .nonce
            .0
            .as_slice()
            .try_into()
            .map_err(|_| UnlockError::ParamsMismatch("bad wrap nonce length".into()))?;
        let aad = wrap_aad(header_aad, slot.slot_id);
        let kek_bytes = aead::open(&slot_key, &nonce, &aad, &slot.wrap.ciphertext.0)
            .map_err(|_| UnlockError::AuthFailed)?;
        MasterKek::from_slice(&kek_bytes)
            .ok_or_else(|| UnlockError::Crypto("unwrapped KEK has wrong length".into()))
    }

    fn wrap_kek(
        &self,
        kek: &MasterKek,
        header_aad: &[u8],
        slot_id: u32,
    ) -> Result<(MethodParams, KekWrap), UnlockError> {
        let mut salt = [0u8; SALT_LEN];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let entropy = self.entropy()?;
        let slot_key = derive_slot_key(&entropy, &salt, self.argon2)?;

        let nonce = aead::fresh_nonce();
        let aad = wrap_aad(header_aad, slot_id);
        let ciphertext = aead::seal(&slot_key, &nonce, &aad, kek.as_bytes())
            .map_err(|e| UnlockError::Crypto(e.to_string()))?;

        let params = MethodParams::Bip39 {
            salt: B64Bytes(salt.to_vec()),
            argon2: self.argon2,
        };
        let wrap = KekWrap {
            nonce: B64Bytes(nonce.to_vec()),
            ciphertext: B64Bytes(ciphertext),
        };
        Ok((params, wrap))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::format::Header;

    /// Tiny Argon2id profile so tests run fast (production uses 64 MiB/t=3/p=1).
    /// NOTE: TEST ONLY. Never used outside `#[cfg(test)]`.
    const FAST: Argon2Params = Argon2Params {
        m_cost_kib: 256,
        t_cost: 1,
        p_cost: 1,
    };

    fn header() -> Header {
        Header {
            format_version: 1,
            suite: crate::seal::format::Suite::v1(),
            bundle_id: [1u8; 16],
            created_unix: 0,
            epoch: 1,
        }
    }

    #[test]
    fn phrase_to_kek_round_trip() {
        let phrase = Bip39Method::generate_phrase().unwrap();
        let method = Bip39Method::with_params(phrase, FAST);
        let kek = MasterKek::generate();
        let aad = header().to_aad_bytes().unwrap();

        let (params, wrap) = method.wrap_kek(&kek, &aad, 0).unwrap();
        // Build a slot with slot_id 0 (matches the wrap AAD).
        let slot = Slot {
            slot_id: 0,
            method: MethodKind::Bip39,
            label: "break-glass".into(),
            created_unix: 0,
            params,
            wrap,
        };
        let recovered = method.recover_kek(&slot, &aad).unwrap();
        assert_eq!(recovered.as_bytes(), kek.as_bytes());
    }

    #[test]
    fn wrong_phrase_fails_closed() {
        let good = Bip39Method::generate_phrase().unwrap();
        let method = Bip39Method::with_params(good, FAST);
        let kek = MasterKek::generate();
        let aad = header().to_aad_bytes().unwrap();
        let (params, wrap) = method.wrap_kek(&kek, &aad, 0).unwrap();
        let slot = Slot {
            slot_id: 0,
            method: MethodKind::Bip39,
            label: "x".into(),
            created_unix: 0,
            params,
            wrap,
        };
        // A *different* valid phrase derives a different slot key -> auth fails.
        let other = Bip39Method::generate_phrase().unwrap();
        let other_method = Bip39Method::with_params(other, FAST);
        assert!(matches!(
            other_method.recover_kek(&slot, &aad),
            Err(UnlockError::AuthFailed)
        ));
    }

    #[test]
    fn malformed_phrase_is_auth_failed() {
        let method = Bip39Method::with_params(Zeroizing::new("not a valid phrase".into()), FAST);
        assert!(method.entropy().is_err());
    }
}
