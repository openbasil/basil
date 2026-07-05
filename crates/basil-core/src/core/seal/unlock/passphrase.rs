//! Production passphrase unlock slot.
//!
//! The passphrase is read by the caller from a file into a zeroizing buffer,
//! KDF'd with Argon2id, and used to AES-256-GCM-unwrap the master KEK.

use rand::RngCore;
use zeroize::Zeroizing;

use super::super::MasterKek;
use super::super::aead::{self, NONCE_LEN};
use super::super::format::{Argon2Params, B64Bytes, KekWrap, MethodKind, MethodParams, Slot};
use super::kdf::{derive_slot_key, wrap_aad};
use super::{UnlockError, UnlockMethod};

/// KDF salt length.
const SALT_LEN: usize = 16;

/// A passphrase unlock method backed by a file-sourced passphrase.
pub struct PassphraseMethod {
    passphrase: Zeroizing<Vec<u8>>,
    argon2: Argon2Params,
}

impl PassphraseMethod {
    /// Build from a passphrase using the production Argon2id profile.
    #[must_use]
    pub const fn new(passphrase: Zeroizing<Vec<u8>>) -> Self {
        Self {
            passphrase,
            argon2: Argon2Params::PRODUCTION,
        }
    }

    /// Build with explicit Argon2id params (tests use a small profile).
    #[must_use]
    pub const fn with_params(passphrase: Zeroizing<Vec<u8>>, argon2: Argon2Params) -> Self {
        Self { passphrase, argon2 }
    }
}

impl UnlockMethod for PassphraseMethod {
    fn kind(&self) -> MethodKind {
        MethodKind::Passphrase
    }

    fn available(&self) -> bool {
        !self.passphrase.is_empty()
    }

    fn recover_kek(&self, slot: &Slot, header_aad: &[u8]) -> Result<MasterKek, UnlockError> {
        let MethodParams::Passphrase { salt, argon2 } = &slot.params else {
            return Err(UnlockError::ParamsMismatch(
                "expected passphrase params".into(),
            ));
        };
        let slot_key = derive_slot_key(&self.passphrase, &salt.0, *argon2)?;
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
        let slot_key = derive_slot_key(&self.passphrase, &salt, self.argon2)?;
        let nonce = aead::fresh_nonce();
        let aad = wrap_aad(header_aad, slot_id);
        let ciphertext = aead::seal(&slot_key, &nonce, &aad, kek.as_bytes())
            .map_err(|e| UnlockError::Crypto(e.to_string()))?;
        let params = MethodParams::Passphrase {
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
    use crate::seal::format::{Header, Suite};

    const FAST: Argon2Params = Argon2Params {
        m_cost_kib: 256,
        t_cost: 1,
        p_cost: 1,
    };

    fn aad() -> Vec<u8> {
        Header {
            format_version: 1,
            suite: Suite::v1(),
            bundle_id: [2u8; 16],
            created_unix: 0,
            epoch: 1,
        }
        .to_aad_bytes()
        .unwrap()
    }

    #[test]
    fn passphrase_round_trip() {
        let method = PassphraseMethod::with_params(Zeroizing::new(b"test-pass".to_vec()), FAST);
        let kek = MasterKek::generate();
        let a = aad();
        let (params, wrap) = method.wrap_kek(&kek, &a, 3).unwrap();
        let slot = Slot {
            slot_id: 3,
            method: MethodKind::Passphrase,
            label: "passphrase".into(),
            created_unix: 0,
            params,
            wrap,
        };
        let recovered = method.recover_kek(&slot, &a).unwrap();
        assert_eq!(recovered.as_bytes(), kek.as_bytes());
    }

    #[test]
    fn wrong_passphrase_fails_closed() {
        let method = PassphraseMethod::with_params(Zeroizing::new(b"right".to_vec()), FAST);
        let kek = MasterKek::generate();
        let a = aad();
        let (params, wrap) = method.wrap_kek(&kek, &a, 1).unwrap();
        let slot = Slot {
            slot_id: 1,
            method: MethodKind::Passphrase,
            label: "passphrase".into(),
            created_unix: 0,
            params,
            wrap,
        };
        let wrong = PassphraseMethod::with_params(Zeroizing::new(b"wrong".to_vec()), FAST);
        assert!(matches!(
            wrong.recover_kek(&slot, &a),
            Err(UnlockError::AuthFailed)
        ));
    }
}
