//! Unlock-method abstraction (§3 of `designs/unlock-and-bundle.html`).
//!
//! One [`UnlockMethod`] = the logic behind one slot kind. A method turns its
//! non-secret [`MethodParams`](super::format::MethodParams) plus an out-of-band
//! secret (`YubiKey` touch / BIP39 phrase / passphrase file) into the ability to unwrap
//! *this slot's* `KekWrap`, recovering the 32-byte master KEK. Every fallible
//! step returns a `Result`; there is no `unwrap`/`expect`/panicking index on any
//! path (§1.3).

use super::{MasterKek, format};

#[cfg(feature = "unlock-age-yubikey")]
pub mod age_yubikey;
#[cfg(feature = "unlock-bip39")]
pub mod bip39;
mod kdf;
pub mod passphrase;
pub mod tpm;

/// Errors any unlock method may return (§3).
#[derive(Debug, thiserror::Error)]
pub enum UnlockError {
    /// Method not usable right now on this host (no token, no key file, …).
    #[error("method unavailable: {0}")]
    Unavailable(String),

    /// Wrong PIN / phrase / passphrase: authentication of the wrap failed.
    #[error("authentication failed")]
    AuthFailed,

    /// Reserved method (e.g. TPM) not yet implemented. Fails closed.
    #[error("method not implemented: {0}")]
    NotImplemented(format::MethodKind),

    /// The slot params did not match the method (malformed bundle).
    #[error("slot params mismatch: {0}")]
    ParamsMismatch(String),

    /// A crypto/KDF failure.
    #[error("crypto: {0}")]
    Crypto(String),

    /// An I/O failure (reading a key file, invoking a plugin).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// One unlock method = the logic behind one slot kind (§3).
///
/// Implementations are stateless w.r.t. the master KEK; they only know how to
/// turn their `params` + an out-of-band secret into the ability to unwrap this
/// slot's `KekWrap`, or to build a fresh wrap over a given KEK.
pub trait UnlockMethod: Send + Sync {
    /// Which slot kind this method handles.
    fn kind(&self) -> format::MethodKind;

    /// Is this method usable right now on this host? (token present, key file
    /// readable, phrase source available). Used to order attempts and report
    /// status.
    fn available(&self) -> bool;

    /// Recover the master KEK from one slot, performing whatever interaction the
    /// method needs. Returns the unwrapped KEK or an [`UnlockError`] (no panic).
    ///
    /// # Errors
    /// Any unlock failure (auth, unavailable, crypto, …), failing closed.
    fn recover_kek(&self, slot: &format::Slot, header_aad: &[u8])
    -> Result<MasterKek, UnlockError>;

    /// Build a fresh `(params, wrap)` for this method over an existing master
    /// KEK (used by `init` / add-slot / re-seal). `slot_id` is the id the new
    /// slot will carry; it is bound into the KEK-wrap AAD (`header || slot_id`,
    /// §2.4) so `recover_kek` for the same slot reproduces the AAD exactly.
    ///
    /// # Errors
    /// Any wrap failure (unavailable method, crypto): fail closed.
    fn wrap_kek(
        &self,
        kek: &MasterKek,
        header_aad: &[u8],
        slot_id: u32,
    ) -> Result<(format::MethodParams, format::KekWrap), UnlockError>;
}
