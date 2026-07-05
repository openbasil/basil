//! Local hardware-or-software signing identity (kept TPM/HSM scaffolding).
//!
//! Adapted from `brightnexus-platform`'s `tpm2.rs` / `factory.rs`. It detects a
//! system TPM and provides a P-256 ECDSA identity, persisted as a `0600` key
//! file when no hardware path is wired up: the software fallback.
//!
//! This is **not** used by the Vault signing path in v1. It is kept as the
//! seed for a future "internal" signing backend (the db-keystore-backed signer
//! mentioned in the design), gated behind the `tpm2` feature so the dependency
//! footprint stays optional.

use std::fs;
use std::path::Path;
use std::sync::Mutex;

use p256::SecretKey;
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("bad key material: {0}")]
    Key(String),
}

/// Whether a system TPM is present (resource-manager or raw device node).
///
/// Re-export of the ungated [`crate::core::tpm_device_present`] probe, kept under
/// this name so existing `tpm2`-feature callers are unaffected.
pub use crate::core::tpm_device_present as tpm_available;

/// A P-256 ECDSA identity, optionally TPM-backed.
pub struct LocalIdentity {
    signing_key: SigningKey,
    public_key: [u8; 65],
    key_id: String,
    sign_lock: Mutex<()>,
}

impl LocalIdentity {
    /// Load the identity stored at `key_path`, generating a fresh P-256 key
    /// (written with `0600` perms) if the file does not yet exist.
    pub fn open_or_create(key_path: &Path) -> Result<Self, IdentityError> {
        let signing = if key_path.exists() {
            let bytes = fs::read(key_path)?;
            let arr: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| IdentityError::Key("unexpected key file length".into()))?;
            let secret = SecretKey::from_bytes(&arr.into())
                .map_err(|e| IdentityError::Key(e.to_string()))?;
            SigningKey::from(secret)
        } else {
            let secret = SecretKey::random(&mut rand::thread_rng());
            let signing = SigningKey::from(secret.clone());
            fs::write(key_path, secret.to_bytes())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(key_path, fs::Permissions::from_mode(0o600))?;
            }
            signing
        };

        let verifying = signing.verifying_key();
        let encoded = verifying.to_encoded_point(false);
        let mut public_key = [0u8; 65];
        public_key.copy_from_slice(encoded.as_bytes());
        let key_id = hex::encode(Sha256::digest(public_key));

        Ok(Self {
            signing_key: signing,
            public_key,
            key_id,
            sign_lock: Mutex::new(()),
        })
    }

    /// Stable id for this key (hex SHA-256 of the public point).
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The uncompressed 65-byte SEC1 public point.
    #[must_use]
    pub const fn public_key(&self) -> [u8; 65] {
        self.public_key
    }

    /// Whether this identity is running on a host with a TPM available.
    pub fn backed_by_tpm(&self) -> bool {
        tpm_available()
    }

    /// Produce a DER-encoded ECDSA (P-256/SHA-256) signature over `data`.
    ///
    /// The signing lock only serializes access; the key it guards is immutable,
    /// so a poisoned lock carries no corrupt state; we recover the guard and
    /// proceed rather than panic (this broker must never panic at runtime).
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let _g = self
            .sign_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let sig: Signature = self.signing_key.sign(data);
        sig.to_der().as_bytes().to_vec()
    }
}
