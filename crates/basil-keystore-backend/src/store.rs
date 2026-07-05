// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Unified key/value secret store for Basil's key-store backend.

#[cfg(feature = "db-keystore")]
use std::path::PathBuf;
#[cfg(feature = "db-keystore")]
use std::sync::Arc;

#[cfg(feature = "db-keystore")]
use db_keystore::{DbKeyStore, DbKeyStoreConfig, EncryptionOpts};
#[cfg(feature = "db-keystore")]
use keyring_core::CredentialStore;
#[cfg(feature = "db-keystore")]
use zero_secrets::SecretArray;
use zero_secrets::SecretBytes;
#[cfg(feature = "db-keystore")]
use zeroize::Zeroizing;

#[cfg(feature = "onepassword")]
use crate::onepassword::{OnePasswordConfig, OnePasswordProvider};

#[cfg(feature = "db-keystore")]
const SERVICE: &str = "basil";

/// Store open configuration.
#[derive(Debug, Clone)]
pub enum StoreConfig {
    /// Placeholder used only when the crate is built without concrete backend
    /// features. `basil-agent` rejects that feature combination before use.
    #[cfg(not(any(feature = "db-keystore", feature = "onepassword")))]
    Unavailable,
    /// Encrypted db-keystore database.
    #[cfg(feature = "db-keystore")]
    DbKeystore {
        /// SQLite-compatible database path.
        path: PathBuf,
        /// turso encryption cipher, for example `aegis256`.
        cipher: String,
        /// 32-byte DEK supplied by Basil's sealed bundle.
        dek: SecretArray<32>,
    },
    /// `1Password` provider URI and addressing context.
    #[cfg(feature = "onepassword")]
    OnePassword {
        /// Provider URI, for example `onepassword://vault` or
        /// `onepassword+token://token@vault`.
        provider_uri: String,
        /// Item-title project namespace.
        project: String,
        /// Item-title profile.
        profile: String,
    },
}

/// Secret-store failure. Variants carry only stable discriminators, paths, or
/// redacted backend summaries, never secret values.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The requested key does not exist.
    #[error("key not found: {0}")]
    NotFound(String),
    /// The concrete backend rejected the operation.
    #[error("backend error: {0}")]
    Backend(String),
    /// The backend cannot store non-UTF-8 bytes.
    #[error("backend requires UTF-8 values")]
    NonUtf8Value,
}

enum StoreInner {
    #[cfg(not(any(feature = "db-keystore", feature = "onepassword")))]
    Unavailable,
    #[cfg(feature = "db-keystore")]
    DbKeystore(Arc<CredentialStore>),
    #[cfg(feature = "onepassword")]
    OnePassword {
        provider: OnePasswordProvider,
        project: String,
        profile: String,
    },
}

/// A unified secret store over enabled key-store backends.
pub struct SecretStore {
    inner: StoreInner,
}

impl SecretStore {
    /// Open a store from configuration.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Backend`] if the configured backend cannot be opened.
    #[cfg_attr(
        not(any(feature = "db-keystore", feature = "onepassword")),
        allow(clippy::missing_const_for_fn, clippy::needless_pass_by_value)
    )]
    pub fn open(config: StoreConfig) -> Result<Self, StoreError> {
        match config {
            #[cfg(not(any(feature = "db-keystore", feature = "onepassword")))]
            StoreConfig::Unavailable => Ok(Self {
                inner: StoreInner::Unavailable,
            }),
            #[cfg(feature = "db-keystore")]
            StoreConfig::DbKeystore { path, cipher, dek } => {
                let hexkey = hex_key(dek.expose_secret());
                let store = DbKeyStore::new(DbKeyStoreConfig {
                    path,
                    encryption_opts: Some(EncryptionOpts::new(cipher, hexkey.as_str())),
                    ..Default::default()
                })
                .map_err(|e| StoreError::Backend(keyring_error_summary(&e).to_owned()))?;
                Ok(Self {
                    inner: StoreInner::DbKeystore(store as Arc<CredentialStore>),
                })
            }
            #[cfg(feature = "onepassword")]
            StoreConfig::OnePassword {
                provider_uri,
                project,
                profile,
            } => {
                let config = OnePasswordConfig::from_uri(&provider_uri)?;
                Ok(Self {
                    inner: StoreInner::OnePassword {
                        provider: OnePasswordProvider::new(config),
                        project,
                        profile,
                    },
                })
            }
        }
    }

    /// Fetch a non-secret value. The returned buffer is plain because Basil uses
    /// this path only for public/value reads.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotFound`] when `key` is absent.
    #[cfg_attr(
        not(any(feature = "db-keystore", feature = "onepassword")),
        allow(unused_variables)
    )]
    pub fn get(&self, key: &str) -> Result<Vec<u8>, StoreError> {
        match &self.inner {
            #[cfg(not(any(feature = "db-keystore", feature = "onepassword")))]
            StoreInner::Unavailable => {
                Err(StoreError::Backend("no-keystore-backend-enabled".into()))
            }
            #[cfg(feature = "db-keystore")]
            StoreInner::DbKeystore(store) => {
                let entry = store
                    .build(SERVICE, key, None)
                    .map_err(|e| StoreError::Backend(keyring_error_summary(&e).to_owned()))?;
                match entry.get_secret() {
                    Ok(bytes) => Ok(bytes),
                    Err(keyring_core::Error::NoEntry) => Err(StoreError::NotFound(key.to_owned())),
                    Err(e) => Err(StoreError::Backend(keyring_error_summary(&e).to_owned())),
                }
            }
            #[cfg(feature = "onepassword")]
            StoreInner::OnePassword {
                provider,
                project,
                profile,
            } => provider
                .get(project, key, profile)?
                .map(|bytes| bytes.to_vec())
                .ok_or_else(|| StoreError::NotFound(key.to_owned())),
        }
    }

    /// Fetch a secret value in a zeroizing owner.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotFound`] when `key` is absent.
    #[cfg_attr(
        not(any(feature = "db-keystore", feature = "onepassword")),
        allow(unused_variables)
    )]
    pub fn get_secret(&self, key: &str) -> Result<SecretBytes, StoreError> {
        match &self.inner {
            #[cfg(not(any(feature = "db-keystore", feature = "onepassword")))]
            StoreInner::Unavailable => {
                Err(StoreError::Backend("no-keystore-backend-enabled".into()))
            }
            #[cfg(feature = "db-keystore")]
            StoreInner::DbKeystore(store) => {
                let entry = store
                    .build(SERVICE, key, None)
                    .map_err(|e| StoreError::Backend(keyring_error_summary(&e).to_owned()))?;
                match entry.get_secret() {
                    Ok(bytes) => Ok(SecretBytes::new(bytes)),
                    Err(keyring_core::Error::NoEntry) => Err(StoreError::NotFound(key.to_owned())),
                    Err(e) => Err(StoreError::Backend(keyring_error_summary(&e).to_owned())),
                }
            }
            #[cfg(feature = "onepassword")]
            StoreInner::OnePassword {
                provider,
                project,
                profile,
            } => provider
                .get(project, key, profile)?
                .map(|bytes| SecretBytes::new(bytes.to_vec()))
                .ok_or_else(|| StoreError::NotFound(key.to_owned())),
        }
    }

    /// Store `value` at `key`, overwriting any previous value.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NonUtf8Value`] when a string-oriented provider such
    /// as `1Password` cannot represent the bytes.
    #[cfg_attr(
        not(any(feature = "db-keystore", feature = "onepassword")),
        allow(unused_variables)
    )]
    pub fn put(&self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        match &self.inner {
            #[cfg(not(any(feature = "db-keystore", feature = "onepassword")))]
            StoreInner::Unavailable => {
                Err(StoreError::Backend("no-keystore-backend-enabled".into()))
            }
            #[cfg(feature = "db-keystore")]
            StoreInner::DbKeystore(store) => {
                let entry = store
                    .build(SERVICE, key, None)
                    .map_err(|e| StoreError::Backend(keyring_error_summary(&e).to_owned()))?;
                entry
                    .set_secret(value)
                    .map_err(|e| StoreError::Backend(keyring_error_summary(&e).to_owned()))
            }
            #[cfg(feature = "onepassword")]
            StoreInner::OnePassword {
                provider,
                project,
                profile,
            } => provider.set(project, key, value, profile),
        }
    }
}

#[cfg(feature = "db-keystore")]
fn hex_key(dek: &[u8]) -> Zeroizing<String> {
    let mut out = String::with_capacity(64);
    for b in dek {
        push_hex_nibble(&mut out, b >> 4);
        push_hex_nibble(&mut out, b & 0x0f);
    }
    Zeroizing::new(out)
}

#[cfg(feature = "db-keystore")]
fn push_hex_nibble(out: &mut String, nibble: u8) {
    out.push(char::from(match nibble {
        0 => b'0',
        1 => b'1',
        2 => b'2',
        3 => b'3',
        4 => b'4',
        5 => b'5',
        6 => b'6',
        7 => b'7',
        8 => b'8',
        9 => b'9',
        10 => b'a',
        11 => b'b',
        12 => b'c',
        13 => b'd',
        14 => b'e',
        _ => b'f',
    }));
}

#[cfg(feature = "db-keystore")]
const fn keyring_error_summary(err: &keyring_core::Error) -> &'static str {
    match err {
        keyring_core::Error::NoEntry => "no-entry",
        keyring_core::Error::Ambiguous(_) => "ambiguous",
        keyring_core::Error::BadEncoding(_) => "bad-encoding",
        keyring_core::Error::TooLong(_, _) => "too-long",
        keyring_core::Error::Invalid(_, _) => "invalid",
        keyring_core::Error::NotSupportedByStore(_) => "not-supported",
        keyring_core::Error::NoDefaultStore => "no-default-store",
        keyring_core::Error::BadStoreFormat(_) => "bad-store-format",
        keyring_core::Error::BadDataFormat(_, _) => "bad-data-format",
        keyring_core::Error::PlatformFailure(_) => "platform-failure",
        keyring_core::Error::NoStorageAccess(_) => "no-storage-access",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]

    #[cfg(feature = "db-keystore")]
    #[test]
    fn db_keystore_config_debug_redacts_dek() {
        use zero_secrets::SecretArray;

        let cfg = super::StoreConfig::DbKeystore {
            path: "test.db".into(),
            cipher: "aegis256".to_string(),
            dek: SecretArray::new([0xabu8; 32]),
        };
        let rendered = format!("{cfg:?}");
        assert!(rendered.contains("REDACTED"));
        assert!(!rendered.contains("171"));
        assert!(!rendered.contains("ab"));
    }

    /// A unique, absolute temp path so parallel tests never share a store file.
    #[cfg(feature = "db-keystore")]
    fn unique_temp_path(stem: &str, ext: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "basil-keystore-{stem}-{}-{n}.{ext}",
            std::process::id()
        ))
    }

    /// Functional coverage for the db-keystore materialize-to-use path over a
    /// real encrypted turso store: provision key material through the store,
    /// read it back in a zeroizing owner, and drive local crypto with it.
    #[cfg(feature = "db-keystore")]
    #[test]
    fn db_keystore_materialize_to_use_round_trip() {
        use crate::{decrypt_aead, encrypt_aead, public_ed25519, sign_ed25519, verify_ed25519};
        use basil::proto::AeadAlgorithm;
        use zero_secrets::SecretArray;

        let path = unique_temp_path("db", "db");
        let store = super::SecretStore::open(super::StoreConfig::DbKeystore {
            path: path.clone(),
            cipher: "aegis256".to_string(),
            dek: SecretArray::new([0x11u8; 32]),
        })
        .expect("open encrypted db-keystore store");

        // --- Ed25519 sign: provision a seed, materialize it, sign, verify.
        let seed = [0x42u8; 32];
        store.put("kv2/signing-seed", &seed).expect("store seed");
        let materialized = store
            .get_secret("kv2/signing-seed")
            .expect("materialize seed");
        assert_eq!(materialized.expose_secret(), &seed);
        let message = b"db-keystore materialize-to-sign";
        let signature = sign_ed25519(materialized.expose_secret(), message).unwrap();
        let public = public_ed25519(materialized.expose_secret()).unwrap();
        assert!(verify_ed25519(&public, message, &signature).unwrap());

        // --- AEAD: provision a key, materialize it, encrypt then decrypt.
        let aead_key = [0x7cu8; 32];
        store
            .put("kv2/aead-key", &aead_key)
            .expect("store aead key");
        let key = store.get_secret("kv2/aead-key").expect("materialize key");
        let plaintext = b"db-keystore materialize-to-use aead";
        let mut envelope = encrypt_aead(
            key.expose_secret(),
            AeadAlgorithm::Aes256Gcm,
            plaintext,
            None,
        )
        .unwrap();
        let recovered = decrypt_aead(key.expose_secret(), &envelope, None).unwrap();
        assert_eq!(recovered.as_slice(), plaintext.as_slice());

        // A tampered envelope fails closed.
        envelope.ciphertext[0] ^= 0x01;
        assert!(matches!(
            decrypt_aead(key.expose_secret(), &envelope, None),
            Err(crate::CryptoError::DecryptFailed)
        ));

        // Absent keys surface as NotFound, never a panic.
        assert!(matches!(
            store.get_secret("kv2/absent"),
            Err(super::StoreError::NotFound(_))
        ));

        drop(store);
        let _ = std::fs::remove_file(&path);
    }

    /// The `1Password` provider-config path fails closed on a URI that is not a
    /// `1Password` scheme (no live `op`/vault required: construction parses the
    /// URI before any I/O).
    #[cfg(feature = "onepassword")]
    #[test]
    fn onepassword_provider_config_fail_closed() {
        // `SecretStore` is intentionally not `Debug`, so match rather than
        // `expect_err`.
        match super::SecretStore::open(super::StoreConfig::OnePassword {
            provider_uri: "not-a-real-scheme://host/path".to_string(),
            project: "p".to_string(),
            profile: "default".to_string(),
        }) {
            Err(super::StoreError::Backend(_)) => {}
            Err(other) => panic!("expected a Backend error, got {other:?}"),
            Ok(_) => panic!("a non-onepassword scheme must fail closed"),
        }
    }
}
