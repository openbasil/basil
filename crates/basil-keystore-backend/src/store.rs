// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Unified key/value secret store for Basil's key-store backend.

use std::fmt;
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
#[derive(Clone)]
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

impl fmt::Debug for StoreConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(not(any(feature = "db-keystore", feature = "onepassword")))]
            Self::Unavailable => f.write_str("Unavailable"),
            #[cfg(feature = "db-keystore")]
            Self::DbKeystore { path, cipher, dek } => f
                .debug_struct("DbKeystore")
                .field("path", path)
                .field("cipher", cipher)
                .field("dek", dek)
                .finish(),
            #[cfg(feature = "onepassword")]
            Self::OnePassword {
                provider_uri: _,
                project,
                profile,
            } => f
                .debug_struct("OnePassword")
                .field("provider_uri", &"REDACTED")
                .field("project", project)
                .field("profile", profile)
                .finish(),
        }
    }
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
    /// A keystore rekey owns the store: the open was refused by the rekey
    /// fence (an on-disk intent marker from a crashed rekey, or a live
    /// rekey's exclusive advisory lock — `marker` then names the lock file).
    /// Produced only by the `db-keystore` arm on Linux; the refusal text
    /// names the marker path and the recovery command verbatim.
    #[error(
        "keystore rekey in progress: intent marker `{marker}` is present; run \
         `basil keystore rekey --resume` to complete recovery"
    )]
    RekeyInProgress {
        /// Path (or database-directory-relative name) of the fencing
        /// marker/lock file.
        marker: String,
    },
}

enum StoreInner {
    #[cfg(not(any(feature = "db-keystore", feature = "onepassword")))]
    Unavailable,
    #[cfg(feature = "db-keystore")]
    DbKeystore {
        store: Arc<CredentialStore>,
        /// Shared rekey advisory lock, held for the store's lifetime so an
        /// offline `basil keystore rekey` cannot start while this store is
        /// open (and vice versa). See `crate::rekey`.
        #[cfg(target_os = "linux")]
        _rekey_lock: std::os::fd::OwnedFd,
    },
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
                // Rekey fence + shared advisory lock (Linux): refuse to open
                // while a rekey intent marker exists or a rekey holds the
                // exclusive lock; otherwise hold the lock shared for the
                // store's lifetime. Fail-closed and typed: the fence itself
                // surfaces as [`StoreError::RekeyInProgress`], every other
                // guard failure as [`StoreError::Backend`].
                #[cfg(target_os = "linux")]
                let rekey_lock =
                    crate::rekey::guard_store_open(&path).map_err(store_open_fence_error)?;
                // Own the encoded DEK in zeroizing storage before writing its
                // first byte, then lend it to db-keystore for decoding. The
                // whole database-layer open runs inside `contained_open`:
                // db-keystore 0.5.0 contains panics only in its rekey/verify
                // entry points, and on a database/DEK mismatch turso may
                // panic as well as return an error. An unwind here would
                // crash the broker at startup, so it is converted into a
                // fail-closed [`StoreError::Backend`] instead. Unwinding
                // drops `hexkey` (and the moved `dek`), so the key material
                // is zeroized on the panic path too.
                let store = contained_open(move || {
                    let hexkey = hex_key(dek.expose_secret());
                    let encryption_opts = EncryptionOpts::new(&cipher, hexkey.as_str())
                        .map_err(|e| StoreError::Backend(keyring_error_summary(&e).to_owned()))?;
                    DbKeyStore::new(DbKeyStoreConfig {
                        path,
                        encryption_opts: Some(encryption_opts),
                        ..Default::default()
                    })
                    .map_err(|e| StoreError::Backend(keyring_error_summary(&e).to_owned()))
                })?;
                Ok(Self {
                    inner: StoreInner::DbKeystore {
                        store: store as Arc<CredentialStore>,
                        #[cfg(target_os = "linux")]
                        _rekey_lock: rekey_lock,
                    },
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
            StoreInner::DbKeystore { store, .. } => {
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
            StoreInner::DbKeystore { store, .. } => {
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
            StoreInner::DbKeystore { store, .. } => {
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

/// Map a [`crate::rekey::guard_store_open`] refusal into the store's typed
/// error. The rekey fence keeps its dedicated variant (preserving the
/// refusal-text contract: the marker path and `basil keystore rekey --resume`
/// verbatim); every other guard failure stays a fail-closed
/// [`StoreError::Backend`] with the guard's secret-free rendering.
#[cfg(all(feature = "db-keystore", target_os = "linux"))]
fn store_open_fence_error(err: crate::rekey::KeystoreRekeyError) -> StoreError {
    match err {
        crate::rekey::KeystoreRekeyError::RekeyInProgress { marker } => {
            StoreError::RekeyInProgress { marker }
        }
        other => StoreError::Backend(other.to_string()),
    }
}

/// Stable summary for a contained database-layer panic during store open.
#[cfg(feature = "db-keystore")]
const CONTAINED_PANIC_SUMMARY: &str = "db-keystore-open-panic-contained";

/// Run the db-keystore open path with panic containment, converting an
/// escaped panic into a fail-closed [`StoreError::Backend`].
///
/// db-keystore 0.5.0 wraps its `rekey_at`/`verify_at` entry points in
/// `catch_unwind`, but **not** [`DbKeyStore::new`]; its own qualification
/// wraps wrong-key `new` in `catch_unwind` because turso may panic (rather
/// than error) on a database/DEK mismatch. The broker's no-panic invariant
/// forbids letting that unwind cross this crate, so the runtime adapter
/// carries the same containment here.
///
/// The panic payload is **discarded**, not reported: it originates in
/// whatever database code panicked, so it is untrusted and could embed
/// buffer contents or key encodings, and `StoreError::Backend` renders its
/// summary via `Display`. The error carries only the stable
/// [`CONTAINED_PANIC_SUMMARY`] discriminator (matching this crate's
/// precedent that panic payloads never reach `Display`; see
/// `rekey::AuditPayload`). Containment presumes `panic = "unwind"`; a
/// `panic = "abort"` build aborts before this conversion can run.
#[cfg(feature = "db-keystore")]
fn contained_open<T>(f: impl FnOnce() -> Result<T, StoreError>) -> Result<T, StoreError> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(result) => result,
        Err(payload) => {
            // Drop (and thereby discard) the untrusted payload explicitly.
            drop(payload);
            Err(StoreError::Backend(CONTAINED_PANIC_SUMMARY.to_owned()))
        }
    }
}

#[cfg(feature = "db-keystore")]
fn hex_key(dek: &[u8]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(64));
    for b in dek {
        push_hex_nibble(&mut out, b >> 4);
        push_hex_nibble(&mut out, b & 0x0f);
    }
    out
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

    #[cfg(feature = "db-keystore")]
    #[test]
    fn db_keystore_rejects_invalid_encryption_options_without_exposing_the_dek() {
        use zero_secrets::SecretArray;

        let result = super::SecretStore::open(super::StoreConfig::DbKeystore {
            path: unique_temp_path("invalid-options", "db"),
            cipher: String::new(),
            dek: SecretArray::new([0xabu8; 32]),
        });

        match result {
            Err(super::StoreError::Backend(summary)) => assert_eq!(summary, "invalid"),
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("invalid encryption options must fail"),
        }
    }

    /// The containment boundary converts an escaped panic into the stable
    /// fail-closed summary and never lets payload text reach the error.
    #[cfg(feature = "db-keystore")]
    #[test]
    fn contained_open_converts_panics_into_backend_errors() {
        // Success and error results pass through unchanged.
        assert!(matches!(super::contained_open(|| Ok(7u32)), Ok(7)));
        let passthrough: Result<(), _> =
            super::contained_open(|| Err(super::StoreError::Backend("invalid".to_owned())));
        assert!(matches!(
            passthrough,
            Err(super::StoreError::Backend(summary)) if summary == "invalid"
        ));

        // A panic is contained; the untrusted payload is discarded, not
        // echoed into the (Display-rendered) error summary.
        let contained: Result<(), super::StoreError> =
            super::contained_open(|| panic!("payload-with-material-abad1dea"));
        match contained {
            Err(super::StoreError::Backend(summary)) => {
                assert_eq!(summary, super::CONTAINED_PANIC_SUMMARY);
                assert!(!summary.contains("abad1dea"));
            }
            Err(other) => panic!("unexpected error variant: {other}"),
            Ok(()) => panic!("a panicking open must fail"),
        }
    }

    /// Wrong-DEK startup qualification (runtime adapter): opening an existing
    /// encrypted store with the wrong DEK must fail closed as an error and
    /// must not unwind out of `SecretStore::open`, whether turso reports the
    /// mismatch as an error or as a panic. The failed attempt must also
    /// release the advisory lock so the correct DEK can still open.
    #[cfg(feature = "db-keystore")]
    #[test]
    fn wrong_dek_startup_is_contained_and_fails_closed() {
        use std::panic::{AssertUnwindSafe, catch_unwind};
        use zero_secrets::SecretArray;

        let path = unique_temp_path("wrong-dek", "db");
        let provisioning_dek = [0x11u8; 32];
        {
            let store = super::SecretStore::open(super::StoreConfig::DbKeystore {
                path: path.clone(),
                cipher: "aegis256".to_string(),
                dek: SecretArray::new(provisioning_dek),
            })
            .expect("open with the provisioning DEK");
            store
                .put("kv2/qualification", b"wrong-dek startup qualification")
                .expect("store value");
        }

        // Open (and, if open unexpectedly succeeds, read) with the wrong
        // DEK. The outer `catch_unwind` proves no unwind path remains: the
        // adapter itself must have already contained any database-layer
        // panic and mapped it to a `StoreError`.
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            super::SecretStore::open(super::StoreConfig::DbKeystore {
                path: path.clone(),
                cipher: "aegis256".to_string(),
                dek: SecretArray::new([0x22u8; 32]),
            })
            .and_then(|store| store.get("kv2/qualification"))
        }));
        match outcome {
            Ok(Err(err)) => {
                // Fail-closed, and the rendered error stays secret-free:
                // neither DEK's hex encoding may appear.
                let rendered = format!("{err}");
                assert!(!rendered.contains(&"11".repeat(32)));
                assert!(!rendered.contains(&"22".repeat(32)));
            }
            Ok(Ok(_)) => panic!("wrong DEK must not open and read the store"),
            Err(unwound) => {
                drop(unwound);
                panic!("wrong-DEK startup unwound out of SecretStore::open");
            }
        }

        // The wrong-DEK attempt held nothing: the correct DEK still opens
        // and reads.
        let store = super::SecretStore::open(super::StoreConfig::DbKeystore {
            path: path.clone(),
            cipher: "aegis256".to_string(),
            dek: SecretArray::new(provisioning_dek),
        })
        .expect("reopen with the correct DEK");
        assert_eq!(
            store.get("kv2/qualification").expect("read value back"),
            b"wrong-dek startup qualification"
        );
        drop(store);
        let _ = std::fs::remove_file(&path);
    }

    /// The rekey store-open fence surfaces as the dedicated typed variant,
    /// and its rendering keeps the refusal-text contract: it names the
    /// marker path and `basil keystore rekey --resume` verbatim.
    #[cfg(all(feature = "db-keystore", target_os = "linux"))]
    #[test]
    fn store_open_fence_is_typed_rekey_in_progress() {
        use zero_secrets::SecretArray;

        let path = unique_temp_path("fence-typed", "db");
        {
            let store = super::SecretStore::open(super::StoreConfig::DbKeystore {
                path: path.clone(),
                cipher: "aegis256".to_string(),
                dek: SecretArray::new([0x11u8; 32]),
            })
            .expect("provision the store");
            drop(store);
        }

        // Plant the on-disk intent marker a crashed rekey would leave.
        let marker_path = {
            let mut name = path.file_name().expect("file name").to_os_string();
            name.push(crate::rekey::MARKER_SUFFIX);
            path.with_file_name(name)
        };
        std::fs::write(&marker_path, b"planted-by-test").expect("write marker");

        let result = super::SecretStore::open(super::StoreConfig::DbKeystore {
            path: path.clone(),
            cipher: "aegis256".to_string(),
            dek: SecretArray::new([0x11u8; 32]),
        });
        let Err(err) = result else {
            panic!("the fence must refuse to open while the marker exists");
        };
        let text = err.to_string();
        let super::StoreError::RekeyInProgress { marker } = err else {
            panic!("expected RekeyInProgress, got: {text}");
        };
        assert!(
            marker.ends_with(crate::rekey::MARKER_SUFFIX),
            "marker must name the intent-marker path: {marker}"
        );
        assert!(text.contains("keystore rekey in progress"), "got: {text}");
        assert!(text.contains(marker.as_str()), "got: {text}");
        assert!(
            text.contains("basil keystore rekey --resume"),
            "refusal must name the recovery command verbatim: {text}"
        );

        let _ = std::fs::remove_file(&marker_path);
        let _ = std::fs::remove_file(&path);
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

    #[cfg(feature = "onepassword")]
    #[test]
    fn onepassword_store_config_debug_redacts_provider_uri() {
        let cfg = super::StoreConfig::OnePassword {
            provider_uri: "onepassword+token://acct:ops_tok@Private".to_string(),
            project: "p".to_string(),
            profile: "default".to_string(),
        };
        let rendered = format!("{cfg:?}");
        assert!(rendered.contains("REDACTED"));
        assert!(!rendered.contains("ops_tok"));
    }
}
