// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Key-store backend adapter.
//!
//! This adapter is compiled only behind `keystore-backend`. The storage and
//! local materialize-to-use crypto live in `basil-keystore-backend`; this module
//! only implements Basil's internal [`Backend`] trait.

use async_trait::async_trait;
use basil_keystore_backend::{
    CryptoError, SecretStore, StoreConfig, StoreError, decrypt_aead, encrypt_aead,
    generate_key_material, keystore_version, public_ed25519, sign_ed25519, verify_ed25519,
};
use basil_proto::{AeadAlgorithm, CiphertextEnvelope, KeyMaterial, KeyType};
use zeroize::Zeroizing;

use super::{Backend, BackendError, KeyMetadata, KvSecret, KvValue, NewKey, PublicKey};

/// Backend over a local/external key-value secret store.
pub struct KeystoreBackend {
    store: SecretStore,
}

impl KeystoreBackend {
    /// Open a key-store backend.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::Backend`] when the configured store cannot open.
    pub fn open(config: StoreConfig) -> Result<Self, BackendError> {
        Ok(Self {
            store: SecretStore::open(config).map_err(store_error)?,
        })
    }

    fn get_secret(&self, key_id: &str) -> Result<Zeroizing<Vec<u8>>, BackendError> {
        self.store
            .get_secret(key_id)
            .map(|secret| Zeroizing::new(secret.into_vec()))
            .map_err(store_error)
    }
}

#[async_trait]
impl Backend for KeystoreBackend {
    fn kind(&self) -> &'static str {
        "keystore"
    }

    async fn new_key(&self, key_type: KeyType) -> Result<NewKey, BackendError> {
        let key_id = uuid::Uuid::new_v4().to_string();
        self.create_named_key(&key_id, key_type).await
    }

    async fn create_named_key(
        &self,
        key_id: &str,
        key_type: KeyType,
    ) -> Result<NewKey, BackendError> {
        if key_type != KeyType::Ed25519 {
            return Err(BackendError::UnsupportedKeyType(key_type));
        }
        let seed = generate_key_material();
        self.store
            .put(key_id, seed.as_slice())
            .map_err(store_error)?;
        let public = public_ed25519(seed.as_slice()).map_err(|err| crypto_error(&err))?;
        Ok(NewKey {
            key_id: key_id.to_owned(),
            public_key: public.to_vec(),
        })
    }

    async fn create_named_aead(
        &self,
        key_id: &str,
        _aead: AeadAlgorithm,
    ) -> Result<(), BackendError> {
        let key = generate_key_material();
        self.store.put(key_id, key.as_slice()).map_err(store_error)
    }

    async fn public_key(&self, key_id: &str) -> Result<Vec<u8>, BackendError> {
        let seed = self.get_secret(key_id)?;
        public_ed25519(seed.as_slice())
            .map(|p| p.to_vec())
            .map_err(|err| crypto_error(&err))
    }

    async fn public_key_with_meta(&self, key_id: &str) -> Result<PublicKey, BackendError> {
        Ok(PublicKey {
            public_key: self.public_key(key_id).await?,
            key_type: KeyType::Ed25519,
            version: keystore_version(),
        })
    }

    async fn key_metadata(&self, key_id: &str) -> Result<KeyMetadata, BackendError> {
        let _present = self.get_secret(key_id)?;
        Ok(KeyMetadata {
            key_type: None,
            latest_version: keystore_version(),
        })
    }

    async fn import(
        &self,
        key_id: &str,
        key_type: KeyType,
        material: &KeyMaterial,
    ) -> Result<NewKey, BackendError> {
        if key_type != KeyType::Ed25519 {
            return Err(BackendError::UnsupportedKeyType(key_type));
        }
        let KeyMaterial::Ed25519Seed(seed) = material else {
            return Err(BackendError::Unsupported("import material"));
        };
        let public = public_ed25519(seed).map_err(|err| crypto_error(&err))?;
        self.store.put(key_id, seed).map_err(store_error)?;
        Ok(NewKey {
            key_id: key_id.to_owned(),
            public_key: public.to_vec(),
        })
    }

    async fn sign(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, BackendError> {
        let seed = self.get_secret(key_id)?;
        sign_ed25519(seed.as_slice(), message)
            .map(|s| s.to_vec())
            .map_err(|err| crypto_error(&err))
    }

    async fn verify(
        &self,
        key_id: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, BackendError> {
        let public = self.public_key(key_id).await?;
        verify_ed25519(&public, message, signature).map_err(|err| crypto_error(&err))
    }

    async fn encrypt(
        &self,
        key_id: &str,
        algorithm: AeadAlgorithm,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<CiphertextEnvelope, BackendError> {
        let key = self.get_secret(key_id)?;
        encrypt_aead(key.as_slice(), algorithm, plaintext, aad).map_err(|err| crypto_error(&err))
    }

    async fn decrypt(
        &self,
        key_id: &str,
        envelope: &CiphertextEnvelope,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, BackendError> {
        let key = self.get_secret(key_id)?;
        decrypt_aead(key.as_slice(), envelope, aad)
            .map(|plaintext| plaintext.to_vec())
            .map_err(|err| crypto_error(&err))
    }

    async fn kv_get(&self, key_id: &str, version: Option<u32>) -> Result<KvValue, BackendError> {
        if let Some(v) = version
            && v != keystore_version()
        {
            return Err(BackendError::KeyNotFound(key_id.to_owned()));
        }
        Ok(KvValue {
            value: self.store.get(key_id).map_err(store_error)?,
            version: keystore_version(),
        })
    }

    async fn kv_get_secret(
        &self,
        key_id: &str,
        version: Option<u32>,
    ) -> Result<KvSecret, BackendError> {
        if let Some(v) = version
            && v != keystore_version()
        {
            return Err(BackendError::KeyNotFound(key_id.to_owned()));
        }
        Ok(KvSecret {
            value: self.get_secret(key_id)?,
            version: keystore_version(),
        })
    }

    async fn kv_put(&self, key_id: &str, value: &[u8]) -> Result<u32, BackendError> {
        self.store.put(key_id, value).map_err(store_error)?;
        Ok(keystore_version())
    }
}

fn store_error(err: StoreError) -> BackendError {
    match err {
        StoreError::NotFound(key) => BackendError::KeyNotFound(key),
        StoreError::Backend(summary) => BackendError::Backend(summary),
        StoreError::NonUtf8Value => BackendError::Backend("non-utf8-secret-for-provider".into()),
    }
}

fn crypto_error(err: &CryptoError) -> BackendError {
    match err {
        CryptoError::DecryptFailed => BackendError::DecryptFailed,
        CryptoError::UnsupportedAlgorithm(algorithm) => {
            BackendError::UnsupportedAlgorithm(*algorithm)
        }
        CryptoError::BadKeyLength { .. }
        | CryptoError::BadSignatureLength { .. }
        | CryptoError::BadNonceLength { .. }
        | CryptoError::EncryptFailed => BackendError::Backend(err.to_string()),
    }
}

/// A unique, absolute temp path so parallel tests never share a store file.
#[cfg(all(test, feature = "db-keystore"))]
fn unique_temp_path(stem: &str, ext: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "basil-keystore-e2e-{stem}-{}-{n}.{ext}",
        std::process::id()
    ))
}

/// End-to-end: unlock a sealed `DbKeystoreDek` bundle credential and drive a
/// materialize-to-use sign/encrypt/decrypt round trip through the `Backend`
/// trait over a real encrypted store. No live vault is required.
#[cfg(all(test, feature = "db-keystore"))]
mod db_keystore_e2e {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::{AeadAlgorithm, Backend as _, BackendError, KeyType, KeystoreBackend, StoreConfig};
    use crate::seal::{
        BackendCred, CredBundle, MethodRegistry, PassphraseMethod, SlotSpec, format, open_bundle,
        seal,
    };
    use basil_keystore_backend::verify_ed25519;
    use zero_secrets::SecretArray;
    use zeroize::Zeroizing;

    /// Tiny Argon2id profile, TEST ONLY (production uses 64 MiB / t=3 / p=1).
    const FAST: crate::seal::Argon2Params = crate::seal::Argon2Params {
        m_cost_kib: 256,
        t_cost: 1,
        p_cost: 1,
    };

    /// Seal a bundle carrying `dek`, then recover it through the unlock path.
    fn seal_and_unlock_dek(dek: [u8; 32]) -> SecretArray<32> {
        let mut payload = CredBundle::empty();
        payload.set(
            "db-keystore",
            BackendCred::DbKeystoreDek {
                dek: SecretArray::new(dek),
            },
        );
        let method = PassphraseMethod::with_params(Zeroizing::new(b"e2e-pass".to_vec()), FAST);
        let file = seal(
            &payload,
            &[SlotSpec {
                method: &method,
                label: "passphrase".into(),
            }],
        )
        .unwrap();
        let parsed = format::decode(&file).unwrap();
        let registry = MethodRegistry::new().with(&method);
        let opened = open_bundle(&parsed, &registry).unwrap();
        opened
            .backends
            .get("db-keystore")
            .and_then(|cred| match cred {
                BackendCred::DbKeystoreDek { dek } => Some(dek.clone()),
                _ => None,
            })
            .expect("sealed DbKeystoreDek must round-trip")
    }

    #[tokio::test]
    async fn unlock_then_materialize_sign_encrypt_decrypt() {
        // (1) Unlock the sealed bundle to recover the DB-opening DEK.
        let dek = seal_and_unlock_dek([0x33u8; 32]);

        // (2) Open the encrypted db-keystore backend with that DEK.
        let path = super::unique_temp_path("db", "db");
        let backend = KeystoreBackend::open(StoreConfig::DbKeystore {
            path: path.clone(),
            cipher: "aegis256".to_string(),
            dek,
        })
        .expect("open encrypted db-keystore backend from the unlocked DEK");

        // (3a) Ed25519 materialize-to-sign: generate, sign, verify (both the
        // broker's own verify and an independent check against the public half).
        let new_key = backend
            .create_named_key("sign-key", KeyType::Ed25519)
            .await
            .expect("provision an Ed25519 key in the store");
        let message = b"db-keystore e2e materialize-to-sign";
        let signature = backend.sign("sign-key", message).await.expect("sign");
        assert!(
            backend
                .verify("sign-key", message, &signature)
                .await
                .unwrap(),
            "the broker verifies its own signature"
        );
        assert!(
            !backend
                .verify("sign-key", b"other message", &signature)
                .await
                .unwrap(),
            "a signature must not verify over a different message"
        );
        assert!(
            verify_ed25519(&new_key.public_key, message, &signature).unwrap(),
            "the signature verifies under the key's derived public half"
        );

        // (3b) AEAD materialize-to-use: generate, encrypt, decrypt, tamper.
        backend
            .create_named_aead("aead-key", AeadAlgorithm::Aes256Gcm)
            .await
            .expect("provision an AEAD key");
        let plaintext = b"db-keystore e2e materialize-to-use aead";
        let mut envelope = backend
            .encrypt("aead-key", AeadAlgorithm::Aes256Gcm, plaintext, None)
            .await
            .expect("encrypt");
        let recovered = backend
            .decrypt("aead-key", &envelope, None)
            .await
            .expect("decrypt");
        assert_eq!(recovered.as_slice(), plaintext.as_slice());

        envelope.ciphertext[0] ^= 0x01;
        assert!(
            matches!(
                backend.decrypt("aead-key", &envelope, None).await,
                Err(BackendError::DecryptFailed)
            ),
            "a tampered envelope must fail closed"
        );

        drop(backend);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn wrong_dek_cannot_open_the_sealed_store() {
        // Provision a key under one DEK, then prove a different unlocked DEK
        // cannot read the encrypted store (fail closed, never a panic).
        let path = super::unique_temp_path("db-wrongdek", "db");
        let dek_a = seal_and_unlock_dek([0x01u8; 32]);
        {
            let backend = KeystoreBackend::open(StoreConfig::DbKeystore {
                path: path.clone(),
                cipher: "aegis256".to_string(),
                dek: dek_a,
            })
            .expect("open with the correct DEK");
            backend
                .create_named_aead("aead-key", AeadAlgorithm::Aes256Gcm)
                .await
                .expect("provision a key");
            drop(backend);
        }

        let dek_b = seal_and_unlock_dek([0x02u8; 32]);
        // Opening with the wrong DEK either fails to open or fails to read; both
        // are fail-closed. If it opens, assert we never recover the key material.
        // (An open refused up front is also fail-closed and needs no assertion.)
        if let Ok(backend) = KeystoreBackend::open(StoreConfig::DbKeystore {
            path: path.clone(),
            cipher: "aegis256".to_string(),
            dek: dek_b,
        }) {
            let err = backend
                .encrypt("aead-key", AeadAlgorithm::Aes256Gcm, b"x", None)
                .await;
            assert!(err.is_err(), "wrong-DEK read must fail closed");
        }
        let _ = std::fs::remove_file(&path);
    }
}

// The `1Password` keystore arm's sealed-cred round trip is exercised in
// `crate::seal::tests` (`keystore_creds_seal_unseal_round_trip`). A live
// materialize-to-use e2e is not run here: unlike the former file-backed
// `dotenv` provider, `1Password` needs an authenticated `op` CLI and a real
// vault, which the offline test lane cannot provide. The `OnePasswordConfig`
// URI parsing and store dispatch are unit-tested in `basil-keystore-backend`.
