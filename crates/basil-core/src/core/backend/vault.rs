// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Vault-compatible (`HashiCorp` Vault or `OpenBao`) `transit` backend,
//! authenticated with a **static token** (`X-Vault-Token`).
//!
//! All the transit wire logic lives in [`super::transit::TransitClient`]; this
//! backend just supplies a fixed token. For SPIFFE/SVID-based auth against the
//! same engine, see [`super::spiffe::SpiffeVaultBackend`].

use async_trait::async_trait;
use zeroize::Zeroizing;

use basil_proto::{AeadAlgorithm, CiphertextEnvelope, KeyMaterial, KeyType};

use super::pki::PkiClient;
use super::transit::{TransitClient, transit_aead_type};
use super::{
    Backend, BackendError, KeyMetadata, KvValue, NewKey, PublicKey, SignOptions, X509Bundle,
    X509Svid,
};

pub struct VaultBackend {
    transit: TransitClient,
    pki: PkiClient,
    token: String,
}

impl VaultBackend {
    /// Build a backend talking to the vault at `addr` with `token`, using the
    /// transit engine mounted at `mount`.
    pub fn new(
        addr: impl Into<String>,
        token: impl Into<String>,
        mount: impl Into<String>,
    ) -> Result<Self, BackendError> {
        crate::ensure_crypto_provider();
        let http = reqwest::Client::builder()
            .build()
            .map_err(|e| BackendError::Transport(e.to_string()))?;
        let addr = addr.into();
        Ok(Self {
            transit: TransitClient::new(http.clone(), &addr, &mount.into()),
            pki: PkiClient::new(http, &addr),
            token: token.into(),
        })
    }
}

#[async_trait]
impl Backend for VaultBackend {
    fn kind(&self) -> &'static str {
        "vault"
    }

    async fn new_key(&self, key_type: KeyType) -> Result<NewKey, BackendError> {
        self.transit.new_key(&self.token, key_type).await
    }

    async fn create_named_key(
        &self,
        key_id: &str,
        key_type: KeyType,
    ) -> Result<NewKey, BackendError> {
        self.transit
            .create_named_key(&self.token, key_id, key_type)
            .await
    }

    async fn create_named_aead(
        &self,
        key_id: &str,
        aead: AeadAlgorithm,
    ) -> Result<(), BackendError> {
        self.transit
            .create_named_aead(&self.token, key_id, transit_aead_type(aead))
            .await
    }

    async fn public_key(&self, key_id: &str) -> Result<Vec<u8>, BackendError> {
        self.transit.read_public_key(&self.token, key_id).await
    }

    async fn public_key_with_meta(&self, key_id: &str) -> Result<PublicKey, BackendError> {
        self.transit
            .read_public_key_with_meta(&self.token, key_id)
            .await
    }

    async fn key_metadata(&self, key_id: &str) -> Result<KeyMetadata, BackendError> {
        self.transit.read_key_metadata(&self.token, key_id).await
    }

    async fn public_keys(
        &self,
        key_id: &str,
    ) -> Result<std::collections::BTreeMap<u32, Vec<u8>>, BackendError> {
        self.transit.read_public_keys(&self.token, key_id).await
    }

    async fn import(
        &self,
        key_id: &str,
        key_type: KeyType,
        material: &KeyMaterial,
    ) -> Result<NewKey, BackendError> {
        self.transit
            .import(&self.token, key_id, key_type, material)
            .await
    }

    async fn sign(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, BackendError> {
        self.transit.sign(&self.token, key_id, message).await
    }

    async fn sign_with_options(
        &self,
        key_id: &str,
        message: &[u8],
        options: SignOptions,
    ) -> Result<Vec<u8>, BackendError> {
        self.transit
            .sign_with_options(&self.token, key_id, message, options)
            .await
    }

    async fn verify(
        &self,
        key_id: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, BackendError> {
        self.transit
            .verify(&self.token, key_id, message, signature)
            .await
    }

    async fn verify_with_options(
        &self,
        key_id: &str,
        message: &[u8],
        signature: &[u8],
        options: SignOptions,
    ) -> Result<bool, BackendError> {
        self.transit
            .verify_with_options(&self.token, key_id, message, signature, options)
            .await
    }

    async fn encrypt(
        &self,
        key_id: &str,
        algorithm: AeadAlgorithm,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<CiphertextEnvelope, BackendError> {
        self.transit
            .encrypt(&self.token, key_id, algorithm, plaintext, aad)
            .await
    }

    async fn decrypt(
        &self,
        key_id: &str,
        envelope: &CiphertextEnvelope,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, BackendError> {
        self.transit
            .decrypt(&self.token, key_id, envelope, aad)
            .await
    }

    async fn rotate(&self, key_id: &str) -> Result<u32, BackendError> {
        self.transit.rotate(&self.token, key_id).await
    }

    async fn kv_get(&self, key_id: &str, version: Option<u32>) -> Result<KvValue, BackendError> {
        self.transit.kv_get(&self.token, key_id, version).await
    }

    async fn kv_get_secret(
        &self,
        key_id: &str,
        version: Option<u32>,
    ) -> Result<Zeroizing<Vec<u8>>, BackendError> {
        self.transit
            .kv_get_secret(&self.token, key_id, version)
            .await
    }

    async fn kv_put(&self, key_id: &str, value: &[u8]) -> Result<u32, BackendError> {
        self.transit.kv_put(&self.token, key_id, value).await
    }

    async fn configure_versions(
        &self,
        key_id: &str,
        min_decryption_version: Option<u32>,
        min_available_version: Option<u32>,
    ) -> Result<(), BackendError> {
        self.transit
            .configure_versions(
                &self.token,
                key_id,
                min_decryption_version,
                min_available_version,
            )
            .await
    }

    async fn issue_x509_svid(
        &self,
        key_id: &str,
        spiffe_id: &str,
        ttl_seconds: u64,
    ) -> Result<X509Svid, BackendError> {
        self.pki
            .issue_x509_svid(&self.token, key_id, spiffe_id, ttl_seconds)
            .await
    }

    async fn issue_x509_cert(
        &self,
        key_id: &str,
        request: &super::X509CertRequest,
    ) -> Result<X509Svid, BackendError> {
        self.pki.issue_x509_cert(&self.token, key_id, request).await
    }

    async fn x509_bundle(&self, key_id: &str) -> Result<X509Bundle, BackendError> {
        self.pki.x509_bundle(&self.token, key_id).await
    }
}
