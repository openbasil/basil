// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Vault-compatible (Vault or `OpenBao`) `transit` backend authenticated with a **self-minted
//! JWT-SVID** instead of a static token.
//!
//! On demand the backend mints a JWT-SVID ([`SvidMinter`]), exchanges it at
//! `auth/<mount>/login` for a short-lived Vault token, caches that token until
//! it nears expiry, and then runs the identical transit operations as the
//! static-token backend. "Same server, different protocol": the wire calls to
//! transit are unchanged. Only the authentication handshake differs.
//!
//! Vault maps the SPIFFE id (the JWT `sub`) to a role and policy, so the
//! *authorization* of what this broker may do lives in vault policy, which is
//! where a future per-client ACL layer will plug in (choosing which SPIFFE id
//! to assume per caller).

use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tracing::{debug, info};

use basil_proto::{AeadAlgorithm, CiphertextEnvelope, KeyMaterial, KeyType};

use super::svid::SvidMinter;
use super::transit::{TransitClient, read_body, transit_aead_type};
use super::{
    Backend, BackendError, KeyMetadata, KvSecret, KvValue, NewKey, PublicKey, SignOptions,
};

/// Re-login this long before the cached token actually expires.
const TOKEN_REFRESH_SKEW: Duration = Duration::from_secs(10);

/// Fallback cache lifetime if vault reports a non-expiring (`0`) lease.
const DEFAULT_LEASE_SECS: u64 = 300;

/// Configuration for the SPIFFE/JWT login exchange.
#[derive(Debug, Clone)]
pub struct SpiffeConfig {
    /// Vault address, e.g. `http://127.0.0.1:8200`.
    pub vault_addr: String,
    /// Transit engine mount path, e.g. `transit`.
    pub transit_mount: String,
    /// JWT auth method mount path, e.g. `jwt`.
    pub jwt_auth_mount: String,
    /// Vault jwt role bound to this broker's SPIFFE id.
    pub role: String,
    /// SPIFFE id stamped into the SVID `sub`.
    pub spiffe_id: String,
    /// Audience (`aud`) the vault role expects (`bound_audiences`).
    pub audience: String,
    /// Lifetime of each minted SVID.
    pub svid_ttl: Duration,
}

struct CachedToken {
    token: String,
    expires_at: Instant,
}

pub struct SpiffeVaultBackend {
    http: reqwest::Client,
    addr: String,
    auth_mount: String,
    role: String,
    transit: TransitClient,
    minter: SvidMinter,
    cached: Mutex<Option<CachedToken>>,
}

impl SpiffeVaultBackend {
    /// Build a backend that **self-generates** a fresh RSA issuer key. Useful for
    /// tests and ephemeral setups; production boots from a sealed-bundle signer
    /// cred via [`Self::from_signer`].
    pub fn new(cfg: SpiffeConfig) -> Result<Self, BackendError> {
        let minter =
            SvidMinter::generate(cfg.spiffe_id.clone(), cfg.audience.clone(), cfg.svid_ttl)?;
        Self::assemble(cfg, minter)
    }

    /// Build a backend from a sealed-bundle [`super::super::seal::BackendCred::SpiffeSigner`]:
    /// an existing PEM private signing key (`PKCS#1` or `PKCS#8`) the broker uses
    /// to self-issue its JWT-SVID, plus the deployment-supplied [`SpiffeConfig`].
    ///
    /// The cred's SPIFFE id (`cfg.spiffe_id`) is what the minter stamps into the
    /// SVID `sub`; the key material never leaves this process.
    pub fn from_signer(key_pem: &str, cfg: SpiffeConfig) -> Result<Self, BackendError> {
        let minter = SvidMinter::from_pem(
            key_pem,
            cfg.spiffe_id.clone(),
            cfg.audience.clone(),
            cfg.svid_ttl,
        )?;
        Self::assemble(cfg, minter)
    }

    /// Shared wiring: build the HTTP/transit clients and assemble the backend
    /// around an already-constructed [`SvidMinter`].
    fn assemble(cfg: SpiffeConfig, minter: SvidMinter) -> Result<Self, BackendError> {
        crate::ensure_crypto_provider();
        let http = reqwest::Client::builder()
            .build()
            .map_err(|e| BackendError::Transport(e.to_string()))?;
        let addr = cfg.vault_addr.trim_end_matches('/').to_string();
        let transit = TransitClient::new(http.clone(), &addr, &cfg.transit_mount);
        Ok(Self {
            http,
            addr,
            auth_mount: cfg.jwt_auth_mount,
            role: cfg.role,
            transit,
            minter,
            cached: Mutex::new(None),
        })
    }

    /// The broker's JWT-SVID validation public key (SPKI PEM). Register this
    /// with Vault's jwt auth via `jwt_validation_pubkeys`.
    #[must_use]
    pub fn public_key_pem(&self) -> &str {
        self.minter.public_key_pem()
    }

    /// The SPIFFE id this broker presents.
    #[must_use]
    pub fn spiffe_id(&self) -> &str {
        self.minter.spiffe_id()
    }

    /// Return a valid Vault token, re-running the SVID login when the cached
    /// token is missing or within [`TOKEN_REFRESH_SKEW`] of expiry.
    async fn token(&self) -> Result<String, BackendError> {
        let mut guard = self.cached.lock().await;
        /* ubs:ignore false positive: time _not_ used as source of randomness. */
        if let Some(c) = guard.as_ref()
            /* ubs:ignore */
            && c.expires_at > Instant::now() + TOKEN_REFRESH_SKEW
        {
            return Ok(c.token.clone());
        }
        let fresh = self.login().await?;
        let token = fresh.token.clone();
        *guard = Some(fresh);
        drop(guard);
        Ok(token)
    }

    /// Mint a fresh JWT-SVID and exchange it at `auth/<mount>/login`.
    async fn login(&self) -> Result<CachedToken, BackendError> {
        let jwt = self.minter.mint()?;
        let url = format!("{}/v1/auth/{}/login", self.addr, self.auth_mount);
        debug!(role = %self.role, spiffe_id = %self.minter.spiffe_id(), "exchanging JWT-SVID for vault token");

        let resp = self
            .http
            .post(url)
            .json(&json!({ "role": self.role, "jwt": jwt }))
            .send()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;
        let body = read_body(resp)
            .await?
            .ok_or_else(|| BackendError::Protocol("empty login response".into()))?;

        let auth = body
            .get("auth")
            .ok_or_else(|| BackendError::Backend("login response has no auth block".into()))?;
        let token = auth
            .get("client_token")
            .and_then(Value::as_str)
            .ok_or_else(|| BackendError::Protocol("no client_token in login response".into()))?
            .to_string();
        let lease = auth
            .get("lease_duration")
            .and_then(Value::as_u64)
            .filter(|&l| l > 0)
            .unwrap_or(DEFAULT_LEASE_SECS);

        info!(lease_seconds = lease, "obtained vault token via JWT-SVID");
        /* ubs:ignore false positive: time is _not_ used as source of randomness. */
        Ok(CachedToken {
            /* ubs:ignore */
            token,
            expires_at: Instant::now() + Duration::from_secs(lease),
        })
    }
}

#[async_trait]
impl Backend for SpiffeVaultBackend {
    fn kind(&self) -> &'static str {
        "spiffe-vault"
    }

    async fn new_key(&self, key_type: KeyType) -> Result<NewKey, BackendError> {
        let token = self.token().await?;
        self.transit.new_key(&token, key_type).await
    }

    async fn create_named_key(
        &self,
        key_id: &str,
        key_type: KeyType,
    ) -> Result<NewKey, BackendError> {
        let token = self.token().await?;
        self.transit
            .create_named_key(&token, key_id, key_type)
            .await
    }

    async fn create_named_aead(
        &self,
        key_id: &str,
        aead: AeadAlgorithm,
    ) -> Result<(), BackendError> {
        let token = self.token().await?;
        self.transit
            .create_named_aead(&token, key_id, transit_aead_type(aead))
            .await
    }

    async fn public_key(&self, key_id: &str) -> Result<Vec<u8>, BackendError> {
        let token = self.token().await?;
        self.transit.read_public_key(&token, key_id).await
    }

    async fn public_key_with_meta(&self, key_id: &str) -> Result<PublicKey, BackendError> {
        let token = self.token().await?;
        self.transit.read_public_key_with_meta(&token, key_id).await
    }

    async fn key_metadata(&self, key_id: &str) -> Result<KeyMetadata, BackendError> {
        let token = self.token().await?;
        self.transit.read_key_metadata(&token, key_id).await
    }

    async fn public_keys(
        &self,
        key_id: &str,
    ) -> Result<std::collections::BTreeMap<u32, Vec<u8>>, BackendError> {
        let token = self.token().await?;
        self.transit.read_public_keys(&token, key_id).await
    }

    async fn import(
        &self,
        key_id: &str,
        key_type: KeyType,
        material: &KeyMaterial,
    ) -> Result<NewKey, BackendError> {
        let token = self.token().await?;
        self.transit
            .import(&token, key_id, key_type, material)
            .await
    }

    async fn sign(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, BackendError> {
        let token = self.token().await?;
        self.transit.sign(&token, key_id, message).await
    }

    async fn sign_with_options(
        &self,
        key_id: &str,
        message: &[u8],
        options: SignOptions,
    ) -> Result<Vec<u8>, BackendError> {
        let token = self.token().await?;
        self.transit
            .sign_with_options(&token, key_id, message, options)
            .await
    }

    async fn verify(
        &self,
        key_id: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, BackendError> {
        let token = self.token().await?;
        self.transit
            .verify(&token, key_id, message, signature)
            .await
    }

    async fn verify_with_options(
        &self,
        key_id: &str,
        message: &[u8],
        signature: &[u8],
        options: SignOptions,
    ) -> Result<bool, BackendError> {
        let token = self.token().await?;
        self.transit
            .verify_with_options(&token, key_id, message, signature, options)
            .await
    }

    async fn encrypt(
        &self,
        key_id: &str,
        algorithm: AeadAlgorithm,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<CiphertextEnvelope, BackendError> {
        let token = self.token().await?;
        self.transit
            .encrypt(&token, key_id, algorithm, plaintext, aad)
            .await
    }

    async fn decrypt(
        &self,
        key_id: &str,
        envelope: &CiphertextEnvelope,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, BackendError> {
        let token = self.token().await?;
        self.transit.decrypt(&token, key_id, envelope, aad).await
    }

    async fn rotate(&self, key_id: &str) -> Result<u32, BackendError> {
        let token = self.token().await?;
        self.transit.rotate(&token, key_id).await
    }

    async fn kv_get(&self, key_id: &str, version: Option<u32>) -> Result<KvValue, BackendError> {
        let token = self.token().await?;
        self.transit.kv_get(&token, key_id, version).await
    }

    async fn kv_get_secret(
        &self,
        key_id: &str,
        version: Option<u32>,
    ) -> Result<KvSecret, BackendError> {
        let token = self.token().await?;
        self.transit.kv_get_secret(&token, key_id, version).await
    }

    async fn kv_put(&self, key_id: &str, value: &[u8]) -> Result<u32, BackendError> {
        let token = self.token().await?;
        self.transit.kv_put(&token, key_id, value).await
    }

    async fn configure_versions(
        &self,
        key_id: &str,
        min_decryption_version: Option<u32>,
        min_available_version: Option<u32>,
    ) -> Result<(), BackendError> {
        let token = self.token().await?;
        self.transit
            .configure_versions(
                &token,
                key_id,
                min_decryption_version,
                min_available_version,
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::{Backend, Duration, SpiffeConfig, SpiffeVaultBackend};
    use rsa::RsaPrivateKey;
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};

    fn config() -> SpiffeConfig {
        SpiffeConfig {
            vault_addr: "http://127.0.0.1:8200/".to_string(),
            transit_mount: "transit".to_string(),
            jwt_auth_mount: "jwt".to_string(),
            role: "basil".to_string(),
            spiffe_id: "spiffe://example.test/basil".to_string(),
            audience: "openbao".to_string(),
            svid_ttl: Duration::from_mins(2),
        }
    }

    /// `from_signer` boots a backend from an existing PEM signing key (the sealed
    /// `SpiffeSigner` cred path) and stamps the cred's SPIFFE id into the SVID.
    #[test]
    fn from_signer_builds_from_bundle_pem() {
        let mut rng = rand::thread_rng();
        let key = RsaPrivateKey::new(&mut rng, 1024).expect("rsa keygen");
        let pem = key.to_pkcs8_pem(LineEnding::LF).expect("pkcs8 pem");

        let backend = SpiffeVaultBackend::from_signer(&pem, config())
            .expect("construct backend from signer cred");
        assert_eq!(backend.kind(), "spiffe-vault");
        assert_eq!(backend.spiffe_id(), "spiffe://example.test/basil");
        assert!(backend.public_key_pem().contains("BEGIN PUBLIC KEY"));
        // Trailing slash on the configured addr is normalized away.
        assert_eq!(backend.addr, "http://127.0.0.1:8200");
    }

    #[test]
    fn from_signer_rejects_invalid_pem() {
        // `SpiffeVaultBackend` is not `Debug`, so match rather than `expect_err`.
        match SpiffeVaultBackend::from_signer("garbage", config()) {
            Err(super::BackendError::Backend(_)) => {}
            Err(other) => panic!("wrong error: {other}"),
            Ok(_) => panic!("invalid pem must be rejected"),
        }
    }
}
