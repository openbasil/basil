// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Blocking client for the basil agent.

use basil_proto::broker::v1 as pb;
use tokio::runtime::Runtime;

use crate::Client;
use crate::client::{
    AgentExplanation, AgentHealth, AgentReadiness, AgentReload, AgentRevocation, AgentStatus,
    AllowedNatsSigner, ImportEntry, IssuedCertificate, KeyHandle, MintedJwt, NatsJwtValidation,
    NatsUserPermissions, SecretValue, SignNatsJwtOptions,
};
use crate::constants::DEFAULT_CONN_TIMEOUT;
use crate::error::Result;
use crate::proto::{AeadAlgorithm, CiphertextEnvelope, KeyMaterial, KeyType};

/// A blocking wrapper around the async gRPC client.
pub struct BlockingClient {
    runtime: Runtime,
    inner: Client,
}

impl BlockingClient {
    /// Connect to the agent listening at `path`.
    pub fn connect(path: &str) -> Result<Self> {
        Self::connect_with_timeout(path, DEFAULT_CONN_TIMEOUT)
    }

    /// Connect with an explicit default per-request timeout in seconds.
    pub fn connect_with_timeout(path: &str, default_timeout: u64) -> Result<Self> {
        let runtime = Runtime::new()?;
        let inner = runtime.block_on(Client::connect_with_timeout(path, default_timeout))?;
        Ok(Self { runtime, inner })
    }

    /// Create a key under catalog name `key_id`.
    pub fn new_key(&mut self, key_id: &str, key_type: KeyType) -> Result<KeyHandle> {
        self.runtime.block_on(self.inner.new_key(key_id, key_type))
    }

    /// Import caller-provided key material.
    pub fn import(
        &mut self,
        key_id: &str,
        key_type: KeyType,
        material: KeyMaterial,
    ) -> Result<KeyHandle> {
        self.runtime
            .block_on(self.inner.import(key_id, key_type, material))
    }

    /// Import several keys in one call (e.g. an `nsc`-init bundle). See
    /// [`Client::import_set`].
    pub fn import_set(&mut self, entries: Vec<ImportEntry>) -> Result<Vec<KeyHandle>> {
        self.runtime.block_on(self.inner.import_set(entries))
    }

    /// Sign `message` with `key_id`, returning the raw signature. `message` is
    /// the raw bytes to be signed, not a precomputed digest, and can be a NATS
    /// server nonce or JWT signing input (see [`Client::sign`]).
    pub fn sign(&mut self, key_id: &str, message: &[u8]) -> Result<Vec<u8>> {
        self.runtime.block_on(self.inner.sign(key_id, message))
    }

    /// Verify `signature` over `message` with `key_id`.
    pub fn verify(&mut self, key_id: &str, message: &[u8], signature: &[u8]) -> Result<bool> {
        self.runtime
            .block_on(self.inner.verify(key_id, message, signature))
    }

    /// Fetch a public key by catalog name and optional version.
    pub fn get_public_key(
        &mut self,
        key_id: &str,
        version: Option<u32>,
    ) -> Result<pb::GetPublicKeyResponse> {
        self.runtime
            .block_on(self.inner.get_public_key(key_id, version))
    }

    /// Encrypt plaintext. Basil owns nonce generation.
    pub fn encrypt(
        &mut self,
        key_id: &str,
        algorithm: AeadAlgorithm,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<CiphertextEnvelope> {
        self.runtime
            .block_on(self.inner.encrypt(key_id, algorithm, plaintext, aad))
    }

    /// Decrypt a Basil ciphertext envelope.
    pub fn decrypt(
        &mut self,
        key_id: &str,
        envelope: CiphertextEnvelope,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        self.runtime
            .block_on(self.inner.decrypt(key_id, envelope, aad))
    }

    /// Wrap plaintext with a KEM/envelope operation.
    pub fn wrap_envelope(
        &mut self,
        key_id: &str,
        kem_algorithm: pb::KemAlgorithm,
        envelope_algorithm: pb::EnvelopeAlgorithm,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<pb::KemEnvelope> {
        self.runtime.block_on(self.inner.wrap_envelope(
            key_id,
            kem_algorithm,
            envelope_algorithm,
            plaintext,
            aad,
        ))
    }

    /// Unwrap a KEM/envelope ciphertext.
    pub fn unwrap_envelope(
        &mut self,
        key_id: &str,
        envelope: pb::KemEnvelope,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        self.runtime
            .block_on(self.inner.unwrap_envelope(key_id, envelope, aad))
    }

    /// Fetch a secret payload.
    pub fn get_secret(&mut self, secret_id: &str, version: Option<u32>) -> Result<SecretValue> {
        self.runtime
            .block_on(self.inner.get_secret(secret_id, version))
    }

    /// Store a secret payload, returning the new version.
    pub fn set_secret(&mut self, secret_id: &str, value: &[u8]) -> Result<u32> {
        self.runtime
            .block_on(self.inner.set_secret(secret_id, value))
    }

    /// Rotate a secret, returning the new version.
    pub fn rotate_secret(&mut self, secret_id: &str) -> Result<u32> {
        self.runtime.block_on(self.inner.rotate_secret(secret_id))
    }

    /// List visible catalog entries, optionally filtered by prefix.
    pub fn list_catalog(&mut self, prefix: Option<&str>) -> Result<Vec<pb::CatalogEntry>> {
        self.runtime.block_on(self.inner.list_catalog(prefix))
    }

    /// Mint a generic JWT credential.
    pub fn mint_jwt(
        &mut self,
        key_id: &str,
        sub: &str,
        ttl_secs: Option<u64>,
        claims: impl serde::Serialize,
    ) -> Result<MintedJwt> {
        self.runtime
            .block_on(self.inner.mint_jwt(key_id, sub, ttl_secs, claims))
    }

    /// Mint a generic JWT credential from pre-encoded additional claim JSON.
    pub fn mint_jwt_json(
        &mut self,
        key_id: &str,
        sub: &str,
        ttl_secs: Option<u64>,
        extra_claims_json: impl Into<Vec<u8>>,
    ) -> Result<MintedJwt> {
        self.runtime.block_on(
            self.inner
                .mint_jwt_json(key_id, sub, ttl_secs, extra_claims_json),
        )
    }

    /// Mint a NATS user JWT signed by an account key held by Basil.
    ///
    /// `issuer_account` is the owning account's identity public `NKey` (`A…`),
    /// **required** when `key_id` is an account *signing* key (it sets
    /// `nats.issuer_account`); pass `None` when `key_id` is the account identity
    /// key itself.
    pub fn mint_nats_user(
        &mut self,
        key_id: &str,
        subject_user_nkey: &str,
        issuer_account: Option<&str>,
        name: &str,
        ttl_secs: Option<u64>,
        permissions: NatsUserPermissions,
    ) -> Result<String> {
        self.runtime.block_on(self.inner.mint_nats_user(
            key_id,
            subject_user_nkey,
            issuer_account,
            name,
            ttl_secs,
            permissions,
        ))
    }

    /// Mint a NATS account JWT signed by an operator key (or self-signed) held by Basil.
    pub fn mint_nats_account(
        &mut self,
        signing_key_id: &str,
        subject_account_nkey: &str,
        name: &str,
        signing_keys: &[String],
        expires_in_secs: Option<u64>,
    ) -> Result<String> {
        self.runtime.block_on(self.inner.mint_nats_account(
            signing_key_id,
            subject_account_nkey,
            name,
            signing_keys,
            expires_in_secs,
        ))
    }

    /// Mint a NATS operator JWT. With `subject_operator_nkey` set to `None` the issuer self-signs.
    #[allow(clippy::too_many_arguments)]
    pub fn mint_nats_operator(
        &mut self,
        signing_key_id: &str,
        subject_operator_nkey: Option<&str>,
        name: &str,
        signing_keys: &[String],
        account_server_url: Option<&str>,
        system_account: Option<&str>,
        expires_in_secs: Option<u64>,
    ) -> Result<String> {
        self.runtime.block_on(self.inner.mint_nats_operator(
            signing_key_id,
            subject_operator_nkey,
            name,
            signing_keys,
            account_server_url,
            system_account,
            expires_in_secs,
        ))
    }

    /// Mint a NATS account-signing-key JWT (subject is an `N`-prefixed signer nkey).
    pub fn mint_nats_signer(
        &mut self,
        signing_key_id: &str,
        subject_nkey: &str,
        name: &str,
        expires_in_secs: Option<u64>,
    ) -> Result<String> {
        self.runtime.block_on(self.inner.mint_nats_signer(
            signing_key_id,
            subject_nkey,
            name,
            expires_in_secs,
        ))
    }

    /// Mint a NATS server JWT (subject is an `N`-prefixed server nkey).
    pub fn mint_nats_server(
        &mut self,
        signing_key_id: &str,
        subject_server_nkey: &str,
        name: &str,
        expires_in_secs: Option<u64>,
    ) -> Result<String> {
        self.runtime.block_on(self.inner.mint_nats_server(
            signing_key_id,
            subject_server_nkey,
            name,
            expires_in_secs,
        ))
    }

    /// Mint a NATS curve (x25519) JWT (subject is an `X`-prefixed curve nkey).
    pub fn mint_nats_curve(
        &mut self,
        signing_key_id: &str,
        subject_curve_nkey: &str,
        name: &str,
        expires_in_secs: Option<u64>,
    ) -> Result<String> {
        self.runtime.block_on(self.inner.mint_nats_curve(
            signing_key_id,
            subject_curve_nkey,
            name,
            expires_in_secs,
        ))
    }

    /// Encrypt with a custodied NATS curve xkey to a recipient public xkey.
    pub fn encrypt_nats_curve(
        &mut self,
        key_id: &str,
        recipient_public_xkey: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        self.runtime.block_on(self.inner.encrypt_nats_curve(
            key_id,
            recipient_public_xkey,
            plaintext,
        ))
    }

    /// Decrypt a NATS curve xkey box from a sender public xkey.
    pub fn decrypt_nats_curve(
        &mut self,
        key_id: &str,
        sender_public_xkey: &str,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        self.runtime.block_on(
            self.inner
                .decrypt_nats_curve(key_id, sender_public_xkey, ciphertext),
        )
    }

    /// Validate and sign a caller-supplied NATS JWT claim document.
    pub fn sign_nats_jwt(
        &mut self,
        key_id: &str,
        claims: impl serde::Serialize,
        options: SignNatsJwtOptions,
    ) -> Result<MintedJwt> {
        self.runtime
            .block_on(self.inner.sign_nats_jwt(key_id, claims, options))
    }

    /// Validate and sign a pre-encoded NATS JWT claim document.
    pub fn sign_nats_jwt_json(
        &mut self,
        key_id: &str,
        claims_json: impl Into<Vec<u8>>,
        options: SignNatsJwtOptions,
    ) -> Result<MintedJwt> {
        self.runtime
            .block_on(self.inner.sign_nats_jwt_json(key_id, claims_json, options))
    }

    /// Validate a presented NATS JWT against candidate catalog keys or public `NKeys`.
    pub fn validate_nats_jwt(
        &mut self,
        jwt: &str,
        allowed_signers: impl IntoIterator<Item = AllowedNatsSigner>,
        expected_type: Option<pb::NatsJwtType>,
    ) -> Result<NatsJwtValidation> {
        self.runtime.block_on(
            self.inner
                .validate_nats_jwt(jwt, allowed_signers, expected_type),
        )
    }

    /// Issue a DNS/IP-SAN X.509 leaf (TLS cert). See [`Client::issue_certificate`].
    pub fn issue_certificate(
        &mut self,
        issuer_key_id: &str,
        common_name: &str,
        dns_sans: &[String],
        ip_sans: &[String],
        ttl_secs: u64,
    ) -> Result<IssuedCertificate> {
        self.runtime.block_on(self.inner.issue_certificate(
            issuer_key_id,
            common_name,
            dns_sans,
            ip_sans,
            ttl_secs,
        ))
    }

    /// The broker's backend identifier, build version, and wire protocol version.
    pub fn status(&mut self) -> Result<AgentStatus> {
        self.runtime.block_on(self.inner.status())
    }

    /// Broker liveness: is the daemon up and serving the socket? No backend I/O.
    pub fn health(&mut self) -> Result<AgentHealth> {
        self.runtime.block_on(self.inner.health())
    }

    /// Broker readiness: can the broker actually serve? Returns a non-secret
    /// summary (counts, coarse reason, active generation id).
    pub fn readiness(&mut self) -> Result<AgentReadiness> {
        self.runtime.block_on(self.inner.readiness())
    }

    /// Trigger a permission-gated catalog/policy hot reload from disk
    /// (`basil-atq`). `check = true` is a dry-run (validate, do not swap). The
    /// config is read from the broker's on-disk paths only, never the wire.
    pub fn reload(&mut self, check: bool) -> Result<AgentReload> {
        self.runtime.block_on(self.inner.reload(check))
    }

    /// Explain a policy decision against the broker's serving generation.
    pub fn explain(&mut self, subject: &str, op: &str, key: &str) -> Result<AgentExplanation> {
        self.runtime.block_on(self.inner.explain(subject, op, key))
    }

    /// Revoke a JWT-SVID by trust-domain/`jti` tuple.
    pub fn revoke(
        &mut self,
        trust_domain: &str,
        jti: &str,
        expires_at_unix: u64,
    ) -> Result<AgentRevocation> {
        self.runtime
            .block_on(self.inner.revoke(trust_domain, jti, expires_at_unix))
    }
}
