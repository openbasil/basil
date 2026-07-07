// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Shared Vault `transit` HTTP operations (`HashiCorp` Vault or `OpenBao`).
//!
//! Both the static-token [`super::vault::VaultBackend`] and the
//! SVID-authenticated [`super::spiffe::SpiffeVaultBackend`] make the *same*
//! transit calls: they differ only in how they obtain the `X-Vault-Token`.
//! This module owns the wire logic, taking the token as a parameter.

use aes_kw::KwpAes256;
use aes_kw::cipher::KeyInit;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use rand::RngCore;
use rsa::pkcs8::DecodePublicKey;
use rsa::{Oaep, RsaPublicKey};
use serde_json::{Value, json};
use sha2::Sha256;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use basil_proto::{AeadAlgorithm, CiphertextEnvelope, KeyMaterial, KeyType};

use super::kms_common::{ecdsa_der_to_raw, ecdsa_raw_to_der};
use super::{BackendError, KeyMetadata, NewKey, PublicKey, SignOptions};

/// Wire version assumed for transit signatures (v1 keys are never rotated).
const SIG_VERSION: u32 = 1;

const VAULT_PATH_SEGMENT_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}')
    .add(b'/');

/// Raw Ed25519 seed length for the CLI seed shortcut; RSA/ECDSA BYOK import uses
/// caller-supplied PKCS#8 DER private material.
const ED25519_SEED_LEN: usize = 32;

/// Fixed 16-byte DER prefix of an RFC 8410 §7 `OneAsymmetricKey` (PKCS#8) wrapping
/// an Ed25519 private key, version v1, with no attributes and no embedded public
/// key. The remaining 32 bytes are the raw seed, giving a 48-byte PKCS#8 DER.
///
/// Transit `keys/<k>/import` requires a PKCS#8 DER private key (not a raw seed)
/// for `type=ed25519` on **both** `OpenBao` and `HashiCorp` Vault; wrapping the raw
/// seed is rejected with an ASN.1 `pkcs8` parse error.
///
/// Byte breakdown (TLV):
/// - `30 2e`            SEQUENCE, length 0x2e = 46 (the 2-byte tag+len of this
///   outer SEQUENCE is excluded from its own length, so 46 + 2 = 48 total).
/// - `02 01 00`        INTEGER version = 0 (v1, per RFC 5958 / RFC 8410).
/// - `30 05 06 03 2b 65 70`  `AlgorithmIdentifier` SEQUENCE (len 5) with OID
///   `1.3.101.112` (`06 03 2b 65 70` = id-Ed25519, RFC 8410 §3).
/// - `04 22`            OCTET STRING (len 0x22 = 34) holding the `privateKey`.
/// - `04 20`            inner OCTET STRING (len 0x20 = 32): the `CurvePrivateKey`
///   wrapper around the raw seed that follows.
const PKCS8_ED25519_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// Length of the PKCS#8 DER (`OneAsymmetricKey`) encoding of an Ed25519 seed.
const PKCS8_ED25519_LEN: usize = PKCS8_ED25519_PREFIX.len() + ED25519_SEED_LEN;

/// Encode a 32-byte raw Ed25519 `seed` as its 48-byte PKCS#8 DER
/// (`OneAsymmetricKey`, RFC 8410 §7) form: the fixed [`PKCS8_ED25519_PREFIX`]
/// followed by the seed. Panic/index-free: capacity-reserved `extend_from_slice`.
fn ed25519_seed_to_pkcs8_der(seed: &[u8; ED25519_SEED_LEN]) -> Vec<u8> {
    let mut der = Vec::with_capacity(PKCS8_ED25519_LEN);
    der.extend_from_slice(&PKCS8_ED25519_PREFIX);
    der.extend_from_slice(seed);
    der
}

/// AES key length for the ephemeral BYOK wrapping key (AES-256-KWP).
const WRAP_AES_LEN: usize = 32;

/// Which engine mount an HTTP path is resolved against.
///
/// The catalog `engine` (Transit vs KV-v2) selects this: transit key ops are
/// op-relative under the configured transit mount, whereas KV-v2 locators are
/// the catalog `path` itself, already carrying their own mount.
///
/// For a transit key the catalog `path` is the **bare key name** (`web-tls`),
/// not the `keys/<name>` HTTP sub-path (§2.2/§2.3). Each op method composes the
/// verb-specific sub-path itself (`sign/<name>`, `keys/<name>`, `encrypt/<name>`,
/// …); the bug fixed in `vault-w3n` was a catalog that stored `transit/keys/<name>`
/// as the path, which made `sign/transit/keys/<name>` resolve to a 404 against a
/// a live Vault server (the live verb path is `/v1/<transit_mount>/sign/<name>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mount {
    /// Prepend the configured transit mount (`/v1/<transit_mount>/<rel>`).
    Transit,
    /// The path is already mount-qualified; use it verbatim (`/v1/<path>`).
    KvAbsolute,
}

/// HTTP client bound to a single transit engine mount.
pub struct TransitClient {
    http: reqwest::Client,
    /// Base address, e.g. `http://127.0.0.1:8200` (no trailing slash).
    addr: String,
    mount: String,
}

impl TransitClient {
    pub(crate) fn new(http: reqwest::Client, addr: &str, mount: &str) -> Self {
        Self {
            http,
            addr: addr.trim_end_matches('/').to_string(),
            mount: mount.to_string(),
        }
    }

    /// Build a request URL for `path`, prefixed with the engine `mount` per
    /// [`Mount`].
    ///
    /// Transit ops ([`Mount::Transit`]) pass an op-relative path (`sign/<id>`,
    /// `keys/<id>`, …) that the **transit** mount is prepended to, giving
    /// `/v1/<transit_mount>/<rel>`. KV-v2 ops ([`Mount::KvAbsolute`]) pass the
    /// catalog `path` verbatim: that locator is **already** mount-qualified
    /// (e.g. `secret/data/web/value`), so the transit mount must NOT be prepended
    /// or the request would route to `/v1/transit/secret/data/...` (vault-0js).
    fn url(&self, mount: Mount, path: &str) -> String {
        self.url_with_query(mount, path, None)
    }

    fn url_with_query(&self, mount: Mount, path: &str, query: Option<&str>) -> String {
        let mut url = match mount {
            Mount::Transit => format!(
                "{}/v1/{}/{}",
                self.addr,
                encode_path(&self.mount),
                encode_path(path)
            ),
            Mount::KvAbsolute => format!("{}/v1/{}", self.addr, encode_path(path)),
        };
        if let Some(query) = query {
            url.push('?');
            url.push_str(query);
        }
        url
    }

    fn url_segments(&self, mount: Mount, segments: &[&str]) -> String {
        match mount {
            Mount::Transit => format!(
                "{}/v1/{}/{}",
                self.addr,
                encode_path(&self.mount),
                encode_segments(segments)
            ),
            Mount::KvAbsolute => format!("{}/v1/{}", self.addr, encode_segments(segments)),
        }
    }

    async fn post_at(
        &self,
        mount: Mount,
        token: &str,
        path: &str,
        body: Value,
    ) -> Result<Option<Value>, BackendError> {
        let resp = self
            .http
            .post(self.url(mount, path))
            .header("X-Vault-Token", token)
            .json(&body)
            .send()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;
        read_body(resp).await
    }

    async fn post_at_segments(
        &self,
        mount: Mount,
        token: &str,
        segments: &[&str],
        body: Value,
    ) -> Result<Option<Value>, BackendError> {
        let resp = self
            .http
            .post(self.url_segments(mount, segments))
            .header("X-Vault-Token", token)
            .json(&body)
            .send()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;
        read_body(resp).await
    }

    async fn get(&self, token: &str, path: &str) -> Result<Value, BackendError> {
        self.get_at(Mount::Transit, token, path).await
    }

    async fn get_at(&self, mount: Mount, token: &str, path: &str) -> Result<Value, BackendError> {
        let resp = self
            .http
            .get(self.url(mount, path))
            .header("X-Vault-Token", token)
            .send()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;
        read_body(resp)
            .await?
            .ok_or_else(|| BackendError::Protocol("empty body where JSON expected".into()))
    }

    async fn get_at_segments(
        &self,
        mount: Mount,
        token: &str,
        segments: &[&str],
    ) -> Result<Value, BackendError> {
        let resp = self
            .http
            .get(self.url_segments(mount, segments))
            .header("X-Vault-Token", token)
            .send()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;
        read_body(resp)
            .await?
            .ok_or_else(|| BackendError::Protocol("empty body where JSON expected".into()))
    }

    async fn get_at_query(
        &self,
        mount: Mount,
        token: &str,
        path: &str,
        query: Option<&str>,
    ) -> Result<Value, BackendError> {
        let resp = self
            .http
            .get(self.url_with_query(mount, path, query))
            .header("X-Vault-Token", token)
            .send()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;
        read_body(resp)
            .await?
            .ok_or_else(|| BackendError::Protocol("empty body where JSON expected".into()))
    }

    /// Like [`Self::get_at`], but returns the **raw** response body as a
    /// [`Zeroizing`] `String` instead of a parsed `Value`. Used by the SECRET KV
    /// read ([`Self::kv_get_secret`]): when the body carries key material, the big
    /// JSON text must be wiped on drop rather than left in a plain `String`. A
    /// non-success status is classified the same way [`read_body`] does (a 404 is
    /// `KeyNotFound`), but the error message does NOT echo the body (no key bytes
    /// in errors).
    async fn get_at_text(
        &self,
        mount: Mount,
        token: &str,
        path: &str,
        query: Option<&str>,
    ) -> Result<Zeroizing<String>, BackendError> {
        let resp = self
            .http
            .get(self.url_with_query(mount, path, query))
            .header("X-Vault-Token", token)
            .send()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;
        let status = resp.status();
        let text = Zeroizing::new(
            resp.text()
                .await
                .map_err(|e| BackendError::Transport(e.to_string()))?,
        );
        if status.is_success() {
            return Ok(text);
        }
        // Never echo the body into the error (it may carry key material); classify
        // by status only, mirroring `read_body`'s 404 -> KeyNotFound split.
        /* ubs:ignore */
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(BackendError::KeyNotFound(format!("HTTP {status}")));
        }
        Err(BackendError::Backend(format!("HTTP {status}")))
    }

    /// Create a new key and read back its public half.
    pub(crate) async fn new_key(
        &self,
        token: &str,
        key_type: KeyType,
    ) -> Result<NewKey, BackendError> {
        let vault_type =
            transit_key_type(key_type).ok_or(BackendError::UnsupportedKeyType(key_type))?;

        // Server assigns the id; transit key names must be path-safe.
        let key_id = format!("sv-{}", Uuid::new_v4().simple());
        self.post_at_segments(
            Mount::Transit,
            token,
            &["keys", &key_id],
            json!({ "type": vault_type }),
        )
        .await?;

        let public_key = self.read_public_key(token, &key_id).await?;
        Ok(NewKey { key_id, public_key })
    }

    /// Create a transit key **at a named path** (`key_id` = the catalog transit
    /// key name), rather than the server-assigned `sv-<uuid>` [`Self::new_key`]
    /// uses. This is the reconcile (`vault-zrg`) `generate` path for a crypto key:
    /// the key must exist at the exact catalog `path` so later `sign`/`encrypt`
    /// ops resolve to it. Reads back the public half on success.
    pub(crate) async fn create_named_key(
        &self,
        token: &str,
        key_id: &str,
        key_type: KeyType,
    ) -> Result<NewKey, BackendError> {
        let vault_type =
            transit_key_type(key_type).ok_or(BackendError::UnsupportedKeyType(key_type))?;
        self.post_at_segments(
            Mount::Transit,
            token,
            &["keys", key_id],
            json!({ "type": vault_type }),
        )
        .await?;
        let public_key = self.read_public_key(token, key_id).await?;
        Ok(NewKey {
            key_id: key_id.to_string(),
            public_key,
        })
    }

    /// Create a transit **symmetric AEAD** key at a named path. AEAD suites
    /// (`aes256-gcm96`, `chacha20-poly1305`) are not wire [`KeyType`]s, so the
    /// reconcile `generate` path passes the transit type string directly. Unlike a
    /// signing key there is no public half to read back; success means the key now
    /// exists at `key_id`.
    pub(crate) async fn create_named_aead(
        &self,
        token: &str,
        key_id: &str,
        vault_type: &str,
    ) -> Result<(), BackendError> {
        self.post_at_segments(
            Mount::Transit,
            token,
            &["keys", key_id],
            json!({ "type": vault_type }),
        )
        .await?;
        Ok(())
    }

    /// Read the latest public key bytes for `key_id` (for Ed25519, 32 raw bytes).
    pub(crate) async fn read_public_key(
        &self,
        token: &str,
        key_id: &str,
    ) -> Result<Vec<u8>, BackendError> {
        let info = self
            .get_at_segments(Mount::Transit, token, &["keys", key_id])
            .await?;
        let data = key_data(&info)?;
        public_key_bytes(data)
    }

    /// Read **every live version's** public key, keyed by version number.
    ///
    /// Transit returns the whole `data.keys` map (`"<version>": { public_key, …
    /// }`) on a single `GET keys/<name>`, so this is one round-trip for all
    /// versions. Used by the rotation/grace-aware JWKS (`basil-uce.2`): the shared
    /// generator publishes one JWK per version still inside the grace window.
    /// Public material only. No private/secret bytes are read.
    pub(crate) async fn read_public_keys(
        &self,
        token: &str,
        key_id: &str,
    ) -> Result<std::collections::BTreeMap<u32, Vec<u8>>, BackendError> {
        let info = self
            .get_at_segments(Mount::Transit, token, &["keys", key_id])
            .await?;
        let data = key_data(&info)?;
        public_keys_by_version(data)
    }

    /// Read the public half **plus** metadata (algorithm + current version).
    pub(crate) async fn read_public_key_with_meta(
        &self,
        token: &str,
        key_id: &str,
    ) -> Result<PublicKey, BackendError> {
        let info = self
            .get_at_segments(Mount::Transit, token, &["keys", key_id])
            .await?;
        let data = key_data(&info)?;
        Ok(PublicKey {
            public_key: public_key_bytes(data)?,
            key_type: transit_type_to_wire(data)?,
            version: latest_version(data),
        })
    }

    /// Read value-free metadata (algorithm + latest version) for `key_id`.
    pub(crate) async fn read_key_metadata(
        &self,
        token: &str,
        key_id: &str,
    ) -> Result<KeyMetadata, BackendError> {
        let info = self
            .get_at_segments(Mount::Transit, token, &["keys", key_id])
            .await?;
        let data = key_data(&info)?;
        Ok(KeyMetadata {
            // Some transit key types (e.g. raw AEAD) have no wire `KeyType`; a key
            // we don't map is reported as type-absent rather than failing `list`.
            key_type: transit_type_to_wire(data).ok(),
            latest_version: latest_version(data),
        })
    }

    /// `IMPORT` (BYOK) provisions transit key `key_id` from caller material.
    ///
    /// Performs the transit BYOK wrapping handshake: fetch the engine's RSA
    /// wrapping key, AES-KWP-wrap the PKCS#8 DER target under a fresh ephemeral
    /// AES-256 key, RSA-OAEP(SHA-256)-wrap that AES key, concatenate, and `POST`
    /// to `keys/<name>/import`. A raw Ed25519 seed is first encoded as PKCS#8 DER
    /// (transit requires that for `type=ed25519`); a supplied PKCS#8 DER is used
    /// verbatim. The material is never written in the clear and the reply carries
    /// only the public half.
    pub(crate) async fn import(
        &self,
        token: &str,
        key_id: &str,
        key_type: KeyType,
        material: &KeyMaterial,
    ) -> Result<NewKey, BackendError> {
        let vault_type =
            transit_key_type(key_type).ok_or(BackendError::UnsupportedKeyType(key_type))?;

        let pkcs8_der = import_target_pkcs8_der(key_type, material)?;

        let wrapping_pem = self.wrapping_key(token).await?;
        let ciphertext = wrap_for_import(&wrapping_pem, &pkcs8_der)?;

        self.post_at_segments(
            Mount::Transit,
            token,
            &["keys", key_id, "import"],
            json!({
                "type": vault_type,
                "hash_function": "SHA256",
                "ciphertext": ciphertext,
            }),
        )
        .await?;

        let public_key = self.read_public_key(token, key_id).await?;
        Ok(NewKey {
            key_id: key_id.to_string(),
            public_key,
        })
    }

    /// Fetch the transit engine's RSA wrapping key (SPKI PEM) for BYOK import.
    async fn wrapping_key(&self, token: &str) -> Result<String, BackendError> {
        let info = self.get(token, "wrapping_key").await?;
        key_data(&info)?
            .get("public_key")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| BackendError::Protocol("no public_key in wrapping_key".into()))
    }

    pub(crate) async fn sign(
        &self,
        token: &str,
        key_id: &str,
        message: &[u8],
    ) -> Result<Vec<u8>, BackendError> {
        self.sign_with_options(token, key_id, message, SignOptions::Default)
            .await
    }

    pub(crate) async fn sign_with_options(
        &self,
        token: &str,
        key_id: &str,
        message: &[u8],
        options: SignOptions,
    ) -> Result<Vec<u8>, BackendError> {
        let body = sign_body(message, options);
        let resp = self
            .post_at_segments(Mount::Transit, token, &["sign", key_id], body)
            .await?
            .ok_or_else(|| BackendError::Protocol("empty sign response".into()))?;
        let sig = resp
            .get("data")
            .and_then(|d| d.get("signature"))
            .and_then(Value::as_str)
            .ok_or_else(|| BackendError::Protocol("no signature in response".into()))?;
        // "vault:v1:<base64>" -> raw bytes.
        let b64 = sig
            .rsplit(':')
            .next()
            .ok_or_else(|| BackendError::Protocol("malformed signature".into()))?;
        let signature = B64
            .decode(b64)
            .map_err(|e| BackendError::Protocol(format!("signature not base64: {e}")))?;
        normalize_signature_for_client(&signature, options)
    }

    pub(crate) async fn verify(
        &self,
        token: &str,
        key_id: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, BackendError> {
        self.verify_with_options(token, key_id, message, signature, SignOptions::Default)
            .await
    }

    pub(crate) async fn verify_with_options(
        &self,
        token: &str,
        key_id: &str,
        message: &[u8],
        signature: &[u8],
        options: SignOptions,
    ) -> Result<bool, BackendError> {
        let signature = signature_for_transit(signature, options)?;
        let vault_sig = format!("vault:v{}:{}", SIG_VERSION, B64.encode(signature));
        let body = verify_body(message, &vault_sig, options);
        let resp = self
            .post_at_segments(Mount::Transit, token, &["verify", key_id], body)
            .await?
            .ok_or_else(|| BackendError::Protocol("empty verify response".into()))?;
        resp.get("data")
            .and_then(|d| d.get("valid"))
            .and_then(Value::as_bool)
            .ok_or_else(|| BackendError::Protocol("no valid flag in response".into()))
    }

    /// `ENCRYPT`: AEAD-encrypt `plaintext` under `key_id`'s latest version.
    ///
    /// Transit owns the nonce (we never send one); it returns the ciphertext as
    /// `vault:vN:<base64>`. We strip the `vault:vN:` wrapper exactly as signatures
    /// do, put the opaque transit blob in [`CiphertextEnvelope::ciphertext`], and
    /// set `key_version = N`. Transit embeds the nonce inside that blob, so the
    /// envelope `nonce` stays **empty** (documented invariant; `decrypt`
    /// reconstructs the wrapper from `alg`+`key_version`+`ciphertext`, never the
    /// `nonce`).
    pub(crate) async fn encrypt(
        &self,
        token: &str,
        key_id: &str,
        algorithm: AeadAlgorithm,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<CiphertextEnvelope, BackendError> {
        let mut body = json!({ "plaintext": B64.encode(plaintext) });
        if let Some(aad) = aad {
            insert(&mut body, "associated_data", Value::String(B64.encode(aad)));
        }
        let resp = self
            .post_at_segments(Mount::Transit, token, &["encrypt", key_id], body)
            .await?
            .ok_or_else(|| BackendError::Protocol("empty encrypt response".into()))?;
        let wrapped = resp
            .get("data")
            .and_then(|d| d.get("ciphertext"))
            .and_then(Value::as_str)
            .ok_or_else(|| BackendError::Protocol("no ciphertext in encrypt response".into()))?;
        let (key_version, ciphertext) = split_vault_wrapped(wrapped)?;
        Ok(CiphertextEnvelope {
            alg: algorithm,
            key_version,
            // Transit embeds the nonce in its opaque ciphertext; we carry none.
            nonce: Vec::new(),
            ciphertext,
        })
    }

    /// `DECRYPT` AEAD-decrypts `envelope` under `key_id`.
    ///
    /// Re-applies the `vault:vN:` wrapper from the envelope's `key_version` +
    /// opaque `ciphertext` (the inverse of [`Self::encrypt`]); transit selects the
    /// right key version itself and reads the embedded nonce. A tag/AAD/version
    /// mismatch is reported by transit as a 4xx, which we collapse to the opaque
    /// [`BackendError::DecryptFailed`] (no oracle).
    pub(crate) async fn decrypt(
        &self,
        token: &str,
        key_id: &str,
        envelope: &CiphertextEnvelope,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, BackendError> {
        let wrapped = format!(
            "vault:v{}:{}",
            envelope.key_version,
            B64.encode(&envelope.ciphertext)
        );
        let mut body = json!({ "ciphertext": wrapped });
        if let Some(aad) = aad {
            insert(&mut body, "associated_data", Value::String(B64.encode(aad)));
        }
        let resp = match self
            .post_at_segments(Mount::Transit, token, &["decrypt", key_id], body)
            .await
        {
            Ok(resp) => {
                resp.ok_or_else(|| BackendError::Protocol("empty decrypt response".into()))?
            }
            // A reachable backend that *rejects* the decrypt (bad tag / AAD /
            // pruned version) is an opaque DecryptFailed, never a leaky message.
            Err(BackendError::Backend(_)) => return Err(BackendError::DecryptFailed),
            Err(other) => return Err(other),
        };
        let pt_b64 = resp
            .get("data")
            .and_then(|d| d.get("plaintext"))
            .and_then(Value::as_str)
            .ok_or_else(|| BackendError::Protocol("no plaintext in decrypt response".into()))?;
        B64.decode(pt_b64).map_err(|_| BackendError::DecryptFailed)
    }

    /// `ROTATE`: bump the transit key version, returning the new latest version.
    pub(crate) async fn rotate(&self, token: &str, key_id: &str) -> Result<u32, BackendError> {
        self.post_at_segments(
            Mount::Transit,
            token,
            &["keys", key_id, "rotate"],
            json!({}),
        )
        .await?;
        let info = self
            .get_at_segments(Mount::Transit, token, &["keys", key_id])
            .await?;
        Ok(latest_version(key_data(&info)?))
    }

    /// Configure the transit version window: `min_decryption_version` (grace
    /// floor) and/or `min_available_version` (retention floor). A `None` field is
    /// omitted from the request so transit leaves it unchanged.
    pub(crate) async fn configure_versions(
        &self,
        token: &str,
        key_id: &str,
        min_decryption_version: Option<u32>,
        min_available_version: Option<u32>,
    ) -> Result<(), BackendError> {
        let mut body = json!({});
        if let Some(v) = min_decryption_version {
            insert(&mut body, "min_decryption_version", Value::from(v));
        }
        if let Some(v) = min_available_version {
            insert(&mut body, "min_available_version", Value::from(v));
        }
        self.post_at_segments(Mount::Transit, token, &["keys", key_id, "config"], body)
            .await?;
        Ok(())
    }

    /// Read a KV-v2 value for `key_id`, returning `(value_bytes, version)`.
    ///
    /// `key_id` is the catalog `path` (the KV-v2 data path, e.g.
    /// `secret/data/web/value`); `version = None` reads the latest version,
    /// `Some(v)` reads that specific version (`?version=`). The value is the
    /// base64 `value` field [`Self::kv_put`] wrote, decoded back to raw bytes so
    /// any byte string round-trips losslessly. A KV-v2 read nests the stored
    /// fields under `data.data` and the version under `data.metadata.version`.
    pub(crate) async fn kv_get(
        &self,
        token: &str,
        key_id: &str,
        version: Option<u32>,
    ) -> Result<super::KvValue, BackendError> {
        let query = version.map(|v| format!("version={v}"));
        // `key_id` is the catalog KV path (`secret/data/<p>`), already
        // mount-qualified: resolve it absolutely, NOT under the transit mount.
        let resp = self
            .get_at_query(Mount::KvAbsolute, token, key_id, query.as_deref())
            .await?;
        // KV-v2 read shape: { data: { data: { value: <b64> }, metadata: { version } } }.
        let data = resp
            .get("data")
            .ok_or_else(|| BackendError::Protocol("missing data in kv read".into()))?;
        let value_b64 = data
            .get("data")
            .and_then(|d| d.get("value"))
            .and_then(Value::as_str)
            .ok_or_else(|| BackendError::Protocol("no value field in kv read".into()))?;
        let value = B64
            .decode(value_b64)
            .map_err(|e| BackendError::Protocol(format!("kv value not base64: {e}")))?;
        let version = data
            .get("metadata")
            .and_then(|m| m.get("version"))
            .and_then(Value::as_u64)
            .map_or_else(
                || version.unwrap_or(1),
                |v| u32::try_from(v).unwrap_or(u32::MAX),
            );
        Ok(super::KvValue { value, version })
    }

    /// Read a KV-v2 value for `key_id` as a SECRET: the decoded bytes wrapped in
    /// [`Zeroizing`] end-to-end, with no plain `String`/`Vec`/`KvValue` owner of
    /// the secret surviving the call.
    ///
    /// Custody chain: the raw HTTP body is read into a [`Zeroizing`] `String`
    /// (wipes the big JSON text on drop); the base64 `data.data.value` field is
    /// extracted into a fresh [`Zeroizing`] `String` and the parsed `Value` is
    /// dropped immediately (its transient b64 residue is the irreducible serde
    /// cost: minimized, not retained); that `Zeroizing` `String` is base64-decoded
    /// into the returned [`Zeroizing`] `Vec<u8>`. Serves the materialize paths
    /// (the value is a private key) and the value-class `get` (the value is a
    /// stored secret, security review finding 17).
    pub(crate) async fn kv_get_secret(
        &self,
        token: &str,
        key_id: &str,
        version: Option<u32>,
    ) -> Result<super::KvSecret, BackendError> {
        let query = version.map(|v| format!("version={v}"));
        // Read the body as zeroizing text (wipes the JSON, which holds the b64 key).
        let body = self
            .get_at_text(Mount::KvAbsolute, token, key_id, query.as_deref())
            .await?;
        // Extract the base64 value into a zeroizing String, then drop the Value
        // immediately so the transient b64 residue inside serde's tree is wiped as
        // soon as possible (the body text is wiped when `body` drops at fn end).
        let (value_b64, read_version): (Zeroizing<String>, u32) = {
            let parsed: Value = serde_json::from_str(&body)
                .map_err(|e| BackendError::Protocol(format!("kv read not JSON: {e}")))?;
            let data = parsed
                .get("data")
                .ok_or_else(|| BackendError::Protocol("missing data in kv read".into()))?;
            let b64 = data
                .get("data")
                .and_then(|d| d.get("value"))
                .and_then(Value::as_str)
                .ok_or_else(|| BackendError::Protocol("no value field in kv read".into()))?;
            let read_version = data
                .get("metadata")
                .and_then(|m| m.get("version"))
                .and_then(Value::as_u64)
                .map_or_else(
                    || version.unwrap_or(1),
                    |v| u32::try_from(v).unwrap_or(u32::MAX),
                );
            (Zeroizing::new(b64.to_string()), read_version)
            // `parsed` (and its inner b64 String) drops here.
        };
        let value = Zeroizing::new(
            B64.decode(value_b64.as_bytes())
                // Do NOT echo decode detail (could leak material); fixed message.
                .map_err(|_| BackendError::Protocol("kv value not base64".into()))?,
        );
        Ok(super::KvSecret {
            value,
            version: read_version,
        })
    }

    /// Write `value` as a fresh KV-v2 version of `key_id`, returning the new
    /// version. `key_id` is the catalog `path` (the KV-v2 data path, already
    /// mount-qualified, e.g. `secret/data/<p>`), resolved absolutely so the write
    /// hits the KV mount rather than being prefixed with the transit mount.
    pub(crate) async fn kv_put(
        &self,
        token: &str,
        key_id: &str,
        value: &[u8],
    ) -> Result<u32, BackendError> {
        // KV-v2 stores a JSON object under `data`; the broker keeps one opaque
        // field (`value`, base64) so any byte string round-trips losslessly.
        let body = json!({ "data": { "value": B64.encode(value) } });
        // `key_id` is the catalog KV path (`secret/data/<p>`), already
        // mount-qualified: resolve it absolutely, NOT under the transit mount.
        let resp = self
            .post_at(Mount::KvAbsolute, token, key_id, body)
            .await?
            .ok_or_else(|| BackendError::Protocol("empty kv write response".into()))?;
        let v = resp
            .get("data")
            .and_then(|d| d.get("version"))
            .and_then(Value::as_u64)
            .ok_or_else(|| BackendError::Protocol("no version in kv write response".into()))?;
        Ok(u32::try_from(v).unwrap_or(u32::MAX))
    }
}

/// Build the transit import target. Transit expects PKCS#8 DER private material
/// for every asymmetric import type; the CLI's raw seed shortcut is Ed25519-only
/// and is encoded into PKCS#8 before wrapping.
fn import_target_pkcs8_der(
    key_type: KeyType,
    material: &KeyMaterial,
) -> Result<Vec<u8>, BackendError> {
    match (key_type, material) {
        (KeyType::Ed25519 | KeyType::Ed25519Nkey, KeyMaterial::Ed25519Seed(seed)) => {
            let seed: &[u8; ED25519_SEED_LEN] = seed.as_slice().try_into().map_err(|_| {
                BackendError::Backend(format!(
                    "ed25519 seed must be {ED25519_SEED_LEN} bytes, got {}",
                    seed.len()
                ))
            })?;
            Ok(ed25519_seed_to_pkcs8_der(seed))
        }
        (_, KeyMaterial::Pkcs8Der(der)) => Ok(der.clone()),
        // Any non-Ed25519 key type with raw seed material: raw seeds are
        // Ed25519-only (RSA/ECDSA need PKCS#8 DER; post-quantum keys are not
        // BYOK-imported through transit at all).
        (_, KeyMaterial::Ed25519Seed(_)) => Err(BackendError::Backend(format!(
            "import key type `{key_type}` requires PKCS#8 DER material; raw seed material is Ed25519-only"
        ))),
    }
}

/// The transit key `type` string for an AEAD suite, used by the reconcile
/// `generate` path to create a symmetric key at its catalog name. Transit names
/// AES-256-GCM `aes256-gcm96` (a 96-bit nonce convergent variant) and
/// ChaCha20-Poly1305 `chacha20-poly1305`.
pub const fn transit_aead_type(aead: AeadAlgorithm) -> &'static str {
    match aead {
        AeadAlgorithm::Aes256Gcm => "aes256-gcm96",
        AeadAlgorithm::Chacha20Poly1305 => "chacha20-poly1305",
    }
}

fn encode_path(path: &str) -> String {
    let mut encoded = String::new();
    for (index, segment) in path.split('/').enumerate() {
        if index > 0 {
            encoded.push('/');
        }
        encoded.push_str(&utf8_percent_encode(segment, VAULT_PATH_SEGMENT_ENCODE_SET).to_string());
    }
    encoded
}

fn encode_segments(segments: &[&str]) -> String {
    let mut encoded = String::new();
    for (index, segment) in segments.iter().enumerate() {
        if index > 0 {
            encoded.push('/');
        }
        encoded.push_str(&utf8_percent_encode(segment, VAULT_PATH_SEGMENT_ENCODE_SET).to_string());
    }
    encoded
}

/// The transit key `type` string for asymmetric wire key types, or `None` for a
/// key type transit cannot create natively.
///
/// Capability gating happens before dispatch in [`crate::manager::BackendManager`]
/// from the catalog backend's static `mintKeyTypes` preset (br basil-wpp.4). This
/// helper is only the mechanical wire-to-transit spelling map. The post-quantum
/// families (`ml-dsa-*`, `ml-kem-*`) have no classical transit `type`: they are
/// software-custodied through the crypto provider, so they map to `None` and the
/// caller fails closed with [`BackendError::UnsupportedKeyType`].
const fn transit_key_type(key_type: KeyType) -> Option<&'static str> {
    match key_type {
        KeyType::Ed25519 | KeyType::Ed25519Nkey => Some("ed25519"),
        KeyType::Rsa2048 => Some("rsa-2048"),
        KeyType::EcdsaP256 => Some("ecdsa-p256"),
        KeyType::EcdsaP384 => Some("ecdsa-p384"),
        KeyType::EcdsaP521 => Some("ecdsa-p521"),
        KeyType::MlDsa44
        | KeyType::MlDsa65
        | KeyType::MlDsa87
        | KeyType::MlKem512
        | KeyType::MlKem768
        | KeyType::MlKem1024 => None,
    }
}

/// Insert `key`→`value` into a JSON object body, ignoring a non-object body
/// (the bodies here are always built as `json!({…})`, so this never drops data).
fn insert(body: &mut Value, key: &str, value: Value) {
    if let Some(obj) = body.as_object_mut() {
        obj.insert(key.to_string(), value);
    }
}

/// Build the transit `sign` request body.
///
/// The `Default` mode sends only `input`: no `prehashed`, no `hash_algorithm`.
/// For an Ed25519 transit key that signs the bytes **as the raw message** (`EdDSA` is
/// not pre-hashed), which is the contract the NATS remote-signer relies on: a client
/// passes the server nonce verbatim and uses the signature to connect, so the user
/// seed never leaves the vault. `Rs256Pkcs1v15Sha256` is the SVID/JWS RSA path.
fn sign_body(message: &[u8], options: SignOptions) -> Value {
    let mut body = json!({ "input": B64.encode(message) });
    insert_sign_options(&mut body, options);
    body
}

/// Build the transit `verify` request body.
fn verify_body(message: &[u8], vault_sig: &str, options: SignOptions) -> Value {
    let mut body = json!({
        "input": B64.encode(message),
        "signature": vault_sig,
    });
    insert_sign_options(&mut body, options);
    body
}

fn insert_sign_options(body: &mut Value, options: SignOptions) {
    if options == SignOptions::Rs256Pkcs1v15Sha256 {
        insert(
            body,
            "signature_algorithm",
            Value::String("pkcs1v15".to_string()),
        );
        insert(
            body,
            "hash_algorithm",
            Value::String("sha2-256".to_string()),
        );
    } else if matches!(
        options,
        SignOptions::Es256 | SignOptions::Es384 | SignOptions::Es512
    ) {
        let hash = match options {
            SignOptions::Es256 => "sha2-256",
            SignOptions::Es384 => "sha2-384",
            SignOptions::Es512 => "sha2-512",
            SignOptions::Default | SignOptions::Rs256Pkcs1v15Sha256 => return,
        };
        insert(body, "hash_algorithm", Value::String(hash.to_string()));
    }
}

fn normalize_signature_for_client(
    signature: &[u8],
    options: SignOptions,
) -> Result<Vec<u8>, BackendError> {
    ecdsa_der_to_raw(signature, options)
}

fn signature_for_transit(signature: &[u8], options: SignOptions) -> Result<Vec<u8>, BackendError> {
    ecdsa_raw_to_der(signature, options)
}

/// Split a transit `vault:vN:<base64>` blob into `(N, raw_bytes)`.
///
/// The same `vault:vN:` framing transit uses for signatures wraps AEAD
/// ciphertext; this is the shared strip step (the inverse of the re-apply in
/// [`TransitClient::decrypt`]).
fn split_vault_wrapped(wrapped: &str) -> Result<(u32, Vec<u8>), BackendError> {
    // Expect exactly `vault:v<digits>:<base64>` (the base64 itself has no ':').
    let mut parts = wrapped.splitn(3, ':');
    let scheme = parts.next();
    let version = parts.next();
    let b64 = parts.next();
    let (Some("vault"), Some(version), Some(b64)) = (scheme, version, b64) else {
        return Err(BackendError::Protocol(format!(
            "malformed transit ciphertext `{wrapped}`"
        )));
    };
    let version = version
        .strip_prefix('v')
        .and_then(|n| n.parse::<u32>().ok())
        .ok_or_else(|| BackendError::Protocol(format!("bad version in `{wrapped}`")))?;
    let bytes = B64
        .decode(b64)
        .map_err(|e| BackendError::Protocol(format!("transit ciphertext not base64: {e}")))?;
    Ok((version, bytes))
}

/// The `data` object of a transit key-info response, or a protocol error.
fn key_data(info: &Value) -> Result<&Value, BackendError> {
    info.get("data")
        .ok_or_else(|| BackendError::Protocol("missing data in key info".into()))
}

/// The latest transit key version (defaults to 1 if the field is absent).
fn latest_version(data: &Value) -> u32 {
    let v = data
        .get("latest_version")
        .and_then(Value::as_u64)
        .unwrap_or(1);
    u32::try_from(v).unwrap_or(u32::MAX)
}

/// The raw public key bytes of the latest version from a transit key-info `data`.
fn public_key_bytes(data: &Value) -> Result<Vec<u8>, BackendError> {
    let latest = latest_version(data);
    let pk_b64 = data
        .get("keys")
        .and_then(|k| k.get(latest.to_string()))
        .and_then(|v| v.get("public_key"))
        .and_then(Value::as_str)
        .ok_or_else(|| BackendError::Protocol("no public_key in key info".into()))?;
    public_key_field_bytes(pk_b64)
}

/// Every version's public key from a transit key-info `data`, keyed by version.
///
/// The transit `data.keys` map is `{ "<version>": { "public_key": "<b64|pem>", …
/// } }`. Each entry with a parseable `public_key` field is decoded; an entry
/// without one (e.g. a symmetric AEAD version) is skipped rather than failing the
/// whole read. An empty result is itself a protocol error (an asymmetric key with
/// no published public material).
fn public_keys_by_version(
    data: &Value,
) -> Result<std::collections::BTreeMap<u32, Vec<u8>>, BackendError> {
    let keys = data
        .get("keys")
        .and_then(Value::as_object)
        .ok_or_else(|| BackendError::Protocol("no keys map in key info".into()))?;
    let mut out = std::collections::BTreeMap::new();
    for (version_str, entry) in keys {
        let Ok(version) = version_str.parse::<u32>() else {
            continue;
        };
        if let Some(pk) = entry.get("public_key").and_then(Value::as_str) {
            out.insert(version, public_key_field_bytes(pk)?);
        }
    }
    if out.is_empty() {
        return Err(BackendError::Protocol(
            "no public_key in any key version".into(),
        ));
    }
    Ok(out)
}

fn public_key_field_bytes(public_key: &str) -> Result<Vec<u8>, BackendError> {
    let trimmed = public_key.trim();
    if trimmed.starts_with("-----BEGIN ") {
        return Ok(trimmed.as_bytes().to_vec());
    }
    B64.decode(trimmed)
        .map_err(|e| BackendError::Protocol(format!("public_key not base64: {e}")))
}

/// Map the transit `data.type` string onto the wire [`KeyType`].
///
/// Returns [`BackendError::UnsupportedKeyType`]-adjacent protocol info for a
/// transit type the wire has no `KeyType` for (e.g. raw AEAD keys).
fn transit_type_to_wire(data: &Value) -> Result<KeyType, BackendError> {
    let ty = data
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| BackendError::Protocol("no type in key info".into()))?;
    match ty {
        "ed25519" => Ok(KeyType::Ed25519),
        // rsa-2048/3072/4096 all map to the single wire rsa-2048 today.
        "rsa-2048" | "rsa-3072" | "rsa-4096" => Ok(KeyType::Rsa2048),
        "ecdsa-p256" => Ok(KeyType::EcdsaP256),
        "ecdsa-p384" => Ok(KeyType::EcdsaP384),
        "ecdsa-p521" => Ok(KeyType::EcdsaP521),
        other => Err(BackendError::Protocol(format!(
            "transit key type `{other}` has no wire KeyType"
        ))),
    }
}

/// Build the transit BYOK import `ciphertext`: AES-KWP-wrap `target` under a
/// fresh AES-256 key, RSA-OAEP(SHA-256)-wrap that key under `wrapping_pem`, and
/// concatenate `rsa_wrapped_aes || kwp_wrapped_target` (the transit import
/// contract), base64-encoded.
fn wrap_for_import(wrapping_pem: &str, target: &[u8]) -> Result<String, BackendError> {
    let rsa_pub = RsaPublicKey::from_public_key_pem(wrapping_pem)
        .map_err(|e| BackendError::Protocol(format!("wrapping key not SPKI PEM: {e}")))?;

    // Fresh ephemeral AES-256 key, used once to KWP-wrap the target.
    let mut aes_key = [0u8; WRAP_AES_LEN];
    rand::thread_rng().fill_bytes(&mut aes_key);

    // AES-KWP output is ceil(len/8)*8 + 8 bytes (one extra semiblock for the IV).
    let mut wrapped_target = vec![0u8; target.len().div_ceil(8) * 8 + 8];
    let kek = KwpAes256::new(&aes_key.into());
    let wrapped_target = kek
        .wrap_key(target, &mut wrapped_target)
        .map_err(|e| BackendError::Backend(format!("aes-kwp wrap failed: {e}")))?;

    // RSA-OAEP-SHA256 wrap of the ephemeral AES key.
    let wrapped_aes = rsa_pub
        .encrypt(&mut rand::thread_rng(), Oaep::new::<Sha256>(), &aes_key)
        .map_err(|e| BackendError::Backend(format!("rsa-oaep wrap failed: {e}")))?;
    // The ephemeral wrapping key has done its job; scrub it.
    aes_key.zeroize();

    let mut blob = wrapped_aes;
    blob.extend_from_slice(wrapped_target);
    Ok(B64.encode(&blob))
}

/// Turn a vault HTTP response into its parsed JSON body (or `None` for an empty
/// `204`-style success), classifying failures into a [`BackendError`].
///
/// Shared with the SPIFFE login exchange, which parses the `auth` block.
pub async fn read_body(resp: reqwest::Response) -> Result<Option<Value>, BackendError> {
    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| BackendError::Transport(e.to_string()))?;

    if !status.is_success() {
        let msg = serde_json::from_str::<Value>(&text)
            .ok()
            .and_then(|v| {
                v.get("errors").and_then(Value::as_array).map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join("; ")
                })
            })
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| format!("HTTP {status}"));
        // A 404 is the backend's authoritative "this key/path is absent" signal
        // (a reachable engine, no material), distinct from a transport failure
        // (unreachable) or any other rejection (auth/5xx). Reconcile (`vault-zrg`)
        // relies on this to tell "absent" (create per missing-policy) apart from
        // "backend down" (a fatal startup error): a 404 is `KeyNotFound`, NOT the
        // generic `Backend(_)`.
        /* ubs false positive: not a secret comparison */
        /* ubs:ignore */
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(BackendError::KeyNotFound(msg));
        }
        return Err(BackendError::Backend(msg));
    }

    if text.trim().is_empty() {
        return Ok(None);
    }
    serde_json::from_str::<Value>(&text)
        .map(Some)
        .map_err(|e| BackendError::Protocol(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> TransitClient {
        // The reqwest client is never driven in these URL-shape tests, but
        // building it still requires the default crypto provider.
        crate::ensure_crypto_provider();
        let http = reqwest::Client::new();
        TransitClient::new(http, "http://127.0.0.1:8200/", "transit")
    }

    #[test]
    fn transit_paths_are_prefixed_with_the_transit_mount() {
        let c = client();
        assert_eq!(
            c.url(Mount::Transit, "sign/sv-abc"),
            "http://127.0.0.1:8200/v1/transit/sign/sv-abc"
        );
        assert_eq!(
            c.url(Mount::Transit, "keys/sv-abc"),
            "http://127.0.0.1:8200/v1/transit/keys/sv-abc"
        );
    }

    /// Every transit op composes its verb sub-path from the **bare** catalog key
    /// name (`web-tls`), giving the live Vault wire shape
    /// `/v1/<transit_mount>/<verb>/<name>` (`vault-w3n`). A catalog that stored
    /// `transit/keys/web-tls` as the path would route `sign` to
    /// `/v1/transit/sign/transit/keys/web-tls`, a 404 against a real server.
    #[test]
    fn transit_op_paths_use_the_bare_key_name_per_verb() {
        let c = client();
        let key = "web-tls"; // catalog `path` = the bare transit key name
        // The sub-path each op method builds, mapped to the expected live URL.
        let cases = [
            (format!("sign/{key}"), "/v1/transit/sign/web-tls"),
            (format!("verify/{key}"), "/v1/transit/verify/web-tls"),
            (format!("encrypt/{key}"), "/v1/transit/encrypt/web-tls"),
            (format!("decrypt/{key}"), "/v1/transit/decrypt/web-tls"),
            (format!("keys/{key}"), "/v1/transit/keys/web-tls"),
            (
                format!("keys/{key}/rotate"),
                "/v1/transit/keys/web-tls/rotate",
            ),
            (
                format!("keys/{key}/import"),
                "/v1/transit/keys/web-tls/import",
            ),
            (
                format!("keys/{key}/config"),
                "/v1/transit/keys/web-tls/config",
            ),
        ];
        for (rel, expected_suffix) in cases {
            let url = c.url(Mount::Transit, &rel);
            assert_eq!(
                url,
                format!("http://127.0.0.1:8200{expected_suffix}"),
                "verb sub-path `{rel}` resolved to the wrong URL"
            );
            // The key name must never re-introduce the `keys/<name>` HTTP path.
            assert!(
                !url.contains("transit/sign/transit")
                    && !url.contains("/sign/keys/")
                    && !url.contains("/encrypt/keys/")
                    && !url.contains("/verify/keys/")
                    && !url.contains("/decrypt/keys/"),
                "transit verb path leaked a keys/ segment: {url}"
            );
        }
        // The shared `wrapping_key` BYOK fetch is a mount-relative singleton.
        assert_eq!(
            c.url(Mount::Transit, "wrapping_key"),
            "http://127.0.0.1:8200/v1/transit/wrapping_key"
        );
    }

    #[test]
    fn kv_paths_use_their_own_mount_not_transit() {
        let c = client();
        // The catalog KV path is already mount-qualified (`secret/data/...`); it
        // must resolve to `/v1/secret/data/...`, NOT `/v1/transit/secret/...`.
        let url = c.url(Mount::KvAbsolute, "secret/data/web/value");
        assert_eq!(url, "http://127.0.0.1:8200/v1/secret/data/web/value");
        assert!(
            !url.contains("/v1/transit/"),
            "KV path leaked through the transit mount: {url}"
        );
    }

    #[test]
    fn kv_path_with_version_query_keeps_its_mount() {
        let c = client();
        let url = c.url_with_query(
            Mount::KvAbsolute,
            "secret/data/web/value",
            Some("version=3"),
        );
        assert_eq!(
            url,
            "http://127.0.0.1:8200/v1/secret/data/web/value?version=3"
        );
        assert!(!url.contains("/v1/transit/"));
    }

    #[test]
    fn transit_key_ids_are_encoded_as_single_path_segments() {
        let c = client();
        let key = "team/key 1?active#frag";
        assert_eq!(
            c.url_segments(Mount::Transit, &["sign", key]),
            "http://127.0.0.1:8200/v1/transit/sign/team%2Fkey%201%3Factive%23frag"
        );
        assert_eq!(
            c.url_segments(Mount::Transit, &["keys", key, "config"]),
            "http://127.0.0.1:8200/v1/transit/keys/team%2Fkey%201%3Factive%23frag/config"
        );
    }

    #[test]
    fn kv_absolute_paths_encode_components_but_keep_query_separate() {
        let c = client();
        assert_eq!(
            c.url_with_query(
                Mount::KvAbsolute,
                "secret/data/team key?literal",
                Some("version=3")
            ),
            "http://127.0.0.1:8200/v1/secret/data/team%20key%3Fliteral?version=3"
        );
    }

    #[test]
    fn aead_type_maps_to_transit_key_type_names() {
        // The reconcile generate path creates a symmetric key from these strings;
        // they must be the live transit key-type spellings.
        assert_eq!(transit_aead_type(AeadAlgorithm::Aes256Gcm), "aes256-gcm96");
        assert_eq!(
            transit_aead_type(AeadAlgorithm::Chacha20Poly1305),
            "chacha20-poly1305"
        );
    }

    #[test]
    fn asymmetric_key_types_map_to_transit_key_type_names() {
        assert_eq!(transit_key_type(KeyType::Ed25519), Some("ed25519"));
        assert_eq!(transit_key_type(KeyType::Ed25519Nkey), Some("ed25519"));
        assert_eq!(transit_key_type(KeyType::Rsa2048), Some("rsa-2048"));
        assert_eq!(transit_key_type(KeyType::EcdsaP256), Some("ecdsa-p256"));
        assert_eq!(transit_key_type(KeyType::EcdsaP384), Some("ecdsa-p384"));
        assert_eq!(transit_key_type(KeyType::EcdsaP521), Some("ecdsa-p521"));
        // Post-quantum families have no classical transit type and fail closed.
        assert_eq!(transit_key_type(KeyType::MlDsa65), None);
        assert_eq!(transit_key_type(KeyType::MlKem768), None);
    }

    #[test]
    fn public_key_field_accepts_base64_or_pem() {
        assert_eq!(
            public_key_field_bytes("AQIDBA==").expect("base64 public key"),
            vec![1, 2, 3, 4]
        );
        let pem = "-----BEGIN PUBLIC KEY-----\nAQID\n-----END PUBLIC KEY-----";
        assert_eq!(
            public_key_field_bytes(pem).expect("pem public key"),
            pem.as_bytes()
        );
    }

    #[test]
    fn a_non_default_transit_mount_is_honored() {
        crate::ensure_crypto_provider();
        let http = reqwest::Client::new();
        let c = TransitClient::new(http, "http://bao:8200", "transit-prod");
        assert_eq!(
            c.url(Mount::Transit, "sign/sv-1"),
            "http://bao:8200/v1/transit-prod/sign/sv-1"
        );
        // KV stays absolute regardless of the transit mount name.
        assert_eq!(
            c.url(Mount::KvAbsolute, "secret/data/x"),
            "http://bao:8200/v1/secret/data/x"
        );
    }

    #[test]
    fn default_sign_body_uses_transit_defaults() {
        let body = sign_body(b"jwt-input", SignOptions::Default);
        assert_eq!(
            body.get("input").and_then(Value::as_str),
            Some("and0LWlucHV0")
        );
        assert!(body.get("signature_algorithm").is_none());
        assert!(body.get("hash_algorithm").is_none());
    }

    /// MF-3 contract: the default sign body carries only the raw `input`. No
    /// `prehashed`, `hash_algorithm`, or `signature_algorithm`. For an Ed25519
    /// transit key that signs the bytes directly as the message, so a NATS client
    /// can pass the server nonce verbatim and use Basil as a remote signer (the
    /// user seed never leaves the vault).
    #[test]
    fn default_sign_is_raw_message_ed25519() {
        let nonce = b"nats-server-nonce";
        let encoded = B64.encode(nonce);
        let body = sign_body(nonce, SignOptions::Default);
        assert_eq!(
            body.get("input").and_then(Value::as_str),
            Some(encoded.as_str())
        );
        assert!(body.get("prehashed").is_none());
        assert!(body.get("hash_algorithm").is_none());
        assert!(body.get("signature_algorithm").is_none());
    }

    #[test]
    fn rs256_sign_body_selects_pkcs1v15_sha256() {
        let body = sign_body(b"jwt-input", SignOptions::Rs256Pkcs1v15Sha256);
        assert_eq!(
            body.get("input").and_then(Value::as_str),
            Some("and0LWlucHV0")
        );
        assert_eq!(
            body.get("signature_algorithm").and_then(Value::as_str),
            Some("pkcs1v15")
        );
        assert_eq!(
            body.get("hash_algorithm").and_then(Value::as_str),
            Some("sha2-256")
        );
    }

    #[test]
    fn es256_sign_body_selects_sha256() {
        let body = sign_body(b"jwt-input", SignOptions::Es256);
        assert_eq!(
            body.get("input").and_then(Value::as_str),
            Some("and0LWlucHV0")
        );
        assert!(body.get("signature_algorithm").is_none());
        assert_eq!(
            body.get("hash_algorithm").and_then(Value::as_str),
            Some("sha2-256")
        );
    }

    #[test]
    fn es384_sign_body_selects_sha384() {
        let body = sign_body(b"jwt-input", SignOptions::Es384);
        assert_eq!(
            body.get("input").and_then(Value::as_str),
            Some("and0LWlucHV0")
        );
        assert!(body.get("signature_algorithm").is_none());
        assert_eq!(
            body.get("hash_algorithm").and_then(Value::as_str),
            Some("sha2-384")
        );
    }

    #[test]
    fn es512_sign_body_selects_sha512() {
        let body = sign_body(b"jwt-input", SignOptions::Es512);
        assert_eq!(
            body.get("input").and_then(Value::as_str),
            Some("and0LWlucHV0")
        );
        assert!(body.get("signature_algorithm").is_none());
        assert_eq!(
            body.get("hash_algorithm").and_then(Value::as_str),
            Some("sha2-512")
        );
    }

    #[test]
    fn rs256_verify_body_selects_pkcs1v15_sha256() {
        let body = verify_body(
            b"jwt-input",
            "vault:v1:c2ln",
            SignOptions::Rs256Pkcs1v15Sha256,
        );
        assert_eq!(
            body.get("input").and_then(Value::as_str),
            Some("and0LWlucHV0")
        );
        assert_eq!(
            body.get("signature").and_then(Value::as_str),
            Some("vault:v1:c2ln")
        );
        assert_eq!(
            body.get("signature_algorithm").and_then(Value::as_str),
            Some("pkcs1v15")
        );
        assert_eq!(
            body.get("hash_algorithm").and_then(Value::as_str),
            Some("sha2-256")
        );
    }

    #[test]
    fn es256_verify_body_selects_sha256() {
        let body = verify_body(b"jwt-input", "vault:v1:c2ln", SignOptions::Es256);
        assert_eq!(
            body.get("input").and_then(Value::as_str),
            Some("and0LWlucHV0")
        );
        assert_eq!(
            body.get("signature").and_then(Value::as_str),
            Some("vault:v1:c2ln")
        );
        assert!(body.get("signature_algorithm").is_none());
        assert_eq!(
            body.get("hash_algorithm").and_then(Value::as_str),
            Some("sha2-256")
        );
    }

    #[test]
    fn es384_verify_body_selects_sha384() {
        let body = verify_body(b"jwt-input", "vault:v1:c2ln", SignOptions::Es384);
        assert_eq!(
            body.get("input").and_then(Value::as_str),
            Some("and0LWlucHV0")
        );
        assert_eq!(
            body.get("signature").and_then(Value::as_str),
            Some("vault:v1:c2ln")
        );
        assert!(body.get("signature_algorithm").is_none());
        assert_eq!(
            body.get("hash_algorithm").and_then(Value::as_str),
            Some("sha2-384")
        );
    }

    #[test]
    fn es512_verify_body_selects_sha512() {
        let body = verify_body(b"jwt-input", "vault:v1:c2ln", SignOptions::Es512);
        assert_eq!(
            body.get("input").and_then(Value::as_str),
            Some("and0LWlucHV0")
        );
        assert_eq!(
            body.get("signature").and_then(Value::as_str),
            Some("vault:v1:c2ln")
        );
        assert!(body.get("signature_algorithm").is_none());
        assert_eq!(
            body.get("hash_algorithm").and_then(Value::as_str),
            Some("sha2-512")
        );
    }

    #[test]
    fn es256_signature_converts_between_transit_der_and_jose_raw() {
        use p256::ecdsa::signature::Signer as _;

        let signing_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let der_signature: p256::ecdsa::Signature = signing_key.sign(b"jwt-input");
        let der = der_signature.to_der();

        let raw =
            normalize_signature_for_client(der.as_bytes(), SignOptions::Es256).expect("der to raw");
        assert_eq!(raw.len(), 64);

        let restored = signature_for_transit(&raw, SignOptions::Es256).expect("raw to transit der");
        assert_eq!(restored, der.as_bytes());
    }

    #[test]
    fn es384_signature_converts_between_transit_der_and_jose_raw() {
        use p384::ecdsa::signature::Signer as _;

        let signing_key = p384::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let der_signature: p384::ecdsa::Signature = signing_key.sign(b"jwt-input");
        let der = der_signature.to_der();

        let raw =
            normalize_signature_for_client(der.as_bytes(), SignOptions::Es384).expect("der to raw");
        assert_eq!(raw.len(), 96);

        let restored = signature_for_transit(&raw, SignOptions::Es384).expect("raw to transit der");
        assert_eq!(restored, der.as_bytes());
    }

    #[test]
    fn es512_signature_converts_between_transit_der_and_jose_raw() {
        use p521::ecdsa::signature::Signer as _;

        let signing_key = p521::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let der_signature: p521::ecdsa::Signature = signing_key.sign(b"jwt-input");
        let der = der_signature.to_der();

        let raw =
            normalize_signature_for_client(der.as_bytes(), SignOptions::Es512).expect("der to raw");
        assert_eq!(raw.len(), 132);

        let restored = signature_for_transit(&raw, SignOptions::Es512).expect("raw to transit der");
        assert_eq!(restored, der.as_bytes());
    }

    /// The BYOK ed25519 import target must be a 48-byte PKCS#8 DER
    /// (`OneAsymmetricKey`, RFC 8410): the documented 16-byte prefix followed by
    /// the 32-byte seed. Transit rejects a raw seed for `type=ed25519`, so this
    /// encoding is the load-bearing fix for `basil-15h`.
    #[test]
    fn ed25519_seed_pkcs8_der_shape() {
        let seed = [0xABu8; ED25519_SEED_LEN];
        let der = ed25519_seed_to_pkcs8_der(&seed);

        assert_eq!(der.len(), 48, "PKCS#8 ed25519 DER must be 48 bytes");
        assert!(
            der.starts_with(&PKCS8_ED25519_PREFIX),
            "DER must begin with the RFC 8410 OneAsymmetricKey prefix"
        );
        assert!(der.ends_with(&seed), "DER must end with the raw seed");
        // Outer SEQUENCE declared length (0x2e = 46) + its own 2-byte tag/len = 48.
        assert_eq!(der.first().copied(), Some(0x30));
        assert_eq!(der.get(1).copied(), Some(0x2e));
    }

    /// Known-answer vector: RFC 8032 §7.1 test 1 secret key (the seed) encodes to
    /// the canonical 48-byte PKCS#8 DER that `openssl pkey -inform DER` parses as
    /// an Ed25519 private key. Locks the byte layout against accidental drift.
    #[test]
    fn ed25519_seed_pkcs8_der_known_vector() {
        // RFC 8032 §7.1, TEST 1 secret key (32-byte seed).
        let seed: [u8; ED25519_SEED_LEN] = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ];
        // The canonical PKCS#8 DER (prefix || seed); matches `openssl pkcs8`.
        let expected: [u8; PKCS8_ED25519_LEN] = [
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20, 0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4,
            0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b,
            0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
        ];
        assert_eq!(ed25519_seed_to_pkcs8_der(&seed), expected.to_vec());
    }

    #[test]
    fn import_target_wraps_seed_only_for_ed25519_types() {
        let seed = vec![0x42; ED25519_SEED_LEN];
        let der =
            import_target_pkcs8_der(KeyType::Ed25519, &KeyMaterial::Ed25519Seed(seed.clone()))
                .expect("ed25519 seed target");
        assert_eq!(der.len(), PKCS8_ED25519_LEN);

        let der = import_target_pkcs8_der(KeyType::Ed25519Nkey, &KeyMaterial::Ed25519Seed(seed))
            .expect("nkey seed target");
        assert_eq!(der.len(), PKCS8_ED25519_LEN);

        assert!(
            import_target_pkcs8_der(
                KeyType::Rsa2048,
                &KeyMaterial::Ed25519Seed(vec![0x42; ED25519_SEED_LEN])
            )
            .is_err()
        );
        assert!(
            import_target_pkcs8_der(
                KeyType::EcdsaP256,
                &KeyMaterial::Ed25519Seed(vec![0x42; ED25519_SEED_LEN])
            )
            .is_err()
        );
    }

    #[test]
    fn import_target_accepts_pkcs8_der_for_rsa_and_ecdsa() {
        let der = vec![0x30, 0x03, 0x02, 0x01, 0x00];
        assert_eq!(
            import_target_pkcs8_der(KeyType::Rsa2048, &KeyMaterial::Pkcs8Der(der.clone()))
                .expect("rsa pkcs8"),
            der
        );
        let der = vec![0x30, 0x03, 0x02, 0x01, 0x01];
        assert_eq!(
            import_target_pkcs8_der(KeyType::EcdsaP256, &KeyMaterial::Pkcs8Der(der.clone()))
                .expect("ecdsa pkcs8"),
            der
        );
    }
}
