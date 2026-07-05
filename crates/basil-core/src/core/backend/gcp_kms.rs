// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! GCP Cloud KMS in-place transit [`Backend`].
//!
//! The private key never leaves Cloud KMS: Basil brokers `sign` / `encrypt` /
//! `decrypt` over gRPC and reads public material through the yoshidan
//! `google-cloud-kms` client. Authentication is Application Default Credentials
//! (`GOOGLE_APPLICATION_CREDENTIALS[_JSON]` or the metadata server) unless the
//! sealed bundle supplies an explicit service-account JSON key.
//!
//! **Scope.** `Ed25519`, `ES256`, and `ES384` signing keys plus symmetric
//! `AES-256-GCM` encrypt/decrypt over **pre-provisioned** keys. Verification is
//! local because Cloud KMS has no server-side asymmetric verify. Signing and
//! public-key reads require the catalog path to name the exact
//! `cryptoKeyVersions/<N>` target. `P-521` is not currently exposed by Cloud KMS,
//! so `ES512` fails closed if the provider rejects the requested version.

use std::collections::BTreeMap;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use google_cloud_gax::grpc::{Code, Status};
use google_cloud_kms::client::{Client, ClientConfig, google_cloud_auth};
use google_cloud_kms::grpc::kms::v1::{
    AsymmetricSignRequest, CreateCryptoKeyRequest, CryptoKey, CryptoKeyVersionTemplate,
    DecryptRequest, Digest as GcpDigest, EncryptRequest, GetCryptoKeyRequest, GetPublicKeyRequest,
    ProtectionLevel, crypto_key::CryptoKeyPurpose as GcpPurpose,
    crypto_key_version::CryptoKeyVersionAlgorithm as GcpAlgorithm, digest as gcp_digest,
};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use basil_proto::{AeadAlgorithm, CiphertextEnvelope, KeyType};

use super::kms_common::{
    ecdsa_der_to_raw, ecdsa_digest, ed25519_public_from_spki, p256_sec1_from_spki,
    p384_sec1_from_spki, pem_to_der, verify_ecdsa_raw,
};
use super::{Backend, BackendError, KeyMetadata, NewKey, PublicKey, SignOptions};

/// Raw `Ed25519` public-key length.
const ED25519_PUB_LEN: usize = 32;
/// Raw `Ed25519` signature length.
const ED25519_SIG_LEN: usize = 64;
/// GCP resource segment that selects one asymmetric key version.
const VERSION_SEGMENT: &str = "/cryptoKeyVersions/";

/// A GCP Cloud KMS transit backend over a pre-provisioned key ring.
pub struct GcpKmsBackend {
    /// The gRPC KMS client (holds no long-lived secret; auth is ambient ADC).
    client: Client,
    /// `projects/{project}/locations/{location}/keyRings/{key_ring}`.
    key_ring: String,
}

impl GcpKmsBackend {
    /// Build a backend for the given key ring, resolving credentials and opening
    /// the gRPC channel.
    ///
    /// # Errors
    ///
    /// [`BackendError::Backend`] when credential parsing/resolution or channel
    /// setup fails.
    pub async fn new(
        project: &str,
        location: &str,
        key_ring: &str,
        service_account_json: Option<&str>,
    ) -> Result<Self, BackendError> {
        let config = if let Some(json) = service_account_json {
            let credentials = google_cloud_auth::credentials::CredentialsFile::new_from_str(json)
                .await
                .map_err(|_| BackendError::Backend("gcp-kms-credentials-invalid".to_owned()))?;
            ClientConfig::default()
                .with_credentials(credentials)
                .await
                .map_err(|_| BackendError::Backend("gcp-kms-auth-failed".to_owned()))?
        } else {
            ClientConfig::default()
                .with_auth()
                .await
                .map_err(|_| BackendError::Backend("gcp-kms-auth-failed".to_owned()))?
        };
        let client = Client::new(config)
            .await
            .map_err(|_| BackendError::Backend("gcp-kms-client-failed".to_owned()))?;
        Ok(Self {
            client,
            key_ring: format!("projects/{project}/locations/{location}/keyRings/{key_ring}"),
        })
    }
}

/// `{key_ring}/cryptoKeys/{key_id}`: the crypto-key resource.
///
/// Symmetric encrypt/decrypt use this form; the server selects the primary
/// version and returns opaque ciphertext bound to the version it chose.
fn crypto_key_name(key_ring: &str, key_id: &str) -> String {
    format!("{key_ring}/cryptoKeys/{}", gcp_crypto_key_id(key_id))
}

/// A parsed catalog path that carries the exact GCP `CryptoKeyVersion`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CryptoKeyVersionRef {
    /// Backend-local `CryptoKey` id.
    key_id: String,
    /// Positive GCP `CryptoKeyVersion` number.
    version: u32,
}

/// Fully-qualified GCP `CryptoKeyVersion` resource plus the version metadata
/// Basil must report back to callers.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CryptoKeyVersionResource {
    /// `{key_ring}/cryptoKeys/{key_id}/cryptoKeyVersions/{version}`.
    name: String,
    /// The selected GCP `CryptoKeyVersion` number.
    version: u32,
}

/// Parse the catalog path form `key-id/cryptoKeyVersions/<positive-u32>`.
fn parse_crypto_key_version(key_id: &str) -> Result<CryptoKeyVersionRef, BackendError> {
    let Some((key_id, version)) = key_id.rsplit_once(VERSION_SEGMENT) else {
        return Err(BackendError::Protocol(
            "gcp-kms asymmetric key path must include /cryptoKeyVersions/<version>".to_owned(),
        ));
    };
    if key_id.is_empty() || version.is_empty() || version.contains('/') {
        return Err(BackendError::Protocol(
            "gcp-kms asymmetric key path has an invalid cryptoKeyVersions suffix".to_owned(),
        ));
    }
    let version = version.parse::<u32>().map_err(|_| {
        BackendError::Protocol(
            "gcp-kms asymmetric key path has a non-numeric cryptoKeyVersions suffix".to_owned(),
        )
    })?;
    if version == 0 {
        return Err(BackendError::Protocol(
            "gcp-kms asymmetric key path version must be positive".to_owned(),
        ));
    }
    Ok(CryptoKeyVersionRef {
        key_id: key_id.to_owned(),
        version,
    })
}

fn gcp_crypto_key_id(key_id: &str) -> String {
    if is_valid_gcp_crypto_key_id(key_id) {
        return key_id.to_owned();
    }
    let mut slug = String::with_capacity(key_id.len());
    for ch in key_id.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            slug.push(ch);
        } else {
            slug.push('-');
        }
    }
    let slug = slug.trim_matches('-');
    let digest = Sha256::digest(key_id.as_bytes());
    let suffix = &URL_SAFE_NO_PAD.encode(digest)[..10];
    let max_slug = 63usize.saturating_sub("basil--".len() + suffix.len());
    let slug = if slug.is_empty() {
        "key"
    } else {
        slug.get(..slug.len().min(max_slug)).unwrap_or("key")
    };
    format!("basil-{slug}-{suffix}")
}

fn is_valid_gcp_crypto_key_id(key_id: &str) -> bool {
    !key_id.is_empty()
        && key_id.len() <= 63
        && key_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Build the explicit version resource required by sign/`get_public_key`.
fn crypto_key_version_name(
    key_ring: &str,
    key_id: &str,
) -> Result<CryptoKeyVersionResource, BackendError> {
    let parsed = parse_crypto_key_version(key_id)?;
    Ok(CryptoKeyVersionResource {
        name: format!(
            "{}/cryptoKeyVersions/{}",
            crypto_key_name(key_ring, &parsed.key_id),
            parsed.version
        ),
        version: parsed.version,
    })
}

fn gcp_key_type(algorithm: i32) -> Result<KeyType, BackendError> {
    match GcpAlgorithm::try_from(algorithm) {
        Ok(GcpAlgorithm::EcSignEd25519) => Ok(KeyType::Ed25519),
        Ok(GcpAlgorithm::EcSignP256Sha256) => Ok(KeyType::EcdsaP256),
        Ok(GcpAlgorithm::EcSignP384Sha384) => Ok(KeyType::EcdsaP384),
        Ok(other) => Err(BackendError::Protocol(format!(
            "gcp-kms get_public_key: unsupported algorithm {}",
            other.as_str_name()
        ))),
        Err(_) => Err(BackendError::Protocol(
            "gcp-kms get_public_key: unknown algorithm".to_owned(),
        )),
    }
}

fn public_from_gcp_spki(der: &[u8], key_type: KeyType) -> Result<Vec<u8>, BackendError> {
    match key_type {
        KeyType::Ed25519 => ed25519_public_from_spki(der),
        KeyType::EcdsaP256 => p256_sec1_from_spki(der),
        KeyType::EcdsaP384 => p384_sec1_from_spki(der),
        other => Err(BackendError::UnsupportedKeyType(other)),
    }
}

fn gcp_sign_digest(message: &[u8], options: SignOptions) -> Result<GcpDigest, BackendError> {
    let digest = ecdsa_digest(message, options)?;
    let digest = match options {
        SignOptions::Es256 => gcp_digest::Digest::Sha256(digest),
        SignOptions::Es384 => gcp_digest::Digest::Sha384(digest),
        SignOptions::Es512 => gcp_digest::Digest::Sha512(digest),
        SignOptions::Default | SignOptions::Rs256Pkcs1v15Sha256 => {
            return Err(BackendError::Unsupported("gcp-kms ecdsa digest"));
        }
    };
    Ok(GcpDigest {
        digest: Some(digest),
    })
}

const fn gcp_key_algorithm(key_type: KeyType) -> Result<GcpAlgorithm, BackendError> {
    match key_type {
        KeyType::Ed25519 | KeyType::Ed25519Nkey => Ok(GcpAlgorithm::EcSignEd25519),
        KeyType::EcdsaP256 => Ok(GcpAlgorithm::EcSignP256Sha256),
        KeyType::EcdsaP384 => Ok(GcpAlgorithm::EcSignP384Sha384),
        KeyType::EcdsaP521
        | KeyType::Rsa2048
        | KeyType::MlDsa44
        | KeyType::MlDsa65
        | KeyType::MlDsa87
        | KeyType::MlKem512
        | KeyType::MlKem768
        | KeyType::MlKem1024 => Err(BackendError::UnsupportedKeyType(key_type)),
    }
}

/// Map a gRPC [`Status`] to a stable, leak-safe [`BackendError`].
fn status_err(key_id: &str, op: &str, status: &Status) -> BackendError {
    if status.code() == Code::NotFound {
        BackendError::KeyNotFound(key_id.to_owned())
    } else {
        BackendError::Backend(format!("gcp-kms-{op}-failed"))
    }
}

#[async_trait]
impl Backend for GcpKmsBackend {
    fn kind(&self) -> &'static str {
        "gcp-kms"
    }

    async fn new_key(&self, key_type: KeyType) -> Result<NewKey, BackendError> {
        let key_id = format!("sv-{}", Uuid::new_v4().simple());
        self.create_named_key(&key_id, key_type).await
    }

    async fn create_named_key(
        &self,
        key_id: &str,
        key_type: KeyType,
    ) -> Result<NewKey, BackendError> {
        let provider_key_id = gcp_crypto_key_id(key_id);
        self.client
            .create_crypto_key(
                CreateCryptoKeyRequest {
                    parent: self.key_ring.clone(),
                    crypto_key_id: provider_key_id,
                    crypto_key: Some(CryptoKey {
                        purpose: GcpPurpose::AsymmetricSign as i32,
                        version_template: Some(CryptoKeyVersionTemplate {
                            protection_level: ProtectionLevel::Software as i32,
                            algorithm: gcp_key_algorithm(key_type)? as i32,
                        }),
                        ..Default::default()
                    }),
                    skip_initial_version_creation: false,
                },
                None,
            )
            .await
            .map_err(|s| status_err(key_id, "create-key", &s))?;
        let versioned_key_id = format!("{key_id}{VERSION_SEGMENT}1");
        let public_key = self.public_key(&versioned_key_id).await?;
        Ok(NewKey {
            key_id: versioned_key_id,
            public_key,
        })
    }

    async fn create_named_aead(
        &self,
        key_id: &str,
        aead: AeadAlgorithm,
    ) -> Result<(), BackendError> {
        if aead != AeadAlgorithm::Aes256Gcm {
            return Err(BackendError::UnsupportedAlgorithm(aead));
        }
        self.client
            .create_crypto_key(
                CreateCryptoKeyRequest {
                    parent: self.key_ring.clone(),
                    crypto_key_id: gcp_crypto_key_id(key_id),
                    crypto_key: Some(CryptoKey {
                        purpose: GcpPurpose::EncryptDecrypt as i32,
                        version_template: Some(CryptoKeyVersionTemplate {
                            protection_level: ProtectionLevel::Software as i32,
                            algorithm: GcpAlgorithm::GoogleSymmetricEncryption as i32,
                        }),
                        ..Default::default()
                    }),
                    skip_initial_version_creation: false,
                },
                None,
            )
            .await
            .map_err(|s| status_err(key_id, "create-key", &s))?;
        Ok(())
    }

    async fn public_key(&self, key_id: &str) -> Result<Vec<u8>, BackendError> {
        let target = crypto_key_version_name(&self.key_ring, key_id)?;
        let resp = self
            .client
            .get_public_key(GetPublicKeyRequest { name: target.name }, None)
            .await
            .map_err(|s| status_err(key_id, "get-public-key", &s))?;
        let der = pem_to_der(&resp.pem)?;
        public_from_gcp_spki(&der, gcp_key_type(resp.algorithm)?)
    }

    async fn public_key_with_meta(&self, key_id: &str) -> Result<PublicKey, BackendError> {
        let target = crypto_key_version_name(&self.key_ring, key_id)?;
        let version = target.version;
        let resp = self
            .client
            .get_public_key(GetPublicKeyRequest { name: target.name }, None)
            .await
            .map_err(|s| status_err(key_id, "get-public-key", &s))?;
        let der = pem_to_der(&resp.pem)?;
        let key_type = gcp_key_type(resp.algorithm)?;
        Ok(PublicKey {
            public_key: public_from_gcp_spki(&der, key_type)?,
            key_type,
            version,
        })
    }

    async fn public_keys(&self, key_id: &str) -> Result<BTreeMap<u32, Vec<u8>>, BackendError> {
        let public = self.public_key_with_meta(key_id).await?;
        Ok(BTreeMap::from([(public.version, public.public_key)]))
    }

    /// Existence + spec probe used by reconcile via a non-mutating `GetCryptoKey`.
    /// Asymmetric catalog paths carry an explicit `/cryptoKeyVersions/<N>` suffix;
    /// symmetric encrypt/decrypt paths name only the `CryptoKey`. Either way the
    /// probe resolves the base `CryptoKey` and reads its purpose: an
    /// asymmetric-sign key reports its [`KeyType`] and the requested version; a
    /// symmetric key has no asymmetric type and reports `None` with version 1. A
    /// `NotFound` maps to [`BackendError::KeyNotFound`] (the clean "absent" signal
    /// reconcile needs); any other failure stays a backend error, so a down or
    /// rejecting backend fails closed.
    async fn key_metadata(&self, key_id: &str) -> Result<KeyMetadata, BackendError> {
        let (base_key_id, latest_version) = if key_id.contains(VERSION_SEGMENT) {
            let parsed = parse_crypto_key_version(key_id)?;
            (parsed.key_id, parsed.version)
        } else {
            (key_id.to_owned(), 1)
        };
        let crypto_key = self
            .client
            .get_crypto_key(
                GetCryptoKeyRequest {
                    name: crypto_key_name(&self.key_ring, &base_key_id),
                },
                None,
            )
            .await
            .map_err(|s| status_err(key_id, "get-crypto-key", &s))?;
        let key_type = match GcpPurpose::try_from(crypto_key.purpose) {
            Ok(GcpPurpose::AsymmetricSign) => {
                let algorithm = crypto_key
                    .version_template
                    .map_or(0, |template| template.algorithm);
                Some(gcp_key_type(algorithm)?)
            }
            // Symmetric encrypt/decrypt (and any non-signing purpose) has no
            // asymmetric key type; reconcile only needs the present/absent signal.
            _ => None,
        };
        Ok(KeyMetadata {
            key_type,
            latest_version,
        })
    }

    async fn sign(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, BackendError> {
        // Ed25519 is pure EdDSA: sign the raw message via `data` (not `digest`).
        let target = crypto_key_version_name(&self.key_ring, key_id)?;
        let resp = self
            .client
            .asymmetric_sign(
                AsymmetricSignRequest {
                    name: target.name,
                    data: message.to_vec(),
                    ..Default::default()
                },
                None,
            )
            .await
            .map_err(|s| status_err(key_id, "sign", &s))?;
        Ok(resp.signature)
    }

    async fn sign_with_options(
        &self,
        key_id: &str,
        message: &[u8],
        options: SignOptions,
    ) -> Result<Vec<u8>, BackendError> {
        if options == SignOptions::Default {
            return self.sign(key_id, message).await;
        }
        let target = crypto_key_version_name(&self.key_ring, key_id)?;
        let resp = self
            .client
            .asymmetric_sign(
                AsymmetricSignRequest {
                    name: target.name,
                    digest: Some(gcp_sign_digest(message, options)?),
                    ..Default::default()
                },
                None,
            )
            .await
            .map_err(|s| status_err(key_id, "sign", &s))?;
        ecdsa_der_to_raw(&resp.signature, options)
    }

    async fn verify(
        &self,
        key_id: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, BackendError> {
        // Cloud KMS has no server-side asymmetric verify: fetch the public key
        // and verify locally. A malformed public/signature verifies false rather
        // than surfacing an oracle-shaped error.
        let public = self.public_key(key_id).await?;
        let Ok(public): Result<[u8; ED25519_PUB_LEN], _> = public.as_slice().try_into() else {
            return Ok(false);
        };
        let Ok(verifying_key) = VerifyingKey::from_bytes(&public) else {
            return Ok(false);
        };
        let Ok(signature): Result<[u8; ED25519_SIG_LEN], _> = signature.try_into() else {
            return Ok(false);
        };
        let signature = Signature::from_bytes(&signature);
        Ok(verifying_key.verify(message, &signature).is_ok())
    }

    async fn verify_with_options(
        &self,
        key_id: &str,
        message: &[u8],
        signature: &[u8],
        options: SignOptions,
    ) -> Result<bool, BackendError> {
        if options == SignOptions::Default {
            return self.verify(key_id, message, signature).await;
        }
        let public = self.public_key_with_meta(key_id).await?;
        let expected = match options {
            SignOptions::Es256 => KeyType::EcdsaP256,
            SignOptions::Es384 => KeyType::EcdsaP384,
            SignOptions::Es512 => KeyType::EcdsaP521,
            SignOptions::Default | SignOptions::Rs256Pkcs1v15Sha256 => {
                return Err(BackendError::Unsupported("gcp-kms verify options"));
            }
        };
        if public.key_type != expected {
            return Ok(false);
        }
        verify_ecdsa_raw(&public.public_key, message, signature, options)
    }

    async fn encrypt(
        &self,
        key_id: &str,
        algorithm: AeadAlgorithm,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<CiphertextEnvelope, BackendError> {
        if algorithm != AeadAlgorithm::Aes256Gcm {
            return Err(BackendError::UnsupportedAlgorithm(algorithm));
        }
        let resp = self
            .client
            .encrypt(
                EncryptRequest {
                    name: crypto_key_name(&self.key_ring, key_id),
                    plaintext: plaintext.to_vec(),
                    additional_authenticated_data: aad.map(<[u8]>::to_vec).unwrap_or_default(),
                    ..Default::default()
                },
                None,
            )
            .await
            .map_err(|s| status_err(key_id, "encrypt", &s))?;
        Ok(CiphertextEnvelope {
            alg: AeadAlgorithm::Aes256Gcm,
            // The Cloud KMS ciphertext is opaque/self-describing (it owns the
            // nonce and version); Basil's version/nonce fields are unused.
            key_version: 1,
            nonce: Vec::new(),
            ciphertext: resp.ciphertext,
        })
    }

    async fn decrypt(
        &self,
        key_id: &str,
        envelope: &CiphertextEnvelope,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, BackendError> {
        if envelope.alg != AeadAlgorithm::Aes256Gcm {
            return Err(BackendError::UnsupportedAlgorithm(envelope.alg));
        }
        let resp = self
            .client
            .decrypt(
                DecryptRequest {
                    name: crypto_key_name(&self.key_ring, key_id),
                    ciphertext: envelope.ciphertext.clone(),
                    additional_authenticated_data: aad.map(<[u8]>::to_vec).unwrap_or_default(),
                    ..Default::default()
                },
                None,
            )
            .await
            .map_err(|s| {
                // Any non-not-found decrypt failure is opaque `DecryptFailed`
                // (a bad tag/AAD/ciphertext must not become an oracle).
                if s.code() == Code::NotFound {
                    BackendError::KeyNotFound(key_id.to_owned())
                } else {
                    BackendError::DecryptFailed
                }
            })?;
        Ok(resp.plaintext)
    }
}

#[cfg(test)]
mod tests {
    // The resource-name builders are the only offline-testable logic here; the
    // KMS operations themselves need live GCP credentials.
    use super::{
        BackendError, CryptoKeyVersionRef, crypto_key_name, crypto_key_version_name,
        gcp_crypto_key_id, is_valid_gcp_crypto_key_id, parse_crypto_key_version,
    };

    const RING: &str = "projects/p/locations/global/keyRings/kr";

    #[test]
    fn crypto_key_name_qualifies_the_key() {
        assert_eq!(
            crypto_key_name(RING, "my-key"),
            "projects/p/locations/global/keyRings/kr/cryptoKeys/my-key"
        );
    }

    #[test]
    fn gcp_crypto_key_id_preserves_valid_ids_and_maps_catalog_paths() {
        assert_eq!(gcp_crypto_key_id("my-key_1"), "my-key_1");
        let mapped = gcp_crypto_key_id("jwt.signing.primary");
        assert!(mapped.starts_with("basil-jwt-signing-primary-"));
        assert!(is_valid_gcp_crypto_key_id(&mapped));
        assert_eq!(mapped, gcp_crypto_key_id("jwt.signing.primary"));
    }

    #[test]
    fn parse_crypto_key_version_accepts_explicit_version() {
        assert_eq!(
            parse_crypto_key_version("my-key/cryptoKeyVersions/7")
                .expect("explicit version parses"),
            CryptoKeyVersionRef {
                key_id: "my-key".to_owned(),
                version: 7
            }
        );
    }

    #[test]
    fn crypto_key_version_name_uses_explicit_version() {
        let target = crypto_key_version_name(RING, "my-key/cryptoKeyVersions/7")
            .expect("explicit version target");
        assert_eq!(
            target.name,
            "projects/p/locations/global/keyRings/kr/cryptoKeys/my-key/cryptoKeyVersions/7"
        );
        assert_eq!(target.version, 7);
    }

    #[test]
    fn crypto_key_version_name_rejects_default_versionless_key() {
        let err = crypto_key_version_name(RING, "my-key").expect_err("version is required");
        assert!(matches!(err, BackendError::Protocol(message) if message.contains("must include")));
    }

    #[test]
    fn parse_crypto_key_version_rejects_invalid_suffixes() {
        for key_id in [
            "my-key/cryptoKeyVersions/",
            "my-key/cryptoKeyVersions/0",
            "my-key/cryptoKeyVersions/latest",
            "my-key/cryptoKeyVersions/7/extra",
        ] {
            let err = parse_crypto_key_version(key_id).expect_err("invalid version suffix");
            assert!(
                matches!(err, BackendError::Protocol(_)),
                "unexpected error for {key_id}: {err}"
            );
        }
    }
}
