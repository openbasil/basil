// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! AWS KMS in-place transit [`Backend`].
//!
//! The private key never leaves KMS: Basil brokers `sign` / `verify` / `encrypt`
//! / `decrypt` and reads public material through the AWS SDK. Authentication is
//! the ambient AWS credential chain (environment, shared profile, IAM role, or
//! IMDS). No secret is held by this backend or sealed in the bundle.
//!
//! **Scope (first cut).** `Ed25519` signing keys and symmetric `AES-256-GCM`
//! encrypt/decrypt over **pre-provisioned** KMS keys. Key provisioning
//! ([`new_key`](Backend::new_key)) is a follow-up: it fails closed with
//! [`BackendError::Unsupported`] rather than silently doing the wrong thing.

use async_trait::async_trait;
use aws_sdk_kms::Client;
use aws_sdk_kms::config::Region;
use aws_sdk_kms::error::ProvideErrorMetadata;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{KeySpec, KeyUsageType, MessageType, SigningAlgorithmSpec};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use basil_proto::{AeadAlgorithm, CiphertextEnvelope, KeyType};
use sha2::{Digest as _, Sha256};
use tokio::time::{Duration, sleep};
use uuid::Uuid;

use super::kms_common::{
    aad_context, ecdsa_der_to_raw, ecdsa_digest, ecdsa_raw_to_der, ed25519_public_from_spki,
    p256_sec1_from_spki, p384_sec1_from_spki, p521_sec1_from_spki,
};
use super::{Backend, BackendError, KeyMetadata, NewKey, PublicKey, SignOptions};

/// The single AWS KMS encryption-context key Basil binds caller `aad` under.
const AAD_CONTEXT_KEY: &str = "basil-aad";
const PROVISION_RETRIES: usize = 5;

/// An AWS KMS transit backend over a pre-provisioned key set.
pub struct AwsKmsBackend {
    /// The KMS client (holds no long-lived secret; auth is ambient).
    client: Client,
}

impl AwsKmsBackend {
    /// Build a backend for `region` (empty ⇒ SDK default resolution), resolving
    /// credentials from the ambient chain. `profile` (empty ⇒ default chain)
    /// selects a named profile from `~/.aws/config`.
    ///
    /// # Errors
    ///
    /// Infallible today (client construction does not perform I/O), but returns
    /// `Result` so credential/region resolution can fail closed in future.
    pub async fn new(region: &str, profile: &str) -> Result<Self, BackendError> {
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
        if !region.is_empty() {
            loader = loader.region(Region::new(region.to_owned()));
        }
        if !profile.is_empty() {
            loader = loader.profile_name(profile);
        }
        let cfg = loader.load().await;
        Ok(Self {
            client: Client::new(&cfg),
        })
    }

    async fn public_key_with_retry(&self, key_id: &str) -> Result<Vec<u8>, BackendError> {
        let mut last = None;
        for attempt in 0..PROVISION_RETRIES {
            match self.public_key(key_id).await {
                Ok(public_key) => return Ok(public_key),
                Err(BackendError::KeyNotFound(_)) if attempt + 1 < PROVISION_RETRIES => {
                    sleep(Duration::from_millis(200)).await;
                    last = Some(BackendError::KeyNotFound(key_id.to_owned()));
                }
                Err(err) => return Err(err),
            }
        }
        Err(last.unwrap_or_else(|| BackendError::KeyNotFound(key_id.to_owned())))
    }
}

/// Classify a KMS SDK error into a stable, leak-safe [`BackendError`], naming the
/// missing action on an authorization failure. `action` is the `PascalCase` KMS
/// action (e.g. `Sign`, `GetPublicKey`). A `NotFoundException` maps to
/// [`BackendError::KeyNotFound`] (the clean "absent" signal reconcile needs); an
/// unmodeled `AccessDeniedException` (read from the shared error metadata) maps to
/// a hint naming `kms:<action>`; anything else is an opaque backend error, so a
/// down or rejecting backend fails closed.
fn map_kms_err<E, R>(
    key_id: &str,
    action: &str,
    err: &aws_sdk_kms::error::SdkError<E, R>,
) -> BackendError
where
    E: ProvideErrorMetadata,
{
    match err.as_service_error().and_then(|e| e.code()) {
        Some(code) if code.contains("NotFound") => BackendError::KeyNotFound(key_id.to_owned()),
        Some(code) if code.contains("AccessDenied") => BackendError::Backend(format!(
            "aws-kms {action} denied for `{key_id}`: the broker's IAM identity is not \
             authorized for kms:{action}. Add it to the broker's IAM policy"
        )),
        _ => BackendError::Backend(format!("aws-kms {action} failed for `{key_id}`")),
    }
}

fn aws_key_ref(key_id: &str) -> String {
    if key_id.starts_with("alias/") || key_id.starts_with("arn:") || looks_like_uuid(key_id) {
        return key_id.to_owned();
    }
    aws_generated_alias(key_id)
}

fn looks_like_uuid(key_id: &str) -> bool {
    key_id.len() == 36 && key_id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
}

fn aws_generated_alias(key_id: &str) -> String {
    let mut slug = String::with_capacity(key_id.len());
    for ch in key_id.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '/' {
            slug.push(ch);
        } else {
            slug.push('_');
        }
    }
    let digest = Sha256::digest(key_id.as_bytes());
    let suffix = &URL_SAFE_NO_PAD.encode(digest)[..12];
    format!("alias/basil/{slug}-{suffix}")
}

const fn aws_key_spec(key_type: KeyType) -> Result<KeySpec, BackendError> {
    match key_type {
        KeyType::Ed25519 | KeyType::Ed25519Nkey => Ok(KeySpec::EccNistEdwards25519),
        KeyType::EcdsaP256 => Ok(KeySpec::EccNistP256),
        KeyType::EcdsaP384 => Ok(KeySpec::EccNistP384),
        KeyType::EcdsaP521 => Ok(KeySpec::EccNistP521),
        KeyType::Rsa2048
        | KeyType::MlDsa44
        | KeyType::MlDsa65
        | KeyType::MlDsa87
        | KeyType::MlKem512
        | KeyType::MlKem768
        | KeyType::MlKem1024 => Err(BackendError::UnsupportedKeyType(key_type)),
    }
}

const fn aws_signing_algorithm(options: SignOptions) -> Result<SigningAlgorithmSpec, BackendError> {
    match options {
        SignOptions::Es256 => Ok(SigningAlgorithmSpec::EcdsaSha256),
        SignOptions::Es384 => Ok(SigningAlgorithmSpec::EcdsaSha384),
        SignOptions::Es512 => Ok(SigningAlgorithmSpec::EcdsaSha512),
        SignOptions::Default | SignOptions::Rs256Pkcs1v15Sha256 => {
            Err(BackendError::Unsupported("aws-kms ecdsa signing algorithm"))
        }
    }
}

fn key_type_from_aws_key_spec(spec: Option<&KeySpec>) -> Result<KeyType, BackendError> {
    match spec {
        Some(KeySpec::EccNistEdwards25519) => Ok(KeyType::Ed25519),
        Some(KeySpec::EccNistP256) => Ok(KeyType::EcdsaP256),
        Some(KeySpec::EccNistP384) => Ok(KeyType::EcdsaP384),
        Some(KeySpec::EccNistP521) => Ok(KeyType::EcdsaP521),
        Some(other) => Err(BackendError::Protocol(format!(
            "aws-kms get_public_key: unsupported key spec {}",
            other.as_str()
        ))),
        None => Err(BackendError::Protocol(
            "aws-kms get_public_key: missing key spec".to_owned(),
        )),
    }
}

fn public_from_aws_spki(der: &[u8], key_type: KeyType) -> Result<Vec<u8>, BackendError> {
    match key_type {
        KeyType::Ed25519 => ed25519_public_from_spki(der),
        KeyType::EcdsaP256 => p256_sec1_from_spki(der),
        KeyType::EcdsaP384 => p384_sec1_from_spki(der),
        KeyType::EcdsaP521 => p521_sec1_from_spki(der),
        other => Err(BackendError::UnsupportedKeyType(other)),
    }
}

#[async_trait]
impl Backend for AwsKmsBackend {
    fn kind(&self) -> &'static str {
        "aws-kms"
    }

    async fn new_key(&self, _key_type: KeyType) -> Result<NewKey, BackendError> {
        let key_id = format!("sv-{}", Uuid::new_v4().simple());
        self.create_named_key(&key_id, _key_type).await
    }

    async fn create_named_key(
        &self,
        key_id: &str,
        key_type: KeyType,
    ) -> Result<NewKey, BackendError> {
        let out = self
            .client
            .create_key()
            .key_spec(aws_key_spec(key_type)?)
            .key_usage(KeyUsageType::SignVerify)
            .description(format!("Basil transit signing key {key_id}"))
            .send()
            .await
            .map_err(|e| map_kms_err(key_id, "CreateKey", &e))?;
        let target_key_id = out
            .key_metadata()
            .map(aws_sdk_kms::types::KeyMetadata::key_id)
            .ok_or_else(|| BackendError::Protocol("aws-kms create_key: no key id".to_owned()))?;
        self.client
            .create_alias()
            .alias_name(aws_key_ref(key_id))
            .target_key_id(target_key_id)
            .send()
            .await
            .map_err(|e| map_kms_err(key_id, "CreateAlias", &e))?;
        let public_key = self.public_key_with_retry(key_id).await?;
        Ok(NewKey {
            key_id: key_id.to_owned(),
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
        let out = self
            .client
            .create_key()
            .key_spec(KeySpec::SymmetricDefault)
            .key_usage(KeyUsageType::EncryptDecrypt)
            .description(format!("Basil transit AEAD key {key_id}"))
            .send()
            .await
            .map_err(|e| map_kms_err(key_id, "CreateKey", &e))?;
        let target_key_id = out
            .key_metadata()
            .map(aws_sdk_kms::types::KeyMetadata::key_id)
            .ok_or_else(|| BackendError::Protocol("aws-kms create_key: no key id".to_owned()))?;
        self.client
            .create_alias()
            .alias_name(aws_key_ref(key_id))
            .target_key_id(target_key_id)
            .send()
            .await
            .map_err(|e| map_kms_err(key_id, "CreateAlias", &e))?;
        Ok(())
    }

    async fn public_key(&self, key_id: &str) -> Result<Vec<u8>, BackendError> {
        let out = self
            .client
            .get_public_key()
            .key_id(aws_key_ref(key_id))
            .send()
            .await
            .map_err(|e| map_kms_err(key_id, "GetPublicKey", &e))?;
        let der = out
            .public_key()
            .ok_or_else(|| BackendError::Protocol("aws-kms get_public_key: no key".to_owned()))?;
        let key_type = key_type_from_aws_key_spec(out.key_spec())?;
        public_from_aws_spki(der.as_ref(), key_type)
    }

    async fn public_key_with_meta(&self, key_id: &str) -> Result<PublicKey, BackendError> {
        let out = self
            .client
            .get_public_key()
            .key_id(aws_key_ref(key_id))
            .send()
            .await
            .map_err(|e| map_kms_err(key_id, "GetPublicKey", &e))?;
        let der = out
            .public_key()
            .ok_or_else(|| BackendError::Protocol("aws-kms get_public_key: no key".to_owned()))?;
        let key_type = key_type_from_aws_key_spec(out.key_spec())?;
        Ok(PublicKey {
            public_key: public_from_aws_spki(der.as_ref(), key_type)?,
            key_type,
            // AWS KMS has no transit-style version counter for a logical key.
            version: 1,
        })
    }

    /// Existence + spec probe used by reconcile and `list` via a non-mutating
    /// `DescribeKey`. AWS KMS has no transit-style version counter, so
    /// `latest_version` is always 1; a `SYMMETRIC_DEFAULT` key has no asymmetric
    /// [`KeyType`] and reports `None`. A `NotFoundException` maps to
    /// [`BackendError::KeyNotFound`] (the clean "absent" signal reconcile needs);
    /// any other failure is a backend error, so a down backend fails closed.
    async fn key_metadata(&self, key_id: &str) -> Result<KeyMetadata, BackendError> {
        let out = self
            .client
            .describe_key()
            .key_id(aws_key_ref(key_id))
            .send()
            .await
            .map_err(|e| map_kms_err(key_id, "DescribeKey", &e))?;
        let key_type = match out
            .key_metadata()
            .and_then(aws_sdk_kms::types::KeyMetadata::key_spec)
        {
            Some(KeySpec::SymmetricDefault) | None => None,
            Some(other) => Some(key_type_from_aws_key_spec(Some(other))?),
        };
        Ok(KeyMetadata {
            key_type,
            latest_version: 1,
        })
    }

    async fn sign(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, BackendError> {
        let out = self
            .client
            .sign()
            .key_id(aws_key_ref(key_id))
            .message(Blob::new(message.to_vec()))
            .message_type(MessageType::Raw)
            .signing_algorithm(SigningAlgorithmSpec::Ed25519Sha512)
            .send()
            .await
            .map_err(|e| map_kms_err(key_id, "Sign", &e))?;
        out.signature()
            .map(|b| b.as_ref().to_vec())
            .ok_or_else(|| BackendError::Protocol("aws-kms sign: no signature".to_owned()))
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
        let digest = ecdsa_digest(message, options)?;
        let out = self
            .client
            .sign()
            .key_id(aws_key_ref(key_id))
            .message(Blob::new(digest))
            .message_type(MessageType::Digest)
            .signing_algorithm(aws_signing_algorithm(options)?)
            .send()
            .await
            .map_err(|e| map_kms_err(key_id, "Sign", &e))?;
        let der = out
            .signature()
            .map(|b| b.as_ref().to_vec())
            .ok_or_else(|| BackendError::Protocol("aws-kms sign: no signature".to_owned()))?;
        ecdsa_der_to_raw(&der, options)
    }

    async fn verify(
        &self,
        key_id: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, BackendError> {
        match self
            .client
            .verify()
            .key_id(aws_key_ref(key_id))
            .message(Blob::new(message.to_vec()))
            .message_type(MessageType::Raw)
            .signature(Blob::new(signature.to_vec()))
            .signing_algorithm(SigningAlgorithmSpec::Ed25519Sha512)
            .send()
            .await
        {
            Ok(out) => Ok(out.signature_valid()),
            Err(e) => {
                // KMS reports an invalid signature as an exception, not `valid=false`.
                if let Some(svc) = e.as_service_error()
                    && svc.is_kms_invalid_signature_exception()
                {
                    return Ok(false);
                }
                Err(map_kms_err(key_id, "Verify", &e))
            }
        }
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
        let digest = ecdsa_digest(message, options)?;
        let der = ecdsa_raw_to_der(signature, options)?;
        match self
            .client
            .verify()
            .key_id(aws_key_ref(key_id))
            .message(Blob::new(digest))
            .message_type(MessageType::Digest)
            .signature(Blob::new(der))
            .signing_algorithm(aws_signing_algorithm(options)?)
            .send()
            .await
        {
            Ok(out) => Ok(out.signature_valid()),
            Err(e) => {
                if let Some(svc) = e.as_service_error()
                    && svc.is_kms_invalid_signature_exception()
                {
                    return Ok(false);
                }
                Err(map_kms_err(key_id, "Verify", &e))
            }
        }
    }

    async fn encrypt(
        &self,
        key_id: &str,
        algorithm: AeadAlgorithm,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<CiphertextEnvelope, BackendError> {
        // KMS symmetric keys are AES-256-GCM; reject any other requested suite
        // rather than silently substituting.
        if algorithm != AeadAlgorithm::Aes256Gcm {
            return Err(BackendError::UnsupportedAlgorithm(algorithm));
        }
        let mut req = self
            .client
            .encrypt()
            .key_id(aws_key_ref(key_id))
            .plaintext(Blob::new(plaintext.to_vec()));
        if let Some(aad) = aad {
            req = req.encryption_context(AAD_CONTEXT_KEY, aad_context(aad));
        }
        let out = req
            .send()
            .await
            .map_err(|e| map_kms_err(key_id, "Encrypt", &e))?;
        let ciphertext = out
            .ciphertext_blob()
            .map(|b| b.as_ref().to_vec())
            .ok_or_else(|| BackendError::Protocol("aws-kms encrypt: no ciphertext".to_owned()))?;
        Ok(CiphertextEnvelope {
            alg: AeadAlgorithm::Aes256Gcm,
            // The KMS ciphertext is opaque and self-describing (KMS owns the
            // nonce and versioning); Basil's version/nonce fields are unused.
            key_version: 1,
            nonce: Vec::new(),
            ciphertext,
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
        let mut req = self
            .client
            .decrypt()
            .key_id(aws_key_ref(key_id))
            .ciphertext_blob(Blob::new(envelope.ciphertext.clone()));
        if let Some(aad) = aad {
            req = req.encryption_context(AAD_CONTEXT_KEY, aad_context(aad));
        }
        let out = req.send().await.map_err(|e| {
            // A tag/context/ciphertext mismatch is opaque `DecryptFailed` (no oracle).
            if let Some(svc) = e.as_service_error()
                && svc.is_invalid_ciphertext_exception()
            {
                return BackendError::DecryptFailed;
            }
            map_kms_err(key_id, "Decrypt", &e)
        })?;
        out.plaintext()
            .map(|b| b.as_ref().to_vec())
            .ok_or_else(|| BackendError::Protocol("aws-kms decrypt: no plaintext".to_owned()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aws_sdk_kms::types::KeySpec;

    use super::{aws_generated_alias, aws_key_ref, aws_key_spec, looks_like_uuid};
    use basil_proto::KeyType;

    #[test]
    fn aws_key_ref_preserves_explicit_ids_and_aliases() {
        assert_eq!(aws_key_ref("alias/manual"), "alias/manual");
        assert_eq!(
            aws_key_ref("arn:aws:kms:us-east-1:123456789012:key/abc"),
            "arn:aws:kms:us-east-1:123456789012:key/abc"
        );
        assert!(looks_like_uuid("12345678-1234-1234-1234-1234567890ab"));
    }

    #[test]
    fn aws_generated_alias_is_valid_and_stable_for_catalog_paths() {
        let alias = aws_generated_alias("jwt.signing.primary");
        assert!(alias.starts_with("alias/basil/jwt_signing_primary-"));
        assert_eq!(alias, aws_generated_alias("jwt.signing.primary"));
        assert!(
            alias
                .bytes()
                .all(|b| { b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'-') })
        );
    }

    #[test]
    fn aws_key_type_maps_to_supported_key_specs() {
        assert_eq!(
            aws_key_spec(KeyType::Ed25519).unwrap(),
            KeySpec::EccNistEdwards25519
        );
        assert_eq!(
            aws_key_spec(KeyType::EcdsaP256).unwrap(),
            KeySpec::EccNistP256
        );
        assert!(aws_key_spec(KeyType::Rsa2048).is_err());
    }
}

/// Opt-in **live** AWS KMS integration test: the regression harness for this
/// backend.
///
/// It runs only when `BASIL_AWS_KMS_LIVE` is set and AWS credentials plus a
/// region resolve from the ambient chain (skips cleanly otherwise, so it is
/// inert in normal CI). Against a real account it provisions one key per
/// supported type, exercises the whole `Backend` surface (create,
/// `key_metadata`, `public_key`, sign/verify, and encrypt/decrypt with and
/// without `aad`), asserts the fail-closed paths, and schedules every key it
/// created for deletion. Enable with `BASIL_AWS_KMS_LIVE=1 AWS_REGION=us-east-1`
/// and credentials on the ambient chain. See `docs/aws-test-report.md` and
/// `br basil-8j33`.
#[cfg(test)]
mod live_tests {
    #![allow(clippy::unwrap_used, clippy::too_many_lines, clippy::similar_names)]

    use super::{AwsKmsBackend, Backend, BackendError, SignOptions, aws_key_ref};
    use basil_proto::{AeadAlgorithm, KeyType};
    use uuid::Uuid;

    fn enabled() -> bool {
        std::env::var("BASIL_AWS_KMS_LIVE").is_ok()
    }

    fn region() -> String {
        std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".to_owned())
    }

    /// Best-effort teardown: resolve the alias to its key id, schedule the key
    /// for deletion (minimum 7-day window), then drop the alias. Errors are
    /// ignored so a failed cleanup never masks a test result.
    async fn schedule_teardown(backend: &AwsKmsBackend, key_id: &str) {
        let aref = aws_key_ref(key_id);
        if let Ok(out) = backend
            .client
            .describe_key()
            .key_id(aref.clone())
            .send()
            .await
            && let Some(id) = out.key_metadata().map(|m| m.key_id().to_owned())
        {
            let _ = backend
                .client
                .schedule_key_deletion()
                .key_id(id)
                .pending_window_in_days(7)
                .send()
                .await;
        }
        let _ = backend.client.delete_alias().alias_name(aref).send().await;
    }

    #[tokio::test]
    async fn aws_kms_backend_end_to_end() {
        if !enabled() {
            eprintln!(
                "skipping aws_kms_backend_end_to_end: set BASIL_AWS_KMS_LIVE=1 with AWS creds"
            );
            return;
        }
        let backend = AwsKmsBackend::new(&region(), "")
            .await
            .expect("build aws-kms backend");
        let run = Uuid::new_v4().simple().to_string();
        let name = |suffix: &str| format!("test/live-{run}-{suffix}");
        let mut created: Vec<String> = Vec::new();

        // Signing keys: create, read public + metadata, sign/verify, reject tamper.
        let signers = [
            ("ed25519", KeyType::Ed25519, SignOptions::Default),
            ("p256", KeyType::EcdsaP256, SignOptions::Es256),
            ("p384", KeyType::EcdsaP384, SignOptions::Es384),
            ("p521", KeyType::EcdsaP521, SignOptions::Es512),
        ];
        for (suffix, key_type, opts) in signers {
            let key = name(suffix);
            backend.create_named_key(&key, key_type).await.unwrap();
            created.push(key.clone());

            assert!(!backend.public_key(&key).await.unwrap().is_empty());
            let meta = backend.key_metadata(&key).await.unwrap();
            assert_eq!(meta.key_type, Some(key_type), "metadata type for {suffix}");

            let msg = format!("basil aws-kms live {suffix}").into_bytes();
            let sig = backend.sign_with_options(&key, &msg, opts).await.unwrap();
            assert!(
                backend
                    .verify_with_options(&key, &msg, &sig, opts)
                    .await
                    .unwrap(),
                "verify good signature for {suffix}"
            );
            let tampered: &[u8] = b"tampered payload";
            assert!(
                !backend
                    .verify_with_options(&key, tampered, &sig, opts)
                    .await
                    .unwrap(),
                "reject tampered payload for {suffix}"
            );
        }

        // AEAD key: round-trip (no aad + aad), reject a wrong aad (fail closed).
        let aead = name("aes256");
        backend
            .create_named_aead(&aead, AeadAlgorithm::Aes256Gcm)
            .await
            .unwrap();
        created.push(aead.clone());
        let plaintext = b"live aead payload".to_vec();

        let sealed = backend
            .encrypt(&aead, AeadAlgorithm::Aes256Gcm, &plaintext, None)
            .await
            .unwrap();
        assert_eq!(
            backend.decrypt(&aead, &sealed, None).await.unwrap(),
            plaintext
        );

        let aad: &[u8] = b"basil-context-v1";
        let wrong_aad: &[u8] = b"wrong-context";
        let sealed_aad = backend
            .encrypt(&aead, AeadAlgorithm::Aes256Gcm, &plaintext, Some(aad))
            .await
            .unwrap();
        assert_eq!(
            backend
                .decrypt(&aead, &sealed_aad, Some(aad))
                .await
                .unwrap(),
            plaintext
        );
        assert!(matches!(
            backend.decrypt(&aead, &sealed_aad, Some(wrong_aad)).await,
            Err(BackendError::DecryptFailed)
        ));

        // Probe semantics: an absent key is a clean KeyNotFound, not a hard error.
        assert!(matches!(
            backend.key_metadata(&name("absent")).await,
            Err(BackendError::KeyNotFound(_))
        ));

        // Fail closed on types/algorithms the backend does not support.
        assert!(matches!(
            backend
                .create_named_key(&name("rsa"), KeyType::Rsa2048)
                .await,
            Err(BackendError::UnsupportedKeyType(_))
        ));
        assert!(matches!(
            backend
                .create_named_aead(&name("cc"), AeadAlgorithm::Chacha20Poly1305)
                .await,
            Err(BackendError::UnsupportedAlgorithm(_))
        ));
        assert!(matches!(
            backend
                .encrypt(&aead, AeadAlgorithm::Chacha20Poly1305, &plaintext, None)
                .await,
            Err(BackendError::UnsupportedAlgorithm(_))
        ));

        // Teardown: schedule every created key for deletion (7-day window).
        for key in &created {
            schedule_teardown(&backend, key).await;
        }
    }
}
