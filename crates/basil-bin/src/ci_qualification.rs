// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Fixed-purpose artifact-sign qualification for a CI identity session.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::os::fd::OwnedFd;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use basil::{EphemeralSealedInvocationOptions, prepare_ephemeral_sealed_invocation};
use basil_cose::{KeyId, MessageRole, ProtectedHeaders, Subject, UnixTime, ValidationParams};
use basil_proto::broker::v1::{
    GetInvocationChallengeRequest, GetInvocationChallengeResponse, SealedResponse,
};
use basil_proto::invocation::{
    InvocationStatusCode, SignInvocationRequest, SignInvocationResponse,
};
use ed25519_dalek::{Signature, VerifyingKey};
use prost::Message as _;
use reqwest::header::{CACHE_CONTROL, CONTENT_TYPE};
use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize as _, Zeroizing};

use super::{ProofIdentity, SessionIdentity, TypedInvocationTransport};

const CONFIG_VERSION: u8 = 1;
const ADAPTER_REQUEST: &[u8] = br#"{"version":1,"operation":"artifact-sign-qualification"}"#;
const STATEMENT_DOMAIN: &[u8] = b"basil-ci-artifact-sign-qualification-v1\0";
const MAX_CONFIG_BYTES: usize = 64 * 1024;
const MAX_CA_BYTES: usize = 64 * 1024;
const MAX_CA_CERTIFICATES: usize = 16;
const MAX_CHALLENGE_BYTES: usize = 4 * 1024;
const MAX_INVOCATION_BYTES: usize = 1024 * 1024;
const MAX_EVIDENCE_BYTES: usize = 8 * 1024;
const HTTP_TIMEOUT: Duration = Duration::from_secs(4);
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum ExpectedResult {
    Success,
    SealedDenied,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct QualificationConfigFile {
    version: u8,
    provider_kind: String,
    expected_token_request_origin: String,
    rule_max_token_age_seconds: u64,
    courier_origin: String,
    courier_ca_bundle_path: PathBuf,
    broker_audience: String,
    request_encryption_key_id: String,
    request_encryption_public_key: String,
    response_signing_key_id: String,
    response_signing_public_key: String,
    artifact_sign_key_id: String,
    artifact_sign_public_key: String,
    expected_result: ExpectedResult,
}

/// Validated qualification authority loaded from one pinned configuration.
pub(super) struct QualificationConfig {
    provider_kind: String,
    expected_token_request_origin: String,
    rule_max_token_age_seconds: u64,
    courier_origin: reqwest::Url,
    broker_audience: String,
    request_encryption_key_id: String,
    request_encryption_public_key: [u8; 32],
    response_signing_key_id: String,
    response_signing_public_key: [u8; 32],
    artifact_sign_key_id: String,
    artifact_sign_public_key: [u8; 32],
    expected_result: ExpectedResult,
    config_sha256: [u8; 32],
    ca_sha256: [u8; 32],
    certificates: Vec<reqwest::Certificate>,
}

impl QualificationConfig {
    /// Load one root-owned configuration and its exclusive courier trust roots.
    pub(super) fn load(path: &Path) -> Result<Self> {
        let config_bytes = read_pinned_root_file(path, MAX_CONFIG_BYTES)
            .context("loading CI qualification configuration")?;
        let config_sha256 = Sha256::digest(&*config_bytes).into();
        let file: QualificationConfigFile = serde_json::from_slice(&config_bytes)
            .context("parsing CI qualification configuration")?;
        if file.version != CONFIG_VERSION {
            bail!("CI qualification configuration version is unsupported");
        }
        if !matches!(file.provider_kind.as_str(), "github" | "forgejoActions") {
            bail!("CI qualification provider kind is unsupported");
        }
        validate_id(&file.request_encryption_key_id)?;
        validate_id(&file.response_signing_key_id)?;
        validate_id(&file.artifact_sign_key_id)?;
        Subject::new(file.broker_audience.clone())
            .context("validating CI qualification broker audience")?;
        let courier_origin = exact_https_origin(&file.courier_origin)?;
        let ca_bytes = read_pinned_root_file(&file.courier_ca_bundle_path, MAX_CA_BYTES)
            .context("loading CI qualification courier CA bundle")?;
        let ca_sha256 = Sha256::digest(&*ca_bytes).into();
        let certificates = parse_certificate_only_pem(&ca_bytes)?;
        Ok(Self {
            provider_kind: file.provider_kind,
            expected_token_request_origin: file.expected_token_request_origin,
            rule_max_token_age_seconds: file.rule_max_token_age_seconds,
            courier_origin,
            broker_audience: file.broker_audience,
            request_encryption_key_id: file.request_encryption_key_id,
            request_encryption_public_key: decode_public_key(&file.request_encryption_public_key)?,
            response_signing_key_id: file.response_signing_key_id,
            response_signing_public_key: decode_public_key(&file.response_signing_public_key)?,
            artifact_sign_key_id: file.artifact_sign_key_id,
            artifact_sign_public_key: decode_public_key(&file.artifact_sign_public_key)?,
            expected_result: file.expected_result,
            config_sha256,
            ca_sha256,
            certificates,
        })
    }

    /// Bind the file authority to the provider bootstrap and protected CLI age.
    pub(super) fn cross_check(
        &self,
        provider_kind: &str,
        expected_origin: &str,
        rule_max_token_age_seconds: u64,
    ) -> Result<()> {
        if self.provider_kind != provider_kind
            || self.expected_token_request_origin != expected_origin
            || self.rule_max_token_age_seconds != rule_max_token_age_seconds
        {
            bail!("CI qualification configuration does not match the session bootstrap");
        }
        Ok(())
    }
}

/// One compile-time registered, one-shot qualification adapter.
pub(super) struct ArtifactSignQualificationAdapter {
    config: QualificationConfig,
    client: reqwest::Client,
    used: AtomicBool,
}

impl ArtifactSignQualificationAdapter {
    /// Build the exclusive-root courier client before provider token acquisition.
    pub(super) fn new(config: QualificationConfig) -> Result<Self> {
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(HTTP_CONNECT_TIMEOUT)
            .timeout(HTTP_TIMEOUT)
            .tls_certs_only(config.certificates.clone())
            .build()
            .context("building CI qualification courier client")?;
        Ok(Self {
            config,
            client,
            used: AtomicBool::new(false),
        })
    }

    fn endpoint(&self, path: &'static str) -> reqwest::Url {
        let mut url = self.config.courier_origin.clone();
        url.set_path(path);
        url
    }

    async fn post(
        &self,
        path: &'static str,
        content_type: &'static str,
        mut body: Zeroizing<Vec<u8>>,
        limit: usize,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let url = self.endpoint(path);
        // The HTTP stack must own the allocation while it is in flight. Move
        // it from the zeroizing staging owner to avoid another ordinary copy.
        let request_body = std::mem::take(&mut *body);
        let mut response = self
            .client
            .post(url.clone())
            .header(CONTENT_TYPE, content_type)
            .body(request_body)
            .send()
            .await
            .map_err(|_| anyhow!("CI qualification courier request failed"))?;
        if response.url() != &url || !response.status().is_success() {
            bail!("CI qualification courier rejected the request");
        }
        if response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            != Some(content_type)
            || response
                .headers()
                .get(CACHE_CONTROL)
                .and_then(|value| value.to_str().ok())
                != Some("no-store")
        {
            bail!("CI qualification courier response metadata is invalid");
        }
        if response
            .content_length()
            .is_some_and(|length| length > limit as u64)
        {
            bail!("CI qualification courier response is too large");
        }
        let mut bytes = Zeroizing::new(Vec::new());
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| anyhow!("CI qualification courier response failed"))?
        {
            if chunk.len() > limit.saturating_sub(bytes.len()) {
                bail!("CI qualification courier response is too large");
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }

    async fn qualify(&self, identity: &SessionIdentity) -> Result<QualificationEvidence> {
        let proof = identity.proof();
        let challenge = self.fetch_challenge(proof).await?;
        let now = unix_now()?;
        let statement_sha256 =
            qualification_statement(&self.config.config_sha256, proof.jkt_bytes(), &challenge);
        let body = SignInvocationRequest {
            key_id: self.config.artifact_sign_key_id.clone(),
            message: statement_sha256.to_vec(),
            algorithm: basil_proto::broker::v1::SigningAlgorithm::Ed25519.into(),
        };
        let mut proof_headers = ProtectedHeaders {
            signer_certificates_jwt: vec![identity.provider_token().to_owned()],
            signer_public_key_cose: Some(proof_key_cose(proof.public_key_bytes())),
            operation_target_key_id: None,
        };
        let options = EphemeralSealedInvocationOptions {
            message_id: random_message_id()?,
            issued_at_unix: now,
            expires_at_unix: Some(now.saturating_add(30)),
            sender_sign_id: proof.jkt().to_owned(),
            sender_subject: None,
            recipient_key_id: self.config.request_encryption_key_id.clone(),
            recipient_subject: Some(self.config.broker_audience.clone()),
            freshness_challenge: challenge,
        };
        let prepared_result = prepare_ephemeral_sealed_invocation(
            options,
            &self.config.request_encryption_public_key,
            &body,
            &proof_headers,
            proof,
        )
        .await;
        for token in &mut proof_headers.signer_certificates_jwt {
            token.zeroize();
        }
        let prepared = prepared_result.context("preparing CI qualification invocation")?;
        let invocation_id = URL_SAFE_NO_PAD.encode(prepared.prepared().request_hash);
        let response_bytes = self
            .post(
                "/v1/invoke",
                "application/cose",
                Zeroizing::new(prepared.prepared().message.clone()),
                MAX_INVOCATION_BYTES,
            )
            .await?;
        let mut response_bytes = response_bytes;
        let response = SealedResponse {
            message: std::mem::take(&mut *response_bytes),
            response_subject: None,
        };
        let pins = BTreeMap::from([(
            self.config.response_signing_key_id.clone(),
            self.config.response_signing_public_key.to_vec(),
        )]);
        let validation = ValidationParams {
            now: UnixTime(i64::from(unix_now()?)),
            max_clock_skew: Duration::from_secs(30),
            max_ttl: Duration::from_secs(300),
            default_ttl: Duration::from_secs(120),
            // Response-role claims omit `aud` in this broker profile. The
            // pinned signer plus authenticated request hash, message ID, and
            // ephemeral response recipient bind it to this exact request.
            allowed_audiences: BTreeSet::new(),
            role: MessageRole::Response,
        };
        let mut result = prepared
            .verify_and_decrypt_sign_response(&response, &pins, &validation)
            .await
            .context("opening CI qualification response")?;
        let outcome = self.validate_result(&mut result, &statement_sha256)?;
        let evidence = QualificationEvidence {
            version: CONFIG_VERSION,
            result: outcome.result,
            invocation_id,
            policy_generation: result.policy_generation,
            target_key_id: self.config.artifact_sign_key_id.clone(),
            config_sha256: hex::encode(self.config.config_sha256),
            ca_sha256: hex::encode(self.config.ca_sha256),
            statement_sha256: hex::encode(statement_sha256),
            signature_sha256: outcome.signature_sha256,
            signature_verified: outcome.signature_verified,
            denial_code: outcome.denial_code,
            denial_retryable: outcome.denial_retryable,
        };
        if serde_json::to_vec(&evidence).map_or(true, |encoded| encoded.len() > MAX_EVIDENCE_BYTES)
        {
            bail!("CI qualification evidence exceeds its bound");
        }
        Ok(evidence)
    }

    async fn fetch_challenge(&self, proof: &ProofIdentity) -> Result<[u8; 32]> {
        let challenge_body = Zeroizing::new(
            GetInvocationChallengeRequest {
                jkt: proof.jkt_bytes().to_vec(),
                courier_observed_source: None,
            }
            .encode_to_vec(),
        );
        let challenge_bytes = self
            .post(
                "/v1/challenge",
                "application/protobuf",
                challenge_body,
                MAX_CHALLENGE_BYTES,
            )
            .await?;
        let challenge = GetInvocationChallengeResponse::decode(challenge_bytes.as_slice())
            .context("decoding CI qualification challenge")?;
        let expires_at_unix = challenge.expires_at_unix;
        let challenge: [u8; 32] = challenge
            .challenge
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("CI qualification challenge has an invalid length"))?;
        let now = unix_now()?;
        if expires_at_unix <= i64::from(now) {
            bail!("CI qualification challenge is already expired");
        }
        Ok(challenge)
    }

    fn validate_result(
        &self,
        result: &mut SignInvocationResponse,
        statement: &[u8; 32],
    ) -> Result<QualificationOutcome> {
        match self.config.expected_result {
            ExpectedResult::Success if result.status.code == InvocationStatusCode::Ok => {
                let mut signature = Zeroizing::new(
                    result
                        .signature
                        .take()
                        .ok_or_else(|| anyhow!("CI qualification response omitted a signature"))?,
                );
                let parsed = Signature::from_slice(&signature)
                    .map_err(|_| anyhow!("CI qualification signature has an invalid length"))?;
                let verifier = VerifyingKey::from_bytes(&self.config.artifact_sign_public_key)
                    .map_err(|_| anyhow!("CI qualification target public key is invalid"))?;
                verifier
                    .verify_strict(statement, &parsed)
                    .map_err(|_| anyhow!("CI qualification target signature is invalid"))?;
                let signature_sha256 = hex::encode(Sha256::digest(&*signature));
                signature.zeroize();
                Ok(QualificationOutcome {
                    result: QualificationResult::Signed,
                    signature_sha256: Some(signature_sha256),
                    signature_verified: true,
                    denial_code: None,
                    denial_retryable: None,
                })
            }
            ExpectedResult::SealedDenied
                if result.status.code == InvocationStatusCode::Denied
                    && !result.status.retryable
                    && result.signature.is_none() =>
            {
                Ok(QualificationOutcome {
                    result: QualificationResult::SealedDenied,
                    signature_sha256: None,
                    signature_verified: false,
                    denial_code: Some(InvocationStatusCode::Denied as u32),
                    denial_retryable: Some(false),
                })
            }
            ExpectedResult::Success | ExpectedResult::SealedDenied => {
                if let Some(signature) = &mut result.signature {
                    signature.zeroize();
                }
                bail!("CI qualification response did not match the expected result");
            }
        }
    }
}

impl TypedInvocationTransport for ArtifactSignQualificationAdapter {
    const ADAPTER_NAME: &'static str = "artifact-sign-qualification";
    const REQUEST_MAX_BYTES: usize = ADAPTER_REQUEST.len();
    const RESPONSE_MAX_BYTES: usize = MAX_EVIDENCE_BYTES;
    type Request = QualificationRequest;
    type Response = QualificationEvidence;

    fn decode_request(bytes: &[u8]) -> std::result::Result<Self::Request, ()> {
        (bytes == ADAPTER_REQUEST)
            .then_some(QualificationRequest)
            .ok_or(())
    }

    fn claim_request(&self) -> std::result::Result<(), ()> {
        claim_one_shot(&self.used).map_err(|_| ())
    }

    async fn invoke(
        &self,
        identity: std::sync::Arc<SessionIdentity>,
        _request: Self::Request,
    ) -> Result<Self::Response> {
        self.qualify(&identity).await
    }
}

fn claim_one_shot(used: &AtomicBool) -> Result<()> {
    used.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map(|_| ())
        .map_err(|_| anyhow!("CI qualification adapter is one-shot"))
}

pub(super) struct QualificationRequest;

struct QualificationOutcome {
    result: QualificationResult,
    signature_sha256: Option<String>,
    signature_verified: bool,
    denial_code: Option<u32>,
    denial_retryable: Option<bool>,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
enum QualificationResult {
    Signed,
    SealedDenied,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) struct QualificationEvidence {
    version: u8,
    result: QualificationResult,
    invocation_id: String,
    policy_generation: u64,
    target_key_id: String,
    config_sha256: String,
    ca_sha256: String,
    statement_sha256: String,
    signature_sha256: Option<String>,
    signature_verified: bool,
    denial_code: Option<u32>,
    denial_retryable: Option<bool>,
}

fn qualification_statement(
    config_sha256: &[u8; 32],
    proof_jkt: &[u8; 32],
    challenge: &[u8; 32],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(STATEMENT_DOMAIN);
    digest.update(config_sha256);
    digest.update(proof_jkt);
    digest.update(challenge);
    digest.finalize().into()
}

fn proof_key_cose(public: [u8; 32]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(40);
    encoded.extend_from_slice(&[0xa3, 0x01, 0x01, 0x20, 0x06, 0x21, 0x58, 0x20]);
    encoded.extend_from_slice(&public);
    encoded
}

fn random_message_id() -> Result<String> {
    let mut bytes = Zeroizing::new([0_u8; 16]);
    getrandom::fill(&mut *bytes)
        .map_err(|error| anyhow!("generating CI qualification message ID: {error}"))?;
    Ok(URL_SAFE_NO_PAD.encode(*bytes))
}

fn unix_now() -> Result<u32> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("reading CI qualification clock")?
        .as_secs();
    u32::try_from(seconds).map_err(|_| anyhow!("CI qualification clock is out of range"))
}

fn exact_https_origin(value: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(value).context("parsing CI qualification courier origin")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
        || value != url.origin().ascii_serialization()
    {
        bail!("CI qualification courier origin is not an exact HTTPS origin");
    }
    Ok(url)
}

fn validate_id(value: &str) -> Result<()> {
    KeyId::from_text(value).context("validating CI qualification key ID")?;
    Ok(())
}

fn decode_public_key(value: &str) -> Result<[u8; 32]> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .context("decoding CI qualification public key")?;
    let key: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow!("CI qualification public key is not 32 bytes"))?;
    if URL_SAFE_NO_PAD.encode(key) != value {
        bail!("CI qualification public key is not canonical base64url");
    }
    Ok(key)
}

fn read_pinned_root_file(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    read_pinned_file_for_uid(path, limit, 0)
}

fn read_pinned_file_for_uid(
    path: &Path,
    limit: usize,
    expected_uid: u32,
) -> Result<Zeroizing<Vec<u8>>> {
    read_pinned_file_for_uid_with_after_read(path, limit, expected_uid, || {})
}

fn read_pinned_file_for_uid_with_after_read<F>(
    path: &Path,
    limit: usize,
    expected_uid: u32,
    after_read: F,
) -> Result<Zeroizing<Vec<u8>>>
where
    F: FnOnce(),
{
    if !path.is_absolute() {
        bail!("CI qualification path must be absolute");
    }
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::RootDir)) {
        bail!("CI qualification path must begin at the filesystem root");
    }
    let mut parts = components.peekable();
    let mut directory = rustix::fs::open(
        "/",
        OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::RDONLY,
        Mode::empty(),
    )?;
    validate_trusted_directory(&directory, expected_uid)?;
    let mut file = None;
    let mut basename = None;
    while let Some(component) = parts.next() {
        let Component::Normal(name) = component else {
            bail!("CI qualification path contains an unsupported component");
        };
        if parts.peek().is_some() {
            directory = rustix::fs::openat(
                &directory,
                name,
                OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::RDONLY,
                Mode::empty(),
            )?;
            validate_trusted_directory(&directory, expected_uid)?;
        } else {
            basename = Some(name.to_os_string());
            file = Some(rustix::fs::openat(
                &directory,
                name,
                OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::RDONLY,
                Mode::empty(),
            )?);
        }
    }
    let descriptor = file.ok_or_else(|| anyhow!("CI qualification path has no file name"))?;
    let stat = rustix::fs::fstat(&descriptor)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != expected_uid
        || stat.st_nlink != 1
        || stat.st_mode & 0o022 != 0
        || stat.st_size <= 0
        || u64::try_from(stat.st_size).map_or(true, |length| length > limit as u64)
    {
        bail!("CI qualification file provenance is invalid");
    }
    let mut source = std::fs::File::from(descriptor);
    let mut bytes = Zeroizing::new(Vec::new());
    source
        .by_ref()
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty()
        || bytes.len() > limit
        || i64::try_from(bytes.len()).ok() != Some(stat.st_size)
    {
        bail!("CI qualification file changed while being read");
    }
    after_read();
    let after = rustix::fs::fstat(&source)?;
    let basename = basename.ok_or_else(|| anyhow!("CI qualification path has no file name"))?;
    let linked = rustix::fs::statat(&directory, &basename, AtFlags::SYMLINK_NOFOLLOW)?;
    if !same_file_snapshot(&stat, &after) || !same_file_snapshot(&stat, &linked) {
        bail!("CI qualification file changed while being read");
    }
    Ok(bytes)
}

fn validate_trusted_directory(directory: &OwnedFd, expected_uid: u32) -> Result<()> {
    let stat = rustix::fs::fstat(directory)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || (stat.st_uid != 0 && stat.st_uid != expected_uid)
        || stat.st_mode & 0o022 != 0
    {
        bail!("CI qualification path ancestor is not trusted");
    }
    Ok(())
}

const fn same_file_snapshot(left: &rustix::fs::Stat, right: &rustix::fs::Stat) -> bool {
    left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
        && left.st_mode == right.st_mode
        && left.st_uid == right.st_uid
        && left.st_gid == right.st_gid
        && left.st_nlink == right.st_nlink
        && left.st_size == right.st_size
        && left.st_mtime == right.st_mtime
        && left.st_mtime_nsec == right.st_mtime_nsec
        && left.st_ctime == right.st_ctime
        && left.st_ctime_nsec == right.st_ctime_nsec
}

fn parse_certificate_only_pem(bytes: &[u8]) -> Result<Vec<reqwest::Certificate>> {
    let mut remaining = bytes;
    let mut certificates = Vec::new();
    loop {
        remaining = remaining.trim_ascii();
        if remaining.is_empty() {
            break;
        }
        if !remaining.starts_with(b"-----BEGIN CERTIFICATE-----") {
            bail!("CI qualification CA bundle is not certificate-only PEM");
        }
        let (rest, pem) = x509_parser::pem::parse_x509_pem(remaining)
            .map_err(|_| anyhow!("CI qualification CA bundle is invalid"))?;
        if pem.label != "CERTIFICATE" || certificates.len() >= MAX_CA_CERTIFICATES {
            bail!("CI qualification CA bundle is invalid");
        }
        let (der_rest, _) = x509_parser::parse_x509_certificate(&pem.contents)
            .map_err(|_| anyhow!("CI qualification CA certificate is invalid"))?;
        if !der_rest.is_empty() {
            bail!("CI qualification CA certificate has trailing bytes");
        }
        certificates.push(
            reqwest::Certificate::from_der(&pem.contents)
                .map_err(|_| anyhow!("CI qualification CA certificate is invalid"))?,
        );
        remaining = rest;
    }
    if certificates.is_empty() {
        bail!("CI qualification CA bundle is empty");
    }
    Ok(certificates)
}

#[cfg(test)]
mod tests {
    use std::fs::Permissions;
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    use std::sync::{Arc, Barrier};

    use basil_proto::invocation::InvocationStatus;
    use ed25519_dalek::{Signer as _, SigningKey};
    use tokio::io::AsyncWriteExt as _;

    use super::*;

    const TEST_CERTIFICATE: &[u8] = include_bytes!("../../basil-core/testdata/jwks_tls_cert.pem");

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let base = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/test-tmp/ci-qualification");
            std::fs::create_dir_all(&base).expect("create trusted test parent");
            let base = base.canonicalize().expect("canonical test parent");
            std::fs::set_permissions(&base, Permissions::from_mode(0o700))
                .expect("protect trusted test parent");
            for attempt in 0..100_u32 {
                let path = base.join(format!("{label}-{}-{attempt}", std::process::id()));
                if std::fs::create_dir(&path).is_ok() {
                    std::fs::set_permissions(&path, Permissions::from_mode(0o700))
                        .expect("protect test directory");
                    return Self(path);
                }
            }
            panic!("could not allocate test directory");
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).expect("remove test directory");
        }
    }

    fn test_config(expected_result: ExpectedResult, public_key: [u8; 32]) -> QualificationConfig {
        QualificationConfig {
            provider_kind: "github".to_string(),
            expected_token_request_origin: "https://tokens.example".to_string(),
            rule_max_token_age_seconds: 300,
            courier_origin: reqwest::Url::parse("https://courier.example").expect("URL"),
            broker_audience: "basil-broker".to_string(),
            request_encryption_key_id: "request-key".to_string(),
            request_encryption_public_key: [1; 32],
            response_signing_key_id: "response-key".to_string(),
            response_signing_public_key: [2; 32],
            artifact_sign_key_id: "artifact-key".to_string(),
            artifact_sign_public_key: public_key,
            expected_result,
            config_sha256: [3; 32],
            ca_sha256: [4; 32],
            certificates: Vec::new(),
        }
    }

    fn test_adapter(
        expected_result: ExpectedResult,
        public_key: [u8; 32],
    ) -> ArtifactSignQualificationAdapter {
        super::super::install_rustls_provider();
        ArtifactSignQualificationAdapter {
            config: test_config(expected_result, public_key),
            client: reqwest::Client::new(),
            used: AtomicBool::new(false),
        }
    }

    #[test]
    fn strict_config_schema_and_bootstrap_cross_check() {
        let key = URL_SAFE_NO_PAD.encode([1_u8; 32]);
        let json = format!(
            r#"{{"version":1,"providerKind":"github","expectedTokenRequestOrigin":"https://tokens.example","ruleMaxTokenAgeSeconds":300,"courierOrigin":"https://courier.example","courierCaBundlePath":"/etc/basil/ca.pem","brokerAudience":"basil-broker","requestEncryptionKeyId":"request-key","requestEncryptionPublicKey":"{key}","responseSigningKeyId":"response-key","responseSigningPublicKey":"{key}","artifactSignKeyId":"artifact-key","artifactSignPublicKey":"{key}","expectedResult":"success"}}"#
        );
        let parsed: QualificationConfigFile =
            serde_json::from_str(&json).expect("closed config parses");
        assert_eq!(parsed.version, 1);
        let with_unknown = json.replacen('{', r#"{"unknown":true,"#, 1);
        assert!(serde_json::from_str::<QualificationConfigFile>(&with_unknown).is_err());

        let config = test_config(ExpectedResult::Success, [1; 32]);
        assert!(
            config
                .cross_check("github", "https://tokens.example", 300)
                .is_ok()
        );
        assert!(
            config
                .cross_check("forgejoActions", "https://tokens.example", 300)
                .is_err()
        );
        assert!(
            config
                .cross_check("github", "https://other.example", 300)
                .is_err()
        );
        assert!(
            config
                .cross_check("github", "https://tokens.example", 299)
                .is_err()
        );
    }

    #[test]
    fn pinned_file_rejects_bad_provenance_bounds_and_replacement() {
        let directory = TestDirectory::new("pinned");
        let uid = rustix::process::geteuid().as_raw();
        let good = directory.path().join("good");
        std::fs::write(&good, b"trusted").expect("write good file");
        std::fs::set_permissions(&good, Permissions::from_mode(0o600)).expect("protect good file");
        assert_eq!(
            &*read_pinned_file_for_uid(&good, 16, uid).expect("pinned read"),
            b"trusted"
        );

        let empty = directory.path().join("empty");
        std::fs::write(&empty, b"").expect("write empty file");
        assert!(read_pinned_file_for_uid(&empty, 16, uid).is_err());
        let large = directory.path().join("large");
        std::fs::write(&large, [0_u8; 17]).expect("write large file");
        assert!(read_pinned_file_for_uid(&large, 16, uid).is_err());
        let writable = directory.path().join("writable");
        std::fs::write(&writable, b"value").expect("write writable file");
        std::fs::set_permissions(&writable, Permissions::from_mode(0o620))
            .expect("make file group writable");
        assert!(read_pinned_file_for_uid(&writable, 16, uid).is_err());

        let hardlink = directory.path().join("hardlink");
        std::fs::hard_link(&good, &hardlink).expect("create hard link");
        assert!(read_pinned_file_for_uid(&good, 16, uid).is_err());
        std::fs::remove_file(hardlink).expect("remove hard link");
        let symlink_path = directory.path().join("symlink");
        symlink(&good, &symlink_path).expect("create symlink");
        assert!(read_pinned_file_for_uid(&symlink_path, 16, uid).is_err());

        let writable_ancestor = directory.path().join("writable-ancestor");
        std::fs::create_dir(&writable_ancestor).expect("create writable ancestor");
        std::fs::set_permissions(&writable_ancestor, Permissions::from_mode(0o770))
            .expect("make ancestor group writable");
        let under_writable = writable_ancestor.join("file");
        std::fs::write(&under_writable, b"value").expect("write nested file");
        assert!(read_pinned_file_for_uid(&under_writable, 16, uid).is_err());

        let real_ancestor = directory.path().join("real-ancestor");
        std::fs::create_dir(&real_ancestor).expect("create real ancestor");
        let nested = real_ancestor.join("file");
        std::fs::write(&nested, b"value").expect("write nested file");
        let linked_ancestor = directory.path().join("linked-ancestor");
        symlink(&real_ancestor, &linked_ancestor).expect("link ancestor");
        assert!(read_pinned_file_for_uid(&linked_ancestor.join("file"), 16, uid).is_err());

        let mutable = directory.path().join("mutable");
        std::fs::write(&mutable, b"before").expect("write mutable file");
        assert!(
            read_pinned_file_for_uid_with_after_read(&mutable, 16, uid, || {
                std::fs::write(&mutable, b"after-longer").expect("rewrite pinned file");
            })
            .is_err()
        );
    }

    #[test]
    fn certificate_parser_rejects_mixed_sections_and_garbage() {
        assert_eq!(
            parse_certificate_only_pem(TEST_CERTIFICATE)
                .expect("certificate-only bundle")
                .len(),
            1
        );
        let mut mixed = TEST_CERTIFICATE.to_vec();
        mixed
            .extend_from_slice(b"\n-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n");
        assert!(parse_certificate_only_pem(&mixed).is_err());
        let mut garbage = TEST_CERTIFICATE.to_vec();
        garbage.extend_from_slice(b"recognizable-trailing-garbage");
        assert!(parse_certificate_only_pem(&garbage).is_err());
        assert!(parse_certificate_only_pem(b"").is_err());
    }

    #[test]
    fn request_is_exact_and_one_shot_gate_is_concurrent() {
        assert!(ArtifactSignQualificationAdapter::decode_request(ADAPTER_REQUEST).is_ok());
        assert!(
            ArtifactSignQualificationAdapter::decode_request(
                br#"{"operation":"artifact-sign-qualification","version":1}"#,
            )
            .is_err()
        );
        assert_eq!(
            ArtifactSignQualificationAdapter::REQUEST_MAX_BYTES,
            ADAPTER_REQUEST.len()
        );

        let gate = Arc::new(AtomicBool::new(false));
        let barrier = Arc::new(Barrier::new(9));
        let mut threads = Vec::new();
        for _ in 0..8 {
            let gate = Arc::clone(&gate);
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                claim_one_shot(&gate).is_ok()
            }));
        }
        barrier.wait();
        let successes = threads
            .into_iter()
            .map(|thread| thread.join().expect("join claimant"))
            .filter(|success| *success)
            .count();
        assert_eq!(successes, 1);
    }

    #[tokio::test]
    async fn malformed_first_frame_consumes_the_adapter_attempt() {
        let adapter = test_adapter(ExpectedResult::Success, [0; 32]);
        let (mut client, mut server) = tokio::net::UnixStream::pair().expect("socket pair");
        client.write_u32(0).await.expect("write malformed length");
        assert!(
            super::super::read_adapter_request(&mut server, &adapter)
                .await
                .is_err()
        );
        assert!(adapter.claim_request().is_err());
    }

    #[test]
    fn statement_digest_binds_every_component() {
        let baseline = qualification_statement(&[1; 32], &[2; 32], &[3; 32]);
        assert_ne!(
            baseline,
            qualification_statement(&[9; 32], &[2; 32], &[3; 32])
        );
        assert_ne!(
            baseline,
            qualification_statement(&[1; 32], &[9; 32], &[3; 32])
        );
        assert_ne!(
            baseline,
            qualification_statement(&[1; 32], &[2; 32], &[9; 32])
        );
    }

    #[test]
    fn signed_and_denied_results_are_closed() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let statement = [8_u8; 32];
        let mut signed = SignInvocationResponse {
            status: InvocationStatus::ok(),
            policy_generation: 42,
            signature: Some(signing_key.sign(&statement).to_bytes().to_vec()),
        };
        let signed_outcome = test_adapter(
            ExpectedResult::Success,
            signing_key.verifying_key().to_bytes(),
        )
        .validate_result(&mut signed, &statement)
        .expect("verified signature");
        assert!(signed_outcome.signature_verified);
        assert_eq!(
            signed_outcome.signature_sha256.as_deref().map(str::len),
            Some(64)
        );
        assert!(signed.signature.is_none());

        let mut denied = SignInvocationResponse {
            status: InvocationStatus {
                code: InvocationStatusCode::Denied,
                reason: "POLICY_DENIED".to_string(),
                message: None,
                retryable: false,
            },
            policy_generation: 43,
            signature: None,
        };
        let denied_outcome = test_adapter(ExpectedResult::SealedDenied, [0; 32])
            .validate_result(&mut denied, &statement)
            .expect("closed denial");
        assert_eq!(denied_outcome.denial_code, Some(2));
        assert_eq!(denied_outcome.denial_retryable, Some(false));
        assert!(!denied_outcome.signature_verified);

        denied.status.retryable = true;
        assert!(
            test_adapter(ExpectedResult::SealedDenied, [0; 32])
                .validate_result(&mut denied, &statement)
                .is_err()
        );
    }

    #[test]
    fn receipt_is_bounded_and_contains_no_secret_carriers() {
        let evidence = QualificationEvidence {
            version: 1,
            result: QualificationResult::Signed,
            invocation_id: URL_SAFE_NO_PAD.encode([1_u8; 32]),
            policy_generation: u64::MAX,
            target_key_id: "artifact-key".to_string(),
            config_sha256: "a".repeat(64),
            ca_sha256: "b".repeat(64),
            statement_sha256: "c".repeat(64),
            signature_sha256: Some("d".repeat(64)),
            signature_verified: true,
            denial_code: None,
            denial_retryable: None,
        };
        let encoded = serde_json::to_vec(&evidence).expect("serialize evidence");
        assert!(encoded.len() <= MAX_EVIDENCE_BYTES);
        let text = std::str::from_utf8(&encoded).expect("JSON UTF-8");
        for forbidden in ["provider.jwt", "challenge", "proof-key", "raw-signature"] {
            assert!(!text.contains(forbidden));
        }
        assert!(text.contains(r#""signature-sha256""#));
        assert!(text.contains(r#""denial-code":null"#));
    }
}
