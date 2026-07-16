// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Sigstore OCI signer policy and exact digest-chain verification.
//!
//! Cosign is an intentionally narrow cryptographic subprocess boundary. Basil
//! invokes one protected absolute executable without a shell or inherited
//! environment, supplies only immutable `repository@sha256:...` references,
//! bounds output and time, and kills the complete process group on timeout or
//! cancellation. Cosign's success is necessary but not sufficient: this module
//! independently hashes and parses the registry index/manifest bytes and checks
//! repository, platform, manifest, config, and signed-payload correlation.

use std::fmt;
use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rustix::process::{Pid, Signal, kill_process_group};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tokio::io::AsyncReadExt as _;
use tokio::process::{Child, Command};
use tokio::time::{Instant, timeout_at};

/// Maximum UTF-8 bytes in a signer-policy name.
pub const MAX_SIGNER_POLICY_NAME_BYTES: usize = 128;
/// Maximum UTF-8 bytes in a repository, issuer, or signer identity.
pub const MAX_SIGNER_VALUE_BYTES: usize = 512;
/// Maximum raw OCI index or manifest bytes accepted for verification.
pub const MAX_OCI_DOCUMENT_BYTES: usize = 4 * 1024 * 1024;
/// Maximum descriptors accepted in one OCI index.
pub const MAX_INDEX_MANIFESTS: usize = 256;
/// Maximum Cosign stdout bytes.
pub const MAX_COSIGN_STDOUT_BYTES: u64 = 1024 * 1024;
/// Maximum Cosign stderr bytes retained transiently before redaction.
pub const MAX_COSIGN_STDERR_BYTES: u64 = 64 * 1024;
/// Maximum Cosign JSON records considered.
pub const MAX_COSIGN_RECORDS: usize = 16;

/// Whether a pinned-key policy requires transparency-log verification.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransparencyPolicy {
    /// Cosign must validate transparency inclusion.
    Required,
    /// Policy deliberately permits verification without transparency.
    Optional,
}

/// Supported Sigstore signer identity modes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "mode", rename_all = "kebab-case", deny_unknown_fields)]
pub enum OciSignerMode {
    /// Exact protected public-key file.
    PinnedKey {
        /// Absolute protected public-key path passed directly to Cosign.
        #[serde(rename = "publicKey")]
        public_key: PathBuf,
        /// Policy-selected transparency requirement.
        transparency: TransparencyPolicy,
    },
    /// Exact keyless OIDC issuer and certificate identity.
    Keyless {
        /// Exact certificate OIDC issuer.
        issuer: String,
        /// Exact certificate identity; no regular expression is accepted.
        identity: String,
    },
}

/// One named policy's repository scope and signer identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OciSignerPolicy {
    /// Exact lowercase OCI repository without tag or digest.
    pub repository: String,
    /// Pinned-key or keyless signer rules.
    #[serde(flatten)]
    pub signer: OciSignerMode,
}

/// Structural signer-policy error. Values are intentionally omitted.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum SignerPolicyError {
    /// Policy name is empty, too large, or unsafe for diagnostics.
    #[error("invalid signer-policy name")]
    Name,
    /// Repository scope is not one exact immutable-reference repository.
    #[error("invalid signer-policy repository scope")]
    Repository,
    /// A protected key path is not absolute or contains lexical traversal.
    #[error("invalid signer-policy public-key path")]
    PublicKeyPath,
    /// Issuer or identity is empty, oversized, or contains control bytes.
    #[error("invalid keyless signer identity")]
    KeylessIdentity,
}

/// Strictly validate one schema-3 named signer policy.
pub fn validate_signer_policy(
    name: &str,
    policy: &OciSignerPolicy,
) -> Result<(), SignerPolicyError> {
    if !bounded_printable(name, MAX_SIGNER_POLICY_NAME_BYTES) {
        return Err(SignerPolicyError::Name);
    }
    validate_repository(&policy.repository)?;
    match &policy.signer {
        OciSignerMode::PinnedKey { public_key, .. } => validate_absolute_path(public_key),
        OciSignerMode::Keyless { issuer, identity } => {
            if bounded_printable(issuer, MAX_SIGNER_VALUE_BYTES)
                && bounded_printable(identity, MAX_SIGNER_VALUE_BYTES)
            {
                Ok(())
            } else {
                Err(SignerPolicyError::KeylessIdentity)
            }
        }
    }
}

fn bounded_printable(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

fn validate_repository(repository: &str) -> Result<(), SignerPolicyError> {
    if !bounded_printable(repository, MAX_SIGNER_VALUE_BYTES)
        || repository.starts_with('/')
        || repository.ends_with('/')
        || repository.contains('@')
        || repository.contains("..")
        || repository
            .split('/')
            .skip(1)
            .any(|component| component.is_empty() || component.contains(':'))
        || repository.chars().any(|character| {
            !(character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '.' | '-' | '_' | '/' | ':'))
        })
    {
        return Err(SignerPolicyError::Repository);
    }
    Ok(())
}

fn validate_absolute_path(path: &Path) -> Result<(), SignerPolicyError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(SignerPolicyError::PublicKeyPath);
    }
    Ok(())
}

/// Exact `sha256:<lowerhex>` OCI digest.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OciDigest([u8; 32]);

impl OciDigest {
    /// Parse the only OCI digest algorithm admitted by this profile.
    pub fn parse(value: &str) -> Result<Self, DigestChainError> {
        let Some(hex) = value.strip_prefix("sha256:") else {
            return Err(DigestChainError::Digest);
        };
        if hex.len() != 64
            || hex
                .bytes()
                .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
        {
            return Err(DigestChainError::Digest);
        }
        let mut digest = [0_u8; 32];
        for (slot, pair) in digest.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
            let pair = std::str::from_utf8(pair).map_err(|_| DigestChainError::Digest)?;
            *slot = u8::from_str_radix(pair, 16).map_err(|_| DigestChainError::Digest)?;
        }
        Ok(Self(digest))
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }
}

impl fmt::Debug for OciDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for OciDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "sha256:")?;
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Selected OCI platform.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OciPlatform {
    /// Operating-system token, for example `linux`.
    pub operating_system: String,
    /// Architecture token, for example `amd64`.
    pub architecture: String,
    /// Optional exact variant, for example `v7`.
    pub variant: Option<String>,
}

impl OciPlatform {
    fn validate(&self) -> Result<(), DigestChainError> {
        if !platform_token(&self.operating_system)
            || !platform_token(&self.architecture)
            || self
                .variant
                .as_deref()
                .is_some_and(|value| !platform_token(value))
        {
            return Err(DigestChainError::Platform);
        }
        Ok(())
    }
}

fn platform_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

/// Raw OCI JSON bytes plus the registry-asserted digest.
#[derive(Clone, Debug)]
pub struct OciDocument {
    /// Registry descriptor digest.
    pub digest: OciDigest,
    /// Exact bytes whose SHA-256 must equal `digest`.
    pub bytes: Vec<u8>,
}

/// Whether the accepted signature covers the index or selected manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignedOciObject {
    /// Multi-platform index.
    Index,
    /// Selected platform manifest.
    Manifest,
}

/// Runtime/registry inputs required for exact chain verification.
#[derive(Clone, Debug)]
pub struct OciImageChain {
    /// Exact repository independently selected for this workload.
    pub repository: String,
    /// Selected platform.
    pub platform: OciPlatform,
    /// Optional containing multi-platform index.
    pub index: Option<OciDocument>,
    /// Selected platform manifest.
    pub manifest: OciDocument,
    /// Config digest reported for the running container.
    pub running_config: OciDigest,
    /// Object whose signature is being accepted.
    pub signed_object: SignedOciObject,
}

/// Independent digest-chain validation failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum DigestChainError {
    /// Digest syntax, algorithm, or content hash is invalid.
    #[error("OCI digest validation failed")]
    Digest,
    /// Raw OCI document is oversized or malformed.
    #[error("OCI document validation failed")]
    Document,
    /// Repository differs from policy or is not exact.
    #[error("OCI repository validation failed")]
    Repository,
    /// Selected platform is invalid, absent, or ambiguous.
    #[error("OCI platform validation failed")]
    Platform,
    /// Index, manifest, config, or signed-object correlation failed.
    #[error("OCI digest chain does not correlate")]
    Correlation,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IndexDocument {
    #[serde(rename = "schemaVersion")]
    schema_version: u8,
    manifests: Vec<IndexDescriptor>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IndexDescriptor {
    #[serde(rename = "mediaType")]
    _media_type: Option<String>,
    digest: String,
    _size: Option<u64>,
    platform: DescriptorPlatform,
    #[serde(default, rename = "annotations")]
    _annotations: std::collections::BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DescriptorPlatform {
    architecture: String,
    os: String,
    variant: Option<String>,
    #[serde(default, rename = "os.version")]
    _os_version: Option<String>,
    #[serde(default, rename = "os.features")]
    _os_features: Vec<String>,
    #[serde(default, rename = "features")]
    _features: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestDocument {
    #[serde(rename = "schemaVersion")]
    schema_version: u8,
    #[serde(rename = "mediaType")]
    _media_type: Option<String>,
    config: ManifestDescriptor,
    #[serde(rename = "layers")]
    _layers: Vec<ManifestDescriptor>,
    #[serde(default, rename = "annotations")]
    _annotations: std::collections::BTreeMap<String, String>,
    #[serde(rename = "subject")]
    _subject: Option<ManifestDescriptor>,
    #[serde(rename = "artifactType")]
    _artifact_type: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestDescriptor {
    #[serde(rename = "mediaType")]
    _media_type: Option<String>,
    digest: String,
    _size: Option<u64>,
    #[serde(default, rename = "annotations")]
    _annotations: std::collections::BTreeMap<String, String>,
    #[serde(default, rename = "urls")]
    _urls: Vec<String>,
    #[serde(default, rename = "data")]
    _data: Option<String>,
    #[serde(default, rename = "artifactType")]
    _artifact_type: Option<String>,
    #[serde(default, rename = "platform")]
    _platform: Option<DescriptorPlatform>,
}

#[derive(Clone, Copy, Debug)]
struct ValidatedChain {
    subject: OciDigest,
    manifest: OciDigest,
    config: OciDigest,
}

// OCI JSON spells this field `os`, while the public typed input deliberately
// uses `operating_system`; their comparison is intentional.
#[allow(clippy::suspicious_operation_groupings)]
fn validate_chain(
    policy: &OciSignerPolicy,
    chain: &OciImageChain,
) -> Result<ValidatedChain, DigestChainError> {
    validate_repository(&chain.repository).map_err(|_| DigestChainError::Repository)?;
    if chain.repository != policy.repository {
        return Err(DigestChainError::Repository);
    }
    chain.platform.validate()?;
    validate_document_hash(&chain.manifest)?;
    let manifest: ManifestDocument = parse_document(&chain.manifest.bytes)?;
    if manifest.schema_version != 2 {
        return Err(DigestChainError::Document);
    }
    let config_digest = OciDigest::parse(&manifest.config.digest)?;
    if config_digest != chain.running_config {
        return Err(DigestChainError::Correlation);
    }
    if let Some(index) = &chain.index {
        validate_document_hash(index)?;
        let parsed: IndexDocument = parse_document(&index.bytes)?;
        if parsed.schema_version != 2 || parsed.manifests.len() > MAX_INDEX_MANIFESTS {
            return Err(DigestChainError::Document);
        }
        let expected_platform = &chain.platform;
        let mut matching = parsed.manifests.iter().filter(|descriptor| {
            let actual_platform = &descriptor.platform;
            actual_platform.os == expected_platform.operating_system
                && actual_platform.architecture == expected_platform.architecture
                && actual_platform.variant == expected_platform.variant
        });
        let Some(selected) = matching.next() else {
            return Err(DigestChainError::Platform);
        };
        if matching.next().is_some() || OciDigest::parse(&selected.digest)? != chain.manifest.digest
        {
            return Err(DigestChainError::Correlation);
        }
    } else if chain.signed_object == SignedOciObject::Index {
        return Err(DigestChainError::Correlation);
    }
    let signed_digest = match chain.signed_object {
        SignedOciObject::Index => chain
            .index
            .as_ref()
            .map(|index| index.digest)
            .ok_or(DigestChainError::Correlation)?,
        SignedOciObject::Manifest => chain.manifest.digest,
    };
    Ok(ValidatedChain {
        subject: signed_digest,
        manifest: chain.manifest.digest,
        config: config_digest,
    })
}

fn validate_document_hash(document: &OciDocument) -> Result<(), DigestChainError> {
    if document.bytes.len() > MAX_OCI_DOCUMENT_BYTES
        || OciDigest::from_bytes(&document.bytes) != document.digest
    {
        return Err(DigestChainError::Digest);
    }
    Ok(())
}

fn parse_document<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, DigestChainError> {
    serde_json::from_slice(bytes).map_err(|_| DigestChainError::Document)
}

/// Process isolation settings for the packaged Cosign verifier.
#[derive(Clone, Debug)]
pub struct CosignConfig {
    /// Protected exact executable path; `PATH` is never consulted.
    pub executable: PathBuf,
    /// Private parent under which one mode-`0700` temporary directory is made.
    pub temp_parent: PathBuf,
    /// Complete verification deadline.
    pub deadline: Duration,
}

impl CosignConfig {
    /// Validate bounded execution configuration and protected path shape.
    #[allow(clippy::incompatible_msrv)]
    pub fn validate(&self) -> Result<(), OciVerificationError> {
        if self.deadline.is_zero() || self.deadline > Duration::from_mins(5) {
            return Err(OciVerificationError::Configuration);
        }
        validate_protected_file(&self.executable)?;
        Ok(())
    }
}

/// Successful signer evidence admitted for the exact running chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OciVerificationEvidence {
    /// Named signer policy that matched.
    pub policy: String,
    /// Exact verified repository.
    pub repository: String,
    /// Signed index or selected manifest.
    pub signed_object: SignedOciObject,
    /// Digest covered by the accepted signature.
    pub signed_digest: OciDigest,
    /// Selected manifest digest.
    pub manifest_digest: OciDigest,
    /// Running config digest.
    pub config_digest: OciDigest,
    /// Selected platform.
    pub platform: OciPlatform,
}

/// Disclosure-safe OCI verification failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum OciVerificationError {
    /// Invalid verifier configuration or unprotected executable/key path.
    #[error("OCI verifier configuration is invalid")]
    Configuration,
    /// Signer policy is invalid.
    #[error("OCI signer policy is invalid")]
    Policy,
    /// Repository/index/manifest/config correlation failed.
    #[error("OCI digest-chain verification failed")]
    DigestChain,
    /// Cosign could not be started or its pipes failed.
    #[error("OCI verifier is unavailable")]
    Unavailable,
    /// Cosign rejected the signature or exited abnormally.
    #[error("OCI signature verification failed")]
    Rejected,
    /// Cosign exceeded its deadline.
    #[error("OCI signature verification timed out")]
    Timeout,
    /// Cosign output exceeded a hard byte bound.
    #[error("OCI verifier output exceeded its limit")]
    OutputLimit,
    /// Cosign produced malformed or non-correlating JSON.
    #[error("OCI verifier output was malformed")]
    MalformedOutput,
}

impl From<DigestChainError> for OciVerificationError {
    fn from(_: DigestChainError) -> Self {
        Self::DigestChain
    }
}

/// Exact-path packaged Cosign verifier.
#[derive(Clone, Debug)]
pub struct CosignVerifier {
    config: CosignConfig,
}

impl CosignVerifier {
    /// Construct after validating protected execution settings.
    pub fn new(config: CosignConfig) -> Result<Self, OciVerificationError> {
        config.validate()?;
        Ok(Self { config })
    }

    /// Verify one named policy and exact running OCI digest chain.
    pub async fn verify(
        &self,
        policy_name: &str,
        policy: &OciSignerPolicy,
        chain: &OciImageChain,
    ) -> Result<OciVerificationEvidence, OciVerificationError> {
        validate_signer_policy(policy_name, policy).map_err(|_| OciVerificationError::Policy)?;
        let validated = validate_chain(policy, chain)?;
        if let OciSignerMode::PinnedKey { public_key, .. } = &policy.signer {
            validate_protected_file(public_key)?;
        }
        let temp = PrivateTempDir::create(&self.config.temp_parent)?;
        let reference = format!("{}@{}", chain.repository, validated.subject);
        let mut command = Command::new(&self.config.executable);
        command
            .arg("verify")
            .arg("--output=json")
            .env_clear()
            .env("TMPDIR", temp.path())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .process_group(0);
        match &policy.signer {
            OciSignerMode::PinnedKey {
                public_key,
                transparency,
            } => {
                command.arg("--key").arg(public_key);
                if *transparency == TransparencyPolicy::Optional {
                    command.arg("--insecure-ignore-tlog");
                }
            }
            OciSignerMode::Keyless { issuer, identity } => {
                command
                    .arg("--certificate-oidc-issuer")
                    .arg(issuer)
                    .arg("--certificate-identity")
                    .arg(identity);
            }
        }
        command.arg("--").arg(&reference);
        let child = command
            .spawn()
            .map_err(|_| OciVerificationError::Unavailable)?;
        let output = wait_bounded(child, self.config.deadline).await?;
        if !output.status.success() {
            return Err(OciVerificationError::Rejected);
        }
        validate_cosign_output(&output.stdout, policy, &reference, validated.subject)?;
        Ok(OciVerificationEvidence {
            policy: policy_name.to_string(),
            repository: chain.repository.clone(),
            signed_object: chain.signed_object,
            signed_digest: validated.subject,
            manifest_digest: validated.manifest,
            config_digest: validated.config,
            platform: chain.platform.clone(),
        })
    }
}

fn validate_protected_file(path: &Path) -> Result<(), OciVerificationError> {
    validate_absolute_path(path).map_err(|_| OciVerificationError::Configuration)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| OciVerificationError::Configuration)?;
    if !metadata.file_type().is_file()
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.nlink() == 0
    {
        return Err(OciVerificationError::Configuration);
    }
    Ok(())
}

struct PrivateTempDir(PathBuf);

impl PrivateTempDir {
    fn create(parent: &Path) -> Result<Self, OciVerificationError> {
        let metadata =
            fs::symlink_metadata(parent).map_err(|_| OciVerificationError::Configuration)?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o022 != 0 {
            return Err(OciVerificationError::Configuration);
        }
        for _ in 0..8 {
            let path = parent.join(format!("basil-cosign-{}", uuid::Uuid::new_v4()));
            match fs::create_dir(&path) {
                Ok(()) => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                        .map_err(|_| OciVerificationError::Unavailable)?;
                    return Ok(Self(path));
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(OciVerificationError::Unavailable),
            }
        }
        Err(OciVerificationError::Unavailable)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for PrivateTempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct ProcessGroupGuard(Option<Pid>);

impl ProcessGroupGuard {
    fn new(child: &Child) -> Self {
        Self(
            child
                .id()
                .and_then(|id| i32::try_from(id).ok())
                .and_then(Pid::from_raw),
        )
    }

    const fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        if let Some(pid) = self.0 {
            let _ = kill_process_group(pid, Signal::KILL);
        }
    }
}

struct BoundedOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
}

async fn wait_bounded(
    mut child: Child,
    duration: Duration,
) -> Result<BoundedOutput, OciVerificationError> {
    let mut guard = ProcessGroupGuard::new(&child);
    let stdout = child
        .stdout
        .take()
        .ok_or(OciVerificationError::Unavailable)?;
    let stderr = child
        .stderr
        .take()
        .ok_or(OciVerificationError::Unavailable)?;
    let deadline = Instant::now() + duration;
    let operation = async {
        let stdout = read_pipe(stdout, MAX_COSIGN_STDOUT_BYTES);
        let stderr = read_pipe(stderr, MAX_COSIGN_STDERR_BYTES);
        let status = child.wait();
        let (stdout, stderr, status) = tokio::join!(stdout, stderr, status);
        let stdout = stdout?;
        let _ = stderr?;
        let status = status.map_err(|_| OciVerificationError::Unavailable)?;
        Ok::<_, OciVerificationError>(BoundedOutput { status, stdout })
    };
    timeout_at(deadline, operation)
        .await
        .map_or(Err(OciVerificationError::Timeout), |result| {
            guard.disarm();
            result
        })
}

async fn read_pipe<R: tokio::io::AsyncRead + Unpin>(
    reader: R,
    limit: u64,
) -> Result<Vec<u8>, OciVerificationError> {
    let mut bytes = Vec::new();
    reader
        .take(limit)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| OciVerificationError::Unavailable)?;
    if u64::try_from(bytes.len()).map_or(true, |length| length >= limit) {
        return Err(OciVerificationError::OutputLimit);
    }
    Ok(bytes)
}

#[derive(Deserialize)]
struct CosignRecord {
    critical: CosignCritical,
    #[serde(default)]
    optional: std::collections::BTreeMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
struct CosignCritical {
    identity: CosignIdentity,
    image: CosignImage,
}

#[derive(Deserialize)]
struct CosignIdentity {
    #[serde(rename = "docker-reference")]
    docker_reference: String,
}

#[derive(Deserialize)]
struct CosignImage {
    #[serde(rename = "docker-manifest-digest")]
    docker_manifest_digest: String,
}

fn validate_cosign_output(
    bytes: &[u8],
    policy: &OciSignerPolicy,
    reference: &str,
    digest: OciDigest,
) -> Result<(), OciVerificationError> {
    let records: Vec<CosignRecord> =
        serde_json::from_slice(bytes).map_err(|_| OciVerificationError::MalformedOutput)?;
    if records.is_empty() || records.len() > MAX_COSIGN_RECORDS {
        return Err(OciVerificationError::MalformedOutput);
    }
    let expected_digest = digest.to_string();
    let matched = records.iter().any(|record| {
        let repository_matches = record.critical.identity.docker_reference == policy.repository
            || record.critical.identity.docker_reference == reference;
        let digest_matches = record.critical.image.docker_manifest_digest == expected_digest;
        let signer_matches = match &policy.signer {
            OciSignerMode::PinnedKey { .. } => true,
            OciSignerMode::Keyless { issuer, identity } => {
                optional_string(&record.optional, &["Issuer", "issuer"]) == Some(issuer.as_str())
                    && optional_string(&record.optional, &["Subject", "subject"])
                        == Some(identity.as_str())
            }
        };
        repository_matches && digest_matches && signer_matches
    });
    if matched {
        Ok(())
    } else {
        Err(OciVerificationError::MalformedOutput)
    }
}

fn optional_string<'a>(
    values: &'a std::collections::BTreeMap<String, serde_json::Value>,
    names: &[&str],
) -> Option<&'a str> {
    names
        .iter()
        .find_map(|name| values.get(*name).and_then(serde_json::Value::as_str))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    struct Fixture {
        root: PathBuf,
        key: PathBuf,
        manifest: OciDocument,
        index: OciDocument,
        config: OciDigest,
    }

    impl Fixture {
        fn new() -> Self {
            let suffix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = std::env::temp_dir().join(format!("basil-cosign-test-{suffix}"));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            let key = root.join("cosign.pub");
            fs::write(&key, "public key").unwrap();
            fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
            let config = OciDigest::from_bytes(b"running config");
            let manifest_bytes = format!(
                "{{\"schemaVersion\":2,\"config\":{{\"digest\":\"{config}\"}},\"layers\":[]}}"
            )
            .into_bytes();
            let manifest = OciDocument {
                digest: OciDigest::from_bytes(&manifest_bytes),
                bytes: manifest_bytes,
            };
            let index_bytes = format!(
                "{{\"schemaVersion\":2,\"manifests\":[{{\"digest\":\"{}\",\"platform\":{{\"architecture\":\"amd64\",\"os\":\"linux\"}}}}]}}",
                manifest.digest
            )
            .into_bytes();
            let index = OciDocument {
                digest: OciDigest::from_bytes(&index_bytes),
                bytes: index_bytes,
            };
            Self {
                root,
                key,
                manifest,
                index,
                config,
            }
        }

        fn policy(&self) -> OciSignerPolicy {
            OciSignerPolicy {
                repository: "registry.example/team/app".to_string(),
                signer: OciSignerMode::PinnedKey {
                    public_key: self.key.clone(),
                    transparency: TransparencyPolicy::Required,
                },
            }
        }

        fn chain(&self, signed_object: SignedOciObject) -> OciImageChain {
            OciImageChain {
                repository: "registry.example/team/app".to_string(),
                platform: OciPlatform {
                    operating_system: "linux".to_string(),
                    architecture: "amd64".to_string(),
                    variant: None,
                },
                index: Some(self.index.clone()),
                manifest: self.manifest.clone(),
                running_config: self.config,
                signed_object,
            }
        }

        fn executable(&self, body: &str) -> PathBuf {
            let path = self
                .root
                .join(format!("fake-cosign-{}", uuid::Uuid::new_v4()));
            fs::write(&path, format!("#!/usr/bin/env bash\nset -eu\n{body}\n")).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            path
        }

        fn verifier(&self, executable: PathBuf, deadline: Duration) -> CosignVerifier {
            CosignVerifier::new(CosignConfig {
                executable,
                temp_parent: self.root.clone(),
                deadline,
            })
            .unwrap()
        }

        fn success_script(
            &self,
            signed: OciDigest,
            issuer_subject: Option<(&str, &str)>,
        ) -> PathBuf {
            let optional = issuer_subject.map_or_else(
                || "{}".to_string(),
                |(issuer, subject)| {
                    format!("{{\"Issuer\":\"{issuer}\",\"Subject\":\"{subject}\"}}")
                },
            );
            self.executable(&format!(
                "printf '%s' '[{{\"critical\":{{\"identity\":{{\"docker-reference\":\"registry.example/team/app\"}},\"image\":{{\"docker-manifest-digest\":\"{signed}\"}}}},\"optional\":{optional}}}]'"
            ))
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[tokio::test]
    async fn valid_index_and_platform_manifest_signatures_succeed() {
        let fixture = Fixture::new();
        for signed_object in [SignedOciObject::Index, SignedOciObject::Manifest] {
            let chain = fixture.chain(signed_object);
            let signed = match signed_object {
                SignedOciObject::Index => fixture.index.digest,
                SignedOciObject::Manifest => fixture.manifest.digest,
            };
            let verifier =
                fixture.verifier(fixture.success_script(signed, None), Duration::from_secs(2));
            let evidence = verifier
                .verify("production", &fixture.policy(), &chain)
                .await
                .unwrap();
            assert_eq!(evidence.signed_object, signed_object);
            assert_eq!(evidence.signed_digest, signed);
            assert_eq!(evidence.config_digest, fixture.config);
        }
    }

    #[tokio::test]
    async fn exact_keyless_issuer_and_identity_are_required() {
        let fixture = Fixture::new();
        let policy = OciSignerPolicy {
            repository: "registry.example/team/app".to_string(),
            signer: OciSignerMode::Keyless {
                issuer: "https://issuer.example".to_string(),
                identity: "release@example.com".to_string(),
            },
        };
        let chain = fixture.chain(SignedOciObject::Manifest);
        let good = fixture.verifier(
            fixture.success_script(
                fixture.manifest.digest,
                Some(("https://issuer.example", "release@example.com")),
            ),
            Duration::from_secs(2),
        );
        assert!(good.verify("keyless", &policy, &chain).await.is_ok());

        let wrong = fixture.verifier(
            fixture.success_script(
                fixture.manifest.digest,
                Some(("https://other.example", "release@example.com")),
            ),
            Duration::from_secs(2),
        );
        assert_eq!(
            wrong.verify("keyless", &policy, &chain).await,
            Err(OciVerificationError::MalformedOutput)
        );
    }

    #[tokio::test]
    async fn wrong_repository_platform_digest_and_config_fail_before_cosign() {
        let fixture = Fixture::new();
        let marker = fixture.root.join("invoked");
        let executable = fixture.executable(&format!("touch {}", marker.display()));
        let verifier = fixture.verifier(executable, Duration::from_secs(2));
        let policy = fixture.policy();

        let mut wrong_repository = fixture.chain(SignedOciObject::Manifest);
        wrong_repository.repository = "registry.example/other/app".to_string();
        assert_eq!(
            verifier
                .verify("production", &policy, &wrong_repository)
                .await,
            Err(OciVerificationError::DigestChain)
        );

        let mut wrong_platform = fixture.chain(SignedOciObject::Manifest);
        wrong_platform.platform.architecture = "arm64".to_string();
        assert_eq!(
            verifier
                .verify("production", &policy, &wrong_platform)
                .await,
            Err(OciVerificationError::DigestChain)
        );

        let mut wrong_digest = fixture.chain(SignedOciObject::Manifest);
        wrong_digest.manifest.digest = OciDigest::from_bytes(b"other");
        assert_eq!(
            verifier.verify("production", &policy, &wrong_digest).await,
            Err(OciVerificationError::DigestChain)
        );

        let mut wrong_config = fixture.chain(SignedOciObject::Manifest);
        wrong_config.running_config = OciDigest::from_bytes(b"other config");
        assert_eq!(
            verifier.verify("production", &policy, &wrong_config).await,
            Err(OciVerificationError::DigestChain)
        );
        assert!(!marker.exists());
    }

    #[tokio::test]
    async fn unsigned_crash_hang_malformed_and_excessive_output_fail_closed() {
        let fixture = Fixture::new();
        let chain = fixture.chain(SignedOciObject::Manifest);
        let policy = fixture.policy();
        let cases = [
            ("exit 1", OciVerificationError::Rejected),
            ("kill -SEGV $$", OciVerificationError::Rejected),
            ("printf 'not-json'", OciVerificationError::MalformedOutput),
        ];
        for (script, expected) in cases {
            let verifier = fixture.verifier(fixture.executable(script), Duration::from_secs(2));
            assert_eq!(
                verifier.verify("production", &policy, &chain).await,
                Err(expected),
                "script: {script}"
            );
        }

        let verifier = fixture.verifier(
            fixture.executable("while :; do :; done"),
            Duration::from_millis(50),
        );
        assert_eq!(
            verifier.verify("production", &policy, &chain).await,
            Err(OciVerificationError::Timeout)
        );
    }

    #[tokio::test]
    async fn excessive_pipe_output_is_terminal_and_bounded() {
        use tokio::io::AsyncWriteExt as _;

        let (mut writer, reader) = tokio::io::duplex(4_096);
        let write = tokio::spawn(async move { writer.write_all(&vec![0_u8; 2_048]).await });
        assert_eq!(
            read_pipe(reader, 1_024).await,
            Err(OciVerificationError::OutputLimit)
        );
        let _ = write.await;
    }

    #[tokio::test]
    async fn child_diagnostics_are_never_returned() {
        let fixture = Fixture::new();
        let verifier = fixture.verifier(
            fixture.executable("printf 'registry-password-secret' >&2; exit 1"),
            Duration::from_secs(2),
        );
        let error = verifier
            .verify(
                "production",
                &fixture.policy(),
                &fixture.chain(SignedOciObject::Manifest),
            )
            .await
            .unwrap_err();
        assert!(!format!("{error:?} {error}").contains("registry-password-secret"));
    }

    #[tokio::test]
    async fn cancellation_kills_the_complete_cosign_process_group() {
        let fixture = Fixture::new();
        let marker = fixture.root.join("processes");
        let script = fixture.executable(&format!(
            "(while :; do :; done) &\nchild=$!\nprintf '%s %s' \"$$\" \"$child\" > {}\nwait",
            marker.display()
        ));
        let verifier = fixture.verifier(script, Duration::from_secs(5));
        let policy = fixture.policy();
        let chain = fixture.chain(SignedOciObject::Manifest);
        let verification =
            tokio::spawn(async move { verifier.verify("production", &policy, &chain).await });
        for _ in 0..100 {
            if marker.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let pids = fs::read_to_string(&marker)
            .unwrap()
            .split_ascii_whitespace()
            .map(str::parse::<i32>)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        verification.abort();
        let _ = verification.await;
        for _ in 0..100 {
            let all_gone = pids.iter().all(|raw| {
                Pid::from_raw(*raw)
                    .is_none_or(|pid| rustix::process::test_kill_process(pid).is_err())
            });
            if all_gone {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(pids.iter().all(|raw| {
            Pid::from_raw(*raw).is_none_or(|pid| rustix::process::test_kill_process(pid).is_err())
        }));
    }

    #[test]
    fn mutable_tags_and_unsafe_policy_shapes_are_rejected() {
        let fixture = Fixture::new();
        let mut policy = fixture.policy();
        policy.repository = "registry.example/team/app:latest".to_string();
        assert_eq!(
            validate_signer_policy("production", &policy),
            Err(SignerPolicyError::Repository)
        );
        assert_eq!(
            validate_signer_policy("bad\nname", &fixture.policy()),
            Err(SignerPolicyError::Name)
        );
    }
}
