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

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use rustix::process::{
    Pid, PidfdFlags, Signal, kill_process_group, pidfd_open, test_kill_process_group,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tokio::io::AsyncReadExt as _;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::process::{Child, Command};
use tokio::time::{Instant, timeout_at};
use tracing::warn;
use zeroize::Zeroizing;

use super::oci_evidence_cache::{
    CacheEntryId, CacheStoreOutcome, EvidenceContext, EvidenceRefreshState, OciEvidenceCache,
    OciEvidenceCacheError,
};
use super::registry_isolation::{RegistryAccess, RegistryIsolationError, RegistryProjection};

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
/// Maximum aggregate new-format Sigstore bundle bytes acquired for one subject.
pub const MAX_SIGSTORE_BUNDLE_BYTES: u64 = 4 * 1024 * 1024;
/// Maximum directory entries examined during one stale verifier-view sweep.
pub const MAX_COSIGN_TEMP_ENTRIES: usize = 1024;
/// Maximum distinct pinned public keys captured in one verification generation.
pub const MAX_PINNED_PUBLIC_KEYS: usize = 64;
/// Maximum bytes in one protected trust root or pinned public key.
pub const MAX_TRUST_FILE_BYTES: u64 = 1024 * 1024;
/// Maximum aggregate protected trust bytes in one verification generation.
pub const MAX_GENERATION_TRUST_BYTES: u64 = 16 * 1024 * 1024;
/// Maximum queued or running stale-evidence refreshes per verifier process.
pub const MAX_BACKGROUND_REFRESHES: usize = 16;

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
#[derive(Clone, Debug, Eq, PartialEq)]
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
    /// Exact remotely fetched config document.
    pub config: OciDocument,
    /// Object whose signature is being accepted.
    pub signed_object: SignedOciObject,
}

/// Runtime facts sufficient to select and validate wholly cached OCI evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OciRuntimeExpectation {
    /// Exact repository independently selected for this workload.
    pub repository: String,
    /// Runtime-resolved containing index digest, when resolution used an index.
    pub index_digest: Option<OciDigest>,
    /// Selected platform manifest digest.
    pub selected_manifest: OciDigest,
    /// Config digest reported for the running container.
    pub running_config: OciDigest,
    /// Selected runtime platform.
    pub platform: OciPlatform,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ValidatedChain {
    subject: OciDigest,
    manifest: OciDigest,
    config: OciDigest,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CachedOfflineBundle {
    version: u8,
    repository: String,
    signed_object: String,
    platform: CachedPlatform,
    index: Option<CachedDocument>,
    manifest: CachedDocument,
    config: CachedDocument,
    records: Vec<CachedOfflineRecord>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CachedPlatform {
    operating_system: String,
    architecture: String,
    variant: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CachedDocument {
    digest: String,
    bytes: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CachedOfflineRecord {
    signed_payload: String,
    sigstore_bundle: String,
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
    validate_document_hash(&chain.config)?;
    let config: serde_json::Value = parse_document(&chain.config.bytes)?;
    if !config.is_object() || chain.config.digest != chain.running_config {
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
        validate_protected_executable(&self.executable)?;
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
    /// Complete replayable Sigstore bundles acquired from the trusted online path.
    pub offline_bundle: Option<OciOfflineBundle>,
}

/// Complete public evidence needed to re-run local Sigstore verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OciOfflineBundle {
    /// Exact repository/source context used for remote collection.
    pub repository: String,
    /// Object whose signature is represented by `records`.
    pub signed_object: SignedOciObject,
    /// Platform selected from the index or runtime expectation.
    pub platform: OciPlatform,
    /// Exact remotely fetched containing index, when present.
    pub index: Option<OciDocument>,
    /// Exact remotely fetched selected manifest.
    pub manifest: OciDocument,
    /// Exact remotely fetched config document.
    pub config: OciDocument,
    /// Repository-bound signed payloads paired with upgraded Sigstore bundles.
    pub records: Vec<OciOfflineRecord>,
}

/// One exact signed payload and the protobuf bundle that verifies it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OciOfflineRecord {
    /// Exact decoded Cosign Simple Signing payload bytes.
    pub signed_payload: Vec<u8>,
    /// Sigstore protobuf bundle produced from the trusted legacy record.
    pub sigstore_bundle: Vec<u8>,
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
    /// Authentication for the exact private-registry authority failed.
    #[error("REGISTRY_AUTH_FAILED")]
    RegistryAuthFailed,
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
#[derive(Debug, Default)]
struct RefreshCoordinator {
    in_flight: Mutex<BTreeSet<CacheEntryId>>,
}

impl RefreshCoordinator {
    fn reserve(&self, id: &CacheEntryId) -> bool {
        let Ok(mut in_flight) = self.in_flight.lock() else {
            return false;
        };
        if in_flight.contains(id) || in_flight.len() >= MAX_BACKGROUND_REFRESHES {
            return false;
        }
        in_flight.insert(id.clone())
    }

    fn release(&self, id: &CacheEntryId) {
        if let Ok(mut in_flight) = self.in_flight.lock() {
            in_flight.remove(id);
        }
    }
}

struct RefreshLease {
    coordinator: Arc<RefreshCoordinator>,
    cache: Arc<OciEvidenceCache>,
    subject: OciDigest,
    id: CacheEntryId,
    attempted_at: u64,
    finished: bool,
}

impl RefreshLease {
    fn finish(mut self, success: bool) {
        let _ = self
            .cache
            .record_refresh(self.subject, &self.id, self.attempted_at, success);
        self.coordinator.release(&self.id);
        self.finished = true;
    }
}

impl Drop for RefreshLease {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self
                .cache
                .record_refresh(self.subject, &self.id, self.attempted_at, false);
            self.coordinator.release(&self.id);
        }
    }
}

#[derive(Clone, Debug)]
pub struct CosignVerifier {
    config: CosignConfig,
    registry_access: RegistryAccess,
    trusted_root: Option<Arc<[u8]>>,
    pinned_keys: BTreeMap<PathBuf, Arc<[u8]>>,
    restart_shape: Option<[u8; 32]>,
    refresh_coordinator: Arc<RefreshCoordinator>,
    #[cfg(test)]
    skip_registry_preflight: bool,
}

impl CosignVerifier {
    /// Construct an explicitly public-registry-only verifier.
    pub fn for_public_registries(config: CosignConfig) -> Result<Self, OciVerificationError> {
        config.validate()?;
        PrivateTempDir::sweep_stale(&config.temp_parent)?;
        Ok(Self {
            config,
            registry_access: RegistryAccess::default(),
            trusted_root: None,
            pinned_keys: BTreeMap::new(),
            restart_shape: None,
            refresh_coordinator: Arc::new(RefreshCoordinator::default()),
            #[cfg(test)]
            skip_registry_preflight: false,
        })
    }

    /// Construct with the required startup registry-access snapshot.
    pub fn new(
        config: CosignConfig,
        registry_access: RegistryAccess,
    ) -> Result<Self, OciVerificationError> {
        config.validate()?;
        PrivateTempDir::sweep_stale(&config.temp_parent)?;
        Ok(Self {
            config,
            registry_access,
            trusted_root: None,
            pinned_keys: BTreeMap::new(),
            restart_shape: None,
            refresh_coordinator: Arc::new(RefreshCoordinator::default()),
            #[cfg(test)]
            skip_registry_preflight: false,
        })
    }

    /// Require one protected local Sigstore trusted-root snapshot for keyless use.
    pub fn with_trusted_root(mut self, path: &Path) -> Result<Self, OciVerificationError> {
        self.trusted_root = Some(read_protected_trust_snapshot(path)?.into());
        self.validate_trust_byte_budget()?;
        Ok(self)
    }

    /// Capture every pinned public key referenced by this generation's policy.
    ///
    /// Later verification materializes only these immutable bytes into its
    /// private subprocess view; it never re-reads a mutable policy path.
    pub fn with_signer_policies(
        mut self,
        policies: &BTreeMap<String, OciSignerPolicy>,
    ) -> Result<Self, OciVerificationError> {
        let paths = policies
            .values()
            .filter_map(|policy| match &policy.signer {
                OciSignerMode::PinnedKey { public_key, .. } => Some(public_key),
                OciSignerMode::Keyless { .. } => None,
            })
            .collect::<BTreeSet<_>>();
        if paths.len() > MAX_PINNED_PUBLIC_KEYS {
            return Err(OciVerificationError::Configuration);
        }
        let mut pinned_keys = BTreeMap::new();
        for path in paths {
            pinned_keys.insert(path.clone(), read_protected_trust_snapshot(path)?.into());
        }
        self.pinned_keys = pinned_keys;
        self.validate_trust_byte_budget()?;
        Ok(self)
    }

    /// Clone immutable execution/registry state while replacing all trust bytes.
    pub fn refreshed_trust(
        &self,
        trusted_root: Option<&Path>,
        policies: &BTreeMap<String, OciSignerPolicy>,
    ) -> Result<Self, OciVerificationError> {
        let mut candidate = self.clone();
        candidate.trusted_root = trusted_root
            .map(read_protected_trust_snapshot)
            .transpose()?
            .map(Arc::from);
        candidate.pinned_keys.clear();
        candidate.with_signer_policies(policies)
    }

    /// Bind an opaque digest of restart-only operator configuration.
    #[must_use]
    pub const fn with_restart_shape(mut self, shape: [u8; 32]) -> Self {
        self.restart_shape = Some(shape);
        self
    }

    /// Return the restart-only configuration digest captured at startup.
    #[must_use]
    pub const fn restart_shape(&self) -> Option<[u8; 32]> {
        self.restart_shape
    }

    fn validate_trust_byte_budget(&self) -> Result<(), OciVerificationError> {
        let root_bytes = self.trusted_root.as_ref().map_or(0_u64, |bytes| {
            u64::try_from(bytes.len()).unwrap_or(u64::MAX)
        });
        let total = self
            .pinned_keys
            .values()
            .try_fold(root_bytes, |total, bytes| {
                total.checked_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
            });
        if total.is_some_and(|bytes| bytes <= MAX_GENERATION_TRUST_BYTES) {
            Ok(())
        } else {
            Err(OciVerificationError::Configuration)
        }
    }

    #[cfg(test)]
    pub(crate) fn trusted_root_snapshot(&self) -> Option<&[u8]> {
        self.trusted_root.as_deref()
    }

    #[cfg(test)]
    pub(crate) fn pinned_key_snapshot(&self, path: &Path) -> Option<&[u8]> {
        self.pinned_keys.get(path).map(AsRef::as_ref)
    }

    fn materialize_pinned_key(
        &self,
        policy: &OciSignerPolicy,
        temp: &Path,
    ) -> Result<Option<PathBuf>, OciVerificationError> {
        let OciSignerMode::PinnedKey { public_key, .. } = &policy.signer else {
            return Ok(None);
        };
        let bytes = self
            .pinned_keys
            .get(public_key)
            .ok_or(OciVerificationError::Configuration)?;
        let path = temp.join("pinned-public-key.pem");
        write_private_public_file(&path, bytes)?;
        Ok(Some(path))
    }

    fn materialize_trusted_root(
        &self,
        temp: &Path,
    ) -> Result<Option<PathBuf>, OciVerificationError> {
        let Some(bytes) = &self.trusted_root else {
            return Ok(None);
        };
        let path = temp.join("trusted-root.json");
        write_private_public_file(&path, bytes)?;
        Ok(Some(path))
    }

    /// Verify one named policy and exact running OCI digest chain.
    #[allow(clippy::too_many_lines)]
    pub async fn verify(
        &self,
        policy_name: &str,
        policy: &OciSignerPolicy,
        chain: &OciImageChain,
    ) -> Result<OciVerificationEvidence, OciVerificationError> {
        validate_signer_policy(policy_name, policy).map_err(|_| OciVerificationError::Policy)?;
        let validated = validate_chain(policy, chain)?;
        let deadline = Instant::now() + self.config.deadline;
        let temp = PrivateTempDir::create(&self.config.temp_parent)?;
        let temp_path = temp.path()?.to_path_buf();
        let pinned_key = self.materialize_pinned_key(policy, &temp_path)?;
        let trusted_root = self.materialize_trusted_root(&temp_path)?;
        let result = async {
            let registry = self
                .registry_access
                .project(&chain.repository, &temp_path)
                .map_err(map_registry_isolation_error)?;
            let reference = format!("{}@{}", chain.repository, validated.subject);
            self.preflight_registry(&chain.repository, validated.subject, deadline)
                .await?;
            let mut command = Command::new(&self.config.executable);
            command
                .arg("verify")
                .arg("--output=json")
                .env_clear()
                .env("TMPDIR", &temp_path)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true)
                .process_group(0);
            if let Some(docker_config) = &registry.docker_config {
                command.env("DOCKER_CONFIG", docker_config);
            }
            if let Some(ca_bundle) = &registry.ca_bundle {
                command.arg("--registry-ca-cert").arg(ca_bundle);
            }
            match &policy.signer {
                OciSignerMode::PinnedKey { transparency, .. } => {
                    command.arg("--key").arg(
                        pinned_key
                            .as_ref()
                            .ok_or(OciVerificationError::Configuration)?,
                    );
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
                    if let Some(trusted_root) = &trusted_root {
                        command.arg("--trusted-root").arg(trusted_root);
                    }
                }
            }
            command.arg("--").arg(&reference);
            let child = command
                .spawn()
                .map_err(|_| OciVerificationError::Unavailable)?;
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|duration| !duration.is_zero())
                .ok_or(OciVerificationError::Timeout)?;
            let output = wait_bounded(child, remaining, MAX_COSIGN_STDOUT_BYTES).await?;
            if !output.status.success() {
                return Err(OciVerificationError::Rejected);
            }
            validate_cosign_output(&output.stdout, policy, &reference, validated.subject)?;
            let offline_bundle = match self
                .download_offline_records(
                    &reference,
                    &chain.repository,
                    validated.subject,
                    policy,
                    pinned_key.as_deref(),
                    &registry,
                    &temp_path,
                    offline_document_bytes(chain)?,
                    deadline,
                )
                .await
            {
                Ok(records) if !records.is_empty() => Some(OciOfflineBundle {
                    repository: chain.repository.clone(),
                    signed_object: chain.signed_object,
                    platform: chain.platform.clone(),
                    index: chain.index.clone(),
                    manifest: chain.manifest.clone(),
                    config: chain.config.clone(),
                    records,
                }),
                Ok(_) | Err(_) => None,
            };
            Ok(OciVerificationEvidence {
                policy: policy_name.to_string(),
                repository: chain.repository.clone(),
                signed_object: chain.signed_object,
                signed_digest: validated.subject,
                manifest_digest: validated.manifest,
                config_digest: validated.config,
                platform: chain.platform.clone(),
                offline_bundle,
            })
        }
        .await;
        temp.cleanup()?;
        result
    }

    /// Re-run cryptographic verification using only cached public bundles and
    /// the current protected key or trusted-root snapshot.
    pub async fn verify_offline(
        &self,
        policy_name: &str,
        policy: &OciSignerPolicy,
        chain: &OciImageChain,
        evidence: &OciOfflineBundle,
        denied_subjects: &BTreeSet<OciDigest>,
    ) -> Result<OciVerificationEvidence, OciVerificationError> {
        validate_signer_policy(policy_name, policy).map_err(|_| OciVerificationError::Policy)?;
        let validated = validate_chain(policy, chain)?;
        if denied_subjects.contains(&validated.subject) {
            return Err(OciVerificationError::Rejected);
        }
        validate_offline_bundle_bounds(evidence)?;
        let evidence_chain = chain_from_evidence(evidence);
        let evidence_validated = validate_chain(policy, &evidence_chain)?;
        if evidence_validated != validated
            || evidence.repository != chain.repository
            || evidence.platform != chain.platform
            || evidence.signed_object != chain.signed_object
            || evidence.index != chain.index
            || evidence.manifest != chain.manifest
            || evidence.config != chain.config
        {
            return Err(OciVerificationError::MalformedOutput);
        }
        let deadline = Instant::now() + self.config.deadline;
        for record in &evidence.records {
            validate_simple_signing_payload(
                &record.signed_payload,
                &chain.repository,
                validated.subject,
            )?;
            if self
                .verify_blob_evidence(
                    policy,
                    &record.signed_payload,
                    &record.sigstore_bundle,
                    deadline,
                )
                .await?
            {
                return Ok(OciVerificationEvidence {
                    policy: policy_name.to_owned(),
                    repository: chain.repository.clone(),
                    signed_object: chain.signed_object,
                    signed_digest: validated.subject,
                    manifest_digest: validated.manifest,
                    config_digest: validated.config,
                    platform: chain.platform.clone(),
                    offline_bundle: Some(evidence.clone()),
                });
            }
        }
        Err(OciVerificationError::Rejected)
    }

    async fn verify_blob_evidence(
        &self,
        policy: &OciSignerPolicy,
        signed_payload: &[u8],
        sigstore_bundle: &[u8],
        deadline: Instant,
    ) -> Result<bool, OciVerificationError> {
        if u64::try_from(signed_payload.len()).map_or(true, |size| size > MAX_SIGSTORE_BUNDLE_BYTES)
            || u64::try_from(sigstore_bundle.len())
                .map_or(true, |size| size > MAX_SIGSTORE_BUNDLE_BYTES)
            || (matches!(policy.signer, OciSignerMode::Keyless { .. })
                && self.trusted_root.is_none())
        {
            return Err(OciVerificationError::Configuration);
        }
        let temp = PrivateTempDir::create(&self.config.temp_parent)?;
        let temp_path = temp.path()?.to_path_buf();
        let pinned_key = self.materialize_pinned_key(policy, &temp_path)?;
        let trusted_root = self.materialize_trusted_root(&temp_path)?;
        let result = async {
            let signed_path = temp.path()?.join("signed-payload");
            write_private_public_file(&signed_path, signed_payload)?;
            let bundle_path = temp.path()?.join("bundle.json");
            write_private_public_file(&bundle_path, sigstore_bundle)?;
            let mut command = Command::new(&self.config.executable);
            command
                .arg("verify-blob")
                .arg("--bundle")
                .arg(&bundle_path)
                .env_clear()
                .env("TMPDIR", temp.path()?)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true)
                .process_group(0);
            match &policy.signer {
                OciSignerMode::PinnedKey { transparency, .. } => {
                    command.arg("--key").arg(
                        pinned_key
                            .as_ref()
                            .ok_or(OciVerificationError::Configuration)?,
                    );
                    if *transparency == TransparencyPolicy::Optional {
                        command.arg("--insecure-ignore-tlog");
                    }
                }
                OciSignerMode::Keyless { issuer, identity } => {
                    let trusted_root = trusted_root
                        .as_ref()
                        .ok_or(OciVerificationError::Configuration)?;
                    command
                        .arg("--trusted-root")
                        .arg(trusted_root)
                        .arg("--certificate-oidc-issuer")
                        .arg(issuer)
                        .arg("--certificate-identity")
                        .arg(identity);
                }
            }
            command.arg("--").arg(&signed_path);
            let child = command
                .spawn()
                .map_err(|_| OciVerificationError::Unavailable)?;
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|duration| !duration.is_zero())
                .ok_or(OciVerificationError::Timeout)?;
            wait_bounded(child, remaining, MAX_COSIGN_STDOUT_BYTES)
                .await
                .map(|output| output.status.success())
        }
        .await;
        temp.cleanup()?;
        result
    }

    /// Validate wholly cached evidence from runtime digests without registry documents.
    pub async fn verify_cached_expectation(
        &self,
        cache: &OciEvidenceCache,
        policy_name: &str,
        policy: &OciSignerPolicy,
        expectation: &OciRuntimeExpectation,
        denied_subjects: &BTreeSet<OciDigest>,
        now: u64,
    ) -> Result<OciVerificationEvidence, OciVerificationError> {
        validate_signer_policy(policy_name, policy).map_err(|_| OciVerificationError::Policy)?;
        if expectation.repository != policy.repository {
            return Err(OciVerificationError::DigestChain);
        }
        expectation
            .platform
            .validate()
            .map_err(|_| OciVerificationError::DigestChain)?;
        let mut subjects = Vec::with_capacity(2);
        if let Some(index) = expectation.index_digest {
            subjects.push(index);
        }
        if !subjects.contains(&expectation.selected_manifest) {
            subjects.push(expectation.selected_manifest);
        }
        let mut inactive = false;
        for subject in subjects {
            let candidates = cache
                .untrusted_candidates(subject, &expectation.repository, now)
                .map_err(map_cache_error)?;
            for candidate in candidates {
                let Ok(bundle) = decode_offline_bundle(&candidate.evidence) else {
                    let _ = cache.remove_exact(subject, &candidate.id);
                    continue;
                };
                if !evidence_matches_expectation(&bundle, expectation) {
                    continue;
                }
                let chain = chain_from_evidence(&bundle);
                match self
                    .verify_offline(policy_name, policy, &chain, &bundle, denied_subjects)
                    .await
                {
                    Ok(evidence) => {
                        cache
                            .touch_exact(subject, &candidate.id, now)
                            .map_err(map_cache_error)?;
                        return Ok(evidence);
                    }
                    Err(
                        OciVerificationError::MalformedOutput
                        | OciVerificationError::DigestChain
                        | OciVerificationError::OutputLimit,
                    ) => {
                        let _ = cache.remove_exact(subject, &candidate.id);
                    }
                    Err(
                        OciVerificationError::Rejected
                        | OciVerificationError::Policy
                        | OciVerificationError::Configuration,
                    ) => inactive = true,
                    Err(error) => return Err(error),
                }
            }
        }
        if inactive {
            Err(OciVerificationError::Rejected)
        } else {
            Err(OciVerificationError::Unavailable)
        }
    }

    /// Prefer locally revalidated persistent evidence, acquiring and storing a
    /// new bundle only when no current-policy cache hit is admitted.
    #[allow(clippy::too_many_arguments)]
    pub async fn verify_with_cache(
        self: &Arc<Self>,
        cache: &Arc<OciEvidenceCache>,
        policy_name: &str,
        policy: &OciSignerPolicy,
        chain: &OciImageChain,
        observed_reference: &str,
        denied_subjects: &BTreeSet<OciDigest>,
        now: u64,
    ) -> Result<OciVerificationEvidence, OciVerificationError> {
        validate_signer_policy(policy_name, policy).map_err(|_| OciVerificationError::Policy)?;
        let validated = validate_chain(policy, chain)?;
        if denied_subjects.contains(&validated.subject) {
            return Err(OciVerificationError::Rejected);
        }
        let candidates = cache
            .untrusted_candidates(validated.subject, &chain.repository, now)
            .map_err(map_cache_error)?;
        for candidate in candidates {
            let Ok(bundle) = decode_offline_bundle(&candidate.evidence) else {
                let _ = cache.remove_exact(validated.subject, &candidate.id);
                continue;
            };
            match self
                .verify_offline(policy_name, policy, chain, &bundle, denied_subjects)
                .await
            {
                Ok(evidence) => {
                    cache
                        .touch_exact(validated.subject, &candidate.id, now)
                        .map_err(map_cache_error)?;
                    if matches!(candidate.refresh, EvidenceRefreshState::Due { .. }) {
                        self.schedule_background_refresh(
                            Arc::clone(cache),
                            candidate.id,
                            validated.subject,
                            policy_name.to_owned(),
                            policy.clone(),
                            chain.clone(),
                            observed_reference.to_owned(),
                            now,
                        );
                    }
                    return Ok(evidence);
                }
                Err(
                    OciVerificationError::MalformedOutput
                    | OciVerificationError::DigestChain
                    | OciVerificationError::OutputLimit,
                ) => {
                    let _ = cache.remove_exact(validated.subject, &candidate.id);
                }
                Err(
                    OciVerificationError::Rejected
                    | OciVerificationError::Policy
                    | OciVerificationError::Configuration,
                ) => {}
                Err(error) => return Err(error),
            }
        }

        let evidence = self.verify(policy_name, policy, chain).await?;
        if let Some(bundle) = &evidence.offline_bundle {
            let encoded = encode_offline_bundle(bundle)?;
            let context = EvidenceContext {
                subject: validated.subject,
                source_context: chain.repository.clone(),
                references: BTreeSet::from([observed_reference.to_owned()]),
            };
            match cache.store(&context, &encoded, now) {
                Ok(CacheStoreOutcome::Stored(_)) => {}
                Ok(CacheStoreOutcome::AtCapacity) => {
                    warn!("OCI evidence cache is at capacity; fresh evidence was not persisted");
                }
                Err(error) => {
                    warn!(error = %error, "failed to persist freshly verified OCI evidence");
                }
            }
        }
        Ok(evidence)
    }

    #[allow(clippy::too_many_arguments)]
    fn schedule_background_refresh(
        self: &Arc<Self>,
        cache: Arc<OciEvidenceCache>,
        id: CacheEntryId,
        subject: OciDigest,
        policy_name: String,
        policy: OciSignerPolicy,
        chain: OciImageChain,
        observed_reference: String,
        now: u64,
    ) {
        if !self.refresh_coordinator.reserve(&id) {
            return;
        }
        let lease = RefreshLease {
            coordinator: Arc::clone(&self.refresh_coordinator),
            cache: Arc::clone(&cache),
            subject,
            id,
            attempted_at: now,
            finished: false,
        };
        let verifier = Arc::clone(self);
        tokio::spawn(async move {
            let success = match verifier.verify(&policy_name, &policy, &chain).await {
                Ok(evidence) => {
                    if let Some(bundle) = &evidence.offline_bundle {
                        match encode_offline_bundle(bundle) {
                            Ok(encoded) => {
                                let context = EvidenceContext {
                                    subject,
                                    source_context: chain.repository.clone(),
                                    references: BTreeSet::from([observed_reference]),
                                };
                                match cache.store(&context, &encoded, now) {
                                    Ok(CacheStoreOutcome::Stored(_)) => {}
                                    Ok(CacheStoreOutcome::AtCapacity) => warn!(
                                        "OCI evidence cache is at capacity; refreshed evidence was not persisted"
                                    ),
                                    Err(error) => warn!(
                                        error = %error,
                                        "failed to persist refreshed OCI evidence"
                                    ),
                                }
                            }
                            Err(error) => warn!(
                                error = %error,
                                "failed to encode refreshed OCI evidence"
                            ),
                        }
                    }
                    true
                }
                Err(error) => {
                    warn!(error = %error, "background OCI evidence refresh failed");
                    false
                }
            };
            lease.finish(success);
        });
    }

    #[allow(clippy::too_many_arguments)]
    async fn download_offline_records(
        &self,
        reference: &str,
        repository: &str,
        digest: OciDigest,
        policy: &OciSignerPolicy,
        pinned_key: Option<&Path>,
        registry: &RegistryProjection,
        temp: &Path,
        document_bytes: usize,
        deadline: Instant,
    ) -> Result<Vec<OciOfflineRecord>, OciVerificationError> {
        let mut command = Command::new(&self.config.executable);
        command
            .arg("download")
            .arg("signature")
            .env_clear()
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .process_group(0);
        if let Some(docker_config) = &registry.docker_config {
            command.env("DOCKER_CONFIG", docker_config);
        }
        if let Some(ca_bundle) = &registry.ca_bundle {
            command.arg("--registry-ca-cert").arg(ca_bundle);
        }
        command.arg("--").arg(reference);
        let child = command
            .spawn()
            .map_err(|_| OciVerificationError::Unavailable)?;
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or(OciVerificationError::Timeout)?;
        let output = wait_bounded(child, remaining, MAX_SIGSTORE_BUNDLE_BYTES).await?;
        if !output.status.success() {
            return Err(OciVerificationError::Unavailable);
        }
        let legacy = parse_legacy_records(&output.stdout, repository, digest, policy)?;
        let mut records = Vec::with_capacity(legacy.len());
        for (index, input) in legacy.into_iter().enumerate() {
            let payload_path = temp.join(format!("downloaded-payload-{index}"));
            let old_bundle_path = temp.join(format!("legacy-bundle-{index}.json"));
            let upgraded_path = temp.join(format!("upgraded-bundle-{index}.json"));
            write_private_public_file(&payload_path, &input.signed_payload)?;
            write_private_public_file(&old_bundle_path, &input.local_bundle)?;
            let mut command = Command::new(&self.config.executable);
            command
                .arg("bundle")
                .arg("create")
                .arg("--artifact")
                .arg(&payload_path)
                .arg("--bundle")
                .arg(&old_bundle_path)
                .arg("--out")
                .arg(&upgraded_path)
                .env_clear()
                .env("TMPDIR", temp)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true)
                .process_group(0);
            if input.ignore_tlog {
                command.arg("--ignore-tlog");
            }
            if matches!(policy.signer, OciSignerMode::PinnedKey { .. }) {
                command
                    .arg("--key")
                    .arg(pinned_key.ok_or(OciVerificationError::Configuration)?);
            }
            if let Some(timestamp) = input.rfc3161_timestamp {
                let timestamp_path = temp.join(format!("rfc3161-{index}.json"));
                write_private_public_file(&timestamp_path, &timestamp)?;
                command.arg("--rfc3161-timestamp").arg(timestamp_path);
            }
            let child = command
                .spawn()
                .map_err(|_| OciVerificationError::Unavailable)?;
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|duration| !duration.is_zero())
                .ok_or(OciVerificationError::Timeout)?;
            let output = wait_bounded(child, remaining, MAX_COSIGN_STDOUT_BYTES).await?;
            if !output.status.success() {
                return Err(OciVerificationError::Rejected);
            }
            let sigstore_bundle = read_private_public_file(&upgraded_path)?;
            validate_upgraded_bundle(&sigstore_bundle)?;
            records.push(OciOfflineRecord {
                signed_payload: input.signed_payload,
                sigstore_bundle,
            });
            validate_acquired_records(&records, document_bytes)?;
        }
        Ok(records)
    }

    async fn preflight_registry(
        &self,
        repository: &str,
        digest: OciDigest,
        deadline: Instant,
    ) -> Result<(), OciVerificationError> {
        #[cfg(test)]
        if self.skip_registry_preflight {
            return Ok(());
        }
        self.registry_access
            .preflight(repository, &digest.to_string(), deadline)
            .await
            .map_err(map_registry_isolation_error)
    }
}

fn chain_from_evidence(evidence: &OciOfflineBundle) -> OciImageChain {
    OciImageChain {
        repository: evidence.repository.clone(),
        platform: evidence.platform.clone(),
        index: evidence.index.clone(),
        manifest: evidence.manifest.clone(),
        running_config: evidence.config.digest,
        config: evidence.config.clone(),
        signed_object: evidence.signed_object,
    }
}

fn evidence_matches_expectation(
    evidence: &OciOfflineBundle,
    expectation: &OciRuntimeExpectation,
) -> bool {
    evidence.repository == expectation.repository
        && evidence.platform == expectation.platform
        && evidence.index.as_ref().map(|document| document.digest) == expectation.index_digest
        && evidence.manifest.digest == expectation.selected_manifest
        && evidence.config.digest == expectation.running_config
}

const fn map_registry_isolation_error(error: RegistryIsolationError) -> OciVerificationError {
    match error {
        RegistryIsolationError::Configuration => OciVerificationError::Configuration,
        RegistryIsolationError::Authentication => OciVerificationError::RegistryAuthFailed,
        RegistryIsolationError::Unavailable => OciVerificationError::Unavailable,
    }
}

fn validate_protected_file(path: &Path) -> Result<(), OciVerificationError> {
    validate_absolute_path(path).map_err(|_| OciVerificationError::Configuration)?;
    validate_protected_ancestors(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| OciVerificationError::Configuration)?;
    let effective_uid = rustix::process::geteuid().as_raw();
    if !metadata.file_type().is_file()
        || (metadata.uid() != 0 && metadata.uid() != effective_uid)
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.nlink() != 1
    {
        return Err(OciVerificationError::Configuration);
    }
    Ok(())
}

fn validate_protected_executable(path: &Path) -> Result<(), OciVerificationError> {
    validate_absolute_path(path).map_err(|_| OciVerificationError::Configuration)?;
    validate_protected_ancestors(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| OciVerificationError::Configuration)?;
    let effective_uid = rustix::process::geteuid().as_raw();
    let immutable_nix_store_hardlink = metadata.nlink() > 0
        && metadata.uid() == 0
        && path
            .strip_prefix("/nix/store")
            .ok()
            .and_then(|relative| relative.components().next())
            .is_some_and(|component| matches!(component, std::path::Component::Normal(_)));
    if !metadata.file_type().is_file()
        || (metadata.uid() != 0 && metadata.uid() != effective_uid)
        || metadata.permissions().mode() & 0o022 != 0
        || (metadata.nlink() != 1 && !immutable_nix_store_hardlink)
    {
        return Err(OciVerificationError::Configuration);
    }
    Ok(())
}

fn read_protected_trust_snapshot(path: &Path) -> Result<Vec<u8>, OciVerificationError> {
    validate_protected_file(path)?;
    let raw = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| OciVerificationError::Configuration)?;
    let mut file = File::from(raw);
    let before = file
        .metadata()
        .map_err(|_| OciVerificationError::Configuration)?;
    let effective_uid = rustix::process::geteuid().as_raw();
    if !before.is_file()
        || (before.uid() != 0 && before.uid() != effective_uid)
        || before.permissions().mode() & 0o022 != 0
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > MAX_TRUST_FILE_BYTES
    {
        return Err(OciVerificationError::Configuration);
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(MAX_TRUST_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| OciVerificationError::Configuration)?;
    let after = file
        .metadata()
        .map_err(|_| OciVerificationError::Configuration)?;
    if bytes.is_empty()
        || u64::try_from(bytes.len()).map_or(true, |size| size > MAX_TRUST_FILE_BYTES)
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
    {
        return Err(OciVerificationError::Configuration);
    }
    Ok(bytes)
}

fn validate_protected_ancestors(path: &Path) -> Result<(), OciVerificationError> {
    let parent = path.parent().ok_or(OciVerificationError::Configuration)?;
    let relative = parent
        .strip_prefix(Path::new("/"))
        .map_err(|_| OciVerificationError::Configuration)?;
    let mut directory = File::from(
        rustix::fs::open(
            "/",
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| OciVerificationError::Configuration)?,
    );
    let effective_uid = rustix::process::geteuid().as_raw();
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(OciVerificationError::Configuration);
        };
        let next = File::from(
            rustix::fs::openat(
                &directory,
                name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NOFOLLOW,
                rustix::fs::Mode::empty(),
            )
            .map_err(|_| OciVerificationError::Configuration)?,
        );
        let metadata = next
            .metadata()
            .map_err(|_| OciVerificationError::Configuration)?;
        let mode = metadata.permissions().mode();
        let owner_allowed = metadata.uid() == 0 || metadata.uid() == effective_uid;
        let root_sticky_boundary = metadata.uid() == 0 && mode & 0o1000 != 0;
        if !metadata.is_dir()
            || !owner_allowed
            || (mode & 0o022 != 0 && !root_sticky_boundary)
            || metadata.nlink() == 0
        {
            return Err(OciVerificationError::Configuration);
        }
        directory = next;
    }
    Ok(())
}

fn write_private_public_file(path: &Path, bytes: &[u8]) -> Result<(), OciVerificationError> {
    if u64::try_from(bytes.len()).map_or(true, |size| size > MAX_SIGSTORE_BUNDLE_BYTES) {
        return Err(OciVerificationError::OutputLimit);
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| OciVerificationError::Unavailable)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| OciVerificationError::Unavailable)?;
    file.write_all(bytes)
        .map_err(|_| OciVerificationError::Unavailable)?;
    file.sync_all()
        .map_err(|_| OciVerificationError::Unavailable)
}

fn validate_simple_signing_payload(
    payload: &[u8],
    repository: &str,
    digest: OciDigest,
) -> Result<(), OciVerificationError> {
    let value: serde_json::Value =
        serde_json::from_slice(payload).map_err(|_| OciVerificationError::MalformedOutput)?;
    let critical = value
        .get("critical")
        .ok_or(OciVerificationError::MalformedOutput)?;
    let signed_repository = critical
        .get("identity")
        .and_then(|identity| identity.get("docker-reference"))
        .and_then(serde_json::Value::as_str)
        .ok_or(OciVerificationError::MalformedOutput)?;
    let signed_digest = critical
        .get("image")
        .and_then(|image| image.get("docker-manifest-digest"))
        .and_then(serde_json::Value::as_str)
        .ok_or(OciVerificationError::MalformedOutput)?;
    let signature_type = critical
        .get("type")
        .and_then(serde_json::Value::as_str)
        .ok_or(OciVerificationError::MalformedOutput)?;
    if signed_repository == repository
        && signed_digest == digest.to_string()
        && signature_type == "cosign container image signature"
    {
        Ok(())
    } else {
        Err(OciVerificationError::MalformedOutput)
    }
}

fn validate_upgraded_bundle(bundle: &[u8]) -> Result<(), OciVerificationError> {
    let value: serde_json::Value =
        serde_json::from_slice(bundle).map_err(|_| OciVerificationError::MalformedOutput)?;
    let media_type = value
        .get("mediaType")
        .and_then(serde_json::Value::as_str)
        .ok_or(OciVerificationError::MalformedOutput)?;
    if !media_type.starts_with("application/vnd.dev.sigstore.bundle")
        || value.get("verificationMaterial").is_none()
        || value.get("messageSignature").is_none()
    {
        return Err(OciVerificationError::MalformedOutput);
    }
    Ok(())
}

fn read_private_public_file(path: &Path) -> Result<Vec<u8>, OciVerificationError> {
    let raw = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| OciVerificationError::Unavailable)?;
    let mut file = File::from(raw);
    let metadata = file
        .metadata()
        .map_err(|_| OciVerificationError::Unavailable)?;
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > MAX_SIGSTORE_BUNDLE_BYTES
    {
        return Err(OciVerificationError::MalformedOutput);
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(MAX_SIGSTORE_BUNDLE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| OciVerificationError::Unavailable)?;
    if u64::try_from(bytes.len()).map_or(true, |size| size > MAX_SIGSTORE_BUNDLE_BYTES) {
        return Err(OciVerificationError::OutputLimit);
    }
    Ok(bytes)
}

struct PrivateTempDir(Option<PathBuf>);

impl PrivateTempDir {
    fn create(parent: &Path) -> Result<Self, OciVerificationError> {
        let metadata = validate_private_temp_parent(parent)?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o022 != 0 {
            return Err(OciVerificationError::Configuration);
        }
        for _ in 0..8 {
            let path = parent.join(format!(
                "basil-cosign-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                        .map_err(|_| OciVerificationError::Unavailable)?;
                    return Ok(Self(Some(path)));
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(OciVerificationError::Unavailable),
            }
        }
        Err(OciVerificationError::Unavailable)
    }

    fn path(&self) -> Result<&Path, OciVerificationError> {
        self.0.as_deref().ok_or(OciVerificationError::Unavailable)
    }

    fn cleanup(mut self) -> Result<(), OciVerificationError> {
        let Some(path) = self.0.take() else {
            return Ok(());
        };
        if fs::remove_dir_all(&path).is_err() {
            self.0 = Some(path);
            return Err(OciVerificationError::Unavailable);
        }
        Ok(())
    }

    fn sweep_stale(parent: &Path) -> Result<(), OciVerificationError> {
        validate_private_temp_parent(parent)?;
        let entries = fs::read_dir(parent).map_err(|_| OciVerificationError::Configuration)?;
        for (index, entry) in entries.enumerate() {
            if index >= MAX_COSIGN_TEMP_ENTRIES {
                return Err(OciVerificationError::Configuration);
            }
            let entry = entry.map_err(|_| OciVerificationError::Unavailable)?;
            let Some(pid) = stale_view_pid(&entry.file_name()) else {
                continue;
            };
            if rustix::process::test_kill_process(pid) != Err(rustix::io::Errno::SRCH) {
                continue;
            }
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|_| OciVerificationError::Unavailable)?;
            if !metadata.file_type().is_dir()
                || metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.permissions().mode() & 0o777 != 0o700
            {
                continue;
            }
            fs::remove_dir_all(entry.path()).map_err(|_| OciVerificationError::Unavailable)?;
        }
        Ok(())
    }
}

fn stale_view_pid(name: &std::ffi::OsStr) -> Option<Pid> {
    let name = name.to_str()?.strip_prefix("basil-cosign-")?;
    let (pid, identifier) = name.split_once('-')?;
    uuid::Uuid::parse_str(identifier).ok()?;
    pid.parse::<i32>().ok().and_then(Pid::from_raw)
}

fn validate_private_temp_parent(parent: &Path) -> Result<fs::Metadata, OciVerificationError> {
    validate_absolute_path(parent).map_err(|_| OciVerificationError::Configuration)?;
    let relative = parent
        .strip_prefix(Path::new("/"))
        .map_err(|_| OciVerificationError::Configuration)?;
    let mut directory = rustix::fs::open(
        "/",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| OciVerificationError::Configuration)?;
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(OciVerificationError::Configuration);
        };
        directory = rustix::fs::openat(
            &directory,
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| OciVerificationError::Configuration)?;
    }
    let metadata = File::from(directory)
        .metadata()
        .map_err(|_| OciVerificationError::Configuration)?;
    if metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(OciVerificationError::Configuration);
    }
    Ok(metadata)
}

impl Drop for PrivateTempDir {
    fn drop(&mut self) {
        if let Some(path) = self.0.take()
            && fs::remove_dir_all(path).is_err()
        {
            warn!("failed to remove private OCI verifier view");
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProcessLifecycleEvent {
    ExitObservedWithoutReap,
    GroupKillCompleted,
    LeaderReaped,
    GroupGone,
}

#[derive(Default)]
struct ProcessLifecycleObserver {
    #[cfg(test)]
    events: Option<Arc<Mutex<Vec<ProcessLifecycleEvent>>>>,
}

impl ProcessLifecycleObserver {
    #[cfg(test)]
    const fn recording(events: Arc<Mutex<Vec<ProcessLifecycleEvent>>>) -> Self {
        Self {
            events: Some(events),
        }
    }

    #[cfg(test)]
    fn record(&self, event: ProcessLifecycleEvent) {
        if let Some(events) = &self.events
            && let Ok(mut events) = events.lock()
        {
            events.push(event);
        }
    }

    #[cfg(not(test))]
    const fn record(&self, event: ProcessLifecycleEvent) {
        let _ = (self, event);
    }
}

struct ProcessGroupGuard {
    pid: Option<Pid>,
    exit: AsyncFd<OwnedFd>,
    observer: ProcessLifecycleObserver,
}

impl ProcessGroupGuard {
    fn new(
        child: &Child,
        observer: ProcessLifecycleObserver,
    ) -> Result<Self, OciVerificationError> {
        let pid = child
            .id()
            .and_then(|id| i32::try_from(id).ok())
            .and_then(Pid::from_raw)
            .ok_or(OciVerificationError::Unavailable)?;
        let pidfd = pidfd_open(pid, PidfdFlags::empty()).map_err(|_| {
            let _ = kill_process_group(pid, Signal::KILL);
            OciVerificationError::Unavailable
        })?;
        let exit = AsyncFd::with_interest(pidfd, Interest::READABLE).map_err(|_| {
            let _ = kill_process_group(pid, Signal::KILL);
            OciVerificationError::Unavailable
        })?;
        Ok(Self {
            pid: Some(pid),
            exit,
            observer,
        })
    }

    async fn observe_exit_without_reaping(&self) -> Result<(), OciVerificationError> {
        let mut readiness = self
            .exit
            .readable()
            .await
            .map_err(|_| OciVerificationError::Unavailable)?;
        readiness.retain_ready();
        self.observer
            .record(ProcessLifecycleEvent::ExitObservedWithoutReap);
        Ok(())
    }

    fn terminate_and_disarm(&mut self) -> Result<Pid, OciVerificationError> {
        let pid = self.pid.ok_or(OciVerificationError::Unavailable)?;
        match kill_process_group(pid, Signal::KILL) {
            Ok(()) | Err(rustix::io::Errno::SRCH) => {}
            Err(_) => return Err(OciVerificationError::Unavailable),
        }
        self.pid = None;
        self.observer
            .record(ProcessLifecycleEvent::GroupKillCompleted);
        Ok(pid)
    }

    async fn wait_until_group_gone(
        &self,
        pid: Pid,
        deadline: Instant,
    ) -> Result<(), OciVerificationError> {
        loop {
            match test_kill_process_group(pid) {
                Err(rustix::io::Errno::SRCH) => {
                    self.observer.record(ProcessLifecycleEvent::GroupGone);
                    return Ok(());
                }
                Ok(()) => {}
                Err(_) => return Err(OciVerificationError::Unavailable),
            }
            if Instant::now() >= deadline {
                return Err(OciVerificationError::Timeout);
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }
}

impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        if let Some(pid) = self.pid {
            let _ = kill_process_group(pid, Signal::KILL);
        }
    }
}

struct BoundedOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
}

async fn wait_bounded(
    child: Child,
    duration: Duration,
    stdout_limit: u64,
) -> Result<BoundedOutput, OciVerificationError> {
    wait_bounded_inner(
        child,
        duration,
        stdout_limit,
        ProcessLifecycleObserver::default(),
    )
    .await
}

async fn wait_bounded_inner(
    mut child: Child,
    duration: Duration,
    stdout_limit: u64,
    observer: ProcessLifecycleObserver,
) -> Result<BoundedOutput, OciVerificationError> {
    let mut guard = ProcessGroupGuard::new(&child, observer)?;
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
        let stdout = read_pipe(stdout, stdout_limit);
        let stderr = read_pipe(stderr, MAX_COSIGN_STDERR_BYTES);
        let status = async {
            guard.observe_exit_without_reaping().await?;
            let pid = guard.terminate_and_disarm()?;
            // The group leader still reserves `pid` until this wait reaps it.
            // Disarming first guarantees cancellation after the group kill can
            // never signal a later process group that reuses the numeric ID.
            let status = child
                .wait()
                .await
                .map_err(|_| OciVerificationError::Unavailable)?;
            guard.observer.record(ProcessLifecycleEvent::LeaderReaped);
            guard.wait_until_group_gone(pid, deadline).await?;
            Ok::<_, OciVerificationError>(status)
        };
        let (stdout, stderr, status) = tokio::join!(stdout, stderr, status);
        let stdout = stdout?;
        let _stderr = Zeroizing::new(stderr?);
        let status = status?;
        Ok::<_, OciVerificationError>(BoundedOutput { status, stdout })
    };
    timeout_at(deadline, operation)
        .await
        .unwrap_or(Err(OciVerificationError::Timeout))
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

#[derive(Debug, Eq, PartialEq)]
struct LegacyUpgradeInput {
    signed_payload: Vec<u8>,
    local_bundle: Vec<u8>,
    rfc3161_timestamp: Option<Vec<u8>>,
    ignore_tlog: bool,
}

#[allow(clippy::too_many_lines)]
fn parse_legacy_records(
    bytes: &[u8],
    repository: &str,
    digest: OciDigest,
    policy: &OciSignerPolicy,
) -> Result<Vec<LegacyUpgradeInput>, OciVerificationError> {
    let mut records = Vec::new();
    let mut seen = 0_usize;
    let mut saw_modern = false;
    for line in bytes.split(|byte| *byte == b'\n') {
        let line = trim_ascii(line);
        if line.is_empty() {
            continue;
        }
        if seen >= MAX_COSIGN_RECORDS {
            return Err(OciVerificationError::MalformedOutput);
        }
        seen += 1;
        let value: serde_json::Value =
            serde_json::from_slice(line).map_err(|_| OciVerificationError::MalformedOutput)?;
        let object = value
            .as_object()
            .ok_or(OciVerificationError::MalformedOutput)?;
        if object.contains_key("mediaType") {
            // OCI 1.1 image bundles use a digest-only DSSE subject today. They
            // cannot satisfy Basil's exact repository-binding invariant.
            if !records.is_empty() {
                return Err(OciVerificationError::MalformedOutput);
            }
            saw_modern = true;
            continue;
        }
        if saw_modern {
            return Err(OciVerificationError::MalformedOutput);
        }
        let signature = object
            .get("Base64Signature")
            .and_then(serde_json::Value::as_str)
            .ok_or(OciVerificationError::MalformedOutput)?;
        let signature_bytes = base64::engine::general_purpose::STANDARD
            .decode(signature)
            .map_err(|_| OciVerificationError::MalformedOutput)?;
        if signature_bytes.is_empty()
            || u64::try_from(signature_bytes.len())
                .map_or(true, |size| size > MAX_SIGSTORE_BUNDLE_BYTES)
        {
            return Err(OciVerificationError::MalformedOutput);
        }
        let payload = object
            .get("Payload")
            .and_then(serde_json::Value::as_str)
            .ok_or(OciVerificationError::MalformedOutput)?;
        let signed_payload = base64::engine::general_purpose::STANDARD
            .decode(payload)
            .map_err(|_| OciVerificationError::MalformedOutput)?;
        if signed_payload.is_empty()
            || u64::try_from(signed_payload.len())
                .map_or(true, |size| size > MAX_SIGSTORE_BUNDLE_BYTES)
        {
            return Err(OciVerificationError::MalformedOutput);
        }
        validate_simple_signing_payload(&signed_payload, repository, digest)?;

        let rekor_bundle = object.get("Bundle").filter(|value| !value.is_null());
        let requires_tlog = !matches!(
            policy.signer,
            OciSignerMode::PinnedKey {
                transparency: TransparencyPolicy::Optional,
                ..
            }
        );
        if requires_tlog && rekor_bundle.is_none() {
            continue;
        }
        let mut local = serde_json::Map::new();
        local.insert(
            "base64Signature".to_owned(),
            serde_json::Value::String(signature.to_owned()),
        );
        if matches!(policy.signer, OciSignerMode::Keyless { .. }) {
            let raw_certificate = object
                .get("Cert")
                .and_then(|certificate| certificate.get("Raw"))
                .and_then(serde_json::Value::as_str)
                .ok_or(OciVerificationError::MalformedOutput)?;
            base64::engine::general_purpose::STANDARD
                .decode(raw_certificate)
                .map_err(|_| OciVerificationError::MalformedOutput)?;
            let certificate = pem_certificate(raw_certificate);
            local.insert(
                "cert".to_owned(),
                serde_json::Value::String(
                    base64::engine::general_purpose::STANDARD.encode(certificate),
                ),
            );
        }
        if let Some(rekor_bundle) = rekor_bundle {
            local.insert("rekorBundle".to_owned(), rekor_bundle.clone());
        }
        let rfc3161_timestamp = object
            .get("RFC3161Timestamp")
            .filter(|value| !value.is_null())
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|_| OciVerificationError::MalformedOutput)?;
        records.push(LegacyUpgradeInput {
            signed_payload,
            local_bundle: serde_json::to_vec(&local)
                .map_err(|_| OciVerificationError::MalformedOutput)?,
            rfc3161_timestamp,
            ignore_tlog: rekor_bundle.is_none(),
        });
    }
    Ok(records)
}

fn pem_certificate(raw_base64_der: &str) -> Vec<u8> {
    let mut output = b"-----BEGIN CERTIFICATE-----\n".to_vec();
    for line in raw_base64_der.as_bytes().chunks(64) {
        output.extend_from_slice(line);
        output.push(b'\n');
    }
    output.extend_from_slice(b"-----END CERTIFICATE-----\n");
    output
}

fn encode_offline_bundle(bundle: &OciOfflineBundle) -> Result<Vec<u8>, OciVerificationError> {
    validate_offline_bundle_bounds(bundle)?;
    let encoded = CachedOfflineBundle {
        version: 2,
        repository: bundle.repository.clone(),
        signed_object: match bundle.signed_object {
            SignedOciObject::Index => "index",
            SignedOciObject::Manifest => "manifest",
        }
        .to_owned(),
        platform: CachedPlatform {
            operating_system: bundle.platform.operating_system.clone(),
            architecture: bundle.platform.architecture.clone(),
            variant: bundle.platform.variant.clone(),
        },
        index: bundle.index.as_ref().map(encode_cached_document),
        manifest: encode_cached_document(&bundle.manifest),
        config: encode_cached_document(&bundle.config),
        records: bundle
            .records
            .iter()
            .map(|record| CachedOfflineRecord {
                signed_payload: base64::engine::general_purpose::STANDARD
                    .encode(&record.signed_payload),
                sigstore_bundle: base64::engine::general_purpose::STANDARD
                    .encode(&record.sigstore_bundle),
            })
            .collect(),
    };
    serde_json::to_vec(&encoded).map_err(|_| OciVerificationError::MalformedOutput)
}

fn decode_offline_bundle(bytes: &[u8]) -> Result<OciOfflineBundle, OciVerificationError> {
    let encoded: CachedOfflineBundle =
        serde_json::from_slice(bytes).map_err(|_| OciVerificationError::MalformedOutput)?;
    if encoded.version != 2
        || encoded.records.is_empty()
        || encoded.records.len() > MAX_COSIGN_RECORDS
    {
        return Err(OciVerificationError::MalformedOutput);
    }
    let records = encoded
        .records
        .into_iter()
        .map(|record| {
            Ok(OciOfflineRecord {
                signed_payload: base64::engine::general_purpose::STANDARD
                    .decode(record.signed_payload)
                    .map_err(|_| OciVerificationError::MalformedOutput)?,
                sigstore_bundle: base64::engine::general_purpose::STANDARD
                    .decode(record.sigstore_bundle)
                    .map_err(|_| OciVerificationError::MalformedOutput)?,
            })
        })
        .collect::<Result<Vec<_>, OciVerificationError>>()?;
    let signed_object = match encoded.signed_object.as_str() {
        "index" => SignedOciObject::Index,
        "manifest" => SignedOciObject::Manifest,
        _ => return Err(OciVerificationError::MalformedOutput),
    };
    let bundle = OciOfflineBundle {
        repository: encoded.repository,
        signed_object,
        platform: OciPlatform {
            operating_system: encoded.platform.operating_system,
            architecture: encoded.platform.architecture,
            variant: encoded.platform.variant,
        },
        index: encoded.index.map(decode_cached_document).transpose()?,
        manifest: decode_cached_document(encoded.manifest)?,
        config: decode_cached_document(encoded.config)?,
        records,
    };
    validate_offline_bundle_bounds(&bundle)?;
    Ok(bundle)
}

fn encode_cached_document(document: &OciDocument) -> CachedDocument {
    CachedDocument {
        digest: document.digest.to_string(),
        bytes: base64::engine::general_purpose::STANDARD.encode(&document.bytes),
    }
}

fn decode_cached_document(document: CachedDocument) -> Result<OciDocument, OciVerificationError> {
    Ok(OciDocument {
        digest: OciDigest::parse(&document.digest)
            .map_err(|_| OciVerificationError::MalformedOutput)?,
        bytes: base64::engine::general_purpose::STANDARD
            .decode(document.bytes)
            .map_err(|_| OciVerificationError::MalformedOutput)?,
    })
}

fn validate_offline_bundle_bounds(bundle: &OciOfflineBundle) -> Result<(), OciVerificationError> {
    let records = &bundle.records;
    if records.is_empty() || records.len() > MAX_COSIGN_RECORDS {
        return Err(OciVerificationError::MalformedOutput);
    }
    validate_repository(&bundle.repository).map_err(|_| OciVerificationError::MalformedOutput)?;
    bundle
        .platform
        .validate()
        .map_err(|_| OciVerificationError::MalformedOutput)?;
    for document in bundle
        .index
        .iter()
        .chain([&bundle.manifest, &bundle.config])
    {
        validate_document_hash(document).map_err(|_| OciVerificationError::MalformedOutput)?;
    }
    if bundle.signed_object == SignedOciObject::Index && bundle.index.is_none() {
        return Err(OciVerificationError::MalformedOutput);
    }
    let document_total = bundle
        .index
        .as_ref()
        .map_or(0, |document| document.bytes.len())
        .checked_add(bundle.manifest.bytes.len())
        .and_then(|total| total.checked_add(bundle.config.bytes.len()))
        .ok_or(OciVerificationError::OutputLimit)?;
    validate_acquired_records(records, document_total)
}

fn offline_document_bytes(chain: &OciImageChain) -> Result<usize, OciVerificationError> {
    chain
        .index
        .as_ref()
        .map_or(0, |document| document.bytes.len())
        .checked_add(chain.manifest.bytes.len())
        .and_then(|total| total.checked_add(chain.config.bytes.len()))
        .ok_or(OciVerificationError::OutputLimit)
}

fn validate_acquired_records(
    records: &[OciOfflineRecord],
    document_bytes: usize,
) -> Result<(), OciVerificationError> {
    if records.is_empty() || records.len() > MAX_COSIGN_RECORDS {
        return Err(OciVerificationError::MalformedOutput);
    }
    let total = records.iter().try_fold(document_bytes, |total, record| {
        total
            .checked_add(record.signed_payload.len())?
            .checked_add(record.sigstore_bundle.len())
    });
    if records
        .iter()
        .any(|record| record.signed_payload.is_empty() || record.sigstore_bundle.is_empty())
        || total
            .and_then(|size| u64::try_from(size).ok())
            .is_none_or(|size| size > MAX_SIGSTORE_BUNDLE_BYTES)
    {
        return Err(OciVerificationError::OutputLimit);
    }
    Ok(())
}

const fn map_cache_error(error: OciEvidenceCacheError) -> OciVerificationError {
    match error {
        OciEvidenceCacheError::InvalidInput | OciEvidenceCacheError::UnsafeLayout => {
            OciVerificationError::Configuration
        }
        OciEvidenceCacheError::Unavailable => OciVerificationError::Unavailable,
        OciEvidenceCacheError::EntryTooLarge => OciVerificationError::OutputLimit,
    }
}

fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = bytes.get(1..).unwrap_or_default();
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = bytes
            .get(..bytes.len().saturating_sub(1))
            .unwrap_or_default();
    }
    bytes
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::core::registry_isolation::{
        RegistryAccess, RegistryAuthDocument, RegistryIsolationError,
    };
    use rustls::ServerConfig as RustlsServerConfig;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _};
    use tokio::io::AsyncWriteExt as _;
    use tokio::net::TcpListener;

    #[derive(Clone, Debug)]
    enum RegistryMode {
        Public,
        RequireBearer(String),
        Status(u16),
    }

    struct TlsRegistry {
        authority: String,
        mode: Arc<Mutex<RegistryMode>>,
        requests: Arc<Mutex<Vec<String>>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl TlsRegistry {
        async fn start() -> Self {
            crate::ensure_crypto_provider();
            let certs = CertificateDer::pem_reader_iter(&mut std::io::Cursor::new(include_bytes!(
                "../../testdata/registry_tls_cert.pem"
            )))
            .collect::<Result<Vec<_>, _>>()
            .expect("parse registry test certificate");
            let key = PrivateKeyDer::from_pem_reader(&mut std::io::Cursor::new(include_bytes!(
                "../../testdata/registry_tls_key.pem"
            )))
            .expect("parse registry test key");
            let config = RustlsServerConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .expect("select TLS versions")
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("build registry TLS config");
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind registry fixture");
            let address = listener.local_addr().expect("registry address");
            let authority = format!("localhost:{}", address.port());
            let mode = Arc::new(Mutex::new(RegistryMode::Public));
            let requests = Arc::new(Mutex::new(Vec::new()));
            let server_mode = Arc::clone(&mode);
            let server_requests = Arc::clone(&requests);
            let task = tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    let acceptor = acceptor.clone();
                    let mode = Arc::clone(&server_mode);
                    let requests = Arc::clone(&server_requests);
                    tokio::spawn(async move {
                        let Ok(mut stream) = acceptor.accept(stream).await else {
                            return;
                        };
                        let mut bytes = Vec::new();
                        let mut chunk = [0_u8; 1024];
                        while bytes.len() <= 16 * 1024 {
                            let Ok(read) = stream.read(&mut chunk).await else {
                                return;
                            };
                            if read == 0 {
                                return;
                            }
                            bytes.extend_from_slice(&chunk[..read]);
                            if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                                break;
                            }
                        }
                        let request = String::from_utf8_lossy(&bytes).into_owned();
                        if let Ok(mut captured) = requests.lock() {
                            captured.push(request.clone());
                        }
                        let mode = mode
                            .lock()
                            .map_or(RegistryMode::Status(500), |guard| guard.clone());
                        let status = match mode {
                            RegistryMode::Public => 200,
                            RegistryMode::RequireBearer(token) => {
                                let expected = format!("authorization: Bearer {token}");
                                if request
                                    .lines()
                                    .any(|line| line.eq_ignore_ascii_case(&expected))
                                {
                                    200
                                } else {
                                    401
                                }
                            }
                            RegistryMode::Status(status) => status,
                        };
                        let reason = match status {
                            200 => "OK",
                            401 => "Unauthorized",
                            403 => "Forbidden",
                            429 => "Too Many Requests",
                            _ => "Service Unavailable",
                        };
                        let response = format!(
                            "HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                        let _ = stream.write_all(response.as_bytes()).await;
                        let _ = stream.shutdown().await;
                    });
                }
            });
            Self {
                authority,
                mode,
                requests,
                task,
            }
        }

        fn set_mode(&self, mode: RegistryMode) {
            if let Ok(mut current) = self.mode.lock() {
                *current = mode;
            }
        }
    }

    impl Drop for TlsRegistry {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    struct Fixture {
        root: PathBuf,
        key: PathBuf,
        manifest: OciDocument,
        index: OciDocument,
        config: OciDocument,
    }

    impl Fixture {
        fn new() -> Self {
            let root =
                std::env::temp_dir().join(format!("basil-cosign-test-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            let key = root.join("cosign.pub");
            fs::write(&key, "public key").unwrap();
            fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
            let config_bytes = br#"{"architecture":"amd64","os":"linux"}"#.to_vec();
            let config = OciDocument {
                digest: OciDigest::from_bytes(&config_bytes),
                bytes: config_bytes,
            };
            let manifest_bytes = format!(
                "{{\"schemaVersion\":2,\"config\":{{\"digest\":\"{}\"}},\"layers\":[]}}",
                config.digest
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
                running_config: self.config.digest,
                config: self.config.clone(),
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
            let mut verifier = CosignVerifier::for_public_registries(CosignConfig {
                executable,
                temp_parent: self.root.clone(),
                deadline,
            })
            .unwrap()
            .with_signer_policies(&BTreeMap::from([("fixture".to_owned(), self.policy())]))
            .unwrap();
            verifier.skip_registry_preflight = true;
            verifier
        }

        fn verifier_with_registry(
            &self,
            executable: PathBuf,
            access: RegistryAccess,
        ) -> CosignVerifier {
            let mut verifier = CosignVerifier::new(
                CosignConfig {
                    executable,
                    temp_parent: self.root.clone(),
                    deadline: Duration::from_secs(2),
                },
                access,
            )
            .unwrap()
            .with_signer_policies(&BTreeMap::from([("fixture".to_owned(), self.policy())]))
            .unwrap();
            verifier.skip_registry_preflight = true;
            verifier
        }

        fn registry_access(&self, contents: &str) -> RegistryAccess {
            let path = self
                .root
                .join(format!("auth-{}.json", uuid::Uuid::new_v4()));
            fs::write(&path, contents).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            let auth = RegistryAuthDocument::load_protected_file(&path).unwrap();
            RegistryAccess::with_document(Some(auth), BTreeMap::new()).unwrap()
        }

        fn tls_registry_access(
            &self,
            authority: &str,
            credential: Option<(&str, &str)>,
        ) -> RegistryAccess {
            let ca = self
                .root
                .join(format!("registry-ca-{}.pem", uuid::Uuid::new_v4()));
            fs::write(&ca, include_bytes!("../../testdata/registry_tls_ca.pem")).unwrap();
            fs::set_permissions(&ca, fs::Permissions::from_mode(0o600)).unwrap();
            let auth = credential.map(|(credential_authority, token)| {
                let path = self
                    .root
                    .join(format!("registry-auth-{}.json", uuid::Uuid::new_v4()));
                fs::write(
                    &path,
                    format!(
                        r#"{{"auths":{{"{credential_authority}":{{"identitytoken":"{token}"}}}}}}"#
                    ),
                )
                .unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                RegistryAuthDocument::load_protected_file(&path).unwrap()
            });
            RegistryAccess::with_document(auth, BTreeMap::from([(authority.to_string(), ca)]))
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

        fn exiting_parent_script(&self, exit_status: i32) -> (PathBuf, PathBuf) {
            let descendant = self
                .root
                .join(format!("descendant-{}", uuid::Uuid::new_v4()));
            let ready = self.root.join(format!("ready-{}", uuid::Uuid::new_v4()));
            let signed = self.manifest.digest;
            let executable = self.executable(&format!(
                r#"case "$1" in
verify)
  parent=$BASHPID
  descendant_ready=0
  trap 'descendant_ready=1' USR1
  (
    exec >/dev/null 2>&1
    exec 9<"$DOCKER_CONFIG/config.json"
    printf '%s' ready > {ready}
    kill -USR1 "$parent"
    kill -STOP "$BASHPID"
  ) &
  descendant=$!
  printf '%s' "$descendant" > {descendant}
  while (( descendant_ready == 0 )); do :; done
  trap - USR1
  test -e {ready}
  printf '%s' '[{{"critical":{{"identity":{{"docker-reference":"registry.example/team/app"}},"image":{{"docker-manifest-digest":"{signed}"}}}},"optional":{{}}}}]'
  exit {exit_status}
  ;;
*) exit 1 ;;
esac"#,
                ready = ready.display(),
                descendant = descendant.display(),
            ));
            (executable, descendant)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn simple_signing_payload(repository: &str, digest: OciDigest) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "critical": {
                "identity": { "docker-reference": repository },
                "image": { "docker-manifest-digest": digest.to_string() },
                "type": "cosign container image signature"
            },
            "optional": null
        }))
        .expect("encode simple signing payload")
    }

    fn legacy_download_record(repository: &str, digest: OciDigest) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "Base64Signature": base64::engine::general_purpose::STANDARD.encode(b"signature"),
            "Payload": base64::engine::general_purpose::STANDARD
                .encode(simple_signing_payload(repository, digest)),
            "Cert": null,
            "Chain": null,
            "Bundle": null,
            "RFC3161Timestamp": null
        }))
        .expect("encode legacy download record")
    }

    fn offline_evidence(chain: &OciImageChain, bundle: &[u8]) -> OciOfflineBundle {
        OciOfflineBundle {
            repository: chain.repository.clone(),
            signed_object: chain.signed_object,
            platform: chain.platform.clone(),
            index: chain.index.clone(),
            manifest: chain.manifest.clone(),
            config: chain.config.clone(),
            records: vec![OciOfflineRecord {
                signed_payload: simple_signing_payload(
                    &chain.repository,
                    match chain.signed_object {
                        SignedOciObject::Index => chain
                            .index
                            .as_ref()
                            .map_or(chain.manifest.digest, |index| index.digest),
                        SignedOciObject::Manifest => chain.manifest.digest,
                    },
                ),
                sigstore_bundle: bundle.to_vec(),
            }],
        }
    }

    #[test]
    fn protected_executable_accepts_nix_store_hardlinks_but_rejects_writable_files() {
        let fixture = Fixture::new();
        let writable = fixture.executable("exit 0");
        fs::set_permissions(&writable, fs::Permissions::from_mode(0o720))
            .expect("make executable group writable");
        assert_eq!(
            CosignConfig {
                executable: writable,
                temp_parent: fixture.root.clone(),
                deadline: Duration::from_secs(2),
            }
            .validate(),
            Err(OciVerificationError::Configuration)
        );

        let hardlink = fixture.root.join("hardlinked-cosign");
        let source = fixture.executable("exit 0");
        fs::hard_link(&source, &hardlink).expect("create non-store hardlink");
        assert_eq!(
            CosignConfig {
                executable: hardlink,
                temp_parent: fixture.root.clone(),
                deadline: Duration::from_secs(2),
            }
            .validate(),
            Err(OciVerificationError::Configuration)
        );

        let Ok(nix_cosign) = fs::canonicalize("/run/current-system/sw/bin/cosign") else {
            return;
        };
        let metadata = fs::metadata(&nix_cosign).expect("Nix Cosign metadata");
        if !nix_cosign.starts_with("/nix/store") || metadata.nlink() <= 1 {
            return;
        }
        CosignConfig {
            executable: nix_cosign,
            temp_parent: fixture.root.clone(),
            deadline: Duration::from_secs(2),
        }
        .validate()
        .expect("immutable root-owned Nix-store executable hardlink is protected");
    }

    #[test]
    fn legacy_parser_binds_repository_digest_and_rejects_mixed_or_unbounded_output() {
        let fixture = Fixture::new();
        let policy = OciSignerPolicy {
            repository: "registry.example/team/app".to_owned(),
            signer: OciSignerMode::PinnedKey {
                public_key: fixture.key.clone(),
                transparency: TransparencyPolicy::Optional,
            },
        };
        let digest = fixture.manifest.digest;
        let valid = legacy_download_record(&policy.repository, digest);
        assert_eq!(
            parse_legacy_records(&valid, &policy.repository, digest, &policy)
                .expect("valid legacy record")
                .len(),
            1
        );
        assert_eq!(
            parse_legacy_records(
                &legacy_download_record("registry.example/other/app", digest),
                &policy.repository,
                digest,
                &policy,
            ),
            Err(OciVerificationError::MalformedOutput)
        );
        assert_eq!(
            parse_legacy_records(
                &legacy_download_record(&policy.repository, OciDigest::from_bytes(b"other")),
                &policy.repository,
                digest,
                &policy,
            ),
            Err(OciVerificationError::MalformedOutput)
        );

        let modern = br#"{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","verificationMaterial":{},"dsseEnvelope":{"payloadType":"application/vnd.in-toto+json","payload":"e30="}}"#;
        assert!(
            parse_legacy_records(modern, &policy.repository, digest, &policy)
                .expect("digest-only modern record is non-cacheable")
                .is_empty()
        );
        let mut mixed = valid.clone();
        mixed.push(b'\n');
        mixed.extend_from_slice(modern);
        assert_eq!(
            parse_legacy_records(&mixed, &policy.repository, digest, &policy),
            Err(OciVerificationError::MalformedOutput)
        );
        let over_records = std::iter::repeat_n(valid, MAX_COSIGN_RECORDS + 1)
            .collect::<Vec<_>>()
            .join(&b'\n');
        assert_eq!(
            parse_legacy_records(&over_records, &policy.repository, digest, &policy),
            Err(OciVerificationError::MalformedOutput)
        );
        let half_limit =
            usize::try_from(MAX_SIGSTORE_BUNDLE_BYTES / 2).expect("bundle limit fits in usize");
        let chain = fixture.chain(SignedOciObject::Manifest);
        let mut aggregate_overflow = offline_evidence(&chain, b"bundle");
        aggregate_overflow.records = vec![OciOfflineRecord {
            signed_payload: vec![0_u8; half_limit],
            sigstore_bundle: vec![0_u8; half_limit + 1],
        }];
        assert_eq!(
            validate_offline_bundle_bounds(&aggregate_overflow),
            Err(OciVerificationError::OutputLimit)
        );
    }

    #[tokio::test]
    async fn offline_path_rejects_replay_tamper_rotation_and_denylist() {
        let fixture = Fixture::new();
        fs::write(&fixture.key, "current-key").expect("write current key generation");
        let executable = fixture.executable("exit 0");
        let verifier = fixture.verifier(executable, Duration::from_secs(2));
        let policy = fixture.policy();
        let chain = fixture.chain(SignedOciObject::Manifest);
        let evidence = offline_evidence(&chain, br#"{"valid":true}"#);
        assert_eq!(
            verifier
                .verify_offline("production", &policy, &chain, &evidence, &BTreeSet::new())
                .await
                .map(|_| ()),
            Ok(())
        );

        let mut replay_chain = chain.clone();
        replay_chain.repository = "registry.example/other/app".to_owned();
        let mut replay_policy = policy.clone();
        replay_policy.repository = replay_chain.repository.clone();
        assert_eq!(
            verifier
                .verify_offline(
                    "production",
                    &replay_policy,
                    &replay_chain,
                    &evidence,
                    &BTreeSet::new(),
                )
                .await,
            Err(OciVerificationError::DigestChain)
        );

        let mut wrong_digest = evidence.clone();
        wrong_digest.records[0].signed_payload =
            simple_signing_payload(&chain.repository, OciDigest::from_bytes(b"other"));
        assert_eq!(
            verifier
                .verify_offline(
                    "production",
                    &policy,
                    &chain,
                    &wrong_digest,
                    &BTreeSet::new(),
                )
                .await,
            Err(OciVerificationError::MalformedOutput)
        );

        let mut tampered_payload = evidence.clone();
        tampered_payload.records[0].signed_payload.push(b'!');
        assert_eq!(
            verifier
                .verify_offline(
                    "production",
                    &policy,
                    &chain,
                    &tampered_payload,
                    &BTreeSet::new(),
                )
                .await,
            Err(OciVerificationError::MalformedOutput)
        );

        let mut tampered_bundle = evidence.clone();
        tampered_bundle.records[0].sigstore_bundle = br#"{"valid":false}"#.to_vec();
        let rejecting_verifier =
            fixture.verifier(fixture.executable("exit 1"), Duration::from_secs(2));
        assert_eq!(
            rejecting_verifier
                .verify_offline(
                    "production",
                    &policy,
                    &chain,
                    &tampered_bundle,
                    &BTreeSet::new(),
                )
                .await,
            Err(OciVerificationError::Rejected)
        );

        let denied = BTreeSet::from([chain.manifest.digest]);
        assert_eq!(
            verifier
                .verify_offline("production", &policy, &chain, &evidence, &denied)
                .await,
            Err(OciVerificationError::Rejected)
        );
        fs::write(&fixture.key, "rotated-key").expect("rotate key generation");
        assert_eq!(
            rejecting_verifier
                .verify_offline("production", &policy, &chain, &evidence, &BTreeSet::new())
                .await,
            Err(OciVerificationError::Rejected)
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn cold_cache_hit_reconstructs_and_hashes_complete_digest_chain() {
        let fixture = Fixture::new();
        let verifier = fixture.verifier(
            fixture.executable("test \"$1\" = verify-blob"),
            Duration::from_secs(2),
        );
        let policy = fixture.policy();
        let chain = fixture.chain(SignedOciObject::Manifest);
        let bundle = offline_evidence(&chain, br#"{"valid":true}"#);
        let encoded = encode_offline_bundle(&bundle).expect("encode complete evidence");
        let cache = OciEvidenceCache::open(
            crate::core::oci_evidence_cache::OciEvidenceCacheConfig::new(
                fixture.root.join("evidence-cache"),
            ),
        )
        .expect("open evidence cache");
        cache
            .store(
                &EvidenceContext {
                    subject: chain.manifest.digest,
                    source_context: chain.repository.clone(),
                    references: BTreeSet::from([format!(
                        "{}@{}",
                        chain.repository, chain.manifest.digest
                    )]),
                },
                &encoded,
                2_000_000_000,
            )
            .expect("store complete evidence");
        let expectation = OciRuntimeExpectation {
            repository: chain.repository.clone(),
            index_digest: chain.index.as_ref().map(|index| index.digest),
            selected_manifest: chain.manifest.digest,
            running_config: chain.running_config,
            platform: chain.platform.clone(),
        };

        let admitted = verifier
            .verify_cached_expectation(
                &cache,
                "production",
                &policy,
                &expectation,
                &BTreeSet::new(),
                2_000_000_001,
            )
            .await
            .expect("cold offline hit");
        assert_eq!(admitted.manifest_digest, chain.manifest.digest);
        assert_eq!(admitted.config_digest, chain.config.digest);

        let mut wrong_runtime = expectation.clone();
        wrong_runtime.running_config = OciDigest::from_bytes(b"different runtime config");
        assert_eq!(
            verifier
                .verify_cached_expectation(
                    &cache,
                    "production",
                    &policy,
                    &wrong_runtime,
                    &BTreeSet::new(),
                    2_000_000_002,
                )
                .await,
            Err(OciVerificationError::Unavailable)
        );
        assert_eq!(
            cache
                .check(2_000_000_002)
                .expect("evidence retained")
                .entries
                .len(),
            1
        );

        let corrupt_cache = OciEvidenceCache::open(
            crate::core::oci_evidence_cache::OciEvidenceCacheConfig::new(
                fixture.root.join("corrupt-evidence-cache"),
            ),
        )
        .expect("open corrupt evidence cache");
        let mut corrupt: serde_json::Value =
            serde_json::from_slice(&encoded).expect("decode cache envelope for corruption");
        corrupt["config"]["bytes"] = serde_json::Value::String(
            base64::engine::general_purpose::STANDARD.encode(br#"{"tampered":true}"#),
        );
        corrupt_cache
            .store(
                &EvidenceContext {
                    subject: chain.manifest.digest,
                    source_context: chain.repository.clone(),
                    references: BTreeSet::from(["registry.example/team/app:tampered".to_owned()]),
                },
                &serde_json::to_vec(&corrupt).expect("encode corrupt evidence"),
                2_000_000_003,
            )
            .expect("store internally corrupt evidence");
        assert_eq!(
            verifier
                .verify_cached_expectation(
                    &corrupt_cache,
                    "production",
                    &policy,
                    &expectation,
                    &BTreeSet::new(),
                    2_000_000_004,
                )
                .await,
            Err(OciVerificationError::Unavailable)
        );
        assert!(
            corrupt_cache
                .check(2_000_000_004)
                .expect("corrupt entry removed")
                .entries
                .is_empty()
        );
    }

    #[tokio::test]
    async fn cold_index_signed_hit_never_uses_online_verifier_path() {
        let fixture = Fixture::new();
        let verifier = fixture.verifier(
            fixture.executable("test \"$1\" = verify-blob"),
            Duration::from_secs(2),
        );
        let policy = fixture.policy();
        let chain = fixture.chain(SignedOciObject::Index);
        let bundle = offline_evidence(&chain, br#"{"valid":true}"#);
        let cache = OciEvidenceCache::open(
            crate::core::oci_evidence_cache::OciEvidenceCacheConfig::new(
                fixture.root.join("index-evidence-cache"),
            ),
        )
        .expect("open index evidence cache");
        let index = chain.index.as_ref().expect("index chain");
        cache
            .store(
                &EvidenceContext {
                    subject: index.digest,
                    source_context: chain.repository.clone(),
                    references: BTreeSet::from([format!("{}@{}", chain.repository, index.digest)]),
                },
                &encode_offline_bundle(&bundle).expect("encode index evidence"),
                2_000_000_000,
            )
            .expect("store index evidence");
        let expectation = OciRuntimeExpectation {
            repository: chain.repository.clone(),
            index_digest: Some(index.digest),
            selected_manifest: chain.manifest.digest,
            running_config: chain.running_config,
            platform: chain.platform.clone(),
        };

        let admitted = verifier
            .verify_cached_expectation(
                &cache,
                "production",
                &policy,
                &expectation,
                &BTreeSet::new(),
                2_000_000_001,
            )
            .await
            .expect("cold index-signed hit");
        assert_eq!(admitted.signed_object, SignedOciObject::Index);
        assert_eq!(admitted.signed_digest, index.digest);
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn stale_hit_deduplicates_background_refresh_and_recovers_diagnostics() {
        let fixture = Fixture::new();
        let chain = fixture.chain(SignedOciObject::Manifest);
        let policy = fixture.policy();
        let counter = fixture.root.join("refresh-count");
        let release = fixture.root.join("refresh-release");
        fs::write(&counter, b"").expect("create counter");
        fs::write(&release, b"").expect("create release");
        let signed = chain.manifest.digest;
        let executable = fixture.executable(&format!(
            r#"case "$1" in
verify-blob) exit 0 ;;
verify)
  printf 'x\n' >> {counter}
  while [ ! -s {release} ]; do :; done
  read -r result < {release}
  if [ "$result" = fail ]; then exit 1; fi
  printf '%s' '[{{"critical":{{"identity":{{"docker-reference":"registry.example/team/app"}},"image":{{"docker-manifest-digest":"{signed}"}}}},"optional":{{}}}}]'
  ;;
download) exit 1 ;;
*) exit 1 ;;
esac"#,
            counter = counter.display(),
            release = release.display()
        ));
        let verifier = Arc::new(fixture.verifier(executable, Duration::from_secs(2)));
        let cache = Arc::new(
            OciEvidenceCache::open(
                crate::core::oci_evidence_cache::OciEvidenceCacheConfig::new(
                    fixture.root.join("refresh-cache"),
                ),
            )
            .expect("open refresh cache"),
        );
        let bundle = offline_evidence(&chain, br#"{"valid":true}"#);
        let collected_at = 2_000_000_000;
        let now = collected_at + crate::core::oci_evidence_cache::REFRESH_AFTER.as_secs() + 1;
        cache
            .store(
                &EvidenceContext {
                    subject: chain.manifest.digest,
                    source_context: chain.repository.clone(),
                    references: BTreeSet::from([format!(
                        "{}@{}",
                        chain.repository, chain.manifest.digest
                    )]),
                },
                &encode_offline_bundle(&bundle).expect("encode stale evidence"),
                collected_at,
            )
            .expect("store stale evidence");

        for _ in 0..8 {
            verifier
                .verify_with_cache(
                    &cache,
                    "production",
                    &policy,
                    &chain,
                    "registry.example/team/app:stable",
                    &BTreeSet::new(),
                    now,
                )
                .await
                .expect("stale hit returns immediately");
        }
        for _ in 0..200 {
            if fs::read_to_string(&counter).is_ok_and(|contents| contents.lines().count() == 1) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(
            fs::read_to_string(&counter)
                .expect("read refresh count")
                .lines()
                .count(),
            1
        );

        fs::write(&release, b"fail\n").expect("release failed refresh");
        for _ in 0..200 {
            if cache
                .doctor(now + 10)
                .is_ok_and(|doctor| doctor.refresh_degraded == 1)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let degraded = cache.doctor(now + 10).expect("failed refresh diagnostics");
        assert_eq!(degraded.refresh_degraded, 1);
        assert_eq!(degraded.longest_degraded_duration_seconds, Some(10));

        fs::write(&release, b"success\n").expect("permit recovery refresh");
        verifier
            .verify_with_cache(
                &cache,
                "production",
                &policy,
                &chain,
                "registry.example/team/app:stable",
                &BTreeSet::new(),
                now + 20,
            )
            .await
            .expect("degraded evidence remains immediately usable");
        for _ in 0..200 {
            if cache
                .doctor(now + 20)
                .is_ok_and(|doctor| doctor.refresh_due == 0)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let recovered = cache.doctor(now + 20).expect("recovery diagnostics");
        assert_eq!(recovered.refresh_due, 0);
        assert_eq!(recovered.refresh_degraded, 0);
        assert_eq!(
            fs::read_to_string(counter)
                .expect("read recovery count")
                .lines()
                .count(),
            2
        );
    }

    #[test]
    fn refresh_coordinator_is_bounded_and_cancelled_lease_records_failure() {
        let fixture = Fixture::new();
        let cache = Arc::new(
            OciEvidenceCache::open(
                crate::core::oci_evidence_cache::OciEvidenceCacheConfig::new(
                    fixture.root.join("cancelled-refresh-cache"),
                ),
            )
            .expect("open cache"),
        );
        let chain = fixture.chain(SignedOciObject::Manifest);
        let context = EvidenceContext {
            subject: chain.manifest.digest,
            source_context: chain.repository,
            references: BTreeSet::from(["registry.example/team/app:stable".to_owned()]),
        };
        let id = match cache
            .store(&context, b"evidence", 2_000_000_000)
            .expect("store evidence")
        {
            CacheStoreOutcome::Stored(id) => id,
            CacheStoreOutcome::AtCapacity => panic!("fixture cache has capacity"),
        };
        let coordinator = Arc::new(RefreshCoordinator::default());
        let mut reserved = Vec::new();
        for index in 0..MAX_BACKGROUND_REFRESHES {
            let candidate = CacheEntryId::parse(&format!("{index:064x}"))
                .expect("bounded candidate identifier");
            assert!(coordinator.reserve(&candidate));
            reserved.push(candidate);
        }
        assert!(
            !coordinator.reserve(
                &CacheEntryId::parse(&format!("{MAX_BACKGROUND_REFRESHES:064x}"))
                    .expect("overflow candidate identifier")
            )
        );
        for candidate in reserved {
            coordinator.release(&candidate);
        }
        assert!(coordinator.reserve(&id));
        let attempted_at = 2_000_000_000 + crate::core::oci_evidence_cache::REFRESH_AFTER.as_secs();
        drop(RefreshLease {
            coordinator,
            cache: Arc::clone(&cache),
            subject: context.subject,
            id,
            attempted_at,
            finished: false,
        });
        let doctor = cache
            .doctor(attempted_at + 7)
            .expect("cancellation diagnostics");
        assert_eq!(doctor.refresh_degraded, 1);
        assert_eq!(doctor.longest_degraded_duration_seconds, Some(7));
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    #[ignore = "requires BASIL_COSIGN_3_1_1 pointing to the exact release binary"]
    async fn real_cosign_3_1_1_fixtures_pass_production_verifier_without_network() {
        const CHILD_ENV: &str = "BASIL_COSIGN_OFFLINE_FIXTURE_CHILD";
        let source_executable = std::env::var_os("BASIL_COSIGN_3_1_1")
            .map(PathBuf::from)
            .and_then(|path| fs::canonicalize(path).ok())
            .expect("set BASIL_COSIGN_3_1_1 to an exact Cosign 3.1.1 binary");
        if std::env::var_os(CHILD_ENV).is_none() {
            let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .and_then(Path::parent)
                .expect("workspace root");
            let output = std::process::Command::new("bwrap")
                .args([
                    "--unshare-user",
                    "--unshare-net",
                    "--uid",
                    "0",
                    "--gid",
                    "0",
                    "--tmpfs",
                    "/",
                    "--dir",
                    "/nix",
                    "--ro-bind",
                    "/nix/store",
                    "/nix/store",
                    "--proc",
                    "/proc",
                    "--dev",
                    "/dev",
                    "--dir",
                    "/tmp",
                    "--dir",
                    "/home",
                    "--dir",
                    "/home/user",
                    "--dir",
                    "/home/user/project",
                    "--dir",
                    "/home/user/project/basil",
                    "--dir",
                    "/home/user/project/basil/.work",
                    "--ro-bind",
                ])
                .arg(workspace)
                .arg(workspace)
                .arg(std::env::current_exe().expect("current test executable"))
                .args([
                    "--exact",
                    "core::oci_verification::tests::real_cosign_3_1_1_fixtures_pass_production_verifier_without_network",
                    "--ignored",
                    "--nocapture",
                ])
                .env(CHILD_ENV, "1")
                .env("BASIL_COSIGN_3_1_1", &source_executable)
                .output()
                .expect("run real fixture test in isolated network namespace");
            assert!(
                output.status.success(),
                "network-isolated fixture test failed:\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        let fixture = Fixture::new();
        let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../basil-tests/fixtures/release-manifest/v1/cosign-3.1.1-conformance");
        let version = std::process::Command::new(&source_executable)
            .arg("version")
            .output()
            .expect("query Cosign fixture verifier version");
        assert!(version.status.success());
        assert!(String::from_utf8_lossy(&version.stdout).contains("GitVersion:    v3.1.1"));
        let executable_bytes = fs::read(&source_executable).expect("read exact Cosign executable");
        let executable = fixture.root.join("cosign-3.1.1");
        fs::write(&executable, executable_bytes).expect("copy protected Cosign executable");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
            .expect("protect Cosign executable");
        let public_key = fixture.root.join("pinned-cosign.pub");
        fs::write(
            &public_key,
            fs::read(directory.join("pinned-cosign.pub")).expect("read public key fixture"),
        )
        .expect("copy public key into protected verifier input");
        fs::set_permissions(&public_key, fs::Permissions::from_mode(0o600))
            .expect("protect verifier public key input");
        let config_bytes = fs::read(directory.join("pinned-config.json")).expect("read config");
        let manifest_bytes =
            fs::read(directory.join("pinned-manifest.json")).expect("read manifest");
        let config = OciDocument {
            digest: OciDigest::from_bytes(&config_bytes),
            bytes: config_bytes,
        };
        let manifest = OciDocument {
            digest: OciDigest::from_bytes(&manifest_bytes),
            bytes: manifest_bytes,
        };
        let chain = OciImageChain {
            repository: "registry.example/team/app".to_owned(),
            platform: OciPlatform {
                operating_system: "linux".to_owned(),
                architecture: "amd64".to_owned(),
                variant: None,
            },
            index: None,
            manifest: manifest.clone(),
            running_config: config.digest,
            config: config.clone(),
            signed_object: SignedOciObject::Manifest,
        };
        let policy = OciSignerPolicy {
            repository: chain.repository.clone(),
            signer: OciSignerMode::PinnedKey {
                public_key,
                transparency: TransparencyPolicy::Optional,
            },
        };
        let keyless_root = fixture.root.join("trusted-root.json");
        fs::write(
            &keyless_root,
            fs::read(directory.join("trusted-root.json")).expect("read trusted-root fixture"),
        )
        .expect("copy protected trusted root");
        fs::set_permissions(&keyless_root, fs::Permissions::from_mode(0o600))
            .expect("protect trusted root");
        let keyless_policy = OciSignerPolicy {
            repository: "registry.example/team/keyless-fixture".to_owned(),
            signer: OciSignerMode::Keyless {
                issuer: "https://token.actions.githubusercontent.com".to_owned(),
                identity: "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main".to_owned(),
            },
        };
        let verifier = CosignVerifier::for_public_registries(CosignConfig {
            executable,
            temp_parent: fixture.root.clone(),
            deadline: Duration::from_secs(30),
        })
        .expect("construct real verifier")
        .with_trusted_root(&keyless_root)
        .expect("snapshot conformance trusted root")
        .with_signer_policies(&BTreeMap::from([
            ("production".to_owned(), policy.clone()),
            ("keyless".to_owned(), keyless_policy.clone()),
        ]))
        .expect("snapshot conformance public key");
        let evidence = OciOfflineBundle {
            repository: chain.repository.clone(),
            signed_object: SignedOciObject::Manifest,
            platform: chain.platform.clone(),
            index: None,
            manifest,
            config,
            records: vec![OciOfflineRecord {
                signed_payload: fs::read(directory.join("pinned-payload.json"))
                    .expect("read signed payload"),
                sigstore_bundle: fs::read(directory.join("pinned-bundle.sigstore.json"))
                    .expect("read Sigstore bundle"),
            }],
        };

        let admitted = verifier
            .verify_offline("production", &policy, &chain, &evidence, &BTreeSet::new())
            .await
            .expect("real Cosign fixture admits");
        assert_eq!(admitted.signed_digest, chain.manifest.digest);
        assert_eq!(admitted.config_digest, chain.config.digest);
        validate_signer_policy("keyless", &keyless_policy).expect("keyless policy validates");
        assert!(
            verifier
                .verify_blob_evidence(
                    &keyless_policy,
                    &fs::read(directory.join("a.txt")).expect("read keyless payload"),
                    &fs::read(directory.join("bundle.sigstore.json")).expect("read keyless bundle"),
                    Instant::now() + Duration::from_secs(30),
                )
                .await
                .expect("real keyless fixture admits")
        );
    }

    #[tokio::test]
    async fn keyless_cache_hit_uses_current_root_and_identity() {
        let fixture = Fixture::new();
        let trusted_root = fixture.root.join("trusted-root.json");
        fs::write(&trusted_root, "current-root").expect("write current root");
        fs::set_permissions(&trusted_root, fs::Permissions::from_mode(0o600))
            .expect("protect current root");
        let executable = fixture.executable("exit 0");
        let verifier = fixture
            .verifier(executable, Duration::from_secs(2))
            .with_trusted_root(&trusted_root)
            .expect("attach trusted root");
        let chain = fixture.chain(SignedOciObject::Manifest);
        let mut policy = OciSignerPolicy {
            repository: chain.repository.clone(),
            signer: OciSignerMode::Keyless {
                issuer: "https://issuer.example".to_owned(),
                identity: "https://identity.example/workflow".to_owned(),
            },
        };
        let evidence = offline_evidence(&chain, br#"{"valid":true}"#);
        assert_eq!(
            verifier
                .verify_offline("production", &policy, &chain, &evidence, &BTreeSet::new())
                .await
                .map(|_| ()),
            Ok(())
        );

        if let OciSignerMode::Keyless { identity, .. } = &mut policy.signer {
            *identity = "https://identity.example/rotated".to_owned();
        }
        let rejecting_verifier = fixture
            .verifier(fixture.executable("exit 1"), Duration::from_secs(2))
            .with_trusted_root(&trusted_root)
            .expect("attach current root to rejecting verifier");
        assert_eq!(
            rejecting_verifier
                .verify_offline("production", &policy, &chain, &evidence, &BTreeSet::new())
                .await,
            Err(OciVerificationError::Rejected)
        );
        if let OciSignerMode::Keyless { identity, .. } = &mut policy.signer {
            *identity = "https://identity.example/workflow".to_owned();
        }
        fs::write(&trusted_root, "rotated-root").expect("rotate trusted root");
        assert_eq!(
            rejecting_verifier
                .verify_offline("production", &policy, &chain, &evidence, &BTreeSet::new())
                .await,
            Err(OciVerificationError::Rejected)
        );
    }

    #[tokio::test]
    async fn failed_bundle_upgrade_does_not_change_online_admission() {
        let fixture = Fixture::new();
        let chain = fixture.chain(SignedOciObject::Manifest);
        let mut policy = fixture.policy();
        policy.signer = OciSignerMode::PinnedKey {
            public_key: fixture.key.clone(),
            transparency: TransparencyPolicy::Optional,
        };
        let legacy = String::from_utf8(legacy_download_record(
            &chain.repository,
            chain.manifest.digest,
        ))
        .expect("legacy JSON is UTF-8");
        let signed = chain.manifest.digest;
        let executable = fixture.executable(&format!(
            r#"case "$1" in
verify) printf '%s' '[{{"critical":{{"identity":{{"docker-reference":"registry.example/team/app"}},"image":{{"docker-manifest-digest":"{signed}"}}}},"optional":{{}}}}]' ;;
download) printf '%s' '{legacy}' ;;
bundle) exit 1 ;;
*) exit 1 ;;
esac"#
        ));
        let verifier = fixture.verifier(executable, Duration::from_secs(2));

        let evidence = verifier
            .verify("production", &policy, &chain)
            .await
            .expect("trusted online verification remains successful");
        assert!(evidence.offline_bundle.is_none());
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
            assert_eq!(evidence.config_digest, fixture.config.digest);
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
            let actual = verifier.verify("production", &policy, &chain).await;
            assert!(
                actual == Err(expected)
                    || (script == "kill -SEGV $$" && actual == Err(OciVerificationError::Timeout)),
                "script: {script}; result: {actual:?}"
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
    async fn private_registry_receives_one_auth_view_without_proxy_inheritance() {
        let fixture = Fixture::new();
        let access = fixture.registry_access(
            r#"{"auths":{"registry.example":{"identitytoken":"private-token"},"other.example":{"identitytoken":"other-token"}}}"#,
        );
        let signed = fixture.manifest.digest;
        let script = fixture.executable(&format!(
            r#"test -n "${{DOCKER_CONFIG:-}}"
config=$(<"$DOCKER_CONFIG/config.json")
case "$config" in
  *private-token*) ;;
  *) exit 71 ;;
esac
case "$config" in
  *other-token*) exit 72 ;;
esac
test -z "${{HTTP_PROXY+x}}${{HTTPS_PROXY+x}}${{ALL_PROXY+x}}${{NO_PROXY+x}}"
printf '%s' '[{{"critical":{{"identity":{{"docker-reference":"registry.example/team/app"}},"image":{{"docker-manifest-digest":"{signed}"}}}},"optional":{{}}}}]'"#
        ));
        let verifier = fixture.verifier_with_registry(script, access);
        let result = verifier
            .verify(
                "production",
                &fixture.policy(),
                &fixture.chain(SignedOciObject::Manifest),
            )
            .await;
        assert!(result.is_ok(), "{result:?}");
    }

    #[tokio::test]
    async fn public_and_cross_registry_requests_do_not_receive_auth() {
        let fixture = Fixture::new();
        let access = fixture
            .registry_access(r#"{"auths":{"private.example":{"identitytoken":"private-token"}}}"#);
        let script = fixture.success_script(fixture.manifest.digest, None);
        let guarded_script = {
            let contents = fs::read_to_string(&script).unwrap();
            let body = contents
                .strip_prefix("#!/usr/bin/env bash\nset -eu\n")
                .unwrap();
            fixture.executable(&format!("test -z \"${{DOCKER_CONFIG+x}}\"\n{body}"))
        };
        let verifier = fixture.verifier_with_registry(guarded_script, access);
        assert!(
            verifier
                .verify(
                    "production",
                    &fixture.policy(),
                    &fixture.chain(SignedOciObject::Manifest),
                )
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn registry_authentication_is_classified_from_redacted_diagnostics() {
        let fixture = Fixture::new();
        let cases = [
            Some(r#"{"auths":{"registry.example":{"identitytoken":"wrong-token"}}}"#),
            Some(r#"{"auths":{"other.example":{"identitytoken":"cross-token"}}}"#),
            None,
        ];
        for auth in cases {
            let verifier = auth.map_or_else(
                || {
                    fixture.verifier(
                        fixture.executable(
                            "printf 'GET https://registry.example/v2/: 401 Unauthorized' >&2; exit 1",
                        ),
                        Duration::from_secs(2),
                    )
                },
                |contents| {
                    let access = fixture.registry_access(contents);
                    fixture.verifier_with_registry(
                        fixture.executable(
                            "printf 'UNAUTHORIZED: authentication required' >&2; exit 1",
                        ),
                        access,
                    )
                },
            );
            let error = verifier
                .verify(
                    "production",
                    &fixture.policy(),
                    &fixture.chain(SignedOciObject::Manifest),
                )
                .await
                .unwrap_err();
            assert_eq!(error, OciVerificationError::Rejected);
            assert!(!format!("{error:?} {error}").contains("token"));
        }
    }

    #[tokio::test]
    async fn signature_and_network_failures_are_not_mislabeled_as_authentication() {
        let fixture = Fixture::new();
        let cases = [
            (
                "printf 'no matching signatures' >&2; exit 1",
                OciVerificationError::Rejected,
            ),
            (
                "printf 'dial tcp: connection refused' >&2; exit 1",
                OciVerificationError::Rejected,
            ),
            (
                "printf 'tls: failed to verify certificate' >&2; exit 1",
                OciVerificationError::Rejected,
            ),
        ];
        for (script, expected) in cases {
            let access = fixture.registry_access(
                r#"{"auths":{"registry.example":{"identitytoken":"private-token"}}}"#,
            );
            let verifier = fixture.verifier_with_registry(fixture.executable(script), access);
            assert_eq!(
                verifier
                    .verify(
                        "production",
                        &fixture.policy(),
                        &fixture.chain(SignedOciObject::Manifest),
                    )
                    .await,
                Err(expected)
            );
        }
    }

    #[tokio::test]
    async fn expired_registry_token_is_a_redacted_authentication_failure() {
        let fixture = Fixture::new();
        let access = fixture
            .registry_access(r#"{"auths":{"registry.example":{"identitytoken":"expired-token"}}}"#);
        let verifier = fixture.verifier_with_registry(
            fixture.executable(
                "printf 'UNAUTHORIZED: authentication required; token expired' >&2; exit 1",
            ),
            access,
        );
        let error = verifier
            .verify(
                "production",
                &fixture.policy(),
                &fixture.chain(SignedOciObject::Manifest),
            )
            .await
            .unwrap_err();
        assert_eq!(error, OciVerificationError::Rejected);
        assert!(!format!("{error:?} {error}").contains("expired-token"));
    }

    #[tokio::test]
    async fn restart_rotation_reloads_the_registry_credential_snapshot() {
        let fixture = Fixture::new();
        let path = fixture.root.join("rotated-auth.json");
        fs::write(
            &path,
            r#"{"auths":{"registry.example":{"identitytoken":"old-token"}}}"#,
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let old = RegistryAuthDocument::load_protected_file(&path).unwrap();
        fs::write(
            &path,
            r#"{"auths":{"registry.example":{"identitytoken":"new-token"}}}"#,
        )
        .unwrap();
        let new = RegistryAuthDocument::load_protected_file(&path).unwrap();
        let signed = fixture.manifest.digest;
        let script_body = format!(
            r#"config=$(<"$DOCKER_CONFIG/config.json")
case "$config" in
  *new-token*) printf '%s' '[{{"critical":{{"identity":{{"docker-reference":"registry.example/team/app"}},"image":{{"docker-manifest-digest":"{signed}"}}}},"optional":{{}}}}]' ;;
  *) printf 'UNAUTHORIZED: authentication required' >&2; exit 1 ;;
esac"#
        );
        let old_verifier = fixture.verifier_with_registry(
            fixture.executable(&script_body),
            RegistryAccess::with_document(Some(old), BTreeMap::new()).unwrap(),
        );
        assert_eq!(
            old_verifier
                .verify(
                    "production",
                    &fixture.policy(),
                    &fixture.chain(SignedOciObject::Manifest),
                )
                .await,
            Err(OciVerificationError::Rejected)
        );
        let new_verifier = fixture.verifier_with_registry(
            fixture.executable(&script_body),
            RegistryAccess::with_document(Some(new), BTreeMap::new()).unwrap(),
        );
        assert!(
            new_verifier
                .verify(
                    "production",
                    &fixture.policy(),
                    &fixture.chain(SignedOciObject::Manifest),
                )
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn exact_https_registry_preflight_classifies_auth_and_availability() {
        let fixture = Fixture::new();
        let registry = TlsRegistry::start().await;
        let repository = format!("{}/team/app", registry.authority);
        let digest = fixture.manifest.digest.to_string();
        let deadline = || Instant::now() + Duration::from_secs(2);

        assert!(
            RegistryAccess::default()
                .preflight("public.invalid/team/app", &digest, deadline())
                .await
                .is_ok()
        );

        registry.set_mode(RegistryMode::Public);
        let public = fixture.tls_registry_access(&registry.authority, None);
        assert!(
            public
                .preflight(&repository, &digest, deadline())
                .await
                .is_ok()
        );

        registry.set_mode(RegistryMode::RequireBearer("valid-token".to_string()));
        let valid = fixture.tls_registry_access(
            &registry.authority,
            Some((&registry.authority, "valid-token")),
        );
        assert!(
            valid
                .preflight(&repository, &digest, deadline())
                .await
                .is_ok()
        );
        for credential in [
            Some((&*registry.authority, "wrong-token")),
            Some(("other.example", "cross-token")),
            None,
        ] {
            let access = fixture.tls_registry_access(&registry.authority, credential);
            assert_eq!(
                access.preflight(&repository, &digest, deadline()).await,
                Err(RegistryIsolationError::Authentication)
            );
        }

        registry.set_mode(RegistryMode::RequireBearer("rotated-token".to_string()));
        assert_eq!(
            valid.preflight(&repository, &digest, deadline()).await,
            Err(RegistryIsolationError::Authentication)
        );
        let rotated = fixture.tls_registry_access(
            &registry.authority,
            Some((&registry.authority, "rotated-token")),
        );
        assert!(
            rotated
                .preflight(&repository, &digest, deadline())
                .await
                .is_ok()
        );

        for status in [429, 500, 503] {
            registry.set_mode(RegistryMode::Status(status));
            assert_eq!(
                rotated.preflight(&repository, &digest, deadline()).await,
                Err(RegistryIsolationError::Unavailable)
            );
        }
        let requests = registry.requests.lock().expect("registry requests");
        assert!(requests.iter().all(|request| {
            request.starts_with(&format!("HEAD /v2/team/app/manifests/{digest} "))
        }));
        drop(requests);
    }

    #[tokio::test]
    async fn production_verifier_uses_https_preflight_without_disclosure() {
        let fixture = Fixture::new();
        let registry = TlsRegistry::start().await;
        registry.set_mode(RegistryMode::RequireBearer("private-token".to_string()));
        let repository = format!("{}/team/app", registry.authority);
        let access = fixture.tls_registry_access(
            &registry.authority,
            Some((&registry.authority, "private-token")),
        );
        let marker = fixture.root.join("cosign-surfaces");
        let signed = fixture.manifest.digest;
        let script = fixture.executable(&format!(
            r#"test -z "${{HTTP_PROXY+x}}${{HTTPS_PROXY+x}}${{ALL_PROXY+x}}${{NO_PROXY+x}}"
printf '%s\n' "$*" "$DOCKER_CONFIG" > {}
printf '%s' '[{{"critical":{{"identity":{{"docker-reference":"{repository}"}},"image":{{"docker-manifest-digest":"{signed}"}}}},"optional":{{}}}}]'"#,
            marker.display()
        ));
        let policy = OciSignerPolicy {
            repository: repository.clone(),
            signer: OciSignerMode::PinnedKey {
                public_key: fixture.key.clone(),
                transparency: TransparencyPolicy::Required,
            },
        };
        let verifier = CosignVerifier::new(
            CosignConfig {
                executable: script,
                temp_parent: fixture.root.clone(),
                deadline: Duration::from_secs(2),
            },
            access,
        )
        .unwrap()
        .with_signer_policies(&BTreeMap::from([("production".to_owned(), policy.clone())]))
        .unwrap();
        let mut chain = fixture.chain(SignedOciObject::Manifest);
        chain.repository = repository;
        assert!(verifier.verify("production", &policy, &chain).await.is_ok());
        let surfaces = fs::read_to_string(marker).unwrap();
        assert!(!surfaces.contains("private-token"));
        assert!(!format!("{verifier:?}").contains("private-token"));
        assert!(fixture.root.read_dir().unwrap().flatten().all(|entry| {
            !entry
                .file_name()
                .to_string_lossy()
                .starts_with("basil-cosign-")
        }));
    }

    #[tokio::test]
    async fn exact_authority_ca_uses_private_cosign_argument() {
        let fixture = Fixture::new();
        let ca = fixture.root.join("registry-ca.pem");
        fs::write(&ca, include_str!("../../testdata/jwks_tls_cert.pem")).unwrap();
        fs::set_permissions(&ca, fs::Permissions::from_mode(0o600)).unwrap();
        let access = RegistryAccess::with_document(
            None,
            BTreeMap::from([("registry.example".to_string(), ca.clone())]),
        )
        .unwrap();
        let marker = fixture.root.join("argv");
        let success =
            fs::read_to_string(fixture.success_script(fixture.manifest.digest, None)).unwrap();
        let body = success
            .strip_prefix("#!/usr/bin/env bash\nset -eu\n")
            .unwrap();
        let script = fixture.executable(&format!(
            "printf '%s' \"$*\" > {}\n{body}",
            marker.display()
        ));
        let verifier = fixture.verifier_with_registry(script, access);
        verifier
            .verify(
                "production",
                &fixture.policy(),
                &fixture.chain(SignedOciObject::Manifest),
            )
            .await
            .unwrap();
        let argv = fs::read_to_string(marker).unwrap();
        assert!(argv.contains("--registry-ca-cert"));
        assert!(!argv.contains(ca.to_string_lossy().as_ref()));
        assert!(!argv.contains("--allow-insecure-registry"));
        assert!(!argv.contains("http://"));
    }

    #[tokio::test]
    async fn verifier_views_are_removed_after_success_and_failure() {
        let fixture = Fixture::new();
        for (script, expected_ok) in [
            (fixture.success_script(fixture.manifest.digest, None), true),
            (fixture.executable("exit 1"), false),
        ] {
            let verifier = fixture.verifier(script, Duration::from_secs(2));
            let result = verifier
                .verify(
                    "production",
                    &fixture.policy(),
                    &fixture.chain(SignedOciObject::Manifest),
                )
                .await;
            assert_eq!(result.is_ok(), expected_ok);
            let private_views = fs::read_dir(&fixture.root)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with("basil-cosign-")
                })
                .count();
            assert_eq!(private_views, 0);
        }
    }

    #[tokio::test]
    async fn successful_parent_exit_kills_descendant_holding_registry_view() {
        let fixture = Fixture::new();
        let (script, descendant) = fixture.exiting_parent_script(0);
        let access = fixture
            .registry_access(r#"{"auths":{"registry.example":{"identitytoken":"private-token"}}}"#);
        let verifier = fixture.verifier_with_registry(script, access);

        let result = verifier
            .verify(
                "production",
                &fixture.policy(),
                &fixture.chain(SignedOciObject::Manifest),
            )
            .await;

        assert!(result.is_ok(), "{result:?}");
        let raw = fs::read_to_string(descendant)
            .unwrap()
            .parse::<i32>()
            .unwrap();
        let pid = Pid::from_raw(raw).unwrap();
        assert_eq!(
            rustix::process::test_kill_process(pid),
            Err(rustix::io::Errno::SRCH)
        );
        assert!(fixture.root.read_dir().unwrap().flatten().all(|entry| {
            !entry
                .file_name()
                .to_string_lossy()
                .starts_with("basil-cosign-")
        }));
    }

    #[tokio::test]
    async fn failed_parent_exit_kills_descendant_holding_registry_view() {
        let fixture = Fixture::new();
        let (script, descendant) = fixture.exiting_parent_script(1);
        let access = fixture
            .registry_access(r#"{"auths":{"registry.example":{"identitytoken":"private-token"}}}"#);
        let verifier = fixture.verifier_with_registry(script, access);

        assert_eq!(
            verifier
                .verify(
                    "production",
                    &fixture.policy(),
                    &fixture.chain(SignedOciObject::Manifest),
                )
                .await,
            Err(OciVerificationError::Rejected)
        );
        let raw = fs::read_to_string(descendant)
            .unwrap()
            .parse::<i32>()
            .unwrap();
        let pid = Pid::from_raw(raw).unwrap();
        assert_eq!(
            rustix::process::test_kill_process(pid),
            Err(rustix::io::Errno::SRCH)
        );
        assert!(fixture.root.read_dir().unwrap().flatten().all(|entry| {
            !entry
                .file_name()
                .to_string_lossy()
                .starts_with("basil-cosign-")
        }));
    }

    #[tokio::test]
    async fn completed_child_cleanup_kills_group_before_reaping_leader() {
        let fixture = Fixture::new();
        let mut command = Command::new(fixture.executable("exit 0"));
        command
            .env_clear()
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .process_group(0);
        let child = command.spawn().unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let observer = ProcessLifecycleObserver::recording(Arc::clone(&events));

        let output = wait_bounded_inner(
            child,
            Duration::from_secs(2),
            MAX_COSIGN_STDOUT_BYTES,
            observer,
        )
        .await
        .unwrap();

        assert!(output.status.success());
        assert_eq!(
            *events.lock().unwrap(),
            [
                ProcessLifecycleEvent::ExitObservedWithoutReap,
                ProcessLifecycleEvent::GroupKillCompleted,
                ProcessLifecycleEvent::LeaderReaped,
                ProcessLifecycleEvent::GroupGone,
            ]
        );
    }

    #[test]
    fn startup_sweeps_only_safely_owned_stale_private_views() {
        let fixture = Fixture::new();
        let stale = fixture
            .root
            .join(format!("basil-cosign-2000000000-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&stale).unwrap();
        fs::set_permissions(&stale, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(stale.join("config.json"), "stale-secret").unwrap();
        let unsafe_stale = fixture
            .root
            .join(format!("basil-cosign-2000000000-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&unsafe_stale).unwrap();
        fs::set_permissions(&unsafe_stale, fs::Permissions::from_mode(0o755)).unwrap();
        let executable = fixture.executable("exit 1");
        let _verifier = fixture.verifier(executable, Duration::from_secs(2));
        assert!(!stale.exists());
        assert!(unsafe_stale.exists());
    }

    #[test]
    fn symlinked_temp_parent_and_excessive_entries_fail_closed() {
        let fixture = Fixture::new();
        let linked = fixture.root.with_file_name(format!(
            "basil-cosign-linked-parent-{}",
            uuid::Uuid::new_v4()
        ));
        std::os::unix::fs::symlink(&fixture.root, &linked).unwrap();
        let executable = fixture.executable("exit 1");
        assert!(matches!(
            CosignVerifier::for_public_registries(CosignConfig {
                executable: executable.clone(),
                temp_parent: linked.clone(),
                deadline: Duration::from_secs(2),
            }),
            Err(OciVerificationError::Configuration)
        ));
        fs::remove_file(linked).unwrap();

        for index in 0..=MAX_COSIGN_TEMP_ENTRIES {
            fs::write(fixture.root.join(format!("unrelated-{index}")), "x").unwrap();
        }
        assert!(matches!(
            CosignVerifier::for_public_registries(CosignConfig {
                executable,
                temp_parent: fixture.root.clone(),
                deadline: Duration::from_secs(2),
            }),
            Err(OciVerificationError::Configuration)
        ));
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
    fn protected_files_reject_writable_symlinked_and_foreign_owned_paths() {
        let fixture = Fixture::new();
        let writable = fixture.root.join("writable-ancestor");
        fs::create_dir(&writable).expect("create writable ancestor");
        fs::set_permissions(&writable, fs::Permissions::from_mode(0o777))
            .expect("make ancestor writable");
        let beneath_writable = writable.join("key.pub");
        fs::write(&beneath_writable, "key").expect("write key beneath writable ancestor");
        fs::set_permissions(&beneath_writable, fs::Permissions::from_mode(0o600))
            .expect("protect key leaf");
        assert_eq!(
            validate_protected_file(&beneath_writable),
            Err(OciVerificationError::Configuration)
        );

        let safe = fixture.root.join("safe-ancestor");
        fs::create_dir(&safe).expect("create safe ancestor");
        fs::set_permissions(&safe, fs::Permissions::from_mode(0o700))
            .expect("protect safe ancestor");
        let linked = fixture.root.join("linked-ancestor");
        std::os::unix::fs::symlink(&safe, &linked).expect("link ancestor");
        let beneath_link = linked.join("key.pub");
        fs::write(safe.join("key.pub"), "key").expect("write linked target key");
        fs::set_permissions(safe.join("key.pub"), fs::Permissions::from_mode(0o600))
            .expect("protect linked target key");
        assert_eq!(
            validate_protected_file(&beneath_link),
            Err(OciVerificationError::Configuration)
        );

        if rustix::process::geteuid().is_root() {
            let foreign = fixture.root.join("foreign-key.pub");
            fs::write(&foreign, "key").expect("write foreign key fixture");
            fs::set_permissions(&foreign, fs::Permissions::from_mode(0o600))
                .expect("protect foreign key fixture");
            std::os::unix::fs::chown(&foreign, Some(65_534), None).expect("assign foreign owner");
            assert_eq!(
                validate_protected_file(&foreign),
                Err(OciVerificationError::Configuration)
            );
        }
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
