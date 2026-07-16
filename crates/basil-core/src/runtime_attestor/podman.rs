// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::similar_names)]

//! Per-owner rootless Podman facts-only attestation provider.

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use futures::{StreamExt as _, stream};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde::{Deserialize, Deserializer};
use thiserror::Error;
use tokio::time::timeout;

use super::procfs::{LinuxProcfs, ProcError, ProcessFact, ProcessFactSource};
use super::{ProviderReply, RuntimeAttestorProvider};
use crate::attestor_protocol::{
    ABSOLUTE_MAX_ID_MAP_RANGES, ABSOLUTE_MAX_INSTANCES, ABSOLUTE_MAX_MOUNTS_PER_INSTANCE,
    ABSOLUTE_MAX_STRING_BYTES, MOUNT_SECURITY_CAPABILITY, QueryScope, wire,
};

const PODMAN_API_VERSION: &str = "5.0.0";
const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PODMAN_OBJECT_BYTES: usize = 1024 * 1024;
const MAX_PODMAN_LIST_BYTES: usize = 16 * 1024 * 1024;
const MAX_CONCURRENT_INSPECTS: usize = 32;
const COMPOSE_PROJECT: &str = "com.docker.compose.project";
const COMPOSE_SERVICE: &str = "com.docker.compose.service";
const COMPOSE_ONE_OFF: &str = "com.docker.compose.oneoff";
const COMPOSE_ORDINAL: &str = "com.docker.compose.container-number";

/// Rootless Podman provider construction failure.
#[derive(Debug, Error)]
pub enum PodmanAttestorConfigError {
    /// Realm name is empty, overlong, or contains a NUL byte.
    #[error("Podman attestor realm is invalid")]
    InvalidRealm,
    /// Rootless realms cannot be owned by host root.
    #[error("Podman attestor owner must be non-root")]
    RootOwner,
    /// The Podman socket path is not exact and absolute.
    #[error("Podman socket path is invalid")]
    InvalidSocketPath,
    /// The bounded Unix-socket HTTP client could not be built.
    #[error("Podman attestor HTTP client could not be built")]
    HttpClient(#[source] reqwest::Error),
}

/// Facts-only provider for one rootless Podman owner on Linux cgroup v2.
pub struct PodmanAttestor {
    realm: String,
    owner_uid: u32,
    owner_gid: u32,
    socket: PathBuf,
    api: Arc<dyn PodmanApi>,
    processes: Arc<dyn ProcessFactSource>,
    owner_scope: Arc<dyn OwnerScopeSource>,
    capabilities: Vec<String>,
}

impl PodmanAttestor {
    /// Construct a provider for one exact per-user Podman Unix socket.
    ///
    /// `owner_uid` and `owner_gid` are the resolved host credentials of the
    /// configured rootless runtime owner and attestor service.
    ///
    /// # Errors
    ///
    /// Returns [`PodmanAttestorConfigError`] for an invalid realm, owner, or
    /// socket path, or when the bounded HTTP client cannot be built.
    pub fn new(
        realm: impl Into<String>,
        owner_uid: u32,
        owner_gid: u32,
        socket: impl AsRef<Path>,
    ) -> Result<Self, PodmanAttestorConfigError> {
        let realm = realm.into();
        validate_realm(&realm)?;
        if owner_uid == 0 {
            return Err(PodmanAttestorConfigError::RootOwner);
        }
        validate_socket_path(socket.as_ref())?;
        let api = HttpPodmanApi::new(socket.as_ref())?;
        Ok(Self {
            realm,
            owner_uid,
            owner_gid,
            socket: socket.as_ref().to_path_buf(),
            api: Arc::new(api),
            processes: Arc::new(LinuxProcfs::default()),
            owner_scope: Arc::new(LinuxOwnerScope),
            capabilities: provider_capabilities(),
        })
    }

    #[cfg(test)]
    fn with_sources(
        realm: &str,
        owner_uid: u32,
        owner_gid: u32,
        api: Arc<dyn PodmanApi>,
        processes: Arc<dyn ProcessFactSource>,
        owner_scope: Arc<dyn OwnerScopeSource>,
    ) -> Self {
        Self {
            realm: realm.to_string(),
            owner_uid,
            owner_gid,
            socket: PathBuf::from("/run/user/1000/podman/podman.sock"),
            api,
            processes,
            owner_scope,
            capabilities: provider_capabilities(),
        }
    }

    async fn supported_environment(&self) -> Result<PodmanProbe, ProviderFailure> {
        self.owner_scope
            .verify(self.owner_uid, self.owner_gid, &self.socket)?;
        let info = self.api.info().await.map_err(ProviderFailure::from)?;
        if !version_at_least(&info.version.api_version, PODMAN_API_VERSION)
            || !info.host.security.rootless
            || !matches!(info.host.cgroup_version.as_str(), "2" | "v2")
            || !info.host.remote_socket.exists
            || info.host.remote_socket.path != expected_socket_uri(&self.socket)?
        {
            return Err(ProviderFailure::Unsupported);
        }
        let uid_map = normalize_runtime_map(&info.host.id_mappings.uidmap)?;
        let gid_map = normalize_runtime_map(&info.host.id_mappings.gidmap)?;
        require_owner_maps(&uid_map, &gid_map, self.owner_uid, self.owner_gid)?;
        Ok(PodmanProbe {
            version: info.version.version,
            uid_map,
            gid_map,
        })
    }

    async fn resolve_inner(
        &self,
        constraints: &wire::PinnedPeer,
    ) -> Result<wire::InstanceFact, ProviderFailure> {
        // The owner-map prefilter deliberately precedes every Podman request.
        // A foreign or host-namespaced PID must not amplify into an API call in
        // another rootless owner's realm.
        let observed = self
            .processes
            .observe(constraints.pid)
            .map_err(|_| ProviderFailure::Changed)?;
        if observed.peer != *constraints {
            return Err(ProviderFailure::Changed);
        }
        if !has_owner_maps(&observed, self.owner_uid, self.owner_gid) {
            return Err(ProviderFailure::NoMatch);
        }
        let probe = self.supported_environment().await?;
        require_probe_maps(&observed, &probe)?;

        let hints = podman_id_hints(&observed.peer.cgroup);
        let [id] = hints.as_slice() else {
            return Err(if hints.is_empty() {
                ProviderFailure::NoMatch
            } else {
                ProviderFailure::MultipleMatches
            });
        };
        self.resolve_candidate(id, &observed, &probe).await
    }

    async fn resolve_candidate(
        &self,
        id: &str,
        observed_peer: &ProcessFact,
        probe: &PodmanProbe,
    ) -> Result<wire::InstanceFact, ProviderFailure> {
        let before = self.inspect_candidate(id).await?;
        validate_instance_id(&before.id)?;
        if before.id != id || !is_running(&before.state) {
            return Err(ProviderFailure::Changed);
        }
        let init_pid = running_pid(&before.state)?;
        let observed_init = self
            .processes
            .observe(init_pid)
            .map_err(|_| ProviderFailure::Changed)?;
        require_probe_maps(&observed_init, probe)?;
        if !cgroup_is_same_or_descendant(&observed_peer.peer.cgroup, &observed_init.peer.cgroup)
            || observed_peer.peer.namespaces != observed_init.peer.namespaces
        {
            return Err(ProviderFailure::NoMatch);
        }
        let image = match self.api.inspect_image(&before.image).await {
            Ok(image) => image,
            Err(PodmanApiError::NotFound) => return Err(ProviderFailure::Changed),
            Err(error) => return Err(error.into()),
        };
        let after = self.inspect_candidate(id).await?;
        if before != after {
            return Err(ProviderFailure::Changed);
        }
        let final_peer = self
            .processes
            .observe(observed_peer.peer.pid)
            .map_err(|_| ProviderFailure::Changed)?;
        let final_init = self
            .processes
            .observe(init_pid)
            .map_err(|_| ProviderFailure::Changed)?;
        if final_peer != *observed_peer || final_init != observed_init {
            return Err(ProviderFailure::Changed);
        }
        require_probe_maps(&final_peer, probe)?;
        require_probe_maps(&final_init, probe)?;
        normalize_instance(&self.realm, &after, &image, final_peer)
    }

    async fn inspect_candidate(&self, id: &str) -> Result<ContainerInspect, ProviderFailure> {
        match self.api.inspect_container(id).await {
            Ok(container) => Ok(container),
            Err(PodmanApiError::NotFound) => Err(ProviderFailure::Changed),
            Err(error) => Err(error.into()),
        }
    }

    async fn query_inner(
        &self,
        scope: &QueryScope,
    ) -> Result<Vec<wire::InstanceFact>, ProviderFailure> {
        let probe = self.supported_environment().await?;
        let filters = match scope {
            QueryScope::InstanceId(id) => {
                validate_instance_id(id)?;
                PodmanFilters::running().with_id(id)
            }
            QueryScope::Project { realm, project } => {
                self.require_query_realm(realm)?;
                PodmanFilters::running().with_label(COMPOSE_PROJECT, project)?
            }
            QueryScope::Service {
                realm,
                project,
                service,
            } => {
                self.require_query_realm(realm)?;
                PodmanFilters::running()
                    .with_label(COMPOSE_PROJECT, project)?
                    .with_label(COMPOSE_SERVICE, service)?
            }
            QueryScope::GlobalDoctor => PodmanFilters::running(),
        };
        let ids = self.list_candidate_ids(&filters).await?;
        let results = stream::iter(ids.into_iter().map(|id| {
            let probe = &probe;
            async move { self.inventory_candidate(&id, probe).await }
        }))
        .buffer_unordered(MAX_CONCURRENT_INSPECTS)
        .collect::<Vec<_>>()
        .await;
        let mut instances = results
            .into_iter()
            .collect::<Result<Vec<_>, ProviderFailure>>()?;
        instances.sort_by(|left, right| left.instance_id.cmp(&right.instance_id));
        Ok(instances)
    }

    async fn inventory_candidate(
        &self,
        id: &str,
        probe: &PodmanProbe,
    ) -> Result<wire::InstanceFact, ProviderFailure> {
        let before = self.inspect_candidate(id).await?;
        if before.id != id || !is_running(&before.state) {
            return Err(ProviderFailure::Changed);
        }
        let init_pid = running_pid(&before.state)?;
        let process = self
            .processes
            .observe(init_pid)
            .map_err(|_| ProviderFailure::Changed)?;
        require_probe_maps(&process, probe)?;
        let image = match self.api.inspect_image(&before.image).await {
            Ok(image) => image,
            Err(PodmanApiError::NotFound) => return Err(ProviderFailure::Changed),
            Err(error) => return Err(error.into()),
        };
        let after = self.inspect_candidate(id).await?;
        if before != after {
            return Err(ProviderFailure::Changed);
        }
        let final_process = self
            .processes
            .observe(init_pid)
            .map_err(|_| ProviderFailure::Changed)?;
        if final_process != process {
            return Err(ProviderFailure::Changed);
        }
        require_probe_maps(&final_process, probe)?;
        normalize_instance(&self.realm, &after, &image, final_process)
    }

    async fn list_candidate_ids(
        &self,
        filters: &PodmanFilters,
    ) -> Result<Vec<String>, ProviderFailure> {
        let summaries = self
            .api
            .list_containers(filters)
            .await
            .map_err(ProviderFailure::from)?;
        if summaries.len() > ABSOLUTE_MAX_INSTANCES {
            return Err(ProviderFailure::ResourceExhausted);
        }
        let mut ids = summaries
            .into_iter()
            .map(|summary| {
                validate_instance_id(&summary.id)?;
                Ok(summary.id)
            })
            .collect::<Result<Vec<_>, ProviderFailure>>()?;
        ids.sort();
        ids.dedup();
        Ok(ids)
    }

    fn require_query_realm(&self, realm: &str) -> Result<(), ProviderFailure> {
        if realm == self.realm {
            Ok(())
        } else {
            Err(ProviderFailure::InvalidRequest)
        }
    }
}

#[async_trait]
impl RuntimeAttestorProvider for PodmanAttestor {
    fn capabilities(&self) -> &[String] {
        &self.capabilities
    }

    async fn health(&self, budget: Duration) -> ProviderReply<wire::HealthFact> {
        match timeout(effective_budget(budget), self.supported_environment()).await {
            Ok(Ok(probe)) => ProviderReply::success(wire::HealthFact {
                runtime: wire::RuntimeKind::Podman as i32,
                diagnostic_version: bounded_diagnostic_version(&probe.version),
                runtime_mode: wire::RuntimeMode::Rootless as i32,
                cgroup_mode: wire::CgroupMode::V2 as i32,
                ready: true,
                missing_capabilities: Vec::new(),
            }),
            Ok(Err(error)) => error.reply(),
            Err(_) => ProviderFailure::DeadlineExceeded.reply(),
        }
    }

    async fn resolve_peer(
        &self,
        peer: &wire::PinnedPeer,
        budget: Duration,
    ) -> ProviderReply<wire::InstanceFact> {
        match timeout(effective_budget(budget), self.resolve_inner(peer)).await {
            Ok(Ok(instance)) => ProviderReply::success(instance),
            Ok(Err(error)) => error.reply(),
            Err(_) => ProviderFailure::DeadlineExceeded.reply(),
        }
    }

    async fn query_instances(
        &self,
        scope: &QueryScope,
        budget: Duration,
    ) -> ProviderReply<Vec<wire::InstanceFact>> {
        match timeout(effective_budget(budget), self.query_inner(scope)).await {
            Ok(Ok(instances)) => ProviderReply::success(instances),
            Ok(Err(error)) => error.reply(),
            Err(_) => ProviderFailure::DeadlineExceeded.reply(),
        }
    }
}

fn provider_capabilities() -> Vec<String> {
    [
        "health",
        MOUNT_SECURITY_CAPABILITY,
        "podman.rootless-owner",
        "query-instances",
        "resolve-peer",
    ]
    .map(str::to_string)
    .to_vec()
}

fn effective_budget(budget: Duration) -> Duration {
    budget.min(OPERATION_TIMEOUT)
}

fn validate_realm(realm: &str) -> Result<(), PodmanAttestorConfigError> {
    if realm.is_empty() || realm.len() > ABSOLUTE_MAX_STRING_BYTES || realm.contains('\0') {
        Err(PodmanAttestorConfigError::InvalidRealm)
    } else {
        Ok(())
    }
}

fn validate_socket_path(socket: &Path) -> Result<(), PodmanAttestorConfigError> {
    let Some(value) = socket.to_str() else {
        return Err(PodmanAttestorConfigError::InvalidSocketPath);
    };
    let components_are_normal = value.split('/').enumerate().all(|(index, component)| {
        (index == 0 && component.is_empty())
            || (index > 0 && !component.is_empty() && component != "." && component != "..")
    });
    if socket.is_absolute()
        && value.len() <= ABSOLUTE_MAX_STRING_BYTES
        && !value.contains('\0')
        && components_are_normal
    {
        return Ok(());
    }
    Err(PodmanAttestorConfigError::InvalidSocketPath)
}

#[derive(Clone, Debug)]
struct PodmanProbe {
    version: String,
    uid_map: Vec<wire::IdMapRange>,
    gid_map: Vec<wire::IdMapRange>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProviderFailure {
    NoMatch,
    MultipleMatches,
    Changed,
    Unavailable,
    ResourceExhausted,
    DeadlineExceeded,
    InvalidRequest,
    Unsupported,
    Invariant,
    NotFound,
}

impl ProviderFailure {
    fn reply<T>(self) -> ProviderReply<T> {
        let (code, diagnostic) = match self {
            Self::NoMatch | Self::NotFound => (wire::OutcomeCode::NoMatch, "no runtime match"),
            Self::MultipleMatches => (
                wire::OutcomeCode::MultipleMatches,
                "multiple runtime matches",
            ),
            Self::Changed => (
                wire::OutcomeCode::ChangedDuringRead,
                "runtime evidence changed during read",
            ),
            Self::Unavailable => (wire::OutcomeCode::Unavailable, "Podman runtime unavailable"),
            Self::ResourceExhausted => (
                wire::OutcomeCode::ResourceExhausted,
                "Podman evidence exceeds compiled bound",
            ),
            Self::DeadlineExceeded => (
                wire::OutcomeCode::DeadlineExceeded,
                "Podman evidence deadline exceeded",
            ),
            Self::InvalidRequest => (
                wire::OutcomeCode::InvalidRequest,
                "invalid Podman query scope",
            ),
            Self::Unsupported => (
                wire::OutcomeCode::InvalidRequest,
                "unsupported Podman runtime mode or owner scope",
            ),
            Self::Invariant => (
                wire::OutcomeCode::InvariantFailure,
                "invalid Podman runtime evidence",
            ),
        };
        ProviderReply::failure(code, diagnostic)
    }
}

impl From<ProcError> for ProviderFailure {
    fn from(error: ProcError) -> Self {
        match error {
            ProcError::Unavailable => Self::Unavailable,
            ProcError::Changed => Self::Changed,
            ProcError::Unsupported => Self::Unsupported,
        }
    }
}

impl From<PodmanApiError> for ProviderFailure {
    fn from(error: PodmanApiError) -> Self {
        match error {
            PodmanApiError::Unavailable => Self::Unavailable,
            PodmanApiError::ResourceExhausted => Self::ResourceExhausted,
            PodmanApiError::Invariant => Self::Invariant,
            PodmanApiError::NotFound => Self::NotFound,
        }
    }
}

#[derive(Clone, Debug, Default)]
struct PodmanFilters(BTreeMap<String, Vec<String>>);

impl PodmanFilters {
    fn running() -> Self {
        let mut filters = BTreeMap::new();
        filters.insert("status".to_string(), vec!["running".to_string()]);
        Self(filters)
    }

    fn with_id(mut self, id: &str) -> Self {
        self.0.insert("id".to_string(), vec![id.to_string()]);
        self
    }

    fn with_label(mut self, key: &str, value: &str) -> Result<Self, ProviderFailure> {
        validate_bounded(value)?;
        self.0
            .entry("label".to_string())
            .or_default()
            .push(format!("{key}={value}"));
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PodmanApiError {
    Unavailable,
    ResourceExhausted,
    Invariant,
    NotFound,
}

#[async_trait]
trait PodmanApi: Send + Sync {
    async fn info(&self) -> Result<PodmanInfo, PodmanApiError>;
    async fn list_containers(
        &self,
        filters: &PodmanFilters,
    ) -> Result<Vec<ContainerSummary>, PodmanApiError>;
    async fn inspect_container(&self, id: &str) -> Result<ContainerInspect, PodmanApiError>;
    async fn inspect_image(&self, id: &str) -> Result<ImageInspect, PodmanApiError>;
}

struct HttpPodmanApi {
    client: reqwest::Client,
}

impl HttpPodmanApi {
    fn new(socket: &Path) -> Result<Self, PodmanAttestorConfigError> {
        crate::ensure_crypto_provider();
        let client = reqwest::Client::builder()
            .unix_socket(socket)
            .timeout(HTTP_REQUEST_TIMEOUT)
            .no_proxy()
            .build()
            .map_err(PodmanAttestorConfigError::HttpClient)?;
        Ok(Self { client })
    }

    async fn get<T>(&self, path: &str, maximum: usize) -> Result<T, PodmanApiError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let mut response = self
            .client
            .get(format!("http://localhost{path}"))
            .send()
            .await
            .map_err(|_| PodmanApiError::Unavailable)?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(PodmanApiError::NotFound);
        }
        if !response.status().is_success() {
            return Err(PodmanApiError::Unavailable);
        }
        if response
            .content_length()
            .is_some_and(|length| length > maximum as u64)
        {
            return Err(PodmanApiError::ResourceExhausted);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| PodmanApiError::Unavailable)?
        {
            if bytes
                .len()
                .checked_add(chunk.len())
                .is_none_or(|length| length > maximum)
            {
                return Err(PodmanApiError::ResourceExhausted);
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).map_err(|_| PodmanApiError::Invariant)
    }
}

#[async_trait]
impl PodmanApi for HttpPodmanApi {
    async fn info(&self) -> Result<PodmanInfo, PodmanApiError> {
        self.get(
            &format!("/v{PODMAN_API_VERSION}/libpod/info"),
            MAX_PODMAN_OBJECT_BYTES,
        )
        .await
    }

    async fn list_containers(
        &self,
        filters: &PodmanFilters,
    ) -> Result<Vec<ContainerSummary>, PodmanApiError> {
        let encoded_filters =
            serde_json::to_string(&filters.0).map_err(|_| PodmanApiError::Invariant)?;
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("all", "false")
            .append_pair("filters", &encoded_filters)
            .finish();
        self.get(
            &format!("/v{PODMAN_API_VERSION}/libpod/containers/json?{query}"),
            MAX_PODMAN_LIST_BYTES,
        )
        .await
    }

    async fn inspect_container(&self, id: &str) -> Result<ContainerInspect, PodmanApiError> {
        let id = utf8_percent_encode(id, NON_ALPHANUMERIC);
        self.get(
            &format!("/v{PODMAN_API_VERSION}/libpod/containers/{id}/json"),
            MAX_PODMAN_OBJECT_BYTES,
        )
        .await
    }

    async fn inspect_image(&self, id: &str) -> Result<ImageInspect, PodmanApiError> {
        let id = utf8_percent_encode(id, NON_ALPHANUMERIC);
        self.get(
            &format!("/v{PODMAN_API_VERSION}/libpod/images/{id}/json"),
            MAX_PODMAN_OBJECT_BYTES,
        )
        .await
    }
}

trait OwnerScopeSource: Send + Sync {
    fn verify(&self, owner_uid: u32, owner_gid: u32, socket: &Path) -> Result<(), ProviderFailure>;
}

struct LinuxOwnerScope;

impl OwnerScopeSource for LinuxOwnerScope {
    fn verify(&self, owner_uid: u32, owner_gid: u32, socket: &Path) -> Result<(), ProviderFailure> {
        if rustix::process::geteuid().as_raw() != owner_uid
            || rustix::process::getegid().as_raw() != owner_gid
        {
            return Err(ProviderFailure::Unsupported);
        }
        let metadata =
            std::fs::symlink_metadata(socket).map_err(|_| ProviderFailure::Unavailable)?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != owner_uid
            || metadata.gid() != owner_gid
            || metadata.mode() & 0o007 != 0
        {
            return Err(ProviderFailure::Unsupported);
        }
        let mut ancestors = socket
            .parent()
            .ok_or(ProviderFailure::Unsupported)?
            .ancestors()
            .collect::<Vec<_>>();
        ancestors.reverse();
        for ancestor in ancestors {
            let metadata =
                std::fs::symlink_metadata(ancestor).map_err(|_| ProviderFailure::Unavailable)?;
            let ancestor_uid = metadata.uid();
            if !metadata.file_type().is_dir()
                || (ancestor_uid != 0 && ancestor_uid != owner_uid)
                || metadata.mode() & 0o022 != 0
            {
                return Err(ProviderFailure::Unsupported);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct PodmanInfo {
    host: PodmanHost,
    version: PodmanVersion,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
struct PodmanHost {
    cgroup_version: String,
    security: PodmanSecurity,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    id_mappings: PodmanIdMappings,
    remote_socket: PodmanRemoteSocket,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct PodmanSecurity {
    rootless: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
struct PodmanIdMappings {
    #[serde(default, deserialize_with = "deserialize_null_default")]
    uidmap: Vec<PodmanIdMapRange>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    gidmap: Vec<PodmanIdMapRange>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct PodmanIdMapRange {
    container_id: u64,
    host_id: u64,
    size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct PodmanRemoteSocket {
    path: String,
    exists: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct PodmanVersion {
    #[serde(rename = "APIVersion")]
    api_version: String,
    version: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct ContainerSummary {
    id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct ContainerInspect {
    id: String,
    name: String,
    image: String,
    state: ContainerState,
    #[serde(default)]
    config: ContainerConfig,
    #[serde(default)]
    host_config: HostConfig,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    mounts: Vec<MountPoint>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct ContainerState {
    pid: i64,
    status: String,
    running: bool,
    paused: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct ContainerConfig {
    #[serde(default, deserialize_with = "deserialize_null_default")]
    labels: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct HostConfig {
    #[serde(default, deserialize_with = "deserialize_null_default")]
    tmpfs: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct MountPoint {
    #[serde(rename = "Type")]
    kind: String,
    #[serde(default)]
    source: String,
    destination: String,
    #[serde(rename = "RW")]
    writable: bool,
    #[serde(default)]
    propagation: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct ImageInspect {
    id: String,
    digest: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    repo_digests: Vec<String>,
    os: String,
    architecture: String,
    variant: Option<String>,
}

fn deserialize_null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

fn normalize_instance(
    realm: &str,
    container: &ContainerInspect,
    image: &ImageInspect,
    process: ProcessFact,
) -> Result<wire::InstanceFact, ProviderFailure> {
    validate_instance_id(&container.id)?;
    if normalize_config_digest(&container.image)? != normalize_config_digest(&image.id)? {
        return Err(ProviderFailure::Changed);
    }
    let observed_unix_millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .filter(|millis| *millis != 0)
        .ok_or(ProviderFailure::Invariant)?;
    let name = container.name.strip_prefix('/').unwrap_or(&container.name);
    validate_bounded(name)?;
    Ok(wire::InstanceFact {
        provenance: Some(wire::FactBinding {
            session: None,
            realm: realm.to_string(),
            provider: wire::RuntimeKind::Podman as i32,
            observed_unix_millis,
        }),
        runtime: wire::RuntimeKind::Podman as i32,
        instance_id: container.id.clone(),
        observed_peer: Some(process.peer),
        uid_map: process.uid_map,
        gid_map: process.gid_map,
        compose: normalize_compose(&container.config.labels)?,
        image: Some(normalize_image(image)?),
        mounts: normalize_mounts(container)?,
        lifecycle: normalize_lifecycle(&container.state)? as i32,
        diagnostic_runtime_name: name.to_string(),
    })
}

fn normalize_compose(
    labels: &BTreeMap<String, String>,
) -> Result<Option<wire::ComposeFact>, ProviderFailure> {
    match (labels.get(COMPOSE_PROJECT), labels.get(COMPOSE_SERVICE)) {
        (None, None) => Ok(None),
        (Some(project), Some(service)) => {
            validate_bounded(project)?;
            validate_bounded(service)?;
            let one_off = labels
                .get(COMPOSE_ONE_OFF)
                .ok_or(ProviderFailure::Invariant)
                .and_then(|value| parse_bool(value))?;
            let replica_ordinal = labels
                .get(COMPOSE_ORDINAL)
                .map(|value| {
                    value
                        .parse::<u32>()
                        .ok()
                        .filter(|ordinal| *ordinal != 0)
                        .ok_or(ProviderFailure::Invariant)
                })
                .transpose()?;
            Ok(Some(wire::ComposeFact {
                project: project.clone(),
                service: service.clone(),
                one_off,
                replica_ordinal,
            }))
        }
        _ => Err(ProviderFailure::Invariant),
    }
}

fn normalize_image(image: &ImageInspect) -> Result<wire::ImageFact, ProviderFailure> {
    let config_digest = normalize_config_digest(&image.id)?;
    validate_sha256(&image.digest)?;
    let mut repository_digests = image
        .repo_digests
        .iter()
        .map(|value| {
            let (_, digest) = value.rsplit_once('@').ok_or(ProviderFailure::Invariant)?;
            validate_sha256(digest)?;
            Ok(digest.to_string())
        })
        .collect::<Result<BTreeSet<_>, ProviderFailure>>()?;
    repository_digests.remove(&image.digest);
    let index_digest = match repository_digests.len() {
        0 => None,
        1 => repository_digests.pop_first(),
        _ => return Err(ProviderFailure::Invariant),
    };
    validate_bounded(&image.os)?;
    validate_bounded(&image.architecture)?;
    if let Some(variant) = &image.variant {
        validate_bounded(variant)?;
    }
    Ok(wire::ImageFact {
        index_digest,
        manifest_digest: image.digest.clone(),
        config_digest,
        os: image.os.clone(),
        architecture: image.architecture.clone(),
        variant: image.variant.clone(),
    })
}

fn normalize_mounts(container: &ContainerInspect) -> Result<Vec<wire::MountFact>, ProviderFailure> {
    if container.mounts.len() > ABSOLUTE_MAX_MOUNTS_PER_INSTANCE
        || container.host_config.tmpfs.len() > ABSOLUTE_MAX_MOUNTS_PER_INSTANCE
    {
        return Err(ProviderFailure::ResourceExhausted);
    }
    let mut mounts = container
        .mounts
        .iter()
        .map(|mount| normalize_mount(mount, &container.host_config))
        .collect::<Result<Vec<_>, _>>()?;
    let runtime_destinations = container
        .mounts
        .iter()
        .map(|mount| mount.destination.as_str())
        .collect::<BTreeSet<_>>();
    for (destination, options) in &container.host_config.tmpfs {
        if !runtime_destinations.contains(destination.as_str()) {
            mounts.push(normalize_tmpfs(destination, options, false)?);
        }
    }
    if mounts.len() > ABSOLUTE_MAX_MOUNTS_PER_INSTANCE {
        return Err(ProviderFailure::ResourceExhausted);
    }
    mounts.sort_by(|left, right| {
        left.container_destination
            .cmp(&right.container_destination)
            .then_with(|| left.host_source.cmp(&right.host_source))
    });
    if mounts.windows(2).any(
        |pair| matches!(pair, [left, right] if left.container_destination == right.container_destination),
    ) {
        return Err(ProviderFailure::Invariant);
    }
    Ok(mounts)
}

fn normalize_mount(
    mount: &MountPoint,
    host_config: &HostConfig,
) -> Result<wire::MountFact, ProviderFailure> {
    validate_bounded(&mount.destination)?;
    let kind = match mount.kind.as_str() {
        "bind" => wire::MountKind::Bind,
        "volume" => wire::MountKind::Volume,
        "tmpfs" => wire::MountKind::Tmpfs,
        _ => return Err(ProviderFailure::Invariant),
    };
    if kind != wire::MountKind::Tmpfs {
        validate_bounded(&mount.source)?;
    } else if !mount.source.is_empty() {
        return Err(ProviderFailure::Invariant);
    }
    let propagation = match mount.propagation.as_str() {
        "" | "private" => wire::MountPropagation::Private,
        "rprivate" => wire::MountPropagation::Rprivate,
        "shared" => wire::MountPropagation::Shared,
        "rshared" => wire::MountPropagation::Rshared,
        "slave" => wire::MountPropagation::Slave,
        "rslave" => wire::MountPropagation::Rslave,
        _ => return Err(ProviderFailure::Invariant),
    };
    if kind == wire::MountKind::Tmpfs {
        let options = host_config
            .tmpfs
            .get(&mount.destination)
            .ok_or(ProviderFailure::Invariant)?;
        return normalize_tmpfs(&mount.destination, options, !mount.writable);
    }
    Ok(wire::MountFact {
        kind: kind as i32,
        host_source: mount.source.clone(),
        container_destination: mount.destination.clone(),
        read_only: !mount.writable,
        propagation: propagation as i32,
        tmpfs_size_bytes: None,
        tmpfs_mode: None,
        tmpfs_nodev: false,
        tmpfs_nosuid: false,
        tmpfs_noexec: false,
        tmpfs_noswap: false,
    })
}

fn normalize_tmpfs(
    destination: &str,
    options: &str,
    observed_read_only: bool,
) -> Result<wire::MountFact, ProviderFailure> {
    validate_bounded(destination)?;
    let projection = parse_tmpfs_options(options)?;
    if projection
        .read_only
        .is_some_and(|configured| configured != observed_read_only)
    {
        return Err(ProviderFailure::Invariant);
    }
    Ok(wire::MountFact {
        kind: wire::MountKind::Tmpfs as i32,
        host_source: String::new(),
        container_destination: destination.to_string(),
        read_only: projection.read_only.unwrap_or(observed_read_only),
        propagation: wire::MountPropagation::Private as i32,
        tmpfs_size_bytes: projection.size_bytes,
        tmpfs_mode: projection.mode,
        tmpfs_nodev: projection.nodev,
        tmpfs_nosuid: projection.nosuid,
        tmpfs_noexec: projection.noexec,
        tmpfs_noswap: projection.noswap,
    })
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
struct TmpfsProjection {
    size_bytes: Option<u64>,
    mode: Option<u32>,
    read_only: Option<bool>,
    nodev: bool,
    nosuid: bool,
    noexec: bool,
    noswap: bool,
}

fn parse_tmpfs_options(options: &str) -> Result<TmpfsProjection, ProviderFailure> {
    if options.len() > ABSOLUTE_MAX_STRING_BYTES || options.contains('\0') {
        return Err(ProviderFailure::ResourceExhausted);
    }
    let mut result = TmpfsProjection::default();
    for option in options.split(',').filter(|option| !option.is_empty()) {
        if let Some(value) = option.strip_prefix("size=") {
            if result.size_bytes.replace(parse_size(value)?).is_some() {
                return Err(ProviderFailure::Invariant);
            }
        } else if let Some(value) = option.strip_prefix("mode=") {
            if result.mode.replace(parse_mode(value)?).is_some() {
                return Err(ProviderFailure::Invariant);
            }
        } else if matches!(option, "ro" | "rw") {
            if result.read_only.replace(option == "ro").is_some() {
                return Err(ProviderFailure::Invariant);
            }
        } else {
            let slot = match option {
                "nodev" => &mut result.nodev,
                "nosuid" => &mut result.nosuid,
                "noexec" => &mut result.noexec,
                "noswap" => &mut result.noswap,
                "dev" | "suid" | "exec" | "swap" => {
                    return Err(ProviderFailure::Invariant);
                }
                _ => continue,
            };
            if std::mem::replace(slot, true) {
                return Err(ProviderFailure::Invariant);
            }
        }
    }
    Ok(result)
}

fn parse_size(value: &str) -> Result<u64, ProviderFailure> {
    let split = value
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(value.len());
    let (number, suffix) = value.split_at(split);
    let number = number
        .parse::<u64>()
        .ok()
        .filter(|number| *number != 0)
        .ok_or(ProviderFailure::Invariant)?;
    let multiplier = match suffix.to_ascii_lowercase().as_str() {
        "" => 1,
        "k" | "kb" => 1024,
        "m" | "mb" => 1024 * 1024,
        "g" | "gb" => 1024 * 1024 * 1024,
        _ => return Err(ProviderFailure::Invariant),
    };
    number
        .checked_mul(multiplier)
        .ok_or(ProviderFailure::ResourceExhausted)
}

fn parse_mode(value: &str) -> Result<u32, ProviderFailure> {
    u32::from_str_radix(value, 8)
        .ok()
        .filter(|mode| *mode <= 0o7777)
        .ok_or(ProviderFailure::Invariant)
}

fn normalize_lifecycle(state: &ContainerState) -> Result<wire::LifecycleState, ProviderFailure> {
    match state.status.as_str() {
        "created" | "configured" | "restarting" => Ok(wire::LifecycleState::Created),
        "running" if state.paused => Ok(wire::LifecycleState::Paused),
        "running" => Ok(wire::LifecycleState::Running),
        "paused" => Ok(wire::LifecycleState::Paused),
        "exited" | "stopped" | "dead" | "removing" => Ok(wire::LifecycleState::Exited),
        _ => Err(ProviderFailure::Invariant),
    }
}

fn is_running(state: &ContainerState) -> bool {
    state.running && matches!(state.status.as_str(), "running" | "paused")
}

fn running_pid(state: &ContainerState) -> Result<u32, ProviderFailure> {
    if !is_running(state) {
        return Err(ProviderFailure::Changed);
    }
    u32::try_from(state.pid)
        .ok()
        .filter(|pid| *pid != 0)
        .ok_or(ProviderFailure::Invariant)
}

fn normalize_runtime_map(
    ranges: &[PodmanIdMapRange],
) -> Result<Vec<wire::IdMapRange>, ProviderFailure> {
    if ranges.is_empty() || ranges.len() > ABSOLUTE_MAX_ID_MAP_RANGES {
        return Err(ProviderFailure::Unsupported);
    }
    let mut normalized = ranges
        .iter()
        .map(|range| {
            let inside_id =
                u32::try_from(range.container_id).map_err(|_| ProviderFailure::Unsupported)?;
            let outside_id =
                u32::try_from(range.host_id).map_err(|_| ProviderFailure::Unsupported)?;
            let length = u32::try_from(range.size)
                .ok()
                .filter(|length| *length != 0)
                .ok_or(ProviderFailure::Unsupported)?;
            if u64::from(inside_id) + u64::from(length) > u64::from(u32::MAX) + 1
                || u64::from(outside_id) + u64::from(length) > u64::from(u32::MAX) + 1
            {
                return Err(ProviderFailure::Unsupported);
            }
            Ok(wire::IdMapRange {
                inside_id,
                outside_id,
                length,
            })
        })
        .collect::<Result<Vec<_>, ProviderFailure>>()?;
    normalized.sort_by_key(|range| range.inside_id);
    if normalized.iter().enumerate().any(|(index, left)| {
        normalized.iter().skip(index + 1).any(|right| {
            overlaps(left.inside_id, left.length, right.inside_id, right.length)
                || overlaps(left.outside_id, left.length, right.outside_id, right.length)
        })
    }) {
        return Err(ProviderFailure::Unsupported);
    }
    Ok(normalized)
}

fn overlaps(first: u32, first_len: u32, second: u32, second_len: u32) -> bool {
    let first_start = u64::from(first);
    let first_end = first_start + u64::from(first_len);
    let second_start = u64::from(second);
    let second_end = second_start + u64::from(second_len);
    first_start < second_end && second_start < first_end
}

fn require_owner_maps(
    uid_map: &[wire::IdMapRange],
    gid_map: &[wire::IdMapRange],
    owner_uid: u32,
    owner_gid: u32,
) -> Result<(), ProviderFailure> {
    let maps_root = |ranges: &[wire::IdMapRange], owner| matches!(ranges.first(), Some(wire::IdMapRange { inside_id: 0, outside_id, length: 1 }) if *outside_id == owner);
    if maps_root(uid_map, owner_uid) && maps_root(gid_map, owner_gid) {
        Ok(())
    } else {
        Err(ProviderFailure::Unsupported)
    }
}

fn has_owner_maps(process: &ProcessFact, owner_uid: u32, owner_gid: u32) -> bool {
    require_owner_maps(&process.uid_map, &process.gid_map, owner_uid, owner_gid).is_ok()
}

fn require_probe_maps(process: &ProcessFact, probe: &PodmanProbe) -> Result<(), ProviderFailure> {
    if process.uid_map == probe.uid_map && process.gid_map == probe.gid_map {
        Ok(())
    } else {
        Err(ProviderFailure::NoMatch)
    }
}

fn expected_socket_uri(socket: &Path) -> Result<String, ProviderFailure> {
    socket
        .to_str()
        .map(|value| format!("unix://{value}"))
        .ok_or(ProviderFailure::Unsupported)
}

fn podman_id_hints(cgroup: &str) -> Vec<String> {
    let mut hints = BTreeSet::new();
    for component in cgroup.split('/').filter(|component| !component.is_empty()) {
        let candidate = component
            .strip_prefix("libpod-")
            .and_then(|value| value.strip_suffix(".scope"))
            .unwrap_or(component);
        if is_instance_id(candidate) {
            hints.insert(candidate.to_string());
        }
    }
    hints.into_iter().collect()
}

fn cgroup_is_same_or_descendant(process: &str, container: &str) -> bool {
    process == container
        || (container != "/"
            && process
                .strip_prefix(container)
                .is_some_and(|suffix| suffix.starts_with('/')))
}

fn validate_instance_id(id: &str) -> Result<(), ProviderFailure> {
    if is_instance_id(id) {
        Ok(())
    } else {
        Err(ProviderFailure::Invariant)
    }
}

fn is_instance_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn normalize_config_digest(value: &str) -> Result<String, ProviderFailure> {
    let digest = if value.starts_with("sha256:") {
        value.to_string()
    } else if is_instance_id(value) {
        format!("sha256:{value}")
    } else {
        return Err(ProviderFailure::Invariant);
    };
    validate_sha256(&digest)?;
    Ok(digest)
}

fn validate_sha256(digest: &str) -> Result<(), ProviderFailure> {
    if digest.strip_prefix("sha256:").is_some_and(is_instance_id) {
        Ok(())
    } else {
        Err(ProviderFailure::Invariant)
    }
}

fn validate_bounded(value: &str) -> Result<(), ProviderFailure> {
    if value.is_empty() || value.len() > ABSOLUTE_MAX_STRING_BYTES || value.contains('\0') {
        Err(ProviderFailure::Invariant)
    } else {
        Ok(())
    }
}

fn parse_bool(value: &str) -> Result<bool, ProviderFailure> {
    if value.eq_ignore_ascii_case("true") {
        Ok(true)
    } else if value.eq_ignore_ascii_case("false") {
        Ok(false)
    } else {
        Err(ProviderFailure::Invariant)
    }
}

fn version_at_least(actual: &str, required: &str) -> bool {
    let parse = |version: &str| {
        let values = version
            .split('.')
            .map(str::parse::<u64>)
            .collect::<Result<Vec<_>, _>>()
            .ok()?;
        matches!(values.as_slice(), [_, _, _]).then_some(values)
    };
    matches!((parse(actual), parse(required)), (Some(actual), Some(required)) if actual >= required)
}

fn bounded_diagnostic_version(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(crate::attestor_protocol::ABSOLUTE_MAX_DIAGNOSTIC_BYTES)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::process::Command;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    const REALM: &str = "podman-user-a";
    const OWNER_UID: u32 = 1001;
    const OWNER_GID: u32 = 1001;

    #[derive(Clone)]
    struct FakeProcesses(BTreeMap<u32, Result<ProcessFact, ProcError>>);

    impl ProcessFactSource for FakeProcesses {
        fn observe(&self, pid: u32) -> Result<ProcessFact, ProcError> {
            self.0
                .get(&pid)
                .cloned()
                .unwrap_or(Err(ProcError::Unavailable))
        }
    }

    struct ChangingProcesses {
        initial: BTreeMap<u32, ProcessFact>,
        replacement: BTreeMap<u32, ProcessFact>,
        calls: Mutex<BTreeMap<u32, usize>>,
    }

    impl ProcessFactSource for ChangingProcesses {
        fn observe(&self, pid: u32) -> Result<ProcessFact, ProcError> {
            let use_replacement = {
                let mut calls = self.calls.lock().unwrap();
                let count = calls.entry(pid).or_default();
                *count += 1;
                let use_replacement = *count > 1;
                drop(calls);
                use_replacement
            };
            if use_replacement && let Some(process) = self.replacement.get(&pid) {
                return Ok(process.clone());
            }
            self.initial
                .get(&pid)
                .cloned()
                .ok_or(ProcError::Unavailable)
        }
    }

    struct FakeOwnerScope(Result<(), ProviderFailure>);

    impl OwnerScopeSource for FakeOwnerScope {
        fn verify(
            &self,
            _owner_uid: u32,
            _owner_gid: u32,
            _socket: &Path,
        ) -> Result<(), ProviderFailure> {
            self.0
        }
    }

    struct FakeApi {
        info: Result<PodmanInfo, PodmanApiError>,
        list: Result<Vec<ContainerSummary>, PodmanApiError>,
        containers: BTreeMap<String, ContainerInspect>,
        images: BTreeMap<String, ImageInspect>,
        replacements: BTreeMap<String, ContainerInspect>,
        inspections: Mutex<BTreeMap<String, usize>>,
        info_calls: AtomicUsize,
        list_calls: AtomicUsize,
    }

    #[async_trait]
    impl PodmanApi for FakeApi {
        async fn info(&self) -> Result<PodmanInfo, PodmanApiError> {
            self.info_calls.fetch_add(1, Ordering::Relaxed);
            self.info.clone()
        }

        async fn list_containers(
            &self,
            _filters: &PodmanFilters,
        ) -> Result<Vec<ContainerSummary>, PodmanApiError> {
            self.list_calls.fetch_add(1, Ordering::Relaxed);
            self.list.clone()
        }

        async fn inspect_container(&self, id: &str) -> Result<ContainerInspect, PodmanApiError> {
            let replacement = {
                let mut inspections = self.inspections.lock().unwrap();
                let count = inspections.entry(id.to_string()).or_default();
                *count += 1;
                let replacement = *count > 1;
                drop(inspections);
                replacement
            };
            if replacement && let Some(container) = self.replacements.get(id) {
                return Ok(container.clone());
            }
            self.containers
                .get(id)
                .cloned()
                .ok_or(PodmanApiError::NotFound)
        }

        async fn inspect_image(&self, id: &str) -> Result<ImageInspect, PodmanApiError> {
            self.images.get(id).cloned().ok_or(PodmanApiError::NotFound)
        }
    }

    fn id(character: char) -> String {
        character.to_string().repeat(64)
    }

    fn digest(character: char) -> String {
        format!("sha256:{}", id(character))
    }

    fn namespaces(seed: u64) -> wire::NamespaceInodes {
        wire::NamespaceInodes {
            user: seed,
            pid: seed + 1,
            mount: seed + 2,
            network: seed + 3,
            uts: seed + 4,
            ipc: seed + 5,
            cgroup: seed + 6,
        }
    }

    fn owner_maps(
        owner_uid: u32,
        owner_gid: u32,
    ) -> (Vec<wire::IdMapRange>, Vec<wire::IdMapRange>) {
        (
            vec![
                wire::IdMapRange {
                    inside_id: 0,
                    outside_id: owner_uid,
                    length: 1,
                },
                wire::IdMapRange {
                    inside_id: 1,
                    outside_id: owner_uid.saturating_mul(100),
                    length: 65_536,
                },
            ],
            vec![
                wire::IdMapRange {
                    inside_id: 0,
                    outside_id: owner_gid,
                    length: 1,
                },
                wire::IdMapRange {
                    inside_id: 1,
                    outside_id: owner_gid.saturating_mul(100),
                    length: 65_536,
                },
            ],
        )
    }

    fn process_for(
        pid: u32,
        start: u64,
        cgroup: &str,
        namespace_seed: u64,
        owner_uid: u32,
        owner_gid: u32,
    ) -> ProcessFact {
        let (uid_map, gid_map) = owner_maps(owner_uid, owner_gid);
        ProcessFact {
            peer: wire::PinnedPeer {
                pid,
                start_time_ticks: start,
                cgroup: cgroup.to_string(),
                namespaces: Some(namespaces(namespace_seed)),
            },
            uid_map,
            gid_map,
        }
    }

    fn process(pid: u32, start: u64, cgroup: &str, namespace_seed: u64) -> ProcessFact {
        process_for(pid, start, cgroup, namespace_seed, OWNER_UID, OWNER_GID)
    }

    fn podman_map(ranges: &[wire::IdMapRange]) -> Vec<PodmanIdMapRange> {
        ranges
            .iter()
            .map(|range| PodmanIdMapRange {
                container_id: u64::from(range.inside_id),
                host_id: u64::from(range.outside_id),
                size: u64::from(range.length),
            })
            .collect()
    }

    fn healthy_info() -> PodmanInfo {
        let (uid_map, gid_map) = owner_maps(OWNER_UID, OWNER_GID);
        PodmanInfo {
            host: PodmanHost {
                cgroup_version: "v2".to_string(),
                security: PodmanSecurity { rootless: true },
                id_mappings: PodmanIdMappings {
                    uidmap: podman_map(&uid_map),
                    gidmap: podman_map(&gid_map),
                },
                remote_socket: PodmanRemoteSocket {
                    path: "unix:///run/user/1000/podman/podman.sock".to_string(),
                    exists: true,
                },
            },
            version: PodmanVersion {
                api_version: "5.8.4".to_string(),
                version: "5.8.4".to_string(),
            },
        }
    }

    fn container(instance_id: &str, pid: u32) -> ContainerInspect {
        let mut labels = BTreeMap::new();
        labels.insert(COMPOSE_PROJECT.to_string(), "payments".to_string());
        labels.insert(COMPOSE_SERVICE.to_string(), "api".to_string());
        labels.insert(COMPOSE_ONE_OFF.to_string(), "False".to_string());
        labels.insert(COMPOSE_ORDINAL.to_string(), "2".to_string());
        let mut tmpfs = BTreeMap::new();
        tmpfs.insert(
            "/run/basil/secrets".to_string(),
            "rw,nodev,nosuid,noexec,noswap,size=32m,mode=0711".to_string(),
        );
        ContainerInspect {
            id: instance_id.to_string(),
            name: "payments-api-2".to_string(),
            image: id('c'),
            state: ContainerState {
                pid: i64::from(pid),
                status: "running".to_string(),
                running: true,
                paused: false,
            },
            config: ContainerConfig { labels },
            host_config: HostConfig { tmpfs },
            mounts: vec![
                MountPoint {
                    kind: "bind".to_string(),
                    source: "/opt/basil/wrapper".to_string(),
                    destination: "/run/basil/bin/basil-entrypoint".to_string(),
                    writable: false,
                    propagation: "rprivate".to_string(),
                },
                MountPoint {
                    kind: "tmpfs".to_string(),
                    source: String::new(),
                    destination: "/run/basil/secrets".to_string(),
                    writable: true,
                    propagation: "private".to_string(),
                },
            ],
        }
    }

    fn image() -> ImageInspect {
        ImageInspect {
            id: id('c'),
            digest: digest('d'),
            repo_digests: vec![
                format!("registry.example/payments@{}", digest('d')),
                format!("registry.example/payments@{}", digest('e')),
            ],
            os: "linux".to_string(),
            architecture: "amd64".to_string(),
            variant: None,
        }
    }

    fn fake_api(containers: Vec<ContainerInspect>) -> FakeApi {
        let summaries = containers
            .iter()
            .map(|container| ContainerSummary {
                id: container.id.clone(),
            })
            .collect();
        FakeApi {
            info: Ok(healthy_info()),
            list: Ok(summaries),
            containers: containers
                .into_iter()
                .map(|container| (container.id.clone(), container))
                .collect(),
            images: BTreeMap::from([(id('c'), image())]),
            replacements: BTreeMap::new(),
            inspections: Mutex::new(BTreeMap::new()),
            info_calls: AtomicUsize::new(0),
            list_calls: AtomicUsize::new(0),
        }
    }

    fn provider_with(
        api: Arc<FakeApi>,
        processes: Arc<dyn ProcessFactSource>,
        owner_scope: Result<(), ProviderFailure>,
    ) -> PodmanAttestor {
        PodmanAttestor::with_sources(
            REALM,
            OWNER_UID,
            OWNER_GID,
            api,
            processes,
            Arc::new(FakeOwnerScope(owner_scope)),
        )
    }

    fn provider(api: Arc<FakeApi>, processes: Vec<ProcessFact>) -> PodmanAttestor {
        provider_with(
            api,
            Arc::new(FakeProcesses(
                processes
                    .into_iter()
                    .map(|process| (process.peer.pid, Ok(process)))
                    .collect(),
            )),
            Ok(()),
        )
    }

    fn outcome_code<T>(reply: &ProviderReply<T>) -> wire::OutcomeCode {
        wire::OutcomeCode::try_from(reply.outcome().code).unwrap()
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ForeignRouteOutcome {
        NoMatch,
        Unavailable,
    }

    impl ForeignRouteOutcome {
        const fn label(self) -> &'static str {
            match self {
                Self::NoMatch => "no_match",
                Self::Unavailable => "unavailable",
            }
        }
    }

    async fn foreign_route_outcome(provider: &PodmanAttestor, pid: u32) -> ForeignRouteOutcome {
        match provider.processes.observe(pid) {
            Ok(foreign) => {
                let result = provider
                    .resolve_peer(&foreign.peer, OPERATION_TIMEOUT)
                    .await;
                assert_eq!(outcome_code(&result), wire::OutcomeCode::NoMatch);
                ForeignRouteOutcome::NoMatch
            }
            Err(error) => {
                assert_eq!(error, ProcError::Unavailable);
                ForeignRouteOutcome::Unavailable
            }
        }
    }

    #[test]
    fn public_configuration_rejects_root_and_ambiguous_paths() {
        assert!(matches!(
            PodmanAttestor::new(REALM, 0, 0, "/run/podman/podman.sock"),
            Err(PodmanAttestorConfigError::RootOwner)
        ));
        assert!(matches!(
            PodmanAttestor::new(REALM, OWNER_UID, OWNER_GID, "relative.sock"),
            Err(PodmanAttestorConfigError::InvalidSocketPath)
        ));
        for socket in [
            "/run/user/1000/../1001/podman.sock",
            "/run/user/./1000/podman.sock",
            "/run//user/1000/podman.sock",
            "/run/user/1000/podman.sock/",
        ] {
            assert!(matches!(
                PodmanAttestor::new(REALM, OWNER_UID, OWNER_GID, socket),
                Err(PodmanAttestorConfigError::InvalidSocketPath)
            ));
        }
        assert!(
            PodmanAttestor::new(
                REALM,
                OWNER_UID,
                OWNER_GID,
                "/run/user/1000/podman/podman.sock"
            )
            .is_ok()
        );
    }

    #[tokio::test]
    async fn health_requires_exact_rootless_owner_socket_maps_and_cgroup_v2() {
        let healthy = provider(Arc::new(fake_api(Vec::new())), Vec::new())
            .health(OPERATION_TIMEOUT)
            .await;
        assert_eq!(outcome_code(&healthy), wire::OutcomeCode::Ok);
        let fact = healthy.value().unwrap();
        assert_eq!(fact.runtime, wire::RuntimeKind::Podman as i32);
        assert_eq!(fact.runtime_mode, wire::RuntimeMode::Rootless as i32);
        assert_eq!(fact.cgroup_mode, wire::CgroupMode::V2 as i32);
        assert!(
            provider_capabilities()
                .iter()
                .any(|capability| capability == "podman.rootless-owner")
        );

        let mut rootful = fake_api(Vec::new());
        rootful.info.as_mut().unwrap().host.security.rootless = false;
        assert_eq!(
            outcome_code(
                &provider(Arc::new(rootful), Vec::new())
                    .health(OPERATION_TIMEOUT)
                    .await
            ),
            wire::OutcomeCode::InvalidRequest
        );

        let mut cgroup_v1 = fake_api(Vec::new());
        cgroup_v1.info.as_mut().unwrap().host.cgroup_version = "v1".to_string();
        assert_eq!(
            outcome_code(
                &provider(Arc::new(cgroup_v1), Vec::new())
                    .health(OPERATION_TIMEOUT)
                    .await
            ),
            wire::OutcomeCode::InvalidRequest
        );

        let mut foreign_mapping = fake_api(Vec::new());
        foreign_mapping
            .info
            .as_mut()
            .unwrap()
            .host
            .id_mappings
            .uidmap[0]
            .host_id = 1002;
        assert_eq!(
            outcome_code(
                &provider(Arc::new(foreign_mapping), Vec::new())
                    .health(OPERATION_TIMEOUT)
                    .await
            ),
            wire::OutcomeCode::InvalidRequest
        );

        let mut wrong_socket = fake_api(Vec::new());
        wrong_socket.info.as_mut().unwrap().host.remote_socket.path =
            "unix:///run/user/1002/podman/podman.sock".to_string();
        assert_eq!(
            outcome_code(
                &provider(Arc::new(wrong_socket), Vec::new())
                    .health(OPERATION_TIMEOUT)
                    .await
            ),
            wire::OutcomeCode::InvalidRequest
        );

        let scope_failure = provider_with(
            Arc::new(fake_api(Vec::new())),
            Arc::new(FakeProcesses(BTreeMap::new())),
            Err(ProviderFailure::Unsupported),
        )
        .health(OPERATION_TIMEOUT)
        .await;
        assert_eq!(
            outcome_code(&scope_failure),
            wire::OutcomeCode::InvalidRequest
        );
    }

    #[tokio::test]
    async fn foreign_owner_is_rejected_before_any_runtime_call() {
        let instance_id = id('a');
        let cgroup = format!("/user.slice/libpod-{instance_id}.scope");
        let foreign = process_for(222, 9, &cgroup, 20, 1002, 1002);
        let api = Arc::new(fake_api(vec![container(&instance_id, 200)]));
        let attestor = provider(Arc::clone(&api), vec![foreign.clone()]);
        let result = attestor
            .resolve_peer(&foreign.peer, OPERATION_TIMEOUT)
            .await;
        assert_eq!(outcome_code(&result), wire::OutcomeCode::NoMatch);
        assert_eq!(api.info_calls.load(Ordering::Relaxed), 0);
        assert_eq!(api.list_calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn foreign_route_reporting_distinguishes_no_match_from_unavailable() {
        let foreign_pid = 222;
        let foreign_cgroup = format!("/user.slice/libpod-{}.scope", id('a'));
        let foreign = process_for(foreign_pid, 9, &foreign_cgroup, 20, 1002, 1002);
        let no_match = provider(Arc::new(fake_api(Vec::new())), vec![foreign]);
        assert_eq!(
            foreign_route_outcome(&no_match, foreign_pid).await,
            ForeignRouteOutcome::NoMatch
        );

        let unavailable = provider(Arc::new(fake_api(Vec::new())), Vec::new());
        assert_eq!(
            foreign_route_outcome(&unavailable, foreign_pid).await,
            ForeignRouteOutcome::Unavailable
        );
    }

    #[tokio::test]
    async fn resolve_correlates_exec_and_projects_only_bounded_facts() {
        let instance_id = id('a');
        let init_cgroup = format!("/user.slice/libpod-{instance_id}.scope");
        let exec_cgroup = format!("{init_cgroup}/exec.scope");
        let init = process(200, 20, &init_cgroup, 10);
        let exec = process(900, 90, &exec_cgroup, 10);
        let attestor = provider(
            Arc::new(fake_api(vec![container(&instance_id, 200)])),
            vec![init, exec.clone()],
        );
        let result = attestor.resolve_peer(&exec.peer, OPERATION_TIMEOUT).await;
        assert_eq!(outcome_code(&result), wire::OutcomeCode::Ok);
        let fact = result.value().unwrap();
        assert_eq!(fact.runtime, wire::RuntimeKind::Podman as i32);
        assert_eq!(fact.instance_id, instance_id);
        assert_eq!(fact.observed_peer.as_ref(), Some(&exec.peer));
        assert_eq!(fact.compose.as_ref().unwrap().replica_ordinal, Some(2));
        assert_eq!(fact.image.as_ref().unwrap().index_digest, Some(digest('e')));
        assert_eq!(fact.image.as_ref().unwrap().manifest_digest, digest('d'));
        assert_eq!(fact.image.as_ref().unwrap().config_digest, digest('c'));
        let tmpfs = fact
            .mounts
            .iter()
            .find(|mount| mount.kind == wire::MountKind::Tmpfs as i32)
            .unwrap();
        assert_eq!(tmpfs.tmpfs_size_bytes, Some(32 * 1024 * 1024));
        assert_eq!(tmpfs.tmpfs_mode, Some(0o711));
        assert!(tmpfs.tmpfs_nodev);
        assert!(tmpfs.tmpfs_nosuid);
        assert!(tmpfs.tmpfs_noexec);
        assert!(tmpfs.tmpfs_noswap);
    }

    #[tokio::test]
    async fn pid_reuse_namespace_conflict_and_restart_fail_closed() {
        let instance_id = id('a');
        let cgroup = format!("/user.slice/libpod-{instance_id}.scope");
        let init = process(200, 20, &cgroup, 10);
        let peer = process(900, 90, &cgroup, 10);

        let mut stale = peer.peer.clone();
        stale.start_time_ticks -= 1;
        let result = provider(
            Arc::new(fake_api(vec![container(&instance_id, 200)])),
            vec![init.clone(), peer.clone()],
        )
        .resolve_peer(&stale, OPERATION_TIMEOUT)
        .await;
        assert_eq!(outcome_code(&result), wire::OutcomeCode::ChangedDuringRead);

        let conflicting = process(900, 90, &cgroup, 99);
        let result = provider(
            Arc::new(fake_api(vec![container(&instance_id, 200)])),
            vec![init.clone(), conflicting.clone()],
        )
        .resolve_peer(&conflicting.peer, OPERATION_TIMEOUT)
        .await;
        assert_eq!(outcome_code(&result), wire::OutcomeCode::NoMatch);

        let mut changed_api = fake_api(vec![container(&instance_id, 200)]);
        let mut restarted = container(&instance_id, 201);
        restarted.state.pid = 201;
        changed_api
            .replacements
            .insert(instance_id.clone(), restarted);
        let result = provider(Arc::new(changed_api), vec![init, peer])
            .resolve_peer(&process(900, 90, &cgroup, 10).peer, OPERATION_TIMEOUT)
            .await;
        assert_eq!(outcome_code(&result), wire::OutcomeCode::ChangedDuringRead);
    }

    #[tokio::test]
    async fn final_process_reobservation_detects_churn() {
        let instance_id = id('a');
        let cgroup = format!("/user.slice/libpod-{instance_id}.scope");
        let init = process(200, 20, &cgroup, 10);
        let peer = process(900, 90, &cgroup, 10);
        let mut changed_peer = peer.clone();
        changed_peer.peer.start_time_ticks += 1;
        let processes = ChangingProcesses {
            initial: BTreeMap::from([(200, init), (900, peer.clone())]),
            replacement: BTreeMap::from([(900, changed_peer)]),
            calls: Mutex::new(BTreeMap::new()),
        };
        let result = provider_with(
            Arc::new(fake_api(vec![container(&instance_id, 200)])),
            Arc::new(processes),
            Ok(()),
        )
        .resolve_peer(&peer.peer, OPERATION_TIMEOUT)
        .await;
        assert_eq!(outcome_code(&result), wire::OutcomeCode::ChangedDuringRead);
    }

    #[tokio::test]
    async fn query_is_owner_local_sorted_scoped_and_bounded_at_one_thousand() {
        let first_id = id('a');
        let second_id = id('b');
        let first_cgroup = format!("/user.slice/libpod-{first_id}.scope");
        let second_cgroup = format!("/user.slice/libpod-{second_id}.scope");
        let result = provider(
            Arc::new(fake_api(vec![
                container(&second_id, 200),
                container(&first_id, 100),
            ])),
            vec![
                process(100, 10, &first_cgroup, 10),
                process(200, 20, &second_cgroup, 20),
            ],
        )
        .query_instances(
            &QueryScope::Project {
                realm: REALM.to_string(),
                project: "payments".to_string(),
            },
            OPERATION_TIMEOUT,
        )
        .await;
        assert_eq!(outcome_code(&result), wire::OutcomeCode::Ok);
        assert_eq!(
            result
                .value()
                .unwrap()
                .iter()
                .map(|fact| fact.instance_id.as_str())
                .collect::<Vec<_>>(),
            [first_id.as_str(), second_id.as_str()]
        );

        let wrong_realm = provider(Arc::new(fake_api(Vec::new())), Vec::new())
            .query_instances(
                &QueryScope::Project {
                    realm: "another-owner".to_string(),
                    project: "payments".to_string(),
                },
                OPERATION_TIMEOUT,
            )
            .await;
        assert_eq!(
            outcome_code(&wrong_realm),
            wire::OutcomeCode::InvalidRequest
        );

        let mut overflow = fake_api(Vec::new());
        overflow.list = Ok((0..=ABSOLUTE_MAX_INSTANCES)
            .map(|index| ContainerSummary {
                id: format!("{index:064x}"),
            })
            .collect());
        let result = provider(Arc::new(overflow), Vec::new())
            .query_instances(&QueryScope::GlobalDoctor, OPERATION_TIMEOUT)
            .await;
        assert_eq!(outcome_code(&result), wire::OutcomeCode::ResourceExhausted);
    }

    #[tokio::test]
    async fn outage_is_typed_without_partial_facts() {
        let mut unavailable = fake_api(Vec::new());
        unavailable.info = Err(PodmanApiError::Unavailable);
        let result = provider(Arc::new(unavailable), Vec::new())
            .health(OPERATION_TIMEOUT)
            .await;
        assert_eq!(outcome_code(&result), wire::OutcomeCode::Unavailable);
        assert!(result.value().is_none());
        assert_eq!(effective_budget(Duration::from_secs(60)), OPERATION_TIMEOUT);
    }

    #[test]
    fn podman_json_casing_nulls_maps_and_cgroup_hints_are_strict() {
        let fixture = r#"{
          "host": {
            "cgroupVersion": "v2",
            "security": {"rootless": true},
            "idMappings": {
              "uidmap": [{"container_id":0,"host_id":1001,"size":1}],
              "gidmap": [{"container_id":0,"host_id":1001,"size":1}]
            },
            "remoteSocket": {"path":"unix:///run/user/1000/podman/podman.sock","exists":true}
          },
          "version": {"APIVersion":"5.8.4","Version":"5.8.4"}
        }"#;
        let info: PodmanInfo = serde_json::from_str(fixture).unwrap();
        assert!(info.host.security.rootless);
        assert_eq!(info.host.id_mappings.uidmap[0].host_id, 1001);

        let image_fixture = format!(
            r#"{{"Id":"{}","Digest":"{}","RepoDigests":null,"Os":"linux","Architecture":"amd64","Variant":null}}"#,
            id('c'),
            digest('d')
        );
        let image: ImageInspect = serde_json::from_str(&image_fixture).unwrap();
        assert!(image.repo_digests.is_empty());

        let instance_id = id('a');
        assert_eq!(
            podman_id_hints(&format!(
                "/user.slice/user-1001.slice/libpod-{instance_id}.scope/exec.scope"
            )),
            [instance_id]
        );
        assert!(podman_id_hints("/user.slice/libpod-short.scope").is_empty());
        assert!(cgroup_is_same_or_descendant("/libpod/a/exec", "/libpod/a"));
        assert!(!cgroup_is_same_or_descendant("/libpod/ab", "/libpod/a"));
        assert!(version_at_least("5.8.4", "5.0.0"));
        assert!(!version_at_least("4.9.9", "5.0.0"));
        assert!(!version_at_least("invalid", "5.0.0"));
    }

    #[tokio::test]
    async fn rootful_null_id_mappings_are_a_typed_mode_rejection() {
        let fixture = r#"{
          "host": {
            "cgroupVersion": "v2",
            "security": {"rootless": false},
            "idMappings": null,
            "remoteSocket": {"path":"unix:///run/podman/podman.sock","exists":true}
          },
          "version": {"APIVersion":"5.8.1","Version":"5.8.1"}
        }"#;
        let info: PodmanInfo = serde_json::from_str(fixture).unwrap();
        assert!(info.host.id_mappings.uidmap.is_empty());
        assert!(info.host.id_mappings.gidmap.is_empty());

        let mut rootful = fake_api(Vec::new());
        rootful.info = Ok(info);
        let result = provider(Arc::new(rootful), Vec::new())
            .health(OPERATION_TIMEOUT)
            .await;
        assert_eq!(outcome_code(&result), wire::OutcomeCode::InvalidRequest);
        assert!(result.value().is_none());
    }

    #[test]
    fn overlapping_maps_and_ambiguous_tmpfs_options_are_rejected() {
        assert_eq!(
            normalize_runtime_map(&[
                PodmanIdMapRange {
                    container_id: 0,
                    host_id: 1001,
                    size: 10,
                },
                PodmanIdMapRange {
                    container_id: 5,
                    host_id: 2000,
                    size: 10,
                },
            ]),
            Err(ProviderFailure::Unsupported)
        );
        for options in ["dev", "nodev,dev", "nosuid,nosuid", "size=1m,size=2m"] {
            assert_eq!(
                parse_tmpfs_options(options),
                Err(ProviderFailure::Invariant),
                "options {options:?} must fail closed"
            );
        }
    }

    fn podman_command(arguments: &[&str]) -> String {
        let output = Command::new("podman").args(arguments).output().unwrap();
        assert!(
            output.status.success(),
            "podman {arguments:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }

    fn shell_command(program: &str) {
        let output = Command::new("bash").args(["-c", program]).output().unwrap();
        assert!(
            output.status.success(),
            "acceptance helper failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn remove_acceptance_containers() {
        let _status = Command::new("bash")
            .args([
                "-c",
                "podman ps -aq --filter label=io.openbasil.podman-attestor-acceptance | xargs -r podman rm -f >/dev/null",
            ])
            .status();
    }

    struct AcceptanceCleanup;

    impl Drop for AcceptanceCleanup {
        fn drop(&mut self) {
            remove_acceptance_containers();
        }
    }

    fn live_socket() -> PathBuf {
        std::env::var_os("BASIL_PODMAN_SOCKET").map_or_else(
            || {
                PathBuf::from(format!(
                    "/run/user/{}/podman/podman.sock",
                    rustix::process::geteuid().as_raw()
                ))
            },
            PathBuf::from,
        )
    }

    fn live_provider() -> PodmanAttestor {
        PodmanAttestor::new(
            REALM,
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw(),
            live_socket(),
        )
        .unwrap()
    }

    fn unsupported_live_provider(owner_uid: u32, owner_gid: u32, socket: &Path) -> PodmanAttestor {
        PodmanAttestor {
            realm: REALM.to_string(),
            owner_uid,
            owner_gid,
            socket: socket.to_path_buf(),
            api: Arc::new(HttpPodmanApi::new(socket).unwrap()),
            processes: Arc::new(LinuxProcfs::default()),
            owner_scope: Arc::new(LinuxOwnerScope),
            capabilities: provider_capabilities(),
        }
    }

    #[tokio::test]
    #[ignore = "requires a live rootless Podman user socket"]
    async fn live_rootless_podman_health_uses_owner_socket_and_maps() {
        let health = live_provider().health(OPERATION_TIMEOUT).await;
        assert_eq!(outcome_code(&health), wire::OutcomeCode::Ok);
        let fact = health.value().unwrap();
        assert_eq!(fact.runtime_mode, wire::RuntimeMode::Rootless as i32);
        assert_eq!(fact.cgroup_mode, wire::CgroupMode::V2 as i32);
    }

    #[tokio::test]
    #[ignore = "requires the Fedora SELinux rootless Podman acceptance guest"]
    #[allow(clippy::too_many_lines)]
    async fn live_rootless_podman_acceptance_matrix() {
        remove_acceptance_containers();
        let _cleanup = AcceptanceCleanup;
        let provider = live_provider();
        assert_eq!(
            outcome_code(&provider.health(OPERATION_TIMEOUT).await),
            wire::OutcomeCode::Ok
        );
        let image = std::env::var("BASIL_PODMAN_IMAGE")
            .unwrap_or_else(|_| "basil-smoke/alpine:smoke".to_string());
        let bind_source = std::env::temp_dir().join(format!(
            "basil-podman-attestor-bind-{}",
            rustix::process::geteuid().as_raw()
        ));
        std::fs::create_dir_all(&bind_source).unwrap();
        let bind = format!("{}:/run/basil/listener:ro,z", bind_source.display());
        let common_labels = [
            "--label",
            "io.openbasil.podman-attestor-acceptance=core",
            "--label",
            "com.docker.compose.project=basil-podman-attestor",
            "--label",
            "com.docker.compose.service=api",
            "--label",
            "com.docker.compose.oneoff=False",
        ];
        let mut first_arguments = vec![
            "run",
            "-d",
            "--network",
            "none",
            "--name",
            "basil-podman-attestor-one",
        ];
        first_arguments.extend(common_labels);
        first_arguments.extend([
            "--label",
            "com.docker.compose.container-number=1",
            "--tmpfs",
            "/run/basil/secrets:rw,nodev,nosuid,noexec,size=4096,mode=0700",
            "--volume",
            &bind,
            &image,
            "sleep",
            "900",
        ]);
        let first_id = podman_command(&first_arguments);
        let mut second_arguments = vec![
            "run",
            "-d",
            "--network",
            "none",
            "--name",
            "basil-podman-attestor-two",
        ];
        second_arguments.extend(common_labels);
        second_arguments.extend([
            "--label",
            "com.docker.compose.container-number=2",
            &image,
            "sleep",
            "900",
        ]);
        let second_id = podman_command(&second_arguments);

        let inventory = provider
            .query_instances(
                &QueryScope::Service {
                    realm: REALM.to_string(),
                    project: "basil-podman-attestor".to_string(),
                    service: "api".to_string(),
                },
                OPERATION_TIMEOUT,
            )
            .await;
        assert_eq!(outcome_code(&inventory), wire::OutcomeCode::Ok);
        let instances = inventory.value().unwrap();
        assert_eq!(instances.len(), 2);
        assert!(
            instances
                .iter()
                .any(|instance| instance.instance_id == first_id)
        );
        assert!(
            instances
                .iter()
                .any(|instance| instance.instance_id == second_id)
        );
        let first = instances
            .iter()
            .find(|instance| instance.instance_id == first_id)
            .unwrap();
        let secret_mount = first
            .mounts
            .iter()
            .find(|mount| mount.container_destination == "/run/basil/secrets")
            .unwrap();
        assert!(secret_mount.tmpfs_nodev);
        assert!(secret_mount.tmpfs_nosuid);
        assert!(secret_mount.tmpfs_noexec);
        // Podman 5.8 rejects explicit `noswap` for rootless tmpfs mounts. The
        // provider still projects the flag whenever the runtime reports it.
        assert!(!secret_mount.tmpfs_noswap);
        let listener_mount = first
            .mounts
            .iter()
            .find(|mount| mount.container_destination == "/run/basil/listener")
            .unwrap();
        assert!(listener_mount.read_only);
        assert_eq!(listener_mount.host_source, bind_source.to_string_lossy());
        let process_label = podman_command(&[
            "inspect",
            "--format",
            "{{.ProcessLabel}}",
            "basil-podman-attestor-one",
        ]);
        assert!(process_label.contains("container_t"));
        let bind_label = Command::new("ls")
            .args(["-Zd", bind_source.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(bind_label.status.success());
        assert!(String::from_utf8_lossy(&bind_label.stdout).contains("container_file_t"));

        podman_command(&["exec", "-d", "basil-podman-attestor-two", "sleep", "300"]);
        let mut exec_pid = None;
        for _ in 0..30 {
            let top = podman_command(&["top", "basil-podman-attestor-two", "hpid,args"]);
            exec_pid = top
                .lines()
                .find(|line| line.contains("sleep 300"))
                .and_then(|line| line.split_whitespace().next())
                .and_then(|pid| pid.parse::<u32>().ok());
            if exec_pid.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let exec_pid = exec_pid.expect("exec host PID must be visible in Podman top output");
        let exec_process = provider.processes.observe(exec_pid).unwrap();
        let resolved = provider
            .resolve_peer(&exec_process.peer, OPERATION_TIMEOUT)
            .await;
        assert_eq!(outcome_code(&resolved), wire::OutcomeCode::Ok);
        assert_eq!(resolved.value().unwrap().instance_id, second_id);

        let mut reused_pid = exec_process.peer.clone();
        reused_pid.start_time_ticks = reused_pid.start_time_ticks.saturating_sub(1);
        assert_eq!(
            outcome_code(&provider.resolve_peer(&reused_pid, OPERATION_TIMEOUT).await),
            wire::OutcomeCode::ChangedDuringRead
        );
        if let Some(foreign_pid) = std::env::var("BASIL_FOREIGN_PID")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
        {
            let outcome = foreign_route_outcome(&provider, foreign_pid).await;
            eprintln!("BASIL_FOREIGN_ROUTE_OUTCOME={}", outcome.label());
        }

        podman_command(&["restart", "basil-podman-attestor-two"]);
        assert_eq!(
            outcome_code(
                &provider
                    .resolve_peer(&exec_process.peer, OPERATION_TIMEOUT)
                    .await
            ),
            wire::OutcomeCode::ChangedDuringRead
        );
        let _remove_bind = std::fs::remove_dir_all(bind_source);
    }

    #[tokio::test]
    #[ignore = "creates 1,001 containers in the capacity-sized Fedora guest"]
    async fn live_rootless_podman_inventory_bound() {
        remove_acceptance_containers();
        let _cleanup = AcceptanceCleanup;
        let image = std::env::var("BASIL_PODMAN_IMAGE")
            .unwrap_or_else(|_| "basil-smoke/alpine:smoke".to_string());
        let command = format!(
            "seq 1 1000 | xargs -P 64 -I{{}} podman run -d --network none \
             --name basil-podman-attestor-scale-{{}} \
             --label io.openbasil.podman-attestor-acceptance=scale \
             --label com.docker.compose.project=basil-podman-attestor-scale \
             --label com.docker.compose.service=scale \
             --label com.docker.compose.oneoff=False \
             {image} sleep 1200 >/dev/null"
        );
        shell_command(&command);
        let provider = live_provider();
        let scope = QueryScope::Project {
            realm: REALM.to_string(),
            project: "basil-podman-attestor-scale".to_string(),
        };
        let inventory = provider.query_instances(&scope, OPERATION_TIMEOUT).await;
        assert_eq!(outcome_code(&inventory), wire::OutcomeCode::Ok);
        assert_eq!(inventory.value().unwrap().len(), ABSOLUTE_MAX_INSTANCES);
        podman_command(&[
            "run",
            "-d",
            "--network",
            "none",
            "--name",
            "basil-podman-attestor-scale-overflow",
            "--label",
            "io.openbasil.podman-attestor-acceptance=scale",
            "--label",
            "com.docker.compose.project=basil-podman-attestor-scale",
            "--label",
            "com.docker.compose.service=scale",
            "--label",
            "com.docker.compose.oneoff=False",
            &image,
            "sleep",
            "1200",
        ]);
        assert_eq!(
            outcome_code(&provider.query_instances(&scope, OPERATION_TIMEOUT).await),
            wire::OutcomeCode::ResourceExhausted
        );
    }

    #[tokio::test]
    #[ignore = "stops and restarts the rootless Podman user service"]
    async fn live_rootless_podman_outage_is_typed_and_recovers() {
        let provider = live_provider();
        let stop = Command::new("systemctl")
            .args(["--user", "stop", "podman.socket", "podman.service"])
            .status()
            .unwrap();
        assert!(stop.success());
        assert_eq!(
            outcome_code(&provider.health(OPERATION_TIMEOUT).await),
            wire::OutcomeCode::Unavailable
        );
        let start = Command::new("systemctl")
            .args(["--user", "start", "podman.socket"])
            .status()
            .unwrap();
        assert!(start.success());
        let mut recovered = false;
        for _ in 0..30 {
            if outcome_code(&provider.health(OPERATION_TIMEOUT).await) == wire::OutcomeCode::Ok {
                recovered = true;
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        assert!(recovered);
    }

    #[tokio::test]
    #[ignore = "requires a live rootful Podman socket"]
    async fn live_podman_rejects_rootful_runtime() {
        let socket = std::env::var_os("BASIL_PODMAN_SOCKET")
            .map_or_else(|| PathBuf::from("/run/podman/podman.sock"), PathBuf::from);
        let provider = unsupported_live_provider(0, 0, &socket);
        assert_eq!(
            outcome_code(&provider.health(OPERATION_TIMEOUT).await),
            wire::OutcomeCode::InvalidRequest
        );
    }
}
