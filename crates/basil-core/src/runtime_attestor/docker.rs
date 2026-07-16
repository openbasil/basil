// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Rootful Docker facts-only attestation provider.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
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
    ABSOLUTE_MAX_INSTANCES, ABSOLUTE_MAX_MOUNTS_PER_INSTANCE, ABSOLUTE_MAX_STRING_BYTES,
    MOUNT_SECURITY_CAPABILITY,
};
use crate::attestor_protocol::{QueryScope, wire};

const DOCKER_API_VERSION: &str = "1.48";
const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DOCKER_OBJECT_BYTES: usize = 1024 * 1024;
const MAX_DOCKER_LIST_BYTES: usize = 16 * 1024 * 1024;
const MAX_CONCURRENT_INSPECTS: usize = 32;
const DOCKER_DESCRIPTOR_CAPABILITY: &str = "docker.image-manifest-descriptor";
const CONTAINERD_SNAPSHOTTER_DRIVER: [&str; 2] = ["driver-type", "io.containerd.snapshotter.v1"];
const COMPOSE_PROJECT: &str = "com.docker.compose.project";
const COMPOSE_SERVICE: &str = "com.docker.compose.service";
const COMPOSE_ONE_OFF: &str = "com.docker.compose.oneoff";
const COMPOSE_ORDINAL: &str = "com.docker.compose.container-number";

/// Rootful Docker provider construction failure.
#[derive(Debug, Error)]
pub enum DockerAttestorConfigError {
    /// Realm name is empty, overlong, or contains a NUL byte.
    #[error("Docker attestor realm is invalid")]
    InvalidRealm,
    /// The bounded Unix-socket HTTP client could not be built.
    #[error("Docker attestor HTTP client could not be built")]
    HttpClient(#[source] reqwest::Error),
}

/// Facts-only provider for rootful Docker on Linux cgroup v2.
pub struct DockerAttestor {
    realm: String,
    api: Arc<dyn DockerApi>,
    processes: Arc<dyn ProcessFactSource>,
    capabilities: Vec<String>,
}

impl DockerAttestor {
    /// Construct a provider for one exact Docker Unix socket and realm.
    ///
    /// # Errors
    ///
    /// Returns [`DockerAttestorConfigError`] for an invalid realm or when the
    /// bounded HTTP client cannot be built.
    pub fn new(
        realm: impl Into<String>,
        socket: impl AsRef<Path>,
    ) -> Result<Self, DockerAttestorConfigError> {
        let realm = realm.into();
        validate_realm(&realm)?;
        let api = HttpDockerApi::new(socket.as_ref())?;
        Ok(Self {
            realm,
            api: Arc::new(api),
            processes: Arc::new(LinuxProcfs::default()),
            capabilities: provider_capabilities(),
        })
    }

    #[cfg(test)]
    fn with_sources(
        realm: &str,
        api: Arc<dyn DockerApi>,
        processes: Arc<dyn ProcessFactSource>,
    ) -> Self {
        Self {
            realm: realm.to_string(),
            api,
            processes,
            capabilities: provider_capabilities(),
        }
    }

    async fn supported_environment(&self) -> Result<DockerProbe, ProviderFailure> {
        let info = self.api.info().await.map_err(ProviderFailure::from)?;
        if info.cgroup_version != "2" {
            return Err(ProviderFailure::Unsupported);
        }
        if info.security_options.iter().any(|option| {
            let normalized = option.to_ascii_lowercase();
            normalized.contains("name=rootless") || normalized.contains("name=userns")
        }) {
            return Err(ProviderFailure::Unsupported);
        }
        // Docker documents this exact `/info` `DriverStatus` row as the
        // capability signal for the containerd image store. That store is
        // required because it is what makes `ImageManifestDescriptor`
        // available; the API version alone does not imply the field is
        // populated on legacy graph-driver installations.
        if !info.driver_status.iter().any(|row| {
            matches!(row.as_slice(), [name, value]
                if name == CONTAINERD_SNAPSHOTTER_DRIVER[0]
                    && value == CONTAINERD_SNAPSHOTTER_DRIVER[1])
        }) {
            return Err(ProviderFailure::Unsupported);
        }
        let version = self.api.version().await.map_err(ProviderFailure::from)?;
        if !api_version_at_least(&version.api_version, DOCKER_API_VERSION) {
            return Err(ProviderFailure::Unsupported);
        }
        Ok(DockerProbe {
            version: version.version,
        })
    }

    async fn resolve_inner(
        &self,
        constraints: &wire::PinnedPeer,
    ) -> Result<wire::InstanceFact, ProviderFailure> {
        self.supported_environment().await?;
        let observed = self
            .processes
            .observe(constraints.pid)
            .map_err(|_| ProviderFailure::Changed)?;
        if observed.peer != *constraints {
            return Err(ProviderFailure::Changed);
        }
        require_initial_user_namespace(&observed)?;

        let hints = docker_id_hints(&observed.peer.cgroup);
        let [id] = hints.as_slice() else {
            return Err(if hints.is_empty() {
                ProviderFailure::NoMatch
            } else {
                ProviderFailure::MultipleMatches
            });
        };
        self.resolve_candidate(id, &observed).await
    }

    async fn inspect_candidate(&self, id: &str) -> Result<ContainerInspect, ProviderFailure> {
        match self.api.inspect_container(id).await {
            Ok(container) => Ok(container),
            Err(DockerApiError::NotFound) => Err(ProviderFailure::Changed),
            Err(error) => Err(error.into()),
        }
    }

    async fn resolve_candidate(
        &self,
        id: &str,
        observed_peer: &ProcessFact,
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
        require_initial_user_namespace(&observed_init)?;
        if !cgroup_is_same_or_descendant(&observed_peer.peer.cgroup, &observed_init.peer.cgroup)
            || observed_peer.peer.namespaces != observed_init.peer.namespaces
        {
            return Err(ProviderFailure::NoMatch);
        }
        let image = match self.api.inspect_image(&before.image).await {
            Ok(image) => image,
            Err(DockerApiError::NotFound) => return Err(ProviderFailure::Changed),
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
        normalize_instance(&self.realm, &after, &image, final_peer)
    }

    async fn query_inner(
        &self,
        scope: &QueryScope,
    ) -> Result<Vec<wire::InstanceFact>, ProviderFailure> {
        self.supported_environment().await?;
        let filters = match scope {
            QueryScope::InstanceId(id) => {
                validate_instance_id(id)?;
                DockerFilters::running().with_id(id)
            }
            QueryScope::Project { realm, project } => {
                self.require_query_realm(realm)?;
                DockerFilters::running().with_label(COMPOSE_PROJECT, project)?
            }
            QueryScope::Service {
                realm,
                project,
                service,
            } => {
                self.require_query_realm(realm)?;
                DockerFilters::running()
                    .with_label(COMPOSE_PROJECT, project)?
                    .with_label(COMPOSE_SERVICE, service)?
            }
            QueryScope::GlobalDoctor => DockerFilters::running(),
        };
        let ids = self.list_candidate_ids(&filters).await?;
        let results = stream::iter(
            ids.into_iter()
                .map(|id| async move { self.inventory_candidate(&id).await }),
        )
        .buffer_unordered(MAX_CONCURRENT_INSPECTS)
        .collect::<Vec<_>>()
        .await;
        let mut instances = results
            .into_iter()
            .collect::<Result<Vec<_>, ProviderFailure>>()?;
        instances.sort_by(|left, right| left.instance_id.cmp(&right.instance_id));
        Ok(instances)
    }

    async fn inventory_candidate(&self, id: &str) -> Result<wire::InstanceFact, ProviderFailure> {
        let before = self.inspect_candidate(id).await?;
        if before.id != id || !is_running(&before.state) {
            return Err(ProviderFailure::Changed);
        }
        let init_pid = running_pid(&before.state)?;
        let process = self
            .processes
            .observe(init_pid)
            .map_err(|_| ProviderFailure::Changed)?;
        require_initial_user_namespace(&process)?;
        let image = match self.api.inspect_image(&before.image).await {
            Ok(image) => image,
            Err(DockerApiError::NotFound) => return Err(ProviderFailure::Changed),
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
        normalize_instance(&self.realm, &after, &image, final_process)
    }

    async fn list_candidate_ids(
        &self,
        filters: &DockerFilters,
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
impl RuntimeAttestorProvider for DockerAttestor {
    fn capabilities(&self) -> &[String] {
        &self.capabilities
    }

    async fn health(&self, budget: Duration) -> ProviderReply<wire::HealthFact> {
        match timeout(effective_budget(budget), self.supported_environment()).await {
            Ok(Ok(probe)) => ProviderReply::success(wire::HealthFact {
                runtime: wire::RuntimeKind::Docker as i32,
                diagnostic_version: bounded_diagnostic_version(&probe.version),
                runtime_mode: wire::RuntimeMode::Rootful as i32,
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
        DOCKER_DESCRIPTOR_CAPABILITY,
        "health",
        MOUNT_SECURITY_CAPABILITY,
        "query-instances",
        "resolve-peer",
    ]
    .map(str::to_string)
    .to_vec()
}

fn effective_budget(budget: Duration) -> Duration {
    budget.min(OPERATION_TIMEOUT)
}

fn validate_realm(realm: &str) -> Result<(), DockerAttestorConfigError> {
    if realm.is_empty() || realm.len() > ABSOLUTE_MAX_STRING_BYTES || realm.contains('\0') {
        Err(DockerAttestorConfigError::InvalidRealm)
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct DockerProbe {
    version: String,
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
            Self::Unavailable => (wire::OutcomeCode::Unavailable, "Docker runtime unavailable"),
            Self::ResourceExhausted => (
                wire::OutcomeCode::ResourceExhausted,
                "Docker evidence exceeds compiled bound",
            ),
            Self::DeadlineExceeded => (
                wire::OutcomeCode::DeadlineExceeded,
                "Docker evidence deadline exceeded",
            ),
            Self::InvalidRequest => (
                wire::OutcomeCode::InvalidRequest,
                "invalid Docker query scope",
            ),
            Self::Unsupported => (
                wire::OutcomeCode::InvalidRequest,
                "unsupported Docker runtime mode",
            ),
            Self::Invariant => (
                wire::OutcomeCode::InvariantFailure,
                "invalid Docker runtime evidence",
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

impl From<DockerApiError> for ProviderFailure {
    fn from(error: DockerApiError) -> Self {
        match error {
            DockerApiError::Unavailable => Self::Unavailable,
            DockerApiError::ResourceExhausted => Self::ResourceExhausted,
            DockerApiError::Invariant => Self::Invariant,
            DockerApiError::NotFound => Self::NotFound,
        }
    }
}

#[derive(Clone, Debug, Default)]
struct DockerFilters(BTreeMap<String, Vec<String>>);

impl DockerFilters {
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
enum DockerApiError {
    Unavailable,
    ResourceExhausted,
    Invariant,
    NotFound,
}

#[async_trait]
trait DockerApi: Send + Sync {
    async fn version(&self) -> Result<DockerVersion, DockerApiError>;
    async fn info(&self) -> Result<DockerInfo, DockerApiError>;
    async fn list_containers(
        &self,
        filters: &DockerFilters,
    ) -> Result<Vec<ContainerSummary>, DockerApiError>;
    async fn inspect_container(&self, id: &str) -> Result<ContainerInspect, DockerApiError>;
    async fn inspect_image(&self, id: &str) -> Result<ImageInspect, DockerApiError>;
}

struct HttpDockerApi {
    client: reqwest::Client,
}

impl HttpDockerApi {
    fn new(socket: &Path) -> Result<Self, DockerAttestorConfigError> {
        crate::ensure_crypto_provider();
        let client = reqwest::Client::builder()
            .unix_socket(socket)
            .http1_only()
            .timeout(HTTP_REQUEST_TIMEOUT)
            .no_proxy()
            .build()
            .map_err(DockerAttestorConfigError::HttpClient)?;
        Ok(Self { client })
    }

    async fn get<T>(&self, path: &str, maximum: usize) -> Result<T, DockerApiError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let mut response = self
            .client
            .get(format!("http://localhost{path}"))
            .send()
            .await
            .map_err(|_| DockerApiError::Unavailable)?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(DockerApiError::NotFound);
        }
        if !response.status().is_success() {
            return Err(DockerApiError::Unavailable);
        }
        if response
            .content_length()
            .is_some_and(|length| length > maximum as u64)
        {
            return Err(DockerApiError::ResourceExhausted);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| DockerApiError::Unavailable)?
        {
            if bytes
                .len()
                .checked_add(chunk.len())
                .is_none_or(|length| length > maximum)
            {
                return Err(DockerApiError::ResourceExhausted);
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).map_err(|_| DockerApiError::Invariant)
    }
}

#[async_trait]
impl DockerApi for HttpDockerApi {
    async fn version(&self) -> Result<DockerVersion, DockerApiError> {
        self.get("/version", MAX_DOCKER_OBJECT_BYTES).await
    }

    async fn info(&self) -> Result<DockerInfo, DockerApiError> {
        self.get(
            &format!("/v{DOCKER_API_VERSION}/info"),
            MAX_DOCKER_OBJECT_BYTES,
        )
        .await
    }

    async fn list_containers(
        &self,
        filters: &DockerFilters,
    ) -> Result<Vec<ContainerSummary>, DockerApiError> {
        let encoded_filters =
            serde_json::to_string(&filters.0).map_err(|_| DockerApiError::Invariant)?;
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("all", "false")
            .append_pair("limit", &(ABSOLUTE_MAX_INSTANCES + 1).to_string())
            .append_pair("filters", &encoded_filters)
            .finish();
        self.get(
            &format!("/v{DOCKER_API_VERSION}/containers/json?{query}"),
            MAX_DOCKER_LIST_BYTES,
        )
        .await
    }

    async fn inspect_container(&self, id: &str) -> Result<ContainerInspect, DockerApiError> {
        let id = utf8_percent_encode(id, NON_ALPHANUMERIC);
        self.get(
            &format!("/v{DOCKER_API_VERSION}/containers/{id}/json"),
            MAX_DOCKER_OBJECT_BYTES,
        )
        .await
    }

    async fn inspect_image(&self, id: &str) -> Result<ImageInspect, DockerApiError> {
        let id = utf8_percent_encode(id, NON_ALPHANUMERIC);
        self.get(
            &format!("/v{DOCKER_API_VERSION}/images/{id}/json"),
            MAX_DOCKER_OBJECT_BYTES,
        )
        .await
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct DockerVersion {
    version: String,
    api_version: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct DockerInfo {
    cgroup_version: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    driver_status: Vec<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    security_options: Vec<String>,
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
    #[serde(default)]
    mounts: Vec<MountPoint>,
    image_manifest_descriptor: Option<ImageDescriptor>,
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
    #[serde(default, deserialize_with = "deserialize_null_default")]
    mounts: Vec<HostMount>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct HostMount {
    #[serde(rename = "Type")]
    kind: String,
    target: String,
    #[serde(default)]
    read_only: bool,
    tmpfs_options: Option<LongTmpfsOptions>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct LongTmpfsOptions {
    #[serde(default)]
    size_bytes: i64,
    #[serde(default)]
    mode: u32,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    options: Vec<Vec<String>>,
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
struct ImageDescriptor {
    digest: String,
    platform: Option<ImagePlatform>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct ImagePlatform {
    os: String,
    architecture: String,
    variant: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct ImageInspect {
    id: String,
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
    if container.image != image.id {
        return Err(ProviderFailure::Changed);
    }
    let observed_unix_millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .filter(|millis| *millis != 0)
        .ok_or(ProviderFailure::Invariant)?;
    let mounts = normalize_mounts(container)?;
    let compose = normalize_compose(&container.config.labels)?;
    let image = normalize_image(container, image)?;
    let name = container.name.strip_prefix('/').unwrap_or(&container.name);
    validate_bounded(name)?;
    Ok(wire::InstanceFact {
        provenance: Some(wire::FactBinding {
            session: None,
            realm: realm.to_string(),
            provider: wire::RuntimeKind::Docker as i32,
            observed_unix_millis,
        }),
        runtime: wire::RuntimeKind::Docker as i32,
        instance_id: container.id.clone(),
        observed_peer: Some(process.peer),
        uid_map: process.uid_map,
        gid_map: process.gid_map,
        compose,
        image: Some(image),
        mounts,
        lifecycle: normalize_lifecycle(&container.state)? as i32,
        diagnostic_runtime_name: name.to_string(),
    })
}

fn normalize_compose(
    labels: &BTreeMap<String, String>,
) -> Result<Option<wire::ComposeFact>, ProviderFailure> {
    let project = labels.get(COMPOSE_PROJECT);
    let service = labels.get(COMPOSE_SERVICE);
    match (project, service) {
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

fn normalize_image(
    container: &ContainerInspect,
    image: &ImageInspect,
) -> Result<wire::ImageFact, ProviderFailure> {
    validate_sha256(&image.id)?;
    let descriptor = container
        .image_manifest_descriptor
        .as_ref()
        .ok_or(ProviderFailure::Invariant)?;
    validate_sha256(&descriptor.digest)?;
    let mut repository_digests = image
        .repo_digests
        .iter()
        .map(|value| {
            let (_, digest) = value.rsplit_once('@').ok_or(ProviderFailure::Invariant)?;
            validate_sha256(digest)?;
            Ok(digest.to_string())
        })
        .collect::<Result<BTreeSet<_>, ProviderFailure>>()?;
    repository_digests.remove(&descriptor.digest);
    let index_digest = match repository_digests.len() {
        0 => None,
        1 => repository_digests.pop_first(),
        _ => return Err(ProviderFailure::Invariant),
    };
    let platform = descriptor.platform.as_ref();
    let os = platform.map_or(image.os.as_str(), |value| value.os.as_str());
    let architecture = platform.map_or(image.architecture.as_str(), |value| {
        value.architecture.as_str()
    });
    let variant = platform
        .and_then(|value| value.variant.as_deref())
        .or(image.variant.as_deref());
    validate_bounded(os)?;
    validate_bounded(architecture)?;
    if let Some(variant) = variant {
        validate_bounded(variant)?;
    }
    Ok(wire::ImageFact {
        index_digest,
        manifest_digest: descriptor.digest.clone(),
        config_digest: image.id.clone(),
        os: os.to_string(),
        architecture: architecture.to_string(),
        variant: variant.map(str::to_string),
    })
}

fn normalize_mounts(container: &ContainerInspect) -> Result<Vec<wire::MountFact>, ProviderFailure> {
    if container.mounts.len() > ABSOLUTE_MAX_MOUNTS_PER_INSTANCE
        || container.host_config.mounts.len() > ABSOLUTE_MAX_MOUNTS_PER_INSTANCE
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
        .map(|mount| (mount.destination.as_str(), mount.kind.as_str()))
        .collect::<BTreeMap<_, _>>();
    let configured_tmpfs = container
        .host_config
        .tmpfs
        .keys()
        .map(String::as_str)
        .chain(
            container
                .host_config
                .mounts
                .iter()
                .filter(|mount| mount.kind == "tmpfs")
                .map(|mount| mount.target.as_str()),
        )
        .collect::<BTreeSet<_>>();
    for destination in &configured_tmpfs {
        match runtime_destinations.get(destination) {
            Some(&"tmpfs") => {}
            Some(_) => return Err(ProviderFailure::Invariant),
            None => mounts.push(normalize_configured_tmpfs(
                &container.host_config,
                destination,
            )?),
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
    if mounts
        .windows(2)
        .any(|pair| {
            matches!(pair, [left, right] if left.container_destination == right.container_destination)
        })
    {
        return Err(ProviderFailure::Invariant);
    }
    Ok(mounts)
}

fn normalize_configured_tmpfs(
    host_config: &HostConfig,
    destination: &str,
) -> Result<wire::MountFact, ProviderFailure> {
    validate_bounded(destination)?;
    let tmpfs = normalized_tmpfs_options(host_config, destination)?;
    Ok(wire::MountFact {
        kind: wire::MountKind::Tmpfs as i32,
        host_source: String::new(),
        container_destination: destination.to_string(),
        read_only: tmpfs.read_only.unwrap_or(false),
        propagation: wire::MountPropagation::Private as i32,
        tmpfs_size_bytes: tmpfs.size_bytes,
        tmpfs_mode: tmpfs.mode,
        tmpfs_nodev: tmpfs.flags.contains(TmpfsFlag::Nodev),
        tmpfs_nosuid: tmpfs.flags.contains(TmpfsFlag::Nosuid),
        tmpfs_noexec: tmpfs.flags.contains(TmpfsFlag::Noexec),
        tmpfs_noswap: tmpfs.flags.contains(TmpfsFlag::Noswap),
    })
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
    let tmpfs = if kind == wire::MountKind::Tmpfs {
        normalized_tmpfs_options(host_config, &mount.destination)?
    } else {
        TmpfsProjection::default()
    };
    let observed_read_only = !mount.writable;
    if tmpfs
        .read_only
        .is_some_and(|configured| configured != observed_read_only)
    {
        return Err(ProviderFailure::Invariant);
    }
    Ok(wire::MountFact {
        kind: kind as i32,
        host_source: mount.source.clone(),
        container_destination: mount.destination.clone(),
        read_only: observed_read_only,
        propagation: propagation as i32,
        tmpfs_size_bytes: tmpfs.size_bytes,
        tmpfs_mode: tmpfs.mode,
        tmpfs_nodev: tmpfs.flags.contains(TmpfsFlag::Nodev),
        tmpfs_nosuid: tmpfs.flags.contains(TmpfsFlag::Nosuid),
        tmpfs_noexec: tmpfs.flags.contains(TmpfsFlag::Noexec),
        tmpfs_noswap: tmpfs.flags.contains(TmpfsFlag::Noswap),
    })
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct TmpfsProjection {
    size_bytes: Option<u64>,
    mode: Option<u32>,
    read_only: Option<bool>,
    flags: TmpfsFlags,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TmpfsFlag {
    Nodev,
    Nosuid,
    Noexec,
    Noswap,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct TmpfsFlags(u8);

impl TmpfsFlags {
    const fn insert(&mut self, flag: TmpfsFlag) -> bool {
        let mask = flag.mask();
        let was_absent = self.0 & mask == 0;
        self.0 |= mask;
        was_absent
    }

    const fn contains(self, flag: TmpfsFlag) -> bool {
        self.0 & flag.mask() != 0
    }
}

impl TmpfsFlag {
    const fn mask(self) -> u8 {
        match self {
            Self::Nodev => 1 << 0,
            Self::Nosuid => 1 << 1,
            Self::Noexec => 1 << 2,
            Self::Noswap => 1 << 3,
        }
    }
}

fn normalized_tmpfs_options(
    host_config: &HostConfig,
    destination: &str,
) -> Result<TmpfsProjection, ProviderFailure> {
    let short = host_config.tmpfs.get(destination);
    let mut long = host_config
        .mounts
        .iter()
        .filter(|mount| mount.kind == "tmpfs" && mount.target == destination);
    let first_long = long.next();
    if long.next().is_some() || (short.is_some() && first_long.is_some()) {
        return Err(ProviderFailure::Invariant);
    }
    let long_options = first_long.and_then(|mount| mount.tmpfs_options.as_ref());
    match (short, long_options) {
        (Some(options), None) => parse_tmpfs_options(options),
        (None, Some(options)) => {
            let mut projection = parse_long_tmpfs_options(options)?;
            projection.read_only = Some(first_long.is_some_and(|mount| mount.read_only));
            Ok(projection)
        }
        (None, None) | (Some(_), Some(_)) => Err(ProviderFailure::Invariant),
    }
}

fn parse_tmpfs_options(options: &str) -> Result<TmpfsProjection, ProviderFailure> {
    if options.len() > ABSOLUTE_MAX_STRING_BYTES || options.contains('\0') {
        return Err(ProviderFailure::ResourceExhausted);
    }
    let mut projection = TmpfsProjection::default();
    for option in options.split(',').filter(|option| !option.is_empty()) {
        if let Some(value) = option.strip_prefix("size=") {
            if projection.size_bytes.replace(parse_size(value)?).is_some() {
                return Err(ProviderFailure::Invariant);
            }
        } else if let Some(value) = option.strip_prefix("mode=")
            && projection.mode.replace(parse_mode(value)?).is_some()
        {
            return Err(ProviderFailure::Invariant);
        } else if matches!(option, "ro" | "rw") {
            if projection.read_only.replace(option == "ro").is_some() {
                return Err(ProviderFailure::Invariant);
            }
        } else {
            set_tmpfs_flag(&mut projection, option)?;
        }
    }
    Ok(projection)
}

fn parse_long_tmpfs_options(
    options: &LongTmpfsOptions,
) -> Result<TmpfsProjection, ProviderFailure> {
    let size_bytes = if options.size_bytes <= 0 {
        None
    } else {
        Some(u64::try_from(options.size_bytes).map_err(|_| ProviderFailure::Invariant)?)
    };
    let mode = if options.mode == 0 {
        None
    } else {
        Some(
            options
                .mode
                .le(&0o7777)
                .then_some(options.mode)
                .ok_or(ProviderFailure::Invariant)?,
        )
    };
    let mut projection = TmpfsProjection {
        size_bytes,
        mode,
        ..TmpfsProjection::default()
    };
    for option in &options.options {
        let name = match option.as_slice() {
            [name] => name.as_str(),
            [name, value] if value.is_empty() => name.as_str(),
            _ => return Err(ProviderFailure::Invariant),
        };
        set_tmpfs_flag(&mut projection, name)?;
    }
    Ok(projection)
}

fn set_tmpfs_flag(projection: &mut TmpfsProjection, option: &str) -> Result<(), ProviderFailure> {
    let flag = match option {
        "nodev" => TmpfsFlag::Nodev,
        "nosuid" => TmpfsFlag::Nosuid,
        "noexec" => TmpfsFlag::Noexec,
        "noswap" => TmpfsFlag::Noswap,
        // The wire projection cannot distinguish an omitted default from an
        // explicit inverse. Reject inverses instead of allowing option order
        // to turn protected mount evidence into an ambiguous boolean.
        "dev" | "suid" | "exec" | "swap" => return Err(ProviderFailure::Invariant),
        _ => return Ok(()),
    };
    if !projection.flags.insert(flag) {
        return Err(ProviderFailure::Invariant);
    }
    Ok(())
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
        "created" | "restarting" => Ok(wire::LifecycleState::Created),
        "running" if state.paused => Ok(wire::LifecycleState::Paused),
        "running" => Ok(wire::LifecycleState::Running),
        "paused" => Ok(wire::LifecycleState::Paused),
        "exited" | "dead" | "removing" => Ok(wire::LifecycleState::Exited),
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

fn require_initial_user_namespace(process: &ProcessFact) -> Result<(), ProviderFailure> {
    let identity = |ranges: &[wire::IdMapRange]| matches!(ranges, [wire::IdMapRange { inside_id: 0, outside_id: 0, length }] if *length == u32::MAX);
    if identity(&process.uid_map) && identity(&process.gid_map) {
        Ok(())
    } else {
        Err(ProviderFailure::Unsupported)
    }
}

fn docker_id_hints(cgroup: &str) -> Vec<String> {
    let mut hints = BTreeSet::new();
    for component in cgroup.split('/').filter(|component| !component.is_empty()) {
        let candidate = component
            .strip_prefix("docker-")
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

fn validate_sha256(digest: &str) -> Result<(), ProviderFailure> {
    let Some(value) = digest.strip_prefix("sha256:") else {
        return Err(ProviderFailure::Invariant);
    };
    if is_instance_id(value) {
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

fn bounded_diagnostic_version(value: &str) -> String {
    if value.is_empty() || value.len() > ABSOLUTE_MAX_STRING_BYTES || value.contains('\0') {
        "unknown".to_string()
    } else {
        value.to_string()
    }
}

fn api_version_at_least(actual: &str, minimum: &str) -> bool {
    fn parse(value: &str) -> Option<(u32, u32)> {
        let (major, minor) = value.split_once('.')?;
        Some((major.parse().ok()?, minor.parse().ok()?))
    }
    parse(actual)
        .zip(parse(minimum))
        .is_some_and(|(actual, minimum)| actual >= minimum)
}

#[cfg(test)]
mod tests {
    use std::process::Command;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    const REALM: &str = "docker-system";

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
        replacements: BTreeMap<u32, ProcessFact>,
        observations: Mutex<BTreeMap<u32, usize>>,
    }

    impl ProcessFactSource for ChangingProcesses {
        fn observe(&self, pid: u32) -> Result<ProcessFact, ProcError> {
            let use_replacement = {
                let mut observations = self.observations.lock().unwrap();
                let count = observations.entry(pid).or_default();
                *count += 1;
                let use_replacement = *count > 1;
                drop(observations);
                use_replacement
            };
            if use_replacement && let Some(replacement) = self.replacements.get(&pid) {
                return Ok(replacement.clone());
            }
            self.initial
                .get(&pid)
                .cloned()
                .ok_or(ProcError::Unavailable)
        }
    }

    struct FakeApi {
        version: Result<DockerVersion, DockerApiError>,
        info: Result<DockerInfo, DockerApiError>,
        list: Result<Vec<ContainerSummary>, DockerApiError>,
        containers: BTreeMap<String, ContainerInspect>,
        images: BTreeMap<String, ImageInspect>,
        replacements: BTreeMap<String, ContainerInspect>,
        inspections: Mutex<BTreeMap<String, usize>>,
        list_calls: AtomicUsize,
        version_calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl DockerApi for FakeApi {
        async fn version(&self) -> Result<DockerVersion, DockerApiError> {
            self.version_calls.fetch_add(1, Ordering::Relaxed);
            self.version.clone()
        }

        async fn info(&self) -> Result<DockerInfo, DockerApiError> {
            self.info.clone()
        }

        async fn list_containers(
            &self,
            _filters: &DockerFilters,
        ) -> Result<Vec<ContainerSummary>, DockerApiError> {
            self.list_calls.fetch_add(1, Ordering::Relaxed);
            self.list.clone()
        }

        async fn inspect_container(&self, id: &str) -> Result<ContainerInspect, DockerApiError> {
            let use_replacement = {
                let mut inspections = self.inspections.lock().unwrap();
                let count = inspections.entry(id.to_string()).or_default();
                *count += 1;
                let use_replacement = *count > 1;
                drop(inspections);
                use_replacement
            };
            if use_replacement && let Some(replacement) = self.replacements.get(id) {
                return Ok(replacement.clone());
            }
            self.containers
                .get(id)
                .cloned()
                .ok_or(DockerApiError::NotFound)
        }

        async fn inspect_image(&self, id: &str) -> Result<ImageInspect, DockerApiError> {
            self.images.get(id).cloned().ok_or(DockerApiError::NotFound)
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

    fn process(pid: u32, start: u64, cgroup: &str, namespace_seed: u64) -> ProcessFact {
        ProcessFact {
            peer: wire::PinnedPeer {
                pid,
                start_time_ticks: start,
                cgroup: cgroup.to_string(),
                namespaces: Some(namespaces(namespace_seed)),
            },
            uid_map: vec![wire::IdMapRange {
                inside_id: 0,
                outside_id: 0,
                length: u32::MAX,
            }],
            gid_map: vec![wire::IdMapRange {
                inside_id: 0,
                outside_id: 0,
                length: u32::MAX,
            }],
        }
    }

    fn container(instance_id: &str, pid: u32, _name: &str) -> ContainerInspect {
        let mut labels = BTreeMap::new();
        labels.insert(COMPOSE_PROJECT.to_string(), "payments".to_string());
        labels.insert(COMPOSE_SERVICE.to_string(), "api".to_string());
        labels.insert(COMPOSE_ONE_OFF.to_string(), "False".to_string());
        labels.insert(COMPOSE_ORDINAL.to_string(), "2".to_string());
        let mut tmpfs = BTreeMap::new();
        tmpfs.insert(
            "/run/basil/secrets".to_string(),
            "rw,nodev,nosuid,noexec,size=32m,mode=711".to_string(),
        );
        ContainerInspect {
            id: instance_id.to_string(),
            name: "/payments-api-2".to_string(),
            image: digest('c'),
            state: ContainerState {
                pid: i64::from(pid),
                status: "running".to_string(),
                running: true,
                paused: false,
            },
            config: ContainerConfig { labels },
            host_config: HostConfig {
                tmpfs,
                mounts: Vec::new(),
            },
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
            image_manifest_descriptor: Some(ImageDescriptor {
                digest: digest('d'),
                platform: Some(ImagePlatform {
                    os: "linux".to_string(),
                    architecture: "amd64".to_string(),
                    variant: None,
                }),
            }),
        }
    }

    fn image() -> ImageInspect {
        ImageInspect {
            id: digest('c'),
            repo_digests: vec![format!("registry.example/payments@{}", digest('e'))],
            os: "linux".to_string(),
            architecture: "amd64".to_string(),
            variant: None,
        }
    }

    fn api(containers: Vec<ContainerInspect>) -> FakeApi {
        let summaries = containers
            .iter()
            .map(|container| ContainerSummary {
                id: container.id.clone(),
            })
            .collect();
        FakeApi {
            version: Ok(DockerVersion {
                version: "29.6.1".to_string(),
                api_version: "1.53".to_string(),
            }),
            info: Ok(DockerInfo {
                cgroup_version: "2".to_string(),
                driver_status: vec![CONTAINERD_SNAPSHOTTER_DRIVER.map(str::to_string).to_vec()],
                security_options: vec!["name=apparmor".to_string()],
            }),
            list: Ok(summaries),
            containers: containers
                .into_iter()
                .map(|container| (container.id.clone(), container))
                .collect(),
            images: BTreeMap::from([(digest('c'), image())]),
            replacements: BTreeMap::new(),
            inspections: Mutex::new(BTreeMap::new()),
            list_calls: AtomicUsize::new(0),
            version_calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn provider(api: FakeApi, processes: Vec<ProcessFact>) -> DockerAttestor {
        DockerAttestor::with_sources(
            REALM,
            Arc::new(api),
            Arc::new(FakeProcesses(
                processes
                    .into_iter()
                    .map(|process| (process.peer.pid, Ok(process)))
                    .collect(),
            )),
        )
    }

    fn outcome_code<T>(reply: &ProviderReply<T>) -> wire::OutcomeCode {
        wire::OutcomeCode::try_from(reply.outcome().code).unwrap()
    }

    #[tokio::test]
    async fn health_accepts_only_rootful_cgroup_v2_without_userns_remap() {
        let healthy = provider(api(Vec::new()), Vec::new())
            .health(OPERATION_TIMEOUT)
            .await;
        assert_eq!(outcome_code(&healthy), wire::OutcomeCode::Ok);
        assert!(
            provider_capabilities()
                .iter()
                .any(|capability| capability == DOCKER_DESCRIPTOR_CAPABILITY)
        );
        assert_eq!(
            healthy.value().unwrap().runtime_mode,
            wire::RuntimeMode::Rootful as i32
        );

        let mut unsupported = api(Vec::new());
        unsupported.info.as_mut().unwrap().security_options = vec!["name=rootless".to_string()];
        unsupported.version = Err(DockerApiError::Unavailable);
        let version_calls = Arc::clone(&unsupported.version_calls);
        assert_eq!(
            outcome_code(
                &provider(unsupported, Vec::new())
                    .health(OPERATION_TIMEOUT)
                    .await,
            ),
            wire::OutcomeCode::InvalidRequest
        );
        assert_eq!(version_calls.load(Ordering::Relaxed), 0);

        for option in ["name=rootless", "name=userns"] {
            let mut unsupported = api(Vec::new());
            unsupported.info.as_mut().unwrap().security_options = vec![option.to_string()];
            let result = provider(unsupported, Vec::new())
                .health(OPERATION_TIMEOUT)
                .await;
            assert_eq!(outcome_code(&result), wire::OutcomeCode::InvalidRequest);
            assert!(result.value().is_none());
        }

        let mut cgroup_v1 = api(Vec::new());
        cgroup_v1.info.as_mut().unwrap().cgroup_version = "1".to_string();
        assert_eq!(
            outcome_code(
                &provider(cgroup_v1, Vec::new())
                    .health(OPERATION_TIMEOUT)
                    .await,
            ),
            wire::OutcomeCode::InvalidRequest
        );

        let mut old_api = api(Vec::new());
        old_api.version.as_mut().unwrap().api_version = "1.47".to_string();
        assert_eq!(
            outcome_code(
                &provider(old_api, Vec::new())
                    .health(OPERATION_TIMEOUT)
                    .await,
            ),
            wire::OutcomeCode::InvalidRequest
        );

        let mut legacy_image_store = api(Vec::new());
        legacy_image_store.info.as_mut().unwrap().driver_status =
            vec![vec!["Backing Filesystem".to_string(), "extfs".to_string()]];
        assert_eq!(
            outcome_code(
                &provider(legacy_image_store, Vec::new())
                    .health(OPERATION_TIMEOUT)
                    .await,
            ),
            wire::OutcomeCode::InvalidRequest
        );
    }

    #[tokio::test]
    async fn resolve_correlates_replica_and_exec_process_by_kernel_facts() {
        let first_id = id('a');
        let second_id = id('b');
        let first_cgroup = format!("/system.slice/docker-{first_id}.scope");
        let second_cgroup = format!("/system.slice/docker-{second_id}.scope");
        let exec_cgroup = format!("{second_cgroup}/nested.scope");
        let exec_peer = process(900, 90, &exec_cgroup, 20);
        let attestor = provider(
            api(vec![
                container(&first_id, 100, "first"),
                container(&second_id, 200, "second"),
            ]),
            vec![
                process(100, 10, &first_cgroup, 10),
                process(200, 20, &second_cgroup, 20),
                exec_peer.clone(),
            ],
        );
        let result = attestor
            .resolve_peer(&exec_peer.peer, OPERATION_TIMEOUT)
            .await;
        assert_eq!(outcome_code(&result), wire::OutcomeCode::Ok);
        let fact = result.value().unwrap();
        assert_eq!(fact.instance_id, second_id);
        assert_eq!(fact.observed_peer.as_ref(), Some(&exec_peer.peer));
        assert_eq!(fact.compose.as_ref().unwrap().replica_ordinal, Some(2));
        assert_eq!(fact.mounts.len(), 2);
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
        assert!(!tmpfs.tmpfs_noswap);
        assert_eq!(fact.image.as_ref().unwrap().index_digest, Some(digest('e')));
    }

    #[tokio::test]
    async fn resolve_rejects_pid_reuse_namespace_conflict_and_remapped_userns() {
        let instance_id = id('a');
        let cgroup = format!("/system.slice/docker-{instance_id}.scope");
        let live = process(900, 91, &cgroup, 20);
        let attestor = provider(
            api(vec![container(&instance_id, 200, "one")]),
            vec![live.clone(), process(200, 20, &cgroup, 21)],
        );
        let mut stale = live.peer.clone();
        stale.start_time_ticks = 90;
        assert_eq!(
            outcome_code(&attestor.resolve_peer(&stale, OPERATION_TIMEOUT).await),
            wire::OutcomeCode::ChangedDuringRead
        );
        assert_eq!(
            outcome_code(
                &provider(api(Vec::new()), Vec::new())
                    .resolve_peer(&live.peer, OPERATION_TIMEOUT)
                    .await,
            ),
            wire::OutcomeCode::ChangedDuringRead
        );
        assert_eq!(
            outcome_code(&attestor.resolve_peer(&live.peer, OPERATION_TIMEOUT).await),
            wire::OutcomeCode::NoMatch
        );

        let mut remapped = live;
        remapped.uid_map[0].outside_id = 100_000;
        let remapped_provider = provider(api(Vec::new()), vec![remapped.clone()]);
        assert_eq!(
            outcome_code(
                &remapped_provider
                    .resolve_peer(&remapped.peer, OPERATION_TIMEOUT)
                    .await,
            ),
            wire::OutcomeCode::InvalidRequest
        );
    }

    #[tokio::test]
    async fn resolve_reports_zero_multiple_churn_and_outage_without_fallback() {
        let peer = process(900, 90, "/shared", 20);
        let zero = provider(api(Vec::new()), vec![peer.clone()]);
        assert_eq!(
            outcome_code(&zero.resolve_peer(&peer.peer, OPERATION_TIMEOUT).await),
            wire::OutcomeCode::NoMatch
        );

        let multiple_peer = process(
            901,
            91,
            &format!(
                "/system.slice/docker-{}.scope/docker-{}.scope",
                id('a'),
                id('b')
            ),
            20,
        );
        let multiple = provider(api(Vec::new()), vec![multiple_peer.clone()]);
        assert_eq!(
            outcome_code(
                &multiple
                    .resolve_peer(&multiple_peer.peer, OPERATION_TIMEOUT)
                    .await,
            ),
            wire::OutcomeCode::MultipleMatches
        );

        let instance_id = id('a');
        let cgroup = format!("/system.slice/docker-{instance_id}.scope");
        let churn_peer = process(900, 90, &cgroup, 20);
        let mut churn_api = api(vec![container(&instance_id, 100, "one")]);
        let mut restarted = container(&instance_id, 101, "one");
        restarted.name = "/renamed".to_string();
        churn_api
            .replacements
            .insert(instance_id.clone(), restarted);
        let churn = provider(
            churn_api,
            vec![
                churn_peer.clone(),
                process(100, 10, &cgroup, 20),
                process(101, 11, &cgroup, 20),
            ],
        );
        assert_eq!(
            outcome_code(
                &churn
                    .resolve_peer(&churn_peer.peer, OPERATION_TIMEOUT)
                    .await,
            ),
            wire::OutcomeCode::ChangedDuringRead
        );

        let vanished_peer = process(902, 92, &cgroup, 20);
        let vanished = provider(api(Vec::new()), vec![vanished_peer.clone()]);
        assert_eq!(
            outcome_code(
                &vanished
                    .resolve_peer(&vanished_peer.peer, OPERATION_TIMEOUT)
                    .await,
            ),
            wire::OutcomeCode::ChangedDuringRead
        );

        let mut unavailable = api(Vec::new());
        unavailable.info = Err(DockerApiError::Unavailable);
        assert_eq!(
            outcome_code(
                &provider(unavailable, vec![peer.clone()])
                    .resolve_peer(&peer.peer, OPERATION_TIMEOUT)
                    .await
            ),
            wire::OutcomeCode::Unavailable
        );
    }

    #[tokio::test]
    async fn inventory_enforces_the_thousand_instance_absolute_bound() {
        let mut bounded_api = api(Vec::new());
        bounded_api.list = Ok((0..=ABSOLUTE_MAX_INSTANCES)
            .map(|index| ContainerSummary {
                id: format!("{index:064x}"),
            })
            .collect());
        let result = provider(bounded_api, Vec::new())
            .query_instances(&QueryScope::GlobalDoctor, OPERATION_TIMEOUT)
            .await;
        assert_eq!(outcome_code(&result), wire::OutcomeCode::ResourceExhausted);
        assert!(result.value().is_none());

        let mut accepted_api = api(Vec::new());
        accepted_api.list = Ok((0..ABSOLUTE_MAX_INSTANCES)
            .map(|index| ContainerSummary {
                id: format!("{index:064x}"),
            })
            .collect());
        let accepted = provider(accepted_api, Vec::new())
            .query_instances(&QueryScope::GlobalDoctor, OPERATION_TIMEOUT)
            .await;
        assert_eq!(
            outcome_code(&accepted),
            wire::OutcomeCode::ChangedDuringRead
        );
        assert!(accepted.value().is_none());
    }

    #[tokio::test]
    async fn inventory_returns_sorted_bounded_facts_and_rejects_cross_realm_scope() {
        let first_id = id('a');
        let second_id = id('b');
        let first_cgroup = format!("/system.slice/docker-{first_id}.scope");
        let second_cgroup = format!("/system.slice/docker-{second_id}.scope");
        let attestor = provider(
            api(vec![
                container(&second_id, 200, "second"),
                container(&first_id, 100, "first"),
            ]),
            vec![
                process(100, 10, &first_cgroup, 10),
                process(200, 20, &second_cgroup, 20),
            ],
        );
        let result = attestor
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
        let wrong_realm = attestor
            .query_instances(
                &QueryScope::Project {
                    realm: "other".to_string(),
                    project: "payments".to_string(),
                },
                OPERATION_TIMEOUT,
            )
            .await;
        assert_eq!(
            outcome_code(&wrong_realm),
            wire::OutcomeCode::InvalidRequest
        );

        let mut partial_api = api(vec![container(&first_id, 100, "first")]);
        partial_api.list = Ok(vec![
            ContainerSummary {
                id: first_id.clone(),
            },
            ContainerSummary {
                id: second_id.clone(),
            },
        ]);
        let partial = provider(partial_api, vec![process(100, 10, &first_cgroup, 10)])
            .query_instances(&QueryScope::GlobalDoctor, OPERATION_TIMEOUT)
            .await;
        assert_eq!(outcome_code(&partial), wire::OutcomeCode::ChangedDuringRead);
    }

    #[tokio::test]
    async fn resolve_reobserves_peer_and_init_after_the_final_runtime_read() {
        let instance_id = id('a');
        let cgroup = format!("/system.slice/docker-{instance_id}.scope");
        let initial_peer = process(900, 90, &cgroup, 20);
        let initial_init = process(100, 10, &cgroup, 20);
        for changed_pid in [900, 100] {
            let mut replacement = if changed_pid == 900 {
                initial_peer.clone()
            } else {
                initial_init.clone()
            };
            replacement.peer.start_time_ticks += 1;
            let processes = ChangingProcesses {
                initial: BTreeMap::from([(900, initial_peer.clone()), (100, initial_init.clone())]),
                replacements: BTreeMap::from([(changed_pid, replacement)]),
                observations: Mutex::new(BTreeMap::new()),
            };
            let provider = DockerAttestor::with_sources(
                REALM,
                Arc::new(api(vec![container(&instance_id, 100, "one")])),
                Arc::new(processes),
            );
            let result = provider
                .resolve_peer(&initial_peer.peer, OPERATION_TIMEOUT)
                .await;
            assert_eq!(outcome_code(&result), wire::OutcomeCode::ChangedDuringRead);
        }
    }

    #[tokio::test]
    async fn resolve_uses_the_cgroup_index_at_one_thousand_container_scale() {
        let instance_id = id('a');
        let cgroup = format!("/system.slice/docker-{instance_id}.scope");
        let peer = process(900, 90, &cgroup, 20);
        let mut fake_api = api(vec![container(&instance_id, 100, "one")]);
        fake_api.list = Ok((0..ABSOLUTE_MAX_INSTANCES)
            .map(|index| ContainerSummary {
                id: format!("{index:064x}"),
            })
            .collect());
        let fake_api = Arc::new(fake_api);
        let provider = DockerAttestor::with_sources(
            REALM,
            fake_api.clone(),
            Arc::new(FakeProcesses(BTreeMap::from([
                (900, Ok(peer.clone())),
                (100, Ok(process(100, 10, &cgroup, 20))),
            ]))),
        );
        let result = provider.resolve_peer(&peer.peer, OPERATION_TIMEOUT).await;
        assert_eq!(outcome_code(&result), wire::OutcomeCode::Ok);
        assert_eq!(fake_api.list_calls.load(Ordering::Relaxed), 0);
        assert_eq!(
            fake_api
                .inspections
                .lock()
                .unwrap()
                .get(&instance_id)
                .copied(),
            Some(2)
        );
    }

    #[test]
    fn long_form_tmpfs_options_preserve_the_closed_security_projection() {
        let mut container = container(&id('a'), 100, "one");
        container.host_config.tmpfs.clear();
        container.host_config.mounts.push(HostMount {
            kind: "tmpfs".to_string(),
            target: "/run/basil/secrets".to_string(),
            read_only: false,
            tmpfs_options: Some(LongTmpfsOptions {
                size_bytes: 32 * 1024 * 1024,
                mode: 0o711,
                options: vec![
                    vec!["nodev".to_string()],
                    vec!["nosuid".to_string(), String::new()],
                    vec!["noexec".to_string()],
                    vec!["noswap".to_string()],
                ],
            }),
        });
        let mounts = normalize_mounts(&container).unwrap();
        let tmpfs = mounts
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

    #[test]
    fn host_config_tmpfs_is_projected_when_runtime_mounts_omit_it() {
        let mut container = container(&id('a'), 100, "one");
        container.mounts.retain(|mount| mount.kind != "tmpfs");
        let mounts = normalize_mounts(&container).unwrap();
        let tmpfs = mounts
            .iter()
            .find(|mount| mount.container_destination == "/run/basil/secrets")
            .unwrap();
        assert_eq!(tmpfs.kind, wire::MountKind::Tmpfs as i32);
        assert!(!tmpfs.read_only);
        assert_eq!(tmpfs.tmpfs_size_bytes, Some(32 * 1024 * 1024));
        assert_eq!(tmpfs.tmpfs_mode, Some(0o711));
        assert!(tmpfs.tmpfs_nodev);
        assert!(tmpfs.tmpfs_nosuid);
        assert!(tmpfs.tmpfs_noexec);
    }

    #[test]
    fn tmpfs_inverse_and_conflicting_security_options_are_rejected() {
        for (protected, inverse) in [
            ("nodev", "dev"),
            ("nosuid", "suid"),
            ("noexec", "exec"),
            ("noswap", "swap"),
        ] {
            for options in [
                inverse.to_string(),
                format!("{protected},{inverse}"),
                format!("{inverse},{protected}"),
            ] {
                assert_eq!(
                    parse_tmpfs_options(&options),
                    Err(ProviderFailure::Invariant),
                    "short-form options {options:?} must be rejected"
                );
            }
            for options in [
                vec![vec![inverse.to_string()]],
                vec![vec![protected.to_string()], vec![inverse.to_string()]],
                vec![vec![inverse.to_string()], vec![protected.to_string()]],
            ] {
                assert_eq!(
                    parse_long_tmpfs_options(&LongTmpfsOptions {
                        size_bytes: 0,
                        mode: 0,
                        options: options.clone(),
                    }),
                    Err(ProviderFailure::Invariant),
                    "long-form options {options:?} must be rejected"
                );
            }
        }
    }

    #[tokio::test]
    #[ignore = "requires a supported rootful Docker daemon at the production socket"]
    async fn live_rootful_docker_health_uses_the_unix_api() {
        let provider = DockerAttestor::new(REALM, "/var/run/docker.sock").unwrap();
        let health = provider.health(OPERATION_TIMEOUT).await;
        assert_eq!(outcome_code(&health), wire::OutcomeCode::Ok);
        assert_eq!(
            health.value().unwrap().cgroup_mode,
            wire::CgroupMode::V2 as i32
        );
    }

    fn docker_command(arguments: &[&str]) -> String {
        let output = Command::new("docker").args(arguments).output().unwrap();
        assert!(
            output.status.success(),
            "docker {arguments:?} failed: {}",
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
                "docker ps -aq --filter label=io.openbasil.attestor-acceptance | xargs -r docker rm -f >/dev/null",
            ])
            .status();
    }

    struct AcceptanceCleanup;

    impl Drop for AcceptanceCleanup {
        fn drop(&mut self) {
            remove_acceptance_containers();
        }
    }

    fn live_provider() -> DockerAttestor {
        let socket = std::env::var_os("BASIL_DOCKER_SOCKET")
            .unwrap_or_else(|| "/var/run/docker.sock".into());
        DockerAttestor::new(REALM, socket).unwrap()
    }

    #[tokio::test]
    #[ignore = "requires the Compose Phase 1 rootful Docker acceptance guest"]
    #[allow(clippy::too_many_lines)]
    async fn live_rootful_docker_acceptance_matrix() {
        remove_acceptance_containers();
        let _cleanup = AcceptanceCleanup;
        let provider = live_provider();
        assert_eq!(
            outcome_code(&provider.health(OPERATION_TIMEOUT).await),
            wire::OutcomeCode::Ok
        );

        let common_labels = [
            "--label",
            "io.openbasil.attestor-acceptance=core",
            "--label",
            "com.docker.compose.project=basil-attestor",
            "--label",
            "com.docker.compose.service=api",
            "--label",
            "com.docker.compose.oneoff=False",
        ];
        let mut first_arguments = vec!["run", "-d", "--name", "basil-attestor-one"];
        first_arguments.extend(common_labels);
        first_arguments.extend([
            "--label",
            "com.docker.compose.container-number=1",
            "--tmpfs",
            "/run/basil/secrets:rw,nodev,nosuid,noexec,size=4096,mode=0700",
            "basil-smoke/alpine:smoke",
            "sleep",
            "600",
        ]);
        let first_id = docker_command(&first_arguments);
        let mut second_arguments = vec!["run", "-d", "--name", "basil-attestor-two"];
        second_arguments.extend(common_labels);
        second_arguments.extend([
            "--label",
            "com.docker.compose.container-number=2",
            "basil-smoke/alpine:smoke",
            "sleep",
            "600",
        ]);
        let second_id = docker_command(&second_arguments);

        let inventory = provider
            .query_instances(
                &QueryScope::Service {
                    realm: REALM.to_string(),
                    project: "basil-attestor".to_string(),
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
        let secret_mount = instances
            .iter()
            .find(|instance| instance.instance_id == first_id)
            .unwrap()
            .mounts
            .iter()
            .find(|mount| mount.container_destination == "/run/basil/secrets")
            .unwrap();
        assert!(secret_mount.tmpfs_nodev);
        assert!(secret_mount.tmpfs_nosuid);
        assert!(secret_mount.tmpfs_noexec);

        docker_command(&["exec", "-d", "basil-attestor-two", "sleep", "300"]);
        let mut exec_pid = None;
        for _ in 0..30 {
            let top = docker_command(&["top", "basil-attestor-two", "-eo", "pid,args"]);
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
        let exec_pid = exec_pid.expect("exec PID must be visible in Docker top output");
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
        let host_process = provider.processes.observe(std::process::id()).unwrap();
        assert_eq!(
            outcome_code(
                &provider
                    .resolve_peer(&host_process.peer, OPERATION_TIMEOUT)
                    .await,
            ),
            wire::OutcomeCode::NoMatch
        );

        docker_command(&["restart", "basil-attestor-two"]);
        let mut restart_changed = false;
        for _ in 0..30 {
            match outcome_code(
                &provider
                    .resolve_peer(&exec_process.peer, OPERATION_TIMEOUT)
                    .await,
            ) {
                wire::OutcomeCode::ChangedDuringRead => {
                    restart_changed = true;
                    break;
                }
                wire::OutcomeCode::Unavailable => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                outcome => panic!("unexpected restart/churn outcome: {outcome:?}"),
            }
        }
        assert!(restart_changed);
    }

    #[tokio::test]
    #[ignore = "creates 1,001 containers in the Compose Phase 1 capacity-sized guest"]
    async fn live_rootful_docker_inventory_bound() {
        remove_acceptance_containers();
        let _cleanup = AcceptanceCleanup;
        shell_command(
            "seq 1 1000 | xargs -P 64 -I{} docker run -d --name basil-attestor-scale-{} \
             --label io.openbasil.attestor-acceptance=scale \
             --label com.docker.compose.project=basil-attestor-scale \
             --label com.docker.compose.service=scale \
             --label com.docker.compose.oneoff=False \
             basil-smoke/alpine:smoke sleep 900 >/dev/null",
        );
        let provider = live_provider();
        let scope = QueryScope::Project {
            realm: REALM.to_string(),
            project: "basil-attestor-scale".to_string(),
        };
        let inventory = provider.query_instances(&scope, OPERATION_TIMEOUT).await;
        assert_eq!(outcome_code(&inventory), wire::OutcomeCode::Ok);
        assert_eq!(inventory.value().unwrap().len(), ABSOLUTE_MAX_INSTANCES);

        docker_command(&[
            "run",
            "-d",
            "--name",
            "basil-attestor-scale-overflow",
            "--label",
            "io.openbasil.attestor-acceptance=scale",
            "--label",
            "com.docker.compose.project=basil-attestor-scale",
            "--label",
            "com.docker.compose.service=scale",
            "--label",
            "com.docker.compose.oneoff=False",
            "basil-smoke/alpine:smoke",
            "sleep",
            "900",
        ]);
        assert_eq!(
            outcome_code(&provider.query_instances(&scope, OPERATION_TIMEOUT).await),
            wire::OutcomeCode::ResourceExhausted
        );
    }

    #[tokio::test]
    #[ignore = "requires a live unsupported Docker daemon at the production socket"]
    async fn live_docker_rejects_rootless_or_userns_remap() {
        assert_eq!(
            outcome_code(&live_provider().health(OPERATION_TIMEOUT).await),
            wire::OutcomeCode::InvalidRequest
        );
    }

    #[tokio::test]
    #[ignore = "stops and restarts Docker in the Compose Phase 1 acceptance guest"]
    async fn live_docker_outage_is_typed_and_recovers() {
        let provider = live_provider();
        let stop = Command::new("systemctl")
            .args(["stop", "docker.socket", "docker.service"])
            .status()
            .unwrap();
        assert!(stop.success());
        assert_eq!(
            outcome_code(&provider.health(OPERATION_TIMEOUT).await),
            wire::OutcomeCode::Unavailable
        );
        let start = Command::new("systemctl")
            .args(["start", "docker.service"])
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

    #[test]
    fn docker_json_uses_oci_descriptor_casing_and_null_collections() {
        let fixture = format!(
            r#"{{
                "Id":"{}","Name":"/api","Image":"{}",
                "State":{{"Pid":42,"Status":"running","Running":true,"Paused":false}},
                "Config":{{"Labels":null}},
                "HostConfig":{{"Tmpfs":null,"Mounts":[{{"Type":"tmpfs","Target":"/run/basil/secrets","TmpfsOptions":{{"SizeBytes":33554432,"Mode":457,"Options":[["noswap",""]]}}}}]}},
                "Mounts":[],
                "ImageManifestDescriptor":{{"digest":"{}","platform":{{"os":"linux","architecture":"arm64","variant":"v8"}}}}
            }}"#,
            id('a'),
            digest('c'),
            digest('d')
        );
        let parsed: ContainerInspect = serde_json::from_str(&fixture).unwrap();
        assert!(parsed.config.labels.is_empty());
        assert!(parsed.host_config.tmpfs.is_empty());
        assert_eq!(parsed.host_config.mounts.len(), 1);
        assert_eq!(
            parsed.host_config.mounts[0]
                .tmpfs_options
                .as_ref()
                .unwrap()
                .options,
            [vec!["noswap".to_string(), String::new()]]
        );
        assert_eq!(
            parsed
                .image_manifest_descriptor
                .unwrap()
                .platform
                .unwrap()
                .architecture,
            "arm64"
        );

        let image_fixture = format!(
            r#"{{"Id":"{}","RepoDigests":null,"Os":"linux","Architecture":"amd64","Variant":null}}"#,
            digest('c')
        );
        let parsed: ImageInspect = serde_json::from_str(&image_fixture).unwrap();
        assert!(parsed.repo_digests.is_empty());
    }

    #[test]
    fn version_and_cgroup_hints_are_strict() {
        assert!(api_version_at_least("1.48", "1.48"));
        assert!(api_version_at_least("1.53", "1.48"));
        assert!(!api_version_at_least("1.47", "1.48"));
        assert!(!api_version_at_least("invalid", "1.48"));
        let instance_id = id('a');
        assert_eq!(
            docker_id_hints(&format!("/system.slice/docker-{instance_id}.scope")),
            [instance_id]
        );
        assert!(docker_id_hints("/system.slice/docker-short.scope").is_empty());
        assert!(cgroup_is_same_or_descendant("/docker/a/child", "/docker/a"));
        assert!(!cgroup_is_same_or_descendant("/docker/ab", "/docker/a"));
    }
}
