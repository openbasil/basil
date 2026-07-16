// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Provider-independent runtime-attestor realm configuration and supervision.
//!
//! Realm configuration is trusted routing authority. This module validates the
//! protected schema, keeps one serial session per realm, and provides the
//! failure-atomic preparation boundary used by configuration reload. Provider
//! evidence collection remains behind [`RealmConnector`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use thiserror::Error;
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::{Notify, watch};

use crate::attestor_protocol::wire;
use crate::attestor_protocol::{
    InventoryResult, QueryScope, ResolvePeerResult, VerifiedPeerBinding,
};
use crate::release_admission::{
    ActiveArtifact, ArtifactRole, CapabilityId, CapabilitySet, ProtocolVersion, ReleaseAdmission,
    ReleaseIdentity, Sha256Digest, TargetTriple,
};

/// Maximum number of configured attestor realms.
pub const MAX_REALMS: usize = 64;
/// Maximum byte length of one canonical realm name.
pub const MAX_REALM_NAME_BYTES: usize = 63;
/// Maximum byte length of one canonical service unit.
pub const MAX_UNIT_NAME_BYTES: usize = 128;
/// Linux `sockaddr_un.sun_path` payload limit, including the trailing NUL.
pub const MAX_SOCKET_PATH_BYTES: usize = 107;
/// Protocol 1's complete required capability vocabulary.
pub const REQUIRED_CAPABILITIES: [&str; 3] = ["health", "query-instances", "resolve-peer"];

const CONNECT_STEP_TIMEOUT: Duration = Duration::from_secs(5);
const INITIAL_RECONNECT_BACKOFF: Duration = Duration::from_millis(250);
const MAX_RECONNECT_BACKOFF: Duration = Duration::from_secs(30);
const MAX_RECONNECT_JITTER_MILLIS: u64 = 250;

/// A canonical protected attestor realm name.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RealmName(String);

impl RealmName {
    /// Validate and copy one realm name.
    ///
    /// # Errors
    ///
    /// Returns [`RealmConfigError`] when the name is empty, overlong, or not in
    /// the closed lowercase ASCII grammar.
    pub fn new(raw: &str) -> Result<Self, RealmConfigError> {
        let bytes = raw.as_bytes();
        let valid_edge = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
        let valid_inner = |byte: u8| valid_edge(byte) || matches!(byte, b'_' | b'-');
        let valid = !bytes.is_empty()
            && bytes.len() <= MAX_REALM_NAME_BYTES
            && bytes.first().copied().is_some_and(valid_edge)
            && bytes.last().copied().is_some_and(valid_edge)
            && bytes.iter().copied().all(valid_inner);
        if !valid {
            return Err(RealmConfigError::InvalidRealmName(raw.to_string()));
        }
        Ok(Self(raw.to_string()))
    }

    /// Borrow the canonical name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RealmName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One canonical decimal user identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmUser {
    spelling: String,
    uid: u32,
}

impl RealmUser {
    fn parse(field: &'static str, raw: &str) -> Result<Self, RealmConfigError> {
        if raw.is_empty() || raw.len() > 10 || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(RealmConfigError::InvalidUid {
                field,
                value: raw.to_string(),
            });
        }
        let uid = raw
            .parse::<u32>()
            .map_err(|_| RealmConfigError::InvalidUid {
                field,
                value: raw.to_string(),
            })?;
        if uid.to_string() != raw {
            return Err(RealmConfigError::InvalidUid {
                field,
                value: raw.to_string(),
            });
        }
        Ok(Self {
            spelling: raw.to_string(),
            uid,
        })
    }

    /// Return the parsed user ID.
    #[must_use]
    pub const fn uid(&self) -> u32 {
        self.uid
    }

    /// Borrow the protected canonical spelling.
    #[must_use]
    pub fn spelling(&self) -> &str {
        &self.spelling
    }
}

/// Closed runtime-attestor provider set.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum RealmProvider {
    /// Rootful Docker provider.
    Docker,
    /// Rootless Podman provider.
    Podman,
}

impl RealmProvider {
    const fn wire_runtime(self) -> wire::RuntimeKind {
        match self {
            Self::Docker => wire::RuntimeKind::Docker,
            Self::Podman => wire::RuntimeKind::Podman,
        }
    }
}

/// Closed provider account and service-manager scope.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum RealmMode {
    /// Dedicated host service managed by the system manager.
    RootfulHost,
    /// Non-root runtime owner managed by that user's manager.
    RootlessOwner,
}

impl RealmMode {
    const fn wire_runtime(self) -> wire::RuntimeMode {
        match self {
            Self::RootfulHost => wire::RuntimeMode::Rootful,
            Self::RootlessOwner => wire::RuntimeMode::Rootless,
        }
    }
}

/// Fully validated protected configuration for one realm.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmConfig {
    /// Closed attestor provider.
    pub provider: RealmProvider,
    /// Provider account and service-manager scope.
    pub runtime_mode: RealmMode,
    /// Exact broker account.
    pub broker_user: RealmUser,
    /// Exact broker service unit.
    pub broker_unit: String,
    /// Exact attestor account and rootless routing scope.
    pub attestor_user: RealmUser,
    /// Exact attestor service unit.
    pub attestor_unit: String,
    /// Canonical private control socket.
    pub socket_path: PathBuf,
    /// Required release artifact role.
    pub release_role: ArtifactRole,
    /// Required release target.
    pub target: TargetTriple,
    /// Exact private protocol version.
    pub protocol: ProtocolVersion,
    /// Sorted complete protocol capability set.
    pub capabilities: CapabilitySet,
}

/// Bounded protected realm map in deterministic name order.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RealmSet(BTreeMap<RealmName, RealmConfig>);

impl RealmSet {
    /// Parse the optional `attestor` object from one schema-3 bootstrap value.
    ///
    /// # Errors
    ///
    /// Returns [`RealmConfigError`] for unknown fields, invalid types, bounds,
    /// identifiers, provider/mode combinations, or socket/account mismatch.
    pub fn from_bootstrap(value: &toml::Value) -> Result<Self, RealmConfigError> {
        let Some(raw) = value.get("attestor") else {
            return Ok(Self::default());
        };
        let document: RawAttestor = raw
            .clone()
            .try_into()
            .map_err(|error: toml::de::Error| RealmConfigError::Schema(error.to_string()))?;
        if document.realms.len() > MAX_REALMS {
            return Err(RealmConfigError::TooManyRealms {
                maximum: MAX_REALMS,
            });
        }
        let mut realms = BTreeMap::new();
        for (raw_name, raw_config) in document.realms {
            let name = RealmName::new(&raw_name)?;
            let config = raw_config.validate(&name)?;
            realms.insert(name, config);
        }
        Ok(Self(realms))
    }

    /// Return the number of configured realms.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether no realm is configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Borrow one exact realm configuration.
    #[must_use]
    pub fn get(&self, name: &RealmName) -> Option<&RealmConfig> {
        self.0.get(name)
    }

    /// Iterate in canonical realm-name order.
    #[must_use]
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&RealmName, &RealmConfig)> {
        self.0.iter()
    }

    /// Verify that every protected realm names the broker's pinned effective
    /// user ID.
    ///
    /// # Errors
    ///
    /// Returns [`RealmConfigError::BrokerUidMismatch`] on the first mismatch.
    pub fn validate_broker_uid(&self, effective_uid: u32) -> Result<(), RealmConfigError> {
        if self
            .0
            .values()
            .all(|config| config.broker_user.uid() == effective_uid)
        {
            Ok(())
        } else {
            Err(RealmConfigError::BrokerUidMismatch)
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAttestor {
    #[serde(default)]
    realms: BTreeMap<String, RawRealmConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawRealmConfig {
    provider: RealmProvider,
    runtime_mode: RealmMode,
    broker_user: String,
    broker_unit: String,
    attestor_user: String,
    attestor_unit: String,
    socket_path: String,
    release_role: String,
    target: String,
    protocol: u32,
    capabilities: Vec<String>,
}

impl RawRealmConfig {
    fn validate(self, name: &RealmName) -> Result<RealmConfig, RealmConfigError> {
        if !matches!(
            (self.provider, self.runtime_mode),
            (RealmProvider::Docker, RealmMode::RootfulHost)
                | (RealmProvider::Podman, RealmMode::RootlessOwner)
        ) {
            return Err(RealmConfigError::ProviderMode {
                provider: self.provider,
                mode: self.runtime_mode,
            });
        }
        let broker_user = RealmUser::parse("brokerUser", &self.broker_user)?;
        let attestor_user = RealmUser::parse("attestorUser", &self.attestor_user)?;
        validate_unit("brokerUnit", &self.broker_unit)?;
        validate_unit("attestorUnit", &self.attestor_unit)?;
        if self.runtime_mode == RealmMode::RootlessOwner && attestor_user.uid() == 0 {
            return Err(RealmConfigError::RootlessRoot);
        }
        let expected_socket = match self.runtime_mode {
            RealmMode::RootfulHost => PathBuf::from(format!(
                "/run/basil/attestors/{}/control.sock",
                name.as_str()
            )),
            RealmMode::RootlessOwner => PathBuf::from(format!(
                "/run/user/{}/basil/attestors/{}/control.sock",
                attestor_user.uid(),
                name.as_str()
            )),
        };
        validate_socket_path(&self.socket_path)?;
        let socket_path = PathBuf::from(&self.socket_path);
        if socket_path != expected_socket {
            return Err(RealmConfigError::SocketScope {
                expected: expected_socket,
            });
        }
        if self.protocol != 1 {
            return Err(RealmConfigError::UnsupportedProtocol(self.protocol));
        }
        let capabilities = CapabilitySet::try_from_iter(
            self.capabilities
                .iter()
                .map(|item| CapabilityId::new(item))
                .collect::<Result<Vec<_>, _>>()?,
        )?;
        let actual = capabilities
            .iter()
            .map(CapabilityId::as_str)
            .collect::<Vec<_>>();
        if actual != REQUIRED_CAPABILITIES {
            return Err(RealmConfigError::Capabilities);
        }
        Ok(RealmConfig {
            provider: self.provider,
            runtime_mode: self.runtime_mode,
            broker_user,
            broker_unit: self.broker_unit,
            attestor_user,
            attestor_unit: self.attestor_unit,
            socket_path,
            release_role: ArtifactRole::new(&self.release_role)?,
            target: TargetTriple::new(&self.target)?,
            protocol: ProtocolVersion::new(self.protocol)?,
            capabilities,
        })
    }
}

fn validate_unit(field: &'static str, unit: &str) -> Result<(), RealmConfigError> {
    let valid = !unit.is_empty()
        && unit.len() <= MAX_UNIT_NAME_BYTES
        && unit.ends_with(".service")
        && unit.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'.' | b'@' | b'-')
        })
        && !unit.contains("..")
        && !unit.contains("\\x");
    if valid {
        Ok(())
    } else {
        Err(RealmConfigError::InvalidUnit {
            field,
            value: unit.to_string(),
        })
    }
}

fn validate_socket_path(path: &str) -> Result<(), RealmConfigError> {
    let valid = !path.is_empty()
        && path.len() <= MAX_SOCKET_PATH_BYTES
        && path.starts_with('/')
        && !path.contains('\0')
        && !path.contains("//")
        && Path::new(path).components().all(|component| {
            matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        });
    if valid {
        Ok(())
    } else {
        Err(RealmConfigError::InvalidSocketPath)
    }
}

/// Typed strict realm-configuration failure.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RealmConfigError {
    /// The `attestor` object did not match its strict schema.
    #[error("invalid `attestor` schema: {0}")]
    Schema(String),
    /// More realms were supplied than the compiled ceiling.
    #[error("realm count exceeds maximum {maximum}")]
    TooManyRealms {
        /// Compiled maximum.
        maximum: usize,
    },
    /// A realm name was not canonical.
    #[error("invalid realm name `{0}`")]
    InvalidRealmName(String),
    /// A UID field did not use canonical decimal form.
    #[error("`{field}` is not a canonical decimal UID")]
    InvalidUid {
        /// Schema field.
        field: &'static str,
        /// Rejected value, retained only in the local typed error.
        value: String,
    },
    /// A service unit was not canonical.
    #[error("`{field}` is not a canonical systemd service unit")]
    InvalidUnit {
        /// Schema field.
        field: &'static str,
        /// Rejected value, retained only in the local typed error.
        value: String,
    },
    /// The provider/mode pair is outside the closed matrix.
    #[error("provider `{provider:?}` does not support mode `{mode:?}`")]
    ProviderMode {
        /// Configured provider.
        provider: RealmProvider,
        /// Configured mode.
        mode: RealmMode,
    },
    /// Rootless mode selected UID 0.
    #[error("rootless attestor UID must be nonzero")]
    RootlessRoot,
    /// A realm names a broker account other than the pinned process account.
    #[error("configured broker UID does not match the pinned effective UID")]
    BrokerUidMismatch,
    /// The socket path was not absolute and normalized.
    #[error("socket path is not absolute, normalized, and within the Linux bound")]
    InvalidSocketPath,
    /// The socket did not match the account scope and realm.
    #[error("socket path does not match the protected realm scope")]
    SocketScope {
        /// Required path, retained for trusted configuration diagnostics.
        expected: PathBuf,
    },
    /// Protocol 1 is the only accepted protocol.
    #[error("unsupported attestor protocol `{0}`")]
    UnsupportedProtocol(u32),
    /// Protocol 1 requires its exact complete capability vocabulary.
    #[error("protocol 1 capabilities must contain exactly the required vocabulary")]
    Capabilities,
    /// A release-admission identity was invalid.
    #[error(transparent)]
    Identity(#[from] crate::release_admission::IdentityError),
    /// A capability collection was invalid.
    #[error(transparent)]
    Collection(#[from] crate::release_admission::CollectionError),
}

/// Stable socket identity captured without following a replacement path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SocketIdentity {
    /// Filesystem device.
    pub device: u64,
    /// Socket inode.
    pub inode: u64,
    /// Socket owner.
    pub owner: u32,
    /// Permission bits.
    pub mode: u32,
}

/// Public realm serving state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealmState {
    /// Expected socket is absent.
    Absent,
    /// Connecting to the configured socket.
    Connecting,
    /// Authenticating the peer and admitted artifact.
    Authenticating,
    /// Binding the private protocol session.
    Handshaking,
    /// Qualifying provider health.
    HealthChecking,
    /// The accepted session can serve.
    Ready,
    /// The accepted session failed closed.
    Degraded,
    /// Same-socket qualification has no serving session.
    Staging,
    /// A removed session is draining.
    Draining,
}

/// Disclosure-safe reason for one realm state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealmReason {
    /// No failure.
    None,
    /// Configured socket is absent.
    SocketAbsent,
    /// Connection has not completed.
    Connecting,
    /// Peer authentication failed.
    AuthenticationFailed,
    /// Release admission failed.
    AdmissionFailed,
    /// Private protocol failed.
    ProtocolFailed,
    /// Provider health failed.
    HealthFailed,
    /// Accepted authority is draining.
    Draining,
}

/// Disclosure-safe status for one accepted realm.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmStatus {
    /// Canonical protected realm name.
    pub name: RealmName,
    /// Closed provider.
    pub provider: RealmProvider,
    /// Closed runtime mode.
    pub mode: RealmMode,
    /// Public serving-state projection.
    pub state: RealmState,
    /// Accepted configuration generation.
    pub generation: u64,
    /// Current authoritative session epoch, or zero before first success.
    pub session_epoch: u64,
    /// Exact private protocol version.
    pub protocol: u32,
    /// Coarse disclosure-safe reason.
    pub reason: RealmReason,
}

/// Aggregate ungated realm readiness partition.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RealmReadiness {
    /// Accepted realms.
    pub total: u32,
    /// Accepted realms projected ready.
    pub ready: u32,
    /// Accepted non-ready, non-absent realms.
    pub degraded: u32,
    /// Accepted absent realms.
    pub absent: u32,
}

/// Provider-independent session failure.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RealmError {
    /// The configured socket is absent.
    #[error("attestor socket is absent")]
    SocketAbsent,
    /// Connecting failed without provider detail disclosure.
    #[error("attestor connection failed")]
    Connect,
    /// Peer/account/unit authentication failed.
    #[error("attestor authentication failed")]
    Authentication,
    /// Release admission failed.
    #[error("attestor release admission failed")]
    Admission,
    /// Protocol binding or response validation failed.
    #[error("attestor protocol failed")]
    Protocol,
    /// Health qualification failed.
    #[error("attestor health qualification failed")]
    Health,
    /// A generation, revision, epoch, actor, or preparation token went stale.
    #[error("attestor realm result is stale")]
    Stale,
    /// The realm is not ready to serve.
    #[error("attestor realm is unavailable")]
    Unavailable,
    /// A checked monotonic counter was exhausted.
    #[error("attestor realm counter exhausted")]
    CounterExhausted,
    /// Another preparation owns an affected realm.
    #[error("attestor realm preparation conflicts with an active preparation")]
    PreparationConflict,
    /// A serial supervisor already owns this realm.
    #[error("attestor realm supervisor is already running")]
    SupervisorRunning,
    /// Dry-run cannot activate a same-socket security change.
    #[error("same-socket realm change requires live qualification")]
    QualificationRequired,
}

/// One measured and admitted provider connection before protocol handshake.
#[async_trait]
pub trait RealmConnection: Send {
    /// Authenticate the peer and return a session holding one active release
    /// guard. Implementations must repeat all checks for every connection.
    async fn authenticate(
        self: Box<Self>,
        config: &RealmConfig,
        generation: u64,
        epoch: u64,
        admission: &ReleaseAdmission,
    ) -> Result<AuthenticatedRealmSession, RealmError>;

    /// Close an unauthenticated connection during cancellation or failure.
    async fn close(self: Box<Self>);
}

/// Provider seam that opens only the one protected configured socket.
///
/// The interface deliberately has no discovery, listener, registration, path
/// mutation, or stale-socket unlink operation.
#[async_trait]
pub trait RealmConnector: Send + Sync {
    /// Open the configured outbound control socket and pin its identity.
    async fn connect(&self, config: &RealmConfig) -> Result<Box<dyn RealmConnection>, RealmError>;

    /// Revalidate one staged socket identity before atomic commit.
    async fn revalidate(
        &self,
        config: &RealmConfig,
        identity: SocketIdentity,
    ) -> Result<(), RealmError>;
}

/// Serial private protocol operations used by a realm supervisor.
#[async_trait]
pub trait RealmSession: Send {
    /// Complete the mandatory fresh handshake.
    async fn handshake(&mut self) -> Result<(), RealmError>;
    /// Return negotiated capabilities after handshake.
    fn negotiated_capabilities(&self) -> &[String];
    /// Run the bounded qualification health call.
    async fn health(&mut self) -> Result<wire::HealthFact, RealmError>;
    /// Resolve one pinned broker-observed peer.
    async fn resolve_peer(
        &mut self,
        peer: wire::PinnedPeer,
    ) -> Result<ResolvePeerResult, RealmError>;
    /// Query one closed inventory scope.
    async fn query_instances(&mut self, scope: QueryScope) -> Result<InventoryResult, RealmError>;
    /// Close the transport. Dropping the owner releases its active artifact.
    async fn close(&mut self);
}

/// Authenticated transport plus the active admitted-artifact reference that
/// spans its complete lifetime.
pub struct AuthenticatedRealmSession {
    session: Box<dyn RealmSession>,
    active_artifact: ActiveArtifact,
    socket_identity: SocketIdentity,
    peer_binding: VerifiedPeerBinding,
}

impl AuthenticatedRealmSession {
    /// Bind a fully authenticated protocol session to its socket, peer, and
    /// active admitted artifact.
    #[must_use]
    pub fn new(
        session: Box<dyn RealmSession>,
        active_artifact: ActiveArtifact,
        socket_identity: SocketIdentity,
        peer_binding: VerifiedPeerBinding,
    ) -> Self {
        Self {
            session,
            active_artifact,
            socket_identity,
            peer_binding,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthorityState {
    Absent,
    Connecting,
    Authenticating,
    Handshaking,
    HealthChecking,
    Ready,
    Degraded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransitionState {
    None,
    Qualifying,
    Restoring,
}

struct SessionSlot {
    epoch: u64,
    inner: AsyncMutex<AuthenticatedRealmSession>,
}

struct RealmEntry {
    config: RealmConfig,
    revision: u64,
    next_epoch: u64,
    current_epoch: u64,
    actor_version: u64,
    generation: u64,
    authority: AuthorityState,
    transition: TransitionState,
    reason: RealmReason,
    session: Option<Arc<SessionSlot>>,
    connecting: bool,
    supervisor_running: bool,
}

struct DrainingEntry {
    status: RealmStatus,
    _session: Arc<SessionSlot>,
}

struct RegistryState {
    generation: u64,
    entries: BTreeMap<RealmName, RealmEntry>,
    tombstones: BTreeMap<RealmName, u64>,
    draining: BTreeMap<RealmName, DrainingEntry>,
    reservations: BTreeMap<RealmName, u128>,
}

struct RegistryInner {
    state: Mutex<RegistryState>,
    changed: Notify,
}

/// Process-owned realm registry and serial supervisor state.
#[derive(Clone)]
pub struct RealmRegistry {
    inner: Arc<RegistryInner>,
}

impl fmt::Debug for RealmRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.lock_state();
        formatter
            .debug_struct("RealmRegistry")
            .field("generation", &state.generation)
            .field("realms", &state.entries.len())
            .finish()
    }
}

impl RealmRegistry {
    /// Create an accepted generation whose realms begin absent and isolated.
    ///
    /// # Errors
    ///
    /// Returns [`RealmError::CounterExhausted`] if `generation` is zero.
    pub fn new(realms: &RealmSet, generation: u64) -> Result<Self, RealmError> {
        if generation == 0 {
            return Err(RealmError::CounterExhausted);
        }
        let entries = realms
            .iter()
            .map(|(name, config)| {
                (
                    name.clone(),
                    RealmEntry {
                        config: config.clone(),
                        revision: 1,
                        next_epoch: 0,
                        current_epoch: 0,
                        actor_version: 1,
                        generation,
                        authority: AuthorityState::Absent,
                        transition: TransitionState::None,
                        reason: RealmReason::SocketAbsent,
                        session: None,
                        connecting: false,
                        supervisor_running: false,
                    },
                )
            })
            .collect();
        Ok(Self {
            inner: Arc::new(RegistryInner {
                state: Mutex::new(RegistryState {
                    generation,
                    entries,
                    tombstones: BTreeMap::new(),
                    draining: BTreeMap::new(),
                    reservations: BTreeMap::new(),
                }),
                changed: Notify::new(),
            }),
        })
    }

    /// Current accepted configuration generation.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.lock_state().generation
    }

    /// Return disclosure-safe accepted realm status, sorted by name.
    #[must_use]
    pub fn statuses(&self) -> Vec<RealmStatus> {
        let state = self.lock_state();
        let mut statuses = state
            .entries
            .iter()
            .map(|(name, entry)| status_for(name, entry))
            .collect::<Vec<_>>();
        statuses.extend(state.draining.values().map(|entry| entry.status.clone()));
        drop(state);
        statuses.sort_by(|left, right| left.name.cmp(&right.name));
        statuses.truncate(MAX_REALMS);
        statuses
    }

    /// Return the ungated accepted-generation readiness partition.
    #[must_use]
    pub fn readiness(&self) -> RealmReadiness {
        let state = self.lock_state();
        let mut result = RealmReadiness::default();
        for (name, entry) in &state.entries {
            result.total = result.total.saturating_add(1);
            match status_for(name, entry).state {
                RealmState::Ready => result.ready = result.ready.saturating_add(1),
                RealmState::Absent => result.absent = result.absent.saturating_add(1),
                RealmState::Connecting
                | RealmState::Authenticating
                | RealmState::Handshaking
                | RealmState::HealthChecking
                | RealmState::Degraded
                | RealmState::Staging
                | RealmState::Draining => {
                    result.degraded = result.degraded.saturating_add(1);
                }
            }
        }
        drop(state);
        result
    }

    /// Perform one complete fresh connection and authentication attempt.
    ///
    /// Every call obtains a new session epoch. No admission result is reused.
    #[allow(clippy::too_many_lines)]
    pub async fn connect_realm(
        &self,
        name: &RealmName,
        connector: &dyn RealmConnector,
        admission: &ReleaseAdmission,
    ) -> Result<(), RealmError> {
        let (config, generation, revision, epoch, old_session) = {
            let mut state = self.lock_state();
            if state.reservations.contains_key(name) {
                return Err(RealmError::PreparationConflict);
            }
            let generation = state.generation;
            let entry = state.entries.get_mut(name).ok_or(RealmError::Unavailable)?;
            if entry.connecting {
                return Err(RealmError::PreparationConflict);
            }
            let epoch = entry
                .next_epoch
                .checked_add(1)
                .ok_or(RealmError::CounterExhausted)?;
            entry.next_epoch = epoch;
            entry.connecting = true;
            transition_entry(entry, AuthorityState::Connecting, RealmReason::Connecting)?;
            let result = (
                entry.config.clone(),
                generation,
                entry.revision,
                epoch,
                entry.session.take(),
            );
            drop(state);
            result
        };
        let _attempt = AttemptLease {
            inner: Arc::clone(&self.inner),
            name: name.clone(),
            revision,
            epoch,
        };
        if let Some(old_session) = old_session {
            close_slot(old_session).await;
        }

        let connection =
            match tokio::time::timeout(CONNECT_STEP_TIMEOUT, connector.connect(&config)).await {
                Ok(Ok(connection)) => connection,
                Ok(Err(error)) => {
                    self.fail_attempt(name, revision, epoch, &error);
                    return Err(error);
                }
                Err(_) => {
                    self.fail_attempt(name, revision, epoch, &RealmError::Connect);
                    return Err(RealmError::Connect);
                }
            };
        self.advance_attempt(name, revision, epoch, AuthorityState::Authenticating)?;
        let mut authenticated = match tokio::time::timeout(
            CONNECT_STEP_TIMEOUT,
            connection.authenticate(&config, generation, epoch, admission),
        )
        .await
        {
            Ok(Ok(session)) => session,
            Ok(Err(error)) => {
                self.fail_attempt(name, revision, epoch, &error);
                return Err(error);
            }
            Err(_) => {
                self.fail_attempt(name, revision, epoch, &RealmError::Authentication);
                return Err(RealmError::Authentication);
            }
        };
        self.advance_attempt(name, revision, epoch, AuthorityState::Handshaking)?;
        if tokio::time::timeout(CONNECT_STEP_TIMEOUT, authenticated.session.handshake())
            .await
            .map_err(|_| RealmError::Protocol)?
            .is_err()
        {
            authenticated.session.close().await;
            self.fail_attempt(name, revision, epoch, &RealmError::Protocol);
            return Err(RealmError::Protocol);
        }
        validate_negotiated(&config, authenticated.session.negotiated_capabilities())?;
        self.advance_attempt(name, revision, epoch, AuthorityState::HealthChecking)?;
        let health = tokio::time::timeout(CONNECT_STEP_TIMEOUT, authenticated.session.health())
            .await
            .map_err(|_| RealmError::Health)??;
        if let Err(error) = validate_health(&config, &health) {
            authenticated.session.close().await;
            self.fail_attempt(name, revision, epoch, &error);
            return Err(error);
        }
        let slot = Arc::new(SessionSlot {
            epoch,
            inner: AsyncMutex::new(authenticated),
        });
        let replaced = {
            let mut state = self.lock_state();
            let entry = state.entries.get_mut(name).ok_or(RealmError::Stale)?;
            ensure_attempt(entry, revision, epoch)?;
            let replaced = entry.session.replace(slot);
            entry.current_epoch = epoch;
            entry.connecting = false;
            entry.transition = TransitionState::None;
            transition_entry(entry, AuthorityState::Ready, RealmReason::None)?;
            drop(state);
            replaced
        };
        if let Some(replaced) = replaced {
            close_slot(replaced).await;
        }
        self.inner.changed.notify_waiters();
        Ok(())
    }

    /// Run the single reconnecting supervisor for one realm until shutdown.
    ///
    /// Failed attempts repeat full authentication after exponential backoff
    /// from 250 milliseconds through 30 seconds plus positive bounded jitter.
    /// A state change or shutdown wakes the supervisor immediately.
    ///
    /// # Errors
    ///
    /// Returns [`RealmError::SupervisorRunning`] for a duplicate supervisor or
    /// a typed counter failure if the session epoch cannot advance.
    pub async fn supervise_realm(
        &self,
        name: RealmName,
        connector: Arc<dyn RealmConnector>,
        admission: Arc<ReleaseAdmission>,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), RealmError> {
        {
            let mut state = self.lock_state();
            let entry = state
                .entries
                .get_mut(&name)
                .ok_or(RealmError::Unavailable)?;
            if entry.supervisor_running {
                return Err(RealmError::SupervisorRunning);
            }
            entry.supervisor_running = true;
            drop(state);
        }
        let _lease = SupervisorLease {
            inner: Arc::clone(&self.inner),
            name: name.clone(),
        };
        let mut backoff = INITIAL_RECONNECT_BACKOFF;
        loop {
            if *shutdown.borrow() {
                return Ok(());
            }
            if !self.realm_exists(&name) {
                return Ok(());
            }
            let notified = self.inner.changed.notified();
            if self.realm_is_ready(&name) {
                tokio::select! {
                    _ = shutdown.changed() => {},
                    () = notified => {},
                }
                continue;
            }
            match self
                .connect_realm(&name, connector.as_ref(), admission.as_ref())
                .await
            {
                Ok(()) => backoff = INITIAL_RECONNECT_BACKOFF,
                Err(RealmError::CounterExhausted) => return Err(RealmError::CounterExhausted),
                Err(_) => {
                    let delay = reconnect_delay(backoff)?;
                    backoff = backoff.saturating_mul(2).min(MAX_RECONNECT_BACKOFF);
                    tokio::select! {
                        () = tokio::time::sleep(delay) => {},
                        _ = shutdown.changed() => {},
                        () = self.inner.changed.notified() => {},
                    }
                }
            }
        }
    }

    /// Resolve a peer through the accepted serial session for `name`.
    pub async fn resolve_peer(
        &self,
        name: &RealmName,
        peer: wire::PinnedPeer,
    ) -> Result<ResolvePeerResult, RealmError> {
        let (slot, token, config) = self.pin_ready(name)?;
        let mut session = slot.inner.lock().await;
        self.validate_token(name, token)?;
        require_negotiated(&session, "resolve-peer")?;
        let result = session.session.resolve_peer(peer).await?;
        if let Some(instance) = result.instance.as_ref() {
            validate_instance(name, &config, instance)?;
        }
        self.validate_token(name, token)?;
        drop(session);
        Ok(result)
    }

    /// Query a closed inventory scope through the accepted serial session.
    pub async fn query_instances(
        &self,
        name: &RealmName,
        scope: QueryScope,
    ) -> Result<InventoryResult, RealmError> {
        validate_scope(name, &scope)?;
        let (slot, token, config) = self.pin_ready(name)?;
        let mut session = slot.inner.lock().await;
        self.validate_token(name, token)?;
        require_negotiated(&session, "query-instances")?;
        let result = session.session.query_instances(scope).await?;
        for instance in &result.instances {
            validate_instance(name, &config, instance)?;
        }
        self.validate_token(name, token)?;
        drop(session);
        Ok(result)
    }

    /// Prepare a candidate realm set without publishing candidate authority.
    #[allow(clippy::too_many_lines)]
    pub async fn prepare_reload(
        &self,
        candidate: RealmSet,
        connector: Arc<dyn RealmConnector>,
        admission: Arc<ReleaseAdmission>,
        dry_run: bool,
    ) -> Result<PreparedReload, RealmError> {
        let prepare_id = new_prepare_id()?;
        let (base_generation, candidate_generation, changes, lifecycle_version) = {
            let mut state = self.lock_state();
            let base_generation = state.generation;
            let candidate_generation = base_generation
                .checked_add(1)
                .ok_or(RealmError::CounterExhausted)?;
            let changes = classify_changes(&state, &candidate)?;
            if dry_run
                && changes.iter().any(|change| {
                    matches!(change.kind, ChangeKind::Changed)
                        && change.old_config.as_ref().is_some_and(|old| {
                            change
                                .new_config
                                .as_ref()
                                .is_some_and(|new| old.socket_path == new.socket_path)
                        })
                })
            {
                return Err(RealmError::QualificationRequired);
            }
            let names = changes
                .iter()
                .map(|change| change.name.clone())
                .collect::<Vec<_>>();
            for name in &names {
                if state.reservations.contains_key(name)
                    || state
                        .entries
                        .get(name)
                        .is_some_and(|entry| entry.connecting)
                {
                    for acquired in &names {
                        if state.reservations.get(acquired) == Some(&prepare_id) {
                            state.reservations.remove(acquired);
                        }
                    }
                    return Err(RealmError::PreparationConflict);
                }
                state.reservations.insert(name.clone(), prepare_id);
            }
            let result = (
                base_generation,
                candidate_generation,
                changes,
                admission.snapshot().lifecycle_version,
            );
            drop(state);
            result
        };

        let mut preparation = PreparedReload {
            inner: Arc::clone(&self.inner),
            prepare_id,
            base_generation,
            candidate_generation,
            lifecycle_version,
            candidate,
            changes,
            staged: BTreeMap::new(),
            restorations: BTreeMap::new(),
            connector,
            admission,
            activatable: !dry_run,
            committed: false,
        };
        for change in preparation.changes.clone() {
            let Some(config) = change.new_config.as_ref() else {
                continue;
            };
            let same_socket = change
                .old_config
                .as_ref()
                .is_some_and(|old| old.socket_path == config.socket_path);
            if same_socket {
                if let Some(old_config) = change.old_config.clone() {
                    preparation
                        .restorations
                        .insert(change.name.clone(), old_config);
                }
                let old_session = {
                    let mut state = self.lock_state();
                    let entry = state
                        .entries
                        .get_mut(&change.name)
                        .ok_or(RealmError::Stale)?;
                    entry.transition = TransitionState::Qualifying;
                    entry.authority = AuthorityState::Degraded;
                    entry.reason = RealmReason::Connecting;
                    bump_actor(entry)?;
                    let result = entry.session.take();
                    drop(state);
                    result
                };
                if let Some(old_session) = old_session {
                    close_slot(old_session).await;
                }
            }
            match qualify_session(
                preparation.connector.as_ref(),
                preparation.admission.as_ref(),
                config,
                candidate_generation,
                change.new_epoch,
            )
            .await
            {
                Ok(mut session) => {
                    session.expected_actor_version = {
                        let state = self.lock_state();
                        state
                            .entries
                            .get(&change.name)
                            .map_or(0, |entry| entry.actor_version)
                    };
                    preparation.staged.insert(change.name.clone(), session);
                }
                Err(error) => {
                    preparation.abort().await;
                    return Err(error);
                }
            }
        }
        Ok(preparation)
    }

    fn advance_attempt(
        &self,
        name: &RealmName,
        revision: u64,
        epoch: u64,
        authority: AuthorityState,
    ) -> Result<(), RealmError> {
        let mut state = self.lock_state();
        let entry = state.entries.get_mut(name).ok_or(RealmError::Stale)?;
        ensure_attempt(entry, revision, epoch)?;
        let result = transition_entry(entry, authority, RealmReason::Connecting);
        drop(state);
        result
    }

    fn fail_attempt(&self, name: &RealmName, revision: u64, epoch: u64, error: &RealmError) {
        let mut state = self.lock_state();
        let Some(entry) = state.entries.get_mut(name) else {
            return;
        };
        if ensure_attempt(entry, revision, epoch).is_err() {
            return;
        }
        entry.session = None;
        entry.connecting = false;
        entry.transition = TransitionState::None;
        entry.authority = if matches!(error, RealmError::SocketAbsent) {
            AuthorityState::Absent
        } else {
            AuthorityState::Degraded
        };
        entry.reason = reason_for_error(error);
        let _ = bump_actor(entry);
        drop(state);
        self.inner.changed.notify_waiters();
    }

    fn pin_ready(
        &self,
        name: &RealmName,
    ) -> Result<(Arc<SessionSlot>, QueryToken, RealmConfig), RealmError> {
        let state = self.lock_state();
        let entry = state.entries.get(name).ok_or(RealmError::Unavailable)?;
        if entry.authority != AuthorityState::Ready {
            return Err(RealmError::Unavailable);
        }
        let session = entry.session.clone().ok_or(RealmError::Unavailable)?;
        Ok((
            session,
            QueryToken {
                base_configuration_generation: state.generation,
                realm_revision: entry.revision,
                session_epoch: entry.current_epoch,
            },
            entry.config.clone(),
        ))
    }

    fn validate_token(&self, name: &RealmName, token: QueryToken) -> Result<(), RealmError> {
        let state = self.lock_state();
        let entry = state.entries.get(name).ok_or(RealmError::Stale)?;
        let current = (
            state.generation,
            entry.generation,
            entry.revision,
            entry.current_epoch,
            entry.authority,
        );
        drop(state);
        let expected = (
            token.base_configuration_generation,
            token.base_configuration_generation,
            token.realm_revision,
            token.session_epoch,
            AuthorityState::Ready,
        );
        if current == expected {
            Ok(())
        } else {
            Err(RealmError::Stale)
        }
    }

    fn realm_is_ready(&self, name: &RealmName) -> bool {
        self.lock_state()
            .entries
            .get(name)
            .is_some_and(|entry| entry.authority == AuthorityState::Ready)
    }

    fn realm_exists(&self, name: &RealmName) -> bool {
        self.lock_state().entries.contains_key(name)
    }

    fn lock_state(&self) -> MutexGuard<'_, RegistryState> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

#[derive(Clone, Copy)]
struct QueryToken {
    base_configuration_generation: u64,
    realm_revision: u64,
    session_epoch: u64,
}

struct AttemptLease {
    inner: Arc<RegistryInner>,
    name: RealmName,
    revision: u64,
    epoch: u64,
}

impl Drop for AttemptLease {
    fn drop(&mut self) {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = state.entries.get_mut(&self.name)
            && entry.connecting
            && (entry.revision, entry.next_epoch) == (self.revision, self.epoch)
        {
            entry.connecting = false;
            entry.session = None;
            entry.transition = TransitionState::None;
            entry.authority = AuthorityState::Degraded;
            entry.reason = RealmReason::ProtocolFailed;
            let _ = bump_actor(entry);
        }
        drop(state);
        self.inner.changed.notify_waiters();
    }
}

struct SupervisorLease {
    inner: Arc<RegistryInner>,
    name: RealmName,
}

impl Drop for SupervisorLease {
    fn drop(&mut self) {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = state.entries.get_mut(&self.name) {
            entry.supervisor_running = false;
        }
        drop(state);
        self.inner.changed.notify_waiters();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChangeKind {
    Added,
    Removed,
    Changed,
}

#[derive(Clone)]
struct RealmChange {
    name: RealmName,
    kind: ChangeKind,
    old_config: Option<RealmConfig>,
    new_config: Option<RealmConfig>,
    old_revision: u64,
    new_revision: u64,
    old_actor_version: u64,
    new_epoch: u64,
}

struct StagedSession {
    slot: Arc<SessionSlot>,
    socket_identity: SocketIdentity,
    peer_binding: VerifiedPeerBinding,
    release: ReleaseIdentity,
    digest: Sha256Digest,
    expected_actor_version: u64,
}

/// Owned preparation handle. Candidate sessions never serve before
/// [`Self::commit`] performs the atomic generation swap.
pub struct PreparedReload {
    inner: Arc<RegistryInner>,
    prepare_id: u128,
    base_generation: u64,
    candidate_generation: u64,
    lifecycle_version: u64,
    candidate: RealmSet,
    changes: Vec<RealmChange>,
    staged: BTreeMap<RealmName, StagedSession>,
    restorations: BTreeMap<RealmName, RealmConfig>,
    connector: Arc<dyn RealmConnector>,
    admission: Arc<ReleaseAdmission>,
    activatable: bool,
    committed: bool,
}

impl PreparedReload {
    /// Revalidate immutable receipts and publish all candidate realm routes or
    /// none of them.
    #[allow(clippy::too_many_lines)]
    pub async fn commit(mut self) -> Result<u64, RealmError> {
        if !self.activatable {
            return Err(RealmError::QualificationRequired);
        }
        if self.admission.snapshot().lifecycle_version != self.lifecycle_version {
            return Err(RealmError::Stale);
        }
        for change in &self.changes {
            if let (Some(config), Some(staged)) =
                (change.new_config.as_ref(), self.staged.get(&change.name))
            {
                self.connector
                    .revalidate(config, staged.socket_identity)
                    .await?;
            }
        }

        let mut draining = Vec::new();
        {
            let mut state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if state.generation != self.base_generation
                || self.admission.snapshot().lifecycle_version != self.lifecycle_version
            {
                return Err(RealmError::Stale);
            }
            for change in &self.changes {
                if state.reservations.get(&change.name) != Some(&self.prepare_id) {
                    return Err(RealmError::Stale);
                }
                if let Some(entry) = state.entries.get(&change.name) {
                    let expected_actor = self
                        .staged
                        .get(&change.name)
                        .map_or(change.old_actor_version, |staged| {
                            staged.expected_actor_version
                        });
                    if entry.revision != change.old_revision
                        || entry.actor_version != expected_actor
                    {
                        return Err(RealmError::Stale);
                    }
                }
                if let Some(staged) = self.staged.get(&change.name) {
                    let session = staged
                        .slot
                        .inner
                        .try_lock()
                        .map_err(|_| RealmError::Stale)?;
                    if session.socket_identity != staged.socket_identity
                        || session.peer_binding != staged.peer_binding
                        || session.active_artifact.release() != &staged.release
                        || session.active_artifact.artifact().digest() != staged.digest
                    {
                        return Err(RealmError::Stale);
                    }
                    drop(session);
                }
            }

            for (name, config) in self.candidate.iter() {
                if let Some(change) = self.changes.iter().find(|change| &change.name == name) {
                    let staged = self.staged.remove(name).ok_or(RealmError::Stale)?;
                    let supervisor_running = state
                        .entries
                        .get(name)
                        .is_some_and(|entry| entry.supervisor_running);
                    if let Some(old) = state.entries.remove(name)
                        && let Some(session) = old.session
                    {
                        draining.push((name.clone(), session));
                    }
                    let actor_version = staged
                        .expected_actor_version
                        .checked_add(1)
                        .ok_or(RealmError::CounterExhausted)?;
                    state.entries.insert(
                        name.clone(),
                        RealmEntry {
                            config: config.clone(),
                            revision: change.new_revision,
                            next_epoch: change.new_epoch,
                            current_epoch: change.new_epoch,
                            actor_version,
                            generation: self.candidate_generation,
                            authority: AuthorityState::Ready,
                            transition: TransitionState::None,
                            reason: RealmReason::None,
                            session: Some(staged.slot),
                            connecting: false,
                            supervisor_running,
                        },
                    );
                } else if let Some(entry) = state.entries.get_mut(name) {
                    entry.generation = self.candidate_generation;
                }
            }
            for change in &self.changes {
                if change.kind == ChangeKind::Removed
                    && let Some(mut removed) = state.entries.remove(&change.name)
                {
                    state
                        .tombstones
                        .insert(change.name.clone(), removed.revision);
                    if let Some(session) = removed.session.take() {
                        let mut status = status_for(&change.name, &removed);
                        status.state = RealmState::Draining;
                        status.reason = RealmReason::Draining;
                        status.generation = self.candidate_generation;
                        state.draining.insert(
                            change.name.clone(),
                            DrainingEntry {
                                status,
                                _session: Arc::clone(&session),
                            },
                        );
                        draining.push((change.name.clone(), session));
                    }
                }
            }
            for change in &self.changes {
                state.reservations.remove(&change.name);
            }
            state.generation = self.candidate_generation;
        }
        self.committed = true;
        self.restorations.clear();
        for (name, session) in draining {
            let inner = Arc::clone(&self.inner);
            spawn_cleanup(async move {
                close_slot(session).await;
                let mut state = inner.state.lock().unwrap_or_else(PoisonError::into_inner);
                state.draining.remove(&name);
            });
        }
        Ok(self.candidate_generation)
    }

    async fn abort(mut self) {
        self.committed = true;
        cleanup_preparation(
            Arc::clone(&self.inner),
            self.prepare_id,
            std::mem::take(&mut self.staged),
            std::mem::take(&mut self.restorations),
            Arc::clone(&self.connector),
            Arc::clone(&self.admission),
            self.base_generation,
        )
        .await;
    }
}

impl Drop for PreparedReload {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let staged = std::mem::take(&mut self.staged);
        let restorations = std::mem::take(&mut self.restorations);
        let inner = Arc::clone(&self.inner);
        let connector = Arc::clone(&self.connector);
        let admission = Arc::clone(&self.admission);
        let prepare_id = self.prepare_id;
        let generation = self.base_generation;
        spawn_cleanup(async move {
            cleanup_preparation(
                inner,
                prepare_id,
                staged,
                restorations,
                connector,
                admission,
                generation,
            )
            .await;
        });
    }
}

fn classify_changes(
    state: &RegistryState,
    candidate: &RealmSet,
) -> Result<Vec<RealmChange>, RealmError> {
    let names = state
        .entries
        .keys()
        .chain(candidate.0.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut changes = Vec::new();
    for name in names {
        let old = state.entries.get(&name);
        let new = candidate.get(&name);
        let kind = match (old, new) {
            (None, Some(_)) => ChangeKind::Added,
            (Some(_), None) => ChangeKind::Removed,
            (Some(old), Some(new)) if old.config != *new => ChangeKind::Changed,
            (Some(_), Some(_)) | (None, None) => continue,
        };
        let old_revision = old.map_or_else(
            || state.tombstones.get(&name).copied().unwrap_or(0),
            |entry| entry.revision,
        );
        let new_revision = if kind == ChangeKind::Removed {
            old_revision
        } else {
            old_revision
                .checked_add(1)
                .ok_or(RealmError::CounterExhausted)?
        };
        let new_epoch = old
            .map_or(0, |entry| entry.next_epoch)
            .checked_add(1)
            .ok_or(RealmError::CounterExhausted)?;
        changes.push(RealmChange {
            name,
            kind,
            old_config: old.map(|entry| entry.config.clone()),
            new_config: new.cloned(),
            old_revision,
            new_revision,
            old_actor_version: old.map_or(0, |entry| entry.actor_version),
            new_epoch,
        });
    }
    Ok(changes)
}

async fn qualify_session(
    connector: &dyn RealmConnector,
    admission: &ReleaseAdmission,
    config: &RealmConfig,
    generation: u64,
    epoch: u64,
) -> Result<StagedSession, RealmError> {
    let connection = tokio::time::timeout(CONNECT_STEP_TIMEOUT, connector.connect(config))
        .await
        .map_err(|_| RealmError::Connect)??;
    let mut session = tokio::time::timeout(
        CONNECT_STEP_TIMEOUT,
        connection.authenticate(config, generation, epoch, admission),
    )
    .await
    .map_err(|_| RealmError::Authentication)??;
    tokio::time::timeout(CONNECT_STEP_TIMEOUT, session.session.handshake())
        .await
        .map_err(|_| RealmError::Protocol)??;
    validate_negotiated(config, session.session.negotiated_capabilities())?;
    let health = tokio::time::timeout(CONNECT_STEP_TIMEOUT, session.session.health())
        .await
        .map_err(|_| RealmError::Health)??;
    validate_health(config, &health)?;
    let socket_identity = session.socket_identity;
    let peer_binding = session.peer_binding;
    let release = session.active_artifact.release().clone();
    let digest = session.active_artifact.artifact().digest();
    Ok(StagedSession {
        slot: Arc::new(SessionSlot {
            epoch,
            inner: AsyncMutex::new(session),
        }),
        socket_identity,
        peer_binding,
        release,
        digest,
        expected_actor_version: 0,
    })
}

async fn cleanup_preparation(
    inner: Arc<RegistryInner>,
    prepare_id: u128,
    staged: BTreeMap<RealmName, StagedSession>,
    restorations: BTreeMap<RealmName, RealmConfig>,
    connector: Arc<dyn RealmConnector>,
    admission: Arc<ReleaseAdmission>,
    generation: u64,
) {
    for staged in staged.into_values() {
        close_slot(staged.slot).await;
    }
    for (name, config) in restorations {
        let epoch = {
            let mut state = inner.state.lock().unwrap_or_else(PoisonError::into_inner);
            let Some(entry) = state.entries.get_mut(&name) else {
                state.reservations.remove(&name);
                continue;
            };
            entry.transition = TransitionState::Restoring;
            let Some(epoch) = entry.next_epoch.checked_add(1) else {
                entry.authority = AuthorityState::Degraded;
                entry.reason = RealmReason::ProtocolFailed;
                state.reservations.remove(&name);
                continue;
            };
            entry.next_epoch = epoch;
            drop(state);
            epoch
        };
        let restored = qualify_session(
            connector.as_ref(),
            admission.as_ref(),
            &config,
            generation,
            epoch,
        )
        .await;
        let reservation_matches = {
            let state = inner.state.lock().unwrap_or_else(PoisonError::into_inner);
            state.reservations.get(&name) == Some(&prepare_id)
        };
        if !reservation_matches {
            if let Ok(restored) = restored {
                close_slot(restored.slot).await;
            }
            continue;
        }
        let mut state = inner.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = state.entries.get_mut(&name) {
            match restored {
                Ok(restored) => {
                    entry.session = Some(restored.slot);
                    entry.current_epoch = epoch;
                    entry.authority = AuthorityState::Ready;
                    entry.reason = RealmReason::None;
                    entry.transition = TransitionState::None;
                }
                Err(error) => {
                    entry.session = None;
                    entry.authority = AuthorityState::Degraded;
                    entry.reason = reason_for_error(&error);
                    entry.transition = TransitionState::None;
                }
            }
            let _ = bump_actor(entry);
        }
        state.reservations.remove(&name);
    }
    let mut state = inner.state.lock().unwrap_or_else(PoisonError::into_inner);
    state.reservations.retain(|_, owner| *owner != prepare_id);
}

fn new_prepare_id() -> Result<u128, RealmError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| RealmError::CounterExhausted)?;
    Ok(u128::from_be_bytes(bytes))
}

fn reconnect_delay(backoff: Duration) -> Result<Duration, RealmError> {
    let mut bytes = [0_u8; 8];
    getrandom::fill(&mut bytes).map_err(|_| RealmError::CounterExhausted)?;
    let jitter = u64::from_be_bytes(bytes) % (MAX_RECONNECT_JITTER_MILLIS + 1);
    Ok(backoff.saturating_add(Duration::from_millis(jitter)))
}

fn validate_negotiated(config: &RealmConfig, negotiated: &[String]) -> Result<(), RealmError> {
    for capability in config.capabilities.iter() {
        if negotiated
            .binary_search_by(|candidate| candidate.as_str().cmp(capability.as_str()))
            .is_err()
        {
            return Err(RealmError::Protocol);
        }
    }
    Ok(())
}

fn require_negotiated(
    session: &AuthenticatedRealmSession,
    capability: &str,
) -> Result<(), RealmError> {
    if session
        .session
        .negotiated_capabilities()
        .binary_search_by(|candidate| candidate.as_str().cmp(capability))
        .is_ok()
    {
        Ok(())
    } else {
        Err(RealmError::Protocol)
    }
}

const fn validate_health(
    config: &RealmConfig,
    health: &wire::HealthFact,
) -> Result<(), RealmError> {
    if !health.ready
        || !health.missing_capabilities.is_empty()
        || health.runtime != config.provider.wire_runtime() as i32
        || health.runtime_mode != config.runtime_mode.wire_runtime() as i32
    {
        return Err(RealmError::Health);
    }
    Ok(())
}

fn validate_scope(name: &RealmName, scope: &QueryScope) -> Result<(), RealmError> {
    match scope {
        QueryScope::Project { realm, .. } | QueryScope::Service { realm, .. }
            if realm != name.as_str() =>
        {
            Err(RealmError::Protocol)
        }
        QueryScope::InstanceId(_)
        | QueryScope::GlobalDoctor
        | QueryScope::Project { .. }
        | QueryScope::Service { .. } => Ok(()),
    }
}

fn validate_instance(
    name: &RealmName,
    config: &RealmConfig,
    instance: &wire::InstanceFact,
) -> Result<(), RealmError> {
    let provenance = instance.provenance.as_ref().ok_or(RealmError::Protocol)?;
    if provenance.realm != name.as_str()
        || provenance.provider != config.provider.wire_runtime() as i32
        || instance.runtime != config.provider.wire_runtime() as i32
    {
        return Err(RealmError::Protocol);
    }
    Ok(())
}

const fn ensure_attempt(entry: &RealmEntry, revision: u64, epoch: u64) -> Result<(), RealmError> {
    if entry.revision == revision && entry.next_epoch == epoch {
        Ok(())
    } else {
        Err(RealmError::Stale)
    }
}

fn transition_entry(
    entry: &mut RealmEntry,
    authority: AuthorityState,
    reason: RealmReason,
) -> Result<(), RealmError> {
    entry.authority = authority;
    entry.reason = reason;
    bump_actor(entry)
}

fn bump_actor(entry: &mut RealmEntry) -> Result<(), RealmError> {
    entry.actor_version = entry
        .actor_version
        .checked_add(1)
        .ok_or(RealmError::CounterExhausted)?;
    Ok(())
}

const fn reason_for_error(error: &RealmError) -> RealmReason {
    match error {
        RealmError::SocketAbsent => RealmReason::SocketAbsent,
        RealmError::Connect
        | RealmError::PreparationConflict
        | RealmError::SupervisorRunning
        | RealmError::QualificationRequired => RealmReason::Connecting,
        RealmError::Authentication => RealmReason::AuthenticationFailed,
        RealmError::Admission => RealmReason::AdmissionFailed,
        RealmError::Protocol | RealmError::Stale | RealmError::CounterExhausted => {
            RealmReason::ProtocolFailed
        }
        RealmError::Health | RealmError::Unavailable => RealmReason::HealthFailed,
    }
}

async fn close_slot(slot: Arc<SessionSlot>) {
    let mut session = slot.inner.lock().await;
    let _epoch = slot.epoch;
    session.session.close().await;
    drop(session);
}

fn spawn_cleanup(future: impl std::future::Future<Output = ()> + Send + 'static) {
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
        runtime.spawn(future);
    }
}

fn status_for(name: &RealmName, entry: &RealmEntry) -> RealmStatus {
    let state = if entry.authority == AuthorityState::Ready {
        RealmState::Ready
    } else {
        match (entry.authority, entry.transition) {
            (_, TransitionState::Qualifying | TransitionState::Restoring) => RealmState::Staging,
            (AuthorityState::Absent, TransitionState::None) => RealmState::Absent,
            (AuthorityState::Connecting, TransitionState::None) => RealmState::Connecting,
            (AuthorityState::Authenticating, TransitionState::None) => RealmState::Authenticating,
            (AuthorityState::Handshaking, TransitionState::None) => RealmState::Handshaking,
            (AuthorityState::HealthChecking, TransitionState::None) => RealmState::HealthChecking,
            (AuthorityState::Degraded, TransitionState::None) => RealmState::Degraded,
            (AuthorityState::Ready, TransitionState::None) => RealmState::Ready,
        }
    };
    RealmStatus {
        name: name.clone(),
        provider: entry.config.provider,
        mode: entry.config.runtime_mode,
        state,
        generation: entry.generation,
        session_epoch: entry.current_epoch,
        protocol: entry.config.protocol.get(),
        reason: entry.reason,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::release_admission::{
        ArtifactRequirement, HistoricalReleaseIdentityCheck, ProductId, ReleaseArtifact, ReleaseId,
        VerifiedReleaseManifest,
    };
    use sha2::{Digest as _, Sha256};

    use super::*;

    fn bootstrap(body: &str) -> toml::Value {
        let raw = format!(
            "schema = \"agent\"\nschemaVersion = 3\n[import]\ncatalog = \"catalog.json\"\npolicy = \"policy.json\"\nbundle = \"bundle.json\"\n{body}"
        );
        toml::from_str(&raw).expect("valid test TOML")
    }

    fn rootful() -> &'static str {
        r#"
[attestor.realms.production-docker]
provider = "docker"
runtimeMode = "rootful-host"
brokerUser = "991"
brokerUnit = "basil-agent.service"
attestorUser = "992"
attestorUnit = "basil-attestor-production-docker.service"
socketPath = "/run/basil/attestors/production-docker/control.sock"
releaseRole = "docker-attestor"
target = "x86_64-unknown-linux-gnu"
protocol = 1
capabilities = ["health", "query-instances", "resolve-peer"]
"#
    }

    fn rootless(uid: u32) -> String {
        format!(
            r#"
[attestor.realms.owner-podman]
provider = "podman"
runtimeMode = "rootless-owner"
brokerUser = "991"
brokerUnit = "basil-agent.service"
attestorUser = "{uid}"
attestorUnit = "basil-attestor-owner-podman.service"
socketPath = "/run/user/{uid}/basil/attestors/owner-podman/control.sock"
releaseRole = "podman-attestor"
target = "x86_64-unknown-linux-gnu"
protocol = 1
capabilities = ["health", "query-instances", "resolve-peer"]
"#
        )
    }

    fn admission() -> Arc<ReleaseAdmission> {
        let capabilities = CapabilitySet::try_from_iter(
            REQUIRED_CAPABILITIES
                .iter()
                .map(|value| CapabilityId::new(value).expect("valid capability")),
        )
        .expect("valid capabilities");
        let artifacts = ["docker-attestor", "podman-attestor"]
            .into_iter()
            .map(|role| {
                ReleaseArtifact::new(
                    ArtifactRole::new(role).expect("valid role"),
                    TargetTriple::new("x86_64-unknown-linux-gnu").expect("valid target"),
                    Sha256Digest::from_bytes([7; 32]),
                    ProtocolVersion::new(1).expect("valid protocol"),
                    capabilities.clone(),
                )
            });
        let manifest = VerifiedReleaseManifest::from_verified_parts(
            HistoricalReleaseIdentityCheck::completed(),
            ProductId::new("basil").expect("valid product"),
            ReleaseId::new("1.0.0").expect("valid release"),
            artifacts,
        )
        .expect("valid manifest");
        Arc::new(ReleaseAdmission::new(manifest))
    }

    #[derive(Clone, Copy)]
    enum FakePlan {
        Success,
        SocketAbsent,
        AuthenticationFailed,
        HealthFailed,
        BlockConnect,
    }

    #[derive(Clone)]
    struct FakeConnector {
        plans: Arc<Mutex<VecDeque<FakePlan>>>,
        connects: Arc<AtomicUsize>,
        authentications: Arc<AtomicUsize>,
        closes: Arc<AtomicUsize>,
        revalidate_failure: Arc<Mutex<bool>>,
        unblock: Arc<Notify>,
    }

    impl FakeConnector {
        fn new(plans: impl IntoIterator<Item = FakePlan>) -> Self {
            Self {
                plans: Arc::new(Mutex::new(plans.into_iter().collect())),
                connects: Arc::new(AtomicUsize::new(0)),
                authentications: Arc::new(AtomicUsize::new(0)),
                closes: Arc::new(AtomicUsize::new(0)),
                revalidate_failure: Arc::new(Mutex::new(false)),
                unblock: Arc::new(Notify::new()),
            }
        }
    }

    #[async_trait]
    impl RealmConnector for FakeConnector {
        async fn connect(
            &self,
            _config: &RealmConfig,
        ) -> Result<Box<dyn RealmConnection>, RealmError> {
            self.connects.fetch_add(1, Ordering::SeqCst);
            let plan = self
                .plans
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .pop_front()
                .unwrap_or(FakePlan::Success);
            if matches!(plan, FakePlan::SocketAbsent) {
                return Err(RealmError::SocketAbsent);
            }
            if matches!(plan, FakePlan::BlockConnect) {
                self.unblock.notified().await;
            }
            Ok(Box::new(FakeConnection {
                plan,
                authentications: Arc::clone(&self.authentications),
                closes: Arc::clone(&self.closes),
            }))
        }

        async fn revalidate(
            &self,
            _config: &RealmConfig,
            _identity: SocketIdentity,
        ) -> Result<(), RealmError> {
            if *self
                .revalidate_failure
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
            {
                Err(RealmError::Stale)
            } else {
                Ok(())
            }
        }
    }

    struct FakeConnection {
        plan: FakePlan,
        authentications: Arc<AtomicUsize>,
        closes: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl RealmConnection for FakeConnection {
        async fn authenticate(
            self: Box<Self>,
            config: &RealmConfig,
            _generation: u64,
            epoch: u64,
            admission: &ReleaseAdmission,
        ) -> Result<AuthenticatedRealmSession, RealmError> {
            self.authentications.fetch_add(1, Ordering::SeqCst);
            if matches!(self.plan, FakePlan::AuthenticationFailed) {
                return Err(RealmError::Authentication);
            }
            let requirement = ArtifactRequirement::new(
                Sha256Digest::from_bytes([7; 32]),
                config.release_role.clone(),
                config.target.clone(),
                config.protocol,
                config.capabilities.clone(),
            );
            let active_artifact = admission
                .begin_preflight(&requirement)
                .map_err(|_| RealmError::Admission)?;
            Ok(AuthenticatedRealmSession::new(
                Box::new(FakeSession {
                    provider: config.provider,
                    mode: config.runtime_mode,
                    health_failure: matches!(self.plan, FakePlan::HealthFailed),
                    capabilities: REQUIRED_CAPABILITIES.map(str::to_string).to_vec(),
                    closes: Arc::clone(&self.closes),
                }),
                active_artifact,
                SocketIdentity {
                    device: 1,
                    inode: epoch,
                    owner: config.attestor_user.uid(),
                    mode: 0o140_600,
                },
                VerifiedPeerBinding::from_authenticator(Sha256::digest(epoch.to_be_bytes()).into()),
            ))
        }

        async fn close(self: Box<Self>) {
            self.closes.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct FakeSession {
        provider: RealmProvider,
        mode: RealmMode,
        health_failure: bool,
        capabilities: Vec<String>,
        closes: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl RealmSession for FakeSession {
        async fn handshake(&mut self) -> Result<(), RealmError> {
            Ok(())
        }

        fn negotiated_capabilities(&self) -> &[String] {
            &self.capabilities
        }

        async fn health(&mut self) -> Result<wire::HealthFact, RealmError> {
            if self.health_failure {
                return Err(RealmError::Health);
            }
            Ok(wire::HealthFact {
                runtime: self.provider.wire_runtime() as i32,
                diagnostic_version: "fake".to_string(),
                runtime_mode: self.mode.wire_runtime() as i32,
                cgroup_mode: wire::CgroupMode::V2 as i32,
                ready: true,
                missing_capabilities: Vec::new(),
            })
        }

        async fn resolve_peer(
            &mut self,
            _peer: wire::PinnedPeer,
        ) -> Result<ResolvePeerResult, RealmError> {
            Err(RealmError::Unavailable)
        }

        async fn query_instances(
            &mut self,
            _scope: QueryScope,
        ) -> Result<InventoryResult, RealmError> {
            Err(RealmError::Unavailable)
        }

        async fn close(&mut self) {
            self.closes.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn strict_schema_accepts_closed_rootful_and_rootless_matrix() {
        let realms = RealmSet::from_bootstrap(&bootstrap(rootful())).expect("valid realms");
        assert_eq!(realms.len(), 1);
        assert!(realms.validate_broker_uid(991).is_ok());
        assert_eq!(
            realms.validate_broker_uid(992),
            Err(RealmConfigError::BrokerUidMismatch)
        );
        let rootless = rootful()
            .replace("production-docker", "owner-podman")
            .replace("docker\"", "podman\"")
            .replace("rootful-host", "rootless-owner")
            .replace("attestorUser = \"992\"", "attestorUser = \"1000\"")
            .replace(
                "/run/basil/attestors/owner-podman/control.sock",
                "/run/user/1000/basil/attestors/owner-podman/control.sock",
            );
        let realms = RealmSet::from_bootstrap(&bootstrap(&rootless)).expect("valid rootless realm");
        assert_eq!(realms.len(), 1);
    }

    #[test]
    fn schema_rejects_unknowns_matrix_uid_paths_and_capability_drift() {
        for invalid in [
            rootful().replace("protocol = 1", "protocol = 1\nunknown = true"),
            rootful().replace("rootful-host", "rootless-owner"),
            rootful().replace("brokerUser = \"991\"", "brokerUser = \"0991\""),
            rootful().replace(
                "/run/basil/attestors/production-docker/control.sock",
                "/tmp/control.sock",
            ),
            rootful().replace(
                "[\"health\", \"query-instances\", \"resolve-peer\"]",
                "[\"health\", \"resolve-peer\"]",
            ),
        ] {
            assert!(RealmSet::from_bootstrap(&bootstrap(&invalid)).is_err());
        }
    }

    #[test]
    fn absent_realms_are_isolated_and_partition_readiness() {
        let realms = RealmSet::from_bootstrap(&bootstrap(rootful())).expect("valid realms");
        let registry = RealmRegistry::new(&realms, 1).expect("valid generation");
        assert_eq!(
            registry.readiness(),
            RealmReadiness {
                total: 1,
                ready: 0,
                degraded: 0,
                absent: 1,
            }
        );
        assert_eq!(registry.statuses()[0].state, RealmState::Absent);
    }

    #[tokio::test]
    async fn reconnect_repeats_authentication_and_spans_guard_lifetime() {
        let realms = RealmSet::from_bootstrap(&bootstrap(rootful())).expect("valid realms");
        let name = RealmName::new("production-docker").expect("valid realm");
        let registry = RealmRegistry::new(&realms, 1).expect("valid registry");
        let connector = FakeConnector::new([FakePlan::Success, FakePlan::Success]);
        let admission = admission();

        registry
            .connect_realm(&name, &connector, admission.as_ref())
            .await
            .expect("first connection");
        assert_eq!(admission.snapshot().current.active_preflights, 1);
        registry
            .connect_realm(&name, &connector, admission.as_ref())
            .await
            .expect("fresh reconnect");

        assert_eq!(connector.connects.load(Ordering::SeqCst), 2);
        assert_eq!(connector.authentications.load(Ordering::SeqCst), 2);
        assert_eq!(connector.closes.load(Ordering::SeqCst), 1);
        assert_eq!(admission.snapshot().current.active_preflights, 1);
        assert_eq!(registry.statuses()[0].session_epoch, 2);
    }

    #[tokio::test]
    async fn realm_failure_is_isolated() {
        let body = format!("{}{}", rootful(), rootless(1000));
        let realms = RealmSet::from_bootstrap(&bootstrap(&body)).expect("valid realms");
        let registry = RealmRegistry::new(&realms, 1).expect("valid registry");
        let connector = FakeConnector::new([FakePlan::Success, FakePlan::SocketAbsent]);
        let admission = admission();
        let first = RealmName::new("owner-podman").expect("valid realm");
        let second = RealmName::new("production-docker").expect("valid realm");
        registry
            .connect_realm(&first, &connector, admission.as_ref())
            .await
            .expect("first realm ready");
        assert_eq!(
            registry
                .connect_realm(&second, &connector, admission.as_ref())
                .await,
            Err(RealmError::SocketAbsent)
        );
        assert_eq!(
            registry.readiness(),
            RealmReadiness {
                total: 2,
                ready: 1,
                degraded: 0,
                absent: 1,
            }
        );
    }

    #[tokio::test]
    async fn authentication_failure_degrades_only_the_reconnecting_realm() {
        let realms = RealmSet::from_bootstrap(&bootstrap(rootful())).expect("valid realms");
        let name = RealmName::new("production-docker").expect("valid realm");
        let registry = RealmRegistry::new(&realms, 1).expect("valid registry");
        let connector = FakeConnector::new([FakePlan::Success, FakePlan::AuthenticationFailed]);
        let admission = admission();
        registry
            .connect_realm(&name, &connector, admission.as_ref())
            .await
            .expect("initial connection");
        assert_eq!(
            registry
                .connect_realm(&name, &connector, admission.as_ref())
                .await,
            Err(RealmError::Authentication)
        );
        assert_eq!(registry.statuses()[0].state, RealmState::Degraded);
        assert_eq!(admission.snapshot().current.active_preflights, 0);
    }

    #[tokio::test]
    async fn same_socket_failure_restores_accepted_generation() {
        let realms = RealmSet::from_bootstrap(&bootstrap(rootful())).expect("valid realms");
        let name = RealmName::new("production-docker").expect("valid realm");
        let registry = RealmRegistry::new(&realms, 1).expect("valid registry");
        let connector = Arc::new(FakeConnector::new([
            FakePlan::Success,
            FakePlan::HealthFailed,
            FakePlan::Success,
        ]));
        let admission = admission();
        registry
            .connect_realm(&name, connector.as_ref(), admission.as_ref())
            .await
            .expect("initial connection");

        let changed = rootful().replace(
            "basil-attestor-production-docker.service",
            "basil-attestor-production-docker-v2.service",
        );
        let candidate = RealmSet::from_bootstrap(&bootstrap(&changed)).expect("valid candidate");
        assert_eq!(
            registry
                .prepare_reload(candidate, connector, Arc::clone(&admission), false)
                .await
                .map(|_| ()),
            Err(RealmError::Health)
        );
        assert_eq!(registry.generation(), 1);
        assert_eq!(registry.statuses()[0].state, RealmState::Ready);
        assert_eq!(admission.snapshot().current.active_preflights, 1);
    }

    #[tokio::test]
    async fn staged_candidate_never_serves_early_and_commit_is_atomic() {
        let realms = RealmSet::from_bootstrap(&bootstrap(&rootless(1000))).expect("valid realms");
        let name = RealmName::new("owner-podman").expect("valid realm");
        let registry = RealmRegistry::new(&realms, 1).expect("valid registry");
        let connector = Arc::new(FakeConnector::new([FakePlan::Success, FakePlan::Success]));
        let admission = admission();
        registry
            .connect_realm(&name, connector.as_ref(), admission.as_ref())
            .await
            .expect("initial connection");

        let candidate =
            RealmSet::from_bootstrap(&bootstrap(&rootless(1001))).expect("valid candidate");
        let prepared = registry
            .prepare_reload(candidate, connector, Arc::clone(&admission), false)
            .await
            .expect("candidate qualifies");
        assert_eq!(registry.generation(), 1);
        assert_eq!(registry.statuses()[0].session_epoch, 1);
        assert_eq!(admission.snapshot().current.active_preflights, 2);

        assert_eq!(prepared.commit().await.expect("commit"), 2);
        tokio::task::yield_now().await;
        assert_eq!(registry.generation(), 2);
        assert_eq!(registry.statuses()[0].session_epoch, 2);
        assert_eq!(admission.snapshot().current.active_preflights, 1);
    }

    #[tokio::test]
    async fn dropped_prepare_cleans_candidate_and_retains_authority() {
        let realms = RealmSet::from_bootstrap(&bootstrap(&rootless(1000))).expect("valid realms");
        let name = RealmName::new("owner-podman").expect("valid realm");
        let registry = RealmRegistry::new(&realms, 1).expect("valid registry");
        let connector = Arc::new(FakeConnector::new([FakePlan::Success, FakePlan::Success]));
        let admission = admission();
        registry
            .connect_realm(&name, connector.as_ref(), admission.as_ref())
            .await
            .expect("initial connection");
        let candidate =
            RealmSet::from_bootstrap(&bootstrap(&rootless(1001))).expect("valid candidate");
        let prepared = registry
            .prepare_reload(candidate, connector, Arc::clone(&admission), false)
            .await
            .expect("candidate qualifies");
        drop(prepared);
        tokio::task::yield_now().await;
        assert_eq!(registry.generation(), 1);
        assert_eq!(registry.statuses()[0].state, RealmState::Ready);
        assert_eq!(admission.snapshot().current.active_preflights, 1);
    }

    #[tokio::test]
    async fn cancelled_same_socket_prepare_restores_before_releasing_lease() {
        let realms = RealmSet::from_bootstrap(&bootstrap(rootful())).expect("valid realms");
        let name = RealmName::new("production-docker").expect("valid realm");
        let registry = RealmRegistry::new(&realms, 1).expect("valid registry");
        let connector = Arc::new(FakeConnector::new([
            FakePlan::Success,
            FakePlan::BlockConnect,
            FakePlan::Success,
        ]));
        let admission = admission();
        registry
            .connect_realm(&name, connector.as_ref(), admission.as_ref())
            .await
            .expect("initial connection");
        let changed = rootful().replace(
            "basil-attestor-production-docker.service",
            "basil-attestor-production-docker-v2.service",
        );
        let candidate = RealmSet::from_bootstrap(&bootstrap(&changed)).expect("valid candidate");
        let task_registry = registry.clone();
        let task_connector = Arc::clone(&connector);
        let task_admission = Arc::clone(&admission);
        let task = tokio::spawn(async move {
            task_registry
                .prepare_reload(candidate, task_connector, task_admission, false)
                .await
        });
        while connector.connects.load(Ordering::SeqCst) < 2 {
            tokio::task::yield_now().await;
        }
        task.abort();
        let _ = task.await;
        for _ in 0..100 {
            if registry.statuses()[0].state == RealmState::Ready {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(registry.generation(), 1);
        assert_eq!(registry.statuses()[0].state, RealmState::Ready);
        assert_eq!(connector.connects.load(Ordering::SeqCst), 3);
        assert_eq!(admission.snapshot().current.active_preflights, 1);
    }

    #[tokio::test]
    async fn stale_revalidation_rejects_without_publishing_candidate() {
        let realms = RealmSet::from_bootstrap(&bootstrap(&rootless(1000))).expect("valid realms");
        let name = RealmName::new("owner-podman").expect("valid realm");
        let registry = RealmRegistry::new(&realms, 1).expect("valid registry");
        let connector = Arc::new(FakeConnector::new([FakePlan::Success, FakePlan::Success]));
        let admission = admission();
        registry
            .connect_realm(&name, connector.as_ref(), admission.as_ref())
            .await
            .expect("initial connection");
        let candidate =
            RealmSet::from_bootstrap(&bootstrap(&rootless(1001))).expect("valid candidate");
        let prepared = registry
            .prepare_reload(
                candidate,
                Arc::clone(&connector) as Arc<dyn RealmConnector>,
                Arc::clone(&admission),
                false,
            )
            .await
            .expect("candidate qualifies");
        *connector
            .revalidate_failure
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = true;
        assert_eq!(prepared.commit().await, Err(RealmError::Stale));
        tokio::task::yield_now().await;
        assert_eq!(registry.generation(), 1);
        assert_eq!(registry.statuses()[0].session_epoch, 1);
        assert_eq!(admission.snapshot().current.active_preflights, 1);
    }

    #[test]
    fn poisoned_registry_lock_is_recovered() {
        let realms = RealmSet::from_bootstrap(&bootstrap(rootful())).expect("valid realms");
        let registry = RealmRegistry::new(&realms, 1).expect("valid registry");
        let inner = Arc::clone(&registry.inner);
        let _ = std::thread::spawn(move || {
            let _guard = inner.state.lock().unwrap_or_else(PoisonError::into_inner);
            panic!("poison test lock");
        })
        .join();
        assert_eq!(registry.generation(), 1);
    }

    #[test]
    fn reconnect_backoff_is_capped_with_positive_bounded_jitter() {
        for backoff in [INITIAL_RECONNECT_BACKOFF, MAX_RECONNECT_BACKOFF] {
            for _ in 0..32 {
                let delay = reconnect_delay(backoff).expect("random jitter");
                assert!(delay >= backoff);
                assert!(delay <= backoff + Duration::from_millis(250));
            }
        }
    }

    #[tokio::test]
    async fn remove_readd_uses_tombstone_revision() {
        let realms = RealmSet::from_bootstrap(&bootstrap(&rootless(1000))).expect("valid realms");
        let name = RealmName::new("owner-podman").expect("valid realm");
        let registry = RealmRegistry::new(&realms, 1).expect("valid registry");
        let connector = Arc::new(FakeConnector::new([FakePlan::Success, FakePlan::Success]));
        let admission = admission();
        registry
            .connect_realm(&name, connector.as_ref(), admission.as_ref())
            .await
            .expect("initial connection");

        registry
            .prepare_reload(
                RealmSet::default(),
                Arc::clone(&connector) as Arc<dyn RealmConnector>,
                Arc::clone(&admission),
                false,
            )
            .await
            .expect("removal prepares")
            .commit()
            .await
            .expect("removal commits");
        assert_eq!(registry.lock_state().tombstones.get(&name), Some(&1));

        registry
            .prepare_reload(realms, connector, Arc::clone(&admission), false)
            .await
            .expect("re-add prepares")
            .commit()
            .await
            .expect("re-add commits");
        assert_eq!(registry.lock_state().entries[&name].revision, 2);
    }
}
