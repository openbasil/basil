// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Concrete authenticated Unix transport for runtime-attestor realms.

use std::fs;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use rustix::io::Errno;
use rustix::process::{Pid, PidfdFlags, pidfd_open};
use sha2::{Digest as _, Sha256};
use tokio::net::UnixStream;

use super::attestor_realm::{
    AuthenticatedRealmSession, RealmConfig, RealmConnection, RealmConnector, RealmError, RealmMode,
    RealmSession, SocketIdentity,
};
use super::catalog::evidence::SystemdEvidence;
use super::process_evidence::{LinuxProcfs, PeerCredentials, PinnedProcess};
use super::release_admission::{ArtifactRequirement, ReleaseAdmission, Sha256Digest};
use crate::attestor_protocol::{
    BrokerSession, CapturedUnixStream, InventoryResult, ProtocolError, ProtocolLimits, QueryScope,
    RequestBudget, ResolvePeerResult, SessionAuthentication, VerifiedPeerBinding, wire,
};

const ACL_ACCESS: &str = "system.posix_acl_access";
const ACL_DEFAULT: &str = "system.posix_acl_default";
const BINDING_DOMAIN: &[u8] = b"basil.realm.peer-binding.v1\0";
const ACL_XATTR_VERSION: u32 = 2;
const ACL_USER_OBJ: u16 = 0x01;
const ACL_USER: u16 = 0x02;
const ACL_GROUP_OBJ: u16 = 0x04;
const ACL_MASK: u16 = 0x10;
const ACL_OTHER: u16 = 0x20;
const MAX_ACL_XATTR_BYTES: usize = 4096;

/// Concrete connector for one protected runtime-attestor Unix socket.
#[derive(Clone)]
pub struct UnixRealmConnector {
    broker_binding: VerifiedPeerBinding,
    limits: ProtocolLimits,
    procfs: LinuxProcfs,
}

impl UnixRealmConnector {
    /// Construct the production Linux connector.
    #[must_use]
    pub fn new(broker_binding: VerifiedPeerBinding, limits: ProtocolLimits) -> Self {
        Self {
            broker_binding,
            limits,
            procfs: LinuxProcfs::default(),
        }
    }
}

struct UnixRealmConnection {
    captured: CapturedUnixStream,
    path: PathBuf,
    path_identity: SocketIdentity,
    broker_binding: VerifiedPeerBinding,
    limits: ProtocolLimits,
    procfs: LinuxProcfs,
}

#[async_trait]
impl RealmConnector for UnixRealmConnector {
    async fn connect(&self, config: &RealmConfig) -> Result<Box<dyn RealmConnection>, RealmError> {
        let before = authenticate_socket_path(config)?;
        let stream = UnixStream::connect(&config.measurement.socket_path)
            .await
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    RealmError::SocketAbsent
                } else {
                    RealmError::Connect
                }
            })?;
        let after = authenticate_socket_path(config)?;
        if before != after {
            return Err(RealmError::Authentication);
        }
        let captured =
            CapturedUnixStream::capture(stream).map_err(|_| RealmError::Authentication)?;
        Ok(Box::new(UnixRealmConnection {
            captured,
            path: config.measurement.socket_path.clone(),
            path_identity: before,
            broker_binding: self.broker_binding,
            limits: self.limits,
            procfs: self.procfs.clone(),
        }))
    }

    async fn revalidate(
        &self,
        config: &RealmConfig,
        identity: SocketIdentity,
    ) -> Result<(), RealmError> {
        if authenticate_socket_path(config)? == identity {
            Ok(())
        } else {
            Err(RealmError::Stale)
        }
    }
}

#[async_trait]
impl RealmConnection for UnixRealmConnection {
    async fn authenticate(
        self: Box<Self>,
        config: &RealmConfig,
        generation: u64,
        epoch: u64,
        admission: &ReleaseAdmission,
    ) -> Result<AuthenticatedRealmSession, RealmError> {
        if self.path != config.measurement.socket_path
            || authenticate_socket_path(config)? != self.path_identity
        {
            return Err(RealmError::Authentication);
        }
        let credentials = self.captured.credentials();
        let pid = credentials.pid.ok_or(RealmError::Authentication)?;
        if pid == 0 || credentials.uid != config.attestor_user.uid() {
            return Err(RealmError::Authentication);
        }
        let raw_pid = i32::try_from(pid).map_err(|_| RealmError::Authentication)?;
        let kernel_pid = Pid::from_raw(raw_pid).ok_or(RealmError::Authentication)?;
        let pidfd = match pidfd_open(kernel_pid, PidfdFlags::empty()) {
            Ok(fd) => Some(fd),
            Err(Errno::NOSYS) => None,
            Err(_) => return Err(RealmError::Authentication),
        };
        let peer = PeerCredentials {
            pid,
            uid: credentials.uid,
            gid: credentials.gid,
        };
        let procfs = self.procfs.clone();
        let mut pin = tokio::task::spawn_blocking(move || procfs.capture(peer))
            .await
            .map_err(|_| RealmError::Authentication)?
            .map_err(|_| RealmError::Authentication)?;
        verify_unit(config, &pin)?;
        let digest = parse_digest(pin.executable_digest().ok_or(RealmError::Authentication)?)?;
        let requirement = ArtifactRequirement::new(
            digest,
            config.release_role.clone(),
            config.target.clone(),
            config.protocol,
            config.capabilities.clone(),
        );
        let active = admission
            .begin_preflight(&requirement)
            .map_err(|_| RealmError::Admission)?;
        let procfs = self.procfs.clone();
        pin = tokio::task::spawn_blocking(move || {
            procfs.revalidate(&mut pin)?;
            Ok::<_, super::process_evidence::ProcessEvidenceError>(pin)
        })
        .await
        .map_err(|_| RealmError::Authentication)?
        .map_err(|_| RealmError::Authentication)?;
        verify_unit(config, &pin)?;
        if parse_digest(pin.executable_digest().ok_or(RealmError::Authentication)?)? != digest
            || authenticate_socket_path(config)? != self.path_identity
        {
            return Err(RealmError::Authentication);
        }
        let attestor_binding = binding(
            config,
            credentials,
            &pin,
            self.path_identity,
            &active,
            generation,
            epoch,
        );
        let authentication = SessionAuthentication {
            generation,
            broker: self.broker_binding,
            attestor: attestor_binding,
        };
        let codec = self.captured.into_framed(attestor_binding, self.limits);
        let required = config
            .capabilities
            .iter()
            .map(|item| item.as_str().to_string());
        let session = BrokerSession::new(codec, authentication, required, self.limits)
            .map_err(|_| RealmError::Protocol)?;
        Ok(AuthenticatedRealmSession::new(
            Box::new(UnixBrokerRealmSession {
                inner: session,
                _pidfd: pidfd,
            }),
            active,
            self.path_identity,
            attestor_binding,
        ))
    }

    async fn close(self: Box<Self>) {}
}

struct UnixBrokerRealmSession {
    inner: BrokerSession<UnixStream>,
    _pidfd: Option<OwnedFd>,
}

#[async_trait]
impl RealmSession for UnixBrokerRealmSession {
    async fn handshake(&mut self) -> Result<(), RealmError> {
        self.inner
            .handshake()
            .await
            .map_err(|_| RealmError::Protocol)
    }

    fn negotiated_capabilities(&self) -> &[String] {
        self.inner.negotiated_capabilities()
    }

    async fn health(&mut self, budget: RequestBudget) -> Result<wire::HealthFact, RealmError> {
        let result = self
            .inner
            .health(budget)
            .await
            .map_err(|error| protocol_error(&error))?;
        result.health.ok_or(RealmError::Health)
    }

    async fn resolve_peer(
        &mut self,
        peer: wire::PinnedPeer,
        budget: RequestBudget,
    ) -> Result<ResolvePeerResult, RealmError> {
        self.inner
            .resolve_peer(peer, budget)
            .await
            .map_err(|error| protocol_error(&error))
    }

    async fn query_instances(
        &mut self,
        scope: QueryScope,
        budget: RequestBudget,
    ) -> Result<InventoryResult, RealmError> {
        self.inner
            .query_instances(scope, budget)
            .await
            .map_err(|error| protocol_error(&error))
    }

    async fn close(&mut self) {}
}

/// Map a protocol failure to its disclosure-safe realm error, preserving the
/// distinct pre-dispatch budget-exhaustion case.
const fn protocol_error(error: &ProtocolError) -> RealmError {
    if matches!(error, ProtocolError::BudgetExhausted) {
        RealmError::BudgetExhausted
    } else {
        RealmError::Protocol
    }
}

/// Where one authenticated component sits on the protected socket path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PathPosition {
    /// A directory above the declared runtime directory.
    Ancestor,
    /// The declared generation-qualified runtime directory itself.
    RuntimeDirectory,
    /// The declared control-socket leaf.
    Socket,
}

/// Authenticate every component of the configured socket path against the
/// protected [`MeasurementAuthority`](super::attestor_realm::MeasurementAuthority):
/// the runtime directory and socket leaf must carry exactly the declared
/// owner, group, mode, and derived access-ACL profile; ancestors must be
/// unwritable to group/other and carry only the expected traverse profile.
fn authenticate_socket_path(config: &RealmConfig) -> Result<SocketIdentity, RealmError> {
    let measurement = &config.measurement;
    let mut current = PathBuf::from("/");
    for component in measurement.socket_path.components().skip(1) {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                RealmError::SocketAbsent
            } else {
                RealmError::Authentication
            }
        })?;
        if metadata.file_type().is_symlink() {
            return Err(RealmError::Authentication);
        }
        let position = if current == measurement.socket_path {
            PathPosition::Socket
        } else if current == measurement.runtime_directory {
            PathPosition::RuntimeDirectory
        } else {
            PathPosition::Ancestor
        };
        let authentic = match position {
            PathPosition::Socket => {
                metadata.file_type().is_socket()
                    && metadata.uid() == measurement.socket_owner.uid()
                    && metadata.gid() == measurement.socket_group.gid()
                    && metadata.mode() & 0o7777 == measurement.socket_mode.bits()
            }
            PathPosition::RuntimeDirectory => {
                metadata.file_type().is_dir()
                    && metadata.uid() == measurement.runtime_directory_owner.uid()
                    && metadata.gid() == measurement.runtime_directory_group.gid()
                    && metadata.mode() & 0o7777 == measurement.runtime_directory_mode.bits()
            }
            PathPosition::Ancestor => {
                metadata.file_type().is_dir()
                    && (metadata.uid() == 0 || metadata.uid() == config.attestor_user.uid())
                    && metadata.mode() & 0o022 == 0
            }
        };
        if !authentic {
            return Err(RealmError::Authentication);
        }
        authenticate_acl(&current, &metadata, config, position)?;
        if position == PathPosition::Socket {
            return Ok(SocketIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
                owner: metadata.uid(),
                group: metadata.gid(),
                mode: metadata.mode(),
            });
        }
    }
    Err(RealmError::Authentication)
}

fn authenticate_acl(
    path: &Path,
    metadata: &fs::Metadata,
    config: &RealmConfig,
    position: PathPosition,
) -> Result<(), RealmError> {
    if read_acl(path, ACL_DEFAULT)?.is_some() {
        return Err(RealmError::Authentication);
    }
    if read_acl(path, ACL_ACCESS)? == expected_access_acl(config, metadata.uid(), position) {
        Ok(())
    } else {
        Err(RealmError::Authentication)
    }
}

/// Return the exact access-ACL profile one authenticated component must
/// carry, or `None` when it must carry no access ACL.
///
/// With distinct broker and attestor accounts the runtime directory and
/// socket always carry the enrollment-installed profile derived from their
/// declared modes plus the broker's traverse/connect entry; a root-owned
/// ancestor must stay ACL-free while an attestor-owned ancestor carries only
/// the broker traverse profile. With one shared account no named entry is
/// needed and any access ACL rejects.
fn expected_access_acl(
    config: &RealmConfig,
    owner: u32,
    position: PathPosition,
) -> Option<Vec<AclEntry>> {
    let broker = config.broker_user.uid();
    if broker == config.attestor_user.uid() {
        return None;
    }
    match position {
        PathPosition::Ancestor => (owner != 0).then(|| {
            vec![
                AclEntry::base(ACL_USER_OBJ, 0o7),
                AclEntry::named_user(broker, 0o1),
                AclEntry::base(ACL_GROUP_OBJ, 0),
                AclEntry::base(ACL_MASK, 0o1),
                AclEntry::base(ACL_OTHER, 0),
            ]
        }),
        PathPosition::RuntimeDirectory => Some(mode_bound_acl(
            config.measurement.runtime_directory_mode.bits(),
            broker,
            0o1,
        )),
        PathPosition::Socket => Some(mode_bound_acl(
            config.measurement.socket_mode.bits(),
            broker,
            0o6,
        )),
    }
}

/// Exact access-ACL entries consistent with one declared octal mode plus one
/// named broker entry: the owner triad is `USER_OBJ`, the declared group
/// triad is both `GROUP_OBJ` (the protected bind group) and `MASK` (which the
/// kernel mirrors into the group mode bits), and the other triad is `OTHER`.
fn mode_bound_acl(mode: u32, broker: u32, broker_permissions: u16) -> Vec<AclEntry> {
    let triad = |shift: u32| u16::try_from((mode >> shift) & 0o7).unwrap_or(0);
    vec![
        AclEntry::base(ACL_USER_OBJ, triad(6)),
        AclEntry::named_user(broker, broker_permissions),
        AclEntry::base(ACL_GROUP_OBJ, triad(3)),
        AclEntry::base(ACL_MASK, triad(3)),
        AclEntry::base(ACL_OTHER, triad(0)),
    ]
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AclEntry {
    tag: u16,
    permissions: u16,
    id: u32,
}

impl AclEntry {
    const fn base(tag: u16, permissions: u16) -> Self {
        Self {
            tag,
            permissions,
            id: u32::MAX,
        }
    }

    const fn named_user(id: u32, permissions: u16) -> Self {
        Self {
            tag: ACL_USER,
            permissions,
            id,
        }
    }
}

fn read_acl(path: &Path, name: &str) -> Result<Option<Vec<AclEntry>>, RealmError> {
    let mut buffer = vec![0_u8; MAX_ACL_XATTR_BYTES];
    let length = match rustix::fs::lgetxattr(path, name, &mut buffer) {
        Ok(length) => length,
        Err(Errno::NODATA) => return Ok(None),
        Err(_) => return Err(RealmError::Authentication),
    };
    if length == 0 || length > MAX_ACL_XATTR_BYTES {
        return Err(RealmError::Authentication);
    }
    let bytes = buffer.get(..length).ok_or(RealmError::Authentication)?;
    parse_acl(bytes).map(Some)
}

fn parse_acl(bytes: &[u8]) -> Result<Vec<AclEntry>, RealmError> {
    let (header, entries) = bytes
        .split_at_checked(4)
        .ok_or(RealmError::Authentication)?;
    let version = u32::from_le_bytes(header.try_into().map_err(|_| RealmError::Authentication)?);
    if version != ACL_XATTR_VERSION || entries.len() % 8 != 0 {
        return Err(RealmError::Authentication);
    }
    let mut parsed = Vec::with_capacity(entries.len() / 8);
    for entry in entries.chunks_exact(8) {
        let (tag, rest) = entry
            .split_at_checked(2)
            .ok_or(RealmError::Authentication)?;
        let (permissions, id) = rest.split_at_checked(2).ok_or(RealmError::Authentication)?;
        parsed.push(AclEntry {
            tag: u16::from_le_bytes(tag.try_into().map_err(|_| RealmError::Authentication)?),
            permissions: u16::from_le_bytes(
                permissions
                    .try_into()
                    .map_err(|_| RealmError::Authentication)?,
            ),
            id: u32::from_le_bytes(id.try_into().map_err(|_| RealmError::Authentication)?),
        });
    }
    Ok(parsed)
}

fn verify_unit(config: &RealmConfig, pin: &PinnedProcess) -> Result<(), RealmError> {
    let expected = SystemdEvidence {
        unit: config.measurement.service_unit.clone(),
        template: config.measurement.service_unit.find('@').map(|at| {
            let mut value = config.measurement.service_unit.clone();
            value.replace_range(at + 1..value.len() - ".service".len(), "");
            value
        }),
        manager_user: match config.runtime_mode {
            RealmMode::RootlessOwner => Some(config.attestor_user.uid()),
            RealmMode::RootfulHost => None,
        },
    };
    if pin.systemd_evidence() != Some(&expected) || pin.start_time_ticks() == 0 {
        return Err(RealmError::Authentication);
    }
    if config.runtime_mode == RealmMode::RootlessOwner {
        let component = format!("user-{}.slice", config.attestor_user.uid());
        if !pin.cgroups().iter().any(|line| {
            line.rsplit_once(':')
                .is_some_and(|(_, path)| path.split('/').any(|actual| actual == component))
        }) {
            return Err(RealmError::Authentication);
        }
    }
    Ok(())
}

fn parse_digest(value: &str) -> Result<Sha256Digest, RealmError> {
    let encoded = value
        .strip_prefix("sha256:")
        .ok_or(RealmError::Authentication)?;
    if encoded.len() != 64 {
        return Err(RealmError::Authentication);
    }
    let mut bytes = [0_u8; 32];
    for (output, pair) in bytes.iter_mut().zip(encoded.as_bytes().chunks_exact(2)) {
        let [high, low] = pair else {
            return Err(RealmError::Authentication);
        };
        let high = hex_nibble(*high).ok_or(RealmError::Authentication)?;
        let low = hex_nibble(*low).ok_or(RealmError::Authentication)?;
        *output = (high << 4) | low;
    }
    Ok(Sha256Digest::from_bytes(bytes))
}

const fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn binding(
    config: &RealmConfig,
    credentials: crate::attestor_protocol::PeerCredentials,
    pin: &PinnedProcess,
    socket: SocketIdentity,
    active: &super::release_admission::ActiveArtifact,
    generation: u64,
    epoch: u64,
) -> VerifiedPeerBinding {
    let executable = pin.executable_object();
    let mut digest = Sha256::new();
    digest.update(BINDING_DOMAIN);
    for value in [
        u64::from(credentials.pid.unwrap_or_default()),
        u64::from(credentials.uid),
        u64::from(credentials.gid),
        pin.start_time_ticks(),
        socket.device,
        socket.inode,
        u64::from(socket.owner),
        u64::from(socket.group),
        u64::from(socket.mode),
        executable.device,
        executable.inode,
        executable.size,
        generation,
        epoch,
    ] {
        digest.update(value.to_be_bytes());
    }
    for value in [
        config.measurement.service_unit.as_bytes(),
        pin.executable_digest().unwrap_or_default().as_bytes(),
        active.release().product().as_str().as_bytes(),
        active.release().release().as_str().as_bytes(),
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
    VerifiedPeerBinding::from_authenticator(digest.finalize().into())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::net::UnixListener;

    use super::*;
    use crate::attestor_protocol::{AttestorRequest, AttestorSession};
    use crate::core::attestor_realm::{RealmName, RealmRegistry, RealmSet};
    use crate::core::release_admission::{
        HistoricalReleaseIdentityCheck, ProductId, ReleaseArtifact, ReleaseId,
        VerifiedReleaseManifest,
    };

    const BROKER_BINDING: VerifiedPeerBinding = VerifiedPeerBinding::from_authenticator([0x42; 32]);

    fn live_body() -> String {
        let broker_uid = std::env::var("BASIL_REALM_BROKER_UID")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or_else(|| rustix::process::geteuid().as_raw());
        let attestor_uid = std::env::var("BASIL_REALM_ATTESTOR_UID")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or_else(|| rustix::process::geteuid().as_raw());
        // Both the server and the connector must derive identical declared
        // values, so the default follows the Fedora user-private-group
        // convention (gid == uid) rather than either process's own egid.
        let declared_gid = std::env::var("BASIL_REALM_ATTESTOR_GID")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(attestor_uid);
        let unit = std::env::var("BASIL_REALM_EXPECTED_UNIT")
            .unwrap_or_else(|_| "basil-attestor-owner-podman-g1.service".to_string());
        fixture_body(broker_uid, attestor_uid, declared_gid, &unit)
    }

    fn fixture_body(broker_uid: u32, attestor_uid: u32, declared_gid: u32, unit: &str) -> String {
        format!(
            r#"
schema = "agent"
schemaVersion = 3
[import]
catalog = "catalog.json"
policy = "policy.json"
bundle = "bundle.json"
[attestor.realms.owner-podman]
provider = "podman"
runtimeMode = "rootless-owner"
brokerUser = "{broker_uid}"
brokerUnit = "basil-agent.service"
attestorUid = "{attestor_uid}"
releaseRole = "podman-attestor"
target = "x86_64-unknown-linux-gnu"
protocol = 1
capabilities = ["health", "query-instances", "resolve-peer"]
[attestor.realms.owner-podman.measurement]
authorityGeneration = 1
serviceUnit = "{unit}"
helperEndpoint = "/run/basil/measure/control.sock"
helperPolicy = "basil-measure-policy-g1"
helperPolicyGeneration = 1
lsmProfile = "selinux:basil_attestor_g1_t"
lsmPolicy = "basil-attestor-policy-g1"
lockdownProfile = "basil-attestor-lockdown-g1"
runtimeDirectory = "/run/basil/attestors/owner-podman/g1"
runtimeDirectoryOwner = "{attestor_uid}"
runtimeDirectoryGroup = "{declared_gid}"
runtimeDirectoryMode = "0770"
runtimeDirectoryAcl = "basil-attestor-bind-g1"
socketPath = "/run/basil/attestors/owner-podman/g1/control.sock"
socketOwner = "{attestor_uid}"
socketGroup = "{declared_gid}"
socketMode = "0660"
socketAcl = "basil-attestor-control-g1"
"#
        )
    }

    fn live_config() -> RealmConfig {
        let body = live_body();
        let value: toml::Value = toml::from_str(&body).unwrap();
        let realms = RealmSet::from_bootstrap(&value).unwrap();
        realms
            .get(&RealmName::new("owner-podman").unwrap())
            .unwrap()
            .clone()
    }

    fn current_pin() -> PinnedProcess {
        let pid = rustix::process::getpid().as_raw_nonzero().get();
        LinuxProcfs::default()
            .capture(PeerCredentials {
                pid: u32::try_from(pid).unwrap(),
                uid: rustix::process::geteuid().as_raw(),
                gid: rustix::process::getegid().as_raw(),
            })
            .unwrap()
    }

    fn admission(config: &RealmConfig, pin: &PinnedProcess) -> Arc<ReleaseAdmission> {
        let digest = parse_digest(pin.executable_digest().unwrap()).unwrap();
        let artifact = ReleaseArtifact::new(
            config.release_role.clone(),
            config.target.clone(),
            digest,
            config.protocol,
            config.capabilities.clone(),
        );
        let manifest = VerifiedReleaseManifest::from_verified_parts(
            HistoricalReleaseIdentityCheck::completed(),
            ProductId::new("basil").unwrap(),
            ReleaseId::new("realm-live-test").unwrap(),
            [artifact],
        )
        .unwrap();
        Arc::new(ReleaseAdmission::new(manifest))
    }

    fn encoded_acl(entries: &[AclEntry]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4 + entries.len() * 8);
        bytes.extend_from_slice(&ACL_XATTR_VERSION.to_le_bytes());
        for entry in entries {
            bytes.extend_from_slice(&entry.tag.to_le_bytes());
            bytes.extend_from_slice(&entry.permissions.to_le_bytes());
            bytes.extend_from_slice(&entry.id.to_le_bytes());
        }
        bytes
    }

    /// Install the runtime directory, socket, and declared modes exactly as
    /// the measurement authority describes them, then the enrollment ACLs.
    fn install_live_socket(config: &RealmConfig) -> UnixListener {
        let parent = config.measurement.socket_path.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        fs::set_permissions(
            parent,
            std::os::unix::fs::PermissionsExt::from_mode(
                config.measurement.runtime_directory_mode.bits(),
            ),
        )
        .unwrap();
        let _ = fs::remove_file(&config.measurement.socket_path);
        let listener = UnixListener::bind(&config.measurement.socket_path).unwrap();
        fs::set_permissions(
            &config.measurement.socket_path,
            std::os::unix::fs::PermissionsExt::from_mode(config.measurement.socket_mode.bits()),
        )
        .unwrap();
        install_live_acl(config);
        listener
    }

    /// Install the exact enrollment ACL profiles the connector authenticates,
    /// derived from `expected_access_acl` so test installation cannot drift
    /// from the production expectation. Setting the access ACL also syncs the
    /// group mode bits to the profile mask, matching the declared modes.
    fn install_live_acl(config: &RealmConfig) {
        if config.broker_user.uid() == config.attestor_user.uid() {
            return;
        }
        let owner = rustix::process::geteuid().as_raw();
        let runtime = PathBuf::from("/run/basil/attestors");
        let parent = config.measurement.socket_path.parent().unwrap();
        for ancestor in parent
            .ancestors()
            .take_while(|path| *path != Path::new("/run/basil/attestors"))
        {
            if !ancestor.starts_with(&runtime) {
                continue;
            }
            let position = if *ancestor == config.measurement.runtime_directory {
                PathPosition::RuntimeDirectory
            } else {
                PathPosition::Ancestor
            };
            let entries = expected_access_acl(config, owner, position).unwrap();
            rustix::fs::lsetxattr(
                ancestor,
                ACL_ACCESS,
                &encoded_acl(&entries),
                rustix::fs::XattrFlags::empty(),
            )
            .unwrap();
        }
        let mut socket_entries = expected_access_acl(config, owner, PathPosition::Socket).unwrap();
        if let Ok(value) = std::env::var("BASIL_REALM_EXTRA_ACL_UID")
            && let Ok(uid) = value.parse::<u32>()
        {
            let position = if uid < config.broker_user.uid() { 1 } else { 2 };
            socket_entries.insert(position, AclEntry::named_user(uid, 0o6));
        }
        rustix::fs::lsetxattr(
            &config.measurement.socket_path,
            ACL_ACCESS,
            &encoded_acl(&socket_entries),
            rustix::fs::XattrFlags::empty(),
        )
        .unwrap();
    }

    #[test]
    fn protocol_error_mapping_preserves_budget_exhaustion() {
        assert_eq!(
            protocol_error(&ProtocolError::BudgetExhausted),
            RealmError::BudgetExhausted
        );
        assert_eq!(
            protocol_error(&ProtocolError::DeadlineExceeded),
            RealmError::Protocol
        );
        assert_eq!(protocol_error(&ProtocolError::Closed), RealmError::Protocol);
    }

    #[test]
    fn digest_profile_rejects_uppercase_and_wrong_length() {
        assert!(parse_digest(&format!("sha256:{}", "a".repeat(64))).is_ok());
        assert_eq!(
            parse_digest(&format!("sha256:{}", "A".repeat(64))),
            Err(RealmError::Authentication)
        );
        assert_eq!(parse_digest("sha256:aa"), Err(RealmError::Authentication));
    }

    fn fixture_config(broker_uid: u32, attestor_uid: u32) -> RealmConfig {
        let body = fixture_body(
            broker_uid,
            attestor_uid,
            attestor_uid,
            "basil-attestor-owner-podman-g1.service",
        );
        let value: toml::Value = toml::from_str(&body).unwrap();
        let realms = RealmSet::from_bootstrap(&value).unwrap();
        realms
            .get(&RealmName::new("owner-podman").unwrap())
            .unwrap()
            .clone()
    }

    #[test]
    fn expected_acl_profiles_follow_the_declared_authority() {
        let config = fixture_config(100, 200);
        // A root-owned ancestor must stay ACL-free; an attestor-owned
        // ancestor carries only the broker traverse profile.
        assert_eq!(
            expected_access_acl(&config, 0, PathPosition::Ancestor),
            None
        );
        assert_eq!(
            expected_access_acl(&config, 200, PathPosition::Ancestor),
            Some(vec![
                AclEntry::base(ACL_USER_OBJ, 0o7),
                AclEntry::named_user(100, 0o1),
                AclEntry::base(ACL_GROUP_OBJ, 0),
                AclEntry::base(ACL_MASK, 0o1),
                AclEntry::base(ACL_OTHER, 0),
            ])
        );
        // The runtime directory profile mirrors the declared 0770 mode plus
        // the broker traverse entry, regardless of component owner.
        assert_eq!(
            expected_access_acl(&config, 0, PathPosition::RuntimeDirectory),
            Some(vec![
                AclEntry::base(ACL_USER_OBJ, 0o7),
                AclEntry::named_user(100, 0o1),
                AclEntry::base(ACL_GROUP_OBJ, 0o7),
                AclEntry::base(ACL_MASK, 0o7),
                AclEntry::base(ACL_OTHER, 0),
            ])
        );
        // The socket profile mirrors the declared 0660 mode plus the broker
        // connect entry.
        assert_eq!(
            expected_access_acl(&config, 200, PathPosition::Socket),
            Some(vec![
                AclEntry::base(ACL_USER_OBJ, 0o6),
                AclEntry::named_user(100, 0o6),
                AclEntry::base(ACL_GROUP_OBJ, 0o6),
                AclEntry::base(ACL_MASK, 0o6),
                AclEntry::base(ACL_OTHER, 0),
            ])
        );
    }

    #[test]
    fn shared_broker_and_attestor_account_forbids_every_access_acl() {
        let config = fixture_config(300, 300);
        for position in [
            PathPosition::Ancestor,
            PathPosition::RuntimeDirectory,
            PathPosition::Socket,
        ] {
            assert_eq!(expected_access_acl(&config, 300, position), None);
            assert_eq!(expected_access_acl(&config, 0, position), None);
        }
    }

    #[test]
    fn exact_acl_parser_accepts_bounded_profile_and_preserves_named_user() {
        let expected = vec![
            AclEntry::base(ACL_USER_OBJ, 0o6),
            AclEntry::named_user(1002, 0o6),
            AclEntry::base(ACL_GROUP_OBJ, 0),
            AclEntry::base(ACL_MASK, 0o6),
            AclEntry::base(ACL_OTHER, 0),
        ];
        assert_eq!(parse_acl(&encoded_acl(&expected)).unwrap(), expected);
        assert_eq!(parse_acl(&[]), Err(RealmError::Authentication));
    }

    #[tokio::test]
    #[ignore = "requires a transient systemd --user service"]
    async fn live_unix_realm_systemd_server() {
        let config = live_config();
        let listener = install_live_socket(&config);
        let ready = std::env::var("BASIL_REALM_READY").unwrap();
        let server_pid = rustix::process::getpid().as_raw_nonzero().get();
        fs::write(&ready, format!("{server_pid}\n")).unwrap();
        let mode = std::env::var("BASIL_REALM_SERVER_MODE").unwrap();
        let count = if mode == "accept" { 2 } else { 1 };
        for epoch in 1..=count {
            let accepted = if mode == "accept" {
                Some(listener.accept().await.unwrap())
            } else {
                tokio::time::timeout(Duration::from_secs(5), listener.accept())
                    .await
                    .ok()
                    .map(Result::unwrap)
            };
            let Some((stream, _)) = accepted else {
                eprintln!("BASIL_PRE_HANDSHAKE_REJECTION_CONFIRMED_NO_CONNECT pid={server_pid}");
                return;
            };
            let pin = current_pin();
            let admission = admission(&config, &pin);
            let active = admission
                .begin_preflight(&ArtifactRequirement::new(
                    parse_digest(pin.executable_digest().unwrap()).unwrap(),
                    config.release_role.clone(),
                    config.target.clone(),
                    config.protocol,
                    config.capabilities.clone(),
                ))
                .unwrap();
            let identity = authenticate_socket_path(&config).unwrap();
            let peer = crate::attestor_protocol::PeerCredentials {
                pid: Some(u32::try_from(rustix::process::getpid().as_raw_nonzero().get()).unwrap()),
                uid: rustix::process::geteuid().as_raw(),
                gid: rustix::process::getegid().as_raw(),
            };
            let attestor = binding(&config, peer, &pin, identity, &active, 1, epoch);
            let captured = CapturedUnixStream::capture(stream).unwrap();
            let codec = captured.into_framed(BROKER_BINDING, ProtocolLimits::default());
            let authentication = SessionAuthentication {
                generation: 1,
                broker: BROKER_BINDING,
                attestor,
            };
            let mut session = AttestorSession::new(
                codec,
                authentication,
                config
                    .capabilities
                    .iter()
                    .map(|item| item.as_str().to_string()),
                ProtocolLimits::default(),
            )
            .unwrap();
            if mode == "reject" {
                let rejected =
                    tokio::time::timeout(Duration::from_secs(5), session.handshake()).await;
                assert!(!matches!(rejected, Ok(Ok(()))));
                eprintln!("BASIL_PRE_HANDSHAKE_REJECTION_CONFIRMED pid={server_pid}");
                return;
            }
            session.handshake().await.unwrap();
            assert!(matches!(
                session.receive().await.unwrap(),
                AttestorRequest::Health { .. }
            ));
            session
                .respond_health(
                    wire::Outcome {
                        code: wire::OutcomeCode::Ok as i32,
                        diagnostic: String::new(),
                    },
                    Some(wire::HealthFact {
                        runtime: wire::RuntimeKind::Podman as i32,
                        diagnostic_version: "live-systemd-unit".to_string(),
                        runtime_mode: wire::RuntimeMode::Rootless as i32,
                        cgroup_mode: wire::CgroupMode::V2 as i32,
                        ready: true,
                        missing_capabilities: Vec::new(),
                    }),
                )
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    #[ignore = "requires a transient systemd --user service"]
    async fn live_unix_realm_systemd_connector() {
        let config = live_config();
        let expected = std::env::var("BASIL_REALM_EXPECT_RESULT").unwrap();
        let pin = current_pin();
        let admission = admission(&config, &pin);
        let connector = UnixRealmConnector::new(BROKER_BINDING, ProtocolLimits::default());
        let name = RealmName::new("owner-podman").unwrap();
        let value = toml::from_str(&live_body()).unwrap();
        let realms = RealmSet::from_bootstrap(&value).unwrap();
        let registry = RealmRegistry::new(&realms, 1).unwrap();
        let first = registry
            .connect_realm(&name, &connector, admission.as_ref())
            .await;
        if expected == "reject" {
            assert_eq!(first, Err(RealmError::Authentication));
            return;
        }
        first.unwrap();
        registry
            .connect_realm(&name, &connector, admission.as_ref())
            .await
            .unwrap();
        assert_eq!(registry.readiness().ready, 1);
    }

    #[test]
    #[ignore = "requires a live cross-UID attestor process"]
    fn live_cross_uid_kernel_diagnostic() {
        let pid = std::env::var("BASIL_REALM_TARGET_PID").unwrap();
        let parsed = pid.parse::<i32>().unwrap();
        let kernel_pid = Pid::from_raw(parsed).unwrap();
        match pidfd_open(kernel_pid, PidfdFlags::empty()) {
            Ok(_) => eprintln!("BASIL_CROSS_UID pidfd_open=ok"),
            Err(error) => eprintln!("BASIL_CROSS_UID pidfd_open=err:{error}"),
        }
        for field in ["stat", "status", "cgroup", "uid_map", "gid_map", "exe"] {
            let path = format!("/proc/{pid}/{field}");
            match fs::File::open(&path) {
                Ok(_) => eprintln!("BASIL_CROSS_UID open_{field}=ok"),
                Err(error) => eprintln!(
                    "BASIL_CROSS_UID open_{field}=err:{}:{:?}",
                    error,
                    error.raw_os_error()
                ),
            }
        }
        for namespace in ["user", "pid", "mnt", "net", "uts", "ipc", "cgroup"] {
            let path = format!("/proc/{pid}/ns/{namespace}");
            match fs::read_link(&path) {
                Ok(_) => eprintln!("BASIL_CROSS_UID ns_{namespace}=ok"),
                Err(error) => eprintln!(
                    "BASIL_CROSS_UID ns_{namespace}=err:{}:{:?}",
                    error,
                    error.raw_os_error()
                ),
            }
        }
    }
}
