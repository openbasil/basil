// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Non-serving listener preparation and no-replace socket publication.

use std::ffi::OsString;
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd as _;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use rustix::fs::{
    AtFlags, CWD, FileType, Mode, OFlags, RenameFlags, chmodat, chownat, fstat, mkdirat, openat,
    renameat_with, statat, unlinkat,
};
use rustix::process::Gid;
use thiserror::Error;
use tokio::net::UnixListener;

use super::connection::{ConnectionRegistry, ConnectionRegistryError, ListenerTransitionGuard};
use super::grpc_server::resolve_group;
use super::listener::{ListenerConfig, ListenerConfigSet, MAX_UNIX_SOCKET_PATH_BYTES};

const MAX_STAGE_ATTEMPTS: usize = 8;

/// Candidate listener transition classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListenerChangeKind {
    /// A new listener is added without affecting existing accepts.
    Add,
    /// An existing listener is removed.
    Remove,
    /// Type, path, mode, or group changes under an existing name.
    Reconfigure,
}

/// Bounded transition impact for one listener name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListenerImpact {
    name: String,
    kind: ListenerChangeKind,
    active_connections: usize,
}

impl ListenerImpact {
    /// Stable listener name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Candidate change classification.
    #[must_use]
    pub const fn kind(&self) -> ListenerChangeKind {
        self.kind
    }

    /// Exact active-transport count at assessment time.
    #[must_use]
    pub const fn active_connections(&self) -> usize {
        self.active_connections
    }
}

/// A disruptive listener transition still has accepted transports.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("listener transition requires zero active connections")]
pub struct ActiveListenerTransition {
    impacts: Vec<ListenerImpact>,
}

/// Failure to acquire and validate an atomic listener transition gate.
#[derive(Debug, Error)]
pub enum ListenerTransitionError {
    /// Another transition already gates an affected listener.
    #[error(transparent)]
    Registry(#[from] ConnectionRegistryError),
    /// A removal or reconfiguration still has accepted transports.
    #[error(transparent)]
    Active(#[from] ActiveListenerTransition),
}

impl ActiveListenerTransition {
    /// Disruptive affected listeners that remain active.
    #[must_use]
    pub fn impacts(&self) -> &[ListenerImpact] {
        &self.impacts
    }
}

/// Assess listener changes without binding, gating accepts, or mutating state.
#[must_use]
pub fn assess_transition(
    current: &ListenerConfigSet,
    candidate: &ListenerConfigSet,
    connections: &ConnectionRegistry,
) -> Vec<ListenerImpact> {
    let mut impacts = Vec::new();
    for listener in current.iter() {
        let kind = match candidate.get(listener.name()) {
            None => Some(ListenerChangeKind::Remove),
            Some(replacement) if replacement != listener => Some(ListenerChangeKind::Reconfigure),
            Some(_) => None,
        };
        if let Some(kind) = kind {
            impacts.push(ListenerImpact {
                name: listener.name().to_string(),
                kind,
                active_connections: connections.active_for_listener(listener.name()),
            });
        }
    }
    for listener in candidate.iter() {
        if current.get(listener.name()).is_none() {
            impacts.push(ListenerImpact {
                name: listener.name().to_string(),
                kind: ListenerChangeKind::Add,
                active_connections: 0,
            });
        }
    }
    impacts.sort_by(|left, right| left.name.cmp(&right.name));
    impacts
}

/// Require every removal or reconfiguration to have zero active transports.
///
/// Adds never depend on connections through unchanged listeners.
///
/// # Errors
///
/// Returns the bounded active impact subset when the transition would disrupt
/// an accepted transport.
pub fn require_zero_active(impacts: &[ListenerImpact]) -> Result<(), ActiveListenerTransition> {
    let blocking = impacts
        .iter()
        .filter(|impact| impact.kind != ListenerChangeKind::Add && impact.active_connections != 0)
        .cloned()
        .collect::<Vec<_>>();
    if blocking.is_empty() {
        Ok(())
    } else {
        Err(ActiveListenerTransition { impacts: blocking })
    }
}

/// Gate disruptive listeners and validate zero active transports atomically
/// against connection registration.
///
/// The caller must retain the returned guard through listener-set commit. If
/// validation fails, the temporary gates are released before this function
/// returns.
///
/// # Errors
///
/// Returns a registry conflict or the bounded active impact set.
pub fn begin_transition(
    current: &ListenerConfigSet,
    candidate: &ListenerConfigSet,
    connections: &ConnectionRegistry,
) -> Result<(Vec<ListenerImpact>, ListenerTransitionGuard), ListenerTransitionError> {
    let mut impacts = assess_transition(current, candidate, connections);
    let disruptive = impacts
        .iter()
        .filter(|impact| impact.kind != ListenerChangeKind::Add)
        .map(|impact| impact.name.clone())
        .collect::<Vec<_>>();
    let guard = connections.begin_listener_transition(disruptive)?;
    for impact in &mut impacts {
        if impact.kind != ListenerChangeKind::Add {
            impact.active_connections = guard.active_for_listener(&impact.name);
        }
    }
    require_zero_active(&impacts)?;
    Ok((impacts, guard))
}

/// Listener preparation or publication failure.
#[derive(Debug, Error)]
pub enum ListenerManagerError {
    /// The final socket parent is absent, a symlink, or not a directory.
    #[error("listener `{listener}` has an untrusted socket parent `{path}`")]
    UntrustedParent {
        /// Listener name.
        listener: String,
        /// Rejected parent or ancestor.
        path: PathBuf,
    },
    /// An object already occupies the final socket path.
    #[error("listener `{listener}` path already exists: `{path}`")]
    PathOccupied {
        /// Listener name.
        listener: String,
        /// Occupied final path.
        path: PathBuf,
    },
    /// No bounded private staging path could be allocated.
    #[error("listener `{listener}` could not allocate a private staging path")]
    StageUnavailable {
        /// Listener name.
        listener: String,
    },
    /// A filesystem operation failed.
    #[error("listener `{listener}` filesystem operation failed for `{path}`")]
    Io {
        /// Listener name.
        listener: String,
        /// Affected path.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: io::Error,
    },
}

/// Read-only qualification result for one listener candidate.
#[derive(Debug)]
pub struct QualifiedListener {
    config: ListenerConfig,
    parent: PathBuf,
    parent_fd: Arc<OwnedFd>,
}

impl QualifiedListener {
    /// Validate path traversal and final-path absence without binding or writing.
    ///
    /// # Errors
    ///
    /// Returns a typed path trust or occupancy error.
    pub fn validate(config: &ListenerConfig) -> Result<Self, ListenerManagerError> {
        let parent =
            config
                .path()
                .parent()
                .ok_or_else(|| ListenerManagerError::UntrustedParent {
                    listener: config.name().to_string(),
                    path: config.path().to_path_buf(),
                })?;
        let parent_fd = Arc::new(open_trusted_parent(config.name(), parent)?);
        let final_name =
            config
                .path()
                .file_name()
                .ok_or_else(|| ListenerManagerError::UntrustedParent {
                    listener: config.name().to_string(),
                    path: config.path().to_path_buf(),
                })?;
        match statat(parent_fd.as_ref(), final_name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => {
                return Err(ListenerManagerError::PathOccupied {
                    listener: config.name().to_string(),
                    path: config.path().to_path_buf(),
                });
            }
            Err(rustix::io::Errno::NOENT) => {}
            Err(error) => {
                return Err(ListenerManagerError::Io {
                    listener: config.name().to_string(),
                    path: config.path().to_path_buf(),
                    source: io::Error::from(error),
                });
            }
        }
        Ok(Self {
            config: config.clone(),
            parent: parent.to_path_buf(),
            parent_fd,
        })
    }

    /// Bind a non-serving socket inside a private `0700` sibling directory and
    /// apply its configured ACL through the pinned directory descriptor before
    /// publication.
    ///
    /// # Errors
    ///
    /// Returns a typed staging error. The final path remains untouched.
    pub fn prepare(self) -> Result<PreparedListener, ListenerManagerError> {
        for _ in 0..MAX_STAGE_ATTEMPTS {
            let suffix = uuid::Uuid::new_v4()
                .as_simple()
                .to_string()
                .chars()
                .take(8)
                .collect::<String>();
            let stage_name = OsString::from(format!(".b-{suffix}"));
            let stage_path = self.parent.join(&stage_name).join("s");
            if stage_path.as_os_str().as_bytes().len() > MAX_UNIX_SOCKET_PATH_BYTES {
                return Err(ListenerManagerError::StageUnavailable {
                    listener: self.config.name().to_string(),
                });
            }
            match mkdirat(
                self.parent_fd.as_ref(),
                &stage_name,
                Mode::from_raw_mode(0o700),
            ) {
                Ok(()) => {}
                Err(rustix::io::Errno::EXIST) => continue,
                Err(error) => {
                    return Err(ListenerManagerError::Io {
                        listener: self.config.name().to_string(),
                        path: self.parent.join(&stage_name),
                        source: io::Error::from(error),
                    });
                }
            }
            let stage_fd = match openat(
                self.parent_fd.as_ref(),
                &stage_name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(stage_fd) => stage_fd,
                Err(error) => {
                    cleanup_private_stage(self.parent_fd.as_ref(), &stage_name, None);
                    return Err(ListenerManagerError::Io {
                        listener: self.config.name().to_string(),
                        path: self.parent.join(&stage_name),
                        source: io::Error::from(error),
                    });
                }
            };
            let bind_path = pinned_stage_bind_path(&stage_fd, &stage_path);
            let listener = match UnixListener::bind(&bind_path) {
                Ok(listener) => listener,
                Err(source) => {
                    cleanup_private_stage(self.parent_fd.as_ref(), &stage_name, Some(&stage_fd));
                    return Err(ListenerManagerError::Io {
                        listener: self.config.name().to_string(),
                        path: stage_path,
                        source,
                    });
                }
            };
            if let Err(error) = apply_private_socket_permissions(
                self.config.name(),
                &stage_fd,
                self.config.mode(),
                self.config.group(),
                &stage_path,
            ) {
                cleanup_private_stage(self.parent_fd.as_ref(), &stage_name, Some(&stage_fd));
                return Err(error);
            }
            let identity = match socket_identity_at(self.config.name(), &stage_fd, "s", &stage_path)
            {
                Ok(identity) => identity,
                Err(error) => {
                    cleanup_private_stage(self.parent_fd.as_ref(), &stage_name, Some(&stage_fd));
                    return Err(error);
                }
            };
            return Ok(PreparedListener {
                config: self.config,
                listener: Some(listener),
                parent_fd: self.parent_fd,
                stage_name,
                stage_fd,
                stage_path,
                identity,
            });
        }
        Err(ListenerManagerError::StageUnavailable {
            listener: self.config.name().to_string(),
        })
    }
}

/// Bound but non-serving listener owned by a rollback guard.
pub struct PreparedListener {
    config: ListenerConfig,
    listener: Option<UnixListener>,
    parent_fd: Arc<OwnedFd>,
    stage_name: OsString,
    stage_fd: OwnedFd,
    stage_path: PathBuf,
    identity: SocketIdentity,
}

/// All newly added listeners staged for one candidate transaction.
pub struct PreparedListenerBatch {
    listeners: Vec<PreparedListener>,
}

impl PreparedListenerBatch {
    /// Qualify and bind every addition without publishing any final path.
    ///
    /// # Errors
    ///
    /// Any failure drops all earlier private stages before returning.
    pub fn prepare<'a>(
        additions: impl IntoIterator<Item = &'a ListenerConfig>,
    ) -> Result<Self, ListenerManagerError> {
        let mut listeners = Vec::new();
        for config in additions {
            listeners.push(QualifiedListener::validate(config)?.prepare()?);
        }
        Ok(Self { listeners })
    }

    /// Publish and permission every staged listener as one rollback unit.
    ///
    /// No listener is returned to an accept-loop owner until all publications
    /// succeed. A later failure drops every earlier published inode.
    ///
    /// # Errors
    ///
    /// Returns the first typed publication failure after complete rollback.
    pub fn publish(self) -> Result<PublishedListenerBatch, ListenerManagerError> {
        let mut published = Vec::new();
        for listener in self.listeners {
            published.push(listener.publish()?);
        }
        Ok(PublishedListenerBatch {
            listeners: published,
        })
    }
}

/// Completely published candidate additions, none yet serving accepts.
pub struct PublishedListenerBatch {
    listeners: Vec<PublishedListener>,
}

impl PublishedListenerBatch {
    /// Borrow the fully published additions in candidate order.
    #[must_use]
    pub fn listeners(&self) -> &[PublishedListener] {
        &self.listeners
    }

    /// Transfer all published listeners to the accept-loop owner.
    #[must_use]
    pub fn into_listeners(self) -> Vec<PublishedListener> {
        self.listeners
    }
}

impl PreparedListener {
    /// Private path used before publication.
    #[must_use]
    pub fn stage_path(&self) -> &Path {
        &self.stage_path
    }

    /// Atomically publish without replacing any final-path object.
    ///
    /// The configured ACL and inode identity were applied and verified through
    /// the private staging directory descriptor before this no-replace rename.
    /// The socket is never polled for accepts until publication succeeds.
    ///
    /// # Errors
    ///
    /// Returns a typed publication or permission error. Failure removes only
    /// the exact socket inode owned by this guard.
    pub fn publish(mut self) -> Result<PublishedListener, ListenerManagerError> {
        let final_path = self.config.path().to_path_buf();
        let Some(final_name) = final_path.file_name().map(ToOwned::to_owned) else {
            return Err(ListenerManagerError::UntrustedParent {
                listener: self.config.name().to_string(),
                path: final_path,
            });
        };
        renameat_with(
            &self.stage_fd,
            "s",
            self.parent_fd.as_ref(),
            &final_name,
            RenameFlags::NOREPLACE,
        )
        .map_err(io::Error::from)
        .map_err(|source| {
            if source.kind() == io::ErrorKind::AlreadyExists {
                ListenerManagerError::PathOccupied {
                    listener: self.config.name().to_string(),
                    path: final_path.clone(),
                }
            } else {
                ListenerManagerError::Io {
                    listener: self.config.name().to_string(),
                    path: final_path.clone(),
                    source,
                }
            }
        })?;
        let Some(listener) = self.listener.take() else {
            return Err(ListenerManagerError::StageUnavailable {
                listener: self.config.name().to_string(),
            });
        };
        let published = PublishedListener {
            config: self.config.clone(),
            listener: Some(listener),
            parent_fd: Arc::clone(&self.parent_fd),
            final_name,
            identity: self.identity,
        };
        // The published guard now owns cleanup.
        self.identity = SocketIdentity::INVALID;
        Ok(published)
    }
}

impl Drop for PreparedListener {
    fn drop(&mut self) {
        remove_owned_socket_at(&self.stage_fd, "s", self.identity);
        let _ = unlinkat(
            self.parent_fd.as_ref(),
            &self.stage_name,
            AtFlags::REMOVEDIR,
        );
    }
}

/// Published socket and bound listener, ready to enter an accept loop.
pub struct PublishedListener {
    config: ListenerConfig,
    listener: Option<UnixListener>,
    parent_fd: Arc<OwnedFd>,
    final_name: OsString,
    identity: SocketIdentity,
}

impl PublishedListener {
    /// Validated listener configuration.
    #[must_use]
    pub const fn config(&self) -> &ListenerConfig {
        &self.config
    }

    /// Borrow the bound listener for accept-loop construction.
    #[must_use]
    pub const fn listener(&self) -> Option<&UnixListener> {
        self.listener.as_ref()
    }

    /// Transfer the bound listener while retaining inode-guarded path cleanup.
    ///
    /// # Errors
    ///
    /// Returns a staging error if internal ownership was already transferred.
    pub fn into_listener(
        mut self,
    ) -> Result<(UnixListener, PublishedSocketLease), ListenerManagerError> {
        let Some(listener) = self.listener.take() else {
            return Err(ListenerManagerError::StageUnavailable {
                listener: self.config.name().to_string(),
            });
        };
        let lease = PublishedSocketLease {
            parent_fd: Arc::clone(&self.parent_fd),
            final_name: self.final_name.clone(),
            identity: self.identity,
        };
        self.identity = SocketIdentity::INVALID;
        Ok((listener, lease))
    }
}

impl Drop for PublishedListener {
    fn drop(&mut self) {
        remove_owned_socket_at(&self.parent_fd, &self.final_name, self.identity);
    }
}

/// Cleanup lease retained for the lifetime of an active accept loop.
pub struct PublishedSocketLease {
    parent_fd: Arc<OwnedFd>,
    final_name: OsString,
    identity: SocketIdentity,
}

impl Drop for PublishedSocketLease {
    fn drop(&mut self) {
        remove_owned_socket_at(&self.parent_fd, &self.final_name, self.identity);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SocketIdentity {
    device: u64,
    inode: u64,
}

impl SocketIdentity {
    const INVALID: Self = Self {
        device: u64::MAX,
        inode: u64::MAX,
    };
}

fn open_trusted_parent(listener: &str, parent: &Path) -> Result<OwnedFd, ListenerManagerError> {
    let mut current_path = PathBuf::from("/");
    let mut current_fd = openat(
        CWD,
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| ListenerManagerError::Io {
        listener: listener.to_string(),
        path: PathBuf::from("/"),
        source: io::Error::from(error),
    })?;
    for component in parent.components() {
        match component {
            Component::RootDir => continue,
            Component::Normal(value) => current_path.push(value),
            _ => {
                return Err(ListenerManagerError::UntrustedParent {
                    listener: listener.to_string(),
                    path: current_path,
                });
            }
        }
        current_fd = openat(
            &current_fd,
            component.as_os_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ListenerManagerError::UntrustedParent {
            listener: listener.to_string(),
            path: current_path.clone(),
        })?;
    }
    let stat = fstat(&current_fd).map_err(|error| ListenerManagerError::Io {
        listener: listener.to_string(),
        path: parent.to_path_buf(),
        source: io::Error::from(error),
    })?;
    let effective_uid = rustix::process::geteuid().as_raw();
    if stat.st_uid != effective_uid || stat.st_mode & 0o022 != 0 {
        return Err(ListenerManagerError::UntrustedParent {
            listener: listener.to_string(),
            path: parent.to_path_buf(),
        });
    }
    Ok(current_fd)
}

#[cfg(target_os = "linux")]
fn pinned_stage_bind_path(stage_fd: &OwnedFd, _display_path: &Path) -> PathBuf {
    PathBuf::from("/proc/self/fd")
        .join(stage_fd.as_raw_fd().to_string())
        .join("s")
}

#[cfg(not(target_os = "linux"))]
fn pinned_stage_bind_path(_stage_fd: &OwnedFd, display_path: &Path) -> PathBuf {
    // The qualified parent is owner-controlled and non-writable to group/world;
    // platforms without Linux procfs retain the validated textual path.
    display_path.to_path_buf()
}

fn apply_private_socket_permissions(
    listener: &str,
    stage_fd: &OwnedFd,
    mode: u32,
    group: Option<&str>,
    path: &Path,
) -> Result<(), ListenerManagerError> {
    if let Some(group) = group {
        let gid = resolve_group(group).map_err(|source| ListenerManagerError::Io {
            listener: listener.to_string(),
            path: path.to_path_buf(),
            source,
        })?;
        chownat(
            stage_fd,
            "s",
            None,
            Some(Gid::from_raw(gid)),
            AtFlags::empty(),
        )
        .map_err(|error| ListenerManagerError::Io {
            listener: listener.to_string(),
            path: path.to_path_buf(),
            source: io::Error::from(error),
        })?;
    }
    chmodat(stage_fd, "s", Mode::from_raw_mode(mode), AtFlags::empty()).map_err(|error| {
        ListenerManagerError::Io {
            listener: listener.to_string(),
            path: path.to_path_buf(),
            source: io::Error::from(error),
        }
    })
}

fn socket_identity_at(
    listener: &str,
    directory: &OwnedFd,
    name: impl AsRef<Path>,
    display_path: &Path,
) -> Result<SocketIdentity, ListenerManagerError> {
    let stat = statat(directory, name.as_ref(), AtFlags::SYMLINK_NOFOLLOW).map_err(|error| {
        ListenerManagerError::Io {
            listener: listener.to_string(),
            path: display_path.to_path_buf(),
            source: io::Error::from(error),
        }
    })?;
    if !FileType::from_raw_mode(stat.st_mode).is_socket() {
        return Err(ListenerManagerError::PathOccupied {
            listener: listener.to_string(),
            path: display_path.to_path_buf(),
        });
    }
    Ok(SocketIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
    })
}

fn remove_owned_socket_at(directory: &OwnedFd, name: impl AsRef<Path>, identity: SocketIdentity) {
    let Ok(stat) = statat(directory, name.as_ref(), AtFlags::SYMLINK_NOFOLLOW) else {
        return;
    };
    if FileType::from_raw_mode(stat.st_mode).is_socket()
        && stat.st_dev == identity.device
        && stat.st_ino == identity.inode
    {
        let _ = unlinkat(directory, name.as_ref(), AtFlags::empty());
    }
}

fn cleanup_private_stage(parent: &OwnedFd, name: impl AsRef<Path>, stage: Option<&OwnedFd>) {
    if let Some(stage) = stage {
        let _ = unlinkat(stage, "s", AtFlags::empty());
    }
    let _ = unlinkat(parent, name.as_ref(), AtFlags::REMOVEDIR);
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;
    use tokio::net::UnixStream;

    use super::*;
    use crate::transport::grpc_server::ListenerType;
    use crate::transport::listener::{
        LegacyListenerConfig, ListenerConfigInput, ListenerConfigSet,
    };

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path =
                PathBuf::from("/tmp").join(format!("b-{}", uuid::Uuid::new_v4().as_simple()));
            std::fs::create_dir(&path).expect("temporary directory");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn config(path: PathBuf, mode: u32) -> ListenerConfig {
        ListenerConfigSet::resolve(
            std::collections::BTreeMap::from([(
                "host".to_string(),
                ListenerConfigInput {
                    listener_type: ListenerType::Host,
                    path,
                    mode: Some(mode),
                    group: None,
                },
            )]),
            LegacyListenerConfig::default(),
        )
        .expect("listener config")
        .get("host")
        .expect("host")
        .clone()
    }

    fn config_set(entries: &[(&str, ListenerType, &str, u32)]) -> ListenerConfigSet {
        ListenerConfigSet::resolve(
            entries
                .iter()
                .map(|(name, listener_type, path, mode)| {
                    (
                        (*name).to_string(),
                        ListenerConfigInput {
                            listener_type: *listener_type,
                            path: PathBuf::from(path),
                            mode: Some(*mode),
                            group: None,
                        },
                    )
                })
                .collect(),
            LegacyListenerConfig::default(),
        )
        .expect("listener set")
    }

    #[tokio::test]
    async fn transition_impact_blocks_only_active_removal_or_reconfiguration() {
        let current = config_set(&[("host", ListenerType::Host, "/run/basil/host.sock", 0o600)]);
        let candidate = config_set(&[
            ("host", ListenerType::Host, "/run/basil/control.sock", 0o660),
            (
                "workloads",
                ListenerType::Container,
                "/run/basil/workloads.sock",
                0o666,
            ),
        ]);
        let registry = ConnectionRegistry::new(4, 4).expect("registry");
        let (stream, _peer) = UnixStream::pair().expect("stream pair");
        let tracked = registry
            .register(stream, "host", ListenerType::Host)
            .expect("tracked host connection");

        let impacts = assess_transition(&current, &candidate, &registry);
        assert_eq!(impacts.len(), 2);
        assert!(impacts.iter().any(|impact| {
            impact.name() == "workloads"
                && impact.kind() == ListenerChangeKind::Add
                && impact.active_connections() == 0
        }));
        let error = require_zero_active(&impacts).expect_err("active reconfiguration blocks");
        assert_eq!(error.impacts().len(), 1);
        assert_eq!(
            error.impacts().first().map(ListenerImpact::name),
            Some("host")
        );

        drop(tracked);
        let impacts = assess_transition(&current, &candidate, &registry);
        require_zero_active(&impacts).expect("transition unblocks after actual Drop");
    }

    #[test]
    fn validation_is_read_only_and_rejects_symlink_parent_and_occupied_path() {
        let directory = TestDirectory::new();
        let socket = directory.path().join("agent.sock");
        let listener = config(socket.clone(), 0o660);
        QualifiedListener::validate(&listener).expect("candidate validates");
        assert!(!socket.exists());

        std::fs::write(&socket, b"not a socket").expect("occupied fixture");
        assert!(matches!(
            QualifiedListener::validate(&listener),
            Err(ListenerManagerError::PathOccupied { .. })
        ));

        let real = directory.path().join("real");
        let linked = directory.path().join("linked");
        std::fs::create_dir(&real).expect("real parent");
        std::os::unix::fs::symlink(&real, &linked).expect("symlink parent");
        let listener = config(linked.join("agent.sock"), 0o600);
        assert!(matches!(
            QualifiedListener::validate(&listener),
            Err(ListenerManagerError::UntrustedParent { .. })
        ));
    }

    #[tokio::test]
    async fn validation_rejects_writable_parent_and_prepare_fails_closed_on_symlink_swap() {
        let directory = TestDirectory::new();
        let writable = directory.path().join("writable");
        std::fs::create_dir(&writable).expect("writable parent");
        std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o777))
            .expect("loosen parent");
        let listener = config(writable.join("agent.sock"), 0o600);
        assert!(matches!(
            QualifiedListener::validate(&listener),
            Err(ListenerManagerError::UntrustedParent { .. })
        ));

        let live = directory.path().join("live");
        let pinned = directory.path().join("pinned");
        let attacker = directory.path().join("attacker");
        std::fs::create_dir(&live).expect("live parent");
        std::fs::create_dir(&attacker).expect("attacker parent");
        let listener = config(live.join("agent.sock"), 0o600);
        let qualified = QualifiedListener::validate(&listener).expect("parent is pinned");
        std::fs::rename(&live, &pinned).expect("move qualified parent");
        std::os::unix::fs::symlink(&attacker, &live).expect("replace path with symlink");

        let prepared = qualified
            .prepare()
            .expect("pinned stage remains usable after textual swap");
        assert!(
            std::fs::read_dir(&attacker)
                .expect("attacker directory")
                .next()
                .is_none(),
            "path swap must not create an attacker-controlled socket"
        );
        drop(prepared);
        assert!(
            std::fs::read_dir(&pinned)
                .expect("pinned directory")
                .next()
                .is_none(),
            "failed staging must clean the pinned directory"
        );
    }

    #[tokio::test]
    async fn prepare_is_private_publish_is_no_replace_and_guards_cleanup() {
        let directory = TestDirectory::new();
        let final_path = directory.path().join("agent.sock");
        let listener = config(final_path.clone(), 0o660);
        let prepared = QualifiedListener::validate(&listener)
            .expect("qualifies")
            .prepare()
            .expect("stages");
        let stage_path = prepared.stage_path().to_path_buf();
        assert!(!final_path.exists());
        assert_eq!(
            std::fs::metadata(&stage_path)
                .expect("stage metadata")
                .permissions()
                .mode()
                & 0o777,
            0o660
        );

        std::fs::write(&final_path, b"race winner").expect("occupy final path");
        assert!(matches!(
            prepared.publish(),
            Err(ListenerManagerError::PathOccupied { .. })
        ));
        assert_eq!(
            std::fs::read(&final_path).expect("foreign path preserved"),
            b"race winner"
        );
        assert!(!stage_path.exists());

        std::fs::remove_file(&final_path).expect("remove fixture");
        let published = QualifiedListener::validate(&listener)
            .expect("requalifies")
            .prepare()
            .expect("restages")
            .publish()
            .expect("publishes");
        assert_eq!(
            std::fs::metadata(&final_path)
                .expect("published metadata")
                .permissions()
                .mode()
                & 0o777,
            0o660
        );
        drop(published);
        assert!(!final_path.exists());

        let published = QualifiedListener::validate(&listener)
            .expect("qualifies for replacement test")
            .prepare()
            .expect("stages replacement test")
            .publish()
            .expect("publishes replacement test");
        let (bound, lease) = published.into_listener().expect("transfers listener");
        std::fs::remove_file(&final_path).expect("unlink owned socket");
        std::fs::write(&final_path, b"foreign replacement").expect("install foreign inode");
        drop(lease);
        drop(bound);
        assert_eq!(
            std::fs::read(&final_path).expect("foreign inode preserved"),
            b"foreign replacement"
        );
    }

    #[tokio::test]
    async fn batch_publication_rolls_back_every_earlier_socket() {
        let directory = TestDirectory::new();
        let first_path = directory.path().join("first.sock");
        let second_path = directory.path().join("second.sock");
        let configs = ListenerConfigSet::resolve(
            std::collections::BTreeMap::from([
                (
                    "first".to_string(),
                    ListenerConfigInput {
                        listener_type: ListenerType::Host,
                        path: first_path.clone(),
                        mode: Some(0o600),
                        group: None,
                    },
                ),
                (
                    "second".to_string(),
                    ListenerConfigInput {
                        listener_type: ListenerType::Host,
                        path: second_path.clone(),
                        mode: Some(0o600),
                        group: None,
                    },
                ),
            ]),
            LegacyListenerConfig::default(),
        )
        .expect("batch config");
        let first = configs.get("first").expect("first");
        let second = configs.get("second").expect("second");

        let prepared = PreparedListenerBatch::prepare([first, second]).expect("batch prepares");
        std::fs::write(&second_path, b"race winner").expect("occupy second final path");
        assert!(prepared.publish().is_err());
        assert!(!first_path.exists());
        assert_eq!(
            std::fs::read(&second_path).expect("race winner remains"),
            b"race winner"
        );
    }
}
