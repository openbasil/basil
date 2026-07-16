// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Non-serving listener preparation and no-replace socket publication.

use std::io;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::path::{Component, Path, PathBuf};

use rustix::fs::{CWD, RenameFlags, renameat_with};
use thiserror::Error;
use tokio::net::UnixListener;

use super::connection::ConnectionRegistry;
use super::grpc_server::{apply_socket_permissions, bind_restricted};
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
#[derive(Clone, Debug)]
pub struct QualifiedListener {
    config: ListenerConfig,
    parent: PathBuf,
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
        validate_parent(config.name(), parent)?;
        match std::fs::symlink_metadata(config.path()) {
            Ok(_) => {
                return Err(ListenerManagerError::PathOccupied {
                    listener: config.name().to_string(),
                    path: config.path().to_path_buf(),
                });
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(ListenerManagerError::Io {
                    listener: config.name().to_string(),
                    path: config.path().to_path_buf(),
                    source,
                });
            }
        }
        Ok(Self {
            config: config.clone(),
            parent: parent.to_path_buf(),
        })
    }

    /// Bind a non-serving socket at a private sibling path with mode `0600`.
    ///
    /// # Errors
    ///
    /// Returns a typed staging error. The final path remains untouched.
    pub fn prepare(self) -> Result<PreparedListener, ListenerManagerError> {
        // Repeat read-only qualification immediately before mutation to narrow
        // validation/use races. Publication still uses atomic no-replace.
        Self::validate(&self.config)?;
        for _ in 0..MAX_STAGE_ATTEMPTS {
            let stage_path = self
                .parent
                .join(format!(".basil-{}.sock", uuid::Uuid::new_v4().as_simple()));
            if stage_path.as_os_str().as_bytes().len() > MAX_UNIX_SOCKET_PATH_BYTES {
                return Err(ListenerManagerError::StageUnavailable {
                    listener: self.config.name().to_string(),
                });
            }
            match bind_restricted(&stage_path.to_string_lossy()) {
                Ok(listener) => {
                    let identity = socket_identity(self.config.name(), &stage_path)?;
                    return Ok(PreparedListener {
                        config: self.config,
                        listener: Some(listener),
                        stage_path,
                        identity,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AddrInUse => {}
                Err(source) => {
                    return Err(ListenerManagerError::Io {
                        listener: self.config.name().to_string(),
                        path: stage_path,
                        source,
                    });
                }
            }
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
    /// The final ACL is applied only after the no-replace rename. Until then,
    /// the staged socket remains owner-only and is never polled for accepts.
    ///
    /// # Errors
    ///
    /// Returns a typed publication or permission error. Failure removes only
    /// the exact socket inode owned by this guard.
    pub fn publish(mut self) -> Result<PublishedListener, ListenerManagerError> {
        let final_path = self.config.path().to_path_buf();
        rename_no_replace(&self.stage_path, &final_path).map_err(|source| {
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
        self.stage_path.clone_from(&final_path);
        if let Err(source) = apply_socket_permissions(
            &final_path.to_string_lossy(),
            self.config.mode(),
            self.config.group(),
        ) {
            remove_owned_socket(&final_path, self.identity);
            return Err(ListenerManagerError::Io {
                listener: self.config.name().to_string(),
                path: final_path,
                source,
            });
        }
        let Some(listener) = self.listener.take() else {
            return Err(ListenerManagerError::StageUnavailable {
                listener: self.config.name().to_string(),
            });
        };
        let published = PublishedListener {
            config: self.config.clone(),
            listener,
            path: final_path,
            identity: self.identity,
        };
        // The published guard now owns cleanup.
        self.identity = SocketIdentity::INVALID;
        Ok(published)
    }
}

impl Drop for PreparedListener {
    fn drop(&mut self) {
        remove_owned_socket(&self.stage_path, self.identity);
    }
}

/// Published socket and bound listener, ready to enter an accept loop.
pub struct PublishedListener {
    config: ListenerConfig,
    listener: UnixListener,
    path: PathBuf,
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
    pub const fn listener(&self) -> &UnixListener {
        &self.listener
    }
}

impl Drop for PublishedListener {
    fn drop(&mut self) {
        remove_owned_socket(&self.path, self.identity);
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

fn validate_parent(listener: &str, parent: &Path) -> Result<(), ListenerManagerError> {
    let mut current = PathBuf::from("/");
    for component in parent.components() {
        match component {
            Component::RootDir => continue,
            Component::Normal(value) => current.push(value),
            _ => {
                return Err(ListenerManagerError::UntrustedParent {
                    listener: listener.to_string(),
                    path: current,
                });
            }
        }
        let metadata =
            std::fs::symlink_metadata(&current).map_err(|source| ListenerManagerError::Io {
                listener: listener.to_string(),
                path: current.clone(),
                source,
            })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ListenerManagerError::UntrustedParent {
                listener: listener.to_string(),
                path: current,
            });
        }
    }
    Ok(())
}

fn socket_identity(listener: &str, path: &Path) -> Result<SocketIdentity, ListenerManagerError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|source| ListenerManagerError::Io {
        listener: listener.to_string(),
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_socket() {
        return Err(ListenerManagerError::PathOccupied {
            listener: listener.to_string(),
            path: path.to_path_buf(),
        });
    }
    Ok(SocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn remove_owned_socket(path: &Path, identity: SocketIdentity) {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return;
    };
    if metadata.file_type().is_socket()
        && metadata.dev() == identity.device
        && metadata.ino() == identity.inode
    {
        let _ = std::fs::remove_file(path);
    }
}

fn rename_no_replace(source: &Path, destination: &Path) -> io::Result<()> {
    renameat_with(CWD, source, CWD, destination, RenameFlags::NOREPLACE)
        .map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))
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
            0o600
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
                        group: Some("basil-definitely-missing-group".to_string()),
                    },
                ),
            ]),
            LegacyListenerConfig::default(),
        )
        .expect("batch config");
        let first = configs.get("first").expect("first");
        let second = configs.get("second").expect("second");

        let prepared = PreparedListenerBatch::prepare([first, second]).expect("batch stages");
        assert!(prepared.publish().is_err());
        assert!(!first_path.exists());
        assert!(!second_path.exists());
    }
}
