// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Attestor-side realm control-socket listener.
//!
//! [`AttestorListener::bind`] is the single named bind point of the
//! production attestor process, so the post-init lockdown boundary
//! (`basil-rslz`) can guard it: the entrypoint creates every thread and
//! long-lived descriptor first, engages the lockdown profile (non-dumpable,
//! thread-synchronized seccomp filter install plus verify), and only then
//! calls `bind`. Nothing in this module spawns a thread or installs any
//! confinement itself.
//!
//! The bind is fail-closed against the installed measurement authority:
//! the generation-qualified runtime directory must already exist exactly as
//! the root authority transaction installed it (real directory, declared
//! owner, exact declared mode; opened `O_NOFOLLOW`), a leftover object at
//! the socket path is unlinked only when it is verifiably a stale socket
//! owned by the separately declared socket owner (the attestor account, not
//! the root directory owner), and the fresh socket is chmodded to the
//! declared mode before `listen`, so the endpoint is never observable with
//! wider permissions. The broker independently authenticates the full path,
//! ACL profile, and socket identity on every connect
//! (`core::attestor_realm_unix`); the checks here are the attestor-side
//! half, not a substitute.
//!
//! [`AttestorListener::accept`] surfaces the accepted stream together with
//! its kernel `SO_PEERCRED` so the entrypoint can reject any peer that is
//! not the enrolled broker UID before a single protocol byte is read.

use std::path::{Path, PathBuf};

use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
use thiserror::Error;

use super::PeerCredentials;
use super::lockdown::LockdownGuard;

/// Declared measurement-authority facts the bind enforces.
///
/// Values come from the protected realm authority (`runtimeDirectoryOwner`,
/// `runtimeDirectoryMode`, `socketOwner`, `socketMode`). The directory owner
/// and the socket owner are separate declared identities: SPEC.md rev 1.2
/// installs a root-owned runtime directory while the attestor account owns
/// the socket it creates inside it. Tests and unprivileged development hosts
/// substitute values for a directory they own.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttestorListenerOptions {
    /// Exact owner UID the runtime directory must carry
    /// (`runtimeDirectoryOwner`; root in the installed authority).
    pub required_directory_owner_uid: u32,
    /// Exact mode bits (`& 0o7777`) the runtime directory must carry.
    pub required_directory_mode: u32,
    /// Exact owner UID a stale socket must carry before it may be removed
    /// (`socketOwner`; the attestor account that created it).
    pub required_socket_owner_uid: u32,
    /// Mode bits applied to the bound socket before `listen`.
    pub socket_mode: u32,
}

/// Failure to bind or accept on the realm control socket.
#[derive(Debug, Error)]
pub enum AttestorListenerError {
    /// The socket path has no parent directory or no file name.
    #[error("realm socket path is not a directory-and-leaf path")]
    InvalidPath,
    /// The runtime directory is missing or does not match the declared
    /// authority (owner or mode).
    #[error("runtime directory does not match the declared measurement authority")]
    UntrustedDirectory,
    /// The socket path is occupied by something other than a verified stale
    /// socket owned by the declared owner.
    #[error("realm socket path is occupied by an unexpected object")]
    PathOccupied,
    /// A socket, filesystem, or accept operation failed.
    #[error("realm listener I/O failed: {0}")]
    Io(#[from] rustix::io::Errno),
    /// Registering or accepting through the async reactor failed.
    #[error("realm listener runtime registration failed: {0}")]
    Runtime(#[from] std::io::Error),
}

/// One accepted broker connection with its kernel-proven peer credentials.
#[derive(Debug)]
pub struct AcceptedRealmPeer {
    /// The accepted stream, not yet used for any protocol byte.
    pub stream: tokio::net::UnixStream,
    /// `SO_PEERCRED` of the connecting process.
    pub credentials: PeerCredentials,
}

/// Bound realm control-socket listener.
#[derive(Debug)]
pub struct AttestorListener {
    inner: tokio::net::UnixListener,
    path: PathBuf,
}

impl AttestorListener {
    /// Bind the realm control socket inside the installed runtime directory.
    ///
    /// The `_lockdown` witness makes the ordered lockdown contract
    /// (`basil-rslz`) a compile-time property: this socket cannot be created
    /// unless [`crate::attestor_protocol::engage`] has already returned a
    /// [`LockdownGuard`], i.e. every thread and long-lived descriptor already
    /// exists, the process is non-dumpable, and the thread-synchronized
    /// seccomp filters are installed and verified. Must run inside a tokio
    /// runtime (the listener registers with the reactor).
    ///
    /// # Errors
    ///
    /// Returns [`AttestorListenerError`] when the runtime directory fails
    /// authority checks, the path is occupied by an unexpected object, or a
    /// socket operation fails.
    pub fn bind(
        path: &Path,
        options: &AttestorListenerOptions,
        _lockdown: &LockdownGuard,
    ) -> Result<Self, AttestorListenerError> {
        let parent = path.parent().ok_or(AttestorListenerError::InvalidPath)?;
        let name = path.file_name().ok_or(AttestorListenerError::InvalidPath)?;
        let parent_fd = rustix::fs::open(
            parent,
            OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::RDONLY,
            Mode::empty(),
        )
        .map_err(|_| AttestorListenerError::UntrustedDirectory)?;
        let parent_stat = rustix::fs::fstat(&parent_fd)?;
        if parent_stat.st_uid != options.required_directory_owner_uid
            || parent_stat.st_mode & 0o7777 != options.required_directory_mode
        {
            return Err(AttestorListenerError::UntrustedDirectory);
        }

        // Remove only a verified stale socket owned by the declared socket
        // owner (not the directory owner: the installed directory is
        // root-owned while the socket belongs to the attestor account that
        // created it); never any other object. There is no socket unit and
        // exactly one admitted attestor per generation directory, so a socket
        // here can only be a leftover of a previous run of this same identity.
        match rustix::fs::statat(&parent_fd, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => {
                if FileType::from_raw_mode(stat.st_mode) != FileType::Socket
                    || stat.st_uid != options.required_socket_owner_uid
                {
                    return Err(AttestorListenerError::PathOccupied);
                }
                rustix::fs::unlinkat(&parent_fd, name, AtFlags::empty())?;
            }
            Err(rustix::io::Errno::NOENT) => {}
            Err(errno) => return Err(errno.into()),
        }

        let fd = rustix::net::socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )?;
        let address = SocketAddrUnix::new(path)?;
        rustix::net::bind(&fd, &address)?;
        // Never observable wider than the declared mode: chmod precedes
        // `listen` (callers additionally run under a restrictive umask).
        rustix::fs::chmodat(
            &parent_fd,
            name,
            Mode::from_bits_truncate(options.socket_mode),
            AtFlags::empty(),
        )?;
        rustix::net::listen(&fd, 8)?;
        let std_listener = std::os::unix::net::UnixListener::from(fd);
        let inner = tokio::net::UnixListener::from_std(std_listener)?;
        Ok(Self {
            inner,
            path: path.to_path_buf(),
        })
    }

    /// Accept one broker connection and capture its kernel credentials.
    ///
    /// No protocol byte is read here; the caller must verify the peer UID
    /// against the enrolled broker before any further use of the stream.
    ///
    /// # Errors
    ///
    /// Returns [`AttestorListenerError`] when `accept` or the credential
    /// read fails.
    pub async fn accept(&self) -> Result<AcceptedRealmPeer, AttestorListenerError> {
        let (stream, _address) = self.inner.accept().await?;
        let credentials = stream.peer_cred()?;
        let pid = credentials
            .pid()
            .and_then(|pid| u32::try_from(pid).ok())
            .filter(|pid| *pid != 0);
        Ok(AcceptedRealmPeer {
            stream,
            credentials: PeerCredentials {
                pid,
                uid: credentials.uid(),
                gid: credentials.gid(),
            },
        })
    }

    /// The bound socket path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;
    use std::os::unix::fs::PermissionsExt as _;

    use super::super::lockdown::{LockdownProfileId, LockdownProfileKind};
    use super::*;

    /// A lockdown witness for bind tests, constructed without engaging seccomp
    /// (engaging inside the shared cargo-test process would filter or kill it).
    fn test_guard() -> LockdownGuard {
        let profile = LockdownProfileId::new(
            "basil-attestor-lockdown-g1",
            NonZeroU64::new(1).expect("nonzero"),
            LockdownProfileKind::AttestorV1,
        )
        .expect("valid test profile");
        LockdownGuard::for_test(profile)
    }

    fn unique_dir(mode: u32) -> PathBuf {
        use std::fmt::Write as _;

        let mut unique = [0_u8; 8];
        getrandom::fill(&mut unique).expect("random");
        let mut name = String::from("basil-attestor-listener-");
        for byte in unique {
            let _ = write!(name, "{byte:02x}");
        }
        let dir = std::env::temp_dir().join(name);
        std::fs::create_dir(&dir).expect("create dir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).expect("chmod dir");
        dir
    }

    fn options(mode: u32) -> AttestorListenerOptions {
        AttestorListenerOptions {
            required_directory_owner_uid: rustix::process::geteuid().as_raw(),
            required_directory_mode: mode,
            required_socket_owner_uid: rustix::process::geteuid().as_raw(),
            socket_mode: 0o660,
        }
    }

    /// The ordered lockdown contract is a compile-time property: `bind`
    /// requires a `&LockdownGuard`, so it is unreachable before
    /// `engage` produced one. This test documents that the socket is created
    /// only with a guard in hand (the guard type has no public constructor
    /// outside `engage`).
    #[tokio::test]
    async fn bind_requires_the_lockdown_witness() {
        let dir = unique_dir(0o700);
        let path = dir.join("control.sock");
        let guard = test_guard();
        assert_eq!(guard.profile().kind(), LockdownProfileKind::AttestorV1);
        let listener =
            AttestorListener::bind(&path, &options(0o700), &guard).expect("bind with guard");
        assert_eq!(listener.path(), path.as_path());
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[tokio::test]
    async fn binds_accepts_and_reports_connecting_peer_credentials() {
        let dir = unique_dir(0o700);
        let path = dir.join("control.sock");
        let listener = AttestorListener::bind(&path, &options(0o700), &test_guard()).expect("bind");
        assert_eq!(listener.path(), path.as_path());
        let socket_mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(socket_mode & 0o7777, 0o660);

        let (connected, accepted) = tokio::join!(tokio::net::UnixStream::connect(&path), async {
            listener.accept().await.expect("accept")
        });
        connected.expect("connect");
        // The connecting peer is this test process.
        assert_eq!(
            accepted.credentials.uid,
            rustix::process::geteuid().as_raw()
        );
        assert_eq!(
            accepted.credentials.gid,
            rustix::process::getegid().as_raw()
        );
        assert_eq!(accepted.credentials.pid, Some(std::process::id()));
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[tokio::test]
    async fn rebind_replaces_only_a_verified_stale_socket() {
        let dir = unique_dir(0o700);
        let path = dir.join("control.sock");
        let first =
            AttestorListener::bind(&path, &options(0o700), &test_guard()).expect("first bind");
        drop(first);
        // Restart: the stale socket file is verified and replaced.
        let second = AttestorListener::bind(&path, &options(0o700), &test_guard()).expect("rebind");
        drop(second);
        // A non-socket object at the path fails closed.
        std::fs::remove_file(&path).expect("clear");
        std::fs::write(&path, b"not a socket").expect("occupy");
        assert!(matches!(
            AttestorListener::bind(&path, &options(0o700), &test_guard()),
            Err(AttestorListenerError::PathOccupied)
        ));
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    /// Stale-socket removal validates the separately declared socket owner
    /// (`socketOwner`), not the directory owner: with a root-owned rev-1.2
    /// runtime directory the leftover socket still belongs to the attestor
    /// account, and a socket owned by anyone else fails closed.
    #[tokio::test]
    async fn stale_socket_owner_is_validated_separately_from_the_directory_owner() {
        let dir = unique_dir(0o700);
        let path = dir.join("control.sock");
        let first =
            AttestorListener::bind(&path, &options(0o700), &test_guard()).expect("first bind");
        drop(first);
        // Same directory authority, but the declared socket owner does not
        // match the leftover socket: fail closed instead of unlinking.
        let mut wrong_socket_owner = options(0o700);
        wrong_socket_owner.required_socket_owner_uid =
            rustix::process::geteuid().as_raw().wrapping_add(1);
        assert!(matches!(
            AttestorListener::bind(&path, &wrong_socket_owner, &test_guard()),
            Err(AttestorListenerError::PathOccupied)
        ));
        // The stale socket was not removed by the failed bind.
        assert!(std::fs::symlink_metadata(&path).is_ok());
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[tokio::test]
    async fn directory_authority_mismatches_fail_closed() {
        let dir = unique_dir(0o755);
        let path = dir.join("control.sock");
        // Declared mode mismatch (authority declares 0700, directory is 0755).
        assert!(matches!(
            AttestorListener::bind(&path, &options(0o700), &test_guard()),
            Err(AttestorListenerError::UntrustedDirectory)
        ));
        // Declared owner mismatch.
        let mut wrong_owner = options(0o755);
        wrong_owner.required_directory_owner_uid =
            rustix::process::geteuid().as_raw().wrapping_add(1);
        assert!(matches!(
            AttestorListener::bind(&path, &wrong_owner, &test_guard()),
            Err(AttestorListenerError::UntrustedDirectory)
        ));
        // Missing directory.
        let missing = dir.join("absent").join("control.sock");
        assert!(matches!(
            AttestorListener::bind(&missing, &options(0o755), &test_guard()),
            Err(AttestorListenerError::UntrustedDirectory)
        ));
        // A symlinked runtime directory is never followed.
        let real = unique_dir(0o700);
        let link = dir.join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        assert!(matches!(
            AttestorListener::bind(&link.join("control.sock"), &options(0o700), &test_guard()),
            Err(AttestorListenerError::UntrustedDirectory)
        ));
        std::fs::remove_dir_all(&dir).expect("cleanup");
        std::fs::remove_dir_all(&real).expect("cleanup");
    }
}
