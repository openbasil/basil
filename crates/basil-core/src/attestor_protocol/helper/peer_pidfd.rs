// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Race-free peer-pidfd acquisition with the `SO_PEERPIDFD` socket option.
//!
//! This is the sole boundary to the `nix` crate: the dependency is a
//! **temporary bridge** (pinned `0.30.x`, `default-features = false`,
//! `features = ["socket"]`, Linux-only) adopted per the `basil-xwiy`
//! maintainer decision because `rustix` does not wrap `SO_PEERPIDFD` yet.
//! It is removed once the sockopt is contributed upstream (`basil-cu2s`).
//! Nothing outside this module names a `nix` type: the surface is
//! [`BorrowedFd`] in, [`OwnedFd`] out, and
//! [`PeerPidfdError`](super::service::PeerPidfdError) on failure.
//!
//! # Fail-closed contract
//!
//! `SO_PEERPIDFD` (kernel 6.5+) returns a pidfd for the process that the
//! kernel recorded as the stream's connected peer — the same process
//! `SO_PEERCRED` describes — with no PID-reuse window. There is **no
//! fallback** of any kind: on kernels without the option the typed
//! `Unsupported` error is returned and every measurement fails closed;
//! substituting `pidfd_open(SO_PEERCRED.pid)` would reopen the reuse race
//! the accepted revision-1.2 contract closes.
//!
//! # Errno mapping
//!
//! - `ENOPROTOOPT` / `EOPNOTSUPP` → `Unsupported`: the kernel predates the
//!   option (< 6.5).
//! - `ESRCH` / `EINVAL` → `PeerVanished`: every argument to the call is
//!   fully controlled here (a validated stream descriptor, `SOL_SOCKET`,
//!   `SO_PEERPIDFD`, and an exactly `int`-sized result buffer supplied by
//!   the wrapper), so the only reachable source of either code is the
//!   kernel's dead-task check when it materializes the pidfd for an
//!   already-reaped peer (`EINVAL` on 6.5-era `pidfd_prepare`, `ESRCH` on
//!   later kernels).
//! - anything else → `Io`. This includes `ENODATA` (the socket has no
//!   recorded peer — it is not a connected `AF_UNIX` stream) and
//!   `ENOTSOCK`; the helper only calls this on a descriptor that already
//!   passed connected-Unix-stream verification, so both are handled as
//!   plain typed failures rather than given their own class.
//!
//! Current kernels (observed on 6.18) can also *succeed* for a peer that
//! already exited: the returned pidfd then names a dead process (`Pid: -1`
//! in `fdinfo`), and the measurement still fails closed at the next
//! pipeline stage because every procfs identity read returns
//! `PeerVanished`.
//!
//! # No descriptor leak
//!
//! The wrapper converts a successful acquisition directly into an
//! [`OwnedFd`]; on every error path the kernel has not returned a
//! descriptor, so there is nothing to leak. The audited `nix` 0.30.1
//! getter reads into a plain `c_int` buffer and constructs the `OwnedFd`
//! only after the syscall succeeds.

use std::os::fd::{BorrowedFd, OwnedFd};

use super::service::PeerPidfdError;

/// Acquire a pidfd for the stream's kernel-recorded connected peer.
///
/// # Errors
///
/// Returns the typed [`PeerPidfdError`] described in the module
/// documentation; there is no fallback acquisition path.
#[cfg(target_os = "linux")]
pub fn acquire(stream: BorrowedFd<'_>) -> Result<OwnedFd, PeerPidfdError> {
    nix::sys::socket::getsockopt(&stream, nix::sys::socket::sockopt::PeerPidfd).map_err(map_errno)
}

/// Non-Linux hosts have no `SO_PEERPIDFD`; acquisition fails closed.
#[cfg(not(target_os = "linux"))]
pub fn acquire(_stream: BorrowedFd<'_>) -> Result<OwnedFd, PeerPidfdError> {
    Err(PeerPidfdError::Unsupported)
}

/// Map the kernel's rejection to the typed acquisition error.
#[cfg(target_os = "linux")]
const fn map_errno(errno: nix::errno::Errno) -> PeerPidfdError {
    match errno {
        nix::errno::Errno::ENOPROTOOPT | nix::errno::Errno::EOPNOTSUPP => {
            PeerPidfdError::Unsupported
        }
        nix::errno::Errno::ESRCH | nix::errno::Errno::EINVAL => PeerPidfdError::PeerVanished,
        _ => PeerPidfdError::Io,
    }
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use std::os::fd::AsFd as _;

    use nix::errno::Errno;

    use super::*;

    fn socketpair() -> (OwnedFd, OwnedFd) {
        rustix::net::socketpair(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::STREAM,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        )
        .unwrap()
    }

    fn fdinfo_pid(fd: &OwnedFd) -> Option<i64> {
        let raw = std::os::fd::AsRawFd::as_raw_fd(fd);
        let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{raw}")).unwrap();
        info.lines().find_map(|line| {
            line.strip_prefix("Pid:")
                .and_then(|rest| rest.trim().parse().ok())
        })
    }

    fn open_fd_count() -> usize {
        std::fs::read_dir("/proc/self/fd").unwrap().count()
    }

    #[test]
    fn errno_mapping_is_exact() {
        assert_eq!(map_errno(Errno::ENOPROTOOPT), PeerPidfdError::Unsupported);
        assert_eq!(map_errno(Errno::EOPNOTSUPP), PeerPidfdError::Unsupported);
        assert_eq!(map_errno(Errno::ESRCH), PeerPidfdError::PeerVanished);
        assert_eq!(map_errno(Errno::EINVAL), PeerPidfdError::PeerVanished);
        assert_eq!(map_errno(Errno::ENODATA), PeerPidfdError::Io);
        assert_eq!(map_errno(Errno::ENOTSOCK), PeerPidfdError::Io);
        assert_eq!(map_errno(Errno::EBADF), PeerPidfdError::Io);
    }

    /// Live acquisition on a connected stream: the returned descriptor is a
    /// pidfd whose `fdinfo` PID equals the `SO_PEERCRED` PID of the same
    /// stream (the peer of a socketpair end is this test process).
    #[test]
    fn live_acquisition_identifies_the_connected_peer() {
        let (a, _b) = socketpair();
        let pidfd = acquire(a.as_fd()).expect("kernel 6.5+ supports SO_PEERPIDFD");
        let credentials = rustix::net::sockopt::socket_peercred(a.as_fd()).unwrap();
        let peercred_pid = i64::from(credentials.pid.as_raw_nonzero().get());
        assert_eq!(fdinfo_pid(&pidfd), Some(peercred_pid));
        assert_eq!(peercred_pid, i64::from(std::process::id()));
    }

    /// A non-`AF_UNIX` connected socket has no recorded peer pid; the typed
    /// `Io` rejection surfaces without leaking any descriptor even across
    /// many repetitions.
    #[test]
    fn unconnected_peer_fails_typed_without_descriptor_leak() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let before = open_fd_count();
        for _ in 0..256 {
            assert_eq!(acquire(stream.as_fd()).unwrap_err(), PeerPidfdError::Io);
        }
        // Parallel tests in this binary open and close descriptors
        // concurrently (pidfds, sockets, runtime-directory fixtures), so the
        // count is compared with generous slack: a real leak here would add
        // one descriptor per iteration (+256), far above any transient churn.
        let after = open_fd_count();
        assert!(
            after <= before + 96,
            "descriptor leak: {before} fds before, {after} after"
        );
    }

    /// A peer that exited and was reaped before acquisition fails closed:
    /// older 6.5-era kernels reject with `PeerVanished`; current kernels
    /// return a pidfd that names a dead process (`Pid: -1`), which the next
    /// pipeline stage (procfs identity) rejects as `PeerVanished`. Either
    /// way no measurement of a vanished peer can proceed.
    #[test]
    fn dead_reaped_peer_fails_closed() {
        let Some(python) = which_on_path("python3") else {
            eprintln!("skipping dead-peer live case: python3 not on PATH");
            return;
        };
        let dir = tempfile_dir();
        let path = dir.join("peer.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let stream = {
            let _spawn_guard = super::super::CHILD_SPAWN_TEST_LOCK.lock().unwrap();
            let mut child = std::process::Command::new(python)
                .arg("-c")
                .arg(format!(
                    "import socket; s = socket.socket(socket.AF_UNIX); s.connect({path:?})"
                ))
                .stdin(std::process::Stdio::null())
                .spawn()
                .unwrap();
            let (stream, _) = listener.accept().unwrap();
            let status = child.wait().unwrap();
            assert!(status.success());
            stream
        };
        match acquire(stream.as_fd()) {
            Err(error) => assert_eq!(error, PeerPidfdError::PeerVanished),
            Ok(pidfd) => assert_eq!(fdinfo_pid(&pidfd), Some(-1)),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn which_on_path(name: &str) -> Option<std::path::PathBuf> {
        let path = std::env::var_os("PATH")?;
        std::env::split_paths(&path)
            .map(|dir| dir.join(name))
            .find(|candidate| candidate.is_file())
    }

    fn tempfile_dir() -> std::path::PathBuf {
        let mut unique = [0_u8; 8];
        getrandom::fill(&mut unique).unwrap();
        let dir = std::env::temp_dir().join(format!("basil-peer-pidfd-{}", hex_of(&unique)));
        std::fs::create_dir(&dir).unwrap();
        dir
    }

    fn hex_of(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{byte:02x}"));
        }
        out
    }
}
