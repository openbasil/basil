// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Production host integrations for the measurement helper.
//!
//! Two integrations are fail-closed placeholders pending safe-wrapper
//! availability (tracked as a follow-up to `basil-f215`):
//!
//! - [`KernelPeerPidfdSource`] must acquire the peer pidfd with the
//!   `SO_PEERPIDFD` socket option. No crate in this workspace's safe
//!   dependency set wraps that option yet (`unsafe_code` is forbidden, so a
//!   raw `getsockopt` is not an option), and substituting
//!   `pidfd_open(SO_PEERCRED.pid)` would weaken the accepted revision-1.2
//!   contract's race-free peer binding. Until the wrapper lands the source
//!   returns [`PeerPidfdError::Unsupported`] and every measurement fails
//!   closed.
//! - [`SystemdUnitResolver`] must resolve `GetUnitByPIDFD` on the system
//!   D-Bus. The workspace carries no D-Bus client; until a bounded transport
//!   lands the resolver returns [`UnitResolveError::Unavailable`].
//!
//! [`ProcfsProcessInspector`] and [`ProcExecutableOpener`] are real:
//! identity comes from `/proc/<pid>/status` and `/proc/<pid>/stat`, and the
//! executable from `/proc/<pid>/exe` (which requires the helper's
//! `CAP_SYS_PTRACE` for cross-UID peers). Lockdown-profile evidence requires
//! installed-manifest integration from the authority installation
//! transaction (`basil-q5we`) and is fail-closed until then.

use std::io::Read;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::path::PathBuf;

use rustix::fs::{Mode, OFlags};

use super::service::{
    ConfinementFacts, ExecutableError, ExecutableOpener, InspectError, PeerPidfdError,
    PeerPidfdSource, ProcessIdentity, ProcessInspector, ResolvedUnit, UnitResolveError,
    UnitResolver,
};

/// Maximum bytes read from one procfs evidence file.
const MAX_PROCFS_BYTES: usize = 64 * 1024;

/// Fail-closed production source for the peer pidfd (`SO_PEERPIDFD`).
#[derive(Clone, Copy, Debug, Default)]
pub struct KernelPeerPidfdSource;

impl PeerPidfdSource for KernelPeerPidfdSource {
    fn peer_pidfd(&self, _stream: BorrowedFd<'_>) -> Result<OwnedFd, PeerPidfdError> {
        // Fail closed: see the module documentation. The accepted contract
        // requires the kernel's `SO_PEERPIDFD`, not a PID-derived pidfd.
        Err(PeerPidfdError::Unsupported)
    }
}

/// Fail-closed production resolver for systemd `GetUnitByPIDFD`.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemdUnitResolver;

impl UnitResolver for SystemdUnitResolver {
    fn unit_by_pidfd(&self, _pidfd: BorrowedFd<'_>) -> Result<ResolvedUnit, UnitResolveError> {
        // Fail closed: see the module documentation.
        Err(UnitResolveError::Unavailable)
    }
}

/// Procfs-backed process identity inspector.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProcfsProcessInspector;

impl ProcessInspector for ProcfsProcessInspector {
    fn identity(&self, pid: u32, _pidfd: BorrowedFd<'_>) -> Result<ProcessIdentity, InspectError> {
        let status = read_proc_file(pid, "status")?;
        let (uid, gid) = parse_status_ids(&status).ok_or(InspectError::Io)?;
        let stat = read_proc_file(pid, "stat")?;
        let start_time_ticks = parse_stat_start_time(&stat).ok_or(InspectError::Io)?;
        Ok(ProcessIdentity {
            uid,
            gid,
            start_time_ticks,
        })
    }

    fn confinement(
        &self,
        _pid: u32,
        _pidfd: BorrowedFd<'_>,
    ) -> Result<ConfinementFacts, InspectError> {
        // The LSM label alone (`/proc/<pid>/attr/current`) cannot satisfy the
        // contract: lockdown-profile evidence comes from the root-owned
        // installed authority manifests (`basil-q5we`) plus live state, and
        // `Seccomp: 2` alone is insufficient. Fail closed until that
        // integration lands.
        Err(InspectError::Unavailable)
    }
}

/// `/proc/<pid>/exe` executable opener (requires `CAP_SYS_PTRACE` cross-UID).
#[derive(Clone, Copy, Debug, Default)]
pub struct ProcExecutableOpener;

impl ExecutableOpener for ProcExecutableOpener {
    fn open_executable(
        &self,
        pid: u32,
        _pidfd: BorrowedFd<'_>,
    ) -> Result<OwnedFd, ExecutableError> {
        let path = PathBuf::from(format!("/proc/{pid}/exe"));
        rustix::fs::open(&path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty()).map_err(|errno| {
            match errno {
                rustix::io::Errno::NOENT | rustix::io::Errno::SRCH => ExecutableError::PeerVanished,
                _ => ExecutableError::Io,
            }
        })
    }
}

/// Read one bounded procfs evidence file for `pid`.
fn read_proc_file(pid: u32, name: &str) -> Result<String, InspectError> {
    let path = PathBuf::from(format!("/proc/{pid}/{name}"));
    let fd = rustix::fs::open(
        &path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|errno| match errno {
        rustix::io::Errno::NOENT | rustix::io::Errno::SRCH => InspectError::PeerVanished,
        _ => InspectError::Io,
    })?;
    let mut file = std::fs::File::from(fd);
    let mut bytes = Vec::new();
    let limit = u64::try_from(MAX_PROCFS_BYTES).unwrap_or(u64::MAX);
    file.by_ref()
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|_| InspectError::Io)?;
    String::from_utf8(bytes).map_err(|_| InspectError::Io)
}

/// Parse effective UID and GID from `/proc/<pid>/status`.
fn parse_status_ids(status: &str) -> Option<(u32, u32)> {
    let mut uid = None;
    let mut gid = None;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            // Fields: real, effective, saved, filesystem.
            uid = rest.split_whitespace().nth(1)?.parse::<u32>().ok();
        } else if let Some(rest) = line.strip_prefix("Gid:") {
            gid = rest.split_whitespace().nth(1)?.parse::<u32>().ok();
        }
    }
    Some((uid?, gid?))
}

/// Parse the process start time (field 22) from `/proc/<pid>/stat`.
///
/// The `comm` field may contain spaces and parentheses; fields are counted
/// from after the last `)`.
fn parse_stat_start_time(stat: &str) -> Option<u64> {
    let after_comm = stat.rsplit_once(')')?.1;
    // `after_comm` starts at field 3 (`state`); `starttime` is field 22.
    after_comm.split_whitespace().nth(19)?.parse::<u64>().ok()
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd;

    use super::*;

    #[test]
    fn reads_own_identity_from_procfs() {
        let pid = std::process::id();
        let pidfd = rustix::process::pidfd_open(
            rustix::process::getpid(),
            rustix::process::PidfdFlags::empty(),
        )
        .expect("pidfd_open self");
        let identity = ProcfsProcessInspector
            .identity(pid, pidfd.as_fd())
            .expect("identity");
        assert_eq!(identity.uid, rustix::process::getuid().as_raw());
        assert_eq!(identity.gid, rustix::process::getgid().as_raw());
        assert!(identity.start_time_ticks > 0);
    }

    #[test]
    fn identity_reports_a_vanished_peer() {
        let pidfd = rustix::process::pidfd_open(
            rustix::process::getpid(),
            rustix::process::PidfdFlags::empty(),
        )
        .expect("pidfd_open self");
        // PID 0 never exists in procfs.
        assert_eq!(
            ProcfsProcessInspector.identity(0, pidfd.as_fd()),
            Err(InspectError::PeerVanished)
        );
    }

    #[test]
    fn opens_own_executable() {
        let pid = std::process::id();
        let pidfd = rustix::process::pidfd_open(
            rustix::process::getpid(),
            rustix::process::PidfdFlags::empty(),
        )
        .expect("pidfd_open self");
        let executable = ProcExecutableOpener
            .open_executable(pid, pidfd.as_fd())
            .expect("open exe");
        let stat = rustix::fs::fstat(&executable).expect("fstat");
        assert_eq!(
            rustix::fs::FileType::from_raw_mode(stat.st_mode),
            rustix::fs::FileType::RegularFile
        );
    }

    #[test]
    fn placeholders_fail_closed() {
        let (a, _b) = rustix::net::socketpair(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::STREAM,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        )
        .expect("socketpair");
        assert_eq!(
            KernelPeerPidfdSource.peer_pidfd(a.as_fd()).unwrap_err(),
            PeerPidfdError::Unsupported
        );
        assert_eq!(
            SystemdUnitResolver.unit_by_pidfd(a.as_fd()).unwrap_err(),
            UnitResolveError::Unavailable
        );
        let pidfd = rustix::process::pidfd_open(
            rustix::process::getpid(),
            rustix::process::PidfdFlags::empty(),
        )
        .expect("pidfd_open self");
        assert_eq!(
            ProcfsProcessInspector
                .confinement(std::process::id(), pidfd.as_fd())
                .unwrap_err(),
            InspectError::Unavailable
        );
    }

    #[test]
    fn parses_stat_with_hostile_comm() {
        let stat = "1234 (a) b) R 1 1 1 0 -1 4194560 1 0 0 0 0 0 0 0 20 0 1 0 987654 1000 1 18446744073709551615";
        assert_eq!(parse_stat_start_time(stat), Some(987_654));
    }
}
