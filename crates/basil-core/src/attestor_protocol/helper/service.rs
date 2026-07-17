// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The measurement-helper request pipeline.
//!
//! Every expectation applied here comes from the root-owned installed
//! allowlist selected by the request-named `(policy identity, generation,
//! realm)` triple — never from request content. The helper derives
//! `SO_PEERCRED` and `SO_COOKIE` from the duplicated stream itself, acquires
//! the peer pidfd, resolves the peer's systemd unit, checks the exact
//! expected unit/LSM/lockdown identities, opens the peer executable, and
//! re-verifies the peer identity after the open (a start-time sandwich) so a
//! peer that exits, execs, or is replaced by PID reuse during measurement is
//! rejected fail closed.
//!
//! Host facilities that need privileged or platform transports are
//! dependency-injected: [`PeerPidfdSource`] (the `SO_PEERPIDFD` socket
//! option), [`UnitResolver`] (systemd `GetUnitByPIDFD`), [`ProcessInspector`]
//! (procfs identity and confinement evidence), and [`ExecutableOpener`]
//! (`/proc/<pid>/exe` under `CAP_SYS_PTRACE`). Conformance tests inject
//! deterministic fakes; production implementations live in
//! [`super::host`].

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use rustix::fs::FileType;
use rustix::net::sockopt;
use rustix::net::{AddressFamily, SocketType};
use thiserror::Error;

use super::allowlist::{AllowlistLookupError, InstalledAllowlist};
use super::transport::{HelperConnection, ReceivedDatagram, TransportError};
use super::wire::{
    MAX_REQUEST_BYTES, MeasuredRecord, MeasurementRequest, NONCE_BYTES, RejectCode,
    RejectionRecord, WireError,
};

/// Failure to acquire the peer pidfd from the duplicated stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum PeerPidfdError {
    /// The host integration for `SO_PEERPIDFD` is not available.
    #[error("peer pidfd acquisition unavailable on this host")]
    Unsupported,
    /// The peer process is already gone.
    #[error("peer process exited before measurement")]
    PeerVanished,
    /// The kernel rejected the acquisition.
    #[error("peer pidfd acquisition failed")]
    Io,
}

/// Failure to resolve the peer's systemd unit.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum UnitResolveError {
    /// The host integration for `GetUnitByPIDFD` is not available.
    #[error("systemd unit resolution unavailable on this host")]
    Unavailable,
    /// The peer process belongs to no system unit.
    #[error("peer process belongs to no system unit")]
    NotFound,
    /// The system manager rejected or failed the query.
    #[error("systemd unit resolution failed")]
    Io,
}

/// Failure to inspect peer process identity or confinement.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum InspectError {
    /// The peer process is already gone.
    #[error("peer process exited during inspection")]
    PeerVanished,
    /// The evidence source for this fact is not available.
    #[error("process evidence unavailable on this host")]
    Unavailable,
    /// Reading or parsing the evidence failed.
    #[error("process inspection failed")]
    Io,
}

/// Failure to open the peer's current executable.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum ExecutableError {
    /// The peer process is already gone.
    #[error("peer process exited before its executable could be opened")]
    PeerVanished,
    /// Opening the executable failed.
    #[error("peer executable open failed")]
    Io,
}

/// The peer's systemd resolution result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedUnit {
    /// Exact system service unit name (for example
    /// `basil-attestor-production-docker-g1.service`).
    pub unit: String,
}

/// Stable peer process identity used for the before/after sandwich.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessIdentity {
    /// Effective UID of the process.
    pub uid: u32,
    /// Effective GID of the process.
    pub gid: u32,
    /// Kernel start time (clock ticks since boot); detects PID reuse.
    pub start_time_ticks: u64,
}

/// Live confinement evidence for the peer process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfinementFacts {
    /// Exact LSM profile identity the process runs under.
    pub lsm_profile: String,
    /// Exact post-init lockdown profile identity the process proves.
    pub lockdown_profile: String,
}

/// Source of the peer pidfd for a connected Unix stream.
pub trait PeerPidfdSource {
    /// Acquire a pidfd for the stream's connected peer.
    ///
    /// # Errors
    ///
    /// Returns [`PeerPidfdError`] when acquisition is unsupported or fails.
    fn peer_pidfd(&self, stream: BorrowedFd<'_>) -> Result<OwnedFd, PeerPidfdError>;
}

/// Resolver of a process's systemd unit by pidfd (`GetUnitByPIDFD`).
pub trait UnitResolver {
    /// Resolve the exact system unit owning the pidfd's process.
    ///
    /// # Errors
    ///
    /// Returns [`UnitResolveError`] when resolution is unavailable or fails.
    fn unit_by_pidfd(&self, pidfd: BorrowedFd<'_>) -> Result<ResolvedUnit, UnitResolveError>;
}

/// Inspector of live peer process identity and confinement.
pub trait ProcessInspector {
    /// Read the peer's stable identity (UID/GID/start time).
    ///
    /// # Errors
    ///
    /// Returns [`InspectError`] when the process is gone or unreadable.
    fn identity(&self, pid: u32, pidfd: BorrowedFd<'_>) -> Result<ProcessIdentity, InspectError>;

    /// Read the peer's live confinement evidence.
    ///
    /// # Errors
    ///
    /// Returns [`InspectError`] when evidence is unavailable or unreadable.
    fn confinement(
        &self,
        pid: u32,
        pidfd: BorrowedFd<'_>,
    ) -> Result<ConfinementFacts, InspectError>;
}

/// Opener of the peer's current executable under `CAP_SYS_PTRACE`.
pub trait ExecutableOpener {
    /// Open the peer's current executable read-only.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutableError`] when the process is gone or the open fails.
    fn open_executable(&self, pid: u32, pidfd: BorrowedFd<'_>) -> Result<OwnedFd, ExecutableError>;
}

/// The result of handling one request.
#[derive(Debug)]
pub enum HelperOutcome {
    /// The measurement succeeded; the record travels with two descriptors.
    Measured {
        /// The bounded record bound to the stream cookie.
        record: MeasuredRecord,
        /// The peer pidfd (first descriptor on the wire).
        pidfd: OwnedFd,
        /// The measured executable (second descriptor on the wire).
        executable: OwnedFd,
    },
    /// The request was rejected with a disclosure-safe code.
    Rejected(RejectionRecord),
}

/// The measurement-helper service.
///
/// The service owns no runtime API, key, or policy-decision state: only the
/// installed allowlist and the injected host facilities.
#[derive(Debug)]
pub struct HelperService<P, U, I, E> {
    allowlist: InstalledAllowlist,
    peer_source: P,
    unit_resolver: U,
    inspector: I,
    executable_opener: E,
}

impl<P, U, I, E> HelperService<P, U, I, E>
where
    P: PeerPidfdSource,
    U: UnitResolver,
    I: ProcessInspector,
    E: ExecutableOpener,
{
    /// Build a service over an installed allowlist and host facilities.
    pub const fn new(
        allowlist: InstalledAllowlist,
        peer_source: P,
        unit_resolver: U,
        inspector: I,
        executable_opener: E,
    ) -> Self {
        Self {
            allowlist,
            peer_source,
            unit_resolver,
            inspector,
            executable_opener,
        }
    }

    /// Handle one received datagram and produce a response outcome.
    ///
    /// Never panics; every failure maps to a typed disclosure-safe rejection.
    #[must_use]
    pub fn handle(&self, datagram: ReceivedDatagram) -> HelperOutcome {
        // Echo identity for rejections that follow a successful decode.
        let mut echo_generation = 0u64;
        let mut echo_nonce = [0u8; NONCE_BYTES];
        let reject = |code: RejectCode, generation: u64, nonce: [u8; NONCE_BYTES]| {
            HelperOutcome::Rejected(RejectionRecord {
                protocol: super::wire::HELPER_PROTOCOL_VERSION,
                code,
                broker_generation: generation,
                nonce,
            })
        };

        if datagram.ancillary_truncated {
            return reject(RejectCode::AncillaryTruncated, echo_generation, echo_nonce);
        }
        if datagram.oversized {
            return reject(RejectCode::MalformedRequest, echo_generation, echo_nonce);
        }
        let request = match MeasurementRequest::decode(&datagram.bytes) {
            Ok(request) => request,
            Err(WireError::UnsupportedProtocol(_)) => {
                return reject(RejectCode::UnsupportedProtocol, echo_generation, echo_nonce);
            }
            Err(_) => {
                return reject(RejectCode::MalformedRequest, echo_generation, echo_nonce);
            }
        };
        echo_generation = request.broker_generation;
        echo_nonce = request.nonce;

        let mut descriptors = datagram.descriptors;
        if descriptors.is_empty() {
            return reject(RejectCode::DescriptorMissing, echo_generation, echo_nonce);
        }
        if descriptors.len() > 1 {
            return reject(RejectCode::DescriptorSurplus, echo_generation, echo_nonce);
        }
        let Some(stream) = descriptors.pop() else {
            return reject(RejectCode::Internal, echo_generation, echo_nonce);
        };

        match self.measure(&request, &stream) {
            Ok((record, pidfd, executable)) => HelperOutcome::Measured {
                record,
                pidfd,
                executable,
            },
            Err(code) => reject(code, echo_generation, echo_nonce),
        }
    }

    /// The fallible measurement pipeline; errors are wire rejection codes.
    fn measure(
        &self,
        request: &MeasurementRequest,
        stream: &OwnedFd,
    ) -> Result<(MeasuredRecord, OwnedFd, OwnedFd), RejectCode> {
        // 1. Select the installed expectation. Request content only selects.
        let expectation = self
            .allowlist
            .lookup(
                &request.policy_identity,
                request.policy_generation,
                &request.realm,
            )
            .map_err(|error| match error {
                AllowlistLookupError::PolicyNotInstalled => RejectCode::PolicyNotInstalled,
                AllowlistLookupError::RealmNotInstalled => RejectCode::RealmNotInstalled,
            })?;

        // 2-3. Verify the descriptor and derive kernel facts from it.
        let facts = derive_stream_facts(stream.as_fd())?;

        // 4. The connect-time peer UID must equal the installed attestor UID.
        if facts.uid != expectation.attestor_uid {
            return Err(RejectCode::PeerIdentityMismatch);
        }

        // 5. Acquire the peer pidfd and capture the pre-measurement identity.
        let pidfd = self
            .peer_source
            .peer_pidfd(stream.as_fd())
            .map_err(|error| match error {
                PeerPidfdError::PeerVanished => RejectCode::PeerExited,
                PeerPidfdError::Unsupported | PeerPidfdError::Io => {
                    RejectCode::PeerDerivationFailed
                }
            })?;
        let before = self
            .inspector
            .identity(facts.pid, pidfd.as_fd())
            .map_err(inspect_reject)?;
        if before.uid != expectation.attestor_uid {
            return Err(RejectCode::PeerIdentityMismatch);
        }

        // 6. Confinement: exact LSM and lockdown identities.
        let confinement = self
            .inspector
            .confinement(facts.pid, pidfd.as_fd())
            .map_err(inspect_reject)?;
        if confinement.lsm_profile != expectation.lsm_profile
            || confinement.lockdown_profile != expectation.lockdown_profile
        {
            return Err(RejectCode::ConfinementMismatch);
        }

        // 7. Unit resolution with the checked generation binding.
        let resolved =
            self.unit_resolver
                .unit_by_pidfd(pidfd.as_fd())
                .map_err(|error| match error {
                    UnitResolveError::NotFound => RejectCode::UnitMismatch,
                    UnitResolveError::Unavailable | UnitResolveError::Io => {
                        RejectCode::UnitResolutionFailed
                    }
                })?;
        if resolved.unit != expectation.service_unit {
            return Err(RejectCode::UnitMismatch);
        }
        if !super::ident::unit_has_generation_suffix(
            &resolved.unit,
            expectation.authority_generation.get(),
        ) {
            return Err(RejectCode::GenerationBinding);
        }

        // 8. Open the current executable under helper authority.
        let executable = self
            .executable_opener
            .open_executable(facts.pid, pidfd.as_fd())
            .map_err(|error| match error {
                ExecutableError::PeerVanished => RejectCode::PeerExited,
                ExecutableError::Io => RejectCode::ExecutableAccess,
            })?;
        let stat = rustix::fs::fstat(&executable).map_err(|_| RejectCode::ExecutableAccess)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            return Err(RejectCode::ExecutableAccess);
        }

        // 9. Post-open sandwich: same process, same identity, still alive.
        let after = self
            .inspector
            .identity(facts.pid, pidfd.as_fd())
            .map_err(|_| RejectCode::PeerExited)?;
        if after != before {
            return Err(RejectCode::PeerExited);
        }
        let recheck = derive_stream_facts(stream.as_fd()).map_err(|_| RejectCode::PeerExited)?;
        if recheck != facts {
            return Err(RejectCode::PeerExited);
        }

        let record = MeasuredRecord {
            protocol: super::wire::HELPER_PROTOCOL_VERSION,
            broker_generation: request.broker_generation,
            nonce: request.nonce,
            cookie: facts.cookie,
            peer_uid: facts.uid,
            peer_gid: facts.gid,
            peer_pid: facts.pid,
            peer_start_time: before.start_time_ticks,
            executable_device: device_of(&stat),
            executable_inode: stat.st_ino,
            realm: request.realm.clone(),
            policy_identity: request.policy_identity.clone(),
            policy_generation: request.policy_generation,
            service_unit: expectation.service_unit.clone(),
        };
        Ok((record, pidfd, executable))
    }
}

/// Kernel facts derived from the duplicated stream itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StreamFacts {
    cookie: u64,
    uid: u32,
    gid: u32,
    pid: u32,
}

/// Verify the descriptor type and derive `SO_COOKIE` plus `SO_PEERCRED`.
fn derive_stream_facts(stream: BorrowedFd<'_>) -> Result<StreamFacts, RejectCode> {
    verify_stream_descriptor(stream)?;
    let cookie = sockopt::socket_cookie(stream).map_err(|_| RejectCode::PeerDerivationFailed)?;
    let credentials =
        sockopt::socket_peercred(stream).map_err(|_| RejectCode::PeerDerivationFailed)?;
    let pid = u32::try_from(credentials.pid.as_raw_nonzero().get())
        .map_err(|_| RejectCode::PeerDerivationFailed)?;
    Ok(StreamFacts {
        cookie,
        uid: credentials.uid.as_raw(),
        gid: credentials.gid.as_raw(),
        pid,
    })
}

const fn inspect_reject(error: InspectError) -> RejectCode {
    match error {
        InspectError::PeerVanished => RejectCode::PeerExited,
        InspectError::Unavailable | InspectError::Io => RejectCode::PeerDerivationFailed,
    }
}

/// Reject a descriptor that is not a connected Unix stream socket.
fn verify_stream_descriptor(fd: BorrowedFd<'_>) -> Result<(), RejectCode> {
    let domain = sockopt::socket_domain(fd).map_err(|_| RejectCode::DescriptorType)?;
    if domain != AddressFamily::UNIX {
        return Err(RejectCode::DescriptorType);
    }
    let kind = sockopt::socket_type(fd).map_err(|_| RejectCode::DescriptorType)?;
    if kind != SocketType::STREAM {
        return Err(RejectCode::DescriptorType);
    }
    Ok(())
}

#[allow(clippy::useless_conversion)]
fn device_of(stat: &rustix::fs::Stat) -> u64 {
    u64::from(stat.st_dev)
}

/// Serve one accepted connection serially until end-of-stream.
///
/// Rejections keep the connection open (the broker owns retry policy); only
/// transport failures end the loop with an error.
///
/// # Errors
///
/// Returns [`TransportError`] when receive or send fails.
pub fn serve_connection<P, U, I, E>(
    connection: &HelperConnection,
    service: &HelperService<P, U, I, E>,
) -> Result<(), TransportError>
where
    P: PeerPidfdSource,
    U: UnitResolver,
    I: ProcessInspector,
    E: ExecutableOpener,
{
    while let Some(datagram) = connection.recv(MAX_REQUEST_BYTES)? {
        match service.handle(datagram) {
            HelperOutcome::Measured {
                record,
                pidfd,
                executable,
            } => {
                let Ok(bytes) = record.encode() else {
                    let rejection = RejectionRecord {
                        protocol: super::wire::HELPER_PROTOCOL_VERSION,
                        code: RejectCode::Internal,
                        broker_generation: record.broker_generation,
                        nonce: record.nonce,
                    };
                    connection.send(&rejection.encode(), &[])?;
                    continue;
                };
                connection.send(&bytes, &[pidfd.as_fd(), executable.as_fd()])?;
            }
            HelperOutcome::Rejected(rejection) => {
                connection.send(&rejection.encode(), &[])?;
            }
        }
    }
    Ok(())
}
