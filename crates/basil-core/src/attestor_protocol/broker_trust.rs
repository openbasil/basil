// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Attestor-side broker trust anchor and peer verification.
//!
//! `docs/attestor-realm-contract/SPEC.md` rev 1.2 gives the attestor exactly
//! one trust root for authenticating its broker peer: the enrollment-installed
//! `/etc/basil/attestors/<realm>/broker.toml` (schema
//! `basil-attestor-broker-trust`, version 1) holding the realm, the decimal
//! broker UID, and the broker's exact non-generation-qualified system service
//! unit. The attestor fd-pins and hashes that file at startup
//! ([`BrokerTrustAnchor::load`]), and on every accepted connection captures
//! the peer's kernel credentials, race-free pidfd (`SO_PEERPIDFD`), PID start
//! time, and system-manager unit, verifies them against the anchor, and binds
//! the verified facts into an opaque [`VerifiedPeerBinding`]
//! ([`verify_broker_peer`]).
//!
//! Deliberately out of scope, per the same contract: the attestor performs no
//! broker executable measurement and no release admission, and this module
//! constructs no session — epoch agreement and `AttestorSession` wiring are
//! separate work (`basil-agrz`).

use std::io::Read as _;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd};
use std::path::Path;

use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::fs::{Mode, OFlags};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use super::codec::{PeerCredentials, VerifiedPeerBinding};
use super::helper::ident;
use super::helper::peer_pidfd;
use super::helper::service::PeerPidfdError;

/// Exact schema identifier the anchor file must declare.
const ANCHOR_SCHEMA: &str = "basil-attestor-broker-trust";
/// Exact schema version the anchor file must declare.
const ANCHOR_SCHEMA_VERSION: u32 = 1;
/// Ceiling on the anchor file size; the file holds five short fields.
const MAX_ANCHOR_BYTES: usize = 4096;
/// Ceiling on one bounded procfs evidence read.
const MAX_PROCFS_BYTES: usize = 64 * 1024;
/// Maximum bytes in the broker service unit name (schema-3 ceiling).
const MAX_UNIT_BYTES: usize = 128;
/// Domain separator for the attestor-side broker peer binding digest.
const BINDING_DOMAIN: &[u8] = b"basil.realm.broker-peer-binding.v1\0";

/// Failure to load the trust anchor or verify the broker peer against it.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum BrokerTrustError {
    /// The anchor path has no parent directory or no file name.
    #[error("trust anchor path is not a directory-and-leaf path")]
    InvalidPath,
    /// The anchor file or its parent directory is missing, is not the
    /// expected file type, is not owned by the required owner, or is
    /// group/other writable.
    #[error("trust anchor source failed ownership or mode validation")]
    UntrustedSource,
    /// The anchor file identity changed while it was being read.
    #[error("trust anchor changed during the pinned read")]
    SourceChanged,
    /// The anchor file exceeds the compiled size ceiling.
    #[error("trust anchor exceeds {MAX_ANCHOR_BYTES} bytes")]
    SourceTooLarge,
    /// The anchor bytes are not valid UTF-8 strict TOML for the schema.
    #[error("trust anchor is malformed")]
    Malformed,
    /// The anchor declares an unexpected schema or schema version.
    #[error("trust anchor schema is not {ANCHOR_SCHEMA} v{ANCHOR_SCHEMA_VERSION}")]
    SchemaMismatch,
    /// The anchor's realm does not equal this attestor's configured realm.
    #[error("trust anchor realm does not match the configured realm")]
    RealmMismatch,
    /// `brokerUid` is not a canonical decimal UID string.
    #[error("trust anchor brokerUid is not a canonical decimal UID")]
    InvalidBrokerUid,
    /// `brokerUnit` is not a canonical, non-generation-qualified system
    /// service unit name.
    #[error("trust anchor brokerUnit is not a canonical non-generation-qualified service unit")]
    InvalidBrokerUnit,
    /// The connecting peer's kernel UID is not the enrolled broker UID.
    #[error("peer UID is not the enrolled broker UID")]
    PeerUidMismatch,
    /// The kernel supplied no usable peer PID.
    #[error("peer PID unavailable from the kernel credentials")]
    PeerPidUnavailable,
    /// The kernel cannot supply a race-free peer pidfd (`SO_PEERPIDFD`);
    /// there is deliberately no `pidfd_open` fallback.
    #[error("race-free peer pidfd unavailable")]
    PidfdUnavailable,
    /// The kernel-recorded pidfd names a different process than the
    /// credential PID.
    #[error("peer pidfd does not name the credential PID")]
    PidfdMismatch,
    /// The peer exited before its facts could be pinned.
    #[error("peer vanished during verification")]
    PeerVanished,
    /// A bounded procfs evidence read failed or was malformed.
    #[error("peer process evidence unavailable")]
    Evidence,
    /// The peer's procfs identity does not match its kernel credentials.
    #[error("peer procfs identity does not match its kernel credentials")]
    IdentityMismatch,
    /// The peer runs under a per-user service manager; the broker must be
    /// an administrator-owned system service.
    #[error("peer runs under a user service manager")]
    UserManagerPlacement,
    /// The peer's system unit does not equal the enrolled `brokerUnit`.
    #[error("peer unit is not the enrolled broker unit")]
    UnitMismatch,
}

/// Strict on-disk shape of `broker.toml` (unknown fields reject).
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AnchorFile {
    schema: String,
    schema_version: u32,
    realm: String,
    broker_uid: String,
    broker_unit: String,
}

/// The fd-pinned, hashed, and validated broker trust anchor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerTrustAnchor {
    realm: String,
    broker_uid: u32,
    broker_unit: String,
    source_digest: [u8; 32],
}

impl BrokerTrustAnchor {
    /// Load and validate the enrollment-installed trust anchor.
    ///
    /// The file and its immediate parent directory are opened without
    /// following symlinks and must be owned by `required_owner_uid` with no
    /// group or other write bit (enrollment installs a UID-0-owned
    /// mode-`0644` file below UID-0-owned non-writable parents; development
    /// hosts substitute an owner for a directory they own). The leaf is read
    /// once through the pinned descriptor, its identity is rechecked after
    /// the read, and the exact bytes are hashed into the anchor digest.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerTrustError`] when the source fails ownership, mode,
    /// size, or identity validation, or the content fails the strict
    /// `basil-attestor-broker-trust` v1 schema, or the anchor realm does not
    /// equal `expected_realm`.
    pub fn load(
        path: &Path,
        expected_realm: &str,
        required_owner_uid: u32,
    ) -> Result<Self, BrokerTrustError> {
        let (bytes, source_digest) = read_pinned_source(path, required_owner_uid)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| BrokerTrustError::Malformed)?;
        let file: AnchorFile = toml::from_str(text).map_err(|_| BrokerTrustError::Malformed)?;
        if file.schema != ANCHOR_SCHEMA || file.schema_version != ANCHOR_SCHEMA_VERSION {
            return Err(BrokerTrustError::SchemaMismatch);
        }
        if !ident::is_valid_realm_name(&file.realm) || file.realm != expected_realm {
            return Err(BrokerTrustError::RealmMismatch);
        }
        let broker_uid =
            ident::parse_decimal_uid(&file.broker_uid).ok_or(BrokerTrustError::InvalidBrokerUid)?;
        if !is_valid_broker_unit(&file.broker_unit) {
            return Err(BrokerTrustError::InvalidBrokerUnit);
        }
        Ok(Self {
            realm: file.realm,
            broker_uid,
            broker_unit: file.broker_unit,
            source_digest,
        })
    }

    /// The configured realm this anchor binds.
    #[must_use]
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// The enrolled broker UID allowed to connect.
    #[must_use]
    pub const fn broker_uid(&self) -> u32 {
        self.broker_uid
    }

    /// The enrolled broker system service unit.
    #[must_use]
    pub fn broker_unit(&self) -> &str {
        &self.broker_unit
    }

    /// SHA-256 of the exact anchor bytes that were validated.
    #[must_use]
    pub const fn source_digest(&self) -> &[u8; 32] {
        &self.source_digest
    }
}

/// One broker peer verified against the trust anchor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedBrokerPeer {
    credentials: PeerCredentials,
    start_time_ticks: u64,
    unit: String,
    binding: VerifiedPeerBinding,
}

impl VerifiedBrokerPeer {
    /// Kernel credentials of the verified peer.
    #[must_use]
    pub const fn credentials(&self) -> PeerCredentials {
        self.credentials
    }

    /// Kernel start time (clock ticks) pinning the peer PID identity.
    #[must_use]
    pub const fn start_time_ticks(&self) -> u64 {
        self.start_time_ticks
    }

    /// The verified system unit of the peer (equals the anchor's unit).
    #[must_use]
    pub fn unit(&self) -> &str {
        &self.unit
    }

    /// The opaque binding over every verified broker fact.
    #[must_use]
    pub const fn binding(&self) -> VerifiedPeerBinding {
        self.binding
    }
}

/// Verify one accepted connection's peer as the enrolled broker.
///
/// `credentials` are the stream's already-captured `SO_PEERCRED`; `stream`
/// is the accepted stream itself, from which the race-free `SO_PEERPIDFD`
/// pidfd is acquired and cross-checked against the credential PID. The
/// peer's procfs identity (UID slots, start time) and system-manager unit
/// are then pinned and compared with the anchor, and the pidfd is polled so
/// facts of an already-exited peer are never bound. On success every
/// verified fact is folded into the returned [`VerifiedPeerBinding`].
///
/// # Errors
///
/// Returns [`BrokerTrustError`] on any mismatch; every failure rejects the
/// connection fail-closed.
pub fn verify_broker_peer(
    anchor: &BrokerTrustAnchor,
    credentials: PeerCredentials,
    stream: BorrowedFd<'_>,
) -> Result<VerifiedBrokerPeer, BrokerTrustError> {
    verify_broker_peer_at(anchor, credentials, stream, Path::new("/proc"))
}

/// [`verify_broker_peer`] over an explicit procfs root (test seam; the
/// pidfd acquisition and its `fdinfo` cross-check always use the real
/// kernel state of the calling process).
fn verify_broker_peer_at(
    anchor: &BrokerTrustAnchor,
    credentials: PeerCredentials,
    stream: BorrowedFd<'_>,
    proc_root: &Path,
) -> Result<VerifiedBrokerPeer, BrokerTrustError> {
    if credentials.uid != anchor.broker_uid {
        return Err(BrokerTrustError::PeerUidMismatch);
    }
    let pid = credentials
        .pid
        .filter(|pid| *pid != 0)
        .ok_or(BrokerTrustError::PeerPidUnavailable)?;
    let pidfd = peer_pidfd::acquire(stream).map_err(|error| match error {
        PeerPidfdError::PeerVanished => BrokerTrustError::PeerVanished,
        PeerPidfdError::Unsupported | PeerPidfdError::Io => BrokerTrustError::PidfdUnavailable,
    })?;

    // The pidfd is the kernel-recorded connected peer; it must name the
    // same process the credentials describe (a dead peer reports `Pid: -1`).
    match pidfd_kernel_pid(pidfd.as_raw_fd()) {
        Some(kernel_pid) if kernel_pid == i64::from(pid) => {}
        Some(-1) => return Err(BrokerTrustError::PeerVanished),
        _ => return Err(BrokerTrustError::PidfdMismatch),
    }

    let status = read_bounded_proc(proc_root, pid, "status")?;
    let uid_slots = parse_status_uids(&status).ok_or(BrokerTrustError::Evidence)?;
    if uid_slots != [anchor.broker_uid; 4] {
        return Err(BrokerTrustError::IdentityMismatch);
    }
    let stat = read_bounded_proc(proc_root, pid, "stat")?;
    let start_time_ticks = parse_stat_start_time(&stat)
        .filter(|ticks| *ticks != 0)
        .ok_or(BrokerTrustError::Evidence)?;
    let cgroups = read_bounded_proc(proc_root, pid, "cgroup")?;
    let unit = system_unit_from_cgroups(&cgroups)?;
    if unit != anchor.broker_unit {
        return Err(BrokerTrustError::UnitMismatch);
    }

    // Every fact above belongs to the connected peer only if that peer is
    // still the process the pidfd names; an exited peer fails closed.
    if peer_exited(pidfd.as_fd())? {
        return Err(BrokerTrustError::PeerVanished);
    }

    let binding = derive_binding(anchor, credentials, pid, start_time_ticks, &unit);
    Ok(VerifiedBrokerPeer {
        credentials,
        start_time_ticks,
        unit,
        binding,
    })
}

/// Open, validate, read, recheck, and hash the anchor source.
fn read_pinned_source(
    path: &Path,
    required_owner_uid: u32,
) -> Result<(Vec<u8>, [u8; 32]), BrokerTrustError> {
    let parent = path.parent().ok_or(BrokerTrustError::InvalidPath)?;
    let name = path.file_name().ok_or(BrokerTrustError::InvalidPath)?;
    let parent_fd = rustix::fs::open(
        parent,
        OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::RDONLY,
        Mode::empty(),
    )
    .map_err(|_| BrokerTrustError::UntrustedSource)?;
    let parent_stat =
        rustix::fs::fstat(&parent_fd).map_err(|_| BrokerTrustError::UntrustedSource)?;
    if parent_stat.st_uid != required_owner_uid || parent_stat.st_mode & 0o022 != 0 {
        return Err(BrokerTrustError::UntrustedSource);
    }
    let fd = rustix::fs::openat(
        &parent_fd,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| BrokerTrustError::UntrustedSource)?;
    let before = rustix::fs::fstat(&fd).map_err(|_| BrokerTrustError::UntrustedSource)?;
    if rustix::fs::FileType::from_raw_mode(before.st_mode) != rustix::fs::FileType::RegularFile
        || before.st_uid != required_owner_uid
        || before.st_mode & 0o022 != 0
    {
        return Err(BrokerTrustError::UntrustedSource);
    }
    let declared_len =
        usize::try_from(before.st_size).map_err(|_| BrokerTrustError::SourceTooLarge)?;
    if declared_len > MAX_ANCHOR_BYTES {
        return Err(BrokerTrustError::SourceTooLarge);
    }

    let mut file = std::fs::File::from(fd);
    let mut bytes = Vec::new();
    let limit = u64::try_from(MAX_ANCHOR_BYTES).unwrap_or(u64::MAX);
    file.by_ref()
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| BrokerTrustError::UntrustedSource)?;
    if bytes.len() > MAX_ANCHOR_BYTES {
        return Err(BrokerTrustError::SourceTooLarge);
    }
    let after = rustix::fs::fstat(&file).map_err(|_| BrokerTrustError::UntrustedSource)?;
    if after.st_size != before.st_size
        || after.st_mtime != before.st_mtime
        || after.st_mtime_nsec != before.st_mtime_nsec
        || after.st_uid != before.st_uid
        || after.st_mode != before.st_mode
    {
        return Err(BrokerTrustError::SourceChanged);
    }
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    Ok((bytes, digest))
}

/// `brokerUnit` validation: the broker-loader unit grammar (mirrors
/// `core::attestor_realm::validate_unit`) plus the rev-1.2 requirement that
/// the broker unit is not generation-qualified.
fn is_valid_broker_unit(unit: &str) -> bool {
    let charset = unit.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'.' | b'@' | b'-')
    });
    !unit.is_empty()
        && unit.len() <= MAX_UNIT_BYTES
        && unit.len() > ".service".len()
        && unit.ends_with(".service")
        && charset
        && !unit.contains("..")
        && !ident::contains_generation_qualifier(unit)
}

/// Read the kernel PID a pidfd names from this process's own `fdinfo`.
fn pidfd_kernel_pid(raw_fd: i32) -> Option<i64> {
    let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{raw_fd}")).ok()?;
    info.lines().find_map(|line| {
        line.strip_prefix("Pid:")
            .and_then(|rest| rest.trim().parse().ok())
    })
}

/// Nonblocking poll: a readable pidfd means the process has exited.
fn peer_exited(pidfd: BorrowedFd<'_>) -> Result<bool, BrokerTrustError> {
    let timeout = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    loop {
        let mut fds = [PollFd::new(&pidfd, PollFlags::IN)];
        match rustix::event::poll(&mut fds, Some(&timeout)) {
            Ok(0) => return Ok(false),
            Ok(_) => return Ok(true),
            Err(rustix::io::Errno::INTR | rustix::io::Errno::AGAIN) => {}
            Err(_) => return Err(BrokerTrustError::Evidence),
        }
    }
}

/// Read one bounded procfs evidence file for `pid` under `proc_root`.
fn read_bounded_proc(proc_root: &Path, pid: u32, name: &str) -> Result<String, BrokerTrustError> {
    let path = proc_root.join(pid.to_string()).join(name);
    let fd = rustix::fs::open(
        &path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|errno| match errno {
        rustix::io::Errno::NOENT | rustix::io::Errno::SRCH => BrokerTrustError::PeerVanished,
        _ => BrokerTrustError::Evidence,
    })?;
    let mut file = std::fs::File::from(fd);
    let mut bytes = Vec::new();
    let limit = u64::try_from(MAX_PROCFS_BYTES).unwrap_or(u64::MAX);
    file.by_ref()
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| BrokerTrustError::Evidence)?;
    // Reject (rather than silently truncate) evidence at or over the
    // ceiling: a truncated read could drop trailing lines and change what
    // the parsers see, so oversize is treated as unusable evidence.
    if bytes.len() > MAX_PROCFS_BYTES {
        return Err(BrokerTrustError::Evidence);
    }
    String::from_utf8(bytes).map_err(|_| BrokerTrustError::Evidence)
}

/// Parse all four `Uid:` slots (real, effective, saved, filesystem).
fn parse_status_uids(status: &str) -> Option<[u32; 4]> {
    let rest = status.lines().find_map(|line| line.strip_prefix("Uid:"))?;
    let mut slots = [0_u32; 4];
    let mut fields = rest.split_whitespace();
    for slot in &mut slots {
        *slot = fields.next()?.parse().ok()?;
    }
    if fields.next().is_some() {
        return None;
    }
    Some(slots)
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

/// Derive the exact system-manager `.service` unit from `/proc/<pid>/cgroup`.
///
/// Rev 1.2 requires the broker to be an administrator-owned system service:
/// any `user.slice`, `user-<uid>.slice`, or `user@<uid>.service` placement
/// rejects, every non-empty line must name the same concrete unit, and a
/// process with no `.service` component is not a system service.
fn system_unit_from_cgroups(raw: &str) -> Result<String, BrokerTrustError> {
    let mut unit: Option<&str> = None;
    for line in raw.lines().filter(|line| !line.is_empty()) {
        let (_, path) = line.rsplit_once(':').ok_or(BrokerTrustError::Evidence)?;
        for component in path.split('/') {
            if is_user_manager_component(component) {
                return Err(BrokerTrustError::UserManagerPlacement);
            }
            if component.ends_with(".service") {
                match unit {
                    Some(existing) if existing != component => {
                        return Err(BrokerTrustError::Evidence);
                    }
                    _ => unit = Some(component),
                }
            }
        }
    }
    unit.map(str::to_string)
        .ok_or(BrokerTrustError::UnitMismatch)
}

/// Return whether one cgroup path component indicates per-user-manager
/// placement (`user.slice`, `user-<uid>.slice`, or a `user@<uid>.service`
/// manager). Rev 1.2 admits only administrator-owned system services on
/// both sides of the realm socket, so both the attestor's broker check and
/// the broker's attestor check (`core::attestor_realm_unix`) reject on it.
pub(crate) fn is_user_manager_component(component: &str) -> bool {
    component == "user.slice" || component.starts_with("user@") || is_user_uid_slice(component)
}

/// Return whether `component` is a `user-<uid>.slice` cgroup component.
fn is_user_uid_slice(component: &str) -> bool {
    component
        .strip_prefix("user-")
        .and_then(|rest| rest.strip_suffix(".slice"))
        .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
}

/// Fold every verified broker fact into the opaque peer binding.
fn derive_binding(
    anchor: &BrokerTrustAnchor,
    credentials: PeerCredentials,
    pid: u32,
    start_time_ticks: u64,
    unit: &str,
) -> VerifiedPeerBinding {
    let mut digest = Sha256::new();
    digest.update(BINDING_DOMAIN);
    for value in [
        u64::from(pid),
        u64::from(credentials.uid),
        u64::from(credentials.gid),
        start_time_ticks,
    ] {
        digest.update(value.to_be_bytes());
    }
    digest.update(anchor.source_digest);
    for value in [anchor.realm.as_bytes(), unit.as_bytes()] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
    VerifiedPeerBinding::from_authenticator(digest.finalize().into())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use std::os::fd::AsFd as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;

    use super::*;

    const GOOD_ANCHOR: &str = r#"
schema = "basil-attestor-broker-trust"
schemaVersion = 1
realm = "production-docker"
brokerUid = "991"
brokerUnit = "basil-agent.service"
"#;

    fn unique_dir() -> PathBuf {
        use std::fmt::Write as _;

        let mut unique = [0_u8; 8];
        getrandom::fill(&mut unique).expect("random");
        let mut name = String::from("basil-broker-trust-");
        for byte in unique {
            let _ = write!(name, "{byte:02x}");
        }
        let dir = std::env::temp_dir().join(name);
        std::fs::create_dir(&dir).expect("create dir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        dir
    }

    fn write_anchor(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join("broker.toml");
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        path
    }

    fn own_uid() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    #[test]
    fn anchor_loads_and_pins_the_exact_bytes() {
        let dir = unique_dir();
        let path = write_anchor(&dir, GOOD_ANCHOR);
        let anchor = BrokerTrustAnchor::load(&path, "production-docker", own_uid()).unwrap();
        assert_eq!(anchor.realm(), "production-docker");
        assert_eq!(anchor.broker_uid(), 991);
        assert_eq!(anchor.broker_unit(), "basil-agent.service");
        let expected: [u8; 32] = Sha256::digest(GOOD_ANCHOR.as_bytes()).into();
        assert_eq!(anchor.source_digest(), &expected);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn anchor_schema_is_strict() {
        let dir = unique_dir();
        for (body, expected) in [
            // Unknown field.
            (
                format!("{GOOD_ANCHOR}extra = 1\n"),
                BrokerTrustError::Malformed,
            ),
            // Wrong schema identifier.
            (
                GOOD_ANCHOR.replace("basil-attestor-broker-trust", "basil-broker"),
                BrokerTrustError::SchemaMismatch,
            ),
            // Wrong schema version.
            (
                GOOD_ANCHOR.replace("schemaVersion = 1", "schemaVersion = 2"),
                BrokerTrustError::SchemaMismatch,
            ),
            // Missing field.
            (
                GOOD_ANCHOR.replace("brokerUid = \"991\"\n", ""),
                BrokerTrustError::Malformed,
            ),
            // Non-canonical decimal UID.
            (
                GOOD_ANCHOR.replace("\"991\"", "\"0991\""),
                BrokerTrustError::InvalidBrokerUid,
            ),
            (
                GOOD_ANCHOR.replace("\"991\"", "\"basil\""),
                BrokerTrustError::InvalidBrokerUid,
            ),
            // Generation-qualified broker unit rejects.
            (
                GOOD_ANCHOR.replace("basil-agent.service", "basil-agent-g1.service"),
                BrokerTrustError::InvalidBrokerUnit,
            ),
            // Unit grammar violations.
            (
                GOOD_ANCHOR.replace("basil-agent.service", "bad/unit.service"),
                BrokerTrustError::InvalidBrokerUnit,
            ),
            (
                GOOD_ANCHOR.replace("basil-agent.service", ".service"),
                BrokerTrustError::InvalidBrokerUnit,
            ),
            (
                GOOD_ANCHOR.replace("basil-agent.service", "basil-agent"),
                BrokerTrustError::InvalidBrokerUnit,
            ),
        ] {
            let path = write_anchor(&dir, &body);
            assert_eq!(
                BrokerTrustAnchor::load(&path, "production-docker", own_uid()).unwrap_err(),
                expected,
                "body: {body}"
            );
        }
        // Realm mismatch against the configured realm.
        let path = write_anchor(&dir, GOOD_ANCHOR);
        assert_eq!(
            BrokerTrustAnchor::load(&path, "other-realm", own_uid()).unwrap_err(),
            BrokerTrustError::RealmMismatch
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn anchor_source_ownership_and_mode_fail_closed() {
        let dir = unique_dir();
        let path = write_anchor(&dir, GOOD_ANCHOR);
        // Wrong required owner.
        assert_eq!(
            BrokerTrustAnchor::load(&path, "production-docker", own_uid().wrapping_add(1))
                .unwrap_err(),
            BrokerTrustError::UntrustedSource
        );
        // Group-writable leaf.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o664)).unwrap();
        assert_eq!(
            BrokerTrustAnchor::load(&path, "production-docker", own_uid()).unwrap_err(),
            BrokerTrustError::UntrustedSource
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        // Group-writable parent.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert_eq!(
            BrokerTrustAnchor::load(&path, "production-docker", own_uid()).unwrap_err(),
            BrokerTrustError::UntrustedSource
        );
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        // A symlinked leaf is never followed.
        let link = dir.join("link.toml");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert_eq!(
            BrokerTrustAnchor::load(&link, "production-docker", own_uid()).unwrap_err(),
            BrokerTrustError::UntrustedSource
        );
        // Oversize source.
        let big = write_anchor(&dir, &format!("{GOOD_ANCHOR}{}", "# pad\n".repeat(1024)));
        assert_eq!(
            BrokerTrustAnchor::load(&big, "production-docker", own_uid()).unwrap_err(),
            BrokerTrustError::SourceTooLarge
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn system_unit_extraction_rejects_user_manager_placement() {
        assert_eq!(
            system_unit_from_cgroups("0::/system.slice/basil-agent.service\n").unwrap(),
            "basil-agent.service"
        );
        for raw in [
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/basil-agent.service\n",
            "0::/user.slice/basil-agent.service\n",
            "0::/user-1000.slice/basil-agent.service\n",
        ] {
            assert_eq!(
                system_unit_from_cgroups(raw).unwrap_err(),
                BrokerTrustError::UserManagerPlacement,
                "raw: {raw}"
            );
        }
        // No service component: not a system service.
        assert_eq!(
            system_unit_from_cgroups("0::/system.slice/whatever.scope\n").unwrap_err(),
            BrokerTrustError::UnitMismatch
        );
        // Ambiguous lines naming different units.
        assert_eq!(
            system_unit_from_cgroups(
                "1:name=x:/system.slice/a.service\n0::/system.slice/b.service\n"
            )
            .unwrap_err(),
            BrokerTrustError::Evidence
        );
        // `user-abc.slice` is not a per-user slice; it does not reject.
        assert_eq!(
            system_unit_from_cgroups("0::/user-abc.slice/basil-agent.service\n").unwrap(),
            "basil-agent.service"
        );
    }

    /// Fake procfs entries for one PID: real facts of this test process are
    /// used for the kernel side (`SO_PEERPIDFD`, `fdinfo`, liveness) while
    /// the identity evidence comes from the seam-controlled root.
    fn fake_proc(pid: u32, uid: u32, cgroup: &str) -> PathBuf {
        let root = unique_dir();
        let dir = root.join(pid.to_string());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("status"),
            format!("Name:\tbroker\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nGid:\t1\t1\t1\t1\n"),
        )
        .unwrap();
        std::fs::write(
            dir.join("stat"),
            format!("{pid} (basil agent) S {} 777 0 0\n", "0 ".repeat(18)),
        )
        .unwrap();
        std::fs::write(dir.join("cgroup"), cgroup).unwrap();
        root
    }

    fn anchor_for_self(dir: &Path) -> BrokerTrustAnchor {
        let body = GOOD_ANCHOR.replace("\"991\"", &format!("\"{}\"", own_uid()));
        let path = write_anchor(dir, &body);
        BrokerTrustAnchor::load(&path, "production-docker", own_uid()).unwrap()
    }

    fn self_credentials() -> PeerCredentials {
        PeerCredentials {
            pid: Some(std::process::id()),
            uid: own_uid(),
            gid: rustix::process::getegid().as_raw(),
        }
    }

    fn socketpair() -> (std::os::fd::OwnedFd, std::os::fd::OwnedFd) {
        rustix::net::socketpair(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::STREAM,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        )
        .unwrap()
    }

    #[test]
    fn full_verification_binds_the_connected_peer() {
        let dir = unique_dir();
        let anchor = anchor_for_self(&dir);
        let pid = std::process::id();
        let proc_root = fake_proc(pid, own_uid(), "0::/system.slice/basil-agent.service\n");
        let (a, _b) = socketpair();
        let verified = verify_broker_peer_at(&anchor, self_credentials(), a.as_fd(), &proc_root)
            .expect("verification succeeds for the live peer");
        assert_eq!(verified.credentials().uid, own_uid());
        assert_eq!(verified.start_time_ticks(), 777);
        assert_eq!(verified.unit(), "basil-agent.service");
        // The binding is deterministic over the same verified facts.
        let (c, _d) = socketpair();
        let again =
            verify_broker_peer_at(&anchor, self_credentials(), c.as_fd(), &proc_root).unwrap();
        assert_eq!(verified.binding(), again.binding());
        std::fs::remove_dir_all(&proc_root).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn verification_rejects_every_mismatched_fact() {
        let dir = unique_dir();
        let anchor = anchor_for_self(&dir);
        let pid = std::process::id();
        let (a, _b) = socketpair();

        // Wrong peer UID rejects before any pidfd or procfs work.
        let mut wrong_uid = self_credentials();
        wrong_uid.uid = wrong_uid.uid.wrapping_add(1);
        assert_eq!(
            verify_broker_peer_at(&anchor, wrong_uid, a.as_fd(), Path::new("/nonexistent"))
                .unwrap_err(),
            BrokerTrustError::PeerUidMismatch
        );
        // Missing PID rejects.
        let mut no_pid = self_credentials();
        no_pid.pid = None;
        assert_eq!(
            verify_broker_peer_at(&anchor, no_pid, a.as_fd(), Path::new("/nonexistent"))
                .unwrap_err(),
            BrokerTrustError::PeerPidUnavailable
        );
        // A credential PID that is not the kernel-recorded peer rejects at
        // the pidfd cross-check, before any procfs read.
        let mut stolen_pid = self_credentials();
        stolen_pid.pid = Some(pid.wrapping_add(7));
        assert_eq!(
            verify_broker_peer_at(&anchor, stolen_pid, a.as_fd(), Path::new("/nonexistent"))
                .unwrap_err(),
            BrokerTrustError::PidfdMismatch
        );
        // Procfs UID slots disagreeing with the credentials reject.
        let other_uid_root = fake_proc(
            pid,
            own_uid().wrapping_add(1),
            "0::/system.slice/basil-agent.service\n",
        );
        assert_eq!(
            verify_broker_peer_at(&anchor, self_credentials(), a.as_fd(), &other_uid_root)
                .unwrap_err(),
            BrokerTrustError::IdentityMismatch
        );
        // User-manager placement rejects.
        let user_root = fake_proc(
            pid,
            own_uid(),
            "0::/user.slice/user-1000.slice/user@1000.service/basil-agent.service\n",
        );
        assert_eq!(
            verify_broker_peer_at(&anchor, self_credentials(), a.as_fd(), &user_root).unwrap_err(),
            BrokerTrustError::UserManagerPlacement
        );
        // A unit other than the enrolled broker unit rejects.
        let wrong_unit_root = fake_proc(pid, own_uid(), "0::/system.slice/impostor.service\n");
        assert_eq!(
            verify_broker_peer_at(&anchor, self_credentials(), a.as_fd(), &wrong_unit_root)
                .unwrap_err(),
            BrokerTrustError::UnitMismatch
        );
        for root in [other_uid_root, user_root, wrong_unit_root] {
            std::fs::remove_dir_all(&root).unwrap();
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn status_uid_parsing_is_exact() {
        assert_eq!(parse_status_uids("Uid:\t1\t2\t3\t4\n"), Some([1, 2, 3, 4]));
        assert_eq!(parse_status_uids("Uid:\t1\t2\t3\n"), None);
        assert_eq!(parse_status_uids("Uid:\t1\t2\t3\t4\t5\n"), None);
        assert_eq!(parse_status_uids("Gid:\t1\t2\t3\t4\n"), None);
    }
}
