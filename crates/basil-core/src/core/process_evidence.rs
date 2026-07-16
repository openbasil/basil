// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Pinned Linux process evidence and fail-closed workload-domain resolution.
//!
//! The kernel peer credential is captured once, while mutable credential slots
//! are reread for every authorization. A PID is never treated as an identity by
//! itself: the process start time pins it against reuse. Namespace, cgroup, and
//! caller-to-host ID-map facts are pinned with it. Executable content is read
//! through the `/proc/<pid>/exe` object, checked for stable metadata, and
//! rehashed after a genuine `execve`; a diagnostic pathname carries no
//! authority.

use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::core::catalog::evidence::{
    AuthorizationDomain, CredentialSlots, EvidenceValue, ProcessEvidence, SystemdEvidence,
};

const MAX_PROC_TEXT_BYTES: u64 = 1024 * 1024;
const MAX_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ID_MAP_RANGES: usize = 340;

/// Credential snapshot returned by `SO_PEERCRED` at connection time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerCredentials {
    /// Peer PID in the broker's PID namespace.
    pub pid: u32,
    /// Peer effective UID in the broker's user namespace.
    pub uid: u32,
    /// Peer effective GID in the broker's user namespace.
    pub gid: u32,
}

/// Stable identity for one opened executable object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutableObjectId {
    /// Device containing the file.
    pub device: u64,
    /// Inode on `device`.
    pub inode: u64,
    /// File length used in stable-read checks.
    pub size: u64,
    /// Metadata-change time, seconds component.
    pub ctime_seconds: i64,
    /// Metadata-change time, nanoseconds component.
    pub ctime_nanoseconds: i64,
    /// Content-modification time, seconds component.
    pub mtime_seconds: i64,
    /// Content-modification time, nanoseconds component.
    pub mtime_nanoseconds: i64,
}

impl ExecutableObjectId {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.size(),
            ctime_seconds: metadata.ctime(),
            ctime_nanoseconds: metadata.ctime_nsec(),
            mtime_seconds: metadata.mtime(),
            mtime_nanoseconds: metadata.mtime_nsec(),
        }
    }
}

/// Namespace inode set that participates in workload classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamespaceInodes {
    /// User namespace.
    pub user: u64,
    /// PID namespace.
    pub pid: u64,
    /// Mount namespace.
    pub mount: u64,
    /// Network namespace.
    pub network: u64,
    /// IPC namespace.
    pub ipc: u64,
    /// UTS namespace.
    pub uts: u64,
}

/// One Linux user-namespace ID-map range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdMapRange {
    /// First caller-visible ID.
    pub inside: u32,
    /// First host-visible ID.
    pub outside: u32,
    /// Number of IDs in this range.
    pub length: u32,
}

impl IdMapRange {
    fn outside_to_inside(self, outside: u32) -> Option<u32> {
        let offset = u64::from(outside).checked_sub(u64::from(self.outside))?;
        if offset >= u64::from(self.length) {
            return None;
        }
        u64::from(self.inside)
            .checked_add(offset)
            .and_then(|value| u32::try_from(value).ok())
    }

    fn inside_to_outside(self, inside: u32) -> Option<u32> {
        let offset = u64::from(inside).checked_sub(u64::from(self.inside))?;
        if offset >= u64::from(self.length) {
            return None;
        }
        u64::from(self.outside)
            .checked_add(offset)
            .and_then(|value| u32::try_from(value).ok())
    }
}

/// Complete bounded observation of one live process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessObservation {
    /// Linux `/proc/<pid>/stat` start-time ticks.
    pub start_time_ticks: u64,
    /// Host-visible current UID slots.
    pub host_uids: CredentialSlots,
    /// Host-visible current GID slots.
    pub host_gids: CredentialSlots,
    /// Host-visible supplementary groups.
    pub host_supplementary_gids: Vec<u32>,
    /// SHA-256 of the stable opened executable object.
    pub executable_digest: String,
    /// Stable metadata identity of the opened executable object.
    pub executable_object: ExecutableObjectId,
    /// Current namespace identity.
    pub namespaces: NamespaceInodes,
    /// Exact normalized cgroup membership lines.
    pub cgroups: Vec<String>,
    /// User namespace UID mapping.
    pub uid_map: Vec<IdMapRange>,
    /// User namespace GID mapping.
    pub gid_map: Vec<IdMapRange>,
    /// Correlated systemd service identity, when one is unambiguous.
    pub systemd: Option<SystemdEvidence>,
}

/// Stable failure category exposed to admission and transport layers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessEvidenceFailureKind {
    /// Evidence could not be read or changed while it was read.
    Unavailable,
    /// Live evidence conflicts with the connection pin.
    Mismatch,
    /// Isolation or mapping is conclusive but unsupported.
    Unsupported,
}

/// Disclosure-safe process evidence failure.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("{kind:?} process evidence at `{field}`")]
pub struct ProcessEvidenceError {
    /// Stable category used for typed denial mapping.
    pub kind: ProcessEvidenceFailureKind,
    /// Bounded evidence-field token; never raw evidence.
    pub field: &'static str,
}

impl ProcessEvidenceError {
    const fn unavailable(field: &'static str) -> Self {
        Self {
            kind: ProcessEvidenceFailureKind::Unavailable,
            field,
        }
    }

    const fn mismatch(field: &'static str) -> Self {
        Self {
            kind: ProcessEvidenceFailureKind::Mismatch,
            field,
        }
    }

    const fn unsupported(field: &'static str) -> Self {
        Self {
            kind: ProcessEvidenceFailureKind::Unsupported,
            field,
        }
    }
}

/// Connection-lifetime pin plus the latest point-of-use process evidence.
#[derive(Debug)]
pub struct PinnedProcess {
    peer: PeerCredentials,
    start_time_ticks: u64,
    namespaces: NamespaceInodes,
    cgroups: Vec<String>,
    caller_peer_uid: u32,
    caller_peer_gid: u32,
    executable_object: ExecutableObjectId,
    executable_file: Option<File>,
    process: ProcessEvidence,
    systemd: Option<SystemdEvidence>,
}

impl PinnedProcess {
    /// Pin one already trusted observation. This constructor is the seam used
    /// by fake procfs/property tests and provider-independent attestors.
    pub fn capture_observation(
        peer: PeerCredentials,
        observation: ProcessObservation,
    ) -> Result<Self, ProcessEvidenceError> {
        Self::capture_parts(peer, observation, None)
    }

    fn capture_parts(
        peer: PeerCredentials,
        observation: ProcessObservation,
        executable_file: Option<File>,
    ) -> Result<Self, ProcessEvidenceError> {
        let mapped_peer_user = map_outside(&observation.uid_map, peer.uid, "uid_map")?;
        let mapped_peer_group = map_outside(&observation.gid_map, peer.gid, "gid_map")?;
        let process = process_evidence(&observation)?;
        Ok(Self {
            peer,
            start_time_ticks: observation.start_time_ticks,
            namespaces: observation.namespaces,
            cgroups: observation.cgroups,
            caller_peer_uid: mapped_peer_user,
            caller_peer_gid: mapped_peer_group,
            executable_object: observation.executable_object,
            executable_file,
            process,
            systemd: observation.systemd,
        })
    }

    /// Revalidate the pin and refresh mutable credential/executable evidence.
    ///
    /// PID reuse, namespace/cgroup movement, and caller/host mapping conflicts
    /// are typed mismatches. Credential slots and supplementary groups are
    /// deliberately refreshed rather than pinned so every authorization sees
    /// the live values. A genuine `execve` replaces the executable digest only
    /// after the new object was read stably.
    pub fn revalidate_observation(
        &mut self,
        observation: ProcessObservation,
    ) -> Result<(), ProcessEvidenceError> {
        if observation.start_time_ticks != self.start_time_ticks {
            return Err(ProcessEvidenceError::mismatch("pid_start_time"));
        }
        if observation.namespaces != self.namespaces {
            return Err(ProcessEvidenceError::mismatch("namespaces"));
        }
        if observation.cgroups != self.cgroups {
            return Err(ProcessEvidenceError::mismatch("cgroups"));
        }
        if map_outside(&observation.uid_map, self.peer.uid, "uid_map")? != self.caller_peer_uid
            || map_outside(&observation.gid_map, self.peer.gid, "gid_map")? != self.caller_peer_gid
        {
            return Err(ProcessEvidenceError::mismatch("caller_host_mapping"));
        }
        self.process = process_evidence(&observation)?;
        self.executable_object = observation.executable_object;
        self.systemd = observation.systemd;
        Ok(())
    }

    /// Latest point-of-use policy evidence.
    #[must_use]
    pub const fn process_evidence(&self) -> &ProcessEvidence {
        &self.process
    }

    /// Correlated systemd identity captured with the current pin.
    #[must_use]
    pub const fn systemd_evidence(&self) -> Option<&SystemdEvidence> {
        self.systemd.as_ref()
    }

    /// Caller-visible UID captured from peer credentials and the pinned map.
    #[must_use]
    pub const fn caller_peer_uid(&self) -> u32 {
        self.caller_peer_uid
    }

    /// Host-visible UID captured by `SO_PEERCRED`.
    #[must_use]
    pub const fn host_peer_uid(&self) -> u32 {
        self.peer.uid
    }
}

fn process_evidence(
    observation: &ProcessObservation,
) -> Result<ProcessEvidence, ProcessEvidenceError> {
    let uids = map_slots(&observation.uid_map, observation.host_uids, "uid_map")?;
    let gids = map_slots(&observation.gid_map, observation.host_gids, "gid_map")?;
    let supplementary_gids = observation
        .host_supplementary_gids
        .iter()
        .map(|id| map_outside(&observation.gid_map, *id, "gid_map"))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ProcessEvidence {
        uids: EvidenceValue::Available(uids),
        gids: EvidenceValue::Available(gids),
        supplementary_gids: EvidenceValue::Available(supplementary_gids),
        executable_digest: EvidenceValue::Available(observation.executable_digest.clone()),
    })
}

fn map_slots(
    ranges: &[IdMapRange],
    slots: CredentialSlots,
    field: &'static str,
) -> Result<CredentialSlots, ProcessEvidenceError> {
    Ok(CredentialSlots {
        real: map_outside(ranges, slots.real, field)?,
        effective: map_outside(ranges, slots.effective, field)?,
        saved: map_outside(ranges, slots.saved, field)?,
        filesystem: map_outside(ranges, slots.filesystem, field)?,
    })
}

fn map_outside(
    ranges: &[IdMapRange],
    outside: u32,
    field: &'static str,
) -> Result<u32, ProcessEvidenceError> {
    let mut matches = ranges
        .iter()
        .filter_map(|range| range.outside_to_inside(outside));
    let Some(value) = matches.next() else {
        return Err(ProcessEvidenceError::unsupported(field));
    };
    if matches.next().is_some()
        || !ranges
            .iter()
            .any(|range| range.inside_to_outside(value) == Some(outside))
    {
        return Err(ProcessEvidenceError::mismatch(field));
    }
    Ok(value)
}

/// Evidence status for one independently established workload domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DomainEvidence<T> {
    /// Trusted evidence conclusively excludes this domain.
    Absent,
    /// Trusted evidence establishes this domain.
    Verified(T),
    /// Evidence establishes isolation, but Basil has no provider/domain for it.
    Unsupported,
    /// A configured provider or required kernel fact is temporarily unavailable.
    Unavailable,
    /// Trusted sources conflict.
    Mismatch,
}

/// Inputs to most-specific workload-domain resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainResolutionEvidence<C> {
    /// Supported-container provider result.
    pub container: DomainEvidence<C>,
    /// Supported systemd-service result.
    pub systemd: DomainEvidence<SystemdEvidence>,
    /// Affirmative host-baseline result after excluding more-specific domains.
    pub host: DomainEvidence<()>,
}

/// Most-specific resolved domain and its correlated evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolvedDomain<C> {
    /// Verified supported container.
    Container(C),
    /// Verified `.service` unit.
    Systemd(SystemdEvidence),
    /// Affirmatively ordinary host process.
    HostProcess,
}

impl<C> ResolvedDomain<C> {
    /// Authorization-domain token consumed by subject eligibility.
    #[must_use]
    pub const fn domain(&self) -> AuthorizationDomain {
        match self {
            Self::Container(_) => AuthorizationDomain::Container,
            Self::Systemd(_) => AuthorizationDomain::SystemdUnit,
            Self::HostProcess => AuthorizationDomain::HostProcess,
        }
    }
}

/// Stable fail-closed workload-domain outcome.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum DomainResolutionError {
    /// Conclusive unsupported isolation; maps to `WORKLOAD_DOMAIN_UNSUPPORTED`.
    #[error("workload domain is unsupported")]
    Unsupported,
    /// Temporary evidence/provider outage; maps to `ATTESTATION_UNAVAILABLE`.
    #[error("workload attestation is unavailable")]
    Unavailable,
    /// Conflicting evidence; maps to an attestation mismatch denial.
    #[error("workload attestation evidence conflicts")]
    Mismatch,
}

/// Resolve container, then systemd, then affirmative host evidence.
///
/// A failure or isolation indication at a more-specific layer is terminal; it
/// is never converted into host authority.
pub fn resolve_domain<C>(
    evidence: DomainResolutionEvidence<C>,
) -> Result<ResolvedDomain<C>, DomainResolutionError> {
    match evidence.container {
        DomainEvidence::Verified(container) => return Ok(ResolvedDomain::Container(container)),
        DomainEvidence::Unsupported => return Err(DomainResolutionError::Unsupported),
        DomainEvidence::Unavailable => return Err(DomainResolutionError::Unavailable),
        DomainEvidence::Mismatch => return Err(DomainResolutionError::Mismatch),
        DomainEvidence::Absent => {}
    }
    match evidence.systemd {
        DomainEvidence::Verified(systemd) => return Ok(ResolvedDomain::Systemd(systemd)),
        DomainEvidence::Unsupported => return Err(DomainResolutionError::Unsupported),
        DomainEvidence::Unavailable => return Err(DomainResolutionError::Unavailable),
        DomainEvidence::Mismatch => return Err(DomainResolutionError::Mismatch),
        DomainEvidence::Absent => {}
    }
    match evidence.host {
        DomainEvidence::Verified(()) => Ok(ResolvedDomain::HostProcess),
        DomainEvidence::Unsupported | DomainEvidence::Absent => {
            Err(DomainResolutionError::Unsupported)
        }
        DomainEvidence::Unavailable => Err(DomainResolutionError::Unavailable),
        DomainEvidence::Mismatch => Err(DomainResolutionError::Mismatch),
    }
}

/// Bounded Linux procfs reader. A non-default root enables hermetic fake-procfs
/// tests without weakening production path selection.
#[derive(Clone, Debug)]
pub struct LinuxProcfs {
    root: PathBuf,
}

impl Default for LinuxProcfs {
    fn default() -> Self {
        Self::new("/proc")
    }
}

impl LinuxProcfs {
    /// Construct a reader rooted at `root`.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Capture and pin one peer directly from bounded procfs reads.
    pub fn capture(&self, peer: PeerCredentials) -> Result<PinnedProcess, ProcessEvidenceError> {
        let (observation, file) = self.observe(peer.pid)?;
        PinnedProcess::capture_parts(peer, observation, Some(file))
    }

    /// Revalidate a live process and refresh point-of-use evidence.
    pub fn revalidate(&self, pin: &mut PinnedProcess) -> Result<(), ProcessEvidenceError> {
        let (observation, file) = self.observe(pin.peer.pid)?;
        pin.revalidate_observation(observation)?;
        pin.executable_file = Some(file);
        Ok(())
    }

    fn observe(&self, pid: u32) -> Result<(ProcessObservation, File), ProcessEvidenceError> {
        let directory = self.root.join(pid.to_string());
        let stat = read_bounded(&directory.join("stat"), MAX_PROC_TEXT_BYTES, "stat")?;
        let status = read_bounded(&directory.join("status"), MAX_PROC_TEXT_BYTES, "status")?;
        let cgroup = read_bounded(&directory.join("cgroup"), MAX_PROC_TEXT_BYTES, "cgroup")?;
        let uid_map = read_bounded(&directory.join("uid_map"), MAX_PROC_TEXT_BYTES, "uid_map")?;
        let gid_map = read_bounded(&directory.join("gid_map"), MAX_PROC_TEXT_BYTES, "gid_map")?;
        let start_time_ticks = parse_start_time(&stat)?;
        let user_slots = parse_slots(&status, "Uid:", "status_uid")?;
        let group_slots = parse_slots(&status, "Gid:", "status_gid")?;
        let host_supplementary_gids = parse_groups(&status)?;
        let cgroups = parse_cgroups(&cgroup)?;
        let uid_map = parse_id_map(&uid_map, "uid_map")?;
        let gid_map = parse_id_map(&gid_map, "gid_map")?;
        let namespaces = read_namespaces(&directory.join("ns"))?;
        let (executable_digest, executable_object, executable_file) =
            read_executable(&directory.join("exe"))?;
        let systemd = systemd_from_cgroups(&cgroups)?;
        Ok((
            ProcessObservation {
                start_time_ticks,
                host_uids: user_slots,
                host_gids: group_slots,
                host_supplementary_gids,
                executable_digest,
                executable_object,
                namespaces,
                cgroups,
                uid_map,
                gid_map,
                systemd,
            },
            executable_file,
        ))
    }
}

fn read_bounded(
    path: &Path,
    limit: u64,
    field: &'static str,
) -> Result<String, ProcessEvidenceError> {
    let mut file = File::open(path).map_err(|_| ProcessEvidenceError::unavailable(field))?;
    let metadata = file
        .metadata()
        .map_err(|_| ProcessEvidenceError::unavailable(field))?;
    if metadata.len() > limit {
        return Err(ProcessEvidenceError::unavailable(field));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ProcessEvidenceError::unavailable(field))?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > limit) {
        return Err(ProcessEvidenceError::unavailable(field));
    }
    String::from_utf8(bytes).map_err(|_| ProcessEvidenceError::unavailable(field))
}

fn parse_start_time(stat: &str) -> Result<u64, ProcessEvidenceError> {
    let (_, fields) = stat
        .rsplit_once(") ")
        .ok_or_else(|| ProcessEvidenceError::unavailable("stat"))?;
    fields
        .split_ascii_whitespace()
        .nth(19)
        .and_then(|value| value.parse().ok())
        .filter(|value| *value != 0)
        .ok_or_else(|| ProcessEvidenceError::unavailable("stat"))
}

fn parse_slots(
    status: &str,
    prefix: &str,
    field: &'static str,
) -> Result<CredentialSlots, ProcessEvidenceError> {
    let line = status
        .lines()
        .find(|line| line.starts_with(prefix))
        .ok_or_else(|| ProcessEvidenceError::unavailable(field))?;
    let values = line
        .split_ascii_whitespace()
        .skip(1)
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ProcessEvidenceError::unavailable(field))?;
    let [real, effective, saved, filesystem] = values.as_slice() else {
        return Err(ProcessEvidenceError::unavailable(field));
    };
    Ok(CredentialSlots {
        real: *real,
        effective: *effective,
        saved: *saved,
        filesystem: *filesystem,
    })
}

fn parse_groups(status: &str) -> Result<Vec<u32>, ProcessEvidenceError> {
    let line = status
        .lines()
        .find(|line| line.starts_with("Groups:"))
        .ok_or_else(|| ProcessEvidenceError::unavailable("status_groups"))?;
    let mut groups = line
        .split_ascii_whitespace()
        .skip(1)
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ProcessEvidenceError::unavailable("status_groups"))?;
    groups.sort_unstable();
    groups.dedup();
    Ok(groups)
}

fn parse_cgroups(raw: &str) -> Result<Vec<String>, ProcessEvidenceError> {
    let mut groups = raw
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    if groups.is_empty() || groups.iter().any(|line| line.contains('\0')) {
        return Err(ProcessEvidenceError::unavailable("cgroups"));
    }
    groups.sort();
    groups.dedup();
    Ok(groups)
}

fn parse_id_map(raw: &str, field: &'static str) -> Result<Vec<IdMapRange>, ProcessEvidenceError> {
    let mut ranges = Vec::new();
    for line in raw.lines() {
        let values = line
            .split_ascii_whitespace()
            .map(str::parse::<u32>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ProcessEvidenceError::unavailable(field))?;
        let [inside, outside, length] = values.as_slice() else {
            return Err(ProcessEvidenceError::unavailable(field));
        };
        if *length == 0 || ranges.len() >= MAX_ID_MAP_RANGES {
            return Err(ProcessEvidenceError::unsupported(field));
        }
        let range = IdMapRange {
            inside: *inside,
            outside: *outside,
            length: *length,
        };
        let inside_end = u64::from(range.inside) + u64::from(range.length);
        let outside_end = u64::from(range.outside) + u64::from(range.length);
        if inside_end > u64::from(u32::MAX) + 1 || outside_end > u64::from(u32::MAX) + 1 {
            return Err(ProcessEvidenceError::unsupported(field));
        }
        ranges.push(range);
    }
    if ranges.is_empty() {
        return Err(ProcessEvidenceError::unsupported(field));
    }
    for (index, left) in ranges.iter().enumerate() {
        if ranges.iter().skip(index + 1).any(|right| {
            ranges_overlap(left.inside, left.length, right.inside, right.length)
                || ranges_overlap(left.outside, left.length, right.outside, right.length)
        }) {
            return Err(ProcessEvidenceError::mismatch(field));
        }
    }
    Ok(ranges)
}

fn ranges_overlap(first: u32, first_length: u32, second: u32, second_length: u32) -> bool {
    let first_start = u64::from(first);
    let first_end = first_start + u64::from(first_length);
    let second_start = u64::from(second);
    let second_end = second_start + u64::from(second_length);
    first_start < second_end && second_start < first_end
}

fn read_namespaces(directory: &Path) -> Result<NamespaceInodes, ProcessEvidenceError> {
    Ok(NamespaceInodes {
        user: read_namespace(directory, "user")?,
        pid: read_namespace(directory, "pid")?,
        mount: read_namespace(directory, "mnt")?,
        network: read_namespace(directory, "net")?,
        ipc: read_namespace(directory, "ipc")?,
        uts: read_namespace(directory, "uts")?,
    })
}

fn read_namespace(directory: &Path, name: &'static str) -> Result<u64, ProcessEvidenceError> {
    let target = fs::read_link(directory.join(name))
        .map_err(|_| ProcessEvidenceError::unavailable("namespaces"))?;
    let target = target.to_string_lossy();
    target
        .strip_suffix(']')
        .and_then(|value| value.rsplit_once('['))
        .and_then(|(_, inode)| inode.parse().ok())
        .filter(|inode| *inode != 0)
        .ok_or_else(|| ProcessEvidenceError::unavailable("namespaces"))
}

fn read_executable(
    path: &Path,
) -> Result<(String, ExecutableObjectId, File), ProcessEvidenceError> {
    let mut file = File::open(path).map_err(|_| ProcessEvidenceError::unavailable("executable"))?;
    let before = file
        .metadata()
        .map_err(|_| ProcessEvidenceError::unavailable("executable"))?;
    if !before.is_file() || before.len() > MAX_EXECUTABLE_BYTES {
        return Err(ProcessEvidenceError::unsupported("executable"));
    }
    let mut hasher = Sha256::new();
    let copied = io::copy(&mut (&mut file).take(MAX_EXECUTABLE_BYTES + 1), &mut hasher)
        .map_err(|_| ProcessEvidenceError::unavailable("executable"))?;
    if copied > MAX_EXECUTABLE_BYTES {
        return Err(ProcessEvidenceError::unsupported("executable"));
    }
    let after = file
        .metadata()
        .map_err(|_| ProcessEvidenceError::unavailable("executable"))?;
    let before_id = ExecutableObjectId::from_metadata(&before);
    let after_id = ExecutableObjectId::from_metadata(&after);
    if before_id != after_id || copied != after.len() {
        return Err(ProcessEvidenceError::unavailable("executable"));
    }
    Ok((format!("sha256:{:x}", hasher.finalize()), after_id, file))
}

fn systemd_from_cgroups(
    cgroups: &[String],
) -> Result<Option<SystemdEvidence>, ProcessEvidenceError> {
    let mut found: Option<SystemdEvidence> = None;
    for line in cgroups {
        let Some((_, path)) = line.rsplit_once(':') else {
            return Err(ProcessEvidenceError::unavailable("cgroups"));
        };
        let manager_user = path.split('/').find_map(|component| {
            component
                .strip_prefix("user-")
                .and_then(|value| value.strip_suffix(".slice"))
                .and_then(|value| value.parse::<u32>().ok())
        });
        for component in path
            .split('/')
            .filter(|component| component.ends_with(".service"))
        {
            if component.starts_with("user@") || component == "init.scope" {
                continue;
            }
            let template = component.find('@').map(|at| {
                let mut value = component.to_string();
                value.replace_range(at + 1..value.len() - ".service".len(), "");
                value
            });
            let candidate = SystemdEvidence {
                unit: component.to_string(),
                template,
                manager_user,
            };
            if found
                .as_ref()
                .is_some_and(|existing| existing != &candidate)
            {
                return Err(ProcessEvidenceError::mismatch("systemd"));
            }
            found = Some(candidate);
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;
    use std::time::{SystemTime, UNIX_EPOCH};

    use proptest::prelude::*;

    use super::*;

    fn object(inode: u64) -> ExecutableObjectId {
        ExecutableObjectId {
            device: 1,
            inode,
            size: 10,
            ctime_seconds: 1,
            ctime_nanoseconds: 0,
            mtime_seconds: 1,
            mtime_nanoseconds: 0,
        }
    }

    fn namespaces() -> NamespaceInodes {
        NamespaceInodes {
            user: 1,
            pid: 2,
            mount: 3,
            network: 4,
            ipc: 5,
            uts: 6,
        }
    }

    fn observation(start: u64) -> ProcessObservation {
        ProcessObservation {
            start_time_ticks: start,
            host_uids: CredentialSlots::uniform(100_800),
            host_gids: CredentialSlots::uniform(100_800),
            host_supplementary_gids: vec![100_800, 100_900],
            executable_digest: "sha256:old".to_string(),
            executable_object: object(7),
            namespaces: namespaces(),
            cgroups: vec!["0::/user.slice/example.scope".to_string()],
            uid_map: vec![IdMapRange {
                inside: 0,
                outside: 100_000,
                length: 65_536,
            }],
            gid_map: vec![IdMapRange {
                inside: 0,
                outside: 100_000,
                length: 65_536,
            }],
            systemd: None,
        }
    }

    fn peer() -> PeerCredentials {
        PeerCredentials {
            pid: 42,
            uid: 100_800,
            gid: 100_800,
        }
    }

    #[test]
    fn pid_reuse_never_refreshes_a_pin() {
        let mut pin = PinnedProcess::capture_observation(peer(), observation(10)).unwrap();
        let error = pin.revalidate_observation(observation(11)).unwrap_err();
        assert_eq!(error.kind, ProcessEvidenceFailureKind::Mismatch);
        assert_eq!(error.field, "pid_start_time");
    }

    #[test]
    fn credentials_refresh_in_caller_namespace_and_mapping_stays_pinned() {
        let mut pin = PinnedProcess::capture_observation(peer(), observation(10)).unwrap();
        let mut changed = observation(10);
        changed.host_uids.effective = 100_801;
        pin.revalidate_observation(changed).unwrap();
        assert_eq!(
            pin.process_evidence().uids,
            EvidenceValue::Available(CredentialSlots {
                real: 800,
                effective: 801,
                saved: 800,
                filesystem: 800,
            })
        );
        assert_eq!(pin.caller_peer_uid(), 800);
        assert_eq!(pin.host_peer_uid(), 100_800);
    }

    #[test]
    fn overlapping_or_changed_maps_fail_closed() {
        let mut bad = observation(10);
        bad.uid_map.push(IdMapRange {
            inside: 800,
            outside: 100_800,
            length: 1,
        });
        assert_eq!(
            PinnedProcess::capture_observation(peer(), bad)
                .unwrap_err()
                .kind,
            ProcessEvidenceFailureKind::Mismatch
        );

        let mut pin = PinnedProcess::capture_observation(peer(), observation(10)).unwrap();
        let mut changed = observation(10);
        changed.uid_map[0].inside = 1;
        assert_eq!(
            pin.revalidate_observation(changed).unwrap_err().field,
            "caller_host_mapping"
        );
    }

    #[test]
    fn exec_replacement_refreshes_digest_but_namespace_or_cgroup_movement_denies() {
        let mut pin = PinnedProcess::capture_observation(peer(), observation(10)).unwrap();
        let mut exec = observation(10);
        exec.executable_object = object(8);
        exec.executable_digest = "sha256:new".to_string();
        pin.revalidate_observation(exec).unwrap();
        assert_eq!(
            pin.process_evidence().executable_digest,
            EvidenceValue::Available("sha256:new".to_string())
        );

        let mut moved = observation(10);
        moved.cgroups = vec!["0::/other.scope".to_string()];
        assert_eq!(
            pin.revalidate_observation(moved).unwrap_err().field,
            "cgroups"
        );
    }

    #[test]
    fn most_specific_resolution_never_falls_back() {
        let systemd = SystemdEvidence {
            unit: "web.service".to_string(),
            template: None,
            manager_user: None,
        };
        let container = resolve_domain(DomainResolutionEvidence {
            container: DomainEvidence::Verified("container-id"),
            systemd: DomainEvidence::Verified(systemd.clone()),
            host: DomainEvidence::Verified(()),
        })
        .unwrap();
        assert_eq!(container, ResolvedDomain::Container("container-id"));

        for more_specific in [
            DomainEvidence::<&str>::Unsupported,
            DomainEvidence::Unavailable,
            DomainEvidence::Mismatch,
        ] {
            assert!(
                resolve_domain(DomainResolutionEvidence {
                    container: more_specific,
                    systemd: DomainEvidence::Verified(systemd.clone()),
                    host: DomainEvidence::Verified(()),
                })
                .is_err()
            );
        }
    }

    #[test]
    fn nspawn_and_sandbox_indications_are_typed_unsupported() {
        for host in [DomainEvidence::Unsupported, DomainEvidence::Absent] {
            assert_eq!(
                resolve_domain::<()>(DomainResolutionEvidence {
                    container: DomainEvidence::Absent,
                    systemd: DomainEvidence::Absent,
                    host,
                }),
                Err(DomainResolutionError::Unsupported)
            );
        }
    }

    #[test]
    fn fake_procfs_pins_executable_object_not_mutable_nix_profile_path() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("basil-procfs-{suffix}"));
        let process = root.join("42");
        fs::create_dir_all(process.join("ns")).unwrap();
        fs::write(
            process.join("stat"),
            format!("42 (fake process) S {} 10\n", "0 ".repeat(18)),
        )
        .unwrap();
        fs::write(
            process.join("status"),
            "Uid:\t100800\t100800\t100800\t100800\nGid:\t100800\t100800\t100800\t100800\nGroups:\t100800 100900\n",
        )
        .unwrap();
        fs::write(process.join("cgroup"), "0::/user.slice/example.scope\n").unwrap();
        fs::write(process.join("uid_map"), "0 100000 65536\n").unwrap();
        fs::write(process.join("gid_map"), "0 100000 65536\n").unwrap();
        for (name, inode) in [
            ("user", 1),
            ("pid", 2),
            ("mnt", 3),
            ("net", 4),
            ("ipc", 5),
            ("uts", 6),
        ] {
            symlink(format!("{name}:[{inode}]"), process.join("ns").join(name)).unwrap();
        }
        let store_one = root.join("nix-store-one");
        let store_two = root.join("nix-store-two");
        fs::write(&store_one, b"first executable").unwrap();
        fs::write(&store_two, b"second executable").unwrap();
        symlink(&store_one, process.join("exe")).unwrap();
        let profile = root.join("current-program");
        symlink(&store_one, &profile).unwrap();

        let procfs = LinuxProcfs::new(&root);
        let mut pin = procfs.capture(peer()).unwrap();
        fs::remove_file(&profile).unwrap();
        symlink(&store_two, &profile).unwrap();
        procfs.revalidate(&mut pin).unwrap();
        assert_eq!(
            pin.process_evidence().executable_digest,
            EvidenceValue::Available(format!("sha256:{:x}", Sha256::digest(b"first executable")))
        );
        fs::remove_dir_all(root).unwrap();
    }

    proptest! {
        #[test]
        fn arbitrary_start_time_change_cannot_preserve_authority(first in 1_u64..u64::MAX, second in 1_u64..u64::MAX) {
            prop_assume!(first != second);
            let mut pin = PinnedProcess::capture_observation(peer(), observation(first)).unwrap();
            let error = pin.revalidate_observation(observation(second)).unwrap_err();
            prop_assert_eq!(error.kind, ProcessEvidenceFailureKind::Mismatch);
        }
    }
}
