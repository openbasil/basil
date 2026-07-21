// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Production host integrations for the measurement helper.
//!
//! - [`KernelPeerPidfdSource`] acquires the peer pidfd with the
//!   `SO_PEERPIDFD` socket option via the bounded
//!   [`peer_pidfd`](super::peer_pidfd) module (kernel 6.5+). There is no
//!   fallback: on kernels without the option every measurement fails closed
//!   with [`PeerPidfdError::Unsupported`], because substituting
//!   `pidfd_open(SO_PEERCRED.pid)` would weaken the accepted revision-1.2
//!   contract's race-free peer binding.
//! - [`SystemdUnitResolver`] is a fail-closed placeholder: it must resolve
//!   `GetUnitByPIDFD` on the system D-Bus, and the workspace carries no
//!   D-Bus client. Until the bounded transport lands (`basil-vww7`) the
//!   resolver returns [`UnitResolveError::Unavailable`].
//!
//! [`ProcfsProcessInspector`] and [`ProcExecutableOpener`] are real:
//! identity comes from `/proc/<pid>/status` and `/proc/<pid>/stat`, and the
//! executable from `/proc/<pid>/exe` (which requires the helper's
//! `CAP_SYS_PTRACE` for cross-UID peers).
//!
//! # Lockdown-profile confinement evidence
//!
//! `Seccomp: 2` alone is insufficient evidence of the configured post-init
//! lockdown profile, and the kernel exposes no lockdown-profile *identity*
//! at all. The contract therefore derives the identity from **protected
//! installation evidence plus live process state**:
//!
//! 1. The live LSM label is read from `/proc/<pid>/attr/current` and
//!    canonicalized (`selinux:<type>` for a `SELinux` context,
//!    `apparmor:<profile>` for an enforcing `AppArmor` profile). The label is
//!    kernel-assigned; the peer cannot forge it.
//! 2. The **installed authority manifests** — immutable root-owned files the
//!    external authority installation transaction (`basil-q5we`) installs —
//!    bind that exact generation-qualified LSM identity to the generation's
//!    `lockdownProfile` identity. Every binding is checked at load
//!    (`ident::embeds_exact_generation`), so a stale or wrong-generation
//!    manifest can never vouch for a candidate label.
//! 3. Live process state must corroborate that a post-init filter is
//!    actually installed: `/proc/<pid>/status` must report `Seccomp: 2`
//!    (a seccomp *filter*, not strict mode) and `NoNewPrivs: 1`.
//!
//! Only when all three hold does the inspector report the manifest's
//! lockdown identity. Anything unprovable reports the non-identity markers
//! [`UNPROVEN_LSM_PROFILE`] / [`UNPROVEN_LOCKDOWN_PROFILE`], which by
//! construction never equal a validated installed expectation, so the
//! service rejects realm-scoped with `ConfinementMismatch`. A store that
//! cannot be trusted at all (missing directory, wrong owner, malformed or
//! ambiguous manifest) is an outage-equivalent host failure and returns
//! [`InspectError::Unavailable`] (`PeerDerivationFailed`-class), exactly as
//! the contract requires.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::io::Read;
use std::num::NonZeroU64;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};

use rustix::fs::{Dir, FileType, Mode, OFlags};
use serde::Deserialize;

use super::ident;
use super::service::{
    ConfinementFacts, ExecutableError, ExecutableOpener, InspectError, PeerPidfdError,
    PeerPidfdSource, ProcessIdentity, ProcessInspector, ResolvedUnit, UnitResolveError,
    UnitResolver,
};

/// Maximum bytes read from one procfs evidence file.
const MAX_PROCFS_BYTES: usize = 64 * 1024;

/// Production default directory of installed authority manifests.
///
/// Sibling of the helper allowlist default (`/etc/basil/measure/policy.d`);
/// the external authority installation transaction installs one immutable
/// root-owned manifest file per realm generation here.
pub const DEFAULT_MANIFEST_DIRECTORY: &str = "/etc/basil/measure/manifest.d";
/// Maximum installed authority-manifest files in one directory.
pub const MAX_INSTALLED_MANIFESTS: usize = 64;
/// Maximum bytes in one authority-manifest file.
pub const MAX_MANIFEST_FILE_BYTES: usize = 64 * 1024;
/// Exact `schema` value of an installed authority-manifest file.
pub const MANIFEST_SCHEMA: &str = "basil-authority-manifest";
/// Exact `schemaVersion` value of an installed authority-manifest file.
pub const MANIFEST_SCHEMA_VERSION: u32 = 1;

/// Marker reported when the live LSM profile cannot be proven.
///
/// Deliberately fails `ident::is_valid_identity` (leading `:`), so it can
/// never equal a validated installed expectation: the comparison in the
/// service fails closed as a realm-scoped `ConfinementMismatch`.
pub const UNPROVEN_LSM_PROFILE: &str = ":unproven-lsm";
/// Marker reported when no lockdown profile is proven for the peer.
///
/// Same non-identity construction as [`UNPROVEN_LSM_PROFILE`].
pub const UNPROVEN_LOCKDOWN_PROFILE: &str = ":unproven-lockdown";

/// Production source for the peer pidfd (`SO_PEERPIDFD`, kernel 6.5+).
///
/// Fail-closed on kernels without the option: the accepted contract
/// requires the kernel's `SO_PEERPIDFD`, not a PID-derived pidfd.
#[derive(Clone, Copy, Debug, Default)]
pub struct KernelPeerPidfdSource;

impl PeerPidfdSource for KernelPeerPidfdSource {
    fn peer_pidfd(&self, stream: BorrowedFd<'_>) -> Result<OwnedFd, PeerPidfdError> {
        super::peer_pidfd::acquire(stream)
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

/// Location and trust requirements of the installed authority-manifest
/// evidence store.
///
/// Production keeps the defaults: [`DEFAULT_MANIFEST_DIRECTORY`] owned by
/// root. Tests and unprivileged development hosts substitute a directory
/// they own.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityManifestOptions {
    /// Directory of installed root-owned authority manifests.
    pub directory: PathBuf,
    /// Exact owner UID required for the directory and every manifest file.
    pub required_owner_uid: u32,
}

impl Default for AuthorityManifestOptions {
    fn default() -> Self {
        Self {
            directory: PathBuf::from(DEFAULT_MANIFEST_DIRECTORY),
            required_owner_uid: 0,
        }
    }
}

/// Procfs-backed process identity inspector.
///
/// Confinement evidence consumes the production-default authority-manifest
/// store ([`AuthorityManifestOptions::default`]); use
/// [`ManifestEvidenceInspector`] to name an explicit store.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProcfsProcessInspector;

impl ProcessInspector for ProcfsProcessInspector {
    fn identity(&self, pid: u32, _pidfd: BorrowedFd<'_>) -> Result<ProcessIdentity, InspectError> {
        procfs_identity(pid)
    }

    fn confinement(
        &self,
        pid: u32,
        _pidfd: BorrowedFd<'_>,
    ) -> Result<ConfinementFacts, InspectError> {
        manifest_confinement(pid, &AuthorityManifestOptions::default())
    }
}

/// Procfs inspector over an explicit installed-manifest evidence store.
///
/// Identity facts are identical to [`ProcfsProcessInspector`]; confinement
/// evidence is derived from the named store instead of the production
/// default. The store is re-read per measurement, so manifests installed
/// additively during authority overlap become visible without a restart.
#[derive(Clone, Debug)]
pub struct ManifestEvidenceInspector {
    options: AuthorityManifestOptions,
}

impl ManifestEvidenceInspector {
    /// Build an inspector over an explicit evidence store.
    #[must_use]
    pub const fn new(options: AuthorityManifestOptions) -> Self {
        Self { options }
    }
}

impl ProcessInspector for ManifestEvidenceInspector {
    fn identity(&self, pid: u32, _pidfd: BorrowedFd<'_>) -> Result<ProcessIdentity, InspectError> {
        procfs_identity(pid)
    }

    fn confinement(
        &self,
        pid: u32,
        _pidfd: BorrowedFd<'_>,
    ) -> Result<ConfinementFacts, InspectError> {
        manifest_confinement(pid, &self.options)
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

/// Read the peer's stable identity (UID/GID/start time) from procfs.
fn procfs_identity(pid: u32) -> Result<ProcessIdentity, InspectError> {
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

/// Derive the peer's confinement facts from the installed authority
/// manifests plus live process state.
///
/// Store failures are outage-equivalent ([`InspectError::Unavailable`]);
/// unprovable facts are reported as the non-identity markers so the
/// service's exact comparison rejects realm-scoped.
fn manifest_confinement(
    pid: u32,
    options: &AuthorityManifestOptions,
) -> Result<ConfinementFacts, InspectError> {
    let manifests = AuthorityManifests::load_dir(&options.directory, options.required_owner_uid)?;
    // Read `status` first so a vanished peer reports `PeerVanished` rather
    // than an unproven-label mismatch.
    let status = read_proc_file(pid, "status")?;
    let raw_label = read_lsm_attr(pid);
    Ok(confinement_evidence(
        &manifests,
        raw_label.as_deref(),
        &status,
    ))
}

/// One parsed installed authority-manifest file.
///
/// The subset of the staged authority manifest the helper consumes as
/// confinement evidence, spelled exactly as the installation transaction
/// pinned it. Field names are camelCase on disk (`authorityGeneration`,
/// `serviceUnit`, `lsmProfile`, `lockdownProfile`).
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ManifestFile {
    schema: String,
    schema_version: u32,
    realm: String,
    authority_generation: u64,
    service_unit: String,
    lsm_profile: String,
    lockdown_profile: String,
}

/// The loaded installed authority-manifest evidence set: the exact
/// generation-qualified LSM identity of each installed generation mapped to
/// the lockdown-profile identity it vouches for.
#[derive(Debug, Default)]
struct AuthorityManifests {
    lockdown_by_lsm: BTreeMap<String, String>,
}

impl AuthorityManifests {
    /// Load every installed manifest from a protected directory.
    ///
    /// The directory and each file are opened without following symlinks,
    /// must be owned by `required_owner_uid`, and must carry no group or
    /// other write bit. Any unexpected entry, bound violation, binding
    /// mismatch, or ambiguous duplicate rejects the whole load as
    /// [`InspectError::Unavailable`] — an outage-equivalent host failure.
    fn load_dir(directory: &Path, required_owner_uid: u32) -> Result<Self, InspectError> {
        let dir_fd = rustix::fs::open(
            directory,
            OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::RDONLY,
            Mode::empty(),
        )
        .map_err(|_| InspectError::Unavailable)?;
        let dir_stat = rustix::fs::fstat(&dir_fd).map_err(|_| InspectError::Unavailable)?;
        if !exclusively_owned(&dir_stat, required_owner_uid) {
            return Err(InspectError::Unavailable);
        }

        let mut names = Vec::new();
        let mut reader = Dir::read_from(&dir_fd).map_err(|_| InspectError::Unavailable)?;
        for entry in reader.by_ref() {
            let entry = entry.map_err(|_| InspectError::Unavailable)?;
            let name_bytes = entry.file_name().to_bytes();
            if name_bytes == b"." || name_bytes == b".." {
                continue;
            }
            let name =
                String::from_utf8(name_bytes.to_vec()).map_err(|_| InspectError::Unavailable)?;
            names.push(name);
        }
        if names.len() > MAX_INSTALLED_MANIFESTS {
            return Err(InspectError::Unavailable);
        }
        names.sort_unstable();

        let mut lockdown_by_lsm: BTreeMap<String, String> = BTreeMap::new();
        for name in names {
            let (lsm_profile, lockdown_profile) =
                load_manifest_file(&dir_fd, &name, required_owner_uid)?;
            match lockdown_by_lsm.entry(lsm_profile) {
                // Two manifests may share one LSM identity (multiple realms
                // on one profile) only when they vouch for the same lockdown
                // identity; a conflicting duplicate is ambiguous evidence.
                Entry::Occupied(existing) if existing.get() != &lockdown_profile => {
                    return Err(InspectError::Unavailable);
                }
                Entry::Occupied(_) => {}
                Entry::Vacant(slot) => {
                    slot.insert(lockdown_profile);
                }
            }
        }
        Ok(Self { lockdown_by_lsm })
    }

    /// The lockdown identity the installed evidence vouches for, if any.
    fn lockdown_for(&self, lsm_profile: &str) -> Option<&str> {
        self.lockdown_by_lsm.get(lsm_profile).map(String::as_str)
    }
}

/// Whether `stat` names the required owner with no group/other write bit.
const fn exclusively_owned(stat: &rustix::fs::Stat, required_owner: u32) -> bool {
    let group_or_other_write = 0o022;
    stat.st_uid == required_owner && (stat.st_mode & group_or_other_write) == 0
}

/// Open, bound-read, parse, and validate one manifest file.
fn load_manifest_file(
    dir_fd: &rustix::fd::OwnedFd,
    name: &str,
    required_owner_uid: u32,
) -> Result<(String, String), InspectError> {
    let Some(stem) = name.strip_suffix(".toml") else {
        return Err(InspectError::Unavailable);
    };
    let file_fd = rustix::fs::openat(
        dir_fd,
        name,
        OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::RDONLY,
        Mode::empty(),
    )
    .map_err(|_| InspectError::Unavailable)?;
    let stat = rustix::fs::fstat(&file_fd).map_err(|_| InspectError::Unavailable)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || !exclusively_owned(&stat, required_owner_uid)
    {
        return Err(InspectError::Unavailable);
    }

    let mut file = std::fs::File::from(file_fd);
    let mut bytes = Vec::new();
    let limit = u64::try_from(MAX_MANIFEST_FILE_BYTES).unwrap_or(u64::MAX);
    file.by_ref()
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| InspectError::Unavailable)?;
    if bytes.len() > MAX_MANIFEST_FILE_BYTES {
        return Err(InspectError::Unavailable);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| InspectError::Unavailable)?;
    let parsed: ManifestFile = toml::from_str(text).map_err(|_| InspectError::Unavailable)?;
    validate_manifest(stem, &parsed).ok_or(InspectError::Unavailable)
}

/// Validate one parsed manifest against the checked generation binding and
/// the `<realm>-g<generation>.toml` file-name binding.
fn validate_manifest(stem: &str, parsed: &ManifestFile) -> Option<(String, String)> {
    if parsed.schema != MANIFEST_SCHEMA || parsed.schema_version != MANIFEST_SCHEMA_VERSION {
        return None;
    }
    if !ident::is_valid_realm_name(&parsed.realm) {
        return None;
    }
    let generation = NonZeroU64::new(parsed.authority_generation)?;
    let suffix = format!("-g{generation}");
    let realm_part = stem.strip_suffix(suffix.as_str())?;
    if realm_part != parsed.realm {
        return None;
    }
    if !ident::is_valid_service_unit(&parsed.service_unit)
        || !ident::unit_has_generation_suffix(&parsed.service_unit, generation.get())
        || !ident::embeds_exact_generation(
            parsed.service_unit.trim_end_matches(".service"),
            generation.get(),
        )
    {
        return None;
    }
    if !ident::is_valid_identity(&parsed.lsm_profile)
        || !ident::embeds_exact_generation(&parsed.lsm_profile, generation.get())
    {
        return None;
    }
    if !ident::is_valid_identity(&parsed.lockdown_profile)
        || !ident::embeds_exact_generation(&parsed.lockdown_profile, generation.get())
    {
        return None;
    }
    Some((parsed.lsm_profile.clone(), parsed.lockdown_profile.clone()))
}

/// Live post-init lockdown state parsed from `/proc/<pid>/status`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LiveLockdownState {
    /// `Seccomp: 2` — a seccomp *filter* is installed (not strict mode).
    seccomp_filter: bool,
    /// `NoNewPrivs: 1`.
    no_new_privs: bool,
}

impl LiveLockdownState {
    /// Whether live state corroborates an installed post-init filter.
    const fn proves_post_init_lockdown(self) -> bool {
        self.seccomp_filter && self.no_new_privs
    }
}

/// Parse the live lockdown corroboration fields from a `status` text.
fn parse_status_lockdown(status: &str) -> LiveLockdownState {
    let mut state = LiveLockdownState {
        seccomp_filter: false,
        no_new_privs: false,
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Seccomp:") {
            state.seccomp_filter = rest.trim() == "2";
        } else if let Some(rest) = line.strip_prefix("NoNewPrivs:") {
            state.no_new_privs = rest.trim() == "1";
        }
    }
    state
}

/// Canonicalize a raw `/proc/<pid>/attr/current` label.
///
/// A `SELinux` context (`user:role:type:…`) canonicalizes to
/// `selinux:<type>`; an *enforcing* `AppArmor` profile (`<profile> (enforce)`)
/// canonicalizes to `apparmor:<profile>`. Anything else — `unconfined`, a
/// complain-mode profile, a path-named profile, garbage — is unprovable and
/// returns `None`.
fn canonical_lsm_label(raw: &str) -> Option<String> {
    let trimmed = raw.trim_end_matches(['\0', '\n']);
    if let Some(profile) = trimmed.strip_suffix(" (enforce)") {
        let candidate = format!("apparmor:{profile}");
        return ident::is_valid_identity(&candidate).then_some(candidate);
    }
    let mut fields = trimmed.split(':');
    let (_user, _role) = (fields.next()?, fields.next()?);
    let type_field = fields.next()?;
    if type_field.is_empty() {
        return None;
    }
    let candidate = format!("selinux:{type_field}");
    ident::is_valid_identity(&candidate).then_some(candidate)
}

/// Derive confinement facts from loaded evidence plus live process state.
///
/// Pure so every manifest-present/absent/stale/wrong-generation and
/// live-state combination is unit-testable without a confined process.
fn confinement_evidence(
    manifests: &AuthorityManifests,
    raw_label: Option<&str>,
    status: &str,
) -> ConfinementFacts {
    let Some(label) = raw_label.and_then(canonical_lsm_label) else {
        return ConfinementFacts {
            lsm_profile: UNPROVEN_LSM_PROFILE.to_owned(),
            lockdown_profile: UNPROVEN_LOCKDOWN_PROFILE.to_owned(),
        };
    };
    let live = parse_status_lockdown(status);
    let lockdown_profile = if live.proves_post_init_lockdown() {
        manifests
            .lockdown_for(&label)
            .map_or_else(|| UNPROVEN_LOCKDOWN_PROFILE.to_owned(), ToOwned::to_owned)
    } else {
        // `Seccomp: 2` (or its absence) without the full live corroboration
        // proves nothing, whatever the manifests say.
        UNPROVEN_LOCKDOWN_PROFILE.to_owned()
    };
    ConfinementFacts {
        lsm_profile: label,
        lockdown_profile,
    }
}

/// Read the raw LSM label of `pid`, if any.
///
/// Every failure other than a vanished peer (which the preceding `status`
/// read already detected) reports "no label": unprovable, never trusted.
fn read_lsm_attr(pid: u32) -> Option<String> {
    let path = PathBuf::from(format!("/proc/{pid}/attr/current"));
    let fd = rustix::fs::open(
        &path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .ok()?;
    let mut file = std::fs::File::from(fd);
    let mut bytes = Vec::new();
    let limit = u64::try_from(MAX_PROCFS_BYTES).unwrap_or(u64::MAX);
    file.by_ref().take(limit).read_to_end(&mut bytes).ok()?;
    String::from_utf8(bytes).ok()
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
    use std::os::unix::fs::PermissionsExt;

    use super::super::allowlist::{AllowlistPart, InstalledAllowlist, RealmExpectation};
    use super::super::service::{HelperOutcome, HelperService};
    use super::super::transport::ReceivedDatagram;
    use super::super::wire::{
        HELPER_PROTOCOL_VERSION, MeasurementRequest, NONCE_BYTES, RejectCode,
    };
    use super::*;

    const REALM: &str = "production-docker";
    const POLICY: &str = "basil-measure-policy-g1";
    const UNIT: &str = "basil-attestor-production-docker-g1.service";
    const LSM: &str = "selinux:basil_attestor_g1_t";
    const LOCKDOWN: &str = "basil-attestor-lockdown-g1";
    const LIVE_LABEL: &str = "system_u:system_r:basil_attestor_g1_t:s0\0";
    const STATUS_CONFINED: &str =
        "Name:\tattestor\nNoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t1\n";
    const STATUS_SECCOMP_ONLY: &str = "NoNewPrivs:\t0\nSeccomp:\t2\n";
    const STATUS_UNCONFINED: &str = "NoNewPrivs:\t0\nSeccomp:\t0\n";

    const GOOD_MANIFEST: &str = r#"
schema = "basil-authority-manifest"
schemaVersion = 1
realm = "production-docker"
authorityGeneration = 1
serviceUnit = "basil-attestor-production-docker-g1.service"
lsmProfile = "selinux:basil_attestor_g1_t"
lockdownProfile = "basil-attestor-lockdown-g1"
"#;
    const GOOD_MANIFEST_NAME: &str = "production-docker-g1.toml";

    fn own_uid() -> u32 {
        rustix::process::getuid().as_raw()
    }

    fn self_pidfd() -> OwnedFd {
        rustix::process::pidfd_open(
            rustix::process::getpid(),
            rustix::process::PidfdFlags::empty(),
        )
        .expect("pidfd_open self")
    }

    /// Minimal private tempdir helper (no tempfile dev-dependency).
    mod tempdir {
        use std::path::PathBuf;
        use std::sync::atomic::{AtomicU64, Ordering};

        pub struct TempDirHandle {
            pub path: PathBuf,
        }

        impl Drop for TempDirHandle {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }

        pub fn write_dir(files: &[(&str, &str)]) -> TempDirHandle {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "basil-authority-manifests-{}-{unique}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).expect("create temp dir");
            for (name, contents) in files {
                std::fs::write(path.join(name), contents).expect("write manifest file");
            }
            TempDirHandle { path }
        }
    }

    fn write_store(files: &[(&str, &str)]) -> tempdir::TempDirHandle {
        tempdir::write_dir(files)
    }

    fn load_store(dir: &Path) -> Result<AuthorityManifests, InspectError> {
        AuthorityManifests::load_dir(dir, own_uid())
    }

    // --- canonical label and live-state parsing ---

    #[test]
    fn canonicalizes_lsm_labels() {
        assert_eq!(
            canonical_lsm_label(LIVE_LABEL).as_deref(),
            Some("selinux:basil_attestor_g1_t")
        );
        assert_eq!(
            canonical_lsm_label("basil-attestor-g1 (enforce)\n").as_deref(),
            Some("apparmor:basil-attestor-g1")
        );
        // Complain mode proves nothing.
        assert_eq!(canonical_lsm_label("basil-attestor-g1 (complain)\n"), None);
        // Path-named AppArmor profiles are not canonical identities.
        assert_eq!(canonical_lsm_label("/usr/bin/foo (enforce)\n"), None);
        assert_eq!(canonical_lsm_label("unconfined\n"), None);
        assert_eq!(canonical_lsm_label(""), None);
        // A context with an empty type field is not evidence.
        assert_eq!(canonical_lsm_label("a:b::s0"), None);
    }

    #[test]
    fn live_state_requires_filter_and_no_new_privs() {
        assert!(parse_status_lockdown(STATUS_CONFINED).proves_post_init_lockdown());
        // `Seccomp: 2` alone is insufficient by contract.
        assert!(!parse_status_lockdown(STATUS_SECCOMP_ONLY).proves_post_init_lockdown());
        assert!(!parse_status_lockdown(STATUS_UNCONFINED).proves_post_init_lockdown());
        // Strict mode is not a post-init filter.
        assert!(
            !parse_status_lockdown("NoNewPrivs:\t1\nSeccomp:\t1\n").proves_post_init_lockdown()
        );
        assert!(!parse_status_lockdown("").proves_post_init_lockdown());
    }

    // --- manifest store loading ---

    #[test]
    fn loads_a_valid_manifest_store() {
        let dir = write_store(&[(GOOD_MANIFEST_NAME, GOOD_MANIFEST)]);
        let store = load_store(&dir.path).expect("load");
        assert_eq!(store.lockdown_for(LSM), Some(LOCKDOWN));
        assert_eq!(store.lockdown_for("selinux:other_g1_t"), None);
    }

    #[test]
    fn duplicate_lsm_identities_must_agree() {
        // A second realm sharing the LSM identity and lockdown is fine.
        let other = GOOD_MANIFEST
            .replace("realm = \"production-docker\"", "realm = \"other-realm\"")
            .replace(
                "basil-attestor-production-docker-g1.service",
                "basil-attestor-other-realm-g1.service",
            );
        let dir = write_store(&[
            (GOOD_MANIFEST_NAME, GOOD_MANIFEST),
            ("other-realm-g1.toml", &other),
        ]);
        assert!(load_store(&dir.path).is_ok());

        // A conflicting lockdown identity for the same LSM identity is
        // ambiguous evidence: the whole store fails closed.
        let conflicting = other.replace(
            "lockdownProfile = \"basil-attestor-lockdown-g1\"",
            "lockdownProfile = \"basil-other-lockdown-g1\"",
        );
        let dir = write_store(&[
            (GOOD_MANIFEST_NAME, GOOD_MANIFEST),
            ("other-realm-g1.toml", &conflicting),
        ]);
        assert_eq!(
            load_store(&dir.path).unwrap_err(),
            InspectError::Unavailable
        );
    }

    #[test]
    fn rejects_manifest_binding_violations() {
        for (mutation, replacement) in [
            // Wrong-generation binding: LSM identity names g2, manifest g1.
            (
                "lsmProfile = \"selinux:basil_attestor_g1_t\"",
                "lsmProfile = \"selinux:basil_attestor_g2_t\"",
            ),
            // Lockdown identity loses its qualifier.
            (
                "lockdownProfile = \"basil-attestor-lockdown-g1\"",
                "lockdownProfile = \"basil-attestor-lockdown\"",
            ),
            // Unit names a foreign generation.
            (
                "serviceUnit = \"basil-attestor-production-docker-g1.service\"",
                "serviceUnit = \"basil-attestor-production-docker-g2.service\"",
            ),
            // Zero generation.
            ("authorityGeneration = 1", "authorityGeneration = 0"),
            // Unknown field.
            (
                "authorityGeneration = 1",
                "authorityGeneration = 1\nextra = 1",
            ),
            // Wrong schema version.
            ("schemaVersion = 1", "schemaVersion = 2"),
        ] {
            let mutated = GOOD_MANIFEST.replace(mutation, replacement);
            let dir = write_store(&[(GOOD_MANIFEST_NAME, &mutated)]);
            assert_eq!(
                load_store(&dir.path).unwrap_err(),
                InspectError::Unavailable,
                "expected rejection for `{replacement}`"
            );
        }
    }

    #[test]
    fn rejects_file_name_binding_and_untrusted_files() {
        // File name must equal `<realm>-g<generation>`.
        let dir = write_store(&[("production-docker-g2.toml", GOOD_MANIFEST)]);
        assert!(load_store(&dir.path).is_err());
        let dir = write_store(&[("other-realm-g1.toml", GOOD_MANIFEST)]);
        assert!(load_store(&dir.path).is_err());
        // Non-manifest entries reject.
        let dir = write_store(&[("README", "not a manifest")]);
        assert!(load_store(&dir.path).is_err());
        // Wrong owner rejects.
        let dir = write_store(&[(GOOD_MANIFEST_NAME, GOOD_MANIFEST)]);
        assert!(AuthorityManifests::load_dir(&dir.path, own_uid().wrapping_add(1)).is_err());
        // A group-writable manifest rejects.
        let file = dir.path.join(GOOD_MANIFEST_NAME);
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o664))
            .expect("chmod manifest");
        assert!(load_store(&dir.path).is_err());
    }

    // --- evidence derivation (pure pipeline) ---

    #[test]
    fn manifest_present_with_live_corroboration_proves_lockdown() {
        let dir = write_store(&[(GOOD_MANIFEST_NAME, GOOD_MANIFEST)]);
        let store = load_store(&dir.path).expect("load");
        let facts = confinement_evidence(&store, Some(LIVE_LABEL), STATUS_CONFINED);
        assert_eq!(facts.lsm_profile, LSM);
        assert_eq!(facts.lockdown_profile, LOCKDOWN);
    }

    #[test]
    fn manifest_absent_or_live_state_insufficient_stays_unproven() {
        let empty = write_store(&[]);
        let store = load_store(&empty.path).expect("load empty");
        // Absent manifest: the label is live but nothing vouches for a
        // lockdown identity.
        let facts = confinement_evidence(&store, Some(LIVE_LABEL), STATUS_CONFINED);
        assert_eq!(facts.lsm_profile, LSM);
        assert_eq!(facts.lockdown_profile, UNPROVEN_LOCKDOWN_PROFILE);

        // Present manifest but `Seccomp: 2` without `NoNewPrivs`.
        let dir = write_store(&[(GOOD_MANIFEST_NAME, GOOD_MANIFEST)]);
        let store = load_store(&dir.path).expect("load");
        let facts = confinement_evidence(&store, Some(LIVE_LABEL), STATUS_SECCOMP_ONLY);
        assert_eq!(facts.lockdown_profile, UNPROVEN_LOCKDOWN_PROFILE);

        // No label at all: both facts are unproven markers.
        let facts = confinement_evidence(&store, None, STATUS_CONFINED);
        assert_eq!(facts.lsm_profile, UNPROVEN_LSM_PROFILE);
        assert_eq!(facts.lockdown_profile, UNPROVEN_LOCKDOWN_PROFILE);
    }

    #[test]
    fn unproven_markers_are_never_valid_identities() {
        assert!(!ident::is_valid_identity(UNPROVEN_LSM_PROFILE));
        assert!(!ident::is_valid_identity(UNPROVEN_LOCKDOWN_PROFILE));
    }

    // --- real-process inspectors ---

    #[test]
    fn reads_own_identity_from_procfs() {
        let pid = std::process::id();
        let pidfd = self_pidfd();
        let identity = ProcfsProcessInspector
            .identity(pid, pidfd.as_fd())
            .expect("identity");
        assert_eq!(identity.uid, rustix::process::getuid().as_raw());
        assert_eq!(identity.gid, rustix::process::getgid().as_raw());
        assert!(identity.start_time_ticks > 0);
    }

    #[test]
    fn identity_reports_a_vanished_peer() {
        let pidfd = self_pidfd();
        // PID 0 never exists in procfs.
        assert_eq!(
            ProcfsProcessInspector.identity(0, pidfd.as_fd()),
            Err(InspectError::PeerVanished)
        );
    }

    #[test]
    fn opens_own_executable() {
        let pid = std::process::id();
        let pidfd = self_pidfd();
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
    fn kernel_source_acquires_the_connected_peer_pidfd() {
        let (a, _b) = rustix::net::socketpair(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::STREAM,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        )
        .expect("socketpair");
        // The peer of a socketpair end is this test process; the production
        // source must return a live pidfd for it on kernel 6.5+.
        let pidfd = KernelPeerPidfdSource
            .peer_pidfd(a.as_fd())
            .expect("SO_PEERPIDFD supported");
        let identity = ProcfsProcessInspector
            .identity(std::process::id(), pidfd.as_fd())
            .expect("identity");
        assert_eq!(identity.uid, rustix::process::geteuid().as_raw());
    }

    #[test]
    fn unit_resolver_placeholder_fails_closed() {
        let (a, _b) = rustix::net::socketpair(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::STREAM,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        )
        .expect("socketpair");
        assert_eq!(
            SystemdUnitResolver.unit_by_pidfd(a.as_fd()).unwrap_err(),
            UnitResolveError::Unavailable
        );
    }

    #[test]
    fn missing_manifest_store_is_outage_equivalent() {
        let pidfd = self_pidfd();
        let inspector = ManifestEvidenceInspector::new(AuthorityManifestOptions {
            directory: PathBuf::from("/nonexistent/basil-authority-manifests"),
            required_owner_uid: own_uid(),
        });
        assert_eq!(
            inspector
                .confinement(std::process::id(), pidfd.as_fd())
                .unwrap_err(),
            InspectError::Unavailable
        );
    }

    #[test]
    fn live_self_process_never_proves_a_lockdown_profile() {
        // The test process is not the confined attestor: even with a valid
        // installed store, its lockdown fact must stay unproven.
        let dir = write_store(&[(GOOD_MANIFEST_NAME, GOOD_MANIFEST)]);
        let pidfd = self_pidfd();
        let inspector = ManifestEvidenceInspector::new(AuthorityManifestOptions {
            directory: dir.path.clone(),
            required_owner_uid: own_uid(),
        });
        let facts = inspector
            .confinement(std::process::id(), pidfd.as_fd())
            .expect("confinement");
        assert_eq!(facts.lockdown_profile, UNPROVEN_LOCKDOWN_PROFILE);
    }

    #[test]
    fn parses_stat_with_hostile_comm() {
        let stat = "1234 (a) b) R 1 1 1 0 -1 4194560 1 0 0 0 0 0 0 0 20 0 1 0 987654 1000 1 18446744073709551615";
        assert_eq!(parse_stat_start_time(stat), Some(987_654));
    }

    // --- helper conformance: confinement evidence through the service ---

    struct FakePeerSource;

    impl PeerPidfdSource for FakePeerSource {
        fn peer_pidfd(&self, _stream: BorrowedFd<'_>) -> Result<OwnedFd, PeerPidfdError> {
            rustix::process::pidfd_open(
                rustix::process::getpid(),
                rustix::process::PidfdFlags::empty(),
            )
            .map_err(|_| PeerPidfdError::Io)
        }
    }

    struct FakeUnitResolver {
        unit: String,
    }

    impl UnitResolver for FakeUnitResolver {
        fn unit_by_pidfd(&self, _pidfd: BorrowedFd<'_>) -> Result<ResolvedUnit, UnitResolveError> {
            Ok(ResolvedUnit {
                unit: self.unit.clone(),
            })
        }
    }

    struct FakeExecutableOpener;

    impl ExecutableOpener for FakeExecutableOpener {
        fn open_executable(
            &self,
            _pid: u32,
            _pidfd: BorrowedFd<'_>,
        ) -> Result<OwnedFd, ExecutableError> {
            rustix::fs::open(
                "/proc/self/exe",
                OFlags::RDONLY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| ExecutableError::Io)
        }
    }

    /// Inspector exercising the real store loader and the real evidence
    /// pipeline over fixed raw procfs texts (only the per-PID reads are
    /// substituted; a test process cannot present a confined label).
    struct FixtureEvidenceInspector {
        directory: PathBuf,
        label: Option<&'static str>,
        status: &'static str,
    }

    impl ProcessInspector for FixtureEvidenceInspector {
        fn identity(
            &self,
            pid: u32,
            pidfd: BorrowedFd<'_>,
        ) -> Result<ProcessIdentity, InspectError> {
            ProcfsProcessInspector.identity(pid, pidfd)
        }

        fn confinement(
            &self,
            _pid: u32,
            _pidfd: BorrowedFd<'_>,
        ) -> Result<ConfinementFacts, InspectError> {
            let manifests = AuthorityManifests::load_dir(&self.directory, own_uid())?;
            Ok(confinement_evidence(&manifests, self.label, self.status))
        }
    }

    fn expectation(generation: u64) -> RealmExpectation {
        RealmExpectation {
            authority_generation: NonZeroU64::new(generation).expect("nonzero"),
            service_unit: UNIT.replace("-g1", &format!("-g{generation}")),
            attestor_uid: own_uid(),
            lsm_profile: LSM.replace("_g1_", &format!("_g{generation}_")),
            lockdown_profile: LOCKDOWN.replace("-g1", &format!("-g{generation}")),
        }
    }

    fn allowlist(generation: u64) -> InstalledAllowlist {
        let part: AllowlistPart = (
            POLICY.replace("-g1", &format!("-g{generation}")),
            NonZeroU64::new(generation).expect("nonzero"),
            vec![(REALM.to_owned(), expectation(generation))],
        );
        InstalledAllowlist::from_parts(vec![part])
    }

    fn request(generation: u64) -> MeasurementRequest {
        MeasurementRequest {
            protocol: HELPER_PROTOCOL_VERSION,
            broker_generation: 7,
            policy_generation: NonZeroU64::new(generation).expect("nonzero"),
            nonce: [3u8; NONCE_BYTES],
            realm: REALM.to_owned(),
            policy_identity: POLICY.replace("-g1", &format!("-g{generation}")),
        }
    }

    fn valid_datagram(stream: BorrowedFd<'_>, generation: u64) -> ReceivedDatagram {
        ReceivedDatagram {
            bytes: request(generation).encode().expect("encode"),
            descriptors: vec![stream.try_clone_to_owned().expect("dup")],
            oversized: false,
            ancillary_truncated: false,
        }
    }

    fn evidence_service<I: ProcessInspector>(
        generation: u64,
        inspector: I,
    ) -> HelperService<FakePeerSource, FakeUnitResolver, I, FakeExecutableOpener> {
        HelperService::new(
            allowlist(generation),
            FakePeerSource,
            FakeUnitResolver {
                unit: UNIT.replace("-g1", &format!("-g{generation}")),
            },
            inspector,
            FakeExecutableOpener,
        )
    }

    fn stream_end() -> OwnedFd {
        let (end, _peer) = rustix::net::socketpair(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::STREAM,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        )
        .expect("stream socketpair");
        end
    }

    fn expect_reject(outcome: &HelperOutcome, code: RejectCode) {
        match outcome {
            HelperOutcome::Rejected(rejection) => assert_eq!(rejection.code, code),
            HelperOutcome::Measured { .. } => panic!("expected rejection {code:?}"),
        }
    }

    #[test]
    fn service_measures_with_present_manifest_evidence() {
        let dir = write_store(&[(GOOD_MANIFEST_NAME, GOOD_MANIFEST)]);
        let service = evidence_service(
            1,
            FixtureEvidenceInspector {
                directory: dir.path.clone(),
                label: Some(LIVE_LABEL),
                status: STATUS_CONFINED,
            },
        );
        let stream = stream_end();
        match service.handle(valid_datagram(stream.as_fd(), 1)) {
            HelperOutcome::Measured { record, .. } => {
                assert_eq!(record.service_unit, UNIT);
                assert_eq!(record.peer_uid, own_uid());
            }
            HelperOutcome::Rejected(rejection) => {
                panic!("expected measurement, got {:?}", rejection.code)
            }
        }
    }

    #[test]
    fn service_rejects_absent_manifest_as_confinement_mismatch() {
        let empty = write_store(&[]);
        let service = evidence_service(
            1,
            FixtureEvidenceInspector {
                directory: empty.path.clone(),
                label: Some(LIVE_LABEL),
                status: STATUS_CONFINED,
            },
        );
        let stream = stream_end();
        expect_reject(
            &service.handle(valid_datagram(stream.as_fd(), 1)),
            RejectCode::ConfinementMismatch,
        );
    }

    #[test]
    fn service_rejects_stale_manifest_generation_as_confinement_mismatch() {
        // The authority moved to generation 2 (expectations, unit, live
        // label) but the store still holds only the old g1 manifest: the g2
        // lockdown identity is unproven and the realm rejects.
        let stale = write_store(&[(GOOD_MANIFEST_NAME, GOOD_MANIFEST)]);
        let service = evidence_service(
            2,
            FixtureEvidenceInspector {
                directory: stale.path.clone(),
                label: Some("system_u:system_r:basil_attestor_g2_t:s0\0"),
                status: STATUS_CONFINED,
            },
        );
        let stream = stream_end();
        expect_reject(
            &service.handle(valid_datagram(stream.as_fd(), 2)),
            RejectCode::ConfinementMismatch,
        );
    }

    #[test]
    fn service_rejects_wrong_generation_manifest_as_derivation_failure() {
        // A manifest whose LSM identity names a foreign generation violates
        // the checked binding: the store is untrustworthy, outage-equivalent.
        let wrong = GOOD_MANIFEST.replace(
            "lsmProfile = \"selinux:basil_attestor_g1_t\"",
            "lsmProfile = \"selinux:basil_attestor_g2_t\"",
        );
        let dir = write_store(&[(GOOD_MANIFEST_NAME, &wrong)]);
        let service = evidence_service(
            1,
            FixtureEvidenceInspector {
                directory: dir.path.clone(),
                label: Some(LIVE_LABEL),
                status: STATUS_CONFINED,
            },
        );
        let stream = stream_end();
        expect_reject(
            &service.handle(valid_datagram(stream.as_fd(), 1)),
            RejectCode::PeerDerivationFailed,
        );
    }

    #[test]
    fn service_rejects_seccomp_alone_as_confinement_mismatch() {
        let dir = write_store(&[(GOOD_MANIFEST_NAME, GOOD_MANIFEST)]);
        let service = evidence_service(
            1,
            FixtureEvidenceInspector {
                directory: dir.path.clone(),
                label: Some(LIVE_LABEL),
                status: STATUS_SECCOMP_ONLY,
            },
        );
        let stream = stream_end();
        expect_reject(
            &service.handle(valid_datagram(stream.as_fd(), 1)),
            RejectCode::ConfinementMismatch,
        );
    }

    #[test]
    fn service_rejects_unconfined_live_peer_via_real_inspector() {
        // Full-pipeline conformance: a real (unconfined) peer process under
        // the manifest-backed inspector can never satisfy the confinement
        // expectation, whatever the installed store says.
        let dir = write_store(&[(GOOD_MANIFEST_NAME, GOOD_MANIFEST)]);
        let service = evidence_service(
            1,
            ManifestEvidenceInspector::new(AuthorityManifestOptions {
                directory: dir.path.clone(),
                required_owner_uid: own_uid(),
            }),
        );
        let stream = stream_end();
        expect_reject(
            &service.handle(valid_datagram(stream.as_fd(), 1)),
            RejectCode::ConfinementMismatch,
        );
    }
}
