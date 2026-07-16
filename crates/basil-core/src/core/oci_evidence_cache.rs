// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Bounded same-machine cache for public OCI verification evidence.
//!
//! Cache bytes are untrusted input. Every lookup calls a current-generation
//! local validator before returning evidence. Policy, trust-root, and denylist
//! decisions are deliberately absent from the on-disk format.

use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, File};
use std::io::{Read as _, Seek as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use base64::Engine as _;
use rustix::fs::{RenameFlags, renameat_with};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use super::oci_verification::OciDigest;

/// Default aggregate encoded cache size.
pub const DEFAULT_CACHE_BYTES: u64 = 512 * 1024 * 1024;
/// Default maximum number of cache entries.
pub const DEFAULT_CACHE_ENTRIES: usize = 10_000;
/// Non-configurable maximum encoded size of one entry.
pub const MAX_ENCODED_ENTRY_BYTES: u64 = 4 * 1024 * 1024;
/// Maximum configurable aggregate encoded cache size.
pub const MAX_CONFIGURED_CACHE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
/// Maximum configurable entry count, bounding every directory walk.
pub const MAX_CONFIGURED_CACHE_ENTRIES: usize = 100_000;
/// Age after which admitted evidence should be refreshed in the background.
pub const REFRESH_AFTER: Duration = Duration::from_secs(30 * 24 * 60 * 60);

const FORMAT_VERSION: u8 = 1;
const ALGORITHM_DIRECTORY: &str = "sha256";
const TOMBSTONE_DIRECTORY: &str = ".pruned";
const MAX_SOURCE_CONTEXT_BYTES: usize = 1024;
const MAX_REFERENCE_BYTES: usize = 1024;
const MAX_REFERENCES: usize = 64;
const MAX_EXTRA_TRAVERSAL_NODES: usize = 1024;

/// Persistent cache configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OciEvidenceCacheConfig {
    /// Absolute private cache directory.
    pub root: PathBuf,
    /// Maximum aggregate encoded bytes.
    pub max_bytes: u64,
    /// Maximum entry count.
    pub max_entries: usize,
}

impl OciEvidenceCacheConfig {
    /// Construct a configuration using the bounded defaults.
    #[must_use]
    pub const fn new(root: PathBuf) -> Self {
        Self {
            root,
            max_bytes: DEFAULT_CACHE_BYTES,
            max_entries: DEFAULT_CACHE_ENTRIES,
        }
    }
}

/// Stable content-derived cache entry identifier.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CacheEntryId(String);

impl CacheEntryId {
    /// Parse one lowercase SHA-256 entry identifier.
    pub fn parse(value: &str) -> Result<Self, OciEvidenceCacheError> {
        if is_lower_hex(value) {
            Ok(Self(value.to_owned()))
        } else {
            Err(OciEvidenceCacheError::InvalidInput)
        }
    }

    /// Return the whitespace-free identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CacheEntryId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Immutable context that prevents evidence replay across subjects or sources.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceContext {
    /// Immutable OCI subject digest.
    pub subject: OciDigest,
    /// Repository/source boundary used when collecting the evidence.
    pub source_context: String,
    /// Operator-facing immutable references associated with this evidence.
    pub references: BTreeSet<String>,
}

impl EvidenceContext {
    /// Validate all bounded context fields.
    pub fn validate(&self) -> Result<(), OciEvidenceCacheError> {
        if !bounded_printable(&self.source_context, MAX_SOURCE_CONTEXT_BYTES)
            || self.references.len() > MAX_REFERENCES
            || self
                .references
                .iter()
                .any(|reference| !bounded_printable(reference, MAX_REFERENCE_BYTES))
        {
            return Err(OciEvidenceCacheError::InvalidInput);
        }
        Ok(())
    }
}

/// Result of current-generation local evidence verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalEvidenceVerdict {
    /// Intrinsic evidence and the current authorization inputs admit it.
    Admit,
    /// Evidence is intrinsically valid but current policy, roots, or denylist reject it.
    Inactive,
    /// Intrinsic cryptography or immutable context is invalid.
    Corrupt,
}

/// Current-generation validator for untrusted cached evidence.
pub trait LocalEvidenceValidator {
    /// Validate complete evidence bytes against immutable context and current state.
    fn validate(&self, context: &EvidenceContext, evidence: &[u8]) -> LocalEvidenceVerdict;
}

impl<F> LocalEvidenceValidator for F
where
    F: Fn(&EvidenceContext, &[u8]) -> LocalEvidenceVerdict,
{
    fn validate(&self, context: &EvidenceContext, evidence: &[u8]) -> LocalEvidenceVerdict {
        self(context, evidence)
    }
}

/// Evidence refresh state derived from persisted timestamps.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceRefreshState {
    /// Evidence is within the refresh interval.
    Fresh,
    /// Evidence remains usable but should be refreshed in the background.
    Due {
        /// Seconds since the last successful collection.
        age_seconds: u64,
        /// First failed refresh time, when refresh has degraded.
        degraded_since: Option<u64>,
    },
}

/// One locally revalidated cache hit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachedEvidence {
    /// Content-derived cache identifier.
    pub id: CacheEntryId,
    /// Complete public verification evidence.
    pub evidence: Vec<u8>,
    /// Generation used for this local validation.
    pub generation: u64,
    /// Whether background collection should refresh the evidence.
    pub refresh: EvidenceRefreshState,
}

/// Bounded lookup result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheLookup {
    /// Evidence admitted by the current local validator.
    pub admitted: Vec<CachedEvidence>,
    /// Intrinsically valid entries rejected by current authorization inputs.
    pub inactive: usize,
    /// Corrupt entries removed during this lookup.
    pub corrupt_removed: usize,
}

/// Result of adding complete evidence to the bounded cache.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CacheStoreOutcome {
    /// Evidence was durably published under this identifier.
    Stored(CacheEntryId),
    /// Capacity was reached; existing usable evidence was left unchanged.
    AtCapacity,
}

/// Operator selector for preview-first pruning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PruneSelector {
    /// Select one exact cache identifier.
    Id(CacheEntryId),
    /// Select every entry carrying one exact immutable reference.
    Reference(String),
}

/// Public entry information used by check, doctor, and prune previews.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheEntryInfo {
    /// Content-derived identifier.
    pub id: CacheEntryId,
    /// Immutable subject digest.
    pub subject: OciDigest,
    /// Source context used for replay resistance.
    pub source_context: String,
    /// Associated immutable references.
    pub references: BTreeSet<String>,
    /// Encoded bytes charged to capacity.
    pub encoded_bytes: u64,
    /// Last cache use time.
    pub last_used: u64,
    /// First successful collection time.
    pub collected_at: u64,
    /// Last successful online collection or refresh time.
    pub last_successful_refresh: u64,
    /// Exact seconds since the last successful refresh.
    pub age_seconds: u64,
    /// Refresh threshold in seconds.
    pub refresh_threshold_seconds: u64,
    /// First continuously failed refresh time.
    pub degraded_since: Option<u64>,
    /// Exact continuous degradation duration in seconds.
    pub degraded_duration_seconds: Option<u64>,
    /// Whether the entry has reached its refresh threshold.
    pub refresh_due: bool,
    /// Refresh state.
    pub refresh: EvidenceRefreshState,
}

/// Read-only cache inspection result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheCheckReport {
    /// Valid entries sorted by identifier.
    pub entries: Vec<CacheEntryInfo>,
    /// Aggregate encoded bytes.
    pub total_bytes: u64,
    /// Corrupt regular files safely removed during inspection.
    pub corrupt_removed: usize,
}

/// Capacity and refresh health summary for doctor output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheDoctorReport {
    /// Current entry count.
    pub entry_count: usize,
    /// Configured entry limit.
    pub max_entries: usize,
    /// Current encoded byte count.
    pub total_bytes: u64,
    /// Configured encoded byte limit.
    pub max_bytes: u64,
    /// Entry-count pressure as a saturating percentage.
    pub entry_pressure_percent: u8,
    /// Encoded-byte pressure as a saturating percentage.
    pub byte_pressure_percent: u8,
    /// Whether either configured capacity limit is reached.
    pub at_capacity: bool,
    /// Entries currently due for refresh.
    pub refresh_due: usize,
    /// Due entries with at least one failed refresh.
    pub refresh_degraded: usize,
    /// Oldest exact evidence age in seconds.
    pub oldest_age_seconds: Option<u64>,
    /// Last successful refresh time of the oldest evidence.
    pub oldest_last_successful_refresh: Option<u64>,
    /// Fixed refresh threshold in seconds.
    pub refresh_threshold_seconds: u64,
    /// Longest current degraded duration in seconds.
    pub longest_degraded_duration_seconds: Option<u64>,
    /// Corrupt entries removed while gathering the report.
    pub corrupt_removed: usize,
}

/// Immutable prune preview. Execute only after an operator confirms it.
#[derive(Debug)]
pub struct CachePrunePlan {
    candidates: Vec<PruneCandidate>,
}

impl CachePrunePlan {
    /// Candidate entries in deterministic identifier order.
    #[must_use]
    pub fn entries(&self) -> Vec<CacheEntryInfo> {
        self.candidates
            .iter()
            .map(|candidate| candidate.info.clone())
            .collect()
    }

    /// Return whether the preview selected no entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }
}

/// Result of executing a previously generated prune preview.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CachePruneResult {
    /// Entries removed with unchanged file identity.
    pub removed: usize,
    /// Entries that changed or disappeared after preview.
    pub skipped: usize,
}

/// Disclosure-safe persistent cache failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum OciEvidenceCacheError {
    /// Configuration, context, selector, or identifier is invalid.
    #[error("OCI evidence cache input is invalid")]
    InvalidInput,
    /// Cache layout ownership, mode, type, or link count is unsafe.
    #[error("OCI evidence cache layout is unsafe")]
    UnsafeLayout,
    /// Cache I/O or lock state is unavailable.
    #[error("OCI evidence cache is unavailable")]
    Unavailable,
    /// Complete encoded evidence exceeds the fixed entry bound.
    #[error("OCI evidence cache entry exceeds its safety bound")]
    EntryTooLarge,
}

/// Private, bounded same-machine evidence cache.
#[derive(Debug)]
pub struct OciEvidenceCache {
    config: OciEvidenceCacheConfig,
    lock: Mutex<()>,
    process_lock: File,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DiskEntry {
    version: u8,
    id: String,
    subject: String,
    source_context: String,
    references: BTreeSet<String>,
    evidence: String,
    evidence_sha256: String,
    collected_at: u64,
    last_used: u64,
    last_refresh: u64,
    degraded_since: Option<u64>,
}

#[derive(Debug)]
struct LoadedEntry {
    disk: DiskEntry,
    context: EvidenceContext,
    evidence: Vec<u8>,
    path: PathBuf,
    identity: FileIdentity,
    encoded_bytes: u64,
    encoded_sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

struct ProcessLockGuard<'a>(&'a File);

struct TraversalBudget {
    remaining: usize,
}

struct LoadBudget {
    remaining_entries: usize,
    remaining_bytes: u64,
}

impl TraversalBudget {
    const fn new(limit: usize) -> Self {
        Self { remaining: limit }
    }

    fn consume(&mut self) -> Result<(), OciEvidenceCacheError> {
        self.remaining = self
            .remaining
            .checked_sub(1)
            .ok_or(OciEvidenceCacheError::UnsafeLayout)?;
        Ok(())
    }
}

impl LoadBudget {
    const fn new(maximum_entries: usize, maximum_bytes: u64) -> Self {
        Self {
            remaining_entries: maximum_entries,
            remaining_bytes: maximum_bytes,
        }
    }

    fn charge(&mut self, encoded_bytes: u64) -> Result<(), OciEvidenceCacheError> {
        self.remaining_entries = self
            .remaining_entries
            .checked_sub(1)
            .ok_or(OciEvidenceCacheError::UnsafeLayout)?;
        self.remaining_bytes = self
            .remaining_bytes
            .checked_sub(encoded_bytes)
            .ok_or(OciEvidenceCacheError::UnsafeLayout)?;
        Ok(())
    }
}

impl<'a> ProcessLockGuard<'a> {
    fn acquire(file: &'a File) -> Result<Self, OciEvidenceCacheError> {
        rustix::fs::flock(file, rustix::fs::FlockOperation::LockExclusive)
            .map_err(|_| OciEvidenceCacheError::Unavailable)?;
        Ok(Self(file))
    }
}

impl Drop for ProcessLockGuard<'_> {
    fn drop(&mut self) {
        let _ = rustix::fs::flock(self.0, rustix::fs::FlockOperation::Unlock);
    }
}

#[derive(Debug)]
struct PruneCandidate {
    info: CacheEntryInfo,
    path: PathBuf,
    identity: FileIdentity,
    encoded_sha256: [u8; 32],
}

pub(crate) struct UntrustedCachedEvidence {
    pub(crate) id: CacheEntryId,
    pub(crate) evidence: Vec<u8>,
    pub(crate) last_successful_refresh: u64,
    pub(crate) refresh: EvidenceRefreshState,
}

impl OciEvidenceCache {
    /// Open or create a private cache after validating all configured bounds.
    pub fn open(config: OciEvidenceCacheConfig) -> Result<Self, OciEvidenceCacheError> {
        validate_config(&config)?;
        ensure_cache_layout(&config.root)?;
        let process_lock = open_process_lock(&config.root)?;
        Ok(Self {
            config,
            lock: Mutex::new(()),
            process_lock,
        })
    }

    /// Open an existing cache without creating or changing any filesystem object.
    ///
    /// This is reserved for read-only diagnostic commands. Normal agent and
    /// cache operations should use [`Self::open`].
    pub fn open_existing_read_only(
        config: OciEvidenceCacheConfig,
    ) -> Result<Self, OciEvidenceCacheError> {
        validate_config(&config)?;
        validate_existing_cache_layout(&config.root)?;
        let process_lock = open_existing_process_lock(&config.root)?;
        Ok(Self {
            config,
            lock: Mutex::new(()),
            process_lock,
        })
    }

    /// Return the active bounded configuration.
    #[must_use]
    pub const fn config(&self) -> &OciEvidenceCacheConfig {
        &self.config
    }

    /// Durably store complete public evidence without evicting usable entries.
    pub fn store(
        &self,
        context: &EvidenceContext,
        evidence: &[u8],
        now: u64,
    ) -> Result<CacheStoreOutcome, OciEvidenceCacheError> {
        context.validate()?;
        if evidence.is_empty() {
            return Err(OciEvidenceCacheError::InvalidInput);
        }
        let _guard = self
            .lock
            .lock()
            .map_err(|_| OciEvidenceCacheError::Unavailable)?;
        let _process_guard = ProcessLockGuard::acquire(&self.process_lock)?;
        ensure_cache_layout(&self.config.root)?;

        let id = derive_entry_id(context, evidence);
        let path = self.entry_path(context.subject, &id);
        let existing = load_entry(&path, context.subject).ok();
        let mut references = context.references.clone();
        if let Some(entry) = &existing {
            references.extend(entry.context.references.iter().cloned());
        }
        if references.len() > MAX_REFERENCES {
            return Err(OciEvidenceCacheError::InvalidInput);
        }
        let disk = DiskEntry {
            version: FORMAT_VERSION,
            id: id.to_string(),
            subject: context.subject.to_string(),
            source_context: context.source_context.clone(),
            references,
            evidence: base64::engine::general_purpose::STANDARD.encode(evidence),
            evidence_sha256: lower_hex(&Sha256::digest(evidence)),
            collected_at: existing
                .as_ref()
                .map_or(now, |entry| entry.disk.collected_at),
            last_used: now,
            last_refresh: now,
            degraded_since: None,
        };
        let encoded = serde_json::to_vec(&disk).map_err(|_| OciEvidenceCacheError::Unavailable)?;
        let encoded_bytes =
            u64::try_from(encoded.len()).map_err(|_| OciEvidenceCacheError::EntryTooLarge)?;
        if encoded_bytes > MAX_ENCODED_ENTRY_BYTES {
            return Err(OciEvidenceCacheError::EntryTooLarge);
        }

        let scan = self.scan_locked(now, true)?;
        let old_bytes = existing.as_ref().map_or(0, |entry| entry.encoded_bytes);
        let new_count = scan.entries.len() + usize::from(existing.is_none());
        let new_bytes = scan
            .total_bytes
            .saturating_sub(old_bytes)
            .checked_add(encoded_bytes)
            .ok_or(OciEvidenceCacheError::InvalidInput)?;
        if new_count > self.config.max_entries || new_bytes > self.config.max_bytes {
            return Ok(CacheStoreOutcome::AtCapacity);
        }

        let directory = self.ensure_subject_directory(context.subject)?;
        atomic_write(&directory, &format!("{}.json", id.as_str()), &encoded)?;
        Ok(CacheStoreOutcome::Stored(id))
    }

    /// Revalidate matching cached evidence under the supplied current generation.
    pub fn lookup<V: LocalEvidenceValidator>(
        &self,
        subject: OciDigest,
        source_context: &str,
        generation: u64,
        now: u64,
        validator: &V,
    ) -> Result<CacheLookup, OciEvidenceCacheError> {
        if !bounded_printable(source_context, MAX_SOURCE_CONTEXT_BYTES) {
            return Err(OciEvidenceCacheError::InvalidInput);
        }
        let _guard = self
            .lock
            .lock()
            .map_err(|_| OciEvidenceCacheError::Unavailable)?;
        let _process_guard = ProcessLockGuard::acquire(&self.process_lock)?;
        ensure_cache_layout(&self.config.root)?;
        let mut admitted = Vec::new();
        let mut inactive = 0_usize;
        let mut corrupt_removed = 0_usize;
        for mut entry in self.scan_subject_locked(subject, now, &mut corrupt_removed, true)? {
            if entry.context.source_context != source_context {
                continue;
            }
            match validator.validate(&entry.context, &entry.evidence) {
                LocalEvidenceVerdict::Admit => {
                    entry.disk.last_used = now;
                    Self::rewrite_loaded(&entry)?;
                    admitted.push(CachedEvidence {
                        id: CacheEntryId::parse(&entry.disk.id)?,
                        evidence: entry.evidence,
                        generation,
                        refresh: refresh_state(&entry.disk, now),
                    });
                }
                LocalEvidenceVerdict::Inactive => inactive += 1,
                LocalEvidenceVerdict::Corrupt => {
                    corrupt_removed +=
                        usize::from(remove_if_identity(&entry.path, entry.identity)?);
                }
            }
        }
        admitted.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(CacheLookup {
            admitted,
            inactive,
            corrupt_removed,
        })
    }

    pub(crate) fn untrusted_candidates(
        &self,
        subject: OciDigest,
        source_context: &str,
        now: u64,
    ) -> Result<Vec<UntrustedCachedEvidence>, OciEvidenceCacheError> {
        if !bounded_printable(source_context, MAX_SOURCE_CONTEXT_BYTES) {
            return Err(OciEvidenceCacheError::InvalidInput);
        }
        let _guard = self
            .lock
            .lock()
            .map_err(|_| OciEvidenceCacheError::Unavailable)?;
        let _process_guard = ProcessLockGuard::acquire(&self.process_lock)?;
        let mut corrupt_removed = 0_usize;
        let mut candidates = self
            .scan_subject_locked(subject, now, &mut corrupt_removed, true)?
            .into_iter()
            .filter(|entry| entry.context.source_context == source_context)
            .map(|entry| {
                let refresh = refresh_state(&entry.disk, now);
                UntrustedCachedEvidence {
                    id: CacheEntryId(entry.disk.id),
                    evidence: entry.evidence,
                    last_successful_refresh: entry.disk.last_refresh,
                    refresh,
                }
            })
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            right
                .last_successful_refresh
                .cmp(&left.last_successful_refresh)
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(candidates)
    }

    pub(crate) fn touch_exact(
        &self,
        subject: OciDigest,
        id: &CacheEntryId,
        now: u64,
    ) -> Result<bool, OciEvidenceCacheError> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| OciEvidenceCacheError::Unavailable)?;
        let _process_guard = ProcessLockGuard::acquire(&self.process_lock)?;
        let path = self.entry_path(subject, id);
        let mut entry = match load_entry(&path, subject) {
            Ok(entry) => entry,
            Err(OciEvidenceCacheError::Unavailable) if !path.exists() => return Ok(false),
            Err(error) => return Err(error),
        };
        entry.disk.last_used = now;
        Self::rewrite_loaded(&entry)?;
        Ok(true)
    }

    pub(crate) fn remove_exact(
        &self,
        subject: OciDigest,
        id: &CacheEntryId,
    ) -> Result<bool, OciEvidenceCacheError> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| OciEvidenceCacheError::Unavailable)?;
        let _process_guard = ProcessLockGuard::acquire(&self.process_lock)?;
        let path = self.entry_path(subject, id);
        let entry = match load_entry(&path, subject) {
            Ok(entry) => entry,
            Err(OciEvidenceCacheError::Unavailable) if !path.exists() => return Ok(false),
            Err(error) => return Err(error),
        };
        remove_if_identity(&path, entry.identity)
    }

    /// Record the result of one background refresh attempt.
    ///
    /// A successful attempt advances the freshness timestamp. Failure records
    /// degradation without deleting or expiring locally valid evidence.
    pub fn record_refresh(
        &self,
        subject: OciDigest,
        id: &CacheEntryId,
        now: u64,
        succeeded: bool,
    ) -> Result<bool, OciEvidenceCacheError> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| OciEvidenceCacheError::Unavailable)?;
        let _process_guard = ProcessLockGuard::acquire(&self.process_lock)?;
        let path = self.entry_path(subject, id);
        match fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(_) => return Err(OciEvidenceCacheError::Unavailable),
        }
        let mut entry = match load_entry(&path, subject) {
            Ok(entry) => entry,
            Err(OciEvidenceCacheError::Unavailable) => {
                return Err(OciEvidenceCacheError::Unavailable);
            }
            Err(
                OciEvidenceCacheError::InvalidInput
                | OciEvidenceCacheError::UnsafeLayout
                | OciEvidenceCacheError::EntryTooLarge,
            ) => return Err(OciEvidenceCacheError::UnsafeLayout),
        };
        if succeeded {
            entry.disk.last_refresh = now;
            entry.disk.degraded_since = None;
        } else if entry.disk.degraded_since.is_none() {
            entry.disk.degraded_since = Some(now);
        }
        Self::rewrite_loaded(&entry)?;
        Ok(true)
    }

    /// Inspect entries, remove safely identified corruption, and report ages.
    pub fn check(&self, now: u64) -> Result<CacheCheckReport, OciEvidenceCacheError> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| OciEvidenceCacheError::Unavailable)?;
        let _process_guard = ProcessLockGuard::acquire(&self.process_lock)?;
        ensure_cache_layout(&self.config.root)?;
        self.scan_locked(now, true)
    }

    /// Summarize capacity pressure and stale or degraded evidence.
    pub fn doctor(&self, now: u64) -> Result<CacheDoctorReport, OciEvidenceCacheError> {
        let report = self.check(now)?;
        Ok(self.doctor_report(&report))
    }

    /// Inspect an existing cache for doctor output without modifying it.
    pub fn doctor_read_only(&self, now: u64) -> Result<CacheDoctorReport, OciEvidenceCacheError> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| OciEvidenceCacheError::Unavailable)?;
        let _process_guard = ProcessLockGuard::acquire(&self.process_lock)?;
        validate_existing_cache_layout(&self.config.root)?;
        let report = self.scan_locked(now, false)?;
        Ok(self.doctor_report(&report))
    }

    fn doctor_report(&self, report: &CacheCheckReport) -> CacheDoctorReport {
        let refresh_due = report
            .entries
            .iter()
            .filter(|entry| matches!(entry.refresh, EvidenceRefreshState::Due { .. }))
            .count();
        let refresh_degraded = report
            .entries
            .iter()
            .filter(|entry| {
                matches!(
                    entry.refresh,
                    EvidenceRefreshState::Due {
                        degraded_since: Some(_),
                        ..
                    }
                )
            })
            .count();
        CacheDoctorReport {
            entry_count: report.entries.len(),
            max_entries: self.config.max_entries,
            total_bytes: report.total_bytes,
            max_bytes: self.config.max_bytes,
            entry_pressure_percent: pressure_percent(
                u64::try_from(report.entries.len()).unwrap_or(u64::MAX),
                u64::try_from(self.config.max_entries).unwrap_or(u64::MAX),
            ),
            byte_pressure_percent: pressure_percent(report.total_bytes, self.config.max_bytes),
            at_capacity: report.entries.len() >= self.config.max_entries
                || report.total_bytes >= self.config.max_bytes,
            refresh_due,
            refresh_degraded,
            oldest_age_seconds: report.entries.iter().map(|entry| entry.age_seconds).max(),
            oldest_last_successful_refresh: report
                .entries
                .iter()
                .min_by_key(|entry| entry.last_successful_refresh)
                .map(|entry| entry.last_successful_refresh),
            refresh_threshold_seconds: REFRESH_AFTER.as_secs(),
            longest_degraded_duration_seconds: report
                .entries
                .iter()
                .filter_map(|entry| entry.degraded_duration_seconds)
                .max(),
            corrupt_removed: report.corrupt_removed,
        }
    }

    /// Produce a deterministic prune preview without changing the cache.
    pub fn plan_prune(
        &self,
        selectors: &[PruneSelector],
        now: u64,
    ) -> Result<CachePrunePlan, OciEvidenceCacheError> {
        if selectors.is_empty()
            || selectors.iter().any(|selector| {
                matches!(selector, PruneSelector::Reference(reference) if
                    !bounded_printable(reference, MAX_REFERENCE_BYTES))
            })
        {
            return Err(OciEvidenceCacheError::InvalidInput);
        }
        let _guard = self
            .lock
            .lock()
            .map_err(|_| OciEvidenceCacheError::Unavailable)?;
        let _process_guard = ProcessLockGuard::acquire(&self.process_lock)?;
        ensure_cache_layout(&self.config.root)?;
        let mut corrupt_removed = 0_usize;
        let loaded = self.load_all_locked(&mut corrupt_removed, true)?;
        let mut candidates = loaded
            .into_iter()
            .filter(|entry| {
                selectors.iter().any(|selector| match selector {
                    PruneSelector::Id(id) => entry.disk.id == id.as_str(),
                    PruneSelector::Reference(reference) => {
                        entry.context.references.contains(reference)
                    }
                })
            })
            .map(|entry| PruneCandidate {
                info: entry_info(&entry, now),
                path: entry.path,
                identity: entry.identity,
                encoded_sha256: entry.encoded_sha256,
            })
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| left.info.id.cmp(&right.info.id));
        Ok(CachePrunePlan { candidates })
    }

    /// Execute a confirmed preview without deleting entries changed since preview.
    pub fn execute_prune(
        &self,
        plan: CachePrunePlan,
    ) -> Result<CachePruneResult, OciEvidenceCacheError> {
        self.execute_prune_with_observer(plan, |_| {})
    }

    fn execute_prune_with_observer(
        &self,
        plan: CachePrunePlan,
        mut observer: impl FnMut(&Path),
    ) -> Result<CachePruneResult, OciEvidenceCacheError> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| OciEvidenceCacheError::Unavailable)?;
        let _process_guard = ProcessLockGuard::acquire(&self.process_lock)?;
        ensure_cache_layout(&self.config.root)?;
        let mut removed = 0_usize;
        let mut skipped = 0_usize;
        for candidate in plan.candidates {
            if retire_preview_candidate(
                &candidate.path,
                candidate.identity,
                candidate.encoded_sha256,
                &self.config.root,
                self.config.max_entries,
                &mut observer,
            )? {
                removed += 1;
            } else {
                skipped += 1;
            }
        }
        Ok(CachePruneResult { removed, skipped })
    }

    fn scan_locked(
        &self,
        now: u64,
        remove_corrupt: bool,
    ) -> Result<CacheCheckReport, OciEvidenceCacheError> {
        let mut corrupt_removed = 0_usize;
        let loaded = self.load_all_locked(&mut corrupt_removed, remove_corrupt)?;
        let total_bytes = loaded.iter().try_fold(0_u64, |total, entry| {
            total
                .checked_add(entry.encoded_bytes)
                .ok_or(OciEvidenceCacheError::InvalidInput)
        })?;
        let mut entries = loaded
            .iter()
            .map(|entry| entry_info(entry, now))
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(CacheCheckReport {
            entries,
            total_bytes,
            corrupt_removed,
        })
    }

    fn load_all_locked(
        &self,
        corrupt_removed: &mut usize,
        remove_corrupt: bool,
    ) -> Result<Vec<LoadedEntry>, OciEvidenceCacheError> {
        let algorithm_path = self.config.root.join(ALGORITHM_DIRECTORY);
        validate_private_directory(&algorithm_path)?;
        let traversal_limit = self
            .config
            .max_entries
            .checked_mul(2)
            .and_then(|limit| limit.checked_add(MAX_EXTRA_TRAVERSAL_NODES))
            .ok_or(OciEvidenceCacheError::InvalidInput)?;
        let mut budget = TraversalBudget::new(traversal_limit);
        let mut load_budget = LoadBudget::new(self.config.max_entries, self.config.max_bytes);
        let directories = read_directory_budgeted(&algorithm_path, &mut budget)?;
        let mut entries = Vec::new();
        for directory in directories {
            let file_name = directory.file_name();
            let name = file_name
                .to_str()
                .ok_or(OciEvidenceCacheError::UnsafeLayout)?;
            let subject = OciDigest::parse(&format!("sha256:{name}"))
                .map_err(|_| OciEvidenceCacheError::UnsafeLayout)?;
            validate_private_directory(&directory.path())?;
            entries.extend(self.scan_subject_with_budget(
                subject,
                corrupt_removed,
                remove_corrupt,
                &mut budget,
                &mut load_budget,
            )?);
        }
        Ok(entries)
    }

    fn scan_subject_locked(
        &self,
        subject: OciDigest,
        now: u64,
        corrupt_removed: &mut usize,
        remove_corrupt: bool,
    ) -> Result<Vec<LoadedEntry>, OciEvidenceCacheError> {
        let limit = self
            .config
            .max_entries
            .checked_add(MAX_EXTRA_TRAVERSAL_NODES)
            .ok_or(OciEvidenceCacheError::InvalidInput)?;
        let _ = now;
        self.scan_subject_with_budget(
            subject,
            corrupt_removed,
            remove_corrupt,
            &mut TraversalBudget::new(limit),
            &mut LoadBudget::new(self.config.max_entries, self.config.max_bytes),
        )
    }

    fn scan_subject_with_budget(
        &self,
        subject: OciDigest,
        corrupt_removed: &mut usize,
        remove_corrupt: bool,
        budget: &mut TraversalBudget,
        load_budget: &mut LoadBudget,
    ) -> Result<Vec<LoadedEntry>, OciEvidenceCacheError> {
        let path = self.subject_directory(subject);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => return Err(OciEvidenceCacheError::Unavailable),
        };
        validate_private_directory_metadata(&metadata)?;
        let paths = read_directory_budgeted(&path, budget)?;
        let mut loaded = Vec::new();
        for directory_entry in paths {
            let entry_path = directory_entry.path();
            let file_name = directory_entry.file_name();
            let name = file_name
                .to_str()
                .ok_or(OciEvidenceCacheError::UnsafeLayout)?;
            if name.starts_with(".tmp-") {
                match fs::symlink_metadata(&entry_path) {
                    Ok(metadata) => {
                        validate_cache_file_metadata(&metadata)?;
                        let pid = temporary_writer_pid(name)
                            .ok_or(OciEvidenceCacheError::UnsafeLayout)?;
                        if remove_corrupt
                            && rustix::process::test_kill_process(pid)
                                == Err(rustix::io::Errno::SRCH)
                        {
                            let identity = FileIdentity {
                                device: metadata.dev(),
                                inode: metadata.ino(),
                            };
                            *corrupt_removed +=
                                usize::from(remove_if_identity(&entry_path, identity)?);
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => return Err(OciEvidenceCacheError::Unavailable),
                }
                continue;
            }
            let Some(id) = name.strip_suffix(".json") else {
                return Err(OciEvidenceCacheError::UnsafeLayout);
            };
            if !is_lower_hex(id) {
                return Err(OciEvidenceCacheError::UnsafeLayout);
            }
            match load_entry_budgeted(&entry_path, subject, load_budget) {
                Ok(entry) => loaded.push(entry),
                Err(
                    error @ (OciEvidenceCacheError::UnsafeLayout
                    | OciEvidenceCacheError::Unavailable),
                ) => return Err(error),
                Err(OciEvidenceCacheError::InvalidInput | OciEvidenceCacheError::EntryTooLarge) => {
                    if !remove_corrupt {
                        return Err(OciEvidenceCacheError::InvalidInput);
                    }
                    if !remove_safe_regular(&entry_path)? {
                        return Err(OciEvidenceCacheError::UnsafeLayout);
                    }
                    *corrupt_removed += 1;
                }
            }
        }
        Ok(loaded)
    }

    fn rewrite_loaded(entry: &LoadedEntry) -> Result<(), OciEvidenceCacheError> {
        let encoded =
            serde_json::to_vec(&entry.disk).map_err(|_| OciEvidenceCacheError::Unavailable)?;
        if u64::try_from(encoded.len()).map_or(true, |size| size > MAX_ENCODED_ENTRY_BYTES) {
            return Err(OciEvidenceCacheError::EntryTooLarge);
        }
        let directory = entry
            .path
            .parent()
            .ok_or(OciEvidenceCacheError::UnsafeLayout)?;
        let name = entry
            .path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .ok_or(OciEvidenceCacheError::UnsafeLayout)?;
        validate_private_directory(directory)?;
        atomic_write(directory, name, &encoded)
    }

    fn entry_path(&self, subject: OciDigest, id: &CacheEntryId) -> PathBuf {
        self.subject_directory(subject)
            .join(format!("{}.json", id.as_str()))
    }

    fn subject_directory(&self, subject: OciDigest) -> PathBuf {
        let digest = subject.to_string();
        self.config
            .root
            .join(ALGORITHM_DIRECTORY)
            .join(digest.trim_start_matches("sha256:"))
    }

    fn ensure_subject_directory(
        &self,
        subject: OciDigest,
    ) -> Result<PathBuf, OciEvidenceCacheError> {
        let path = self.subject_directory(subject);
        create_or_validate_private_directory(&path)?;
        Ok(path)
    }
}

fn validate_config(config: &OciEvidenceCacheConfig) -> Result<(), OciEvidenceCacheError> {
    if !config.root.is_absolute()
        || config
            .root
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        || config.max_bytes == 0
        || config.max_bytes > MAX_CONFIGURED_CACHE_BYTES
        || config.max_entries == 0
        || config.max_entries > MAX_CONFIGURED_CACHE_ENTRIES
    {
        return Err(OciEvidenceCacheError::InvalidInput);
    }
    Ok(())
}

fn ensure_cache_layout(root: &Path) -> Result<(), OciEvidenceCacheError> {
    let parent = root.parent().ok_or(OciEvidenceCacheError::InvalidInput)?;
    validate_protected_parent(parent)?;
    if !root.exists() {
        create_private_directory(root)?;
    }
    validate_private_directory(root)?;
    create_or_validate_private_directory(&root.join(ALGORITHM_DIRECTORY))
}

fn validate_existing_cache_layout(root: &Path) -> Result<(), OciEvidenceCacheError> {
    let parent = root.parent().ok_or(OciEvidenceCacheError::InvalidInput)?;
    validate_protected_parent(parent)?;
    validate_private_directory(root)?;
    validate_private_directory(&root.join(ALGORITHM_DIRECTORY))
}

fn open_process_lock(root: &Path) -> Result<File, OciEvidenceCacheError> {
    validate_private_directory(root)?;
    let directory = open_absolute_directory_no_follow(root)?;
    let raw_file = rustix::fs::openat(
        directory,
        ".lock",
        rustix::fs::OFlags::RDWR
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::from_raw_mode(0o600),
    )
    .map_err(|_| OciEvidenceCacheError::UnsafeLayout)?;
    let file = File::from(raw_file);
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| OciEvidenceCacheError::Unavailable)?;
    let metadata = file
        .metadata()
        .map_err(|_| OciEvidenceCacheError::Unavailable)?;
    validate_cache_file_metadata(&metadata)?;
    Ok(file)
}

fn open_existing_process_lock(root: &Path) -> Result<File, OciEvidenceCacheError> {
    validate_private_directory(root)?;
    let directory = open_absolute_directory_no_follow(root)?;
    let raw_file = rustix::fs::openat(
        directory,
        ".lock",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| OciEvidenceCacheError::UnsafeLayout)?;
    let file = File::from(raw_file);
    let metadata = file
        .metadata()
        .map_err(|_| OciEvidenceCacheError::Unavailable)?;
    validate_cache_file_metadata(&metadata)?;
    Ok(file)
}

fn validate_protected_parent(path: &Path) -> Result<(), OciEvidenceCacheError> {
    let file = open_absolute_directory_no_follow(path)?;
    let metadata = file
        .metadata()
        .map_err(|_| OciEvidenceCacheError::Unavailable)?;
    let effective_uid = rustix::process::geteuid().as_raw();
    if !metadata.is_dir()
        || (metadata.uid() != 0 && metadata.uid() != effective_uid)
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.nlink() == 0
    {
        return Err(OciEvidenceCacheError::UnsafeLayout);
    }
    Ok(())
}

fn create_or_validate_private_directory(path: &Path) -> Result<(), OciEvidenceCacheError> {
    match fs::create_dir(path) {
        Ok(()) => {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .map_err(|_| OciEvidenceCacheError::Unavailable)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(OciEvidenceCacheError::Unavailable),
    }
    validate_private_directory(path)
}

fn create_private_directory(path: &Path) -> Result<(), OciEvidenceCacheError> {
    fs::create_dir(path).map_err(|_| OciEvidenceCacheError::Unavailable)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| OciEvidenceCacheError::Unavailable)
}

fn validate_private_directory(path: &Path) -> Result<(), OciEvidenceCacheError> {
    let file = open_absolute_directory_no_follow(path)?;
    let metadata = file
        .metadata()
        .map_err(|_| OciEvidenceCacheError::Unavailable)?;
    validate_private_directory_metadata(&metadata)
}

fn validate_private_directory_metadata(
    metadata: &fs::Metadata,
) -> Result<(), OciEvidenceCacheError> {
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o700
        || metadata.nlink() == 0
    {
        return Err(OciEvidenceCacheError::UnsafeLayout);
    }
    Ok(())
}

fn open_absolute_directory_no_follow(path: &Path) -> Result<File, OciEvidenceCacheError> {
    let relative = path
        .strip_prefix(Path::new("/"))
        .map_err(|_| OciEvidenceCacheError::InvalidInput)?;
    let mut directory = rustix::fs::open(
        "/",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| OciEvidenceCacheError::UnsafeLayout)?;
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(OciEvidenceCacheError::InvalidInput);
        };
        directory = rustix::fs::openat(
            &directory,
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| OciEvidenceCacheError::UnsafeLayout)?;
    }
    Ok(File::from(directory))
}

fn read_directory_budgeted(
    path: &Path,
    budget: &mut TraversalBudget,
) -> Result<Vec<fs::DirEntry>, OciEvidenceCacheError> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(path).map_err(|_| OciEvidenceCacheError::Unavailable)? {
        budget.consume()?;
        entries.push(entry.map_err(|_| OciEvidenceCacheError::Unavailable)?);
    }
    Ok(entries)
}

fn load_entry(
    path: &Path,
    expected_subject: OciDigest,
) -> Result<LoadedEntry, OciEvidenceCacheError> {
    load_entry_budgeted(
        path,
        expected_subject,
        &mut LoadBudget::new(1, MAX_ENCODED_ENTRY_BYTES),
    )
}

fn load_entry_budgeted(
    path: &Path,
    expected_subject: OciDigest,
    budget: &mut LoadBudget,
) -> Result<LoadedEntry, OciEvidenceCacheError> {
    let mut file = open_absolute_file_no_follow(path)?;
    let metadata = file
        .metadata()
        .map_err(|_| OciEvidenceCacheError::Unavailable)?;
    validate_cache_file_metadata(&metadata)?;
    if metadata.len() > MAX_ENCODED_ENTRY_BYTES {
        return Err(OciEvidenceCacheError::EntryTooLarge);
    }
    // Reserve both global ceilings before allocating, reading, or decoding any
    // attacker-controlled entry bytes. Charges are intentionally not refunded
    // for corrupt entries: a hostile tree must not gain additional allocation
    // attempts merely by failing validation late.
    budget.charge(metadata.len())?;
    let identity = FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    let mut encoded = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(MAX_ENCODED_ENTRY_BYTES + 1)
        .read_to_end(&mut encoded)
        .map_err(|_| OciEvidenceCacheError::Unavailable)?;
    if u64::try_from(encoded.len()).map_or(true, |size| size > MAX_ENCODED_ENTRY_BYTES) {
        return Err(OciEvidenceCacheError::EntryTooLarge);
    }
    let disk: DiskEntry =
        serde_json::from_slice(&encoded).map_err(|_| OciEvidenceCacheError::InvalidInput)?;
    let context = EvidenceContext {
        subject: OciDigest::parse(&disk.subject)
            .map_err(|_| OciEvidenceCacheError::InvalidInput)?,
        source_context: disk.source_context.clone(),
        references: disk.references.clone(),
    };
    context.validate()?;
    let evidence = base64::engine::general_purpose::STANDARD
        .decode(&disk.evidence)
        .map_err(|_| OciEvidenceCacheError::InvalidInput)?;
    if disk.version != FORMAT_VERSION
        || context.subject != expected_subject
        || evidence.is_empty()
        || disk.evidence_sha256 != lower_hex(&Sha256::digest(&evidence))
        || disk.id != derive_entry_id(&context, &evidence).as_str()
        || path.file_stem().and_then(std::ffi::OsStr::to_str) != Some(disk.id.as_str())
        || disk.last_refresh < disk.collected_at
    {
        return Err(OciEvidenceCacheError::InvalidInput);
    }
    Ok(LoadedEntry {
        disk,
        context,
        evidence,
        path: path.to_owned(),
        identity,
        encoded_bytes: u64::try_from(encoded.len())
            .map_err(|_| OciEvidenceCacheError::EntryTooLarge)?,
        encoded_sha256: Sha256::digest(&encoded).into(),
    })
}

fn open_absolute_file_no_follow(path: &Path) -> Result<File, OciEvidenceCacheError> {
    open_absolute_file_no_follow_with_flags(path, rustix::fs::OFlags::RDONLY)
}

fn open_absolute_file_no_follow_with_flags(
    path: &Path,
    access: rustix::fs::OFlags,
) -> Result<File, OciEvidenceCacheError> {
    let name = path
        .file_name()
        .ok_or(OciEvidenceCacheError::InvalidInput)?;
    let parent = path.parent().ok_or(OciEvidenceCacheError::InvalidInput)?;
    let directory = open_absolute_directory_no_follow(parent)?;
    let file = rustix::fs::openat(
        directory,
        name,
        access | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| OciEvidenceCacheError::UnsafeLayout)?;
    Ok(File::from(file))
}

fn validate_cache_file_metadata(metadata: &fs::Metadata) -> Result<(), OciEvidenceCacheError> {
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(OciEvidenceCacheError::UnsafeLayout);
    }
    Ok(())
}

fn atomic_write(directory: &Path, name: &str, bytes: &[u8]) -> Result<(), OciEvidenceCacheError> {
    if u64::try_from(bytes.len()).map_or(true, |size| size > MAX_ENCODED_ENTRY_BYTES)
        || name.contains('/')
        || name.starts_with('.')
    {
        return Err(OciEvidenceCacheError::InvalidInput);
    }
    validate_private_directory(directory)?;
    let directory_file = open_absolute_directory_no_follow(directory)?;
    let temporary = format!(".tmp-{}-{}", std::process::id(), uuid::Uuid::new_v4());
    let raw_file = rustix::fs::openat(
        &directory_file,
        temporary.as_str(),
        rustix::fs::OFlags::RDWR
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::from_raw_mode(0o600),
    )
    .map_err(|_| OciEvidenceCacheError::Unavailable)?;
    let mut file = File::from(raw_file);
    let result = (|| {
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| OciEvidenceCacheError::Unavailable)?;
        file.write_all(bytes)
            .map_err(|_| OciEvidenceCacheError::Unavailable)?;
        file.sync_all()
            .map_err(|_| OciEvidenceCacheError::Unavailable)?;
        let metadata = file
            .metadata()
            .map_err(|_| OciEvidenceCacheError::Unavailable)?;
        validate_cache_file_metadata(&metadata)?;
        rustix::fs::renameat(&directory_file, temporary.as_str(), &directory_file, name)
            .map_err(|_| OciEvidenceCacheError::Unavailable)?;
        directory_file
            .sync_all()
            .map_err(|_| OciEvidenceCacheError::Unavailable)
    })();
    if result.is_err() {
        let _ = rustix::fs::unlinkat(
            &directory_file,
            temporary.as_str(),
            rustix::fs::AtFlags::empty(),
        );
    }
    result
}

fn remove_safe_regular(path: &Path) -> Result<bool, OciEvidenceCacheError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(OciEvidenceCacheError::Unavailable),
    };
    if validate_cache_file_metadata(&metadata).is_err() {
        return Ok(false);
    }
    remove_if_identity(
        path,
        FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        },
    )
}

fn retire_preview_candidate(
    path: &Path,
    identity: FileIdentity,
    encoded_sha256: [u8; 32],
    cache_root: &Path,
    maximum_tombstones: usize,
    observer: &mut impl FnMut(&Path),
) -> Result<bool, OciEvidenceCacheError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(OciEvidenceCacheError::Unavailable),
    };
    if metadata.dev() != identity.device
        || metadata.ino() != identity.inode
        || validate_cache_file_metadata(&metadata).is_err()
    {
        return Ok(false);
    }
    let mut file = match open_absolute_file_no_follow_with_flags(path, rustix::fs::OFlags::RDWR) {
        Ok(file) => file,
        Err(OciEvidenceCacheError::UnsafeLayout) => return Ok(false),
        Err(error) => return Err(error),
    };
    let source_parent = path.parent().ok_or(OciEvidenceCacheError::UnsafeLayout)?;
    let source_name = path
        .file_name()
        .ok_or(OciEvidenceCacheError::UnsafeLayout)?;
    let source_directory = open_absolute_directory_no_follow(source_parent)?;
    let (tombstone_directory_path, tombstone_directory) =
        prepare_tombstone_directory(cache_root, maximum_tombstones)?;
    let tombstone_name = format!("{}.json", uuid::Uuid::new_v4().as_simple());
    renameat_with(
        &source_directory,
        source_name,
        &tombstone_directory,
        tombstone_name.as_str(),
        RenameFlags::NOREPLACE,
    )
    .map_err(|error| {
        if error == rustix::io::Errno::NOENT {
            OciEvidenceCacheError::UnsafeLayout
        } else {
            OciEvidenceCacheError::Unavailable
        }
    })?;
    let tombstone_path = tombstone_directory_path.join(&tombstone_name);
    let moved_metadata =
        fs::symlink_metadata(&tombstone_path).map_err(|_| OciEvidenceCacheError::UnsafeLayout)?;
    if moved_metadata.dev() != identity.device
        || moved_metadata.ino() != identity.inode
        || validate_cache_file_metadata(&moved_metadata).is_err()
    {
        restore_tombstone(
            &tombstone_directory,
            &tombstone_name,
            &source_directory,
            source_name,
        )?;
        return Ok(false);
    }

    file.rewind()
        .map_err(|_| OciEvidenceCacheError::Unavailable)?;
    let mut encoded = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(MAX_ENCODED_ENTRY_BYTES + 1)
        .read_to_end(&mut encoded)
        .map_err(|_| OciEvidenceCacheError::Unavailable)?;
    let after = file
        .metadata()
        .map_err(|_| OciEvidenceCacheError::Unavailable)?;
    let matches_preview = after.dev() == identity.device
        && after.ino() == identity.inode
        && validate_cache_file_metadata(&after).is_ok()
        && u64::try_from(encoded.len()).is_ok_and(|size| size <= MAX_ENCODED_ENTRY_BYTES)
        && <[u8; 32]>::from(Sha256::digest(&encoded)) == encoded_sha256;
    if !matches_preview {
        restore_tombstone(
            &tombstone_directory,
            &tombstone_name,
            &source_directory,
            source_name,
        )?;
        return Ok(false);
    }

    // The adversarial test swaps this pathname here. Reclamation below is by
    // the already-validated descriptor, so such a swap cannot redirect it.
    observer(&tombstone_path);
    file.set_len(0)
        .map_err(|_| OciEvidenceCacheError::Unavailable)?;
    file.sync_all()
        .map_err(|_| OciEvidenceCacheError::Unavailable)?;
    source_directory
        .sync_all()
        .map_err(|_| OciEvidenceCacheError::Unavailable)?;
    tombstone_directory
        .sync_all()
        .map_err(|_| OciEvidenceCacheError::Unavailable)?;
    Ok(true)
}

fn prepare_tombstone_directory(
    cache_root: &Path,
    maximum_tombstones: usize,
) -> Result<(PathBuf, File), OciEvidenceCacheError> {
    let path = cache_root.join(TOMBSTONE_DIRECTORY);
    create_or_validate_private_directory(&path)?;
    let tombstones = fs::read_dir(&path)
        .map_err(|_| OciEvidenceCacheError::Unavailable)?
        .take(maximum_tombstones.saturating_add(1))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| OciEvidenceCacheError::Unavailable)?;
    if tombstones.len() >= maximum_tombstones {
        return Err(OciEvidenceCacheError::UnsafeLayout);
    }
    for tombstone in tombstones {
        let metadata = fs::symlink_metadata(tombstone.path())
            .map_err(|_| OciEvidenceCacheError::Unavailable)?;
        validate_cache_file_metadata(&metadata)?;
    }
    Ok((path.clone(), open_absolute_directory_no_follow(&path)?))
}

fn restore_tombstone(
    tombstone_directory: &File,
    tombstone_name: &str,
    source_directory: &File,
    source_name: &std::ffi::OsStr,
) -> Result<(), OciEvidenceCacheError> {
    renameat_with(
        tombstone_directory,
        tombstone_name,
        source_directory,
        source_name,
        RenameFlags::NOREPLACE,
    )
    .map_err(|_| OciEvidenceCacheError::UnsafeLayout)
}

fn remove_if_identity(path: &Path, identity: FileIdentity) -> Result<bool, OciEvidenceCacheError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(OciEvidenceCacheError::Unavailable),
    };
    if metadata.dev() != identity.device
        || metadata.ino() != identity.inode
        || validate_cache_file_metadata(&metadata).is_err()
    {
        return Ok(false);
    }
    let parent = path.parent().ok_or(OciEvidenceCacheError::UnsafeLayout)?;
    let name = path
        .file_name()
        .ok_or(OciEvidenceCacheError::UnsafeLayout)?;
    let directory = open_absolute_directory_no_follow(parent)?;
    rustix::fs::unlinkat(&directory, name, rustix::fs::AtFlags::empty())
        .map_err(|_| OciEvidenceCacheError::Unavailable)?;
    directory
        .sync_all()
        .map_err(|_| OciEvidenceCacheError::Unavailable)?;
    Ok(true)
}

fn derive_entry_id(context: &EvidenceContext, evidence: &[u8]) -> CacheEntryId {
    let mut hasher = Sha256::new();
    hash_component(&mut hasher, context.subject.to_string().as_bytes());
    hash_component(&mut hasher, context.source_context.as_bytes());
    hash_component(&mut hasher, evidence);
    CacheEntryId(lower_hex(&hasher.finalize()))
}

fn temporary_writer_pid(name: &str) -> Option<rustix::process::Pid> {
    let name = name.strip_prefix(".tmp-")?;
    let (pid, identifier) = name.split_once('-')?;
    uuid::Uuid::parse_str(identifier).ok()?;
    pid.parse::<i32>()
        .ok()
        .and_then(rustix::process::Pid::from_raw)
}

fn hash_component(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
}

fn entry_info(entry: &LoadedEntry, now: u64) -> CacheEntryInfo {
    let age_seconds = now.saturating_sub(entry.disk.last_refresh);
    let degraded_duration_seconds = entry
        .disk
        .degraded_since
        .map(|since| now.saturating_sub(since));
    CacheEntryInfo {
        id: CacheEntryId(entry.disk.id.clone()),
        subject: entry.context.subject,
        source_context: entry.context.source_context.clone(),
        references: entry.context.references.clone(),
        encoded_bytes: entry.encoded_bytes,
        last_used: entry.disk.last_used,
        collected_at: entry.disk.collected_at,
        last_successful_refresh: entry.disk.last_refresh,
        age_seconds,
        refresh_threshold_seconds: REFRESH_AFTER.as_secs(),
        degraded_since: entry.disk.degraded_since,
        degraded_duration_seconds,
        refresh_due: age_seconds >= REFRESH_AFTER.as_secs(),
        refresh: refresh_state(&entry.disk, now),
    }
}

const fn refresh_state(entry: &DiskEntry, now: u64) -> EvidenceRefreshState {
    let age_seconds = now.saturating_sub(entry.last_refresh);
    if age_seconds >= REFRESH_AFTER.as_secs() {
        EvidenceRefreshState::Due {
            age_seconds,
            degraded_since: entry.degraded_since,
        }
    } else {
        EvidenceRefreshState::Fresh
    }
}

fn bounded_printable(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value.chars().any(char::is_control)
        && !value.chars().any(char::is_whitespace)
}

fn pressure_percent(used: u64, maximum: u64) -> u8 {
    let percent = used.saturating_mul(100).checked_div(maximum).unwrap_or(100);
    u8::try_from(percent.min(100)).unwrap_or(100)
}

fn is_lower_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn lower_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;
    use std::sync::{Arc, Barrier};
    use std::thread;

    use super::*;

    const NOW: u64 = 2_000_000_000;

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "basil-oci-evidence-cache-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));
            fs::create_dir(&root).expect("create fixture root");
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                .expect("protect fixture root");
            Self { root }
        }

        fn cache(&self) -> OciEvidenceCache {
            OciEvidenceCache::open(OciEvidenceCacheConfig::new(self.root.join("cache")))
                .expect("open cache")
        }

        fn cache_with_limits(&self, max_bytes: u64, max_entries: usize) -> OciEvidenceCache {
            OciEvidenceCache::open(OciEvidenceCacheConfig {
                root: self.root.join("cache"),
                max_bytes,
                max_entries,
            })
            .expect("open bounded cache")
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn subject(fill: char) -> OciDigest {
        OciDigest::parse(&format!("sha256:{}", fill.to_string().repeat(64))).expect("valid subject")
    }

    fn context(fill: char, reference: &str) -> EvidenceContext {
        EvidenceContext {
            subject: subject(fill),
            source_context: "registry.example/team/app".to_owned(),
            references: BTreeSet::from([reference.to_owned()]),
        }
    }

    fn stored_id(outcome: CacheStoreOutcome) -> CacheEntryId {
        match outcome {
            CacheStoreOutcome::Stored(id) => id,
            CacheStoreOutcome::AtCapacity => panic!("test cache unexpectedly at capacity"),
        }
    }

    #[test]
    fn offline_lookup_revalidates_every_hit_under_current_generation() {
        let fixture = Fixture::new();
        let cache = fixture.cache();
        let context = context('1', "registry.example/team/app@sha256:111");
        let id = stored_id(
            cache
                .store(&context, b"complete-public-evidence", NOW)
                .expect("store"),
        );
        let calls = std::cell::Cell::new(0_u32);

        let lookup = cache
            .lookup(
                context.subject,
                &context.source_context,
                42,
                NOW + 1,
                &|seen: &EvidenceContext, bytes: &[u8]| {
                    calls.set(calls.get() + 1);
                    assert_eq!(seen, &context);
                    assert_eq!(bytes, b"complete-public-evidence");
                    LocalEvidenceVerdict::Admit
                },
            )
            .expect("offline lookup");

        assert_eq!(calls.get(), 1);
        assert_eq!(lookup.admitted.len(), 1);
        assert_eq!(lookup.admitted[0].id, id);
        assert_eq!(lookup.admitted[0].generation, 42);
        assert_eq!(lookup.inactive, 0);
        assert_eq!(lookup.corrupt_removed, 0);
    }

    #[test]
    fn current_revocation_is_immediate_without_destroying_valid_evidence() {
        let fixture = Fixture::new();
        let cache = fixture.cache();
        let context = context('2', "registry.example/team/app@sha256:222");
        cache.store(&context, b"signed-bundle", NOW).expect("store");

        let revoked = cache
            .lookup(
                context.subject,
                &context.source_context,
                2,
                NOW + 1,
                &|_: &EvidenceContext, _: &[u8]| LocalEvidenceVerdict::Inactive,
            )
            .expect("revoked lookup");
        assert!(revoked.admitted.is_empty());
        assert_eq!(revoked.inactive, 1);
        assert_eq!(cache.check(NOW + 1).expect("check").entries.len(), 1);

        let restored = cache
            .lookup(
                context.subject,
                &context.source_context,
                3,
                NOW + 2,
                &|_: &EvidenceContext, _: &[u8]| LocalEvidenceVerdict::Admit,
            )
            .expect("restored lookup");
        assert_eq!(restored.admitted.len(), 1);
    }

    #[test]
    fn validator_detected_corruption_is_removed_as_a_miss() {
        let fixture = Fixture::new();
        let cache = fixture.cache();
        let context = context('3', "registry.example/team/app@sha256:333");
        cache.store(&context, b"bad-signature", NOW).expect("store");

        let lookup = cache
            .lookup(
                context.subject,
                &context.source_context,
                4,
                NOW + 1,
                &|_: &EvidenceContext, _: &[u8]| LocalEvidenceVerdict::Corrupt,
            )
            .expect("corrupt lookup");
        assert!(lookup.admitted.is_empty());
        assert_eq!(lookup.corrupt_removed, 1);
        assert!(cache.check(NOW + 1).expect("check").entries.is_empty());
    }

    #[test]
    fn truncated_and_context_replayed_entries_are_removed_safely() {
        let fixture = Fixture::new();
        let cache = fixture.cache();
        let first = context('4', "registry.example/team/app@sha256:444");
        let second = context('5', "registry.example/team/app@sha256:555");
        let first_id = stored_id(cache.store(&first, b"first", NOW).expect("store first"));
        let second_id = stored_id(cache.store(&second, b"second", NOW).expect("store second"));
        let first_path = cache.entry_path(first.subject, &first_id);
        let second_path = cache.entry_path(second.subject, &second_id);

        fs::write(&first_path, b"{").expect("truncate entry");
        let mut replay: serde_json::Value =
            serde_json::from_slice(&fs::read(&second_path).expect("read entry for replay"))
                .expect("parse entry");
        replay["subject"] = serde_json::Value::String(first.subject.to_string());
        fs::write(
            &second_path,
            serde_json::to_vec(&replay).expect("encode replay"),
        )
        .expect("write replay");

        let report = cache.check(NOW + 1).expect("corruption check");
        assert_eq!(report.corrupt_removed, 2);
        assert!(report.entries.is_empty());
        assert!(!first_path.exists());
        assert!(!second_path.exists());
    }

    #[test]
    fn read_only_doctor_does_not_repair_corrupt_entries() {
        let fixture = Fixture::new();
        let cache = fixture.cache();
        let context = context('5', "registry.example/team/app@sha256:doctor");
        let id = stored_id(cache.store(&context, b"evidence", NOW).expect("store"));
        let path = cache.entry_path(context.subject, &id);
        fs::write(&path, b"{").expect("truncate entry");
        let diagnostic = OciEvidenceCache::open_existing_read_only(cache.config().clone())
            .expect("open existing cache read-only");

        assert_eq!(
            diagnostic.doctor_read_only(NOW + 1),
            Err(OciEvidenceCacheError::InvalidInput)
        );
        assert!(path.exists());
        assert_eq!(fs::read(path).expect("read unchanged entry"), b"{");
    }

    #[test]
    fn capacity_never_evicts_existing_usable_evidence() {
        let fixture = Fixture::new();
        let cache = fixture.cache_with_limits(MAX_ENCODED_ENTRY_BYTES, 1);
        let first = context('6', "registry.example/team/app@sha256:666");
        let second = context('7', "registry.example/team/app@sha256:777");
        let first_id = stored_id(cache.store(&first, b"first", NOW).expect("store first"));

        assert_eq!(
            cache
                .store(&second, b"second", NOW + 1)
                .expect("capacity result"),
            CacheStoreOutcome::AtCapacity
        );
        let report = cache.check(NOW + 1).expect("check");
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.entries[0].id, first_id);
        let doctor = cache.doctor(NOW + 1).expect("capacity doctor");
        assert!(doctor.at_capacity);
        assert_eq!(doctor.entry_pressure_percent, 100);

        let byte_limited = OciEvidenceCache::open(OciEvidenceCacheConfig {
            root: cache.config().root.clone(),
            max_bytes: report.total_bytes,
            max_entries: 2,
        })
        .expect("reopen at exact byte capacity");
        assert_eq!(
            byte_limited
                .store(&second, b"second", NOW + 2)
                .expect("byte capacity result"),
            CacheStoreOutcome::AtCapacity
        );
        assert_eq!(
            byte_limited
                .check(NOW + 2)
                .expect("byte check")
                .entries
                .len(),
            1
        );
    }

    #[test]
    fn independent_handles_serialize_capacity_accounting() {
        let fixture = Fixture::new();
        let config = OciEvidenceCacheConfig {
            root: fixture.root.join("cache"),
            max_bytes: MAX_ENCODED_ENTRY_BYTES,
            max_entries: 1,
        };
        OciEvidenceCache::open(config.clone()).expect("initialize cache");
        let barrier = Arc::new(Barrier::new(3));
        let mut writers = Vec::new();
        for (fill, evidence) in [('1', b"one".as_slice()), ('2', b"two".as_slice())] {
            let config = config.clone();
            let barrier = Arc::clone(&barrier);
            writers.push(thread::spawn(move || {
                let cache = OciEvidenceCache::open(config).expect("open writer");
                let context = context(fill, "registry.example/team/app@sha256:capacity");
                barrier.wait();
                cache.store(&context, evidence, NOW).expect("store outcome")
            }));
        }
        barrier.wait();
        let outcomes = writers
            .into_iter()
            .map(|writer| writer.join().expect("writer completed"))
            .collect::<Vec<_>>();
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, CacheStoreOutcome::Stored(_)))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, CacheStoreOutcome::AtCapacity))
                .count(),
            1
        );
        assert_eq!(
            OciEvidenceCache::open(config)
                .expect("open checker")
                .check(NOW)
                .expect("check")
                .entries
                .len(),
            1
        );
    }

    #[test]
    fn repeated_observed_references_are_unioned_for_pruning() {
        let fixture = Fixture::new();
        let cache = fixture.cache();
        let first = context('3', "registry.example/team/app:stable");
        let mut second = first.clone();
        second.references = BTreeSet::from(["registry.example/team/app:v2".to_owned()]);
        let first_id = stored_id(cache.store(&first, b"same-evidence", NOW).expect("first"));
        let second_id = stored_id(
            cache
                .store(&second, b"same-evidence", NOW + 1)
                .expect("second"),
        );
        assert_eq!(first_id, second_id);
        let report = cache.check(NOW + 1).expect("check union");
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.entries[0].references.len(), 2);
        assert_eq!(
            cache
                .plan_prune(
                    &[PruneSelector::Reference(
                        "registry.example/team/app:stable".to_owned(),
                    )],
                    NOW + 1,
                )
                .expect("old reference preview")
                .entries()
                .len(),
            1
        );
    }

    #[test]
    fn sixty_fifth_reference_rejects_without_modifying_entry() {
        let fixture = Fixture::new();
        let cache = fixture.cache();
        let mut first = context('3', "registry.example/team/app:0");
        first.references = (0..MAX_REFERENCES)
            .map(|index| format!("registry.example/team/app:{index}"))
            .collect();
        let id = stored_id(cache.store(&first, b"same-evidence", NOW).expect("first"));
        let path = cache.entry_path(first.subject, &id);
        let before = fs::read(&path).expect("read entry before rejected union");
        let mut extra = context('3', "registry.example/team/app:0");
        extra.references = BTreeSet::from([format!("registry.example/team/app:{MAX_REFERENCES}")]);

        assert_eq!(
            cache.store(&extra, b"same-evidence", NOW + 1),
            Err(OciEvidenceCacheError::InvalidInput)
        );
        assert_eq!(
            fs::read(&path).expect("read entry after rejected union"),
            before
        );
        let report = cache.check(NOW + 1).expect("check unchanged entry");
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.entries[0].references.len(), MAX_REFERENCES);
        assert_eq!(report.entries[0].last_used, NOW);
    }

    #[test]
    fn encoded_entry_limit_is_fixed_and_non_disableable() {
        let fixture = Fixture::new();
        let cache = fixture.cache();
        let context = context('8', "registry.example/team/app@sha256:888");
        let oversized = vec![0_u8; usize::try_from(MAX_ENCODED_ENTRY_BYTES).expect("usize")];
        assert_eq!(
            cache.store(&context, &oversized, NOW),
            Err(OciEvidenceCacheError::EntryTooLarge)
        );
    }

    #[test]
    fn concurrent_readers_observe_only_complete_atomic_entries() {
        let fixture = Fixture::new();
        let cache = fixture.cache();
        let context = context('9', "registry.example/team/app@sha256:999");
        cache.store(&context, b"complete", NOW).expect("store");
        let barrier = Arc::new(Barrier::new(9));
        let mut readers = Vec::new();
        for generation in 1..=8 {
            let config = cache.config().clone();
            let barrier = Arc::clone(&barrier);
            let context = context.clone();
            readers.push(thread::spawn(move || {
                let cache = OciEvidenceCache::open(config).expect("open independent reader");
                barrier.wait();
                cache
                    .lookup(
                        context.subject,
                        &context.source_context,
                        generation,
                        NOW + generation,
                        &|_: &EvidenceContext, bytes: &[u8]| {
                            assert_eq!(bytes, b"complete");
                            LocalEvidenceVerdict::Admit
                        },
                    )
                    .expect("concurrent lookup")
            }));
        }
        barrier.wait();
        for offset in 1..=8 {
            cache
                .store(&context, b"complete", NOW + offset)
                .expect("concurrent atomic rewrite");
        }
        for reader in readers {
            assert_eq!(reader.join().expect("reader completed").admitted.len(), 1);
        }
    }

    #[test]
    fn refresh_due_and_degradation_do_not_expire_evidence() {
        let fixture = Fixture::new();
        let cache = fixture.cache();
        let context = context('a', "registry.example/team/app@sha256:aaa");
        let id = stored_id(cache.store(&context, b"stale", NOW).expect("store"));
        let due = NOW + REFRESH_AFTER.as_secs();

        let doctor = cache.doctor(due).expect("doctor");
        assert_eq!(doctor.refresh_due, 1);
        assert_eq!(doctor.refresh_degraded, 0);
        assert!(
            cache
                .record_refresh(context.subject, &id, due, false)
                .expect("record failure")
        );
        let degraded = cache.doctor(due + 1).expect("degraded doctor");
        assert_eq!(degraded.refresh_degraded, 1);
        let lookup = cache
            .lookup(
                context.subject,
                &context.source_context,
                7,
                due + 1,
                &|_: &EvidenceContext, _: &[u8]| LocalEvidenceVerdict::Admit,
            )
            .expect("degraded evidence remains usable");
        assert_eq!(lookup.admitted.len(), 1);

        assert!(
            cache
                .record_refresh(context.subject, &id, due + 2, true)
                .expect("refresh")
        );
        assert_eq!(cache.doctor(due + 2).expect("fresh doctor").refresh_due, 0);
    }

    #[test]
    fn refresh_diagnostics_preserve_first_failure_and_clear_on_recovery() {
        let fixture = Fixture::new();
        let cache = fixture.cache();
        let context = context('a', "registry.example/team/app@sha256:diagnostics");
        let id = stored_id(cache.store(&context, b"stale", NOW).expect("store"));
        let due = NOW + REFRESH_AFTER.as_secs();

        assert!(
            cache
                .record_refresh(context.subject, &id, due + 3, false)
                .expect("first failure")
        );
        assert!(
            cache
                .record_refresh(context.subject, &id, due + 9, false)
                .expect("repeated failure")
        );
        let degraded = cache.doctor(due + 13).expect("degraded diagnostics");
        assert_eq!(
            degraded.oldest_age_seconds,
            Some(REFRESH_AFTER.as_secs() + 13)
        );
        assert_eq!(degraded.oldest_last_successful_refresh, Some(NOW));
        assert_eq!(degraded.refresh_threshold_seconds, REFRESH_AFTER.as_secs());
        assert_eq!(degraded.longest_degraded_duration_seconds, Some(10));
        let entry = &cache.check(due + 13).expect("entry diagnostics").entries[0];
        assert_eq!(entry.degraded_since, Some(due + 3));
        assert_eq!(entry.degraded_duration_seconds, Some(10));

        assert!(
            cache
                .record_refresh(context.subject, &id, due + 14, true)
                .expect("recovery")
        );
        let recovered = cache.doctor(due + 14).expect("recovered diagnostics");
        assert_eq!(recovered.refresh_due, 0);
        assert_eq!(recovered.refresh_degraded, 0);
        assert_eq!(recovered.oldest_age_seconds, Some(0));
        assert_eq!(recovered.longest_degraded_duration_seconds, None);
    }

    #[test]
    fn prune_is_preview_first_exact_and_reference_scoped() {
        let fixture = Fixture::new();
        let cache = fixture.cache();
        let shared_reference = "registry.example/team/app@sha256:shared";
        let first = context('b', shared_reference);
        let second = context('c', shared_reference);
        let third = context('d', "registry.example/team/app@sha256:other");
        let first_id = stored_id(cache.store(&first, b"first", NOW).expect("first"));
        cache.store(&second, b"second", NOW).expect("second");
        cache.store(&third, b"third", NOW).expect("third");

        assert!(matches!(
            cache.plan_prune(&[], NOW),
            Err(OciEvidenceCacheError::InvalidInput)
        ));
        let exact = cache
            .plan_prune(&[PruneSelector::Id(first_id)], NOW)
            .expect("exact preview");
        assert_eq!(exact.entries().len(), 1);
        assert_eq!(
            cache
                .check(NOW)
                .expect("preview is read only")
                .entries
                .len(),
            3
        );
        assert_eq!(
            cache.execute_prune(exact).expect("exact prune"),
            CachePruneResult {
                removed: 1,
                skipped: 0
            }
        );

        let references = cache
            .plan_prune(
                &[PruneSelector::Reference(shared_reference.to_owned())],
                NOW,
            )
            .expect("reference preview");
        assert_eq!(references.entries().len(), 1);
        cache.execute_prune(references).expect("reference prune");
        assert_eq!(cache.check(NOW).expect("final check").entries.len(), 1);

        let unmatched = cache
            .plan_prune(
                &[PruneSelector::Reference(
                    "registry.example/none@sha256:0".to_owned(),
                )],
                NOW,
            )
            .expect("empty preview");
        assert!(unmatched.is_empty());
        assert_eq!(
            cache.execute_prune(unmatched).expect("empty execute"),
            CachePruneResult {
                removed: 0,
                skipped: 0
            }
        );
    }

    #[test]
    fn changed_entry_is_skipped_after_prune_preview() {
        let fixture = Fixture::new();
        let cache = fixture.cache();
        let context = context('e', "registry.example/team/app@sha256:eee");
        let id = stored_id(cache.store(&context, b"first", NOW).expect("store"));
        let plan = cache
            .plan_prune(&[PruneSelector::Id(id.clone())], NOW)
            .expect("preview");
        let path = cache.entry_path(context.subject, &id);
        fs::remove_file(&path).expect("remove original");
        fs::write(&path, b"replacement").expect("write replacement");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("protect replacement");

        assert_eq!(
            cache.execute_prune(plan).expect("execute guarded plan"),
            CachePruneResult {
                removed: 0,
                skipped: 1
            }
        );
        assert!(path.exists());
    }

    #[test]
    fn prune_reclaims_only_the_opened_inode_across_same_uid_path_swap() {
        let fixture = Fixture::new();
        let cache = fixture.cache();
        let context = context('e', "registry.example/team/app@sha256:prune-race");
        let id = stored_id(cache.store(&context, b"expected", NOW).expect("store"));
        let plan = cache
            .plan_prune(&[PruneSelector::Id(id.clone())], NOW)
            .expect("preview");
        let entry_path = cache.entry_path(context.subject, &id);
        let mut relocated = None;
        let mut replacement = None;

        let result = cache
            .execute_prune_with_observer(plan, |tombstone| {
                let moved = tombstone.with_extension("expected");
                fs::rename(tombstone, &moved).expect("same-uid mutator relocates expected inode");
                fs::write(tombstone, b"foreign replacement").expect("install raced replacement");
                fs::set_permissions(tombstone, fs::Permissions::from_mode(0o600))
                    .expect("protect raced replacement");
                relocated = Some(moved);
                replacement = Some(tombstone.to_path_buf());
            })
            .expect("descriptor-safe prune");
        assert_eq!(
            result,
            CachePruneResult {
                removed: 1,
                skipped: 0
            }
        );
        assert!(!entry_path.exists());
        assert_eq!(
            fs::read(relocated.expect("relocated expected path")).expect("read reclaimed inode"),
            b""
        );
        assert_eq!(
            fs::read(replacement.expect("replacement path")).expect("read foreign replacement"),
            b"foreign replacement"
        );
        assert!(
            cache
                .check(NOW)
                .expect("live scan ignores tombstones")
                .entries
                .is_empty()
        );

        drop(cache);
        let reopened = fixture.cache();
        assert!(
            reopened
                .check(NOW)
                .expect("restart ignores retained tombstones")
                .entries
                .is_empty()
        );
        assert_eq!(
            stored_id(
                reopened
                    .store(&context, b"expected", NOW + 1)
                    .expect("restore exact entry")
            ),
            id
        );
        assert_eq!(
            reopened
                .check(NOW + 1)
                .expect("restored scan")
                .entries
                .len(),
            1
        );
    }

    #[test]
    fn retained_prune_tombstones_are_bounded_and_not_charged_as_live_entries() {
        let fixture = Fixture::new();
        let cache = fixture.cache_with_limits(MAX_ENCODED_ENTRY_BYTES, 2);
        let context = context('e', "registry.example/team/app@sha256:tombstone-bound");
        for offset in 0..2 {
            let id = stored_id(
                cache
                    .store(&context, b"repeat", NOW + offset)
                    .expect("store repeated entry"),
            );
            let plan = cache
                .plan_prune(&[PruneSelector::Id(id)], NOW + offset)
                .expect("preview repeated entry");
            cache.execute_prune(plan).expect("bounded prune");
            assert!(
                cache
                    .check(NOW + offset)
                    .expect("live check")
                    .entries
                    .is_empty()
            );
        }
        let id = stored_id(
            cache
                .store(&context, b"repeat", NOW + 3)
                .expect("store after tombstone capacity"),
        );
        let plan = cache
            .plan_prune(&[PruneSelector::Id(id)], NOW + 3)
            .expect("third preview");
        assert_eq!(
            cache.execute_prune(plan),
            Err(OciEvidenceCacheError::UnsafeLayout)
        );
        assert_eq!(
            fs::read_dir(cache.config().root.join(TOMBSTONE_DIRECTORY))
                .expect("tombstone directory")
                .count(),
            2
        );
        assert_eq!(
            cache
                .check(NOW + 3)
                .expect("third entry retained")
                .entries
                .len(),
            1
        );
    }

    #[test]
    fn same_inode_content_change_is_skipped_after_prune_preview() {
        let fixture = Fixture::new();
        let cache = fixture.cache();
        let context = context('e', "registry.example/team/app@sha256:same-inode");
        let id = stored_id(cache.store(&context, b"first", NOW).expect("store"));
        let plan = cache
            .plan_prune(&[PruneSelector::Id(id.clone())], NOW)
            .expect("preview");
        let path = cache.entry_path(context.subject, &id);
        let before = fs::metadata(&path).expect("metadata before mutation");
        fs::write(&path, b"same-inode-mutated").expect("mutate existing entry");
        let after = fs::metadata(&path).expect("metadata after mutation");
        assert_eq!(before.ino(), after.ino());

        assert_eq!(
            cache.execute_prune(plan).expect("execute guarded plan"),
            CachePruneResult {
                removed: 0,
                skipped: 1
            }
        );
        assert_eq!(
            fs::read(path).expect("read retained mutation"),
            b"same-inode-mutated"
        );
    }

    #[test]
    fn global_traversal_budget_bounds_excess_subject_directories() {
        let fixture = Fixture::new();
        let cache = fixture.cache_with_limits(MAX_ENCODED_ENTRY_BYTES, 1);
        let algorithm_path = cache.config().root.join(ALGORITHM_DIRECTORY);
        let traversal_limit = 2 + MAX_EXTRA_TRAVERSAL_NODES;
        for index in 0..=traversal_limit {
            let path = algorithm_path.join(format!("{index:064x}"));
            fs::create_dir(&path).expect("create excess subject directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("protect excess subject directory");
        }

        assert_eq!(cache.check(NOW), Err(OciEvidenceCacheError::UnsafeLayout));
    }

    #[test]
    fn global_byte_budget_is_charged_before_untrusted_entry_decode() {
        let fixture = Fixture::new();
        let cache = fixture.cache();
        let context = context('f', "registry.example/team/app@sha256:byte-budget");
        let id = stored_id(cache.store(&context, b"evidence", NOW).expect("store"));
        let path = cache.entry_path(context.subject, &id);
        fs::write(&path, vec![b'{'; 1024]).expect("install malformed bounded entry");
        drop(cache);

        let bounded = fixture.cache_with_limits(512, 1);
        assert_eq!(
            bounded.check(NOW),
            Err(OciEvidenceCacheError::UnsafeLayout),
            "global byte exhaustion must reject before malformed JSON is decoded"
        );
    }

    #[test]
    fn unsafe_modes_and_symlinked_layouts_are_rejected() {
        let fixture = Fixture::new();
        let cache_root = fixture.root.join("mode-cache");
        fs::create_dir(&cache_root).expect("create unsafe root");
        fs::set_permissions(&cache_root, fs::Permissions::from_mode(0o755)).expect("unsafe mode");
        assert!(matches!(
            OciEvidenceCache::open(OciEvidenceCacheConfig::new(cache_root)),
            Err(OciEvidenceCacheError::UnsafeLayout)
        ));

        let target = fixture.root.join("target");
        fs::create_dir(&target).expect("create target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).expect("protect target");
        let linked = fixture.root.join("linked-cache");
        symlink(&target, &linked).expect("create symlink");
        assert!(matches!(
            OciEvidenceCache::open(OciEvidenceCacheConfig::new(linked)),
            Err(OciEvidenceCacheError::UnsafeLayout)
        ));

        let cache = fixture.cache();
        let context = context('f', "registry.example/team/app@sha256:fff");
        let id = stored_id(cache.store(&context, b"evidence", NOW).expect("store"));
        let entry_path = cache.entry_path(context.subject, &id);
        fs::remove_file(&entry_path).expect("remove cache file");
        symlink(&target, &entry_path).expect("replace entry with symlink");
        assert_eq!(cache.check(NOW), Err(OciEvidenceCacheError::UnsafeLayout));
    }
}
