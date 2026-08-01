// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Verified-swap rekey boundary over `db-keystore` (`rekey_at`/`verify_at`).
//!
//! This module implements the adapter side of the accepted rekey design
//! (basil-eds8, implemented by basil-gq77): zeroizing DEK pass-through,
//! staging-directory custody, the intent-marker fence, the atomic
//! destination swap with WAL-sidecar disposal, and typed fail-closed error
//! mapping under the no-panic broker rule. The offline CLI orchestration
//! (`basil keystore rekey`) composes these primitives; the command itself
//! stays a fail-closed stub until its adversarial review completes.
//!
//! # Caller obligations
//!
//! - **Quiescence**: the caller must ensure no live opener of the database
//!   (probe the agent socket; the [`RekeyLock`] and the marker fence are
//!   defense in depth, not a substitute).
//! - **Lock order**: acquire the [`RekeyLock`] (exclusive) *before* taking
//!   the sealed-bundle writer role, and hold it from before staging through
//!   marker removal and the final directory sync. The broker's store open
//!   path holds the same lock shared for the store's lifetime.
//! - **Blocking**: all functions here are synchronous and may block on
//!   database I/O and lock retries. Call from async contexts only via
//!   `spawn_blocking`; a broker-runtime rekey is out of scope by design.
//! - **Erasure**: old DB and sidecar inodes are unlinked, never overwritten.
//!   Confidentiality of residual ciphertext rests on cryptographic erasure —
//!   after the bundle epoch advance the retired DEK exists nowhere basil
//!   controls — and stays conditional on operator backup hygiene: the
//!   completion warning must tell the operator to destroy pre-rekey bundle
//!   backups and any old dek-file copy (a restored backup resurrects the
//!   old DEK; the epoch sidecar is not a security boundary against a local
//!   writer).
//!
//! # Accepted residual
//!
//! turso holds transient, unwiped copies of the hex-encoded DEK and of row
//! buffers for the duration of the operation (basil-1som R1a/G8). This is
//! accepted for the offline command: heap-only, never persisted, and the
//! destination WAL is created `0600` and checkpoint-truncated. The adapter
//! adds no copies of its own.
//!
//! Only the descriptor-relative `rekey_at`/`verify_at` entry points are
//! used. The path-based `DbKeyStore::rekey` is forbidden in basil code
//! (adoption condition C4): it `create_dir_all`s destination parents with
//! umask-default modes and follows source symlinks.

// Adoption condition C2: `catch_unwind` panic containment inside db-keystore
// requires `panic = "unwind"`. Fail the build loudly if any profile sets
// `panic = "abort"` for a target that links this module.
#[cfg(not(panic = "unwind"))]
compile_error!(
    "db-keystore rekey panic containment requires `panic = \"unwind\"`; \
     no basil profile may set `panic = \"abort\"` (adoption condition C2)"
);

use std::fmt::{self, Write as _};
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::path::Path;

use db_keystore::rekey::{RekeyError, SensitiveKey};
use db_keystore::{EncryptionOpts, rekey_at, verify_at};
use rustix::fs::{AtFlags, FileType, FlockOperation, Mode, OFlags};
use rustix::io::Errno;
use zero_secrets::SecretArray;
use zeroize::Zeroizing;

/// Staging directory created inside the database directory for the rekeyed
/// candidate. Fresh per rekey run; never reused.
pub const STAGING_DIR_NAME: &str = ".rekey-staging";

/// Fixed candidate file name inside the staging directory.
pub const CANDIDATE_NAME: &str = "candidate.db";

/// Suffix of the intent-marker file (appended to the database name).
pub const MARKER_SUFFIX: &str = ".rekey-intent";

/// Suffix of the advisory-lock file (appended to the database name).
pub const LOCK_SUFFIX: &str = ".rekey-lock";

/// The turso WAL/SHM sidecar suffix set this adapter disposes of during the
/// swap.
///
/// Mirror of db-keystore's internal pin (adoption condition C3): a turso
/// bump must fail the pin test until the set is re-verified.
pub const SIDECAR_SUFFIXES: [&str; 2] = ["-wal", "-tshm"];

/// The turso version the [`SIDECAR_SUFFIXES`] set was verified against
/// (adoption condition C3; see `tests/rekey_boundary.rs`).
pub const PINNED_TURSO_VERSION: &str = "0.7.1";

/// First line of the intent-marker file: magic plus format version.
const MARKER_MAGIC: &str = "basil-rekey-intent-v1";

/// Backend identifier recorded in (and required of) the marker.
const MARKER_BACKEND: &str = "db-keystore";

/// Upper bound on the marker file size accepted at read time.
const MARKER_MAX_BYTES: u64 = 4096;

/// Upper bound (chars) on backend detail text copied into error values.
const DETAIL_MAX_CHARS: usize = 512;

/// Upper bound (chars) on the contained-panic audit payload (second layer;
/// db-keystore bounds to 256 at capture).
const PANIC_MAX_CHARS: usize = 256;

/// Which database a wrong-DEK failure refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DekSide {
    /// The live source database (old DEK).
    Source,
    /// The staged destination candidate (new DEK).
    Destination,
}

impl fmt::Display for DekSide {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source => f.write_str("source"),
            Self::Destination => f.write_str("destination"),
        }
    }
}

/// Bounded, redacted diagnostic text from a contained database-layer panic.
///
/// Never rendered by `Display` of the error; retrieve it explicitly with
/// [`AuditPayload::audit_text`] for the audit/log sink only. `Debug` prints a
/// redaction placeholder so accidental logging cannot leak the payload.
pub struct AuditPayload(String);

impl AuditPayload {
    /// The sanitized payload, for the audit sink only.
    #[must_use]
    pub fn audit_text(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AuditPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuditPayload(<redacted>)")
    }
}

/// Typed, fail-closed rekey-boundary error. Messages never contain secret
/// material; contained-panic diagnostics are withheld from `Display` and
/// `Debug` (see [`AuditPayload`]).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KeystoreRekeyError {
    /// A database could not be decrypted with the supplied DEK.
    #[error("wrong DEK for the {side} database; nothing was modified")]
    WrongDek {
        /// Which side failed to decrypt.
        side: DekSide,
    },
    /// The source is missing or not a usable `db-keystore` database.
    #[error("source database unusable: {detail}")]
    CorruptSource {
        /// Bounded upstream detail.
        detail: String,
    },
    /// Source and candidate did not compare byte-exact, or the candidate
    /// became unreadable before the marker was written.
    #[error("rekey verification failed: {detail}")]
    VerificationFailed {
        /// Bounded upstream detail (record identifiers only, secret-free).
        detail: String,
    },
    /// The destination could not be created safely, vanished, or was
    /// substituted inside basil's own staging directory.
    #[error("unsafe rekey destination: {detail}")]
    UnsafeDestination {
        /// Bounded upstream detail.
        detail: String,
    },
    /// The source directory entry stopped referring to the validated inode.
    #[error("source database was replaced mid-rekey: {detail}")]
    SourceReplaced {
        /// Bounded upstream detail.
        detail: String,
    },
    /// A stale staging directory exists without an intent marker (for
    /// example after `kill -9` between staging creation and the marker).
    #[error(
        "stale rekey staging directory `{STAGING_DIR_NAME}` exists without an \
         intent marker: inspect its contents, then remove it manually before \
         rerunning `basil keystore rekey`"
    )]
    StagingExists,
    /// An intent marker already exists; recovery must run first.
    #[error(
        "keystore rekey in progress: intent marker `{marker}` is present; run \
         `basil keystore rekey --resume` to complete recovery"
    )]
    RekeyInProgress {
        /// Path (or database-directory-relative name) of the marker file.
        marker: String,
    },
    /// No intent marker was found where one was required.
    #[error("no rekey intent marker `{marker}` found")]
    MarkerMissing {
        /// Database-directory-relative name of the marker file.
        marker: String,
    },
    /// The intent marker failed validation.
    #[error("rekey intent marker invalid: {detail}")]
    MarkerInvalid {
        /// What failed (field names and bounds only; content never echoed).
        detail: String,
    },
    /// A recovery hash re-check failed: the candidate (or the swapped-in
    /// database) does not match the ciphertext recorded in the marker.
    #[error("rekey recovery hash mismatch: {detail}; manual intervention required")]
    CandidateHashMismatch {
        /// What was hashed and how it diverged (no content).
        detail: String,
    },
    /// Recovery found a state outside the protocol (tampering inside the
    /// database directory or staging directory).
    #[error("rekey recovery unrecoverable: {detail}; manual intervention required")]
    RecoveryUnrecoverable {
        /// What was found (names and states only; no content).
        detail: String,
    },
    /// A lock, staged candidate, or transition was supplied for another
    /// database target.
    #[error("rekey target identity mismatch: {detail}")]
    TargetMismatch {
        /// Which identity component did not match.
        detail: String,
    },
    /// A destructive transition was requested before the preceding protocol
    /// phase had completed.
    #[error("invalid rekey protocol phase: {detail}")]
    InvalidPhase {
        /// The missing or inconsistent phase evidence.
        detail: String,
    },
    /// The store's shared advisory lock is held (the agent, or another
    /// opener, is live).
    #[error("keystore is in use (advisory lock `{path}` is held); stop the agent first")]
    AgentLive {
        /// Path (or database-directory-relative name) of the lock file.
        path: String,
    },
    /// The new-DEK file is readable by group or world, or is not a regular
    /// owned file.
    #[error("new-DEK file rejected: {detail}")]
    DekFilePermissions {
        /// Which check failed (mode/ownership/file type; no content).
        detail: String,
    },
    /// The new-DEK file does not contain exactly the required raw bytes.
    #[error("new-DEK file must contain exactly {expected} raw bytes, found {actual}")]
    DekFileLength {
        /// Required byte count.
        expected: u64,
        /// Actual file size.
        actual: u64,
    },
    /// A panic escaped the database layer and was contained upstream. The
    /// diagnostic payload is withheld from user-facing output; the audit
    /// sink may read it via [`AuditPayload::audit_text`].
    #[error("database layer panic was contained; diagnostic text withheld (audit log only)")]
    ContainedPanic {
        /// Bounded, control-char-stripped payload for the audit sink only.
        audit: AuditPayload,
    },
    /// Fail-closed catch-all for backend/database/filesystem failures.
    #[error("rekey backend failure: {detail}")]
    Backend {
        /// Bounded operation and error detail.
        detail: String,
    },
}

/// Bound `text` to `max` chars and replace control characters, so untrusted
/// upstream detail can neither flood logs nor smuggle terminal controls.
fn bounded_detail(text: &str, max: usize) -> String {
    let mut out: String = text
        .chars()
        .take(max)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if text.chars().nth(max).is_some() {
        out.push_str("… (truncated)");
    }
    out
}

/// Map an upstream [`RekeyError`] into the adapter's typed error.
///
/// Never formats the upstream error via `Debug`, and never surfaces a panic
/// payload in `Display` (it is re-bounded and stored for the audit sink
/// only). Unknown variants (the enum is `non_exhaustive`) fail closed as
/// [`KeystoreRekeyError::Backend`].
fn map_upstream(err: RekeyError) -> KeystoreRekeyError {
    match err {
        RekeyError::WrongSourceKey => KeystoreRekeyError::WrongDek {
            side: DekSide::Source,
        },
        RekeyError::WrongDestinationKey => KeystoreRekeyError::WrongDek {
            side: DekSide::Destination,
        },
        RekeyError::CorruptSource(msg) | RekeyError::SourceNotFound(msg) => {
            KeystoreRekeyError::CorruptSource {
                detail: bounded_detail(&msg, DETAIL_MAX_CHARS),
            }
        }
        RekeyError::VerificationMismatch(msg) | RekeyError::CorruptDestination(msg) => {
            KeystoreRekeyError::VerificationFailed {
                detail: bounded_detail(&msg, DETAIL_MAX_CHARS),
            }
        }
        RekeyError::DestinationExists(msg)
        | RekeyError::UnsafeDestination(msg)
        | RekeyError::DestinationNotFound(msg)
        | RekeyError::DestinationReplaced(msg) => KeystoreRekeyError::UnsafeDestination {
            detail: bounded_detail(&msg, DETAIL_MAX_CHARS),
        },
        RekeyError::SourceReplaced(msg) => KeystoreRekeyError::SourceReplaced {
            detail: bounded_detail(&msg, DETAIL_MAX_CHARS),
        },
        RekeyError::Panicked(payload) => KeystoreRekeyError::ContainedPanic {
            audit: AuditPayload(bounded_detail(&payload, PANIC_MAX_CHARS)),
        },
        // InvalidKey / Io / Database and any future variant: fail closed with
        // bounded Display text (upstream contract: messages are secret-free).
        other => KeystoreRekeyError::Backend {
            detail: bounded_detail(&other.to_string(), DETAIL_MAX_CHARS),
        },
    }
}

/// Map a rustix errno from adapter-owned filesystem work.
fn fs_err(op: &'static str, errno: Errno) -> KeystoreRekeyError {
    KeystoreRekeyError::Backend {
        detail: format!("{op}: {errno}"),
    }
}

/// Map a std I/O error from adapter-owned filesystem work.
fn io_err(op: &'static str, err: &std::io::Error) -> KeystoreRekeyError {
    KeystoreRekeyError::Backend {
        detail: format!("{op}: {err}"),
    }
}

/// Reject anything that is not a plain single path component.
fn validate_component(name: &str) -> Result<(), KeystoreRekeyError> {
    let plain = !name.is_empty()
        && name.len() <= 255
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\0');
    if plain {
        Ok(())
    } else {
        Err(KeystoreRekeyError::Backend {
            detail: "database name must be a plain single path component".to_owned(),
        })
    }
}

/// Marker file name for `db_name`.
fn marker_name(db_name: &str) -> String {
    format!("{db_name}{MARKER_SUFFIX}")
}

/// Lock file name for `db_name`.
fn lock_name(db_name: &str) -> String {
    format!("{db_name}{LOCK_SUFFIX}")
}

/// A zeroizing 32-byte DEK owner for the rekey boundary.
///
/// The bytes live in a [`Zeroizing`] array wiped on drop. Passing a
/// `SensitiveDek` **by value** into [`rekey_to_staging`] is deliberate: the
/// function is the narrowly scoped owner of the old key and drops it before
/// returning, so no old-key-bearing state survives the staging step.
pub struct SensitiveDek {
    bytes: Zeroizing<[u8; 32]>,
    #[cfg(test)]
    probe: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

impl SensitiveDek {
    /// Copy a DEK out of a sealed-bundle [`SecretArray`] into zeroizing
    /// storage. The caller's copy stays owned (and wiped) by the caller.
    #[must_use]
    pub fn from_secret(dek: &SecretArray<32>) -> Self {
        let mut bytes = Zeroizing::new([0u8; 32]);
        bytes.copy_from_slice(dek.expose_secret());
        Self {
            bytes,
            #[cfg(test)]
            probe: None,
        }
    }

    /// Wrap an already-zeroizing raw DEK.
    #[must_use]
    pub const fn from_raw(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self {
            bytes,
            #[cfg(test)]
            probe: None,
        }
    }

    /// Build the db-keystore key type from these bytes.
    fn key(&self) -> Result<SensitiveKey, KeystoreRekeyError> {
        SensitiveKey::from_bytes(self.bytes.as_slice()).map_err(map_upstream)
    }

    /// Attach a drop probe (drop-instrumentation proof for the old-DEK drop
    /// boundary).
    #[cfg(test)]
    fn with_probe(mut self, probe: std::sync::Arc<std::sync::atomic::AtomicBool>) -> Self {
        self.probe = Some(probe);
        self
    }
}

#[cfg(test)]
impl Drop for SensitiveDek {
    fn drop(&mut self) {
        if let Some(probe) = &self.probe {
            probe.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

impl fmt::Debug for SensitiveDek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SensitiveDek(<redacted>)")
    }
}

/// Read a new-DEK file: exactly 32 raw bytes, regular file, owned by the
/// current user, not group/world readable. The bytes are read straight into
/// zeroizing storage.
///
/// # Errors
///
/// [`KeystoreRekeyError::DekFilePermissions`] on mode/ownership/type
/// violations, [`KeystoreRekeyError::DekFileLength`] when the file is not
/// exactly 32 bytes, and [`KeystoreRekeyError::Backend`] on I/O failure.
pub fn read_new_dek_file(path: &Path) -> Result<SensitiveDek, KeystoreRekeyError> {
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|errno| fs_err("open new-DEK file", errno))?;
    let stat = rustix::fs::fstat(&fd).map_err(|errno| fs_err("fstat new-DEK file", errno))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(KeystoreRekeyError::DekFilePermissions {
            detail: "not a regular file".to_owned(),
        });
    }
    if stat.st_uid != rustix::process::geteuid().as_raw() {
        return Err(KeystoreRekeyError::DekFilePermissions {
            detail: "not owned by the current user".to_owned(),
        });
    }
    if stat.st_mode & 0o077 != 0 {
        return Err(KeystoreRekeyError::DekFilePermissions {
            detail: "group/world access bits set; require mode 0600 or stricter".to_owned(),
        });
    }
    let actual = u64::try_from(stat.st_size).unwrap_or(0);
    if actual != 32 {
        return Err(KeystoreRekeyError::DekFileLength {
            expected: 32,
            actual,
        });
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    let mut file = File::from(fd);
    file.read_exact(bytes.as_mut_slice())
        .map_err(|err| io_err("read new-DEK file", &err))?;
    // Reject growth between fstat and read: EOF must follow immediately.
    let mut probe = [0u8; 1];
    let n = file
        .read(&mut probe)
        .map_err(|err| io_err("read new-DEK file", &err))?;
    if n != 0 {
        return Err(KeystoreRekeyError::DekFileLength {
            expected: 32,
            actual: 33,
        });
    }
    Ok(SensitiveDek::from_raw(bytes))
}

/// The exclusive rekey advisory lock.
///
/// One lock file exists per database (`<db_name>.rekey-lock`, next to the
/// database). The broker's store open path holds it **shared** for the
/// store's lifetime; a rekey run holds it **exclusive** from before staging
/// through marker removal and the final directory sync. Sidecar disposal and
/// every marker mutation require this witness value, which is only
/// constructible through [`RekeyLock::acquire_exclusive`]. The lock is
/// released when the value drops.
///
/// Lock order: acquire this lock before taking the sealed-bundle writer
/// role; release after both.
#[derive(Debug)]
pub struct RekeyLock {
    _fd: OwnedFd,
    target: RekeyTarget,
}

/// Stable identity of the directory/name pair protected by a rekey lock.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RekeyTarget {
    directory_device: u64,
    directory_inode: u64,
    db_name: String,
}

fn target_for(db_dir: BorrowedFd<'_>, db_name: &str) -> Result<RekeyTarget, KeystoreRekeyError> {
    validate_component(db_name)?;
    let stat =
        rustix::fs::fstat(db_dir).map_err(|errno| fs_err("fstat database directory", errno))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
        return Err(KeystoreRekeyError::TargetMismatch {
            detail: "rekey target descriptor is not a directory".to_owned(),
        });
    }
    Ok(RekeyTarget {
        directory_device: stat.st_dev,
        directory_inode: stat.st_ino,
        db_name: db_name.to_owned(),
    })
}

fn validate_lock_target(
    lock: &RekeyLock,
    db_dir: BorrowedFd<'_>,
    db_name: &str,
) -> Result<(), KeystoreRekeyError> {
    let actual = target_for(db_dir, db_name)?;
    if lock.target != actual {
        return Err(KeystoreRekeyError::TargetMismatch {
            detail: "the lock belongs to a different database directory or name".to_owned(),
        });
    }
    Ok(())
}

/// Open (creating if absent) the advisory lock file, with fail-closed
/// sanity checks on a pre-existing file.
fn open_lock_file(db_dir: BorrowedFd<'_>, db_name: &str) -> Result<OwnedFd, KeystoreRekeyError> {
    let name = lock_name(db_name);
    let fd = rustix::fs::openat(
        db_dir,
        name.as_str(),
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|errno| fs_err("open rekey lock file", errno))?;
    let stat = rustix::fs::fstat(&fd).map_err(|errno| fs_err("fstat rekey lock file", errno))?;
    let sane = FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
        && stat.st_uid == rustix::process::geteuid().as_raw()
        && stat.st_nlink == 1
        && stat.st_mode.trailing_zeros() >= 6;
    if sane {
        Ok(fd)
    } else {
        Err(KeystoreRekeyError::Backend {
            detail: format!("rekey lock file `{name}` failed ownership/mode sanity checks"),
        })
    }
}

impl RekeyLock {
    /// Acquire the exclusive rekey lock for `db_name` inside `db_dir`
    /// (non-blocking).
    ///
    /// # Errors
    ///
    /// [`KeystoreRekeyError::AgentLive`] when the lock is held (the agent or
    /// another opener has the store open, or another rekey is running);
    /// [`KeystoreRekeyError::Backend`] on filesystem failure.
    pub fn acquire_exclusive(
        db_dir: BorrowedFd<'_>,
        db_name: &str,
    ) -> Result<Self, KeystoreRekeyError> {
        validate_component(db_name)?;
        let fd = open_lock_file(db_dir, db_name)?;
        rustix::fs::flock(&fd, FlockOperation::NonBlockingLockExclusive).map_err(|errno| {
            if errno == Errno::WOULDBLOCK {
                KeystoreRekeyError::AgentLive {
                    path: lock_name(db_name),
                }
            } else {
                fs_err("lock rekey lock file (exclusive)", errno)
            }
        })?;
        Ok(Self {
            _fd: fd,
            target: target_for(db_dir, db_name)?,
        })
    }
}

/// Acquire the store-lifetime **shared** advisory lock (broker open path).
/// Returns the lock-holding descriptor; dropping it releases the lock.
fn acquire_shared_lock(
    db_dir: BorrowedFd<'_>,
    db_name: &str,
) -> Result<OwnedFd, KeystoreRekeyError> {
    validate_component(db_name)?;
    let fd = open_lock_file(db_dir, db_name)?;
    rustix::fs::flock(&fd, FlockOperation::NonBlockingLockShared).map_err(|errno| {
        if errno == Errno::WOULDBLOCK {
            KeystoreRekeyError::RekeyInProgress {
                marker: lock_name(db_name),
            }
        } else {
            fs_err("lock rekey lock file (shared)", errno)
        }
    })?;
    Ok(fd)
}

/// Is an intent marker entry (of any file type; fail closed) present?
///
/// # Errors
///
/// [`KeystoreRekeyError::Backend`] on filesystem failure.
pub fn marker_present(db_dir: BorrowedFd<'_>, db_name: &str) -> Result<bool, KeystoreRekeyError> {
    validate_component(db_name)?;
    match rustix::fs::statat(
        db_dir,
        marker_name(db_name).as_str(),
        AtFlags::SYMLINK_NOFOLLOW,
    ) {
        Ok(_) => Ok(true),
        Err(Errno::NOENT) => Ok(false),
        Err(errno) => Err(fs_err("stat rekey intent marker", errno)),
    }
}

/// Broker store-open fence (crate-internal): take the shared lock, then
/// refuse to open while an intent marker exists. Returns the lock-holding
/// descriptor to keep for the store's lifetime.
pub(crate) fn guard_store_open(db_path: &Path) -> Result<OwnedFd, KeystoreRekeyError> {
    let db_name = db_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| KeystoreRekeyError::Backend {
            detail: "database path has no UTF-8 file name".to_owned(),
        })?;
    let parent = db_path.parent().filter(|p| !p.as_os_str().is_empty());
    // The configured database directory is trusted operator input, so
    // symlinked *directory* components are allowed here (unlike every
    // rekey-time open, which is O_NOFOLLOW descriptor-relative).
    let db_dir = rustix::fs::open(
        parent.unwrap_or_else(|| Path::new(".")),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|errno| fs_err("open database directory", errno))?;
    // Lock first, then check the marker: a live rekey holds the exclusive
    // lock (so the shared attempt fails), and a crashed rekey leaves the
    // marker (caught below with no writer racing us while we hold the
    // shared lock).
    let lock = acquire_shared_lock(db_dir.as_fd(), db_name)?;
    if marker_present(db_dir.as_fd(), db_name)? {
        let marker_path = parent
            .unwrap_or_else(|| Path::new("."))
            .join(marker_name(db_name));
        return Err(KeystoreRekeyError::RekeyInProgress {
            marker: marker_path.display().to_string(),
        });
    }
    Ok(lock)
}

/// Bundle pre/post epochs recorded in the intent marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochPair {
    /// Bundle epoch before the reseal (old DEK).
    pub pre: u64,
    /// Bundle epoch after the reseal (new DEK); must exceed `pre`.
    pub post: u64,
}

/// Which recovery mode applies, derived from the live bundle epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryPhase {
    /// The bundle is at the pre-rekey epoch: the commit point was never
    /// crossed; recovery rolls back to the exact pre-rekey state.
    RollBack,
    /// The bundle is at the post-rekey epoch: recovery rolls forward only.
    RollForward,
}

/// What a roll-forward recovery found and did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryOutcome {
    /// The candidate was still staged; the swap was performed and finished.
    ResumedSwap,
    /// The swap had already completed (the live database matched the
    /// marker's candidate hash); only the finish step ran.
    SwapAlreadyComplete,
}

/// Parsed and validated intent marker.
///
/// Created `O_EXCL`/`O_NOFOLLOW` mode `0600` next to the database; read back
/// only through a validated descriptor (regular file, current-user owned,
/// link count 1, bounded size). The marker is a **fence**, not the commit
/// point: it makes the broker refuse to open and records both ciphertext
/// hashes for recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentMarker {
    /// Candidate file name inside the staging directory (always
    /// [`CANDIDATE_NAME`] in version 1).
    pub candidate_name: String,
    /// BLAKE3 of the candidate's ciphertext bytes at staging time.
    pub candidate_b3: [u8; 32],
    /// BLAKE3 of the pre-rekey live database's ciphertext bytes. Pre-epoch
    /// rollback verifies the live database against this before deleting the
    /// candidate, so a restored-backup misclassification becomes a typed
    /// error instead of a rollback over a new-DEK live database.
    pub old_db_b3: [u8; 32],
    /// Bundle pre/post epochs.
    pub epochs: EpochPair,
    /// Marker creation time (Unix seconds; informational only).
    pub created_unix: u64,
}

fn hex_encode(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn hex_decode_32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (slot, pair) in out.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        let hi = char::from(*pair.first()?).to_digit(16)?;
        let lo = char::from(*pair.get(1)?).to_digit(16)?;
        *slot = u8::try_from((hi << 4) | lo).ok()?;
    }
    Some(out)
}

impl IntentMarker {
    /// Internal consistency checks shared by build and parse.
    fn validate(&self) -> Result<(), KeystoreRekeyError> {
        if self.candidate_name != CANDIDATE_NAME {
            return Err(KeystoreRekeyError::MarkerInvalid {
                detail: format!("candidate name must be `{CANDIDATE_NAME}` in version 1"),
            });
        }
        if self.epochs.post <= self.epochs.pre {
            return Err(KeystoreRekeyError::MarkerInvalid {
                detail: "post-epoch must exceed pre-epoch".to_owned(),
            });
        }
        Ok(())
    }

    /// Which recovery phase applies for the live `bundle_epoch`.
    ///
    /// # Errors
    ///
    /// [`KeystoreRekeyError::RecoveryUnrecoverable`] when the bundle epoch
    /// matches neither recorded epoch (a bundle from outside this rekey run,
    /// for example a restored backup).
    pub fn phase_for_bundle_epoch(
        &self,
        bundle_epoch: u64,
    ) -> Result<RecoveryPhase, KeystoreRekeyError> {
        if bundle_epoch == self.epochs.pre {
            Ok(RecoveryPhase::RollBack)
        } else if bundle_epoch == self.epochs.post {
            Ok(RecoveryPhase::RollForward)
        } else {
            Err(KeystoreRekeyError::RecoveryUnrecoverable {
                detail: format!(
                    "bundle epoch {bundle_epoch} matches neither the marker pre-epoch {} \
                     nor post-epoch {}",
                    self.epochs.pre, self.epochs.post
                ),
            })
        }
    }

    fn serialize(&self) -> String {
        let mut out = String::with_capacity(256);
        let _ = writeln!(out, "{MARKER_MAGIC}");
        let _ = writeln!(out, "backend={MARKER_BACKEND}");
        let _ = writeln!(out, "candidate={}", self.candidate_name);
        let _ = writeln!(out, "candidate-b3={}", hex_encode(&self.candidate_b3));
        let _ = writeln!(out, "old-db-b3={}", hex_encode(&self.old_db_b3));
        let _ = writeln!(out, "pre-epoch={}", self.epochs.pre);
        let _ = writeln!(out, "post-epoch={}", self.epochs.post);
        let _ = writeln!(out, "created-unix={}", self.created_unix);
        out
    }

    /// Strict parse: exact field order, no duplicates or unknown fields, no
    /// content echoed into errors.
    fn parse(bytes: &[u8]) -> Result<Self, KeystoreRekeyError> {
        let invalid = |detail: &str| KeystoreRekeyError::MarkerInvalid {
            detail: detail.to_owned(),
        };
        let text = std::str::from_utf8(bytes).map_err(|_| invalid("not UTF-8"))?;
        let mut lines = text.lines();
        if lines.next() != Some(MARKER_MAGIC) {
            return Err(invalid("bad magic/version line"));
        }
        let mut field = |key: &'static str| -> Result<&str, KeystoreRekeyError> {
            lines
                .next()
                .and_then(|line| line.strip_prefix(key))
                .and_then(|rest| rest.strip_prefix('='))
                .ok_or_else(|| invalid(&format!("missing or misordered field `{key}`")))
        };
        let backend = field("backend")?;
        if backend != MARKER_BACKEND {
            return Err(invalid("backend identifier mismatch"));
        }
        let candidate_name = field("candidate")?.to_owned();
        let candidate_b3 =
            hex_decode_32(field("candidate-b3")?).ok_or_else(|| invalid("bad candidate-b3 hex"))?;
        let old_db_b3 =
            hex_decode_32(field("old-db-b3")?).ok_or_else(|| invalid("bad old-db-b3 hex"))?;
        let pre = field("pre-epoch")?
            .parse::<u64>()
            .map_err(|_| invalid("bad pre-epoch"))?;
        let post = field("post-epoch")?
            .parse::<u64>()
            .map_err(|_| invalid("bad post-epoch"))?;
        let created_unix = field("created-unix")?
            .parse::<u64>()
            .map_err(|_| invalid("bad created-unix"))?;
        if lines.next().is_some() {
            return Err(invalid("trailing content"));
        }
        let marker = Self {
            candidate_name,
            candidate_b3,
            old_db_b3,
            epochs: EpochPair { pre, post },
            created_unix,
        };
        marker.validate()?;
        Ok(marker)
    }
}

/// BLAKE3 of a descriptor's full contents via `pread` at explicit offsets
/// (never `read`, so shared file descriptions and prior offsets are
/// irrelevant). Ciphertext only; hashing it leaks no secret.
fn blake3_of_fd(fd: BorrowedFd<'_>) -> Result<[u8; 32], KeystoreRekeyError> {
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 16384];
    let mut offset: u64 = 0;
    loop {
        let n = rustix::io::pread(fd, &mut buf, offset)
            .map_err(|errno| fs_err("pread for hashing", errno))?;
        if n == 0 {
            break;
        }
        let chunk = buf.get(..n).ok_or_else(|| KeystoreRekeyError::Backend {
            detail: "pread returned more bytes than the buffer holds".to_owned(),
        })?;
        hasher.update(chunk);
        offset = offset
            .checked_add(u64::try_from(n).unwrap_or(0))
            .ok_or_else(|| KeystoreRekeyError::Backend {
                detail: "file offset overflow while hashing".to_owned(),
            })?;
    }
    Ok(*hasher.finalize().as_bytes())
}

/// BLAKE3 of the file `name` inside `dir` (`O_RDONLY|O_NOFOLLOW`).
fn blake3_of_entry(
    dir: BorrowedFd<'_>,
    name: &str,
) -> Result<Option<[u8; 32]>, KeystoreRekeyError> {
    match rustix::fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => Ok(Some(blake3_of_fd(fd.as_fd())?)),
        Err(Errno::NOENT) => Ok(None),
        Err(errno) => Err(fs_err("open file for hashing", errno)),
    }
}

/// Inputs for one rekey staging run. The directory descriptor must be
/// opened by the caller with `O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC` (and read
/// access, so it can be fsynced).
#[derive(Debug)]
pub struct RekeyPlan<'a> {
    /// Directory holding the live keystore database.
    pub db_dir: BorrowedFd<'a>,
    /// Single path component of the live database inside `db_dir`.
    pub db_name: &'a str,
    /// turso encryption cipher (unchanged by rekey), for example `aegis256`.
    pub cipher: &'a str,
}

/// Copy/verification counts from a successful staging run. Contains no
/// secret material; safe to audit-log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RekeyReport {
    /// Records copied — equal to records verified, by construction: both
    /// `rekey_at` and the standalone re-verification compare every record
    /// byte-exact before success.
    pub copied: u64,
}

/// A staged, twice-verified rekey candidate awaiting the bundle reseal and
/// swap.
///
/// Holds the staging directory and candidate descriptors so the
/// pinned-inode custody chain extends from creation through the swap.
#[derive(Debug)]
pub struct StagedCandidate {
    staging_dir: OwnedFd,
    candidate_fd: OwnedFd,
    report: RekeyReport,
    candidate_b3: [u8; 32],
    old_db_b3: [u8; 32],
    target: RekeyTarget,
}

impl StagedCandidate {
    /// Copy/verification counts for the audit log.
    #[must_use]
    pub const fn report(&self) -> RekeyReport {
        self.report
    }

    /// BLAKE3 of the candidate's ciphertext, computed from the descriptor
    /// returned by `rekey_at` (unbroken custody).
    #[must_use]
    pub const fn candidate_b3(&self) -> [u8; 32] {
        self.candidate_b3
    }

    /// BLAKE3 of the pre-rekey live database's ciphertext.
    #[must_use]
    pub const fn old_db_b3(&self) -> [u8; 32] {
        self.old_db_b3
    }

    /// Build the intent marker for this candidate.
    ///
    /// # Errors
    ///
    /// [`KeystoreRekeyError::MarkerInvalid`] when `epochs` is not strictly
    /// increasing.
    pub fn intent_marker(&self, epochs: EpochPair) -> Result<IntentMarker, KeystoreRekeyError> {
        let created_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let marker = IntentMarker {
            candidate_name: CANDIDATE_NAME.to_owned(),
            candidate_b3: self.candidate_b3,
            old_db_b3: self.old_db_b3,
            epochs,
            created_unix,
        };
        marker.validate()?;
        Ok(marker)
    }
}

/// Create the private staging directory and return its validated descriptor.
fn create_staging_dir(db_dir: BorrowedFd<'_>) -> Result<OwnedFd, KeystoreRekeyError> {
    match rustix::fs::statat(db_dir, STAGING_DIR_NAME, AtFlags::SYMLINK_NOFOLLOW) {
        Err(Errno::NOENT) => {}
        Ok(_) => return Err(KeystoreRekeyError::StagingExists),
        Err(errno) => return Err(fs_err("stat staging directory", errno)),
    }
    match rustix::fs::mkdirat(db_dir, STAGING_DIR_NAME, Mode::from_raw_mode(0o700)) {
        Ok(()) => {}
        Err(Errno::EXIST) => return Err(KeystoreRekeyError::StagingExists),
        Err(errno) => return Err(fs_err("create staging directory", errno)),
    }
    let staging = rustix::fs::openat(
        db_dir,
        STAGING_DIR_NAME,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|errno| fs_err("open staging directory", errno))?;
    let stat =
        rustix::fs::fstat(&staging).map_err(|errno| fs_err("fstat staging directory", errno))?;
    let fresh = stat.st_uid == rustix::process::geteuid().as_raw()
        && stat.st_mode & 0o777 == 0o700
        && stat.st_nlink == 2;
    if fresh {
        Ok(staging)
    } else {
        Err(KeystoreRekeyError::UnsafeDestination {
            detail: "staging directory failed freshness/ownership checks".to_owned(),
        })
    }
}

/// Best-effort staging cleanup on a pre-marker failure (own entries only:
/// the fixed candidate name inside our fresh directory, then the directory).
fn remove_staging_best_effort(db_dir: BorrowedFd<'_>, staging: &OwnedFd) {
    let _ = rustix::fs::unlinkat(staging, CANDIDATE_NAME, AtFlags::empty());
    let _ = rustix::fs::unlinkat(db_dir, STAGING_DIR_NAME, AtFlags::REMOVEDIR);
    let _ = rustix::fs::fsync(db_dir);
}

/// Stage a rekeyed candidate.
///
/// Creates the private `0700` staging directory inside `plan.db_dir`, runs
/// `rekey_at` (old DEK → new DEK), re-verifies the candidate against the
/// live source with `verify_at` (both DEKs in hand), and records both
/// ciphertext BLAKE3 hashes.
///
/// `old_dek` is consumed: this function is the narrowly scoped owner of the
/// old key, and both it and the old-key `EncryptionOpts` are dropped before
/// the function returns, so no old-key-bearing state survives into the
/// marker/reseal/swap steps. Before the intent marker is written, any
/// failure cleans up the staging directory (own entries only) and leaves
/// the system untouched.
///
/// # Errors
///
/// Typed and fail-closed: wrong-DEK, corrupt-source, verification,
/// unsafe-destination, [`KeystoreRekeyError::StagingExists`] on a stale
/// staging directory, and [`KeystoreRekeyError::Backend`] for bounded
/// backend/filesystem detail. A contained database-layer panic surfaces as
/// [`KeystoreRekeyError::ContainedPanic`].
pub fn rekey_to_staging(
    plan: &RekeyPlan<'_>,
    old_dek: SensitiveDek,
    new_dek: &SensitiveDek,
    lock: &RekeyLock,
) -> Result<StagedCandidate, KeystoreRekeyError> {
    validate_lock_target(lock, plan.db_dir, plan.db_name)?;
    let target = target_for(plan.db_dir, plan.db_name)?;
    let staging = create_staging_dir(plan.db_dir)?;

    let staged = stage_and_verify(plan, &old_dek, new_dek, staging.as_fd());
    // Old-DEK drop boundary: the narrowly scoped owner (and the old-key
    // EncryptionOpts inside stage_and_verify) are gone before this function
    // returns, on success and failure alike.
    drop(old_dek);
    let (candidate_fd, report) = match staged {
        Ok(value) => value,
        Err(err) => {
            remove_staging_best_effort(plan.db_dir, &staging);
            return Err(err);
        }
    };

    let hashed = hash_pair(plan, candidate_fd.as_fd());
    let (candidate_b3, old_db_b3) = match hashed {
        Ok(value) => value,
        Err(err) => {
            remove_staging_best_effort(plan.db_dir, &staging);
            return Err(err);
        }
    };
    Ok(StagedCandidate {
        staging_dir: staging,
        candidate_fd,
        report,
        candidate_b3,
        old_db_b3,
        target,
    })
}

/// `rekey_at` + `verify_at` against the staged candidate. Owns the old-key
/// [`EncryptionOpts`] for exactly this scope.
fn stage_and_verify(
    plan: &RekeyPlan<'_>,
    old_dek: &SensitiveDek,
    new_dek: &SensitiveDek,
    staging: BorrowedFd<'_>,
) -> Result<(OwnedFd, RekeyReport), KeystoreRekeyError> {
    let old_opts = EncryptionOpts::with_key(plan.cipher, old_dek.key()?).map_err(|err| {
        KeystoreRekeyError::Backend {
            detail: bounded_detail(&err.to_string(), DETAIL_MAX_CHARS),
        }
    })?;
    let new_opts = EncryptionOpts::with_key(plan.cipher, new_dek.key()?).map_err(|err| {
        KeystoreRekeyError::Backend {
            detail: bounded_detail(&err.to_string(), DETAIL_MAX_CHARS),
        }
    })?;

    let (outcome, candidate_fd) = rekey_at(
        plan.db_dir,
        plan.db_name,
        Some(&old_opts),
        staging,
        CANDIDATE_NAME,
        Some(&new_opts),
    )
    .map_err(map_upstream)?;

    // Fresh-run strengthening (pre.2): standalone re-verification of the
    // candidate against the live source before any marker exists. Recovery
    // cannot do this (the retired DEK no longer exists there), which is why
    // the marker also records the candidate's ciphertext BLAKE3.
    let verified = verify_at(
        plan.db_dir,
        plan.db_name,
        Some(&old_opts),
        staging,
        CANDIDATE_NAME,
        Some(&new_opts),
    )
    .map_err(map_upstream)?;
    drop(old_opts);
    if verified != outcome.copied {
        return Err(KeystoreRekeyError::VerificationFailed {
            detail: format!(
                "re-verification count {verified} != rekey copy count {}",
                outcome.copied
            ),
        });
    }
    Ok((
        candidate_fd,
        RekeyReport {
            copied: outcome.copied,
        },
    ))
}

/// Hash the candidate (via its returned descriptor) and the pre-rekey live
/// database.
fn hash_pair(
    plan: &RekeyPlan<'_>,
    candidate_fd: BorrowedFd<'_>,
) -> Result<([u8; 32], [u8; 32]), KeystoreRekeyError> {
    let candidate_b3 = blake3_of_fd(candidate_fd)?;
    let old_db_b3 =
        blake3_of_entry(plan.db_dir, plan.db_name)?.ok_or_else(|| KeystoreRekeyError::Backend {
            detail: "live database disappeared while hashing".to_owned(),
        })?;
    Ok((candidate_b3, old_db_b3))
}

/// Write the intent marker and fsync it and the directory.
///
/// The marker (`<db_name>.rekey-intent`, `O_EXCL`/`O_NOFOLLOW`, mode
/// `0600`) fences broker opens and records both ciphertext hashes; it is
/// **not** the commit point.
///
/// # Errors
///
/// [`KeystoreRekeyError::RekeyInProgress`] when a marker already exists;
/// [`KeystoreRekeyError::MarkerInvalid`] on inconsistent contents;
/// [`KeystoreRekeyError::Backend`] on filesystem failure.
pub fn write_intent_marker(
    db_dir: BorrowedFd<'_>,
    db_name: &str,
    marker: &IntentMarker,
    lock: &RekeyLock,
) -> Result<(), KeystoreRekeyError> {
    validate_lock_target(lock, db_dir, db_name)?;
    marker.validate()?;
    let name = marker_name(db_name);
    let fd = match rustix::fs::openat(
        db_dir,
        name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    ) {
        Ok(fd) => fd,
        Err(Errno::EXIST) => return Err(KeystoreRekeyError::RekeyInProgress { marker: name }),
        Err(errno) => return Err(fs_err("create rekey intent marker", errno)),
    };
    let mut file = File::from(fd);
    file.write_all(marker.serialize().as_bytes())
        .map_err(|err| io_err("write rekey intent marker", &err))?;
    file.sync_all()
        .map_err(|err| io_err("fsync rekey intent marker", &err))?;
    drop(file);
    rustix::fs::fsync(db_dir).map_err(|errno| fs_err("fsync database directory", errno))
}

/// Read and validate the intent marker through a checked descriptor:
/// `O_NOFOLLOW` open, regular file, owned by the current user, link count 1,
/// bounded size, strict version/backend/field parsing.
///
/// # Errors
///
/// [`KeystoreRekeyError::MarkerMissing`] when absent;
/// [`KeystoreRekeyError::MarkerInvalid`] on any validation failure;
/// [`KeystoreRekeyError::Backend`] on filesystem failure.
pub fn read_intent_marker(
    db_dir: BorrowedFd<'_>,
    db_name: &str,
) -> Result<IntentMarker, KeystoreRekeyError> {
    validate_component(db_name)?;
    let name = marker_name(db_name);
    let fd = match rustix::fs::openat(
        db_dir,
        name.as_str(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Err(KeystoreRekeyError::MarkerMissing { marker: name }),
        Err(Errno::LOOP) => {
            return Err(KeystoreRekeyError::MarkerInvalid {
                detail: "marker is a symlink".to_owned(),
            });
        }
        Err(errno) => return Err(fs_err("open rekey intent marker", errno)),
    };
    let stat =
        rustix::fs::fstat(&fd).map_err(|errno| fs_err("fstat rekey intent marker", errno))?;
    let size = u64::try_from(stat.st_size).unwrap_or(u64::MAX);
    let sane = FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
        && stat.st_uid == rustix::process::geteuid().as_raw()
        && stat.st_nlink == 1
        && stat.st_mode.trailing_zeros() >= 6
        && size > 0
        && size <= MARKER_MAX_BYTES;
    if !sane {
        return Err(KeystoreRekeyError::MarkerInvalid {
            detail: "marker failed file-type/ownership/link-count/size checks".to_owned(),
        });
    }
    // Read through the validated descriptor only (no re-open by name).
    let mut bytes = Vec::with_capacity(usize::try_from(size).unwrap_or(0));
    let file = File::from(fd);
    file.take(MARKER_MAX_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|err| io_err("read rekey intent marker", &err))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MARKER_MAX_BYTES {
        return Err(KeystoreRekeyError::MarkerInvalid {
            detail: "marker grew past the size bound during read".to_owned(),
        });
    }
    IntentMarker::parse(&bytes)
}

/// Unlink the old WAL/SHM sidecars (step 4a). Names are constructed from the
/// validated `db_name` plus the pinned suffix set; absent sidecars are fine.
fn unlink_old_sidecars(db_dir: BorrowedFd<'_>, db_name: &str) -> Result<(), KeystoreRekeyError> {
    for suffix in SIDECAR_SUFFIXES {
        let name = format!("{db_name}{suffix}");
        validate_component(&name)?;
        match rustix::fs::unlinkat(db_dir, name.as_str(), AtFlags::empty()) {
            Ok(()) | Err(Errno::NOENT) => {}
            Err(errno) => return Err(fs_err("unlink old sidecar", errno)),
        }
    }
    rustix::fs::fsync(db_dir).map_err(|errno| fs_err("fsync database directory", errno))
}

/// Perform the destination swap (step 4).
///
/// Unlinks the old sidecars, then atomically renames the candidate over the
/// live database, syncing the directory around both. The candidate's
/// directory entry is re-checked against the staged descriptor immediately
/// before the rename.
///
/// Call only after the bundle reseal (the commit point): from here recovery
/// is roll-forward only, fenced by the intent marker.
///
/// # Errors
///
/// [`KeystoreRekeyError::UnsafeDestination`] when the staged entry no longer
/// matches the staged inode; [`KeystoreRekeyError::Backend`] on filesystem
/// failure.
pub fn swap_candidate(
    db_dir: BorrowedFd<'_>,
    db_name: &str,
    staged: &StagedCandidate,
    lock: &RekeyLock,
) -> Result<(), KeystoreRekeyError> {
    validate_lock_target(lock, db_dir, db_name)?;
    let target = target_for(db_dir, db_name)?;
    if staged.target != target {
        return Err(KeystoreRekeyError::TargetMismatch {
            detail: "the staged candidate belongs to a different database target".to_owned(),
        });
    }
    let marker = read_intent_marker(db_dir, db_name)?;
    if marker.candidate_b3 != staged.candidate_b3 || marker.old_db_b3 != staged.old_db_b3 {
        return Err(KeystoreRekeyError::InvalidPhase {
            detail: "intent marker does not describe the staged candidate".to_owned(),
        });
    }
    let entry = rustix::fs::statat(
        staged.staging_dir.as_fd(),
        CANDIDATE_NAME,
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(|errno| fs_err("stat staged candidate", errno))?;
    let pinned = rustix::fs::fstat(&staged.candidate_fd)
        .map_err(|errno| fs_err("fstat staged candidate", errno))?;
    if entry.st_dev != pinned.st_dev || entry.st_ino != pinned.st_ino {
        return Err(KeystoreRekeyError::UnsafeDestination {
            detail: "staged candidate entry no longer matches the created inode".to_owned(),
        });
    }
    let current_b3 = blake3_of_fd(staged.candidate_fd.as_fd())?;
    if current_b3 != staged.candidate_b3 {
        return Err(KeystoreRekeyError::CandidateHashMismatch {
            detail: "staged candidate changed after verification".to_owned(),
        });
    }
    unlink_old_sidecars(db_dir, db_name)?;
    rustix::fs::renameat(staged.staging_dir.as_fd(), CANDIDATE_NAME, db_dir, db_name)
        .map_err(|errno| fs_err("rename candidate over database", errno))?;
    rustix::fs::fsync(db_dir).map_err(|errno| fs_err("fsync database directory", errno))
}

/// Finish (step 5): unlink the intent marker, sync, remove the now-empty
/// staging directory, sync again.
///
/// # Errors
///
/// [`KeystoreRekeyError::MarkerMissing`] when no marker exists;
/// [`KeystoreRekeyError::Backend`] on filesystem failure (including a
/// non-empty staging directory, which recovery must inspect).
pub fn finish_rekey(
    db_dir: BorrowedFd<'_>,
    db_name: &str,
    lock: &RekeyLock,
) -> Result<(), KeystoreRekeyError> {
    validate_lock_target(lock, db_dir, db_name)?;
    let marker = read_intent_marker(db_dir, db_name)?;
    let live_b3 =
        blake3_of_entry(db_dir, db_name)?.ok_or_else(|| KeystoreRekeyError::InvalidPhase {
            detail: "cannot finish rekey without a live database after swap".to_owned(),
        })?;
    if live_b3 != marker.candidate_b3 {
        return Err(KeystoreRekeyError::InvalidPhase {
            detail: "the live database does not match the staged candidate; swap not complete"
                .to_owned(),
        });
    }
    if let Some(staging) = open_staging_for_recovery(db_dir)?
        && blake3_of_entry(staging.as_fd(), marker.candidate_name.as_str())?.is_some()
    {
        return Err(KeystoreRekeyError::InvalidPhase {
            detail: "the staged candidate is still present; swap must complete first".to_owned(),
        });
    }
    let name = marker_name(db_name);
    match rustix::fs::unlinkat(db_dir, name.as_str(), AtFlags::empty()) {
        Ok(()) => {}
        Err(Errno::NOENT) => return Err(KeystoreRekeyError::MarkerMissing { marker: name }),
        Err(errno) => return Err(fs_err("unlink rekey intent marker", errno)),
    }
    rustix::fs::fsync(db_dir).map_err(|errno| fs_err("fsync database directory", errno))?;
    match rustix::fs::unlinkat(db_dir, STAGING_DIR_NAME, AtFlags::REMOVEDIR) {
        Ok(()) | Err(Errno::NOENT) => {}
        Err(errno) => return Err(fs_err("remove staging directory", errno)),
    }
    rustix::fs::fsync(db_dir).map_err(|errno| fs_err("fsync database directory", errno))
}

/// Open the staging directory for recovery, if present.
fn open_staging_for_recovery(
    db_dir: BorrowedFd<'_>,
) -> Result<Option<OwnedFd>, KeystoreRekeyError> {
    match rustix::fs::openat(
        db_dir,
        STAGING_DIR_NAME,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => Ok(Some(fd)),
        Err(Errno::NOENT) => Ok(None),
        Err(Errno::NOTDIR | Errno::LOOP) => Err(KeystoreRekeyError::RecoveryUnrecoverable {
            detail: format!("`{STAGING_DIR_NAME}` exists but is not a plain directory"),
        }),
        Err(errno) => Err(fs_err("open staging directory", errno)),
    }
}

/// Pre-epoch recovery: roll back to the exact pre-rekey state.
///
/// The live database is first verified against the marker's recorded
/// pre-rekey ciphertext BLAKE3 — a mismatch (for example a restored backup
/// rolled over a new-DEK live database) is a typed unrecoverable error and
/// nothing is deleted. On match, the candidate and staging directory are
/// removed, then the marker, and the directory is synced. No DEK is needed
/// or accepted.
///
/// # Errors
///
/// [`KeystoreRekeyError::RecoveryUnrecoverable`] on a live-database hash
/// mismatch or a tampered staging entry; [`KeystoreRekeyError::Backend`] on
/// filesystem failure.
pub fn roll_back(
    db_dir: BorrowedFd<'_>,
    db_name: &str,
    marker: &IntentMarker,
    lock: &RekeyLock,
) -> Result<(), KeystoreRekeyError> {
    validate_lock_target(lock, db_dir, db_name)?;
    marker.validate()?;
    let live_b3 = blake3_of_entry(db_dir, db_name)?.ok_or_else(|| {
        KeystoreRekeyError::RecoveryUnrecoverable {
            detail: format!("live database `{db_name}` is missing before the commit point"),
        }
    })?;
    if live_b3 != marker.old_db_b3 {
        return Err(KeystoreRekeyError::RecoveryUnrecoverable {
            detail: format!(
                "live database `{db_name}` does not match the pre-rekey ciphertext \
                 recorded in the intent marker (possibly a restored backup); refusing \
                 to roll back"
            ),
        });
    }
    if let Some(staging) = open_staging_for_recovery(db_dir)? {
        match rustix::fs::unlinkat(&staging, marker.candidate_name.as_str(), AtFlags::empty()) {
            Ok(()) | Err(Errno::NOENT) => {}
            Err(errno) => return Err(fs_err("unlink candidate", errno)),
        }
        drop(staging);
        match rustix::fs::unlinkat(db_dir, STAGING_DIR_NAME, AtFlags::REMOVEDIR) {
            Ok(()) | Err(Errno::NOENT) => {}
            Err(errno) => return Err(fs_err("remove staging directory", errno)),
        }
    }
    match rustix::fs::unlinkat(db_dir, marker_name(db_name).as_str(), AtFlags::empty()) {
        Ok(()) | Err(Errno::NOENT) => {}
        Err(errno) => return Err(fs_err("unlink rekey intent marker", errno)),
    }
    rustix::fs::fsync(db_dir).map_err(|errno| fs_err("fsync database directory", errno))
}

/// Post-epoch recovery: roll forward only (the retired DEK no longer
/// exists; nothing can be re-staged).
///
/// If the candidate is still staged, its ciphertext is re-checked against
/// the marker's BLAKE3 and the swap plus finish steps run. If the staging
/// directory is empty or gone (a crash after the rename consumed the
/// candidate — a normal crash state, not tampering), the file at `db_name`
/// is hashed against the marker's candidate BLAKE3; on match, only the
/// finish step runs. Anything else is a typed unrecoverable error and the
/// candidate is never deleted before a successful rename.
///
/// # Errors
///
/// [`KeystoreRekeyError::CandidateHashMismatch`] when a hash re-check
/// fails; [`KeystoreRekeyError::RecoveryUnrecoverable`] on states outside
/// the protocol; [`KeystoreRekeyError::Backend`] on filesystem failure.
pub fn roll_forward(
    db_dir: BorrowedFd<'_>,
    db_name: &str,
    marker: &IntentMarker,
    lock: &RekeyLock,
) -> Result<RecoveryOutcome, KeystoreRekeyError> {
    validate_lock_target(lock, db_dir, db_name)?;
    marker.validate()?;
    validate_component(&marker.candidate_name)?;
    let staging = open_staging_for_recovery(db_dir)?;
    if let Some(staging) = staging {
        let candidate_b3 = blake3_of_entry(staging.as_fd(), marker.candidate_name.as_str())?;
        if let Some(found_b3) = candidate_b3 {
            if found_b3 != marker.candidate_b3 {
                return Err(KeystoreRekeyError::CandidateHashMismatch {
                    detail: format!(
                        "staged candidate `{}` does not match the intent marker",
                        marker.candidate_name
                    ),
                });
            }
            unlink_old_sidecars(db_dir, db_name)?;
            rustix::fs::renameat(
                staging.as_fd(),
                marker.candidate_name.as_str(),
                db_dir,
                db_name,
            )
            .map_err(|errno| fs_err("rename candidate over database", errno))?;
            rustix::fs::fsync(db_dir).map_err(|errno| fs_err("fsync database directory", errno))?;
            drop(staging);
            finish_rekey(db_dir, db_name, lock)?;
            return Ok(RecoveryOutcome::ResumedSwap);
        }
        drop(staging);
    }
    // Candidate absent: the rename may already have consumed it. The marker
    // fence guarantees no writer has touched the file at `db_name`.
    let live_b3 = blake3_of_entry(db_dir, db_name)?.ok_or_else(|| {
        KeystoreRekeyError::RecoveryUnrecoverable {
            detail: format!("neither a staged candidate nor a live database `{db_name}` exists"),
        }
    })?;
    if live_b3 != marker.candidate_b3 {
        return Err(KeystoreRekeyError::CandidateHashMismatch {
            detail: format!(
                "no staged candidate, and the live database `{db_name}` does not \
                 match the swap-completed state recorded in the intent marker"
            ),
        });
    }
    finish_rekey(db_dir, db_name, lock)?;
    Ok(RecoveryOutcome::SwapAlreadyComplete)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    fn sample_marker() -> IntentMarker {
        IntentMarker {
            candidate_name: CANDIDATE_NAME.to_owned(),
            candidate_b3: [0x11; 32],
            old_db_b3: [0x22; 32],
            epochs: EpochPair { pre: 4, post: 5 },
            created_unix: 1_760_000_000,
        }
    }

    /// Adoption condition C2 (runtime layer): `catch_unwind` must actually
    /// catch, which requires `panic = "unwind"`. Under `panic = "abort"`
    /// this test aborts the harness — the desired loud failure — and the
    /// module-level `compile_error!` guard fails the build outright.
    #[test]
    fn panic_strategy_supports_containment() {
        let caught = std::panic::catch_unwind(|| -> u32 { panic!("containment probe") });
        assert!(caught.is_err());
    }

    #[test]
    fn marker_round_trips_and_parses_strictly() {
        let marker = sample_marker();
        let parsed = IntentMarker::parse(marker.serialize().as_bytes()).unwrap();
        assert_eq!(parsed, marker);
    }

    #[test]
    fn marker_parse_rejects_confusion_and_tampering() {
        let good = sample_marker().serialize();
        let cases: Vec<String> = vec![
            good.replace(MARKER_MAGIC, "basil-rekey-intent-v2"),
            good.replace("backend=db-keystore", "backend=other"),
            good.replace("candidate=candidate.db", "candidate=../evil"),
            good.replace("pre-epoch=4", "pre-epoch=9"), // post <= pre
            format!("{good}extra=1\n"),
            good.replacen("candidate-b3=", "candidate-b3=zz", 1),
            {
                // Reordered fields.
                let mut lines: Vec<&str> = good.lines().collect();
                lines.swap(1, 2);
                let mut out = lines.join("\n");
                out.push('\n');
                out
            },
        ];
        for case in cases {
            assert!(
                matches!(
                    IntentMarker::parse(case.as_bytes()),
                    Err(KeystoreRekeyError::MarkerInvalid { .. })
                ),
                "case must be rejected: {case:?}"
            );
        }
        assert!(matches!(
            IntentMarker::parse(&[0xff, 0xfe]),
            Err(KeystoreRekeyError::MarkerInvalid { .. })
        ));
    }

    #[test]
    fn phase_derivation_matches_epochs_and_fails_closed() {
        let marker = sample_marker();
        assert_eq!(
            marker.phase_for_bundle_epoch(4).unwrap(),
            RecoveryPhase::RollBack
        );
        assert_eq!(
            marker.phase_for_bundle_epoch(5).unwrap(),
            RecoveryPhase::RollForward
        );
        assert!(matches!(
            marker.phase_for_bundle_epoch(7),
            Err(KeystoreRekeyError::RecoveryUnrecoverable { .. })
        ));
    }

    #[test]
    fn upstream_error_mapping_is_fail_closed_and_typed() {
        assert!(matches!(
            map_upstream(RekeyError::WrongSourceKey),
            KeystoreRekeyError::WrongDek {
                side: DekSide::Source
            }
        ));
        assert!(matches!(
            map_upstream(RekeyError::WrongDestinationKey),
            KeystoreRekeyError::WrongDek {
                side: DekSide::Destination
            }
        ));
        assert!(matches!(
            map_upstream(RekeyError::VerificationMismatch("svc/user".into())),
            KeystoreRekeyError::VerificationFailed { .. }
        ));
        assert!(matches!(
            map_upstream(RekeyError::CorruptDestination("x".into())),
            KeystoreRekeyError::VerificationFailed { .. }
        ));
        assert!(matches!(
            map_upstream(RekeyError::DestinationNotFound("x".into())),
            KeystoreRekeyError::UnsafeDestination { .. }
        ));
        assert!(matches!(
            map_upstream(RekeyError::DestinationReplaced("x".into())),
            KeystoreRekeyError::UnsafeDestination { .. }
        ));
        assert!(matches!(
            map_upstream(RekeyError::DestinationExists("x".into())),
            KeystoreRekeyError::UnsafeDestination { .. }
        ));
        assert!(matches!(
            map_upstream(RekeyError::Database("locking retries exhausted".into())),
            KeystoreRekeyError::Backend { .. }
        ));
    }

    #[test]
    fn contained_panic_payload_is_withheld_from_display_and_debug() {
        let noisy = format!("secret-adjacent {}\x1b[31m", "x".repeat(1000));
        let err = map_upstream(RekeyError::Panicked(noisy));
        let shown = err.to_string();
        assert!(!shown.contains("secret-adjacent"));
        let debugged = format!("{err:?}");
        assert!(!debugged.contains("secret-adjacent"));
        if let KeystoreRekeyError::ContainedPanic { audit } = err {
            assert!(audit.audit_text().starts_with("secret-adjacent"));
            assert!(audit.audit_text().chars().count() <= PANIC_MAX_CHARS + 16);
            assert!(!audit.audit_text().contains('\x1b'));
        } else {
            panic!("expected ContainedPanic");
        }
    }

    #[test]
    fn sensitive_dek_debug_is_redacted() {
        let dek = SensitiveDek::from_raw(Zeroizing::new([0xab; 32]));
        assert_eq!(format!("{dek:?}"), "SensitiveDek(<redacted>)");
    }

    /// Old-DEK drop boundary (drop instrumentation): the by-value owner is
    /// dropped inside `rekey_to_staging` even on the error path, so no
    /// old-key-bearing state survives the call.
    #[test]
    fn old_dek_owner_is_dropped_by_staging_even_on_error() {
        let dir = std::env::temp_dir().join(format!(
            "basil-rekey-dropprobe-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir(&dir).unwrap();
        let db_dir = rustix::fs::open(
            &dir,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let lock = RekeyLock::acquire_exclusive(db_dir.as_fd(), "keystore.db").unwrap();

        let probe = Arc::new(AtomicBool::new(false));
        let old_dek =
            SensitiveDek::from_raw(Zeroizing::new([0x01; 32])).with_probe(Arc::clone(&probe));
        let new_dek = SensitiveDek::from_raw(Zeroizing::new([0x02; 32]));
        let plan = RekeyPlan {
            db_dir: db_dir.as_fd(),
            db_name: "keystore.db", // does not exist: staging fails, typed
            cipher: "aegis256",
        };
        let result = rekey_to_staging(&plan, old_dek, &new_dek, &lock);
        assert!(result.is_err());
        assert!(
            probe.load(Ordering::SeqCst),
            "old DEK owner must be dropped inside rekey_to_staging"
        );
        drop(lock);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn component_validation_rejects_traversal() {
        for bad in ["", ".", "..", "a/b", "a\0b"] {
            assert!(validate_component(bad).is_err(), "{bad:?} must be rejected");
        }
        assert!(validate_component("keystore.db").is_ok());
    }

    #[test]
    fn hex_helpers_round_trip() {
        let bytes = [0x5a; 32];
        assert_eq!(hex_decode_32(&hex_encode(&bytes)).unwrap(), bytes);
        assert!(hex_decode_32("zz").is_none());
        assert!(hex_decode_32(&"g".repeat(64)).is_none());
    }
}
