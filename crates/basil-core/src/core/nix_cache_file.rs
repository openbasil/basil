// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Safe, byte-preserving mutation primitives for `file://` Nix caches.
//!
//! [`LockedCacheRoot`] resolves the cache root one component at a time without
//! following symlinks, owns the root descriptor, and holds one advisory lock
//! descriptor for its entire lifetime. A commit uses only descriptor-relative
//! operations: it compares the original [`NarinfoSnapshot`] with a fresh open,
//! writes a same-directory temporary file, preserves ownership and mode, syncs
//! the file, renames it, and syncs the containing directory.
//!
//! The lock is cooperative. A process that ignores
//! `.nix-cache-signatures.lock` can still modify a target after the final
//! comparison and before `renameat`. The snapshot identity and byte comparison
//! detect interference up to that small window. Production cache roots require
//! an exclusive publisher or a publisher set that follows this lock discipline.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};
use std::time::{Duration, Instant};

use rustix::fs::{AtFlags, Dir, FileType, FlockOperation, Mode, OFlags};
use thiserror::Error;

/// Stable root-relative lock-file name used by all cache mutations.
pub const CACHE_LOCK_FILE: &str = ".nix-cache-signatures.lock";

/// Maximum `.narinfo` size accepted by the bounded reader.
pub const MAX_NARINFO_BYTES: u64 = 1_048_576;

/// Maximum exact value accepted after a `Sig: ` prefix.
pub const MAX_SIGNATURE_VALUE_BYTES: usize = 1_024;

const LOCK_MODE: Mode = Mode::from_raw_mode(0o600);
const GROUP_OR_OTHER_WRITE: Mode = Mode::from_raw_mode(0o022);
const TEMPORARY_NAME_ATTEMPTS: usize = 8;

/// Errors returned by safe Nix cache mutation primitives.
#[derive(Debug, Error)]
pub enum NixCacheFileError {
    /// A supplied cache-root or target path is not a safe supported path.
    #[error("invalid Nix cache path")]
    InvalidPath,
    /// The cache root, lock, target, or traversed directory has unsafe metadata.
    #[error("unsafe Nix cache filesystem layout")]
    UnsafeLayout,
    /// Another cooperative publisher currently holds the cache-root lock.
    #[error("Nix cache mutation lock is busy")]
    LockBusy,
    /// The cache-root lock was not acquired before its deadline.
    #[error("timed out waiting for Nix cache mutation lock")]
    LockTimeout,
    /// The target changed or was replaced after it was read.
    #[error("Nix cache target changed before commit")]
    Interference,
    /// The `.narinfo` input exceeds [`MAX_NARINFO_BYTES`].
    #[error("Nix narinfo exceeds the accepted size limit")]
    NarinfoTooLarge,
    /// The `.narinfo` bytes violate the mutation profile.
    #[error("invalid Nix narinfo: {0}")]
    InvalidNarinfo(&'static str),
    /// Adding a signature found the same key name with different signature bytes.
    #[error("SIGNATURE_CONFLICT: use replace for the existing Nix cache key name")]
    SignatureConflict,
    /// The operating system could not supply random temporary-name bytes.
    #[error("operating-system randomness unavailable for Nix cache temporary file")]
    RandomnessUnavailable,
    /// Every bounded temporary-name attempt collided with an existing entry.
    #[error("could not allocate a unique Nix cache temporary file")]
    TemporaryNameExhausted,
    /// Removing a failed pre-rename temporary file failed.
    #[error("failed to clean up Nix cache temporary file: {0}")]
    TemporaryCleanupFailed(#[source] std::io::Error),
    /// The temporary file was removed, but that cleanup could not be synced.
    #[error("Nix cache temporary cleanup completed with uncertain durability: {0}")]
    CleanupDurabilityUncertain(#[source] std::io::Error),
    /// A filesystem operation failed.
    #[error("Nix cache filesystem operation failed: {0}")]
    Io(#[source] std::io::Error),
}

impl From<rustix::io::Errno> for NixCacheFileError {
    fn from(error: rustix::io::Errno) -> Self {
        Self::Io(std::io::Error::from(error))
    }
}

impl From<std::io::Error> for NixCacheFileError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// One byte-preserving change to a `.narinfo` record.
#[derive(Clone, Copy, Debug)]
pub enum NarinfoMutation<'a> {
    /// Add a signature, rejecting a same-name signature conflict.
    Add {
        /// Exact value written after `Sig: `.
        signature: &'a str,
    },
    /// Remove every old key-name line and add the new signature.
    Replace {
        /// Names of superseded Nix cache keys to remove.
        old_key_names: &'a [&'a str],
        /// New exact value written after `Sig: `.
        signature: &'a str,
    },
    /// Remove every signature line whose key name is listed.
    Remove {
        /// Names whose exact matching signature lines are removed.
        key_names: &'a [&'a str],
    },
}

/// Result of applying a byte-preserving `.narinfo` edit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NarinfoEdit {
    /// The requested mutation is already satisfied.
    Unchanged,
    /// Exact replacement bytes for the record.
    Changed(Vec<u8>),
}

/// Result of committing a `.narinfo` mutation.
#[derive(Debug)]
pub enum NarinfoCommit {
    /// No pathname mutation was necessary.
    Unchanged,
    /// A temporary file was atomically renamed over the target and synced.
    Written,
    /// Rename committed the new file, but the directory sync failed.
    ///
    /// The target may already contain the replacement. Callers must report the
    /// uncertain durability state and must not treat this as a pre-commit error.
    CommittedDurabilityUncertain {
        /// Error returned by the post-rename directory sync.
        error: std::io::Error,
    },
}

#[cfg(test)]
type TemporaryBindingHook = fn(&OwnedFd, &str) -> Result<(), NixCacheFileError>;
#[cfg(test)]
type FinalComparisonHook = fn(&OwnedFd, &OsStr) -> Result<(), NixCacheFileError>;
#[cfg(test)]
type CommitStageHook = fn(CommitStage);

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommitStage {
    BeforeWrite,
    AfterWrite,
    BeforeFileSync,
    AfterFileSync,
    BeforeRename,
    AfterRename,
    BeforeDirectorySync,
    AfterDirectorySync,
}

#[cfg(test)]
impl CommitStage {
    const fn name(self) -> &'static str {
        match self {
            Self::BeforeWrite => "before-write",
            Self::AfterWrite => "after-write",
            Self::BeforeFileSync => "before-file-sync",
            Self::AfterFileSync => "after-file-sync",
            Self::BeforeRename => "before-rename",
            Self::AfterRename => "after-rename",
            Self::BeforeDirectorySync => "before-directory-sync",
            Self::AfterDirectorySync => "after-directory-sync",
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InjectedCommitFailure {
    AfterWrite,
    FileSync,
    Rename,
    DirectorySync,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default)]
struct CommitHooks {
    before_temporary_binding: Option<TemporaryBindingHook>,
    before_final_comparison: Option<FinalComparisonHook>,
    stage: Option<CommitStageHook>,
    failure: Option<InjectedCommitFailure>,
    fail_cleanup_sync: bool,
}

#[cfg(test)]
impl CommitHooks {
    fn observe(self, stage: CommitStage) {
        if let Some(hook) = self.stage {
            hook(stage);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u128,
    inode: u128,
    mode: Mode,
    links: u128,
    owner: u32,
    group: u32,
    size: i128,
    modified_seconds: i128,
    modified_nanoseconds: i128,
    changed_seconds: i128,
    changed_nanoseconds: i128,
}

impl FileIdentity {
    fn from_file(file: &File) -> Result<Self, NixCacheFileError> {
        let metadata = file.metadata()?;
        let stat = rustix::fs::fstat(file)?;
        Ok(Self {
            device: u128::from(metadata.dev()),
            inode: u128::from(metadata.ino()),
            mode: Mode::from_raw_mode(stat.st_mode),
            links: u128::from(metadata.nlink()),
            owner: metadata.uid(),
            group: metadata.gid(),
            size: i128::from(metadata.size()),
            modified_seconds: i128::from(metadata.mtime()),
            modified_nanoseconds: i128::from(metadata.mtime_nsec()),
            changed_seconds: i128::from(metadata.ctime()),
            changed_nanoseconds: i128::from(metadata.ctime_nsec()),
        })
    }
}

/// Fresh `.narinfo` bytes coupled to the identity observed while reading them.
#[derive(Clone, Debug)]
pub struct NarinfoSnapshot {
    bytes: Vec<u8>,
    identity: FileIdentity,
}

/// Descriptor-held, read-only cache root used for safe mutation previews.
///
/// This type applies the same no-symlink, ownership, mode, link-count, size,
/// and descriptor/path identity checks as [`LockedCacheRoot`], but never opens
/// or creates [`CACHE_LOCK_FILE`]. It must not be used to commit a mutation.
#[derive(Debug)]
pub struct ReadOnlyCacheRoot {
    root: OwnedFd,
}

impl ReadOnlyCacheRoot {
    /// Open a cache root for descriptor-relative preview reads without locking.
    pub fn open(cache_root: &Path) -> Result<Self, NixCacheFileError> {
        let root = open_cache_root(cache_root)?;
        validate_mutation_directory(&root)?;
        Ok(Self { root })
    }

    /// Read a fresh, bounded snapshot without opening the mutation lock.
    pub fn read_narinfo(&self, relative: &Path) -> Result<NarinfoSnapshot, NixCacheFileError> {
        let (directory, name) = open_parent(&self.root, relative)?;
        read_snapshot_at(&directory, &name)
    }

    /// Enumerate root `.narinfo` names through the held descriptor.
    pub fn root_narinfo_names(&self, limit: usize) -> Result<Vec<OsString>, NixCacheFileError> {
        root_narinfo_names(&self.root, limit)
    }
}

impl NarinfoSnapshot {
    /// Return the exact bytes read from the target.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Descriptor-held cache root and stable advisory mutation lock.
///
/// Dropping this value closes the lock descriptor and releases the kernel lock.
/// The lock file itself is never unlinked.
#[derive(Debug)]
pub struct LockedCacheRoot {
    root: OwnedFd,
    lock: OwnedFd,
}

impl LockedCacheRoot {
    /// Try once to open and exclusively lock `cache_root`.
    ///
    /// This returns [`NixCacheFileError::LockBusy`] instead of waiting when
    /// another cooperative publisher holds the lock.
    pub fn try_acquire(cache_root: &Path) -> Result<Self, NixCacheFileError> {
        Self::acquire_inner(cache_root, None)
    }

    /// Open and exclusively lock `cache_root`, retrying until `timeout`.
    ///
    /// Each retry uses the same open lock descriptor. Callers that need
    /// cancellation can use [`Self::try_acquire`] in their own cancel-aware
    /// loop.
    pub fn acquire(cache_root: &Path, timeout: Duration) -> Result<Self, NixCacheFileError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(NixCacheFileError::InvalidPath)?;
        Self::acquire_inner(cache_root, Some(deadline))
    }

    fn acquire_inner(
        cache_root: &Path,
        deadline: Option<Instant>,
    ) -> Result<Self, NixCacheFileError> {
        let root = open_cache_root(cache_root)?;
        validate_mutation_directory(&root)?;
        let lock = open_or_create_lock(&root)?;

        acquire_flock_with(
            deadline,
            || rustix::fs::flock(&lock, FlockOperation::NonBlockingLockExclusive),
            std::thread::sleep,
        )?;

        validate_lock_descriptor(&lock)?;
        validate_lock_path(&root, &lock)?;
        Ok(Self { root, lock })
    }

    /// Read a fresh, bounded snapshot of a root-relative regular file.
    pub fn read_narinfo(&self, relative: &Path) -> Result<NarinfoSnapshot, NixCacheFileError> {
        let (directory, name) = open_parent(&self.root, relative)?;
        read_snapshot_at(&directory, &name)
    }

    /// Enumerate root `.narinfo` names while the cooperative lock is held.
    pub fn root_narinfo_names(&self, limit: usize) -> Result<Vec<OsString>, NixCacheFileError> {
        root_narinfo_names(&self.root, limit)
    }

    /// Apply `mutation` and atomically commit it when the target is unchanged.
    pub fn mutate_narinfo(
        &self,
        relative: &Path,
        mutation: NarinfoMutation<'_>,
    ) -> Result<NarinfoCommit, NixCacheFileError> {
        let snapshot = self.read_narinfo(relative)?;
        match edit_narinfo(snapshot.bytes(), mutation)? {
            NarinfoEdit::Unchanged => Ok(NarinfoCommit::Unchanged),
            NarinfoEdit::Changed(replacement) => {
                self.commit_narinfo(relative, &snapshot, &replacement)
            }
        }
    }

    /// Atomically replace a target when its snapshot identity and bytes match.
    ///
    /// The expected snapshot must have come from [`Self::read_narinfo`] while
    /// this same lock guard was held. The method rejects a same-bytes pathname
    /// substitution because it also compares the file identity.
    pub fn commit_narinfo(
        &self,
        relative: &Path,
        expected: &NarinfoSnapshot,
        replacement: &[u8],
    ) -> Result<NarinfoCommit, NixCacheFileError> {
        self.commit_narinfo_inner(
            relative,
            expected,
            replacement,
            #[cfg(test)]
            CommitHooks::default(),
        )
    }

    #[cfg(test)]
    fn commit_narinfo_with_hooks(
        &self,
        relative: &Path,
        expected: &NarinfoSnapshot,
        replacement: &[u8],
        hooks: CommitHooks,
    ) -> Result<NarinfoCommit, NixCacheFileError> {
        self.commit_narinfo_inner(relative, expected, replacement, hooks)
    }

    fn commit_narinfo_inner(
        &self,
        relative: &Path,
        expected: &NarinfoSnapshot,
        replacement: &[u8],
        #[cfg(test)] hooks: CommitHooks,
    ) -> Result<NarinfoCommit, NixCacheFileError> {
        let replacement_size =
            u64::try_from(replacement.len()).map_err(|_| NixCacheFileError::NarinfoTooLarge)?;
        if replacement_size > MAX_NARINFO_BYTES {
            return Err(NixCacheFileError::NarinfoTooLarge);
        }
        validate_narinfo(replacement)?;
        let (directory, name) = open_parent(&self.root, relative)?;
        let current = read_snapshot_at(&directory, &name)?;
        if current.identity != expected.identity || current.bytes != expected.bytes {
            return Err(NixCacheFileError::Interference);
        }
        if replacement == expected.bytes {
            return Ok(NarinfoCommit::Unchanged);
        }

        let (temporary_name, temporary) = create_temporary(&directory)?;

        let result = Self::write_and_commit(
            &directory,
            &name,
            &temporary_name,
            temporary,
            expected,
            replacement,
            #[cfg(test)]
            hooks,
        );
        match result {
            Ok(outcome) => Ok(outcome),
            Err(error) => Err(cleanup_temporary(
                &directory,
                &temporary_name,
                error,
                #[cfg(test)]
                hooks,
            )),
        }
    }

    fn write_and_commit(
        directory: &OwnedFd,
        name: &OsStr,
        temporary_name: &str,
        temporary: OwnedFd,
        expected: &NarinfoSnapshot,
        replacement: &[u8],
        #[cfg(test)] hooks: CommitHooks,
    ) -> Result<NarinfoCommit, NixCacheFileError> {
        let mut file = File::from(temporary);
        #[cfg(test)]
        hooks.observe(CommitStage::BeforeWrite);
        file.write_all(replacement)?;
        #[cfg(test)]
        hooks.observe(CommitStage::AfterWrite);
        #[cfg(test)]
        if hooks.failure == Some(InjectedCommitFailure::AfterWrite) {
            return Err(injected_io_error("injected temporary write failure"));
        }

        let temporary_stat = rustix::fs::fstat(&file)?;
        if temporary_stat.st_uid != expected.identity.owner
            || temporary_stat.st_gid != expected.identity.group
        {
            rustix::fs::fchown(
                &file,
                Some(rustix::process::Uid::from_raw(expected.identity.owner)),
                Some(rustix::process::Gid::from_raw(expected.identity.group)),
            )?;
        }
        rustix::fs::fchmod(&file, expected.identity.mode)?;
        #[cfg(test)]
        hooks.observe(CommitStage::BeforeFileSync);
        #[cfg(test)]
        if hooks.failure == Some(InjectedCommitFailure::FileSync) {
            return Err(injected_io_error("injected pre-rename file sync failure"));
        }
        sync_file(&file)?;
        #[cfg(test)]
        hooks.observe(CommitStage::AfterFileSync);

        #[cfg(test)]
        if let Some(hook) = hooks.before_final_comparison {
            hook(directory, name)?;
        }
        let fresh = read_snapshot_at(directory, name)?;
        if fresh.identity != expected.identity || fresh.bytes != expected.bytes {
            return Err(NixCacheFileError::Interference);
        }

        #[cfg(test)]
        if let Some(hook) = hooks.before_temporary_binding {
            hook(directory, temporary_name)?;
        }
        validate_mutation_directory(directory)?;
        validate_temporary_binding(directory, temporary_name, &file, expected)?;
        #[cfg(test)]
        hooks.observe(CommitStage::BeforeRename);
        #[cfg(test)]
        if hooks.failure == Some(InjectedCommitFailure::Rename) {
            return Err(injected_io_error("injected atomic rename failure"));
        }
        rustix::fs::renameat(directory, temporary_name, directory, name)?;
        #[cfg(test)]
        hooks.observe(CommitStage::AfterRename);
        #[cfg(test)]
        hooks.observe(CommitStage::BeforeDirectorySync);
        let sync_result = {
            #[cfg(test)]
            if hooks.failure == Some(InjectedCommitFailure::DirectorySync) {
                Err(std::io::Error::other(
                    "injected post-rename directory sync failure",
                ))
            } else {
                rustix::fs::fsync(directory).map_err(std::io::Error::from)
            }
            #[cfg(not(test))]
            {
                rustix::fs::fsync(directory).map_err(std::io::Error::from)
            }
        };
        match sync_result {
            Ok(()) => {
                #[cfg(test)]
                hooks.observe(CommitStage::AfterDirectorySync);
                Ok(NarinfoCommit::Written)
            }
            Err(error) => Ok(NarinfoCommit::CommittedDurabilityUncertain { error }),
        }
    }

    /// Keep the lock descriptor observably live for callers and tests.
    #[must_use]
    pub fn holds_lock(&self) -> bool {
        rustix::fs::fstat(&self.lock).is_ok()
    }
}

fn root_narinfo_names(root: &OwnedFd, limit: usize) -> Result<Vec<OsString>, NixCacheFileError> {
    let mut names = Vec::new();
    let mut directory = Dir::read_from(root)?;
    for entry in directory.by_ref() {
        let entry = entry?;
        if entry.file_name().to_bytes().ends_with(b".narinfo") {
            if names.len() >= limit {
                return Err(NixCacheFileError::InvalidPath);
            }
            names.push(OsStr::from_bytes(entry.file_name().to_bytes()).to_os_string());
        }
    }
    names.sort_unstable();
    Ok(names)
}

fn open_parent(root: &OwnedFd, relative: &Path) -> Result<(OwnedFd, OsString), NixCacheFileError> {
    if relative.is_absolute() {
        return Err(NixCacheFileError::InvalidPath);
    }
    let mut components = relative.components().peekable();
    let mut directory = rustix::io::fcntl_dupfd_cloexec(root, 0)?;
    validate_mutation_directory(&directory)?;
    let mut name = None;

    while let Some(component) = components.next() {
        let Component::Normal(value) = component else {
            return Err(NixCacheFileError::InvalidPath);
        };
        if components.peek().is_none() {
            name = Some(value.to_owned());
            break;
        }
        directory = rustix::fs::openat(
            &directory,
            value,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| NixCacheFileError::UnsafeLayout)?;
        validate_mutation_directory(&directory)?;
    }

    let name = name.ok_or(NixCacheFileError::InvalidPath)?;
    if name == OsStr::new(CACHE_LOCK_FILE) {
        return Err(NixCacheFileError::InvalidPath);
    }
    Ok((directory, name))
}

fn create_temporary(directory: &OwnedFd) -> Result<(String, OwnedFd), NixCacheFileError> {
    for _ in 0..TEMPORARY_NAME_ATTEMPTS {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|_| NixCacheFileError::RandomnessUnavailable)?;
        let temporary_name = format!(
            ".basil-narinfo-tmp-{}-{}",
            std::process::id(),
            uuid::Uuid::from_bytes(random).as_simple()
        );
        match rustix::fs::openat(
            directory,
            temporary_name.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            LOCK_MODE,
        ) {
            Ok(temporary) => return Ok((temporary_name, temporary)),
            Err(error) if error == rustix::io::Errno::EXIST => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err(NixCacheFileError::TemporaryNameExhausted)
}

fn validate_temporary_binding(
    directory: &OwnedFd,
    temporary_name: &str,
    temporary: &File,
    expected: &NarinfoSnapshot,
) -> Result<(), NixCacheFileError> {
    let descriptor = rustix::fs::fstat(temporary)?;
    validate_temporary_metadata(&descriptor, expected)?;
    let path = rustix::fs::statat(directory, temporary_name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| NixCacheFileError::Interference)?;
    validate_temporary_metadata(&path, expected)?;
    if !same_filesystem_object(&descriptor, &path) {
        return Err(NixCacheFileError::Interference);
    }
    Ok(())
}

fn validate_temporary_metadata(
    stat: &rustix::fs::Stat,
    expected: &NarinfoSnapshot,
) -> Result<(), NixCacheFileError> {
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != expected.identity.owner
        || stat.st_gid != expected.identity.group
        || stat.st_nlink != 1
        || Mode::from_raw_mode(stat.st_mode) != expected.identity.mode
    {
        return Err(NixCacheFileError::Interference);
    }
    Ok(())
}

fn cleanup_temporary(
    directory: &OwnedFd,
    temporary_name: &str,
    original: NixCacheFileError,
    #[cfg(test)] hooks: CommitHooks,
) -> NixCacheFileError {
    if let Err(error) = rustix::fs::unlinkat(directory, temporary_name, AtFlags::empty()) {
        return NixCacheFileError::TemporaryCleanupFailed(std::io::Error::from(error));
    }
    let sync_result = {
        #[cfg(test)]
        if hooks.fail_cleanup_sync {
            Err(std::io::Error::other(
                "injected temporary cleanup directory sync failure",
            ))
        } else {
            rustix::fs::fsync(directory).map_err(std::io::Error::from)
        }
        #[cfg(not(test))]
        {
            rustix::fs::fsync(directory).map_err(std::io::Error::from)
        }
    };
    match sync_result {
        Ok(()) => original,
        Err(error) => NixCacheFileError::CleanupDurabilityUncertain(error),
    }
}

#[cfg(test)]
fn injected_io_error(message: &'static str) -> NixCacheFileError {
    NixCacheFileError::Io(std::io::Error::other(message))
}

fn acquire_flock_with(
    deadline: Option<Instant>,
    mut attempt: impl FnMut() -> rustix::io::Result<()>,
    mut wait: impl FnMut(Duration),
) -> Result<(), NixCacheFileError> {
    let mut attempted = false;
    loop {
        if attempted && deadline.is_some_and(|limit| Instant::now() >= limit) {
            return Err(NixCacheFileError::LockTimeout);
        }
        attempted = true;
        match attempt() {
            Ok(()) => return Ok(()),
            Err(error) if error == rustix::io::Errno::AGAIN => {
                let Some(limit) = deadline else {
                    return Err(NixCacheFileError::LockBusy);
                };
                let now = Instant::now();
                if now >= limit {
                    return Err(NixCacheFileError::LockTimeout);
                }
                wait(
                    limit
                        .saturating_duration_since(now)
                        .min(Duration::from_millis(10)),
                );
            }
            Err(error) if error == rustix::io::Errno::INTR && deadline.is_some() => {}
            Err(error) => return Err(error.into()),
        }
    }
}

impl Drop for LockedCacheRoot {
    fn drop(&mut self) {
        let _ = rustix::fs::flock(&self.lock, FlockOperation::Unlock);
    }
}

/// Apply one text-preserving edit to exact `.narinfo` bytes.
pub fn edit_narinfo(
    input: &[u8],
    mutation: NarinfoMutation<'_>,
) -> Result<NarinfoEdit, NixCacheFileError> {
    validate_narinfo(input)?;
    match mutation {
        NarinfoMutation::Add { signature } => add_signature(input, signature),
        NarinfoMutation::Replace {
            old_key_names,
            signature,
        } => replace_signatures(input, old_key_names, signature),
        NarinfoMutation::Remove { key_names } => remove_signatures(input, key_names),
    }
}

fn validate_narinfo(input: &[u8]) -> Result<(), NixCacheFileError> {
    if input.len() as u64 > MAX_NARINFO_BYTES {
        return Err(NixCacheFileError::NarinfoTooLarge);
    }
    if input.contains(&b'\r') {
        return Err(NixCacheFileError::InvalidNarinfo(
            "contains-carriage-return",
        ));
    }

    let mut nar_hash_count = 0_u8;
    for line in lines(input) {
        let bytes = line.content(input);
        if let Some(value) = bytes.strip_prefix(b"NarHash: ") {
            nar_hash_count = nar_hash_count.saturating_add(1);
            if !is_nix32_sha256(value) {
                return Err(NixCacheFileError::InvalidNarinfo(
                    "narhash-not-sha256-nix32",
                ));
            }
        }
        if bytes.starts_with(b"Sig:") && !bytes.starts_with(b"Sig: ") {
            return Err(NixCacheFileError::InvalidNarinfo(
                "malformed-signature-line",
            ));
        }
        if let Some(value) = bytes.strip_prefix(b"Sig: ") {
            signature_key(value)?;
        }
    }
    if nar_hash_count != 1 {
        return Err(NixCacheFileError::InvalidNarinfo("expected-one-narhash"));
    }
    Ok(())
}

fn is_nix32_sha256(value: &[u8]) -> bool {
    const PREFIX: &[u8] = b"sha256:";
    const NIX32: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";
    value.len() == PREFIX.len() + 52
        && value.starts_with(PREFIX)
        && value
            .get(PREFIX.len()..)
            .is_some_and(|digest| digest.iter().all(|byte| NIX32.contains(byte)))
}

fn add_signature(input: &[u8], signature: &str) -> Result<NarinfoEdit, NixCacheFileError> {
    let key = validate_signature_argument(signature)?;
    let signature_bytes = signature.as_bytes();
    let mut identical = false;
    let mut conflict = false;
    for line in lines(input) {
        if let Some(value) = line.content(input).strip_prefix(b"Sig: ")
            && signature_key(value)? == key
        {
            identical |= value == signature_bytes;
            conflict |= value != signature_bytes;
        }
    }
    if conflict {
        return Err(NixCacheFileError::SignatureConflict);
    }
    if identical {
        return Ok(NarinfoEdit::Unchanged);
    }
    Ok(NarinfoEdit::Changed(insert_signature(
        input,
        signature_bytes,
    )?))
}

fn replace_signatures(
    input: &[u8],
    old_key_names: &[&str],
    signature: &str,
) -> Result<NarinfoEdit, NixCacheFileError> {
    validate_key_names(old_key_names)?;
    validate_signature_argument(signature)?;
    let filtered = filter_signatures(input, old_key_names)?;
    match add_signature(&filtered, signature)? {
        NarinfoEdit::Unchanged if filtered == input => Ok(NarinfoEdit::Unchanged),
        NarinfoEdit::Unchanged => Ok(NarinfoEdit::Changed(filtered)),
        NarinfoEdit::Changed(output) if output == input => Ok(NarinfoEdit::Unchanged),
        NarinfoEdit::Changed(output) => Ok(NarinfoEdit::Changed(output)),
    }
}

fn remove_signatures(input: &[u8], key_names: &[&str]) -> Result<NarinfoEdit, NixCacheFileError> {
    validate_key_names(key_names)?;
    let output = filter_signatures(input, key_names)?;
    if output == input {
        Ok(NarinfoEdit::Unchanged)
    } else {
        Ok(NarinfoEdit::Changed(output))
    }
}

fn validate_signature_argument(signature: &str) -> Result<&[u8], NixCacheFileError> {
    if signature.len() > MAX_SIGNATURE_VALUE_BYTES || signature.contains(['\n', '\r']) {
        return Err(NixCacheFileError::InvalidNarinfo(
            "invalid-signature-argument",
        ));
    }
    signature_key(signature.as_bytes())
}

fn validate_key_names(key_names: &[&str]) -> Result<(), NixCacheFileError> {
    for key_name in key_names {
        if key_name.is_empty() || key_name.contains([':', '\n', '\r']) || !key_name.is_ascii() {
            return Err(NixCacheFileError::InvalidNarinfo("invalid-key-name"));
        }
    }
    Ok(())
}

fn signature_key(signature: &[u8]) -> Result<&[u8], NixCacheFileError> {
    let Some(separator) = signature.iter().position(|byte| *byte == b':') else {
        return Err(NixCacheFileError::InvalidNarinfo(
            "malformed-signature-value",
        ));
    };
    let key = signature
        .get(..separator)
        .ok_or(NixCacheFileError::InvalidNarinfo(
            "malformed-signature-value",
        ))?;
    if key.is_empty() || !key.is_ascii() || key.contains(&b'\n') || key.contains(&b'\r') {
        return Err(NixCacheFileError::InvalidNarinfo(
            "malformed-signature-value",
        ));
    }
    Ok(key)
}

fn filter_signatures(input: &[u8], key_names: &[&str]) -> Result<Vec<u8>, NixCacheFileError> {
    let mut output = Vec::with_capacity(input.len());
    for line in lines(input) {
        let remove = if let Some(value) = line.content(input).strip_prefix(b"Sig: ") {
            let key = signature_key(value)?;
            key_names
                .iter()
                .any(|candidate| candidate.as_bytes() == key)
        } else {
            false
        };
        if !remove {
            output.extend_from_slice(line.full(input));
        }
    }
    Ok(output)
}

fn insert_signature(input: &[u8], signature: &[u8]) -> Result<Vec<u8>, NixCacheFileError> {
    let insertion = lines(input)
        .filter(|line| line.content(input).starts_with(b"Sig: "))
        .map(|line| line.end)
        .last()
        .unwrap_or(input.len());
    let at_end = insertion == input.len();
    let has_final_newline = input.ends_with(b"\n");
    let output_len = input
        .len()
        .checked_add(signature.len())
        .and_then(|length| length.checked_add(6))
        .ok_or(NixCacheFileError::NarinfoTooLarge)?;
    let output_len_u64 =
        u64::try_from(output_len).map_err(|_| NixCacheFileError::NarinfoTooLarge)?;
    if output_len_u64 > MAX_NARINFO_BYTES {
        return Err(NixCacheFileError::NarinfoTooLarge);
    }
    let mut output = Vec::with_capacity(output_len);
    output.extend_from_slice(input.get(..insertion).unwrap_or_default());
    if at_end && !input.is_empty() && !has_final_newline {
        output.push(b'\n');
    }
    output.extend_from_slice(b"Sig: ");
    output.extend_from_slice(signature);
    if !at_end || has_final_newline {
        output.push(b'\n');
    }
    output.extend_from_slice(input.get(insertion..).unwrap_or_default());
    Ok(output)
}

#[derive(Clone, Copy, Debug)]
struct Line {
    start: usize,
    content_end: usize,
    end: usize,
}

impl Line {
    fn content(self, input: &[u8]) -> &[u8] {
        input.get(self.start..self.content_end).unwrap_or_default()
    }

    fn full(self, input: &[u8]) -> &[u8] {
        input.get(self.start..self.end).unwrap_or_default()
    }
}

fn lines(input: &[u8]) -> impl Iterator<Item = Line> + '_ {
    let mut start = 0_usize;
    std::iter::from_fn(move || {
        if start >= input.len() {
            return None;
        }
        let remainder = input.get(start..)?;
        let relative_end = remainder.iter().position(|byte| *byte == b'\n');
        let (content_end, end) = relative_end.map_or((input.len(), input.len()), |relative| {
            let content_end = start.saturating_add(relative);
            (content_end, content_end.saturating_add(1))
        });
        let line = Line {
            start,
            content_end,
            end,
        };
        start = end;
        Some(line)
    })
}

fn open_cache_root(path: &Path) -> Result<OwnedFd, NixCacheFileError> {
    if path.as_os_str().is_empty() {
        return Err(NixCacheFileError::InvalidPath);
    }
    let start = if path.is_absolute() { "/" } else { "." };
    let mut directory = rustix::fs::open(
        start,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                directory = rustix::fs::openat(
                    &directory,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                )
                .map_err(|_| NixCacheFileError::UnsafeLayout)?;
            }
            Component::ParentDir | Component::Prefix(_) => {
                return Err(NixCacheFileError::InvalidPath);
            }
        }
    }
    Ok(directory)
}

fn validate_mutation_directory(directory: &OwnedFd) -> Result<(), NixCacheFileError> {
    let stat = rustix::fs::fstat(directory)?;
    if !directory_metadata_is_safe(
        FileType::from_raw_mode(stat.st_mode),
        stat.st_uid,
        Mode::from_raw_mode(stat.st_mode),
        u128::from(stat.st_nlink),
        rustix::process::geteuid().as_raw(),
    ) {
        return Err(NixCacheFileError::UnsafeLayout);
    }
    Ok(())
}

fn directory_metadata_is_safe(
    file_type: FileType,
    owner: u32,
    mode: Mode,
    links: u128,
    effective_uid: u32,
) -> bool {
    file_type == FileType::Directory
        && owner == effective_uid
        && !mode.intersects(GROUP_OR_OTHER_WRITE)
        && links != 0
}

fn open_or_create_lock(root: &OwnedFd) -> Result<OwnedFd, NixCacheFileError> {
    let create = rustix::fs::openat(
        root,
        CACHE_LOCK_FILE,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        LOCK_MODE,
    );
    match create {
        Ok(lock) => {
            rustix::fs::fchmod(&lock, LOCK_MODE)?;
            rustix::fs::fsync(&lock)?;
            rustix::fs::fsync(root)?;
            validate_lock_descriptor(&lock)?;
            Ok(lock)
        }
        Err(error) if error == rustix::io::Errno::EXIST => {
            let lock = rustix::fs::openat(
                root,
                CACHE_LOCK_FILE,
                OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|_| NixCacheFileError::UnsafeLayout)?;
            validate_lock_descriptor(&lock)?;
            Ok(lock)
        }
        Err(_) => Err(NixCacheFileError::UnsafeLayout),
    }
}

fn validate_lock_descriptor(lock: &OwnedFd) -> Result<(), NixCacheFileError> {
    let stat = rustix::fs::fstat(lock)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || Mode::from_raw_mode(stat.st_mode) != LOCK_MODE
        || stat.st_nlink != 1
    {
        return Err(NixCacheFileError::UnsafeLayout);
    }
    Ok(())
}

fn validate_lock_path(root: &OwnedFd, lock: &OwnedFd) -> Result<(), NixCacheFileError> {
    let descriptor = rustix::fs::fstat(lock)?;
    let path = rustix::fs::statat(root, CACHE_LOCK_FILE, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| NixCacheFileError::UnsafeLayout)?;
    if descriptor.st_dev != path.st_dev || descriptor.st_ino != path.st_ino {
        return Err(NixCacheFileError::UnsafeLayout);
    }
    Ok(())
}

fn read_snapshot_at(
    directory: &OwnedFd,
    name: &OsStr,
) -> Result<NarinfoSnapshot, NixCacheFileError> {
    let path_stat = rustix::fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| NixCacheFileError::UnsafeLayout)?;
    validate_target(&path_stat)?;
    let descriptor = rustix::fs::openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY,
        Mode::empty(),
    )
    .map_err(|_| NixCacheFileError::UnsafeLayout)?;
    let stat = rustix::fs::fstat(&descriptor)?;
    validate_target(&stat)?;
    if !same_filesystem_object(&path_stat, &stat) {
        return Err(NixCacheFileError::Interference);
    }
    let before_size = u64::try_from(stat.st_size).map_err(|_| NixCacheFileError::UnsafeLayout)?;
    if before_size > MAX_NARINFO_BYTES {
        return Err(NixCacheFileError::NarinfoTooLarge);
    }

    let mut file = File::from(descriptor);
    let before_identity = FileIdentity::from_file(&file)?;
    file.seek(SeekFrom::Start(0))?;
    let capacity = usize::try_from(before_size).map_err(|_| NixCacheFileError::NarinfoTooLarge)?;
    let mut bytes = Vec::with_capacity(capacity);
    (&mut file)
        .take(MAX_NARINFO_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)?;
    let bytes_len = u64::try_from(bytes.len()).map_err(|_| NixCacheFileError::NarinfoTooLarge)?;
    if bytes_len > MAX_NARINFO_BYTES {
        return Err(NixCacheFileError::NarinfoTooLarge);
    }
    let after_identity = FileIdentity::from_file(&file)?;
    if before_identity != after_identity || after_identity.size != i128::from(bytes_len) {
        return Err(NixCacheFileError::Interference);
    }
    Ok(NarinfoSnapshot {
        bytes,
        identity: before_identity,
    })
}

fn validate_target(stat: &rustix::fs::Stat) -> Result<(), NixCacheFileError> {
    if !target_metadata_is_safe(
        FileType::from_raw_mode(stat.st_mode),
        stat.st_uid,
        Mode::from_raw_mode(stat.st_mode),
        u128::from(stat.st_nlink),
        rustix::process::geteuid().as_raw(),
    ) {
        return Err(NixCacheFileError::UnsafeLayout);
    }
    Ok(())
}

fn target_metadata_is_safe(
    file_type: FileType,
    owner: u32,
    mode: Mode,
    links: u128,
    effective_uid: u32,
) -> bool {
    file_type == FileType::RegularFile
        && owner == effective_uid
        && !mode.intersects(GROUP_OR_OTHER_WRITE)
        && links == 1
}

fn same_filesystem_object(left: &rustix::fs::Stat, right: &rustix::fs::Stat) -> bool {
    left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
        && FileType::from_raw_mode(left.st_mode) == FileType::from_raw_mode(right.st_mode)
        && left.st_uid == right.st_uid
        && left.st_gid == right.st_gid
        && left.st_mode == right.st_mode
        && left.st_nlink == right.st_nlink
}

fn sync_file(file: &File) -> Result<(), NixCacheFileError> {
    rustix::fs::fsync(file)?;
    #[cfg(target_os = "macos")]
    rustix::fs::fcntl_fullfsync(file)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::fs;
    use std::io::{BufRead as _, BufReader};
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::os::unix::net::UnixListener;
    use std::os::unix::process::ExitStatusExt as _;
    use std::process::{Child, Command, ExitStatus, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;

    use serde::Deserialize;

    use super::*;

    const NARINFO_CORPUS: &str =
        include_str!("../../../basil-tests/fixtures/nix-cache-signing/narinfo-fidelity.json");
    const PROCESS_HELPER_ENV: &str = "BASIL_NIX_CACHE_COMMIT_HELPER";
    const PROCESS_ROOT_ENV: &str = "BASIL_NIX_CACHE_COMMIT_ROOT";
    const PROCESS_STAGE_ENV: &str = "BASIL_NIX_CACHE_COMMIT_STAGE";
    const PROCESS_OCCURRENCE_ENV: &str = "BASIL_NIX_CACHE_COMMIT_OCCURRENCE";
    const PROCESS_TARGETS_ENV: &str = "BASIL_NIX_CACHE_COMMIT_TARGETS";
    const PROCESS_DEADLINE: Duration = Duration::from_secs(10);
    const TEST_NARINFO: &[u8] =
        b"NarHash: sha256:09ymwqf5i9q7d4dm7x4pjjcqqj0qrcp5lnznbh42gfsci5hcbqqm\n";
    const TEST_SIGNATURE: &str = "crash-key:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    #[derive(Debug, Deserialize)]
    struct Corpus {
        vectors: Vec<Vector>,
    }

    #[derive(Debug, Deserialize)]
    struct Vector {
        name: String,
        input: String,
        operation: Operation,
        expected: Expected,
    }

    #[derive(Debug, Deserialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    enum Operation {
        Add {
            signature: String,
        },
        Replace {
            old_key_names: Vec<String>,
            signature: String,
        },
        Remove {
            key_names: Vec<String>,
        },
    }

    #[derive(Debug, Deserialize)]
    struct Expected {
        status: String,
        output: Option<String>,
        reason: Option<String>,
    }

    #[derive(Debug)]
    struct TemporaryDirectory(std::path::PathBuf);

    impl TemporaryDirectory {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            for _ in 0..16 {
                let suffix = NEXT.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "basil-nix-cache-file-{}-{suffix}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("temporary directory: {error}"),
                }
            }
            panic!("temporary directory collision limit exhausted")
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn temporary_directory() -> TemporaryDirectory {
        TemporaryDirectory::new()
    }

    fn substitute_temporary(
        directory: &OwnedFd,
        temporary_name: &str,
    ) -> Result<(), NixCacheFileError> {
        let original = rustix::fs::statat(directory, temporary_name, AtFlags::SYMLINK_NOFOLLOW)?;
        let captured = format!("{temporary_name}.captured");
        rustix::fs::renameat(directory, temporary_name, directory, captured.as_str())?;
        let replacement = rustix::fs::openat(
            directory,
            temporary_name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            LOCK_MODE,
        )?;
        if original.st_uid != rustix::process::geteuid().as_raw()
            || original.st_gid != rustix::process::getegid().as_raw()
        {
            rustix::fs::fchown(
                &replacement,
                Some(rustix::process::Uid::from_raw(original.st_uid)),
                Some(rustix::process::Gid::from_raw(original.st_gid)),
            )?;
        }
        rustix::fs::fchmod(&replacement, Mode::from_raw_mode(original.st_mode & 0o7777))?;
        Ok(())
    }

    fn noncooperating_target_write(
        directory: &OwnedFd,
        name: &OsStr,
    ) -> Result<(), NixCacheFileError> {
        let descriptor = rustix::fs::openat(
            directory,
            name,
            OFlags::WRONLY | OFlags::TRUNC | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )?;
        let mut file = File::from(descriptor);
        file.write_all(
            b"NarHash: sha256:09ymwqf5i9q7d4dm7x4pjjcqqj0qrcp5lnznbh42gfsci5hcbqqm\nX-Writer: ignored-lock\n",
        )?;
        sync_file(&file)
    }

    fn assert_no_temporary(directory: &Path) {
        assert!(temporary_names(directory).is_empty());
    }

    fn temporary_names(directory: &Path) -> Vec<OsString> {
        let mut names = fs::read_dir(directory)
            .unwrap_or_else(|error| panic!("read directory: {error}"))
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .filter(|name| name.to_string_lossy().starts_with(".basil-narinfo-tmp-"))
            .collect::<Vec<_>>();
        names.sort_unstable();
        names
    }

    fn apply_vector(vector: &Vector) -> Result<NarinfoEdit, NixCacheFileError> {
        let old_names;
        let key_names;
        let mutation = match &vector.operation {
            Operation::Add { signature } => NarinfoMutation::Add { signature },
            Operation::Replace {
                old_key_names,
                signature,
            } => {
                old_names = old_key_names.iter().map(String::as_str).collect::<Vec<_>>();
                NarinfoMutation::Replace {
                    old_key_names: &old_names,
                    signature,
                }
            }
            Operation::Remove { key_names: names } => {
                key_names = names.iter().map(String::as_str).collect::<Vec<_>>();
                NarinfoMutation::Remove {
                    key_names: &key_names,
                }
            }
        };
        edit_narinfo(vector.input.as_bytes(), mutation)
    }

    fn stage_barrier(stage: CommitStage) {
        static HITS: AtomicU64 = AtomicU64::new(0);
        let Ok(expected) = std::env::var(PROCESS_STAGE_ENV) else {
            return;
        };
        if expected != stage.name() {
            return;
        }
        let occurrence = std::env::var(PROCESS_OCCURRENCE_ENV)
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(1);
        if HITS.fetch_add(1, Ordering::SeqCst).saturating_add(1) != occurrence {
            return;
        }
        println!("BASIL_COMMIT_BARRIER={}", stage.name());
        std::io::stdout()
            .flush()
            .unwrap_or_else(|error| panic!("flush barrier: {error}"));
        let mut release = [0_u8; 1];
        std::io::stdin()
            .read_exact(&mut release)
            .unwrap_or_else(|error| panic!("wait for barrier release: {error}"));
    }

    struct ChildGuard {
        child: Option<Child>,
    }

    impl ChildGuard {
        fn new(child: Child) -> Self {
            Self { child: Some(child) }
        }

        fn child_mut(&mut self) -> &mut Child {
            self.child
                .as_mut()
                .unwrap_or_else(|| panic!("child already reaped"))
        }

        fn signal_and_wait(&mut self, signal: rustix::process::Signal) -> ExitStatus {
            let mut child = self
                .child
                .take()
                .unwrap_or_else(|| panic!("child already reaped"));
            let raw_pid = i32::try_from(child.id())
                .unwrap_or_else(|error| panic!("child pid does not fit i32: {error}"));
            let pid = rustix::process::Pid::from_raw(raw_pid)
                .unwrap_or_else(|| panic!("child pid must be nonzero"));
            rustix::process::kill_process(pid, signal)
                .unwrap_or_else(|error| panic!("signal mutation child: {error}"));

            let (sender, receiver) = mpsc::sync_channel(1);
            let _waiter = std::thread::spawn(move || {
                let _ = sender.send(child.wait());
            });
            match receiver.recv_timeout(PROCESS_DEADLINE) {
                Ok(result) => {
                    result.unwrap_or_else(|error| panic!("wait for mutation child: {error}"))
                }
                Err(error) => {
                    let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
                    match receiver.recv_timeout(PROCESS_DEADLINE) {
                        Ok(_) => panic!("mutation child exceeded exit deadline: {error}"),
                        Err(reap_error) => panic!(
                            "mutation child could not be reaped after SIGKILL: {error}; {reap_error}"
                        ),
                    }
                }
            }
        }
    }

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if let Some(mut child) = self.child.take() {
                let _ = child.kill();
                let (sender, receiver) = mpsc::sync_channel(1);
                let _waiter = std::thread::spawn(move || {
                    let _ = sender.send(child.wait());
                });
                let _ = receiver.recv_timeout(PROCESS_DEADLINE);
            }
        }
    }

    struct BarrierChild {
        process: ChildGuard,
    }

    impl BarrierChild {
        fn kill_and_assert_sigkill(&mut self) {
            let status = self.process.signal_and_wait(rustix::process::Signal::KILL);
            assert_eq!(
                status.signal(),
                Some(rustix::process::Signal::KILL.as_raw())
            );
            assert_eq!(status.code(), None);
        }
    }

    fn spawn_barrier_child(
        root: &Path,
        stage: CommitStage,
        occurrence: u64,
        targets: usize,
    ) -> BarrierChild {
        let executable = std::env::current_exe()
            .unwrap_or_else(|error| panic!("locate current test executable: {error}"));
        let child = Command::new(executable)
            .arg("--exact")
            .arg("core::nix_cache_file::tests::process_mutation_child")
            .arg("--nocapture")
            .env(PROCESS_HELPER_ENV, "1")
            .env(PROCESS_ROOT_ENV, root)
            .env(PROCESS_STAGE_ENV, stage.name())
            .env(PROCESS_OCCURRENCE_ENV, occurrence.to_string())
            .env(PROCESS_TARGETS_ENV, targets.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap_or_else(|error| panic!("spawn mutation child: {error}"));
        let mut process = ChildGuard::new(child);
        let stdout = process
            .child_mut()
            .stdout
            .take()
            .unwrap_or_else(|| panic!("mutation child stdout must be piped"));
        let (sender, receiver) = mpsc::sync_channel(8);
        let _reader = std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        let deadline = Instant::now()
            .checked_add(PROCESS_DEADLINE)
            .unwrap_or_else(|| panic!("process deadline overflow"));
        let expected = format!("BASIL_COMMIT_BARRIER={}", stage.name());
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "mutation child barrier timed out");
            match receiver.recv_timeout(remaining) {
                Ok(Ok(line)) if line == expected => break,
                Ok(Ok(_)) => {}
                Ok(Err(error)) => panic!("read mutation child: {error}"),
                Err(error) => panic!("mutation child barrier failed: {error}"),
            }
        }
        BarrierChild { process }
    }

    fn count_test_signatures(bytes: &[u8]) -> usize {
        bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| *line == format!("Sig: {TEST_SIGNATURE}").as_bytes())
            .count()
    }

    fn rerun_target(locked: &LockedCacheRoot, index: usize) -> NarinfoCommit {
        locked
            .mutate_narinfo(
                Path::new(&format!("path-{index}.narinfo")),
                NarinfoMutation::Add {
                    signature: TEST_SIGNATURE,
                },
            )
            .unwrap_or_else(|error| panic!("rerun target {index}: {error}"))
    }

    fn prepare_process_targets(directory: &Path, count: usize) {
        for index in 0..count {
            fs::write(
                directory.join(format!("path-{index}.narinfo")),
                TEST_NARINFO,
            )
            .unwrap_or_else(|error| panic!("write process target {index}: {error}"));
        }
    }

    #[test]
    fn process_mutation_child() {
        if std::env::var_os(PROCESS_HELPER_ENV).is_none() {
            return;
        }
        let root = std::env::var_os(PROCESS_ROOT_ENV).map_or_else(
            || panic!("mutation helper needs cache root"),
            std::path::PathBuf::from,
        );
        let targets = std::env::var(PROCESS_TARGETS_ENV)
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(1);
        let locked = LockedCacheRoot::try_acquire(&root)
            .unwrap_or_else(|error| panic!("mutation helper lock: {error}"));
        for index in 0..targets {
            let relative = format!("path-{index}.narinfo");
            let snapshot = locked
                .read_narinfo(Path::new(&relative))
                .unwrap_or_else(|error| panic!("mutation helper read: {error}"));
            let replacement = match edit_narinfo(
                snapshot.bytes(),
                NarinfoMutation::Add {
                    signature: TEST_SIGNATURE,
                },
            )
            .unwrap_or_else(|error| panic!("mutation helper edit: {error}"))
            {
                NarinfoEdit::Changed(bytes) => bytes,
                NarinfoEdit::Unchanged => continue,
            };
            let outcome = locked
                .commit_narinfo_with_hooks(
                    Path::new(&relative),
                    &snapshot,
                    &replacement,
                    CommitHooks {
                        stage: Some(stage_barrier),
                        ..CommitHooks::default()
                    },
                )
                .unwrap_or_else(|error| panic!("mutation helper commit: {error}"));
            assert!(matches!(outcome, NarinfoCommit::Written));
        }
    }

    #[test]
    fn normative_narinfo_fidelity_corpus() {
        let corpus: Corpus = serde_json::from_str(NARINFO_CORPUS)
            .unwrap_or_else(|error| panic!("parse narinfo corpus: {error}"));
        for vector in &corpus.vectors {
            let actual = apply_vector(vector);
            if vector.expected.status == "accept" {
                let expected = vector
                    .expected
                    .output
                    .as_ref()
                    .unwrap_or_else(|| panic!("{}: accepted vector has output", vector.name));
                let edit = actual
                    .unwrap_or_else(|error| panic!("{}: unexpected error: {error}", vector.name));
                let bytes = match edit {
                    NarinfoEdit::Unchanged => vector.input.as_bytes(),
                    NarinfoEdit::Changed(ref output) => output.as_slice(),
                };
                assert_eq!(bytes, expected.as_bytes(), "{}", vector.name);
            } else {
                let error = actual
                    .err()
                    .unwrap_or_else(|| panic!("{}: expected rejection", vector.name));
                match vector.expected.reason.as_deref() {
                    Some("SIGNATURE_CONFLICT") => {
                        assert!(matches!(error, NixCacheFileError::SignatureConflict));
                    }
                    Some(reason) => assert_eq!(
                        error.to_string(),
                        format!("invalid Nix narinfo: {reason}"),
                        "{}",
                        vector.name
                    ),
                    None => panic!("{}: rejection has no reason", vector.name),
                }
            }
        }
    }

    #[test]
    fn lock_is_stable_and_exclusive() {
        let directory = temporary_directory();
        let first = LockedCacheRoot::try_acquire(directory.path())
            .unwrap_or_else(|error| panic!("first lock: {error}"));
        assert!(first.holds_lock());
        assert!(matches!(
            LockedCacheRoot::try_acquire(directory.path()),
            Err(NixCacheFileError::LockBusy)
        ));
        assert!(matches!(
            LockedCacheRoot::acquire(directory.path(), Duration::ZERO),
            Err(NixCacheFileError::LockTimeout)
        ));
        drop(first);
        LockedCacheRoot::try_acquire(directory.path())
            .unwrap_or_else(|error| panic!("lock after release: {error}"));
        let metadata = fs::metadata(directory.path().join(CACHE_LOCK_FILE))
            .unwrap_or_else(|error| panic!("lock metadata: {error}"));
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 1);
    }

    #[test]
    fn repeated_lock_interrupts_observe_deadline() {
        let attempts = Cell::new(0_u8);
        let result = acquire_flock_with(
            Some(Instant::now()),
            || {
                attempts.set(attempts.get().saturating_add(1));
                Err(rustix::io::Errno::INTR)
            },
            |_| panic!("interrupted lock attempt must not sleep"),
        );
        assert!(matches!(result, Err(NixCacheFileError::LockTimeout)));
        assert_eq!(attempts.get(), 1);
    }

    #[test]
    fn atomic_commit_preserves_mode_owner_and_unknown_bytes() {
        let directory = temporary_directory();
        let path = directory.path().join("example.narinfo");
        let input = b"StorePath: /nix/store/example\nNarHash: sha256:09ymwqf5i9q7d4dm7x4pjjcqqj0qrcp5lnznbh42gfsci5hcbqqm\nNarSize: 1\nReferences: \nX-Unknown:\tkeep  me\n";
        fs::write(&path, input).unwrap_or_else(|error| panic!("write target: {error}"));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640))
            .unwrap_or_else(|error| panic!("chmod target: {error}"));
        let before = fs::metadata(&path).unwrap_or_else(|error| panic!("metadata: {error}"));
        let locked = LockedCacheRoot::try_acquire(directory.path())
            .unwrap_or_else(|error| panic!("lock: {error}"));
        assert!(matches!(
            locked
                .mutate_narinfo(
                    Path::new("example.narinfo"),
                    NarinfoMutation::Add {
                        signature: "cache:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
                    },
                )
                .unwrap_or_else(|error| panic!("mutate: {error}")),
            NarinfoCommit::Written
        ));
        let after = fs::metadata(&path).unwrap_or_else(|error| panic!("metadata: {error}"));
        assert_eq!(after.mode() & 0o7777, before.mode() & 0o7777);
        assert_eq!(after.uid(), before.uid());
        assert_eq!(after.gid(), before.gid());
        let output = fs::read(&path).unwrap_or_else(|error| panic!("read target: {error}"));
        assert!(output.starts_with(input));
        assert!(
            output
                .windows(b"X-Unknown:\tkeep  me".len())
                .any(|window| { window == b"X-Unknown:\tkeep  me" })
        );
    }

    #[test]
    fn temporary_path_substitution_fails_before_rename() {
        let directory = temporary_directory();
        let path = directory.path().join("example.narinfo");
        let input = b"NarHash: sha256:09ymwqf5i9q7d4dm7x4pjjcqqj0qrcp5lnznbh42gfsci5hcbqqm\n";
        let replacement = b"NarHash: sha256:09ymwqf5i9q7d4dm7x4pjjcqqj0qrcp5lnznbh42gfsci5hcbqqm\nX: replacement\n";
        fs::write(&path, input).unwrap_or_else(|error| panic!("write target: {error}"));
        let locked = LockedCacheRoot::try_acquire(directory.path())
            .unwrap_or_else(|error| panic!("lock: {error}"));
        let snapshot = locked
            .read_narinfo(Path::new("example.narinfo"))
            .unwrap_or_else(|error| panic!("snapshot: {error}"));
        let result = locked.commit_narinfo_with_hooks(
            Path::new("example.narinfo"),
            &snapshot,
            replacement,
            CommitHooks {
                before_temporary_binding: Some(substitute_temporary),
                ..CommitHooks::default()
            },
        );
        assert!(matches!(result, Err(NixCacheFileError::Interference)));
        assert_eq!(
            fs::read(&path).unwrap_or_else(|error| panic!("read target: {error}")),
            input
        );
        for entry in fs::read_dir(directory.path())
            .unwrap_or_else(|error| panic!("read directory: {error}"))
            .filter_map(Result::ok)
        {
            if entry.file_name().to_string_lossy().ends_with(".captured") {
                fs::remove_file(entry.path())
                    .unwrap_or_else(|error| panic!("remove captured temporary: {error}"));
            }
        }
        assert_no_temporary(directory.path());
    }

    #[test]
    fn pre_rename_sync_failure_leaves_target_unchanged_and_cleans_temp() {
        let directory = temporary_directory();
        let path = directory.path().join("example.narinfo");
        let input = b"NarHash: sha256:09ymwqf5i9q7d4dm7x4pjjcqqj0qrcp5lnznbh42gfsci5hcbqqm\n";
        let replacement = b"NarHash: sha256:09ymwqf5i9q7d4dm7x4pjjcqqj0qrcp5lnznbh42gfsci5hcbqqm\nX: replacement\n";
        fs::write(&path, input).unwrap_or_else(|error| panic!("write target: {error}"));
        let locked = LockedCacheRoot::try_acquire(directory.path())
            .unwrap_or_else(|error| panic!("lock: {error}"));
        let snapshot = locked
            .read_narinfo(Path::new("example.narinfo"))
            .unwrap_or_else(|error| panic!("snapshot: {error}"));
        let result = locked.commit_narinfo_with_hooks(
            Path::new("example.narinfo"),
            &snapshot,
            replacement,
            CommitHooks {
                failure: Some(InjectedCommitFailure::FileSync),
                ..CommitHooks::default()
            },
        );
        assert!(matches!(result, Err(NixCacheFileError::Io(_))));
        assert_eq!(
            fs::read(&path).unwrap_or_else(|error| panic!("read target: {error}")),
            input
        );
        assert_no_temporary(directory.path());
    }

    #[test]
    fn write_and_rename_failures_leave_old_target_and_clean_temp() {
        for hooks in [
            CommitHooks {
                failure: Some(InjectedCommitFailure::AfterWrite),
                ..CommitHooks::default()
            },
            CommitHooks {
                failure: Some(InjectedCommitFailure::Rename),
                ..CommitHooks::default()
            },
        ] {
            let directory = temporary_directory();
            let path = directory.path().join("example.narinfo");
            fs::write(&path, TEST_NARINFO).unwrap_or_else(|error| panic!("write target: {error}"));
            let locked = LockedCacheRoot::try_acquire(directory.path())
                .unwrap_or_else(|error| panic!("lock: {error}"));
            let snapshot = locked
                .read_narinfo(Path::new("example.narinfo"))
                .unwrap_or_else(|error| panic!("snapshot: {error}"));
            let replacement = match edit_narinfo(
                snapshot.bytes(),
                NarinfoMutation::Add {
                    signature: TEST_SIGNATURE,
                },
            )
            .unwrap_or_else(|error| panic!("edit: {error}"))
            {
                NarinfoEdit::Changed(bytes) => bytes,
                NarinfoEdit::Unchanged => panic!("test mutation must change target"),
            };
            assert!(matches!(
                locked.commit_narinfo_with_hooks(
                    Path::new("example.narinfo"),
                    &snapshot,
                    &replacement,
                    hooks,
                ),
                Err(NixCacheFileError::Io(_))
            ));
            assert_eq!(
                fs::read(&path).unwrap_or_else(|error| panic!("read target: {error}")),
                TEST_NARINFO
            );
            assert_no_temporary(directory.path());
        }
    }

    #[test]
    fn post_rename_sync_failure_reports_committed_uncertain() {
        let directory = temporary_directory();
        let path = directory.path().join("example.narinfo");
        let input = b"NarHash: sha256:09ymwqf5i9q7d4dm7x4pjjcqqj0qrcp5lnznbh42gfsci5hcbqqm\n";
        let replacement = b"NarHash: sha256:09ymwqf5i9q7d4dm7x4pjjcqqj0qrcp5lnznbh42gfsci5hcbqqm\nX: replacement\n";
        fs::write(&path, input).unwrap_or_else(|error| panic!("write target: {error}"));
        let locked = LockedCacheRoot::try_acquire(directory.path())
            .unwrap_or_else(|error| panic!("lock: {error}"));
        let snapshot = locked
            .read_narinfo(Path::new("example.narinfo"))
            .unwrap_or_else(|error| panic!("snapshot: {error}"));
        let result = locked
            .commit_narinfo_with_hooks(
                Path::new("example.narinfo"),
                &snapshot,
                replacement,
                CommitHooks {
                    failure: Some(InjectedCommitFailure::DirectorySync),
                    ..CommitHooks::default()
                },
            )
            .unwrap_or_else(|error| panic!("commit result: {error}"));
        assert!(matches!(
            result,
            NarinfoCommit::CommittedDurabilityUncertain { .. }
        ));
        assert_eq!(
            fs::read(&path).unwrap_or_else(|error| panic!("read target: {error}")),
            replacement
        );
        assert_no_temporary(directory.path());
    }

    #[test]
    fn every_commit_boundary_survives_sigkill_and_idempotent_rerun() {
        let stages = [
            CommitStage::BeforeWrite,
            CommitStage::AfterWrite,
            CommitStage::BeforeFileSync,
            CommitStage::AfterFileSync,
            CommitStage::BeforeRename,
            CommitStage::AfterRename,
            CommitStage::BeforeDirectorySync,
            CommitStage::AfterDirectorySync,
        ];
        for stage in stages {
            let directory = temporary_directory();
            prepare_process_targets(directory.path(), 1);
            let mut child = spawn_barrier_child(directory.path(), stage, 1, 1);
            let held_lock = fs::metadata(directory.path().join(CACHE_LOCK_FILE))
                .unwrap_or_else(|error| panic!("held lock metadata: {error}"));
            assert!(matches!(
                LockedCacheRoot::try_acquire(directory.path()),
                Err(NixCacheFileError::LockBusy)
            ));
            child.kill_and_assert_sigkill();

            let before_rerun = fs::read(directory.path().join("path-0.narinfo"))
                .unwrap_or_else(|error| panic!("read interrupted target: {error}"));
            let renamed = matches!(
                stage,
                CommitStage::AfterRename
                    | CommitStage::BeforeDirectorySync
                    | CommitStage::AfterDirectorySync
            );
            assert_eq!(count_test_signatures(&before_rerun), usize::from(renamed));
            let stale_temporaries = temporary_names(directory.path());
            assert_eq!(stale_temporaries.len(), usize::from(!renamed));

            let locked = LockedCacheRoot::try_acquire(directory.path())
                .unwrap_or_else(|error| panic!("lock after SIGKILL: {error}"));
            let stable_lock = fs::metadata(directory.path().join(CACHE_LOCK_FILE))
                .unwrap_or_else(|error| panic!("stable lock metadata: {error}"));
            assert_eq!(held_lock.dev(), stable_lock.dev());
            assert_eq!(held_lock.ino(), stable_lock.ino());
            let rerun = rerun_target(&locked, 0);
            assert!(matches!(
                (renamed, rerun),
                (true, NarinfoCommit::Unchanged) | (false, NarinfoCommit::Written)
            ));
            let recovered = fs::read(directory.path().join("path-0.narinfo"))
                .unwrap_or_else(|error| panic!("read recovered target: {error}"));
            assert_eq!(count_test_signatures(&recovered), 1);
            assert_eq!(temporary_names(directory.path()), stale_temporaries);
        }
    }

    #[test]
    fn sigkill_partial_batch_releases_lock_and_rerun_has_no_duplicates() {
        let directory = temporary_directory();
        prepare_process_targets(directory.path(), 2);
        let mut child = spawn_barrier_child(directory.path(), CommitStage::BeforeRename, 2, 2);
        assert_eq!(
            count_test_signatures(
                &fs::read(directory.path().join("path-0.narinfo"))
                    .unwrap_or_else(|error| panic!("read first target: {error}"))
            ),
            1
        );
        assert_eq!(
            fs::read(directory.path().join("path-1.narinfo"))
                .unwrap_or_else(|error| panic!("read second target: {error}")),
            TEST_NARINFO
        );
        child.kill_and_assert_sigkill();
        assert_eq!(temporary_names(directory.path()).len(), 1);

        let locked = LockedCacheRoot::try_acquire(directory.path())
            .unwrap_or_else(|error| panic!("lock after SIGKILL: {error}"));
        assert!(matches!(rerun_target(&locked, 0), NarinfoCommit::Unchanged));
        assert!(matches!(rerun_target(&locked, 1), NarinfoCommit::Written));
        for index in 0..2 {
            let recovered = fs::read(directory.path().join(format!("path-{index}.narinfo")))
                .unwrap_or_else(|error| panic!("read recovered target {index}: {error}"));
            assert_eq!(count_test_signatures(&recovered), 1);
        }
        assert_eq!(temporary_names(directory.path()).len(), 1);
    }

    #[test]
    fn cleanup_sync_failure_has_distinct_status() {
        let directory = temporary_directory();
        let path = directory.path().join("example.narinfo");
        let input = b"NarHash: sha256:09ymwqf5i9q7d4dm7x4pjjcqqj0qrcp5lnznbh42gfsci5hcbqqm\n";
        let replacement = b"NarHash: sha256:09ymwqf5i9q7d4dm7x4pjjcqqj0qrcp5lnznbh42gfsci5hcbqqm\nX: replacement\n";
        fs::write(&path, input).unwrap_or_else(|error| panic!("write target: {error}"));
        let locked = LockedCacheRoot::try_acquire(directory.path())
            .unwrap_or_else(|error| panic!("lock: {error}"));
        let snapshot = locked
            .read_narinfo(Path::new("example.narinfo"))
            .unwrap_or_else(|error| panic!("snapshot: {error}"));
        let result = locked.commit_narinfo_with_hooks(
            Path::new("example.narinfo"),
            &snapshot,
            replacement,
            CommitHooks {
                failure: Some(InjectedCommitFailure::FileSync),
                fail_cleanup_sync: true,
                ..CommitHooks::default()
            },
        );
        assert!(matches!(
            result,
            Err(NixCacheFileError::CleanupDurabilityUncertain(_))
        ));
        assert_eq!(
            fs::read(&path).unwrap_or_else(|error| panic!("read target: {error}")),
            input
        );
        assert_no_temporary(directory.path());
    }

    #[test]
    fn same_bytes_target_substitution_fails_closed() {
        let directory = temporary_directory();
        let path = directory.path().join("example.narinfo");
        let input = b"NarHash: sha256:09ymwqf5i9q7d4dm7x4pjjcqqj0qrcp5lnznbh42gfsci5hcbqqm\n";
        fs::write(&path, input).unwrap_or_else(|error| panic!("write target: {error}"));
        let locked = LockedCacheRoot::try_acquire(directory.path())
            .unwrap_or_else(|error| panic!("lock: {error}"));
        let snapshot = locked
            .read_narinfo(Path::new("example.narinfo"))
            .unwrap_or_else(|error| panic!("snapshot: {error}"));
        fs::rename(&path, directory.path().join("old.narinfo"))
            .unwrap_or_else(|error| panic!("rename target: {error}"));
        fs::write(&path, input).unwrap_or_else(|error| panic!("substitute target: {error}"));
        assert!(matches!(
            locked.commit_narinfo(
                Path::new("example.narinfo"),
                &snapshot,
                b"NarHash: sha256:09ymwqf5i9q7d4dm7x4pjjcqqj0qrcp5lnznbh42gfsci5hcbqqm\nX: replacement\n",
            ),
            Err(NixCacheFileError::Interference)
        ));
        assert_eq!(
            fs::read(&path).unwrap_or_else(|error| panic!("read target: {error}")),
            input
        );
    }

    #[test]
    fn noncooperating_writer_before_final_comparison_fails_closed() {
        let directory = temporary_directory();
        let path = directory.path().join("example.narinfo");
        fs::write(&path, TEST_NARINFO).unwrap_or_else(|error| panic!("write target: {error}"));
        let locked = LockedCacheRoot::try_acquire(directory.path())
            .unwrap_or_else(|error| panic!("lock: {error}"));
        let snapshot = locked
            .read_narinfo(Path::new("example.narinfo"))
            .unwrap_or_else(|error| panic!("snapshot: {error}"));
        let replacement = match edit_narinfo(
            snapshot.bytes(),
            NarinfoMutation::Add {
                signature: TEST_SIGNATURE,
            },
        )
        .unwrap_or_else(|error| panic!("edit: {error}"))
        {
            NarinfoEdit::Changed(bytes) => bytes,
            NarinfoEdit::Unchanged => panic!("test mutation must change target"),
        };
        assert!(matches!(
            locked.commit_narinfo_with_hooks(
                Path::new("example.narinfo"),
                &snapshot,
                &replacement,
                CommitHooks {
                    before_final_comparison: Some(noncooperating_target_write),
                    ..CommitHooks::default()
                },
            ),
            Err(NixCacheFileError::Interference)
        ));
        let writer_bytes = fs::read(&path)
            .unwrap_or_else(|error| panic!("read noncooperating writer bytes: {error}"));
        assert!(writer_bytes.ends_with(b"X-Writer: ignored-lock\n"));
        assert_eq!(count_test_signatures(&writer_bytes), 0);
        assert_no_temporary(directory.path());
    }

    #[test]
    fn changed_target_content_fails_closed() {
        let directory = temporary_directory();
        let path = directory.path().join("example.narinfo");
        let input = b"NarHash: sha256:09ymwqf5i9q7d4dm7x4pjjcqqj0qrcp5lnznbh42gfsci5hcbqqm\n";
        fs::write(&path, input).unwrap_or_else(|error| panic!("write target: {error}"));
        let locked = LockedCacheRoot::try_acquire(directory.path())
            .unwrap_or_else(|error| panic!("lock: {error}"));
        let snapshot = locked
            .read_narinfo(Path::new("example.narinfo"))
            .unwrap_or_else(|error| panic!("snapshot: {error}"));
        let changed =
            b"NarHash: sha256:09ymwqf5i9q7d4dm7x4pjjcqqj0qrcp5lnznbh42gfsci5hcbqqm\nX: changed\n";
        fs::write(&path, changed).unwrap_or_else(|error| panic!("change target: {error}"));
        assert!(matches!(
            locked.commit_narinfo(Path::new("example.narinfo"), &snapshot, input),
            Err(NixCacheFileError::Interference)
        ));
        assert_eq!(
            fs::read(&path).unwrap_or_else(|error| panic!("read target: {error}")),
            changed
        );
    }

    #[test]
    fn group_writable_cache_root_fails_closed() {
        let directory = temporary_directory();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o770))
            .unwrap_or_else(|error| panic!("chmod root: {error}"));
        assert!(matches!(
            LockedCacheRoot::try_acquire(directory.path()),
            Err(NixCacheFileError::UnsafeLayout)
        ));
    }

    #[test]
    fn unsafe_nested_parent_metadata_fails_closed() {
        let directory = temporary_directory();
        let nested = directory.path().join("nested");
        fs::create_dir(&nested).unwrap_or_else(|error| panic!("create nested: {error}"));
        fs::write(
            nested.join("example.narinfo"),
            b"NarHash: sha256:09ymwqf5i9q7d4dm7x4pjjcqqj0qrcp5lnznbh42gfsci5hcbqqm\n",
        )
        .unwrap_or_else(|error| panic!("write target: {error}"));
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o770))
            .unwrap_or_else(|error| panic!("chmod nested: {error}"));
        let locked = LockedCacheRoot::try_acquire(directory.path())
            .unwrap_or_else(|error| panic!("lock: {error}"));
        assert!(matches!(
            locked.read_narinfo(Path::new("nested/example.narinfo")),
            Err(NixCacheFileError::UnsafeLayout)
        ));

        let effective_uid = rustix::process::geteuid().as_raw();
        assert!(!directory_metadata_is_safe(
            FileType::Directory,
            effective_uid.wrapping_add(1),
            Mode::from_raw_mode(0o755),
            1,
            effective_uid,
        ));
    }

    #[test]
    fn writable_and_hardlinked_targets_fail_closed() {
        let directory = temporary_directory();
        let writable = directory.path().join("writable.narinfo");
        let linked = directory.path().join("linked.narinfo");
        let second_link = directory.path().join("second-link.narinfo");
        let input = b"NarHash: sha256:09ymwqf5i9q7d4dm7x4pjjcqqj0qrcp5lnznbh42gfsci5hcbqqm\n";
        fs::write(&writable, input).unwrap_or_else(|error| panic!("write target: {error}"));
        fs::set_permissions(&writable, fs::Permissions::from_mode(0o660))
            .unwrap_or_else(|error| panic!("chmod target: {error}"));
        fs::write(&linked, input).unwrap_or_else(|error| panic!("write linked: {error}"));
        fs::hard_link(&linked, &second_link)
            .unwrap_or_else(|error| panic!("hard link target: {error}"));
        let locked = LockedCacheRoot::try_acquire(directory.path())
            .unwrap_or_else(|error| panic!("lock: {error}"));
        assert!(matches!(
            locked.read_narinfo(Path::new("writable.narinfo")),
            Err(NixCacheFileError::UnsafeLayout)
        ));
        assert!(matches!(
            locked.read_narinfo(Path::new("linked.narinfo")),
            Err(NixCacheFileError::UnsafeLayout)
        ));
    }

    #[test]
    fn socket_and_device_metadata_fail_before_read() {
        let directory = temporary_directory();
        let socket_path = directory.path().join("publisher.socket");
        let _listener = UnixListener::bind(&socket_path)
            .unwrap_or_else(|error| panic!("bind test socket: {error}"));
        let locked = LockedCacheRoot::try_acquire(directory.path())
            .unwrap_or_else(|error| panic!("lock: {error}"));
        assert!(matches!(
            locked.read_narinfo(Path::new("publisher.socket")),
            Err(NixCacheFileError::UnsafeLayout)
        ));
        let effective_uid = rustix::process::geteuid().as_raw();
        for file_type in [FileType::CharacterDevice, FileType::BlockDevice] {
            assert!(!target_metadata_is_safe(
                file_type,
                effective_uid,
                Mode::from_raw_mode(0o600),
                1,
                effective_uid,
            ));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fifo_is_rejected_without_blocking() {
        let directory = temporary_directory();
        let root = rustix::fs::open(
            directory.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .unwrap_or_else(|error| panic!("open test root: {error}"));
        rustix::fs::mkfifoat(&root, "publisher.fifo", Mode::from_raw_mode(0o600))
            .unwrap_or_else(|error| panic!("create fifo: {error}"));
        let locked = LockedCacheRoot::try_acquire(directory.path())
            .unwrap_or_else(|error| panic!("lock: {error}"));
        let started = Instant::now();
        assert!(matches!(
            locked.read_narinfo(Path::new("publisher.fifo")),
            Err(NixCacheFileError::UnsafeLayout)
        ));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn symlink_roots_targets_and_traversal_fail_closed() {
        let directory = temporary_directory();
        let real = directory.path().join("real");
        fs::create_dir(&real).unwrap_or_else(|error| panic!("create root: {error}"));
        let linked_root = directory.path().join("linked-root");
        symlink(&real, &linked_root).unwrap_or_else(|error| panic!("link root: {error}"));
        assert!(matches!(
            LockedCacheRoot::try_acquire(&linked_root),
            Err(NixCacheFileError::UnsafeLayout)
        ));

        let locked = LockedCacheRoot::try_acquire(&real)
            .unwrap_or_else(|error| panic!("lock real root: {error}"));
        fs::write(
            real.join("outside.narinfo"),
            b"NarHash: sha256:09ymwqf5i9q7d4dm7x4pjjcqqj0qrcp5lnznbh42gfsci5hcbqqm\n",
        )
        .unwrap_or_else(|error| panic!("write outside: {error}"));
        symlink("outside.narinfo", real.join("linked.narinfo"))
            .unwrap_or_else(|error| panic!("link target: {error}"));
        assert!(matches!(
            locked.read_narinfo(Path::new("linked.narinfo")),
            Err(NixCacheFileError::UnsafeLayout)
        ));

        fs::create_dir(real.join("nested"))
            .unwrap_or_else(|error| panic!("create nested: {error}"));
        symlink("nested", real.join("linked-directory"))
            .unwrap_or_else(|error| panic!("link directory: {error}"));
        assert!(matches!(
            locked.read_narinfo(Path::new("linked-directory/value.narinfo")),
            Err(NixCacheFileError::UnsafeLayout)
        ));
    }

    #[test]
    fn unsafe_lock_path_fails_closed() {
        let directory = temporary_directory();
        let victim = directory.path().join("victim");
        fs::write(&victim, b"victim").unwrap_or_else(|error| panic!("write victim: {error}"));
        symlink("victim", directory.path().join(CACHE_LOCK_FILE))
            .unwrap_or_else(|error| panic!("link lock: {error}"));
        assert!(matches!(
            LockedCacheRoot::try_acquire(directory.path()),
            Err(NixCacheFileError::UnsafeLayout)
        ));
        assert_eq!(
            fs::read(&victim).unwrap_or_else(|error| panic!("read victim: {error}")),
            b"victim"
        );
    }
}
