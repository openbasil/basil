// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Durable write-ahead receipts for the external authority installation
//! transaction.
//!
//! The journal holds the staged, commit-intent, committed/active, and retired
//! receipts described by the realm contract. The fsynced commit-intent receipt
//! is the transaction's **sole linearization point**: an installation is
//! logically committed exactly when its [`IntentReceipt`] is durable, and at
//! no other moment. Every append flushes the record and the journal's parent
//! directory before it is reported durable.
//!
//! Records use checksummed length-prefixed framing so a torn append (a crash
//! mid-write) is distinguishable from interior corruption: a record cut short
//! at the exact tail reads as a torn tail, while a fully present frame whose
//! checksum fails reads as corruption and fails closed **even at the tail** —
//! treating it as torn could silently drop a durable intent under bit rot. A
//! crash that persists the appended file length but not the payload bytes
//! (metadata-before-data ordering on some filesystems) therefore blocks
//! startup as [`JournalError::Corrupt`] and needs operator intervention, the
//! same as any other corruption. A torn record that still validates by chance
//! is a known residual gap tracked as `basil-3c3l`.

use std::fmt;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::num::NonZeroU64;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use super::manifest::ManifestId;
use crate::core::attestor_realm::RealmName;
use crate::release_admission::Sha256Digest;

/// Maximum serialized payload bytes of one journal record.
pub const MAX_RECORD_BYTES: usize = 16 * 1024;

const FRAME_LENGTH_BYTES: usize = 4;
const FRAME_CHECKSUM_BYTES: usize = 32;

/// Unique identifier of one installation transaction.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TransactionId([u8; 16]);

impl TransactionId {
    /// Allocate a fresh random transaction identifier.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::EntropyUnavailable`] when the operating-system
    /// entropy source fails.
    pub fn new() -> Result<Self, JournalError> {
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| JournalError::EntropyUnavailable)?;
        Ok(Self(bytes))
    }

    /// Construct a transaction identifier from fixed bytes (test fixtures and
    /// journal decoding).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    fn to_hex(self) -> String {
        let mut hex = String::with_capacity(32);
        for byte in self.0 {
            let _ = fmt::Write::write_fmt(&mut hex, format_args!("{byte:02x}"));
        }
        hex
    }

    fn from_hex(hex: &str) -> Option<Self> {
        if hex.len() != 32 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        let mut bytes = [0_u8; 16];
        for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
            let pair = std::str::from_utf8(chunk).ok()?;
            *bytes.get_mut(index)? = u8::from_str_radix(pair, 16).ok()?;
        }
        Some(Self(bytes))
    }
}

impl fmt::Display for TransactionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

impl fmt::Debug for TransactionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "TransactionId({self})")
    }
}

impl Serialize for TransactionId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for TransactionId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let hex = String::deserialize(deserializer)?;
        Self::from_hex(&hex)
            .ok_or_else(|| serde::de::Error::custom("invalid transaction identifier"))
    }
}

/// Serde helpers for [`Sha256Digest`] journal fields (lowercase hex).
pub(crate) mod digest_serde {
    use super::{Deserialize as _, Deserializer, Serializer, Sha256Digest};

    pub fn serialize<S: Serializer>(
        digest: &Sha256Digest,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut hex = String::with_capacity(64);
        for byte in digest.as_bytes() {
            let _ = std::fmt::Write::write_fmt(&mut hex, format_args!("{byte:02x}"));
        }
        serializer.serialize_str(&hex)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Sha256Digest, D::Error> {
        let hex = String::deserialize(deserializer)?;
        if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(serde::de::Error::custom("invalid digest encoding"));
        }
        let mut bytes = [0_u8; 32];
        for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
            let pair = std::str::from_utf8(chunk)
                .map_err(|_| serde::de::Error::custom("invalid digest encoding"))?;
            let byte = u8::from_str_radix(pair, 16)
                .map_err(|_| serde::de::Error::custom("invalid digest encoding"))?;
            if let Some(slot) = bytes.get_mut(index) {
                *slot = byte;
            }
        }
        Ok(Sha256Digest::from_bytes(bytes))
    }
}

/// Serde helpers for [`RealmName`] journal fields.
pub(crate) mod realm_serde {
    use super::{Deserialize as _, Deserializer, RealmName, Serializer};

    pub fn serialize<S: Serializer>(realm: &RealmName, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(realm.as_str())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<RealmName, D::Error> {
        let raw = String::deserialize(deserializer)?;
        RealmName::new(&raw).map_err(|_| serde::de::Error::custom("invalid realm name"))
    }
}

/// Receipt written when the root installer durably stages a candidate
/// manifest, before any host mutation beyond the staged file itself.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StagedReceipt {
    /// Owning installation transaction.
    pub transaction: TransactionId,
    /// Target realm.
    #[serde(with = "realm_serde")]
    pub realm: RealmName,
    /// Identity of the staged candidate manifest.
    pub manifest: ManifestId,
    /// Candidate authority generation.
    pub authority_generation: NonZeroU64,
    /// Candidate helper-policy generation.
    pub helper_policy_generation: NonZeroU64,
    /// Identity of the currently authoritative manifest, if any.
    pub previous_manifest: Option<ManifestId>,
}

/// The write-ahead commit-intent receipt: the transaction's sole
/// linearization point. Once this record is durable the installation is
/// logically committed and can only complete forward.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntentReceipt {
    /// Owning installation transaction.
    pub transaction: TransactionId,
    /// Target realm.
    #[serde(with = "realm_serde")]
    pub realm: RealmName,
    /// Identity of the candidate manifest being committed.
    pub new_manifest: ManifestId,
    /// Identity of the manifest being superseded, if any.
    pub previous_manifest: Option<ManifestId>,
    /// Exact candidate corpus fingerprint compared at pre-commit.
    #[serde(with = "digest_serde")]
    pub candidate_corpus: Sha256Digest,
    /// Exact broker configuration-generation fingerprint at intent.
    #[serde(with = "digest_serde")]
    pub configuration_generation: Sha256Digest,
    /// Candidate authority generation being committed.
    pub authority_generation: NonZeroU64,
    /// Superseded authority generation retained for bounded drain, if any.
    pub previous_generation: Option<NonZeroU64>,
    /// Bounded drain deadline for the superseded generation, in milliseconds.
    pub drain_deadline_millis: u64,
}

/// Receipt written after the broker publication swap: the committed/active
/// finalization record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActiveReceipt {
    /// Owning installation transaction.
    pub transaction: TransactionId,
    /// Target realm.
    #[serde(with = "realm_serde")]
    pub realm: RealmName,
    /// Committed authority generation now serving.
    pub authority_generation: NonZeroU64,
    /// Broker registry generation observed at publication.
    pub serving_generation: u64,
}

/// Receipt written after a committed old generation finishes bounded drain
/// and is dismantled.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetiredReceipt {
    /// Owning installation transaction.
    pub transaction: TransactionId,
    /// Target realm.
    #[serde(with = "realm_serde")]
    pub realm: RealmName,
    /// The retired old authority generation.
    pub retired_generation: NonZeroU64,
    /// The old helper-policy generation retired with it, if it was pinned
    /// only by the retired authority generation.
    pub retired_helper_policy_generation: Option<NonZeroU64>,
}

/// Terminal receipt written when a staged, never-committed candidate is
/// removed (pre-commit rejection, provably-absent intent, or reconciliation
/// discard).
///
/// It closes the transaction's journal track so rejected attempts do not
/// accumulate as live staged records across restarts. Legal only while no
/// commit-intent receipt exists for the transaction.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiscardedReceipt {
    /// Owning installation transaction.
    pub transaction: TransactionId,
    /// Target realm.
    #[serde(with = "realm_serde")]
    pub realm: RealmName,
}

/// One durable journal record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "receipt", rename_all = "camelCase")]
pub enum JournalRecord {
    /// Candidate manifest staged.
    Staged(StagedReceipt),
    /// Commit intent durable — the sole linearization point.
    Intent(IntentReceipt),
    /// Publication finalized (committed/active).
    Active(ActiveReceipt),
    /// Old generation retired after bounded drain.
    Retired(RetiredReceipt),
    /// Staged candidate discarded without ever committing (terminal).
    Discarded(DiscardedReceipt),
}

impl JournalRecord {
    /// The owning transaction of this record.
    #[must_use]
    pub const fn transaction(&self) -> TransactionId {
        match self {
            Self::Staged(receipt) => receipt.transaction,
            Self::Intent(receipt) => receipt.transaction,
            Self::Active(receipt) => receipt.transaction,
            Self::Retired(receipt) => receipt.transaction,
            Self::Discarded(receipt) => receipt.transaction,
        }
    }

    /// The realm this record belongs to.
    #[must_use]
    pub const fn realm(&self) -> &RealmName {
        match self {
            Self::Staged(receipt) => &receipt.realm,
            Self::Intent(receipt) => &receipt.realm,
            Self::Active(receipt) => &receipt.realm,
            Self::Retired(receipt) => &receipt.realm,
            Self::Discarded(receipt) => &receipt.realm,
        }
    }
}

/// Typed journal failure.
#[derive(Debug, Error)]
pub enum JournalError {
    /// The operating-system entropy source failed.
    #[error("entropy source unavailable")]
    EntropyUnavailable,
    /// A record exceeded [`MAX_RECORD_BYTES`].
    #[error("journal record exceeds the size bound")]
    RecordTooLarge,
    /// Serialization failed.
    #[error("journal record serialization failed")]
    Serialize,
    /// A fully present record failed checksum or decoding — interior or at
    /// the tail: the journal fails closed.
    #[error("journal is corrupt")]
    Corrupt,
    /// The journal path — a directory component on the way to the installer
    /// state directory, or the journal file itself — failed the trusted
    /// ownership/mode verification. Fail closed: never read or append
    /// through an untrusted path.
    #[error("journal path failed trust verification: {reason}")]
    UntrustedPath {
        /// Which trust check failed (static description, no path content).
        reason: &'static str,
    },
    /// Filesystem I/O failed.
    #[error("journal I/O failed: {kind}")]
    Io {
        /// The failing I/O error kind.
        kind: std::io::ErrorKind,
    },
}

impl From<std::io::Error> for JournalError {
    fn from(error: std::io::Error) -> Self {
        Self::Io { kind: error.kind() }
    }
}

/// A full journal read: every valid record plus whether the file ends in a
/// torn (partially appended) record.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct JournalReadout {
    /// Every complete, checksum-valid record in append order.
    pub records: Vec<JournalRecord>,
    /// Whether the journal ends in a torn partial append. A torn tail is not
    /// a durable receipt: durability requires the complete fsynced record.
    pub torn_tail: bool,
}

impl JournalReadout {
    /// Whether a durable commit-intent receipt exists for `transaction`.
    #[must_use]
    pub fn intent_for(&self, transaction: TransactionId) -> Option<&IntentReceipt> {
        self.records.iter().find_map(|record| match record {
            JournalRecord::Intent(receipt) if receipt.transaction == transaction => Some(receipt),
            _ => None,
        })
    }

    /// Whether a committed/active receipt exists for `transaction`.
    #[must_use]
    pub fn active_for(&self, transaction: TransactionId) -> Option<&ActiveReceipt> {
        self.records.iter().find_map(|record| match record {
            JournalRecord::Active(receipt) if receipt.transaction == transaction => Some(receipt),
            _ => None,
        })
    }
}

/// File-backed intent journal with fsynced checksummed appends.
///
/// Appends are durable before they return: the record bytes are flushed with
/// `fsync` and the parent directory is flushed so the file's existence and
/// length survive a crash. The journal is owned by the root installer
/// authority; the broker only ever consumes acknowledgements and readouts.
#[derive(Clone, Debug)]
pub struct FileIntentJournal {
    path: PathBuf,
}

impl FileIntentJournal {
    /// Standard journal file name inside the installer state directory.
    pub const FILE_NAME: &'static str = "commit-intent.journal";

    /// Address the journal file inside `directory`.
    #[must_use]
    pub fn in_directory(directory: &Path) -> Self {
        Self {
            path: directory.join(Self::FILE_NAME),
        }
    }

    /// The journal file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one record, fsync the file, then fsync the state directory.
    /// The record is durable only when this returns `Ok`.
    ///
    /// The open path is hardened against symlink and ownership attacks: the
    /// installer state directory is reached by a descriptor-relative
    /// component walk from `/` (`openat` with `O_NOFOLLOW` and `O_DIRECTORY`
    /// per component), every component must be owned by root or the
    /// effective user and be neither group- nor world-writable (a root-owned
    /// sticky directory such as `/tmp` is accepted as an *ancestor*
    /// boundary, never as the state directory itself), and the journal file
    /// — created `0600`, opened `O_NOFOLLOW` relative to the walked
    /// directory descriptor — must be a regular, singly-linked file with the
    /// same ownership bound and no group/world write bit. The journal has
    /// exactly one writer — the root installer authority — and appends are
    /// serialized.
    ///
    /// A torn tail (a partial frame from a crashed earlier append) is healed
    /// here: it is not durable by definition, so it is truncated away before
    /// the new frame is written. Appending to a journal with interior
    /// corruption refuses with [`JournalError::Corrupt`].
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] when serialization, the size bound, existing
    /// corruption, path trust verification, or any I/O or fsync step fails.
    /// On error the record must be treated as not durable until a read
    /// proves otherwise.
    pub fn append(&self, record: &JournalRecord) -> Result<(), JournalError> {
        let payload = serde_json::to_vec(record).map_err(|_| JournalError::Serialize)?;
        if payload.len() > MAX_RECORD_BYTES {
            return Err(JournalError::RecordTooLarge);
        }
        let length = u32::try_from(payload.len()).map_err(|_| JournalError::RecordTooLarge)?;
        let checksum: [u8; 32] = Sha256::digest(&payload).into();
        let mut frame =
            Vec::with_capacity(FRAME_LENGTH_BYTES + payload.len() + FRAME_CHECKSUM_BYTES);
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(&payload);
        frame.extend_from_slice(&checksum);

        let directory = self.open_trusted_state_directory()?;

        // Validate the existing journal and locate the durable end so a torn
        // tail never prefixes (and thereby corrupts) the new frame.
        let (existing_len, durable_len) = match read_bytes_at(&directory)? {
            Some(bytes) => {
                let (_, durable_len) = parse_journal(&bytes)?;
                (bytes.len(), durable_len)
            }
            None => (0, 0),
        };

        let fd = rustix::fs::openat(
            &directory,
            Self::FILE_NAME,
            OFlags::WRONLY | OFlags::APPEND | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(io_error)?;
        let mut file = File::from(fd);
        verify_trusted_journal_file(&file)?;
        if existing_len > durable_len
            && let Ok(durable) = u64::try_from(durable_len)
        {
            file.set_len(durable)?;
        }
        file.write_all(&frame)?;
        file.sync_all()?;
        drop(file);
        directory.sync_all()?;
        Ok(())
    }

    /// Read every record. An absent journal file reads as empty.
    ///
    /// The journal is reached through the same hardened descriptor-relative
    /// walk and file verification as [`FileIntentJournal::append`], so a
    /// reader (broker-side reconciliation, doctor) refuses a journal behind
    /// a symlinked, foreign-owned, or group/world-writable path instead of
    /// trusting its content.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::Corrupt`] when a fully present record is
    /// damaged (fail closed, even at the tail),
    /// [`JournalError::UntrustedPath`] when path trust verification fails,
    /// and [`JournalError::Io`] on filesystem failure. A partial record at
    /// the exact tail is reported via [`JournalReadout::torn_tail`], not as
    /// an error.
    pub fn read(&self) -> Result<JournalReadout, JournalError> {
        let directory = self.open_trusted_state_directory()?;
        match read_bytes_at(&directory)? {
            Some(bytes) => Ok(parse_journal(&bytes)?.0),
            None => Ok(JournalReadout::default()),
        }
    }

    /// Open the installer state directory (the journal's parent) with a
    /// descriptor-relative component walk from `/`: every component is
    /// opened `openat(O_DIRECTORY | O_NOFOLLOW)` relative to the previous
    /// descriptor and verified for trusted ownership and modes, so neither a
    /// symlinked component nor a foreign-owned or loosely-permissioned
    /// directory can redirect or expose the journal.
    fn open_trusted_state_directory(&self) -> Result<File, JournalError> {
        let directory = self.path.parent().ok_or(JournalError::UntrustedPath {
            reason: "journal path has no parent directory",
        })?;
        let relative = directory
            .strip_prefix("/")
            .map_err(|_| JournalError::UntrustedPath {
                reason: "installer state directory path must be absolute",
            })?;
        let component_count = relative.components().count();
        let mut current = File::from(
            rustix::fs::open(
                "/",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(io_error)?,
        );
        for (index, component) in relative.components().enumerate() {
            let std::path::Component::Normal(name) = component else {
                return Err(JournalError::UntrustedPath {
                    reason: "state directory path has a non-plain component",
                });
            };
            let next = File::from(
                rustix::fs::openat(
                    &current,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(io_error)?,
            );
            verify_trusted_directory(&next.metadata()?, index + 1 == component_count)?;
            current = next;
        }
        if component_count == 0 {
            // The state directory is `/` itself: verify it directly.
            verify_trusted_directory(&current.metadata()?, true)?;
        }
        Ok(current)
    }
}

/// Verify one walked directory component. Every component must be a
/// directory owned by root or the effective user and carry no group/world
/// write bit. A root-owned sticky directory (for example `/tmp`) is accepted
/// as an **ancestor** boundary only — other users cannot rename or unlink
/// foreign entries there, and the next component is opened
/// descriptor-relative with `O_NOFOLLOW` and re-verified — but the state
/// directory itself gets no such exception.
fn verify_trusted_directory(
    metadata: &std::fs::Metadata,
    is_state_directory: bool,
) -> Result<(), JournalError> {
    let effective_uid = rustix::process::geteuid().as_raw();
    let mode = metadata.permissions().mode();
    if !metadata.is_dir() {
        return Err(JournalError::UntrustedPath {
            reason: "path component is not a directory",
        });
    }
    if metadata.uid() != 0 && metadata.uid() != effective_uid {
        return Err(JournalError::UntrustedPath {
            reason: "directory is not owned by root or the effective user",
        });
    }
    let root_sticky_boundary = !is_state_directory && metadata.uid() == 0 && mode & 0o1000 != 0;
    if mode & 0o022 != 0 && !root_sticky_boundary {
        return Err(JournalError::UntrustedPath {
            reason: "directory is group- or world-writable",
        });
    }
    if metadata.nlink() == 0 {
        return Err(JournalError::UntrustedPath {
            reason: "directory was unlinked while being verified",
        });
    }
    Ok(())
}

/// Verify the opened journal file descriptor: a regular, singly-linked file
/// owned by root or the effective user with no group/world write bit. Run on
/// the descriptor (never the path) so the verified inode is exactly the one
/// read or written.
fn verify_trusted_journal_file(file: &File) -> Result<(), JournalError> {
    let metadata = file.metadata()?;
    let effective_uid = rustix::process::geteuid().as_raw();
    if !metadata.file_type().is_file() {
        return Err(JournalError::UntrustedPath {
            reason: "journal is not a regular file",
        });
    }
    if metadata.uid() != 0 && metadata.uid() != effective_uid {
        return Err(JournalError::UntrustedPath {
            reason: "journal is not owned by root or the effective user",
        });
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(JournalError::UntrustedPath {
            reason: "journal is group- or world-writable",
        });
    }
    if metadata.nlink() != 1 {
        return Err(JournalError::UntrustedPath {
            reason: "journal has unexpected hard links",
        });
    }
    Ok(())
}

/// Read the raw journal bytes relative to the verified state-directory
/// descriptor, with `O_NOFOLLOW` on the file and descriptor verification
/// before any byte is trusted. An absent file reads as `None`.
fn read_bytes_at(directory: &File) -> Result<Option<Vec<u8>>, JournalError> {
    let fd = match rustix::fs::openat(
        directory,
        FileIntentJournal::FILE_NAME,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(errno) => return Err(io_error(errno)),
    };
    let mut file = File::from(fd);
    verify_trusted_journal_file(&file)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(Some(bytes))
}

fn io_error(errno: Errno) -> JournalError {
    JournalError::Io {
        kind: std::io::Error::from(errno).kind(),
    }
}

/// Parse the journal bytes into a readout plus the byte offset just past the
/// last complete valid frame (the durable length; a torn tail lies beyond it).
fn parse_journal(bytes: &[u8]) -> Result<(JournalReadout, usize), JournalError> {
    let mut records = Vec::new();
    let mut offset = 0_usize;
    while offset < bytes.len() {
        let Some(header) = bytes.get(offset..offset.saturating_add(FRAME_LENGTH_BYTES)) else {
            // Fewer than four trailing bytes: torn mid-length append.
            return Ok((
                JournalReadout {
                    records,
                    torn_tail: true,
                },
                offset,
            ));
        };
        let mut length_bytes = [0_u8; FRAME_LENGTH_BYTES];
        length_bytes.copy_from_slice(header);
        let length = u32::from_be_bytes(length_bytes) as usize;
        if length > MAX_RECORD_BYTES {
            // A complete length prefix with an absurd value is interior
            // damage, not a torn append prefix.
            return Err(JournalError::Corrupt);
        }
        let payload_start = offset.saturating_add(FRAME_LENGTH_BYTES);
        let payload_end = payload_start.saturating_add(length);
        let frame_end = payload_end.saturating_add(FRAME_CHECKSUM_BYTES);
        let Some(payload) = bytes.get(payload_start..payload_end) else {
            return Ok((
                JournalReadout {
                    records,
                    torn_tail: true,
                },
                offset,
            ));
        };
        let Some(stored_checksum) = bytes.get(payload_end..frame_end) else {
            return Ok((
                JournalReadout {
                    records,
                    torn_tail: true,
                },
                offset,
            ));
        };
        let computed: [u8; 32] = Sha256::digest(payload).into();
        if stored_checksum != computed {
            // The declared frame is fully present but damaged: fail closed
            // whether or not it is the last frame.
            return Err(JournalError::Corrupt);
        }
        let record: JournalRecord =
            serde_json::from_slice(payload).map_err(|_| JournalError::Corrupt)?;
        records.push(record);
        offset = frame_end;
    }
    Ok((
        JournalReadout {
            records,
            torn_tail: false,
        },
        offset,
    ))
}

#[cfg(test)]
pub(crate) fn parse_journal_bytes(bytes: &[u8]) -> Result<JournalReadout, JournalError> {
    parse_journal(bytes).map(|(readout, _)| readout)
}

/// Trust verification of the journal open path (the descriptor-relative
/// walk and file checks). Framing, torn-tail, and corruption semantics are
/// covered in `super::tests`.
#[cfg(test)]
mod trusted_path_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::num::NonZeroU64;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};

    use super::{
        FileIntentJournal, JournalError, JournalRecord, ManifestId, StagedReceipt, TransactionId,
    };
    use crate::core::attestor_realm::RealmName;
    use crate::release_admission::Sha256Digest;

    struct TempDir {
        path: PathBuf,
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn tempdir(stem: &str) -> TempDir {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "basil-journal-trust-{stem}-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        TempDir { path }
    }

    fn record() -> JournalRecord {
        JournalRecord::Staged(StagedReceipt {
            transaction: TransactionId::from_bytes([7; 16]),
            realm: RealmName::new("owner-podman").expect("realm"),
            manifest: ManifestId::from_digest(Sha256Digest::from_bytes([1; 32])),
            authority_generation: NonZeroU64::new(2).expect("nonzero"),
            helper_policy_generation: NonZeroU64::new(2).expect("nonzero"),
            previous_manifest: None,
        })
    }

    fn chmod(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
    }

    fn untrusted_reason(result: Result<impl Sized, JournalError>) -> &'static str {
        match result {
            Err(JournalError::UntrustedPath { reason }) => reason,
            Err(other) => panic!("expected UntrustedPath, got: {other}"),
            Ok(_) => panic!("expected UntrustedPath, got Ok"),
        }
    }

    #[test]
    fn round_trips_through_a_nested_trusted_walk() {
        let dir = tempdir("nested");
        let state = dir.path.join("authority-install");
        std::fs::create_dir(&state).expect("create state dir");
        let journal = FileIntentJournal::in_directory(&state);
        journal.append(&record()).expect("append");
        let readout = journal.read().expect("read");
        assert_eq!(readout.records.len(), 1);
        assert!(!readout.torn_tail);
    }

    #[test]
    fn relative_state_directory_is_refused_on_both_paths() {
        let journal = FileIntentJournal::in_directory(Path::new("relative/state"));
        assert_eq!(
            untrusted_reason(journal.append(&record())),
            "installer state directory path must be absolute"
        );
        // Fail closed even where a plain read would report an absent file.
        assert_eq!(
            untrusted_reason(journal.read()),
            "installer state directory path must be absolute"
        );
    }

    #[test]
    fn world_writable_state_directory_is_refused() {
        let dir = tempdir("world-writable");
        let journal = FileIntentJournal::in_directory(&dir.path);
        journal.append(&record()).expect("append while trusted");
        chmod(&dir.path, 0o757);
        assert_eq!(
            untrusted_reason(journal.append(&record())),
            "directory is group- or world-writable"
        );
        assert_eq!(
            untrusted_reason(journal.read()),
            "directory is group- or world-writable"
        );
        chmod(&dir.path, 0o755);
        journal.read().expect("trusted again after chmod back");
    }

    #[test]
    fn sticky_bit_does_not_excuse_the_state_directory_itself() {
        // A root-owned sticky ancestor (like `/tmp`) is acceptable, but the
        // state directory itself must never be sticky-world-writable.
        let dir = tempdir("sticky-state");
        let journal = FileIntentJournal::in_directory(&dir.path);
        chmod(&dir.path, 0o1777);
        assert_eq!(
            untrusted_reason(journal.append(&record())),
            "directory is group- or world-writable"
        );
        chmod(&dir.path, 0o755);
    }

    #[test]
    fn symlinked_state_directory_component_is_refused() {
        let dir = tempdir("symlinked-dir");
        let real = dir.path.join("real");
        std::fs::create_dir(&real).expect("create real dir");
        let planted = dir.path.join("state");
        std::os::unix::fs::symlink(&real, &planted).expect("plant symlink");
        let journal = FileIntentJournal::in_directory(&planted);
        // The descriptor-relative `O_NOFOLLOW` open refuses the component.
        assert!(matches!(
            journal.append(&record()),
            Err(JournalError::Io { .. })
        ));
        assert!(matches!(journal.read(), Err(JournalError::Io { .. })));
    }

    #[test]
    fn group_writable_journal_file_is_refused() {
        let dir = tempdir("loose-file");
        let journal = FileIntentJournal::in_directory(&dir.path);
        journal.append(&record()).expect("append");
        chmod(journal.path(), 0o620);
        assert_eq!(
            untrusted_reason(journal.read()),
            "journal is group- or world-writable"
        );
        assert_eq!(
            untrusted_reason(journal.append(&record())),
            "journal is group- or world-writable"
        );
    }

    #[test]
    fn hardlinked_journal_file_is_refused() {
        let dir = tempdir("hardlink");
        let journal = FileIntentJournal::in_directory(&dir.path);
        journal.append(&record()).expect("append");
        std::fs::hard_link(journal.path(), dir.path.join("second-link")).expect("hard link");
        assert_eq!(
            untrusted_reason(journal.read()),
            "journal has unexpected hard links"
        );
        assert_eq!(
            untrusted_reason(journal.append(&record())),
            "journal has unexpected hard links"
        );
    }

    #[test]
    fn journal_entry_that_is_not_a_regular_file_is_refused_on_read() {
        let dir = tempdir("not-regular");
        let journal = FileIntentJournal::in_directory(&dir.path);
        std::fs::create_dir(journal.path()).expect("plant directory at journal path");
        assert_eq!(
            untrusted_reason(journal.read()),
            "journal is not a regular file"
        );
    }
}
