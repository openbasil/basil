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
//! mid-write) is distinguishable from interior corruption: a partial or
//! checksum-failing record at the exact tail reads as a torn tail, while any
//! damaged record followed by more bytes fails closed as corruption. A torn
//! record that still validates by chance is a known residual gap tracked as
//! `basil-3c3l`.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

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
    /// A complete interior record failed checksum or decoding: the journal
    /// fails closed.
    #[error("journal is corrupt")]
    Corrupt,
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

    /// Append one record, fsync the file, then fsync the parent directory.
    /// The record is durable only when this returns `Ok`.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] when serialization, the size bound, or any
    /// I/O or fsync step fails. On error the record must be treated as not
    /// durable until a read proves otherwise.
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

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(&frame)?;
        file.sync_all()?;
        drop(file);
        if let Some(parent) = self.path.parent() {
            File::open(parent)?.sync_all()?;
        }
        Ok(())
    }

    /// Read every record. An absent journal file reads as empty.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::Corrupt`] when an interior record is damaged
    /// (fail closed) and [`JournalError::Io`] on filesystem failure. A
    /// partial record at the exact tail is reported via
    /// [`JournalReadout::torn_tail`], not as an error.
    pub fn read(&self) -> Result<JournalReadout, JournalError> {
        let mut bytes = Vec::new();
        match File::open(&self.path) {
            Ok(mut file) => {
                file.read_to_end(&mut bytes)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(JournalReadout::default());
            }
            Err(error) => return Err(error.into()),
        }
        parse_journal(&bytes)
    }
}

fn parse_journal(bytes: &[u8]) -> Result<JournalReadout, JournalError> {
    let mut records = Vec::new();
    let mut offset = 0_usize;
    while offset < bytes.len() {
        let Some(header) = bytes.get(offset..offset.saturating_add(FRAME_LENGTH_BYTES)) else {
            // Fewer than four trailing bytes: torn mid-length append.
            return Ok(JournalReadout {
                records,
                torn_tail: true,
            });
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
            return Ok(JournalReadout {
                records,
                torn_tail: true,
            });
        };
        let Some(stored_checksum) = bytes.get(payload_end..frame_end) else {
            return Ok(JournalReadout {
                records,
                torn_tail: true,
            });
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
    Ok(JournalReadout {
        records,
        torn_tail: false,
    })
}

#[cfg(test)]
pub(crate) fn parse_journal_bytes(bytes: &[u8]) -> Result<JournalReadout, JournalError> {
    parse_journal(bytes)
}
