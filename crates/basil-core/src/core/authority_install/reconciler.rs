// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Startup and doctor reconciliation of the intent journal.
//!
//! Reconciliation is a pure classification of the durable journal into a
//! plan. The journal is append-only and accumulates every installation
//! attempt for the life of the installer state directory, so classification
//! is **realm-succession aware** rather than per-transaction:
//!
//! - A staged transaction without a commit-intent receipt is **inert**: it
//!   never disturbed the old authority and never claims realm ownership. Any
//!   number may accumulate (every rejected attempt leaves one). Each is
//!   discarded idempotently on every reconciliation until its terminal
//!   [`JournalRecord::Discarded`] receipt is durable.
//! - Committed transactions (durable intent) in one realm form a
//!   **succession chain** in intent order. A successor's durable intent
//!   receipt names its predecessor's authority generation, and the
//!   successor's own forward completion retires the predecessor — the
//!   predecessor's track never receives a terminal record of its own (a
//!   first-install transaction in particular never does). Only the newest
//!   committed transaction owns the realm: it completes forward or recovers
//!   as the serving authority; superseded predecessors require no action.
//! - A broken chain — a superseded transaction still demanding forward
//!   completion, or a successor whose intent does not name its
//!   predecessor's generation — fails closed as split ownership.
//! - A torn tail record is not a durable receipt: it never upgrades a
//!   transaction's state.

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

use super::journal::{JournalReadout, JournalRecord, TransactionId};
use crate::core::attestor_realm::RealmName;

/// One reconciliation action. Each transaction owns at most one action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReconcileAction {
    /// A staged transaction without intent: remove the staged candidate,
    /// release its guards, and durably append its terminal discarded
    /// receipt. The old authority was never disturbed. Idempotent: the
    /// action repeats on every reconciliation until the discarded receipt
    /// lands.
    DiscardStaged {
        /// The abandoned transaction.
        transaction: TransactionId,
        /// Its realm.
        realm: RealmName,
    },
    /// A durable intent without a committed/active receipt: logically
    /// committed. Complete forward to the new generation before the broker
    /// serves or reports readiness. Never cleaned as abandoned.
    CompleteForward {
        /// The committed transaction.
        transaction: TransactionId,
        /// Its realm.
        realm: RealmName,
    },
    /// The realm's newest committed/active receipt: recover it as the
    /// serving authority and resume any pending bounded drain of the
    /// predecessor generation named by this transaction's intent receipt.
    RecoverActive {
        /// The committed transaction.
        transaction: TransactionId,
        /// Its realm.
        realm: RealmName,
        /// Whether a superseded generation still awaits retirement.
        retirement_pending: bool,
    },
}

/// Typed reconciliation failure. Any failure blocks readiness.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ReconcileError {
    /// A record kind appeared without its required predecessor (intent or
    /// discarded without staged, active without intent, retired without
    /// active, discarded after intent).
    #[error("journal record order violation")]
    OrderViolation,
    /// The same record kind appeared twice for one transaction.
    #[error("duplicate journal record for one transaction")]
    DuplicateRecord,
    /// One transaction's records disagree about its realm.
    #[error("journal records disagree about a transaction's realm")]
    RealmMismatch,
    /// A realm's committed-transaction succession is broken: a superseded
    /// transaction still demands forward completion, or a successor's intent
    /// does not name its predecessor's authority generation.
    #[error("split ownership: broken authority succession in one realm")]
    SplitOwnership,
}

/// The reconciliation plan for one journal readout.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReconcilePlan {
    /// One action per transaction that needs one, in journal order of first
    /// appearance.
    pub actions: Vec<ReconcileAction>,
}

impl ReconcilePlan {
    /// Whether the broker may serve and report readiness. Every durable
    /// intent must complete forward first.
    #[must_use]
    pub fn ready(&self) -> bool {
        !self
            .actions
            .iter()
            .any(|action| matches!(action, ReconcileAction::CompleteForward { .. }))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransactionState {
    Staged,
    Intent,
    Active,
    Retired,
    Discarded,
}

struct TransactionTrack {
    realm: RealmName,
    state: TransactionState,
    order: usize,
    /// Journal position of the durable intent receipt, when committed.
    intent_order: Option<usize>,
    /// Committed authority generation, from the intent receipt.
    authority_generation: Option<std::num::NonZeroU64>,
    /// Superseded predecessor generation, from the intent receipt.
    previous_generation: Option<std::num::NonZeroU64>,
}

/// Classify the durable journal into a reconciliation plan.
///
/// # Errors
///
/// Returns [`ReconcileError`] for order violations, duplicate records, realm
/// mismatches, or broken realm succession. Every error fails closed: the
/// caller must not report readiness over an unreconciled journal.
pub fn reconcile(readout: &JournalReadout) -> Result<ReconcilePlan, ReconcileError> {
    let mut tracks: BTreeMap<TransactionId, TransactionTrack> = BTreeMap::new();
    for (order, record) in readout.records.iter().enumerate() {
        match record {
            JournalRecord::Staged(_) => {
                if tracks.contains_key(&record.transaction()) {
                    return Err(ReconcileError::DuplicateRecord);
                }
                tracks.insert(
                    record.transaction(),
                    TransactionTrack {
                        realm: record.realm().clone(),
                        state: TransactionState::Staged,
                        order,
                        intent_order: None,
                        authority_generation: None,
                        previous_generation: None,
                    },
                );
            }
            JournalRecord::Intent(receipt) => {
                let track = advance(
                    &mut tracks,
                    record,
                    TransactionState::Staged,
                    TransactionState::Intent,
                )?;
                track.intent_order = Some(order);
                track.authority_generation = Some(receipt.authority_generation);
                track.previous_generation = receipt.previous_generation;
            }
            JournalRecord::Active(_) => {
                advance(
                    &mut tracks,
                    record,
                    TransactionState::Intent,
                    TransactionState::Active,
                )?;
            }
            JournalRecord::Retired(_) => {
                advance(
                    &mut tracks,
                    record,
                    TransactionState::Active,
                    TransactionState::Retired,
                )?;
            }
            JournalRecord::Discarded(_) => {
                advance(
                    &mut tracks,
                    record,
                    TransactionState::Staged,
                    TransactionState::Discarded,
                )?;
            }
        }
    }

    let superseded = validate_succession(&tracks)?;

    let mut ordered: Vec<(&TransactionId, &TransactionTrack)> = tracks.iter().collect();
    ordered.sort_by_key(|(_, track)| track.order);
    let mut actions = Vec::new();
    for (transaction, track) in ordered {
        match track.state {
            TransactionState::Staged => actions.push(ReconcileAction::DiscardStaged {
                transaction: *transaction,
                realm: track.realm.clone(),
            }),
            TransactionState::Intent => actions.push(ReconcileAction::CompleteForward {
                transaction: *transaction,
                realm: track.realm.clone(),
            }),
            TransactionState::Active if !superseded.contains(&track.order) => {
                actions.push(ReconcileAction::RecoverActive {
                    transaction: *transaction,
                    realm: track.realm.clone(),
                    retirement_pending: track.previous_generation.is_some(),
                });
            }
            // Superseded active tracks are the successor's responsibility;
            // retired and discarded tracks are terminal.
            TransactionState::Active | TransactionState::Retired | TransactionState::Discarded => {}
        }
    }
    Ok(ReconcilePlan { actions })
}

/// Validate each realm's committed-transaction succession chain — committed
/// transactions (those with a durable intent) in one realm, in intent order;
/// every non-final link must have been superseded cleanly by its successor's
/// intent — and return the journal orders of the superseded predecessors.
fn validate_succession(
    tracks: &BTreeMap<TransactionId, TransactionTrack>,
) -> Result<BTreeSet<usize>, ReconcileError> {
    let mut chains: BTreeMap<&RealmName, Vec<&TransactionTrack>> = BTreeMap::new();
    for track in tracks.values() {
        if track.intent_order.is_some() {
            chains.entry(&track.realm).or_default().push(track);
        }
    }
    let mut superseded: BTreeSet<usize> = BTreeSet::new();
    for chain in chains.values_mut() {
        chain.sort_by_key(|track| track.intent_order);
        for (predecessor, successor) in chain.iter().zip(chain.iter().skip(1)) {
            if predecessor.state == TransactionState::Intent {
                // A superseded transaction still demanding forward
                // completion: two transactions would own the realm's
                // forward path.
                return Err(ReconcileError::SplitOwnership);
            }
            if successor.previous_generation != predecessor.authority_generation {
                // The successor's intent does not chain to its predecessor.
                return Err(ReconcileError::SplitOwnership);
            }
            superseded.insert(predecessor.order);
        }
    }
    Ok(superseded)
}

fn advance<'t>(
    tracks: &'t mut BTreeMap<TransactionId, TransactionTrack>,
    record: &JournalRecord,
    expected: TransactionState,
    next: TransactionState,
) -> Result<&'t mut TransactionTrack, ReconcileError> {
    let track = tracks
        .get_mut(&record.transaction())
        .ok_or(ReconcileError::OrderViolation)?;
    if track.realm != *record.realm() {
        return Err(ReconcileError::RealmMismatch);
    }
    if track.state == next {
        return Err(ReconcileError::DuplicateRecord);
    }
    if track.state != expected {
        return Err(ReconcileError::OrderViolation);
    }
    track.state = next;
    Ok(track)
}
