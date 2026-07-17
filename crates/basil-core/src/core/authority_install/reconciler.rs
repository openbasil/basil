// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Startup and doctor reconciliation of the intent journal.
//!
//! Reconciliation is a pure classification of the durable journal into a
//! plan. It discards **only** staged transactions without a commit-intent
//! receipt, completes every durable intent forward before readiness, recovers
//! committed/active receipts, retires only committed old generations, and
//! never splits one transaction's ownership across actions. A torn tail
//! record is not a durable receipt: it never upgrades a transaction's state.

use std::collections::BTreeMap;

use thiserror::Error;

use super::journal::{JournalReadout, JournalRecord, TransactionId};
use crate::core::attestor_realm::RealmName;

/// One reconciliation action. Each transaction owns exactly one action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReconcileAction {
    /// A staged transaction without intent: remove the staged candidate and
    /// release its guards. The old authority was never disturbed.
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
    /// A committed/active receipt: recover it as the serving authority and
    /// resume any pending bounded drain.
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
    /// A record kind appeared without its required predecessor (intent
    /// without staged, active without intent, retired without active).
    #[error("journal record order violation")]
    OrderViolation,
    /// The same record kind appeared twice for one transaction.
    #[error("duplicate journal record for one transaction")]
    DuplicateRecord,
    /// Two unfinished transactions claim the same realm: ownership would
    /// split.
    #[error("split ownership: two unfinished transactions claim one realm")]
    SplitOwnership,
}

/// The reconciliation plan for one journal readout.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReconcilePlan {
    /// One action per non-retired transaction, in journal order of first
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
}

struct TransactionTrack {
    realm: RealmName,
    state: TransactionState,
    order: usize,
}

/// Classify the durable journal into a reconciliation plan.
///
/// # Errors
///
/// Returns [`ReconcileError`] for order violations, duplicate records, or
/// split ownership. Every error fails closed: the caller must not report
/// readiness over an unreconciled journal.
pub fn reconcile(readout: &JournalReadout) -> Result<ReconcilePlan, ReconcileError> {
    let mut tracks: BTreeMap<TransactionId, TransactionTrack> = BTreeMap::new();
    for (order, record) in readout.records.iter().enumerate() {
        let transaction = record.transaction();
        match record {
            JournalRecord::Staged(_) => {
                if tracks.contains_key(&transaction) {
                    return Err(ReconcileError::DuplicateRecord);
                }
                tracks.insert(
                    transaction,
                    TransactionTrack {
                        realm: record.realm().clone(),
                        state: TransactionState::Staged,
                        order,
                    },
                );
            }
            JournalRecord::Intent(_) => {
                advance(
                    &mut tracks,
                    transaction,
                    TransactionState::Staged,
                    TransactionState::Intent,
                )?;
            }
            JournalRecord::Active(_) => {
                advance(
                    &mut tracks,
                    transaction,
                    TransactionState::Intent,
                    TransactionState::Active,
                )?;
            }
            JournalRecord::Retired(_) => {
                advance(
                    &mut tracks,
                    transaction,
                    TransactionState::Active,
                    TransactionState::Retired,
                )?;
            }
        }
    }

    // Never split ownership: at most one unfinished transaction per realm.
    let mut unfinished_by_realm: BTreeMap<&RealmName, usize> = BTreeMap::new();
    for track in tracks.values() {
        if track.state != TransactionState::Retired {
            let count = unfinished_by_realm.entry(&track.realm).or_insert(0);
            *count = count.saturating_add(1);
            if *count > 1 {
                return Err(ReconcileError::SplitOwnership);
            }
        }
    }

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
            TransactionState::Active => {
                let retirement_pending = readout
                    .intent_for(*transaction)
                    .is_some_and(|intent| intent.previous_generation.is_some());
                actions.push(ReconcileAction::RecoverActive {
                    transaction: *transaction,
                    realm: track.realm.clone(),
                    retirement_pending,
                });
            }
            TransactionState::Retired => {}
        }
    }
    Ok(ReconcilePlan { actions })
}

fn advance(
    tracks: &mut BTreeMap<TransactionId, TransactionTrack>,
    transaction: TransactionId,
    expected: TransactionState,
    next: TransactionState,
) -> Result<(), ReconcileError> {
    let track = tracks
        .get_mut(&transaction)
        .ok_or(ReconcileError::OrderViolation)?;
    if track.state == next {
        return Err(ReconcileError::DuplicateRecord);
    }
    if track.state != expected {
        return Err(ReconcileError::OrderViolation);
    }
    track.state = next;
    Ok(())
}
