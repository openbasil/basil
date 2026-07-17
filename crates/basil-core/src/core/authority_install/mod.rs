// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! External authority installation transaction.
//!
//! This module drives a measurement-authority change end to end on the broker
//! side: stage a root-owned candidate manifest, load LSM policy additively,
//! `daemon-reload`, install the candidate helper allowlist generation, start
//! the candidate attestor, qualify it non-serving, run the final pre-commit
//! comparison, and only then ask the root installer authority to append the
//! fsynced write-ahead **commit-intent receipt** — the transaction's sole
//! linearization point. The installer's acknowledgement merely reports that
//! the receipt is durable; it carries no independent commit authority.
//!
//! Acknowledgements resolve to exactly three outcomes:
//!
//! - **Durable** — the receipt is fsynced; the installation is logically
//!   committed and completes forward (publication, active receipt, bounded
//!   drain, retirement) and can no longer be rejected.
//! - **Provably absent** — the installer states the receipt was never
//!   appended and never will be; the transaction resolves to pre-commit
//!   rejection with the old authority still serving.
//! - **Indeterminate** — the acknowledgement was lost or ambiguous. The
//!   broker never finalizes rejection, publication, or old-authority
//!   resumption while durability is unknown; only journal reconciliation
//!   (re-asking the installer) resolves the transaction.
//!
//! Before durable intent, failure or crash at any step leaves the old
//! manifest authoritative and serving and the staged generation removable.
//! After durable intent every path completes forward to the new generation;
//! failure is an applied/recovery-required outcome that startup or doctor
//! reconciliation must finish before readiness.

pub mod journal;
pub mod manifest;
pub mod reconciler;
#[cfg(test)]
mod tests;

use std::future::Future;
use std::num::NonZeroU64;
use std::time::Duration;

use async_trait::async_trait;
use thiserror::Error;

pub use journal::{
    ActiveReceipt, FileIntentJournal, IntentReceipt, JournalError, JournalReadout, JournalRecord,
    RetiredReceipt, StagedReceipt, TransactionId,
};
pub use manifest::{ManifestError, ManifestId, RetainedGeneration, StagedManifest};
pub use reconciler::{ReconcileAction, ReconcileError, ReconcilePlan, reconcile};

use crate::core::attestor_realm::{RealmError, RealmName};
use crate::release_admission::Sha256Digest;

/// Ordered installation steps.
///
/// The driver performs them strictly in this order; the additive LSM load
/// always precedes `daemon-reload`, which precedes helper-allowlist
/// installation and candidate start, and nothing dismantles the old
/// generation before retirement.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum InstallStep {
    /// Write and fsync the root-owned staged manifest.
    StageManifest,
    /// Load SELinux/AppArmor policy additively beside the old generation.
    LoadLsmAdditive,
    /// `daemon-reload` without stopping or rewriting the old generation.
    DaemonReload,
    /// Install the candidate helper allowlist generation additively.
    InstallHelperGeneration,
    /// Start the candidate attestor under its generation-qualified identity.
    StartCandidate,
    /// Broker-side non-serving qualification of the candidate.
    Qualification,
    /// Final pre-commit comparison against the staged manifest.
    PreCommitComparison,
    /// Append and fsync the write-ahead commit-intent receipt.
    CommitIntent,
    /// The atomic publication swap of realms and serving generation.
    Publication,
    /// Write and fsync the committed/active receipt.
    ActiveReceipt,
    /// Bounded drain of the superseded generation.
    Drain,
    /// Dismantle the committed, drained old generation.
    Retirement,
}

/// Typed installation failure.
#[derive(Debug, Error)]
pub enum InstallError {
    /// The host cannot keep both authority generations installed at once.
    /// The implementation must not degrade or dismantle the old authority to
    /// make room; the candidate rejects before intent.
    #[error("host maintenance required: both authority generations cannot coexist")]
    HostMaintenanceRequired,
    /// An installer step failed without further disclosure.
    #[error("installer step failed")]
    Installer,
    /// Staged-manifest validation failed.
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    /// The intent journal failed.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// A realm qualification or publication operation failed.
    #[error(transparent)]
    Realm(#[from] RealmError),
    /// The qualified candidate corpus does not match the staged manifest's
    /// pinned corpus fingerprint.
    #[error("candidate corpus fingerprint mismatch")]
    CorpusMismatch,
    /// Retirement was requested for a transaction without a durable
    /// committed/active receipt.
    #[error("retirement requires a committed transaction")]
    RetireBeforeCommit,
}

/// Installer acknowledgement of one commit-intent append.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntentAck {
    /// The receipt and its journal are fsynced: the transaction is
    /// logically committed.
    Durable,
    /// The installer states the receipt was never appended and never will
    /// be: provably absent, resolving to pre-commit rejection.
    RejectedBeforeAppend,
    /// The acknowledgement was dropped, delayed past its deadline, or the
    /// installer session severed: durability is unknown.
    Lost,
}

/// Installer's answer when the broker reconciles an ambiguous intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntentStatus {
    /// The receipt is durable in the journal.
    Durable,
    /// The installer proves the receipt is absent and will never be
    /// appended.
    ProvablyAbsent,
    /// The installer cannot yet prove either; durability stays unknown.
    Unknown,
}

/// The root installer authority the broker delegates privileged steps to.
///
/// Implementations own the intent journal and all root-only host mutation.
/// Every method must be additive with respect to the old generation: nothing
/// before [`Self::retire_generation`] may stop, restart, mask, unlink, or
/// rewrite old units, policies, directories, sockets, or helper allowlist
/// generations.
#[async_trait]
pub trait InstallerAuthority: Send + Sync {
    /// Durably write the staged manifest and its [`StagedReceipt`].
    async fn stage_manifest(
        &self,
        receipt: &StagedReceipt,
        manifest: &StagedManifest,
    ) -> Result<(), InstallError>;

    /// Load the candidate LSM policy/profile additively beside every
    /// retained generation.
    async fn load_lsm_additive(&self, manifest: &StagedManifest) -> Result<(), InstallError>;

    /// Reload the system manager without touching the old generation.
    async fn daemon_reload(&self) -> Result<(), InstallError>;

    /// Install the candidate helper allowlist generation as immutable
    /// root-owned files beside every retained generation. The single
    /// measurement-helper service keeps running.
    async fn install_helper_generation(
        &self,
        manifest: &StagedManifest,
    ) -> Result<(), InstallError>;

    /// Start the candidate attestor under its generation-qualified identity.
    async fn start_candidate(&self, manifest: &StagedManifest) -> Result<(), InstallError>;

    /// Append the write-ahead commit-intent receipt, fsync the journal and
    /// its parent directory, and acknowledge. This acknowledgement reports
    /// durability; it has no independent commit authority.
    async fn append_commit_intent(&self, receipt: &IntentReceipt) -> IntentAck;

    /// Reconcile one ambiguous intent by consulting the durable journal.
    async fn intent_status(&self, transaction: TransactionId)
    -> Result<IntentStatus, InstallError>;

    /// Durably write the committed/active receipt after publication.
    async fn finalize_active(&self, receipt: &ActiveReceipt) -> Result<(), InstallError>;

    /// Dismantle one committed, drained old generation and durably record
    /// its retirement. The only removal primitive in the transaction.
    async fn retire_generation(&self, receipt: &RetiredReceipt) -> Result<(), InstallError>;

    /// Remove one staged, never-committed candidate (manifest, unit,
    /// policies, helper generation). Legal only while no commit-intent
    /// receipt exists for the transaction.
    async fn discard_staged(&self, transaction: TransactionId) -> Result<(), InstallError>;

    /// Read the durable journal for reconciliation.
    async fn read_journal(&self) -> Result<JournalReadout, InstallError>;
}

/// One qualified, non-serving candidate that can be revalidated and then
/// atomically published. Dropping the value abandons the candidate and
/// restores staged state without touching the old authority.
#[async_trait]
pub trait CandidatePromotion: Send {
    /// Non-destructive final pre-commit comparison. Every staleness
    /// dimension rejects here, before intent, without disturbing the old
    /// session.
    async fn revalidate(&self) -> Result<(), RealmError>;

    /// The exact fingerprint of the qualified candidate corpus.
    fn corpus_fingerprint(&self) -> Sha256Digest;

    /// Atomically publish the candidate as the serving generation and
    /// return the new serving generation.
    async fn publish(self: Box<Self>) -> Result<u64, RealmError>;
}

/// The authority being superseded by an installation, if any.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreviousAuthority {
    /// Installed manifest identity of the old authority.
    pub manifest: ManifestId,
    /// Old authority generation.
    pub generation: NonZeroU64,
    /// Old helper-policy generation pinned by the old authority.
    pub helper_policy_generation: NonZeroU64,
}

/// One complete installation request.
#[derive(Clone, Debug)]
pub struct InstallationRequest {
    /// Unique transaction identifier.
    pub transaction: TransactionId,
    /// The validated staged manifest.
    pub manifest: StagedManifest,
    /// Exact candidate corpus fingerprint the qualified candidate must match.
    pub candidate_corpus: Sha256Digest,
    /// Exact broker configuration-generation fingerprint at intent time.
    pub configuration_generation: Sha256Digest,
    /// The authority being superseded, if any.
    pub previous: Option<PreviousAuthority>,
    /// Bounded drain deadline for the superseded generation.
    pub drain_deadline: Duration,
}

impl InstallationRequest {
    fn intent_receipt(&self) -> IntentReceipt {
        IntentReceipt {
            transaction: self.transaction,
            realm: self.manifest.realm().clone(),
            new_manifest: self.manifest.manifest_id(),
            previous_manifest: self.previous.map(|previous| previous.manifest),
            candidate_corpus: self.candidate_corpus,
            configuration_generation: self.configuration_generation,
            authority_generation: self.manifest.authority_generation(),
            previous_generation: self.previous.map(|previous| previous.generation),
            drain_deadline_millis: u64::try_from(self.drain_deadline.as_millis())
                .unwrap_or(u64::MAX),
        }
    }

    fn staged_receipt(&self) -> StagedReceipt {
        StagedReceipt {
            transaction: self.transaction,
            realm: self.manifest.realm().clone(),
            manifest: self.manifest.manifest_id(),
            authority_generation: self.manifest.authority_generation(),
            helper_policy_generation: self.manifest.helper_policy_generation(),
            previous_manifest: self.previous.map(|previous| previous.manifest),
        }
    }
}

/// A committed installation: the new generation serves; the old generation
/// (if any) is draining and retires through [`retire_previous`].
#[derive(Debug)]
pub struct CommittedInstallation {
    /// The owning transaction.
    pub transaction: TransactionId,
    /// The realm that changed authority.
    pub realm: RealmName,
    /// The broker registry generation now serving.
    pub serving_generation: u64,
    /// Retirement ticket for the superseded generation, if any.
    pub retirement: Option<RetirementTicket>,
}

/// Permission to retire one superseded generation after bounded drain.
/// Redeemable only for a committed transaction; [`retire_previous`] rechecks
/// the journal before dismantling anything.
#[derive(Clone, Debug)]
pub struct RetirementTicket {
    /// The owning transaction.
    pub transaction: TransactionId,
    /// The realm that changed authority.
    pub realm: RealmName,
    /// The superseded authority to dismantle after drain.
    pub previous: PreviousAuthority,
}

/// A transaction whose intent durability is unknown. The broker holds the
/// qualified candidate parked — neither rejected nor published — until
/// reconciliation resolves it.
pub struct PendingIntent {
    receipt: IntentReceipt,
    promotion: Box<dyn CandidatePromotion>,
    previous: Option<PreviousAuthority>,
}

impl std::fmt::Debug for PendingIntent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingIntent")
            .field("transaction", &self.receipt.transaction)
            .field("realm", &self.receipt.realm)
            .finish_non_exhaustive()
    }
}

impl PendingIntent {
    /// The ambiguous transaction.
    #[must_use]
    pub const fn transaction(&self) -> TransactionId {
        self.receipt.transaction
    }

    /// Re-ask the installer for the intent's durability and resolve the
    /// transaction. Returns [`InstallOutcome::DurabilityUnknown`] again when
    /// the installer still cannot prove either outcome; the caller retries.
    pub async fn resolve(self, installer: &dyn InstallerAuthority) -> InstallOutcome {
        let transaction = self.receipt.transaction;
        match installer.intent_status(transaction).await {
            Ok(IntentStatus::Durable) => {
                complete_forward(installer, self.receipt, self.promotion, self.previous).await
            }
            Ok(IntentStatus::ProvablyAbsent) => {
                // The parked candidate is dropped here: guard release and
                // staged-state restoration without touching old authority.
                drop(self.promotion);
                let _ = installer.discard_staged(transaction).await;
                InstallOutcome::RejectedPreCommit {
                    step: InstallStep::CommitIntent,
                    error: InstallError::Installer,
                }
            }
            Ok(IntentStatus::Unknown) | Err(_) => InstallOutcome::DurabilityUnknown(self),
        }
    }
}

/// Terminal (or parked) outcome of one installation drive.
#[derive(Debug)]
pub enum InstallOutcome {
    /// The transaction committed and the new generation serves.
    Committed(CommittedInstallation),
    /// The transaction rejected before durable intent. The old manifest is
    /// authoritative and serving; the staged generation is removable.
    RejectedPreCommit {
        /// The step that rejected.
        step: InstallStep,
        /// The typed failure.
        error: InstallError,
    },
    /// Intent is durable but forward completion did not finish. Recovery
    /// must complete forward to the new generation before the broker serves
    /// or reports readiness. Never a rejection.
    RecoveryRequired {
        /// The owning transaction.
        transaction: TransactionId,
        /// The step that failed after durable intent.
        step: InstallStep,
    },
    /// Intent durability is unknown. Nothing is finalized; only journal
    /// reconciliation resolves the transaction.
    DurabilityUnknown(PendingIntent),
}

/// Drive one complete installation transaction.
///
/// `qualify` runs after the candidate attestor starts and must return the
/// broker's qualified, still non-serving candidate. Every failure before the
/// commit-intent receipt is durable resolves to
/// [`InstallOutcome::RejectedPreCommit`] with the old authority untouched;
/// every failure after resolves forward.
pub async fn run_installation<F, Fut>(
    installer: &dyn InstallerAuthority,
    request: InstallationRequest,
    qualify: F,
) -> InstallOutcome
where
    F: FnOnce() -> Fut + Send,
    Fut: Future<Output = Result<Box<dyn CandidatePromotion>, RealmError>> + Send,
{
    let staged_receipt = request.staged_receipt();
    if let Err(error) = installer
        .stage_manifest(&staged_receipt, &request.manifest)
        .await
    {
        return reject_pre_commit(
            installer,
            request.transaction,
            InstallStep::StageManifest,
            error,
        )
        .await;
    }
    if let Err(error) = installer.load_lsm_additive(&request.manifest).await {
        return reject_pre_commit(
            installer,
            request.transaction,
            InstallStep::LoadLsmAdditive,
            error,
        )
        .await;
    }
    if let Err(error) = installer.daemon_reload().await {
        return reject_pre_commit(
            installer,
            request.transaction,
            InstallStep::DaemonReload,
            error,
        )
        .await;
    }
    if let Err(error) = installer.install_helper_generation(&request.manifest).await {
        return reject_pre_commit(
            installer,
            request.transaction,
            InstallStep::InstallHelperGeneration,
            error,
        )
        .await;
    }
    if let Err(error) = installer.start_candidate(&request.manifest).await {
        return reject_pre_commit(
            installer,
            request.transaction,
            InstallStep::StartCandidate,
            error,
        )
        .await;
    }
    let promotion = match qualify().await {
        Ok(promotion) => promotion,
        Err(error) => {
            return reject_pre_commit(
                installer,
                request.transaction,
                InstallStep::Qualification,
                InstallError::Realm(error),
            )
            .await;
        }
    };
    // Final pre-commit comparison: every staleness dimension rejects here,
    // before intent, without disturbing the old session.
    if promotion.corpus_fingerprint() != request.candidate_corpus {
        drop(promotion);
        return reject_pre_commit(
            installer,
            request.transaction,
            InstallStep::PreCommitComparison,
            InstallError::CorpusMismatch,
        )
        .await;
    }
    if let Err(error) = promotion.revalidate().await {
        drop(promotion);
        return reject_pre_commit(
            installer,
            request.transaction,
            InstallStep::PreCommitComparison,
            InstallError::Realm(error),
        )
        .await;
    }

    let receipt = request.intent_receipt();
    match installer.append_commit_intent(&receipt).await {
        IntentAck::Durable => {
            complete_forward(installer, receipt, promotion, request.previous).await
        }
        IntentAck::RejectedBeforeAppend => {
            drop(promotion);
            reject_pre_commit(
                installer,
                request.transaction,
                InstallStep::CommitIntent,
                InstallError::Installer,
            )
            .await
        }
        IntentAck::Lost => {
            let pending = PendingIntent {
                receipt,
                promotion,
                previous: request.previous,
            };
            pending.resolve(installer).await
        }
    }
}

/// Complete a logically committed transaction forward: publication, then the
/// committed/active receipt. Failure is applied/recovery-required, never a
/// rejection.
async fn complete_forward(
    installer: &dyn InstallerAuthority,
    receipt: IntentReceipt,
    promotion: Box<dyn CandidatePromotion>,
    previous: Option<PreviousAuthority>,
) -> InstallOutcome {
    let transaction = receipt.transaction;
    let realm = receipt.realm.clone();
    let Ok(serving_generation) = promotion.publish().await else {
        return InstallOutcome::RecoveryRequired {
            transaction,
            step: InstallStep::Publication,
        };
    };
    let active = ActiveReceipt {
        transaction,
        realm: realm.clone(),
        authority_generation: receipt.authority_generation,
        serving_generation,
    };
    if installer.finalize_active(&active).await.is_err() {
        return InstallOutcome::RecoveryRequired {
            transaction,
            step: InstallStep::ActiveReceipt,
        };
    }
    InstallOutcome::Committed(CommittedInstallation {
        transaction,
        realm: realm.clone(),
        serving_generation,
        retirement: previous.map(|previous| RetirementTicket {
            transaction,
            realm,
            previous,
        }),
    })
}

/// Resolve one pre-commit rejection: the old authority stays serving and the
/// staged candidate is removed best-effort (the reconciler discards any
/// remainder as a staged transaction without intent).
async fn reject_pre_commit(
    installer: &dyn InstallerAuthority,
    transaction: TransactionId,
    step: InstallStep,
    error: InstallError,
) -> InstallOutcome {
    let _ = installer.discard_staged(transaction).await;
    InstallOutcome::RejectedPreCommit { step, error }
}

/// Dismantle one superseded generation after bounded drain.
///
/// Retirement rechecks the durable journal and refuses unless a
/// committed/active receipt exists for the ticket's transaction: only
/// committed old generations retire. The old helper-policy generation
/// retires with it only when the new authority pins a different one.
///
/// # Errors
///
/// Returns [`InstallError::RetireBeforeCommit`] without a durable
/// committed/active receipt, and any installer failure otherwise.
pub async fn retire_previous(
    installer: &dyn InstallerAuthority,
    ticket: &RetirementTicket,
    new_helper_policy_generation: NonZeroU64,
) -> Result<(), InstallError> {
    let readout = installer.read_journal().await?;
    if readout.active_for(ticket.transaction).is_none() {
        return Err(InstallError::RetireBeforeCommit);
    }
    let retired_helper = (ticket.previous.helper_policy_generation != new_helper_policy_generation)
        .then_some(ticket.previous.helper_policy_generation);
    let receipt = RetiredReceipt {
        transaction: ticket.transaction,
        realm: ticket.realm.clone(),
        retired_generation: ticket.previous.generation,
        retired_helper_policy_generation: retired_helper,
    };
    installer.retire_generation(&receipt).await
}
