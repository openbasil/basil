// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! SPEC conformance tests 5, 7, and 9: installation crash/cancel boundaries,
//! acknowledgement loss, reload injection, and journal reconciliation.

use std::collections::BTreeMap;
use std::num::NonZeroU64;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;

use super::*;
use crate::core::attestor_realm::{RealmConfig, RealmName, RealmSet};
use crate::release_admission::Sha256Digest;

fn bootstrap(body: &str) -> toml::Value {
    let raw = format!(
        "schema = \"agent\"\nschemaVersion = 3\n[import]\ncatalog = \"catalog.json\"\npolicy = \"policy.json\"\nbundle = \"bundle.json\"\n{body}"
    );
    toml::from_str(&raw).expect("valid test TOML")
}

fn realm_body(generation: u64) -> String {
    format!(
        r#"
[attestor.realms.owner-podman]
provider = "podman"
runtimeMode = "rootless-owner"
brokerUser = "991"
brokerUnit = "basil-agent.service"
attestorUid = "1000"
releaseRole = "podman-attestor"
target = "x86_64-unknown-linux-gnu"
protocol = 1
capabilities = ["health", "query-instances", "resolve-peer"]

[attestor.realms.owner-podman.measurement]
authorityGeneration = {generation}
serviceUnit = "basil-attestor-owner-podman-g{generation}.service"
helperEndpoint = "/run/basil/measure/control.sock"
helperPolicy = "basil-measure-policy-g{generation}"
helperPolicyGeneration = {generation}
lsmProfile = "selinux:basil_attestor_g{generation}_t"
lsmPolicy = "basil-attestor-policy-g{generation}"
lockdownProfile = "basil-attestor-lockdown-g{generation}"
runtimeDirectory = "/run/basil/attestors/owner-podman/g{generation}"
runtimeDirectoryOwner = "0"
runtimeDirectoryGroup = "993"
runtimeDirectoryMode = "0770"
runtimeDirectoryAcl = "basil-attestor-bind-g{generation}"
socketPath = "/run/basil/attestors/owner-podman/g{generation}/control.sock"
socketOwner = "1000"
socketGroup = "994"
socketMode = "0660"
socketAcl = "basil-attestor-control-g{generation}"
"#
    )
}

fn realm_config(generation: u64) -> (RealmName, RealmConfig) {
    let realms =
        RealmSet::from_bootstrap(&bootstrap(&realm_body(generation))).expect("valid realm config");
    let name = RealmName::new("owner-podman").expect("valid realm name");
    let config = realms.get(&name).expect("configured realm").clone();
    (name, config)
}

fn nonzero(value: u64) -> NonZeroU64 {
    NonZeroU64::new(value).expect("nonzero fixture")
}

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}

fn manifest(generation: u64) -> StagedManifest {
    let (name, config) = realm_config(generation);
    StagedManifest::stage(&name, &config, BTreeMap::new(), &[], None).expect("stageable manifest")
}

fn retained_g1() -> RetainedGeneration {
    RetainedGeneration {
        generation: nonzero(1),
        manifest: manifest(1).manifest_id(),
        runtime_directory: PathBuf::from("/run/basil/attestors/owner-podman/g1"),
        socket_path: PathBuf::from("/run/basil/attestors/owner-podman/g1/control.sock"),
    }
}

fn request(transaction: TransactionId) -> InstallationRequest {
    InstallationRequest {
        transaction,
        manifest: manifest(2),
        candidate_corpus: digest(9),
        configuration_generation: digest(11),
        previous: Some(PreviousAuthority {
            manifest: manifest(1).manifest_id(),
            generation: nonzero(1),
            helper_policy_generation: nonzero(1),
        }),
        drain_deadline: Duration::from_secs(30),
    }
}

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

    pub fn create() -> TempDirHandle {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "basil-authority-install-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        TempDirHandle { path }
    }
}

/// Which trait step of the fake installer fails, if any.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FailPoint {
    None,
    Stage,
    Lsm,
    DaemonReload,
    Helper,
    Start,
    FinalizeActive,
}

/// How the fake installer treats the commit-intent append.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AckMode {
    AppendDurable,
    AppendLoseAck,
    LoseWithoutAppend,
    RejectBeforeAppend,
    TornAppendLoseAck,
}

struct FakeInstaller {
    journal: FileIntentJournal,
    log: Mutex<Vec<&'static str>>,
    fail_point: FailPoint,
    fail_error: fn() -> InstallError,
    ack_mode: AckMode,
    absent_status: IntentStatus,
    discards: AtomicUsize,
    retired: Mutex<Vec<RetiredReceipt>>,
}

impl FakeInstaller {
    fn new(dir: &tempdir::TempDirHandle) -> Self {
        Self {
            journal: FileIntentJournal::in_directory(&dir.path),
            log: Mutex::new(Vec::new()),
            fail_point: FailPoint::None,
            fail_error: || InstallError::Installer,
            ack_mode: AckMode::AppendDurable,
            absent_status: IntentStatus::Unknown,
            discards: AtomicUsize::new(0),
            retired: Mutex::new(Vec::new()),
        }
    }

    fn log_step(&self, step: &'static str) {
        self.log.lock().expect("log lock").push(step);
    }

    fn steps(&self) -> Vec<&'static str> {
        self.log.lock().expect("log lock").clone()
    }

    fn step(&self, name: &'static str, point: FailPoint) -> Result<(), InstallError> {
        self.log_step(name);
        if self.fail_point == point {
            return Err((self.fail_error)());
        }
        Ok(())
    }
}

#[async_trait]
impl InstallerAuthority for FakeInstaller {
    async fn stage_manifest(
        &self,
        receipt: &StagedReceipt,
        _manifest: &StagedManifest,
    ) -> Result<(), InstallError> {
        self.step("stage", FailPoint::Stage)?;
        self.journal
            .append(&JournalRecord::Staged(receipt.clone()))
            .map_err(InstallError::from)
    }

    async fn load_lsm_additive(&self, _manifest: &StagedManifest) -> Result<(), InstallError> {
        self.step("lsm", FailPoint::Lsm)
    }

    async fn daemon_reload(&self) -> Result<(), InstallError> {
        self.step("daemon-reload", FailPoint::DaemonReload)
    }

    async fn install_helper_generation(
        &self,
        _manifest: &StagedManifest,
    ) -> Result<(), InstallError> {
        self.step("helper", FailPoint::Helper)
    }

    async fn start_candidate(&self, _manifest: &StagedManifest) -> Result<(), InstallError> {
        self.step("start", FailPoint::Start)
    }

    async fn append_commit_intent(&self, receipt: &IntentReceipt) -> IntentAck {
        self.log_step("intent");
        match self.ack_mode {
            AckMode::AppendDurable | AckMode::AppendLoseAck => {
                if self
                    .journal
                    .append(&JournalRecord::Intent(receipt.clone()))
                    .is_err()
                {
                    return IntentAck::Lost;
                }
                if self.ack_mode == AckMode::AppendDurable {
                    IntentAck::Durable
                } else {
                    IntentAck::Lost
                }
            }
            AckMode::LoseWithoutAppend => IntentAck::Lost,
            AckMode::RejectBeforeAppend => IntentAck::RejectedBeforeAppend,
            AckMode::TornAppendLoseAck => {
                // Crash mid-append: a partial frame reaches the file, the
                // fsync never completes, and the acknowledgement is lost.
                let payload =
                    serde_json::to_vec(&JournalRecord::Intent(receipt.clone())).expect("serialize");
                let length = u32::try_from(payload.len()).expect("bounded length");
                let mut torn = length.to_be_bytes().to_vec();
                torn.extend_from_slice(payload.get(..payload.len() / 2).expect("half payload"));
                let mut bytes = std::fs::read(self.journal.path()).unwrap_or_default();
                bytes.extend_from_slice(&torn);
                std::fs::write(self.journal.path(), bytes).expect("write torn journal");
                IntentAck::Lost
            }
        }
    }

    async fn intent_status(
        &self,
        transaction: TransactionId,
    ) -> Result<IntentStatus, InstallError> {
        self.log_step("status");
        let readout = self.journal.read()?;
        if readout.intent_for(transaction).is_some() {
            return Ok(IntentStatus::Durable);
        }
        Ok(self.absent_status)
    }

    async fn finalize_active(&self, receipt: &ActiveReceipt) -> Result<(), InstallError> {
        self.step("active", FailPoint::FinalizeActive)?;
        self.journal
            .append(&JournalRecord::Active(receipt.clone()))
            .map_err(InstallError::from)
    }

    async fn retire_generation(&self, receipt: &RetiredReceipt) -> Result<(), InstallError> {
        self.log_step("retire");
        self.journal
            .append(&JournalRecord::Retired(receipt.clone()))?;
        self.retired
            .lock()
            .expect("retired lock")
            .push(receipt.clone());
        Ok(())
    }

    async fn discard_staged(&self, transaction: TransactionId) -> Result<(), InstallError> {
        self.log_step("discard");
        self.discards.fetch_add(1, Ordering::SeqCst);
        // Close the journal track with the terminal discarded receipt, as
        // the installer contract requires (skipped when staging failed
        // before its receipt was appended).
        let readout = self.journal.read()?;
        let staged_realm = readout.records.iter().find_map(|record| match record {
            JournalRecord::Staged(receipt) if receipt.transaction == transaction => {
                Some(receipt.realm.clone())
            }
            _ => None,
        });
        if let Some(realm) = staged_realm {
            self.journal
                .append(&JournalRecord::Discarded(DiscardedReceipt {
                    transaction,
                    realm,
                }))?;
        }
        Ok(())
    }

    async fn read_journal(&self) -> Result<JournalReadout, InstallError> {
        Ok(self.journal.read()?)
    }
}

struct FakePromotion {
    corpus: Sha256Digest,
    revalidate_stale: bool,
    publish_fails: bool,
    published: Arc<AtomicBool>,
    dropped_unpublished: Arc<AtomicUsize>,
}

impl FakePromotion {
    fn tracked(published: &Arc<AtomicBool>, dropped_unpublished: &Arc<AtomicUsize>) -> Self {
        Self {
            corpus: digest(9),
            revalidate_stale: false,
            publish_fails: false,
            published: Arc::clone(published),
            dropped_unpublished: Arc::clone(dropped_unpublished),
        }
    }
}

impl Drop for FakePromotion {
    fn drop(&mut self) {
        if !self.published.load(Ordering::SeqCst) {
            // Dropping an unpublished candidate releases its guards and
            // restores staged state without touching the old authority.
            self.dropped_unpublished.fetch_add(1, Ordering::SeqCst);
        }
    }
}

#[async_trait]
impl CandidatePromotion for FakePromotion {
    async fn revalidate(&self) -> Result<(), RealmError> {
        if self.revalidate_stale {
            return Err(RealmError::Stale);
        }
        Ok(())
    }

    fn corpus_fingerprint(&self) -> Sha256Digest {
        self.corpus
    }

    async fn publish(self: Box<Self>) -> Result<u64, RealmError> {
        if self.publish_fails {
            return Err(RealmError::Stale);
        }
        self.published.store(true, Ordering::SeqCst);
        Ok(2)
    }
}

fn tracked_promotion() -> (Box<FakePromotion>, Arc<AtomicBool>, Arc<AtomicUsize>) {
    let published = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicUsize::new(0));
    let promotion = Box::new(FakePromotion::tracked(&published, &dropped));
    (promotion, published, dropped)
}

// --- Journal durability and framing (supports SPEC test 5) ---

#[test]
fn journal_round_trips_every_receipt_kind_durably() {
    let dir = tempdir::create();
    let journal = FileIntentJournal::in_directory(&dir.path);
    let transaction = TransactionId::from_bytes([1; 16]);
    let staged = request(transaction).staged_receipt();
    let intent = request(transaction).intent_receipt();
    let active = ActiveReceipt {
        transaction,
        realm: RealmName::new("owner-podman").expect("realm"),
        authority_generation: nonzero(2),
        serving_generation: 2,
    };
    let retired = RetiredReceipt {
        transaction,
        realm: RealmName::new("owner-podman").expect("realm"),
        retired_generation: nonzero(1),
        retired_helper_policy_generation: Some(nonzero(1)),
    };
    let discarded = DiscardedReceipt {
        transaction: TransactionId::from_bytes([99; 16]),
        realm: RealmName::new("owner-podman").expect("realm"),
    };
    let records = [
        JournalRecord::Staged(staged),
        JournalRecord::Intent(intent),
        JournalRecord::Active(active),
        JournalRecord::Retired(retired),
        JournalRecord::Discarded(discarded),
    ];
    for record in &records {
        journal.append(record).expect("append");
    }
    let readout = journal.read().expect("read");
    assert!(!readout.torn_tail);
    assert_eq!(readout.records, records);
    assert!(readout.intent_for(transaction).is_some());
    assert!(readout.active_for(transaction).is_some());
}

#[test]
fn journal_reports_torn_tail_and_keeps_prior_records() {
    let dir = tempdir::create();
    let journal = FileIntentJournal::in_directory(&dir.path);
    let transaction = TransactionId::from_bytes([2; 16]);
    journal
        .append(&JournalRecord::Staged(
            request(transaction).staged_receipt(),
        ))
        .expect("append");
    let complete = std::fs::read(journal.path()).expect("read journal bytes");
    // Cut mid-length, mid-payload, and mid-checksum: all torn, never corrupt.
    for cut in [2_usize, complete.len() / 2, complete.len() - 8] {
        let mut torn = complete.clone();
        torn.extend_from_slice(complete.get(..cut).expect("cut"));
        let readout = journal::parse_journal_bytes(&torn).expect("torn is not corrupt");
        assert!(readout.torn_tail, "cut at {cut} must read as torn");
        assert_eq!(readout.records.len(), 1, "prior record survives cut {cut}");
    }
}

#[test]
fn journal_interior_damage_fails_closed() {
    let dir = tempdir::create();
    let journal = FileIntentJournal::in_directory(&dir.path);
    let transaction = TransactionId::from_bytes([3; 16]);
    journal
        .append(&JournalRecord::Staged(
            request(transaction).staged_receipt(),
        ))
        .expect("append staged");
    journal
        .append(&JournalRecord::Intent(
            request(transaction).intent_receipt(),
        ))
        .expect("append intent");
    let complete = std::fs::read(journal.path()).expect("read journal bytes");
    // Flip one payload byte of the FIRST record: interior damage.
    let mut damaged = complete.clone();
    if let Some(byte) = damaged.get_mut(10) {
        *byte ^= 0xFF;
    }
    assert!(matches!(
        journal::parse_journal_bytes(&damaged),
        Err(JournalError::Corrupt)
    ));
    // An absurd but complete length prefix is corruption, not a torn tail.
    let mut absurd = complete;
    absurd.extend_from_slice(&u32::MAX.to_be_bytes());
    absurd.extend_from_slice(&[0_u8; 16]);
    assert!(matches!(
        journal::parse_journal_bytes(&absurd),
        Err(JournalError::Corrupt)
    ));
}

#[test]
fn journal_append_heals_a_torn_tail_and_refuses_corruption() {
    let dir = tempdir::create();
    let journal = FileIntentJournal::in_directory(&dir.path);
    let transaction = TransactionId::from_bytes([4; 16]);
    journal
        .append(&JournalRecord::Staged(
            request(transaction).staged_receipt(),
        ))
        .expect("append staged");
    // Simulate a crashed earlier append: a partial frame at the tail.
    let intent = request(transaction).intent_receipt();
    let payload = serde_json::to_vec(&JournalRecord::Intent(intent.clone())).expect("serialize");
    let length = u32::try_from(payload.len()).expect("bounded");
    let mut bytes = std::fs::read(journal.path()).expect("read");
    let durable_len = bytes.len();
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(payload.get(..payload.len() / 2).expect("half"));
    std::fs::write(journal.path(), bytes).expect("write torn");
    // The next append truncates the non-durable torn tail first, so the new
    // frame never reads as interior corruption.
    journal
        .append(&JournalRecord::Intent(intent))
        .expect("append heals the torn tail");
    let readout = journal.read().expect("read");
    assert!(!readout.torn_tail);
    assert_eq!(readout.records.len(), 2);
    assert!(readout.intent_for(transaction).is_some());
    // Interior corruption refuses further appends: fail closed.
    let mut damaged = std::fs::read(journal.path()).expect("read");
    if let Some(byte) = damaged.get_mut(10) {
        *byte ^= 0xFF;
    }
    std::fs::write(journal.path(), damaged).expect("write damaged");
    assert!(matches!(
        journal.append(&JournalRecord::Staged(
            request(TransactionId::from_bytes([5; 16])).staged_receipt(),
        )),
        Err(JournalError::Corrupt)
    ));
    let expected_len = u64::try_from(durable_len).expect("bounded");
    assert!(
        std::fs::metadata(journal.path()).expect("metadata").len() > expected_len,
        "a refused append never truncates a corrupt journal"
    );
}

#[test]
fn journal_is_created_private_and_never_follows_a_symlink() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempdir::create();
    let journal = FileIntentJournal::in_directory(&dir.path);
    let transaction = TransactionId::from_bytes([6; 16]);
    journal
        .append(&JournalRecord::Staged(
            request(transaction).staged_receipt(),
        ))
        .expect("append");
    let mode = std::fs::metadata(journal.path())
        .expect("metadata")
        .permissions()
        .mode();
    assert_eq!(mode & 0o077, 0, "no group/world access: {mode:o}");
    // A symlink planted at the journal path fails closed on both paths.
    let target = dir.path.join("elsewhere");
    std::fs::write(&target, b"decoy").expect("write target");
    std::fs::remove_file(journal.path()).expect("remove journal");
    std::os::unix::fs::symlink(&target, journal.path()).expect("plant symlink");
    assert!(matches!(
        journal.append(&JournalRecord::Staged(
            request(transaction).staged_receipt(),
        )),
        Err(JournalError::Io { .. })
    ));
    assert!(matches!(journal.read(), Err(JournalError::Io { .. })));
    assert_eq!(
        std::fs::read(&target).expect("target intact"),
        b"decoy",
        "the symlink target is never written through"
    );
}

// --- Staged manifests ---

#[test]
fn staging_rejects_generation_reuse_and_path_collisions() {
    let (name, config_g1) = realm_config(1);
    let retained = vec![retained_g1()];
    assert_eq!(
        StagedManifest::stage(&name, &config_g1, BTreeMap::new(), &retained, None),
        Err(ManifestError::GenerationReuse)
    );
    let (_, config_g2) = realm_config(2);
    let mut dir_collision = retained.clone();
    if let Some(entry) = dir_collision.get_mut(0) {
        entry.generation = nonzero(3);
        entry.runtime_directory = config_g2.measurement.runtime_directory.clone();
    }
    assert_eq!(
        StagedManifest::stage(&name, &config_g2, BTreeMap::new(), &dir_collision, None),
        Err(ManifestError::RuntimeDirectoryCollision)
    );
    let mut socket_collision = retained.clone();
    if let Some(entry) = socket_collision.get_mut(0) {
        entry.generation = nonzero(3);
        entry.socket_path = config_g2.measurement.socket_path.clone();
    }
    assert_eq!(
        StagedManifest::stage(&name, &config_g2, BTreeMap::new(), &socket_collision, None),
        Err(ManifestError::SocketPathCollision)
    );
    assert!(StagedManifest::stage(&name, &config_g2, BTreeMap::new(), &retained, None).is_ok());
}

#[test]
fn manifest_id_pins_every_generation_qualified_component() {
    let first = manifest(2).manifest_id();
    let second = manifest(2).manifest_id();
    assert_eq!(first, second, "manifest identity is deterministic");
    assert_ne!(
        manifest(2).manifest_id(),
        manifest(3).manifest_id(),
        "a different pinned generation yields a different manifest identity"
    );
    let (name, config) = realm_config(2);
    let mut fingerprints = BTreeMap::new();
    fingerprints.insert("attestor-binary".to_string(), digest(4));
    let with_fingerprints =
        StagedManifest::stage(&name, &config, fingerprints, &[], None).expect("stageable");
    assert_ne!(manifest(2).manifest_id(), with_fingerprints.manifest_id());
}

// --- SPEC test 5 + 7: crash/cancel boundaries and reload injection ---

#[tokio::test]
async fn pre_intent_failure_at_every_step_leaves_old_authority() {
    let cases = [
        (FailPoint::Stage, InstallStep::StageManifest),
        (FailPoint::Lsm, InstallStep::LoadLsmAdditive),
        (FailPoint::DaemonReload, InstallStep::DaemonReload),
        (FailPoint::Helper, InstallStep::InstallHelperGeneration),
        (FailPoint::Start, InstallStep::StartCandidate),
    ];
    for (fail_point, expected_step) in cases {
        let dir = tempdir::create();
        let mut installer = FakeInstaller::new(&dir);
        installer.fail_point = fail_point;
        let transaction = TransactionId::from_bytes([5; 16]);
        let (promotion, published, dropped) = tracked_promotion();
        let outcome = run_installation(&installer, request(transaction), move || async move {
            Ok(promotion as Box<dyn CandidatePromotion>)
        })
        .await;
        let InstallOutcome::RejectedPreCommit { step, .. } = outcome else {
            panic!("{fail_point:?} must reject pre-commit");
        };
        assert_eq!(step, expected_step);
        assert_eq!(installer.discards.load(Ordering::SeqCst), 1);
        assert!(!published.load(Ordering::SeqCst), "candidate never serves");
        assert_eq!(dropped.load(Ordering::SeqCst), 1, "guard released");
        let readout = installer.journal.read().expect("read journal");
        assert!(
            readout.intent_for(transaction).is_none(),
            "no intent receipt exists before {expected_step:?} rejection"
        );
    }
}

#[tokio::test]
async fn qualification_and_pre_commit_comparison_reject_before_intent() {
    // Qualification failure.
    let dir = tempdir::create();
    let installer = FakeInstaller::new(&dir);
    let transaction = TransactionId::from_bytes([6; 16]);
    let outcome = run_installation(&installer, request(transaction), || async {
        Err(RealmError::Health)
    })
    .await;
    assert!(matches!(
        outcome,
        InstallOutcome::RejectedPreCommit {
            step: InstallStep::Qualification,
            ..
        }
    ));
    // Stale source fingerprint: qualified corpus differs from the manifest.
    let (mut promotion, published, dropped) = tracked_promotion();
    promotion.corpus = digest(200);
    let outcome = run_installation(&installer, request(transaction), move || async move {
        Ok(promotion as Box<dyn CandidatePromotion>)
    })
    .await;
    assert!(matches!(
        outcome,
        InstallOutcome::RejectedPreCommit {
            step: InstallStep::PreCommitComparison,
            error: InstallError::CorpusMismatch,
        }
    ));
    assert!(!published.load(Ordering::SeqCst));
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    // Stale realm binding at final comparison.
    let (mut promotion, _, _) = tracked_promotion();
    promotion.revalidate_stale = true;
    let outcome = run_installation(&installer, request(transaction), move || async move {
        Ok(promotion as Box<dyn CandidatePromotion>)
    })
    .await;
    assert!(matches!(
        outcome,
        InstallOutcome::RejectedPreCommit {
            step: InstallStep::PreCommitComparison,
            error: InstallError::Realm(RealmError::Stale),
        }
    ));
    let readout = installer.journal.read().expect("read journal");
    assert!(readout.intent_for(transaction).is_none());
}

#[tokio::test]
async fn successful_installation_orders_steps_additively() {
    let dir = tempdir::create();
    let installer = FakeInstaller::new(&dir);
    let transaction = TransactionId::from_bytes([7; 16]);
    let (promotion, published, _) = tracked_promotion();
    let outcome = run_installation(&installer, request(transaction), move || async move {
        Ok(promotion as Box<dyn CandidatePromotion>)
    })
    .await;
    let InstallOutcome::Committed(committed) = outcome else {
        panic!("installation must commit");
    };
    assert_eq!(committed.serving_generation, 2);
    assert!(published.load(Ordering::SeqCst));
    assert_eq!(
        installer.steps(),
        vec![
            "stage",
            "lsm",
            "daemon-reload",
            "helper",
            "start",
            "intent",
            "active"
        ],
        "additive LSM load precedes daemon-reload, helper install, and start; \
         nothing dismantles the old generation"
    );
    let retirement = committed.retirement.expect("retirement ticket");
    assert_eq!(retirement.previous.generation, nonzero(1));
    let readout = installer.journal.read().expect("read journal");
    assert!(readout.intent_for(transaction).is_some());
    assert!(readout.active_for(transaction).is_some());
}

#[tokio::test]
async fn host_maintenance_required_rejects_before_intent() {
    let dir = tempdir::create();
    let mut installer = FakeInstaller::new(&dir);
    installer.fail_point = FailPoint::Start;
    installer.fail_error = || InstallError::HostMaintenanceRequired;
    let transaction = TransactionId::from_bytes([8; 16]);
    let (promotion, _, _) = tracked_promotion();
    let outcome = run_installation(&installer, request(transaction), move || async move {
        Ok(promotion as Box<dyn CandidatePromotion>)
    })
    .await;
    assert!(matches!(
        outcome,
        InstallOutcome::RejectedPreCommit {
            step: InstallStep::StartCandidate,
            error: InstallError::HostMaintenanceRequired,
        }
    ));
    let readout = installer.journal.read().expect("read journal");
    assert!(readout.intent_for(transaction).is_none());
}

// --- SPEC test 5: acknowledgement loss on both sides of the fsync ---

#[tokio::test]
async fn durable_but_unacknowledged_intent_resolves_forward() {
    let dir = tempdir::create();
    let mut installer = FakeInstaller::new(&dir);
    installer.ack_mode = AckMode::AppendLoseAck;
    let transaction = TransactionId::from_bytes([9; 16]);
    let (promotion, published, _) = tracked_promotion();
    let outcome = run_installation(&installer, request(transaction), move || async move {
        Ok(promotion as Box<dyn CandidatePromotion>)
    })
    .await;
    assert!(
        matches!(outcome, InstallOutcome::Committed(_)),
        "a durable receipt with a lost acknowledgement resolves forward"
    );
    assert!(published.load(Ordering::SeqCst));
    assert_eq!(installer.discards.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn provably_absent_intent_resolves_to_pre_commit_rejection() {
    let dir = tempdir::create();
    let mut installer = FakeInstaller::new(&dir);
    installer.ack_mode = AckMode::LoseWithoutAppend;
    installer.absent_status = IntentStatus::ProvablyAbsent;
    let transaction = TransactionId::from_bytes([10; 16]);
    let (promotion, published, dropped) = tracked_promotion();
    let outcome = run_installation(&installer, request(transaction), move || async move {
        Ok(promotion as Box<dyn CandidatePromotion>)
    })
    .await;
    assert!(matches!(
        outcome,
        InstallOutcome::RejectedPreCommit {
            step: InstallStep::CommitIntent,
            ..
        }
    ));
    assert!(!published.load(Ordering::SeqCst));
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    assert_eq!(installer.discards.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn unknown_durability_finalizes_nothing_until_reconciled() {
    let dir = tempdir::create();
    let mut installer = FakeInstaller::new(&dir);
    installer.ack_mode = AckMode::LoseWithoutAppend;
    installer.absent_status = IntentStatus::Unknown;
    let transaction = TransactionId::from_bytes([11; 16]);
    let (promotion, published, dropped) = tracked_promotion();
    let outcome = run_installation(&installer, request(transaction), move || async move {
        Ok(promotion as Box<dyn CandidatePromotion>)
    })
    .await;
    let InstallOutcome::DurabilityUnknown(pending) = outcome else {
        panic!("unknown durability must park the transaction");
    };
    assert!(!published.load(Ordering::SeqCst), "no publication");
    assert_eq!(
        dropped.load(Ordering::SeqCst),
        0,
        "no rejection: guard parked"
    );
    assert_eq!(installer.discards.load(Ordering::SeqCst), 0, "no discard");
    // Still unknown: stays parked.
    let outcome = pending.resolve(&installer).await;
    let InstallOutcome::DurabilityUnknown(pending) = outcome else {
        panic!("still-unknown durability must stay parked");
    };
    // The installer completes the delayed append; reconciliation now proves
    // durability and the transaction completes forward.
    installer
        .journal
        .append(&JournalRecord::Intent(
            request(transaction).intent_receipt(),
        ))
        .expect("late append");
    let outcome = pending.resolve(&installer).await;
    assert!(matches!(outcome, InstallOutcome::Committed(_)));
    assert!(published.load(Ordering::SeqCst));
}

#[tokio::test]
async fn installer_rejection_before_append_is_pre_commit() {
    let dir = tempdir::create();
    let mut installer = FakeInstaller::new(&dir);
    installer.ack_mode = AckMode::RejectBeforeAppend;
    let transaction = TransactionId::from_bytes([20; 16]);
    let (promotion, published, dropped) = tracked_promotion();
    let outcome = run_installation(&installer, request(transaction), move || async move {
        Ok(promotion as Box<dyn CandidatePromotion>)
    })
    .await;
    assert!(matches!(
        outcome,
        InstallOutcome::RejectedPreCommit {
            step: InstallStep::CommitIntent,
            ..
        }
    ));
    assert!(!published.load(Ordering::SeqCst));
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    let readout = installer.journal.read().expect("read journal");
    assert!(readout.intent_for(transaction).is_none());
}

#[tokio::test]
async fn torn_intent_append_is_not_durable() {
    let dir = tempdir::create();
    let mut installer = FakeInstaller::new(&dir);
    installer.ack_mode = AckMode::TornAppendLoseAck;
    installer.absent_status = IntentStatus::ProvablyAbsent;
    let transaction = TransactionId::from_bytes([12; 16]);
    let (promotion, published, _) = tracked_promotion();
    let outcome = run_installation(&installer, request(transaction), move || async move {
        Ok(promotion as Box<dyn CandidatePromotion>)
    })
    .await;
    assert!(
        matches!(
            outcome,
            InstallOutcome::RejectedPreCommit {
                step: InstallStep::CommitIntent,
                ..
            }
        ),
        "a torn append is provably absent once the installer says so"
    );
    assert!(!published.load(Ordering::SeqCst));
    let readout = installer.journal.read().expect("journal reads");
    assert!(readout.intent_for(transaction).is_none());
    // The rejection's discard appended the terminal discarded receipt,
    // healing (truncating) the non-durable torn tail in the process.
    assert!(!readout.torn_tail, "the discard append heals the torn tail");
    assert_eq!(readout.records.len(), 2, "staged + discarded receipts");
    assert!(matches!(
        readout.records.last(),
        Some(JournalRecord::Discarded(_))
    ));
}

#[tokio::test]
async fn post_intent_failure_is_recovery_required_never_rejection() {
    // Publication failure after durable intent.
    let dir = tempdir::create();
    let installer = FakeInstaller::new(&dir);
    let transaction = TransactionId::from_bytes([13; 16]);
    let (mut promotion, _, _) = tracked_promotion();
    promotion.publish_fails = true;
    let outcome = run_installation(&installer, request(transaction), move || async move {
        Ok(promotion as Box<dyn CandidatePromotion>)
    })
    .await;
    assert!(matches!(
        outcome,
        InstallOutcome::RecoveryRequired {
            step: InstallStep::Publication,
            ..
        }
    ));
    assert_eq!(
        installer.discards.load(Ordering::SeqCst),
        0,
        "never discarded"
    );
    // Active-receipt failure after publication.
    let dir = tempdir::create();
    let mut installer = FakeInstaller::new(&dir);
    installer.fail_point = FailPoint::FinalizeActive;
    let (promotion, published, _) = tracked_promotion();
    let outcome = run_installation(&installer, request(transaction), move || async move {
        Ok(promotion as Box<dyn CandidatePromotion>)
    })
    .await;
    assert!(matches!(
        outcome,
        InstallOutcome::RecoveryRequired {
            step: InstallStep::ActiveReceipt,
            ..
        }
    ));
    assert!(published.load(Ordering::SeqCst), "publication stands");
    assert_eq!(installer.discards.load(Ordering::SeqCst), 0);
    let readout = installer.journal.read().expect("read journal");
    assert!(readout.intent_for(transaction).is_some(), "intent survives");
}

// --- Drain and retirement ---

#[tokio::test]
async fn retirement_requires_a_committed_transaction() {
    let dir = tempdir::create();
    let installer = FakeInstaller::new(&dir);
    let transaction = TransactionId::from_bytes([14; 16]);
    let ticket = RetirementTicket {
        transaction,
        realm: RealmName::new("owner-podman").expect("realm"),
        previous: PreviousAuthority {
            manifest: manifest(1).manifest_id(),
            generation: nonzero(1),
            helper_policy_generation: nonzero(1),
        },
    };
    // No committed/active receipt: retirement refuses and dismantles nothing.
    assert!(matches!(
        retire_previous(&installer, &ticket, nonzero(2)).await,
        Err(InstallError::RetireBeforeCommit)
    ));
    assert!(installer.retired.lock().expect("retired lock").is_empty());
    // Commit the transaction, then retire.
    let (promotion, _, _) = tracked_promotion();
    let outcome = run_installation(&installer, request(transaction), move || async move {
        Ok(promotion as Box<dyn CandidatePromotion>)
    })
    .await;
    assert!(matches!(outcome, InstallOutcome::Committed(_)));
    retire_previous(&installer, &ticket, nonzero(2))
        .await
        .expect("retire committed old generation");
    let retired = installer.retired.lock().expect("retired lock").clone();
    assert_eq!(retired.len(), 1);
    assert_eq!(retired[0].retired_generation, nonzero(1));
    assert_eq!(
        retired[0].retired_helper_policy_generation,
        Some(nonzero(1)),
        "old helper-policy generation retires only after its pinning authority"
    );
}

#[tokio::test]
async fn shared_helper_policy_generation_is_not_retired() {
    let dir = tempdir::create();
    let installer = FakeInstaller::new(&dir);
    let transaction = TransactionId::from_bytes([15; 16]);
    let (promotion, _, _) = tracked_promotion();
    let outcome = run_installation(&installer, request(transaction), move || async move {
        Ok(promotion as Box<dyn CandidatePromotion>)
    })
    .await;
    assert!(matches!(outcome, InstallOutcome::Committed(_)));
    let ticket = RetirementTicket {
        transaction,
        realm: RealmName::new("owner-podman").expect("realm"),
        previous: PreviousAuthority {
            manifest: manifest(1).manifest_id(),
            generation: nonzero(1),
            helper_policy_generation: nonzero(1),
        },
    };
    // The new authority still pins helper-policy generation 1: retire the
    // authority generation but keep the helper generation installed.
    retire_previous(&installer, &ticket, nonzero(1))
        .await
        .expect("retire");
    let retired = installer.retired.lock().expect("retired lock").clone();
    assert_eq!(retired[0].retired_helper_policy_generation, None);
}

#[tokio::test]
async fn rejected_attempts_accumulate_without_bricking_reconciliation() {
    let dir = tempdir::create();
    let installer = FakeInstaller::new(&dir);
    // Two rejected attempts in the same realm (stale corpus), no crash.
    for id in [21_u8, 22] {
        let (mut promotion, _, _) = tracked_promotion();
        promotion.corpus = digest(200);
        let outcome = run_installation(
            &installer,
            request(TransactionId::from_bytes([id; 16])),
            move || async move { Ok(promotion as Box<dyn CandidatePromotion>) },
        )
        .await;
        assert!(matches!(outcome, InstallOutcome::RejectedPreCommit { .. }));
    }
    // A third attempt succeeds.
    let transaction = TransactionId::from_bytes([23; 16]);
    let (promotion, _, _) = tracked_promotion();
    let outcome = run_installation(&installer, request(transaction), move || async move {
        Ok(promotion as Box<dyn CandidatePromotion>)
    })
    .await;
    assert!(matches!(outcome, InstallOutcome::Committed(_)));
    // The journal now holds three transactions' history for one realm.
    // Reconciliation still classifies it: recover the committed authority,
    // nothing else, and readiness is never bricked.
    let readout = installer.journal.read().expect("read journal");
    let plan = reconcile(&readout).expect("multi-attempt journal reconciles");
    assert_eq!(
        plan.actions,
        vec![ReconcileAction::RecoverActive {
            transaction,
            realm: RealmName::new("owner-podman").expect("realm"),
            retirement_pending: true,
        }]
    );
    assert!(plan.ready());
}

// --- SPEC test 9: reconciler ---

fn staged_record(id: u8, realm: &str) -> JournalRecord {
    JournalRecord::Staged(StagedReceipt {
        transaction: TransactionId::from_bytes([id; 16]),
        realm: RealmName::new(realm).expect("realm"),
        manifest: manifest(2).manifest_id(),
        authority_generation: nonzero(2),
        helper_policy_generation: nonzero(2),
        previous_manifest: None,
    })
}

fn intent_record(id: u8, realm: &str, previous: Option<u64>) -> JournalRecord {
    intent_gen_record(id, realm, 2, previous)
}

fn intent_gen_record(id: u8, realm: &str, generation: u64, previous: Option<u64>) -> JournalRecord {
    JournalRecord::Intent(IntentReceipt {
        transaction: TransactionId::from_bytes([id; 16]),
        realm: RealmName::new(realm).expect("realm"),
        new_manifest: manifest(2).manifest_id(),
        previous_manifest: None,
        candidate_corpus: digest(9),
        configuration_generation: digest(11),
        authority_generation: nonzero(generation),
        previous_generation: previous.map(nonzero),
        drain_deadline_millis: 30_000,
    })
}

fn discarded_record(id: u8, realm: &str) -> JournalRecord {
    JournalRecord::Discarded(DiscardedReceipt {
        transaction: TransactionId::from_bytes([id; 16]),
        realm: RealmName::new(realm).expect("realm"),
    })
}

fn active_record(id: u8, realm: &str) -> JournalRecord {
    JournalRecord::Active(ActiveReceipt {
        transaction: TransactionId::from_bytes([id; 16]),
        realm: RealmName::new(realm).expect("realm"),
        authority_generation: nonzero(2),
        serving_generation: 2,
    })
}

fn retired_record(id: u8, realm: &str) -> JournalRecord {
    JournalRecord::Retired(RetiredReceipt {
        transaction: TransactionId::from_bytes([id; 16]),
        realm: RealmName::new(realm).expect("realm"),
        retired_generation: nonzero(1),
        retired_helper_policy_generation: None,
    })
}

fn readout(records: Vec<JournalRecord>) -> JournalReadout {
    JournalReadout {
        records,
        torn_tail: false,
    }
}

#[test]
fn reconciler_discards_only_staged_without_intent() {
    let plan = reconcile(&readout(vec![staged_record(1, "owner-podman")])).expect("plan");
    assert_eq!(plan.actions.len(), 1);
    assert!(matches!(
        plan.actions[0],
        ReconcileAction::DiscardStaged { .. }
    ));
    assert!(
        plan.ready(),
        "an abandoned staged candidate never blocks readiness"
    );
}

#[test]
fn reconciler_completes_every_durable_intent_before_readiness() {
    let plan = reconcile(&readout(vec![
        staged_record(1, "owner-podman"),
        intent_record(1, "owner-podman", Some(1)),
    ]))
    .expect("plan");
    assert_eq!(plan.actions.len(), 1);
    assert!(matches!(
        plan.actions[0],
        ReconcileAction::CompleteForward { .. }
    ));
    assert!(
        !plan.ready(),
        "a durable intent must complete forward before the broker reports readiness"
    );
}

#[test]
fn reconciler_recovers_active_receipts_and_retires_only_committed() {
    let plan = reconcile(&readout(vec![
        staged_record(1, "owner-podman"),
        intent_record(1, "owner-podman", Some(1)),
        active_record(1, "owner-podman"),
    ]))
    .expect("plan");
    assert_eq!(
        plan.actions,
        vec![ReconcileAction::RecoverActive {
            transaction: TransactionId::from_bytes([1; 16]),
            realm: RealmName::new("owner-podman").expect("realm"),
            retirement_pending: true,
        }]
    );
    assert!(plan.ready());
    // No superseded generation: nothing awaits retirement.
    let plan = reconcile(&readout(vec![
        staged_record(2, "owner-podman"),
        intent_record(2, "owner-podman", None),
        active_record(2, "owner-podman"),
    ]))
    .expect("plan");
    assert_eq!(
        plan.actions,
        vec![ReconcileAction::RecoverActive {
            transaction: TransactionId::from_bytes([2; 16]),
            realm: RealmName::new("owner-podman").expect("realm"),
            retirement_pending: false,
        }]
    );
    // A fully retired transaction needs no action.
    let plan = reconcile(&readout(vec![
        staged_record(3, "owner-podman"),
        intent_record(3, "owner-podman", Some(1)),
        active_record(3, "owner-podman"),
        retired_record(3, "owner-podman"),
    ]))
    .expect("plan");
    assert!(plan.actions.is_empty());
    assert!(plan.ready());
}

#[test]
fn reconciler_rejects_order_violations_and_duplicates() {
    assert_eq!(
        reconcile(&readout(vec![intent_record(1, "owner-podman", None)])),
        Err(ReconcileError::OrderViolation),
        "intent without staged"
    );
    assert_eq!(
        reconcile(&readout(vec![
            staged_record(1, "owner-podman"),
            active_record(1, "owner-podman"),
        ])),
        Err(ReconcileError::OrderViolation),
        "active without intent"
    );
    assert_eq!(
        reconcile(&readout(vec![
            staged_record(1, "owner-podman"),
            intent_record(1, "owner-podman", None),
            retired_record(1, "owner-podman"),
        ])),
        Err(ReconcileError::OrderViolation),
        "retired without active"
    );
    assert_eq!(
        reconcile(&readout(vec![
            staged_record(1, "owner-podman"),
            staged_record(1, "owner-podman"),
        ])),
        Err(ReconcileError::DuplicateRecord)
    );
    assert_eq!(
        reconcile(&readout(vec![
            staged_record(1, "owner-podman"),
            intent_record(1, "owner-podman", None),
            intent_record(1, "owner-podman", None),
        ])),
        Err(ReconcileError::DuplicateRecord)
    );
    assert_eq!(
        reconcile(&readout(vec![discarded_record(1, "owner-podman")])),
        Err(ReconcileError::OrderViolation),
        "discarded without staged"
    );
    assert_eq!(
        reconcile(&readout(vec![
            staged_record(1, "owner-podman"),
            intent_record(1, "owner-podman", None),
            discarded_record(1, "owner-podman"),
        ])),
        Err(ReconcileError::OrderViolation),
        "a committed transaction can never be discarded"
    );
    assert_eq!(
        reconcile(&readout(vec![
            staged_record(1, "owner-podman"),
            discarded_record(1, "owner-podman"),
            discarded_record(1, "owner-podman"),
        ])),
        Err(ReconcileError::DuplicateRecord)
    );
    assert_eq!(
        reconcile(&readout(vec![
            staged_record(1, "owner-podman"),
            intent_record(1, "production-docker", None),
        ])),
        Err(ReconcileError::RealmMismatch),
        "one transaction's records must agree on the realm"
    );
}

#[test]
fn reconciler_discards_repeated_rejected_attempts_without_split_ownership() {
    // Two rejected attempts (staged, never committed) in one realm are both
    // inert: neither claims realm ownership, and startup stays recoverable.
    let plan = reconcile(&readout(vec![
        staged_record(1, "owner-podman"),
        staged_record(2, "owner-podman"),
    ]))
    .expect("repeated rejected attempts never brick reconciliation");
    assert_eq!(plan.actions.len(), 2);
    assert!(
        plan.actions
            .iter()
            .all(|action| matches!(action, ReconcileAction::DiscardStaged { .. }))
    );
    assert!(plan.ready());
    // Once their terminal discarded receipts land, nothing remains.
    let plan = reconcile(&readout(vec![
        staged_record(1, "owner-podman"),
        discarded_record(1, "owner-podman"),
        staged_record(2, "owner-podman"),
        discarded_record(2, "owner-podman"),
    ]))
    .expect("plan");
    assert!(plan.actions.is_empty());
    assert!(plan.ready());
    // Rejected attempts coexist with the realm's serving authority.
    let plan = reconcile(&readout(vec![
        staged_record(1, "owner-podman"),
        intent_record(1, "owner-podman", Some(1)),
        active_record(1, "owner-podman"),
        staged_record(2, "owner-podman"),
        discarded_record(2, "owner-podman"),
        staged_record(3, "owner-podman"),
    ]))
    .expect("plan");
    assert_eq!(
        plan.actions,
        vec![
            ReconcileAction::RecoverActive {
                transaction: TransactionId::from_bytes([1; 16]),
                realm: RealmName::new("owner-podman").expect("realm"),
                retirement_pending: true,
            },
            ReconcileAction::DiscardStaged {
                transaction: TransactionId::from_bytes([3; 16]),
                realm: RealmName::new("owner-podman").expect("realm"),
            },
        ]
    );
}

#[test]
fn reconciler_supersedes_predecessors_across_transactions() {
    let realm = RealmName::new("owner-podman").expect("realm");
    // A committed first install (no previous, so no retired record ever)
    // keeps owning the realm while a successor is merely staged.
    let plan = reconcile(&readout(vec![
        staged_record(1, "owner-podman"),
        intent_gen_record(1, "owner-podman", 2, None),
        active_record(1, "owner-podman"),
        staged_record(2, "owner-podman"),
    ]))
    .expect("plan");
    assert_eq!(
        plan.actions,
        vec![
            ReconcileAction::RecoverActive {
                transaction: TransactionId::from_bytes([1; 16]),
                realm: realm.clone(),
                retirement_pending: false,
            },
            ReconcileAction::DiscardStaged {
                transaction: TransactionId::from_bytes([2; 16]),
                realm: realm.clone(),
            },
        ]
    );
    // The successor's durable intent supersedes the first install: only the
    // successor completes forward; the predecessor needs no action of its
    // own (its retirement belongs to the successor).
    let history = vec![
        staged_record(1, "owner-podman"),
        intent_gen_record(1, "owner-podman", 2, None),
        active_record(1, "owner-podman"),
        staged_record(2, "owner-podman"),
        intent_gen_record(2, "owner-podman", 3, Some(2)),
    ];
    let plan = reconcile(&readout(history.clone())).expect("plan");
    assert_eq!(
        plan.actions,
        vec![ReconcileAction::CompleteForward {
            transaction: TransactionId::from_bytes([2; 16]),
            realm: realm.clone(),
        }]
    );
    assert!(!plan.ready());
    // Successor active: recover it, with the predecessor's drain pending —
    // never the superseded generation.
    let mut with_active = history;
    with_active.push(active_record(2, "owner-podman"));
    let plan = reconcile(&readout(with_active.clone())).expect("plan");
    assert_eq!(
        plan.actions,
        vec![ReconcileAction::RecoverActive {
            transaction: TransactionId::from_bytes([2; 16]),
            realm,
            retirement_pending: true,
        }]
    );
    assert!(plan.ready());
    // Successor retired its predecessor: the realm's whole history is
    // finished — in particular no RecoverActive for the superseded first
    // install.
    let mut finished = with_active;
    finished.push(retired_record(2, "owner-podman"));
    let plan = reconcile(&readout(finished)).expect("plan");
    assert!(plan.actions.is_empty());
    assert!(plan.ready());
}

#[test]
fn reconciler_fails_closed_on_broken_succession() {
    // A superseded transaction still demanding forward completion: two
    // transactions would own the realm's forward path.
    assert_eq!(
        reconcile(&readout(vec![
            staged_record(1, "owner-podman"),
            intent_gen_record(1, "owner-podman", 2, None),
            staged_record(2, "owner-podman"),
            intent_gen_record(2, "owner-podman", 3, Some(2)),
        ])),
        Err(ReconcileError::SplitOwnership)
    );
    // A successor whose intent does not name its predecessor's generation.
    assert_eq!(
        reconcile(&readout(vec![
            staged_record(1, "owner-podman"),
            intent_gen_record(1, "owner-podman", 2, None),
            active_record(1, "owner-podman"),
            staged_record(2, "owner-podman"),
            intent_gen_record(2, "owner-podman", 3, None),
        ])),
        Err(ReconcileError::SplitOwnership)
    );
    assert_eq!(
        reconcile(&readout(vec![
            staged_record(1, "owner-podman"),
            intent_gen_record(1, "owner-podman", 2, None),
            active_record(1, "owner-podman"),
            staged_record(2, "owner-podman"),
            intent_gen_record(2, "owner-podman", 3, Some(9)),
        ])),
        Err(ReconcileError::SplitOwnership)
    );
    // Distinct realms stay independent.
    let plan = reconcile(&readout(vec![
        staged_record(1, "owner-podman"),
        intent_gen_record(1, "owner-podman", 2, None),
        staged_record(2, "production-docker"),
        intent_gen_record(2, "production-docker", 2, None),
    ]))
    .expect("plan");
    assert_eq!(plan.actions.len(), 2);
}

#[test]
fn reconciler_treats_a_torn_tail_as_absent() {
    let dir = tempdir::create();
    let journal = FileIntentJournal::in_directory(&dir.path);
    let transaction = TransactionId::from_bytes([16; 16]);
    journal
        .append(&JournalRecord::Staged(
            request(transaction).staged_receipt(),
        ))
        .expect("append staged");
    // A torn intent append: partial frame at the tail.
    let intent = serde_json::to_vec(&intent_record(16, "owner-podman", None)).expect("serialize");
    let length = u32::try_from(intent.len()).expect("bounded");
    let mut bytes = std::fs::read(journal.path()).expect("read");
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(intent.get(..intent.len() / 3).expect("third"));
    std::fs::write(journal.path(), bytes).expect("write torn");
    let readout = journal.read().expect("torn journal reads");
    assert!(readout.torn_tail);
    let plan = reconcile(&readout).expect("plan");
    assert_eq!(plan.actions.len(), 1);
    assert!(
        matches!(plan.actions[0], ReconcileAction::DiscardStaged { .. }),
        "a torn receipt never upgrades a staged transaction to committed"
    );
}
