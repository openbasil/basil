// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Live boundary tests for the db-keystore rekey adapter: wrong-key,
//! verification/destination failures, marker fencing and lock races, and
//! crash-shaped interruption at each protocol step boundary.

#![cfg(all(feature = "db-keystore", target_os = "linux"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::os::fd::{AsFd as _, OwnedFd};
use std::path::PathBuf;

use basil_keystore_backend::rekey::{
    CANDIDATE_NAME, EpochPair, KeystoreRekeyError, PINNED_TURSO_VERSION, RecoveryOutcome,
    RekeyLock, RekeyPlan, SIDECAR_SUFFIXES, STAGING_DIR_NAME, SensitiveDek, StagedCandidate,
    finish_rekey, marker_present, read_intent_marker, read_new_dek_file, rekey_to_staging,
    roll_back, roll_forward, swap_candidate, write_intent_marker,
};
use basil_keystore_backend::{SecretStore, StoreConfig, StoreError};
use rustix::fs::{Mode, OFlags};
use zero_secrets::SecretArray;
use zeroize::Zeroizing;

const DB_NAME: &str = "keystore.db";
const CIPHER: &str = "aegis256";
const OLD_DEK: [u8; 32] = [0x11; 32];
const NEW_DEK: [u8; 32] = [0x2f; 32];
const EPOCHS: EpochPair = EpochPair { pre: 3, post: 4 };

/// Fresh per-test directory plus an `O_DIRECTORY` descriptor for it.
struct TestDir {
    path: PathBuf,
    fd: OwnedFd,
}

impl TestDir {
    fn new(stem: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("basil-rekey-{stem}-{}-{n}", std::process::id()));
        std::fs::create_dir(&path).expect("create test dir");
        let fd = rustix::fs::open(
            &path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open test dir");
        Self { path, fd }
    }

    fn db_path(&self) -> PathBuf {
        self.path.join(DB_NAME)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn open_store(dir: &TestDir, dek: [u8; 32]) -> Result<SecretStore, StoreError> {
    SecretStore::open(StoreConfig::DbKeystore {
        path: dir.db_path(),
        cipher: CIPHER.to_string(),
        dek: SecretArray::new(dek),
    })
}

/// Create a populated keystore under `OLD_DEK` and close it.
fn provision(dir: &TestDir) {
    let store = open_store(dir, OLD_DEK).expect("provision store");
    store.put("kv2/alpha", b"alpha-secret").expect("put alpha");
    store.put("kv2/beta", b"beta-secret").expect("put beta");
    drop(store);
}

fn deks() -> (SensitiveDek, SensitiveDek) {
    (
        SensitiveDek::from_raw(Zeroizing::new(OLD_DEK)),
        SensitiveDek::from_raw(Zeroizing::new(NEW_DEK)),
    )
}

fn stage(dir: &TestDir, lock: &RekeyLock) -> StagedCandidate {
    let (old_dek, new_dek) = deks();
    let plan = RekeyPlan {
        db_dir: dir.fd.as_fd(),
        db_name: DB_NAME,
        cipher: CIPHER,
    };
    rekey_to_staging(&plan, old_dek, &new_dek, lock).expect("stage candidate")
}

fn entries(dir: &TestDir) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(&dir.path)
        .expect("read dir")
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// Adoption condition C3: the turso version and the sidecar suffix set are
/// pinned together; a turso bump must fail here until the set is re-verified.
#[test]
fn sidecar_suffix_set_is_pinned_to_the_turso_version() {
    assert_eq!(SIDECAR_SUFFIXES, ["-wal", "-tshm"]);
    let lock = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock"))
        .expect("read workspace Cargo.lock");
    let mut version = None;
    let mut lines = lock.lines();
    while let Some(line) = lines.next() {
        if line.trim() == "name = \"turso\"" {
            version = lines.next().and_then(|v| {
                v.trim()
                    .strip_prefix("version = \"")
                    .and_then(|v| v.strip_suffix('"'))
            });
            break;
        }
    }
    assert_eq!(
        version,
        Some(PINNED_TURSO_VERSION),
        "turso version changed: re-verify the WAL/SHM sidecar suffix set \
         against the new turso, then update PINNED_TURSO_VERSION"
    );
}

/// Empirical half of C3: every sidecar a provisioned store leaves next to
/// the database is covered by the pinned suffix set (turso unlinks `-tshm`
/// on a clean close, so the on-disk set may be a strict subset).
#[test]
fn provisioned_store_leaves_only_pinned_sidecars() {
    let dir = TestDir::new("sidecars");
    provision(&dir);
    let extras: Vec<String> = entries(&dir)
        .into_iter()
        .filter(|name| name != DB_NAME && name != &format!("{DB_NAME}.rekey-lock"))
        .collect();
    assert!(!extras.is_empty(), "expected at least one sidecar");
    for name in &extras {
        assert!(
            SIDECAR_SUFFIXES
                .iter()
                .any(|suffix| *name == format!("{DB_NAME}{suffix}")),
            "sidecar `{name}` is not covered by the pinned suffix set"
        );
    }
}

/// Happy path: stage, fence, swap, finish; the store reopens under the new
/// DEK with intact records, and the report counts the copied records.
#[test]
fn full_rekey_round_trip_preserves_records_under_the_new_dek() {
    let dir = TestDir::new("roundtrip");
    provision(&dir);
    let lock = RekeyLock::acquire_exclusive(dir.fd.as_fd(), DB_NAME).expect("lock");
    let staged = stage(&dir, &lock);
    assert_eq!(staged.report().copied, 2);
    assert_ne!(staged.candidate_b3(), staged.old_db_b3());

    let marker = staged.intent_marker(EPOCHS).expect("marker");
    write_intent_marker(dir.fd.as_fd(), DB_NAME, &marker, &lock).expect("write marker");
    assert!(marker_present(dir.fd.as_fd(), DB_NAME).unwrap());
    let read_back = read_intent_marker(dir.fd.as_fd(), DB_NAME).expect("read marker");
    assert_eq!(read_back, marker);
    assert_eq!(read_back.old_db_b3, staged.old_db_b3());

    // (Bundle reseal — the commit point — happens here in the real flow.)
    swap_candidate(dir.fd.as_fd(), DB_NAME, &staged, &lock).expect("swap");
    finish_rekey(dir.fd.as_fd(), DB_NAME, &lock).expect("finish");
    drop(staged);
    drop(lock);

    assert!(!marker_present(dir.fd.as_fd(), DB_NAME).unwrap());
    assert!(!dir.path.join(STAGING_DIR_NAME).exists());

    let store = open_store(&dir, NEW_DEK).expect("reopen with new DEK");
    assert_eq!(store.get("kv2/alpha").unwrap(), b"alpha-secret");
    assert_eq!(store.get("kv2/beta").unwrap(), b"beta-secret");
    drop(store);

    // The old DEK no longer opens the store (open or first read fails).
    let old = open_store(&dir, OLD_DEK);
    match old {
        Err(_) => {}
        Ok(store) => assert!(store.get("kv2/alpha").is_err(), "old DEK must fail"),
    }
}

/// Wrong old DEK: typed wrong-key error, nothing modified, staging cleaned.
#[test]
fn wrong_old_dek_fails_closed_and_leaves_the_system_untouched() {
    let dir = TestDir::new("wrongkey");
    provision(&dir);
    let before = entries(&dir);
    let lock = RekeyLock::acquire_exclusive(dir.fd.as_fd(), DB_NAME).expect("lock");
    let bad_old = SensitiveDek::from_raw(Zeroizing::new([0xee; 32]));
    let new_dek = SensitiveDek::from_raw(Zeroizing::new(NEW_DEK));
    let plan = RekeyPlan {
        db_dir: dir.fd.as_fd(),
        db_name: DB_NAME,
        cipher: CIPHER,
    };
    let err = rekey_to_staging(&plan, bad_old, &new_dek, &lock).unwrap_err();
    assert!(
        matches!(
            err,
            KeystoreRekeyError::WrongDek { .. } | KeystoreRekeyError::CorruptSource { .. }
        ),
        "unexpected error: {err}"
    );
    drop(lock);
    assert_eq!(entries(&dir), before, "pre-marker failure must be a no-op");
    let store = open_store(&dir, OLD_DEK).expect("still opens with the old DEK");
    assert_eq!(store.get("kv2/alpha").unwrap(), b"alpha-secret");
}

/// A stale staging directory (crash before the marker) is typed, never
/// reused, never deleted; the error names the operator remediation.
#[test]
fn stale_staging_dir_is_a_typed_refusal_with_remediation() {
    let dir = TestDir::new("stalestaging");
    provision(&dir);
    std::fs::create_dir(dir.path.join(STAGING_DIR_NAME)).expect("stale staging");
    let lock = RekeyLock::acquire_exclusive(dir.fd.as_fd(), DB_NAME).expect("lock");
    let (old_dek, new_dek) = deks();
    let plan = RekeyPlan {
        db_dir: dir.fd.as_fd(),
        db_name: DB_NAME,
        cipher: CIPHER,
    };
    let err = rekey_to_staging(&plan, old_dek, &new_dek, &lock).unwrap_err();
    assert!(matches!(err, KeystoreRekeyError::StagingExists));
    let text = err.to_string();
    assert!(text.contains("inspect"));
    assert!(text.contains("remove it manually"));
    assert!(dir.path.join(STAGING_DIR_NAME).exists(), "never deleted");
}

/// Marker fencing: while the intent marker exists, the broker's store open
/// refuses, naming the marker path and the recovery command verbatim.
#[test]
fn store_open_is_fenced_while_the_marker_exists() {
    let dir = TestDir::new("fence");
    provision(&dir);
    let lock = RekeyLock::acquire_exclusive(dir.fd.as_fd(), DB_NAME).expect("lock");
    let staged = stage(&dir, &lock);
    let marker = staged.intent_marker(EPOCHS).expect("marker");
    write_intent_marker(dir.fd.as_fd(), DB_NAME, &marker, &lock).expect("write marker");
    drop(staged);
    drop(lock);

    let Err(err) = open_store(&dir, OLD_DEK) else {
        panic!("store open must be fenced while the marker exists");
    };
    let text = err.to_string();
    assert!(text.contains("rekey in progress"), "got: {text}");
    assert!(
        text.contains(&format!("{DB_NAME}.rekey-intent")),
        "got: {text}"
    );
    assert!(
        text.contains("basil keystore rekey --resume"),
        "refusal must name the recovery command verbatim: {text}"
    );

    // A second marker write is also refused.
    let lock = RekeyLock::acquire_exclusive(dir.fd.as_fd(), DB_NAME).expect("relock");
    let err = write_intent_marker(dir.fd.as_fd(), DB_NAME, &marker, &lock).unwrap_err();
    assert!(matches!(err, KeystoreRekeyError::RekeyInProgress { .. }));
}

/// Lock races: an open store blocks the exclusive rekey lock, and an
/// exclusive rekey lock blocks store open — both typed, both non-blocking.
#[test]
fn advisory_lock_serializes_store_open_and_rekey() {
    let dir = TestDir::new("lockrace");
    provision(&dir);

    // Store open holds the shared lock: rekey must refuse.
    let store = open_store(&dir, OLD_DEK).expect("open store");
    let err = RekeyLock::acquire_exclusive(dir.fd.as_fd(), DB_NAME).unwrap_err();
    assert!(matches!(err, KeystoreRekeyError::AgentLive { .. }));
    drop(store);

    // Rekey holds the exclusive lock: store open must refuse.
    let lock = RekeyLock::acquire_exclusive(dir.fd.as_fd(), DB_NAME).expect("lock");
    let Err(err) = open_store(&dir, OLD_DEK) else {
        panic!("store open must fail while the exclusive rekey lock is held");
    };
    assert!(err.to_string().contains("rekey"), "got: {err}");
    drop(lock);

    // Both released: store opens again.
    drop(open_store(&dir, OLD_DEK).expect("reopen"));
}

/// Crash between marker write (step 2) and the bundle reseal (step 3):
/// the bundle is at the pre-epoch, so recovery rolls back to the exact
/// pre-rekey state without needing any DEK.
#[test]
fn crash_before_commit_rolls_back_to_the_exact_pre_rekey_state() {
    let dir = TestDir::new("rollback");
    provision(&dir);
    let before_db = std::fs::read(dir.db_path()).expect("read db");
    let lock = RekeyLock::acquire_exclusive(dir.fd.as_fd(), DB_NAME).expect("lock");
    let staged = stage(&dir, &lock);
    let marker = staged.intent_marker(EPOCHS).expect("marker");
    write_intent_marker(dir.fd.as_fd(), DB_NAME, &marker, &lock).expect("write marker");
    drop(staged); // crash: descriptors gone, marker + staging on disk

    let marker = read_intent_marker(dir.fd.as_fd(), DB_NAME).expect("read marker");
    assert_eq!(
        marker.phase_for_bundle_epoch(EPOCHS.pre).unwrap(),
        basil_keystore_backend::rekey::RecoveryPhase::RollBack
    );
    roll_back(dir.fd.as_fd(), DB_NAME, &marker, &lock).expect("roll back");
    drop(lock);

    assert!(!marker_present(dir.fd.as_fd(), DB_NAME).unwrap());
    assert!(!dir.path.join(STAGING_DIR_NAME).exists());
    assert_eq!(std::fs::read(dir.db_path()).unwrap(), before_db);
    let store = open_store(&dir, OLD_DEK).expect("pre-rekey state restored");
    assert_eq!(store.get("kv2/alpha").unwrap(), b"alpha-secret");
}

/// C5 hardening: rollback refuses (typed, destructive-step-free) when the
/// live database does not match the marker's recorded pre-rekey ciphertext
/// (the restored-backup misclassification).
#[test]
fn rollback_refuses_when_the_live_db_does_not_match_the_marker() {
    let dir = TestDir::new("rollbacktamper");
    provision(&dir);
    let lock = RekeyLock::acquire_exclusive(dir.fd.as_fd(), DB_NAME).expect("lock");
    let staged = stage(&dir, &lock);
    let marker = staged.intent_marker(EPOCHS).expect("marker");
    write_intent_marker(dir.fd.as_fd(), DB_NAME, &marker, &lock).expect("write marker");
    drop(staged);

    // Simulate a different database at db_name (e.g. restored backup).
    std::fs::write(dir.db_path(), b"not the recorded pre-rekey bytes").unwrap();
    let err = roll_back(dir.fd.as_fd(), DB_NAME, &marker, &lock).unwrap_err();
    assert!(matches!(
        err,
        KeystoreRekeyError::RecoveryUnrecoverable { .. }
    ));
    // Nothing was deleted: marker and staged candidate both survive.
    assert!(marker_present(dir.fd.as_fd(), DB_NAME).unwrap());
    assert!(
        dir.path
            .join(STAGING_DIR_NAME)
            .join(CANDIDATE_NAME)
            .exists()
    );
}

/// Crash between the bundle reseal (step 3) and the swap (step 4): the
/// candidate is still staged; roll-forward re-checks its hash, swaps, and
/// finishes.
#[test]
fn crash_after_commit_rolls_forward_by_resuming_the_swap() {
    let dir = TestDir::new("rollforward");
    provision(&dir);
    let lock = RekeyLock::acquire_exclusive(dir.fd.as_fd(), DB_NAME).expect("lock");
    let staged = stage(&dir, &lock);
    let marker = staged.intent_marker(EPOCHS).expect("marker");
    write_intent_marker(dir.fd.as_fd(), DB_NAME, &marker, &lock).expect("write marker");
    drop(staged); // crash after the (simulated) reseal

    let marker = read_intent_marker(dir.fd.as_fd(), DB_NAME).expect("read marker");
    assert_eq!(
        marker.phase_for_bundle_epoch(EPOCHS.post).unwrap(),
        basil_keystore_backend::rekey::RecoveryPhase::RollForward
    );
    let outcome = roll_forward(dir.fd.as_fd(), DB_NAME, &marker, &lock).expect("roll forward");
    assert_eq!(outcome, RecoveryOutcome::ResumedSwap);
    drop(lock);

    assert!(!marker_present(dir.fd.as_fd(), DB_NAME).unwrap());
    assert!(!dir.path.join(STAGING_DIR_NAME).exists());
    let store = open_store(&dir, NEW_DEK).expect("new DEK opens");
    assert_eq!(store.get("kv2/beta").unwrap(), b"beta-secret");
}

/// Crash between the swap (4b) and finish (5): staging is empty and the
/// candidate already sits at `db_name`; roll-forward detects the completed
/// swap via the hash and performs step 5 only.
#[test]
fn crash_after_swap_detects_completion_and_finishes_only() {
    let dir = TestDir::new("swapdone");
    provision(&dir);
    let lock = RekeyLock::acquire_exclusive(dir.fd.as_fd(), DB_NAME).expect("lock");
    let staged = stage(&dir, &lock);
    let marker = staged.intent_marker(EPOCHS).expect("marker");
    write_intent_marker(dir.fd.as_fd(), DB_NAME, &marker, &lock).expect("write marker");
    swap_candidate(dir.fd.as_fd(), DB_NAME, &staged, &lock).expect("swap");
    drop(staged); // crash before finish: marker + empty staging remain

    assert!(dir.path.join(STAGING_DIR_NAME).exists());
    let marker = read_intent_marker(dir.fd.as_fd(), DB_NAME).expect("read marker");
    let outcome = roll_forward(dir.fd.as_fd(), DB_NAME, &marker, &lock).expect("roll forward");
    assert_eq!(outcome, RecoveryOutcome::SwapAlreadyComplete);
    drop(lock);

    assert!(!marker_present(dir.fd.as_fd(), DB_NAME).unwrap());
    assert!(!dir.path.join(STAGING_DIR_NAME).exists());
    let store = open_store(&dir, NEW_DEK).expect("new DEK opens");
    assert_eq!(store.get("kv2/alpha").unwrap(), b"alpha-secret");
}

/// Roll-forward refuses when the staged candidate does not match the
/// marker's hash (tampering inside basil's own staging directory); the
/// candidate is never deleted.
#[test]
fn roll_forward_refuses_a_tampered_candidate() {
    let dir = TestDir::new("tamperedcand");
    provision(&dir);
    let lock = RekeyLock::acquire_exclusive(dir.fd.as_fd(), DB_NAME).expect("lock");
    let staged = stage(&dir, &lock);
    let marker = staged.intent_marker(EPOCHS).expect("marker");
    write_intent_marker(dir.fd.as_fd(), DB_NAME, &marker, &lock).expect("write marker");
    drop(staged);

    let candidate = dir.path.join(STAGING_DIR_NAME).join(CANDIDATE_NAME);
    std::fs::write(&candidate, b"tampered").unwrap();
    let err = roll_forward(dir.fd.as_fd(), DB_NAME, &marker, &lock).unwrap_err();
    assert!(matches!(
        err,
        KeystoreRekeyError::CandidateHashMismatch { .. }
    ));
    assert!(candidate.exists(), "candidate must never be deleted");
    assert!(marker_present(dir.fd.as_fd(), DB_NAME).unwrap());
}

/// The sidecar files under the retired DEK are gone after the swap. An
/// unclean close can leave the full set, so any member absent after the
/// clean provisioning close is recreated here to exercise both unlinks.
#[test]
fn swap_disposes_of_the_old_wal_and_shm_sidecars() {
    let dir = TestDir::new("sidecardisposal");
    provision(&dir);
    let lock = RekeyLock::acquire_exclusive(dir.fd.as_fd(), DB_NAME).expect("lock");
    let staged = stage(&dir, &lock);
    let marker = staged.intent_marker(EPOCHS).expect("marker");
    write_intent_marker(dir.fd.as_fd(), DB_NAME, &marker, &lock).expect("write marker");
    // Any member absent after the clean staging close is recreated so the
    // swap exercises both unlinks (an unclean close leaves the full set).
    for suffix in SIDECAR_SUFFIXES {
        let sidecar = dir.path.join(format!("{DB_NAME}{suffix}"));
        if !sidecar.exists() {
            std::fs::write(&sidecar, b"stale sidecar under the retired DEK").unwrap();
        }
    }
    swap_candidate(dir.fd.as_fd(), DB_NAME, &staged, &lock).expect("swap");
    finish_rekey(dir.fd.as_fd(), DB_NAME, &lock).expect("finish");
    for suffix in SIDECAR_SUFFIXES {
        assert!(
            !dir.path.join(format!("{DB_NAME}{suffix}")).exists(),
            "old sidecar {suffix} must be unlinked"
        );
    }
}

/// A lock and candidate are bound to the directory/name pair used to create
/// them.  Supplying them with another database is rejected before any
/// destructive operation is attempted.
#[test]
fn lock_and_candidate_cannot_be_reused_for_another_database() {
    let first = TestDir::new("identity-first");
    let second = TestDir::new("identity-second");
    provision(&first);
    provision(&second);
    let lock = RekeyLock::acquire_exclusive(first.fd.as_fd(), DB_NAME).expect("lock");
    let staged = stage(&first, &lock);
    let marker = staged.intent_marker(EPOCHS).expect("marker");

    let err = write_intent_marker(second.fd.as_fd(), DB_NAME, &marker, &lock).unwrap_err();
    assert!(matches!(err, KeystoreRekeyError::TargetMismatch { .. }));
    let err = swap_candidate(second.fd.as_fd(), DB_NAME, &staged, &lock).unwrap_err();
    assert!(matches!(err, KeystoreRekeyError::TargetMismatch { .. }));
    let err = finish_rekey(second.fd.as_fd(), DB_NAME, &lock).unwrap_err();
    assert!(matches!(err, KeystoreRekeyError::TargetMismatch { .. }));
    assert!(second.db_path().exists());
    assert!(second.path.join(format!("{DB_NAME}-wal")).exists());
}

/// The candidate is re-hashed after the inode check and before sidecar
/// disposal, so an in-place mutation cannot pass the fresh-run swap.
#[test]
fn swap_rejects_in_place_candidate_mutation_before_sidecar_disposal() {
    let dir = TestDir::new("candidate-mutation");
    provision(&dir);
    let lock = RekeyLock::acquire_exclusive(dir.fd.as_fd(), DB_NAME).expect("lock");
    let staged = stage(&dir, &lock);
    let marker = staged.intent_marker(EPOCHS).expect("marker");
    write_intent_marker(dir.fd.as_fd(), DB_NAME, &marker, &lock).expect("write marker");
    for suffix in SIDECAR_SUFFIXES {
        std::fs::write(
            dir.path.join(format!("{DB_NAME}{suffix}")),
            b"sidecar under the old key",
        )
        .expect("create sidecar");
    }

    let candidate_path = dir.path.join(STAGING_DIR_NAME).join(CANDIDATE_NAME);
    let mut candidate = std::fs::OpenOptions::new()
        .write(true)
        .open(&candidate_path)
        .expect("open candidate");
    std::io::Write::write_all(&mut candidate, b"x").expect("mutate candidate");
    drop(candidate);

    let err = swap_candidate(dir.fd.as_fd(), DB_NAME, &staged, &lock).unwrap_err();
    assert!(matches!(
        err,
        KeystoreRekeyError::CandidateHashMismatch { .. }
    ));
    for suffix in SIDECAR_SUFFIXES {
        assert!(
            dir.path.join(format!("{DB_NAME}{suffix}")).exists(),
            "sidecar must survive failed validation: {suffix}"
        );
    }
    assert!(marker_present(dir.fd.as_fd(), DB_NAME).unwrap());
}

/// Finish is phase-gated: it cannot remove the fence while the candidate is
/// still staged and the live database is still the old ciphertext.
#[test]
fn finish_rekey_rejects_before_swap() {
    let dir = TestDir::new("finish-phase");
    provision(&dir);
    let lock = RekeyLock::acquire_exclusive(dir.fd.as_fd(), DB_NAME).expect("lock");
    let staged = stage(&dir, &lock);
    let marker = staged.intent_marker(EPOCHS).expect("marker");
    write_intent_marker(dir.fd.as_fd(), DB_NAME, &marker, &lock).expect("write marker");
    let err = finish_rekey(dir.fd.as_fd(), DB_NAME, &lock).unwrap_err();
    assert!(matches!(err, KeystoreRekeyError::InvalidPhase { .. }));
    assert!(marker_present(dir.fd.as_fd(), DB_NAME).unwrap());
}

/// Marker hardening: a symlinked marker is rejected at read time.
#[test]
fn symlinked_marker_is_rejected() {
    let dir = TestDir::new("markersymlink");
    provision(&dir);
    let target = dir.path.join("innocuous");
    std::fs::write(&target, b"x").unwrap();
    std::os::unix::fs::symlink(&target, dir.path.join(format!("{DB_NAME}.rekey-intent"))).unwrap();
    let err = read_intent_marker(dir.fd.as_fd(), DB_NAME).unwrap_err();
    assert!(matches!(err, KeystoreRekeyError::MarkerInvalid { .. }));
    // The fence still refuses store open (any entry counts).
    assert!(open_store(&dir, OLD_DEK).is_err());
}

/// New-DEK file discipline: exact length, owner-only mode, regular file.
#[test]
fn new_dek_file_reader_enforces_length_and_permissions() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = TestDir::new("dekfile");

    let short = dir.path.join("short.dek");
    std::fs::write(&short, [0u8; 16]).unwrap();
    std::fs::set_permissions(&short, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        read_new_dek_file(&short).unwrap_err(),
        KeystoreRekeyError::DekFileLength {
            expected: 32,
            actual: 16
        }
    ));

    let lax = dir.path.join("lax.dek");
    std::fs::write(&lax, [7u8; 32]).unwrap();
    std::fs::set_permissions(&lax, std::fs::Permissions::from_mode(0o640)).unwrap();
    assert!(matches!(
        read_new_dek_file(&lax).unwrap_err(),
        KeystoreRekeyError::DekFilePermissions { .. }
    ));

    let good = dir.path.join("good.dek");
    std::fs::write(&good, [7u8; 32]).unwrap();
    std::fs::set_permissions(&good, std::fs::Permissions::from_mode(0o600)).unwrap();
    read_new_dek_file(&good).expect("valid DEK file reads");
}
