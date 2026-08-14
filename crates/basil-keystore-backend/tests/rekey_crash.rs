// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Subprocess crash and recovery tests for the `db-keystore` rekey protocol.

#![cfg(all(feature = "db-keystore", target_os = "linux"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::enum_variant_names,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, TryRecvError};
use std::time::{Duration, Instant};

use basil_keystore_backend::rekey::{
    BundleTransitionBinding, CANDIDATE_NAME, EpochPair, KeystoreRekeyError, RecoveryOutcome,
    RecoveryPhase, RekeyLock, RekeyPlan, SIDECAR_SUFFIXES, STAGING_DIR_NAME, SensitiveDek,
    finish_rekey, read_intent_marker, rekey_to_staging, roll_back, roll_forward, swap_candidate,
    write_intent_marker,
};
use basil_keystore_backend::{SecretStore, StoreConfig};
use rustix::fs::{AtFlags, Mode, OFlags};
use zero_secrets::SecretArray;
use zeroize::Zeroizing;

const DB_NAME: &str = "keystore.db";
const CIPHER: &str = "aegis256";
const OLD_DEK: [u8; 32] = [0x31; 32];
const NEW_DEK: [u8; 32] = [0xa7; 32];
const EPOCHS: EpochPair = EpochPair { pre: 41, post: 42 };
const BUNDLE_ID: [u8; 16] = [0x61; 16];
const BACKEND_ID: &str = "crash-test-keystore";
const PRE_BUNDLE_B3: [u8; 32] = [0x62; 32];
const POST_BUNDLE_B3: [u8; 32] = [0x63; 32];
const HELPER_ACTION: &str = "BASIL_REKEY_CRASH_HELPER_ACTION";
const HELPER_DIR: &str = "BASIL_REKEY_CRASH_HELPER_DIR";
const HELPER_STATE: &str = "BASIL_REKEY_CRASH_HELPER_STATE";
const HELPER_DEK: &str = "BASIL_REKEY_CRASH_HELPER_DEK";
const HELPER_EXPECT: &str = "BASIL_REKEY_CRASH_HELPER_EXPECT";
const READY_PREFIX: &str = "BASIL_REKEY_CRASH_READY=";
const RECOVERY_PREFIX: &str = "BASIL_REKEY_CRASH_RECOVERY=";
const EPOCH_FILE: &str = ".test-bundle-epoch";
const EPOCH_TEMP_FILE: &str = ".test-bundle-epoch.next";
const HELPER_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug)]
enum CrashState {
    AfterStaging,
    AfterMarkerPreEpoch,
    AfterPostEpoch,
    AfterSidecarUnlink,
    AfterRename,
    AfterStagingRemoval,
    AfterFinish,
}

impl CrashState {
    const fn name(self) -> &'static str {
        match self {
            Self::AfterStaging => "1-after-staging",
            Self::AfterMarkerPreEpoch => "2-after-marker-pre-epoch",
            Self::AfterPostEpoch => "3-after-post-epoch",
            Self::AfterSidecarUnlink => "4-after-sidecar-unlink",
            Self::AfterRename => "5-after-rename",
            Self::AfterStagingRemoval => "6-after-staging-removal",
            Self::AfterFinish => "7-after-finish",
        }
    }

    fn parse(value: &str) -> Self {
        match value {
            "1-after-staging" => Self::AfterStaging,
            "2-after-marker-pre-epoch" => Self::AfterMarkerPreEpoch,
            "3-after-post-epoch" => Self::AfterPostEpoch,
            "4-after-sidecar-unlink" => Self::AfterSidecarUnlink,
            "5-after-rename" => Self::AfterRename,
            "6-after-staging-removal" => Self::AfterStagingRemoval,
            "7-after-finish" => Self::AfterFinish,
            other => panic!("unknown crash state: {other}"),
        }
    }

    const fn marker(self) -> bool {
        !matches!(self, Self::AfterStaging | Self::AfterFinish)
    }

    const fn staged_candidate(self) -> bool {
        matches!(
            self,
            Self::AfterStaging
                | Self::AfterMarkerPreEpoch
                | Self::AfterPostEpoch
                | Self::AfterSidecarUnlink
        )
    }

    const fn staging_dir(self) -> bool {
        !matches!(self, Self::AfterStagingRemoval | Self::AfterFinish)
    }

    const fn old_sidecars(self) -> bool {
        matches!(
            self,
            Self::AfterStaging | Self::AfterMarkerPreEpoch | Self::AfterPostEpoch
        )
    }

    const fn post_epoch(self) -> bool {
        matches!(
            self,
            Self::AfterPostEpoch
                | Self::AfterSidecarUnlink
                | Self::AfterRename
                | Self::AfterStagingRemoval
                | Self::AfterFinish
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecoveryExpectation {
    Missing,
    RollBack,
    ResumedSwap,
    SwapAlreadyComplete,
}

impl RecoveryExpectation {
    const fn name(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::RollBack => "rollback",
            Self::ResumedSwap => "resumed-swap",
            Self::SwapAlreadyComplete => "swap-already-complete",
        }
    }

    fn parse(value: &str) -> Self {
        match value {
            "missing" => Self::Missing,
            "rollback" => Self::RollBack,
            "resumed-swap" => Self::ResumedSwap,
            "swap-already-complete" => Self::SwapAlreadyComplete,
            other => panic!("unknown recovery expectation: {other}"),
        }
    }
}

struct TestDir {
    path: PathBuf,
    fd: OwnedFd,
}

impl TestDir {
    fn new(stem: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "basil-rekey-crash-{stem}-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("create test directory");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .expect("protect test directory");
        let fd = open_dir(&path);
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

#[derive(Debug, PartialEq, Eq)]
struct Inventory {
    marker: bool,
    staging_dir: bool,
    candidate: bool,
    old_sidecars: Vec<String>,
}

fn open_dir(path: &Path) -> OwnedFd {
    rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .expect("open test directory")
}

fn open_store(path: &Path, dek: [u8; 32]) -> Result<SecretStore, String> {
    SecretStore::open(StoreConfig::DbKeystore {
        path: path.join(DB_NAME),
        cipher: CIPHER.to_owned(),
        dek: SecretArray::new(dek),
    })
    .map_err(|error| error.to_string())
}

fn provision(dir: &TestDir) {
    let store = open_store(&dir.path, OLD_DEK).expect("provision store");
    store.put("kv2/alpha", b"alpha-secret").expect("put alpha");
    store.put("kv2/beta", b"beta-secret").expect("put beta");
    drop(store);
    persist_epoch(&dir.path, EPOCHS.pre);
}

fn persist_epoch(path: &Path, epoch: u64) {
    use std::os::unix::fs::OpenOptionsExt as _;

    let temporary = path.join(EPOCH_TEMP_FILE);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .expect("create durable test epoch");
    writeln!(file, "{epoch}").expect("write durable test epoch");
    file.sync_all().expect("sync durable test epoch");
    drop(file);
    std::fs::rename(&temporary, path.join(EPOCH_FILE)).expect("publish durable test epoch");
    let db_dir = open_dir(path);
    rustix::fs::fsync(&db_dir).expect("sync test epoch publication");
}

fn read_epoch(path: &Path) -> u64 {
    std::fs::read_to_string(path.join(EPOCH_FILE))
        .expect("read durable test epoch")
        .trim()
        .parse()
        .expect("parse durable test epoch")
}

fn inventory(path: &Path) -> Inventory {
    let old_sidecars = SIDECAR_SUFFIXES
        .iter()
        .map(|suffix| format!("{DB_NAME}{suffix}"))
        .filter(|name| path.join(name).exists())
        .collect();
    Inventory {
        marker: path.join(format!("{DB_NAME}.rekey-intent")).exists(),
        staging_dir: path.join(STAGING_DIR_NAME).exists(),
        candidate: path.join(STAGING_DIR_NAME).join(CANDIDATE_NAME).exists(),
        old_sidecars,
    }
}

fn helper_command(action: &str, path: &Path) -> Command {
    let mut command =
        Command::new(std::env::current_exe().expect("locate current test executable"));
    command
        .arg("--exact")
        .arg("child_helper")
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env(HELPER_ACTION, action)
        .env(HELPER_DIR, path);
    command
}

fn wait_bounded(child: &mut Child, context: &str) {
    let deadline = Instant::now() + HELPER_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait().expect("poll helper") {
            assert!(status.success(), "{context} helper failed with {status}");
            return;
        }
        if Instant::now() >= deadline {
            child.kill().expect("kill timed-out helper");
            let _ = child.wait();
            panic!("{context} helper exceeded {HELPER_TIMEOUT:?}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn run_helper(action: &str, path: &Path, configure: impl FnOnce(&mut Command)) {
    let mut command = helper_command(action, path);
    configure(&mut command);
    command.stdout(Stdio::null()).stderr(Stdio::inherit());
    let mut child = command.spawn().expect("spawn helper");
    wait_bounded(&mut child, action);
}

fn crash_at(path: &Path, state: CrashState) {
    let mut command = helper_command("crash", path);
    command
        .env(HELPER_STATE, state.name())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let mut child = command.spawn().expect("spawn crash helper");
    let stdout = child.stdout.take().expect("capture helper stdout");
    let (sender, receiver) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let line = line.expect("read crash helper output");
            if let Some(offset) = line.find(READY_PREFIX) {
                let boundary = &line[offset + READY_PREFIX.len()..];
                sender.send(boundary.to_owned()).expect("send boundary");
                return;
            }
        }
    });

    let deadline = Instant::now() + HELPER_TIMEOUT;
    loop {
        match receiver.try_recv() {
            Ok(boundary) => {
                assert_eq!(boundary, state.name());
                child.kill().expect("SIGKILL crash helper");
                let status = child.wait().expect("reap crash helper");
                assert_eq!(status.signal(), Some(9), "helper must die by SIGKILL");
                reader.join().expect("join output reader");
                return;
            }
            Err(TryRecvError::Disconnected) => {
                let status = child.wait().expect("reap failed crash helper");
                reader.join().expect("join output reader");
                panic!("crash helper exited before sentinel: {status}");
            }
            Err(TryRecvError::Empty) => {}
        }
        if let Some(status) = child.try_wait().expect("poll crash helper") {
            reader.join().expect("join output reader");
            panic!("crash helper exited before sentinel: {status}");
        }
        if Instant::now() >= deadline {
            child.kill().expect("kill stalled crash helper");
            let _ = child.wait();
            reader.join().expect("join output reader");
            panic!("crash helper did not reach {state:?}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn probe(path: &Path, dek: &str, expected: &str) {
    run_helper("probe", path, |command| {
        command.env(HELPER_DEK, dek).env(HELPER_EXPECT, expected);
    });
}

fn recover(path: &Path) -> RecoveryExpectation {
    let mut command = helper_command("recover", path);
    command.stdout(Stdio::piped()).stderr(Stdio::inherit());
    let mut child = command.spawn().expect("spawn recovery helper");
    wait_bounded(&mut child, "recover");
    let mut output = String::new();
    child
        .stdout
        .take()
        .expect("capture recovery output")
        .read_to_string(&mut output)
        .expect("read recovery output");
    let outcome = output
        .lines()
        .find_map(|line| {
            line.find(RECOVERY_PREFIX)
                .map(|offset| &line[offset + RECOVERY_PREFIX.len()..])
        })
        .expect("recovery helper must report its observed outcome");
    RecoveryExpectation::parse(outcome)
}

fn assert_inventory(path: &Path, state: CrashState) {
    let found = inventory(path);
    assert_eq!(found.marker, state.marker(), "{state:?}: marker inventory");
    assert_eq!(
        found.staging_dir,
        state.staging_dir(),
        "{state:?}: staging directory inventory"
    );
    assert_eq!(
        found.candidate,
        state.staged_candidate(),
        "{state:?}: candidate inventory"
    );
    assert_eq!(
        !found.old_sidecars.is_empty(),
        state.old_sidecars(),
        "{state:?}: old sidecar inventory was {:?}",
        found.old_sidecars
    );
}

fn assert_clean_rekey_inventory(path: &Path, old_sidecars: bool) {
    let found = inventory(path);
    assert!(!found.marker, "marker survived recovery");
    assert!(!found.staging_dir, "staging directory survived recovery");
    assert!(!found.candidate, "candidate survived recovery");
    assert_eq!(
        !found.old_sidecars.is_empty(),
        old_sidecars,
        "post-recovery old sidecar inventory was {:?}",
        found.old_sidecars
    );
}

#[test]
fn subprocess_sigkill_recovery_matrix_covers_every_durable_state() {
    let cases = [
        (CrashState::AfterStaging, RecoveryExpectation::Missing),
        (
            CrashState::AfterMarkerPreEpoch,
            RecoveryExpectation::RollBack,
        ),
        (CrashState::AfterPostEpoch, RecoveryExpectation::ResumedSwap),
        (
            CrashState::AfterSidecarUnlink,
            RecoveryExpectation::ResumedSwap,
        ),
        (
            CrashState::AfterRename,
            RecoveryExpectation::SwapAlreadyComplete,
        ),
        (
            CrashState::AfterStagingRemoval,
            RecoveryExpectation::SwapAlreadyComplete,
        ),
        (CrashState::AfterFinish, RecoveryExpectation::Missing),
    ];

    for (state, recovery) in cases {
        let dir = TestDir::new(state.name());
        provision(&dir);
        crash_at(&dir.path, state);
        assert_inventory(&dir.path, state);
        assert_eq!(
            read_epoch(&dir.path),
            if state.post_epoch() {
                EPOCHS.post
            } else {
                EPOCHS.pre
            },
            "{state:?}: durable epoch"
        );

        if state.marker() {
            probe(&dir.path, "old", "fenced");
        }

        // This fresh process opens a fresh directory descriptor and acquires
        // the same exclusive lock. Success proves SIGKILL released the
        // crashed process's kernel lock before recovery begins.
        assert_eq!(recover(&dir.path), recovery);

        match recovery {
            RecoveryExpectation::Missing => {
                if matches!(state, CrashState::AfterStaging) {
                    assert_inventory(&dir.path, state);
                    probe(&dir.path, "old", "readable");
                    probe(&dir.path, "new", "unreadable");
                } else {
                    assert_clean_rekey_inventory(&dir.path, false);
                    probe(&dir.path, "new", "readable");
                    probe(&dir.path, "old", "unreadable");
                }
            }
            RecoveryExpectation::RollBack => {
                assert_clean_rekey_inventory(&dir.path, true);
                probe(&dir.path, "old", "readable");
                probe(&dir.path, "new", "unreadable");
            }
            RecoveryExpectation::ResumedSwap | RecoveryExpectation::SwapAlreadyComplete => {
                assert_clean_rekey_inventory(&dir.path, false);
                probe(&dir.path, "new", "readable");
                probe(&dir.path, "old", "unreadable");
            }
        }
    }
}

#[test]
fn substituted_lock_names_fail_closed() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let symlink_dir = TestDir::new("lock-symlink");
    provision(&symlink_dir);
    let lock_path = symlink_dir.path.join(format!("{DB_NAME}.rekey-lock"));
    std::fs::remove_file(&lock_path).expect("remove original lock file");
    symlink(symlink_dir.db_path(), &lock_path).expect("substitute lock symlink");
    assert!(
        matches!(
            RekeyLock::acquire_exclusive(symlink_dir.fd.as_fd(), DB_NAME),
            Err(KeystoreRekeyError::Backend { .. })
        ),
        "exclusive acquisition must reject a symlinked lock name"
    );
    assert!(
        open_store(&symlink_dir.path, OLD_DEK).is_err(),
        "broker open must reject a symlinked lock name"
    );

    let hardlink_dir = TestDir::new("lock-hardlink");
    provision(&hardlink_dir);
    let lock_path = hardlink_dir.path.join(format!("{DB_NAME}.rekey-lock"));
    std::fs::remove_file(&lock_path).expect("remove original lock file");
    let decoy = hardlink_dir.path.join("lock-decoy");
    std::fs::write(&decoy, b"decoy").expect("write decoy");
    std::fs::set_permissions(&decoy, std::fs::Permissions::from_mode(0o600))
        .expect("set decoy mode");
    std::fs::hard_link(&decoy, &lock_path).expect("substitute hard-linked lock");
    assert!(
        matches!(
            RekeyLock::acquire_exclusive(hardlink_dir.fd.as_fd(), DB_NAME),
            Err(KeystoreRekeyError::Backend { .. })
        ),
        "exclusive acquisition must reject a multiply-linked lock file"
    );
    assert!(
        open_store(&hardlink_dir.path, OLD_DEK).is_err(),
        "broker open must reject a multiply-linked lock file"
    );

    let replaced_dir = TestDir::new("lock-replaced-after-acquire");
    provision(&replaced_dir);
    let lock = RekeyLock::acquire_exclusive(replaced_dir.fd.as_fd(), DB_NAME)
        .expect("acquire original lock");
    let lock_path = replaced_dir.path.join(format!("{DB_NAME}.rekey-lock"));
    std::fs::remove_file(&lock_path).expect("unlink held lock name");
    std::fs::write(&lock_path, b"").expect("create replacement lock");
    std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o600))
        .expect("set replacement lock mode");

    let old_dek = SensitiveDek::from_raw(Zeroizing::new(OLD_DEK));
    let new_dek = SensitiveDek::from_raw(Zeroizing::new(NEW_DEK));
    let plan = RekeyPlan {
        db_dir: replaced_dir.fd.as_fd(),
        db_name: DB_NAME,
        cipher: CIPHER,
    };
    assert!(
        matches!(
            rekey_to_staging(&plan, old_dek, &new_dek, &lock),
            Err(KeystoreRekeyError::TargetMismatch { .. })
        ),
        "a destructive transition must reject a lock name replaced after acquisition"
    );
    assert!(
        !replaced_dir.path.join(STAGING_DIR_NAME).exists(),
        "lock revalidation must fail before staging mutates the directory"
    );
}

#[test]
fn child_helper() {
    let Ok(action) = std::env::var(HELPER_ACTION) else {
        return;
    };
    let path = PathBuf::from(std::env::var_os(HELPER_DIR).expect("helper directory"));
    match action.as_str() {
        "crash" => child_crash(
            &path,
            CrashState::parse(&std::env::var(HELPER_STATE).expect("crash state")),
        ),
        "probe" => child_probe(
            &path,
            &std::env::var(HELPER_DEK).expect("probe DEK"),
            &std::env::var(HELPER_EXPECT).expect("probe expectation"),
        ),
        "recover" => child_recover(&path),
        other => panic!("unknown helper action: {other}"),
    }
}

fn child_crash(path: &Path, state: CrashState) {
    let db_dir = open_dir(path);
    let lock = RekeyLock::acquire_exclusive(db_dir.as_fd(), DB_NAME).expect("exclusive lock");
    let old_dek = SensitiveDek::from_raw(Zeroizing::new(OLD_DEK));
    let new_dek = SensitiveDek::from_raw(Zeroizing::new(NEW_DEK));
    let plan = RekeyPlan {
        db_dir: db_dir.as_fd(),
        db_name: DB_NAME,
        cipher: CIPHER,
    };
    let staged = rekey_to_staging(&plan, old_dek, &new_dek, &lock).expect("stage candidate");
    assert_eq!(staged.report().copied, 2, "record count at staging");
    sync_staging(db_dir.as_fd());

    // The staging directory is freshly created below `db_dir`, so its
    // candidate and the live database necessarily share a filesystem.
    // The rename cannot cross a mount boundary and therefore cannot return
    // `EXDEV`; cross-filesystem staging is not a representable test input.
    let staging = rustix::fs::openat(
        db_dir.as_fd(),
        STAGING_DIR_NAME,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .expect("open staging directory");
    assert_eq!(
        rustix::fs::fstat(&db_dir)
            .expect("stat database directory")
            .st_dev,
        rustix::fs::fstat(&staging)
            .expect("stat staging directory")
            .st_dev,
        "staging and live database directory must share st_dev"
    );
    drop(staging);

    if !matches!(state, CrashState::AfterStaging) {
        let binding = BundleTransitionBinding::new(
            BUNDLE_ID,
            BACKEND_ID,
            PRE_BUNDLE_B3,
            POST_BUNDLE_B3,
            EPOCHS,
            staged.report().copied,
        )
        .expect("build bundle binding");
        let marker = staged.intent_marker(binding).expect("build marker");
        write_intent_marker(db_dir.as_fd(), DB_NAME, &marker, &lock).expect("write marker");
    }
    if state.post_epoch() {
        persist_epoch(path, EPOCHS.post);
    }
    if matches!(state, CrashState::AfterSidecarUnlink) {
        unlink_sidecars_for_boundary(db_dir.as_fd());
    }
    if matches!(
        state,
        CrashState::AfterRename | CrashState::AfterStagingRemoval | CrashState::AfterFinish
    ) {
        swap_candidate(db_dir.as_fd(), DB_NAME, &staged, &lock).expect("swap candidate");
    }
    if matches!(state, CrashState::AfterStagingRemoval) {
        remove_empty_staging_for_boundary(db_dir.as_fd());
    }
    if matches!(state, CrashState::AfterFinish) {
        finish_rekey(db_dir.as_fd(), DB_NAME, &lock).expect("finish rekey");
    }

    println!("{READY_PREFIX}{}", state.name());
    std::io::stdout()
        .flush()
        .expect("flush durable boundary sentinel");
    // The parent kills the process immediately. The timeout keeps a broken
    // parent from leaving a helper alive indefinitely.
    std::thread::sleep(HELPER_TIMEOUT);
    panic!("parent did not SIGKILL crash helper");
}

fn sync_staging(db_dir: std::os::fd::BorrowedFd<'_>) {
    let staging = rustix::fs::openat(
        db_dir,
        STAGING_DIR_NAME,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .expect("open staging for sync");
    let candidate = rustix::fs::openat(
        staging.as_fd(),
        CANDIDATE_NAME,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .expect("open candidate for sync");
    rustix::fs::fsync(&candidate).expect("sync candidate");
    rustix::fs::fsync(&staging).expect("sync staging directory");
    rustix::fs::fsync(db_dir).expect("sync database directory");
}

fn unlink_sidecars_for_boundary(db_dir: std::os::fd::BorrowedFd<'_>) {
    for suffix in SIDECAR_SUFFIXES {
        let name = format!("{DB_NAME}{suffix}");
        match rustix::fs::unlinkat(db_dir, name, AtFlags::empty()) {
            Ok(()) | Err(rustix::io::Errno::NOENT) => {}
            Err(error) => panic!("unlink old sidecar: {error}"),
        }
    }
    rustix::fs::fsync(db_dir).expect("sync sidecar unlinks");
}

fn remove_empty_staging_for_boundary(db_dir: std::os::fd::BorrowedFd<'_>) {
    rustix::fs::unlinkat(db_dir, STAGING_DIR_NAME, AtFlags::REMOVEDIR)
        .expect("remove empty staging directory");
    rustix::fs::fsync(db_dir).expect("sync staging-directory removal");
}

fn child_probe(path: &Path, dek_name: &str, expected: &str) {
    let dek = match dek_name {
        "old" => OLD_DEK,
        "new" => NEW_DEK,
        other => panic!("unknown probe DEK: {other}"),
    };
    let opened = open_store(path, dek);
    match expected {
        "fenced" => {
            let error = opened.err().expect("store open must be fenced");
            assert!(
                error.contains("rekey in progress"),
                "unexpected fence: {error}"
            );
        }
        "readable" => {
            let store = opened.expect("store must open with expected DEK");
            assert_eq!(store.get("kv2/alpha").expect("read alpha"), b"alpha-secret");
            assert_eq!(store.get("kv2/beta").expect("read beta"), b"beta-secret");
        }
        "unreadable" => match opened {
            Err(_) => {}
            Ok(store) => assert!(
                store.get("kv2/alpha").is_err(),
                "wrong DEK must not read a record"
            ),
        },
        other => panic!("unknown probe expectation: {other}"),
    }
}

fn child_recover(path: &Path) {
    let db_dir = open_dir(path);
    let lock = RekeyLock::acquire_exclusive(db_dir.as_fd(), DB_NAME)
        .expect("SIGKILL must release the exclusive rekey lock");
    let marker = read_intent_marker(db_dir.as_fd(), DB_NAME);
    let outcome = match marker {
        Err(KeystoreRekeyError::MarkerMissing { .. }) => RecoveryExpectation::Missing,
        Err(error) => panic!("read recovery marker: {error}"),
        Ok(marker) => {
            let epoch = read_epoch(path);
            let bundle_b3 = if epoch == EPOCHS.pre {
                PRE_BUNDLE_B3
            } else {
                POST_BUNDLE_B3
            };
            match marker
                .phase_for_authenticated_bundle(BUNDLE_ID, BACKEND_ID, bundle_b3, epoch)
                .expect("derive recovery phase from durable bundle tuple")
            {
                RecoveryPhase::RollBack => {
                    roll_back(db_dir.as_fd(), DB_NAME, &marker, &lock).expect("roll back");
                    RecoveryExpectation::RollBack
                }
                RecoveryPhase::RollForward => {
                    match roll_forward(db_dir.as_fd(), DB_NAME, &marker, &lock)
                        .expect("roll forward from durable epoch")
                    {
                        RecoveryOutcome::ResumedSwap => RecoveryExpectation::ResumedSwap,
                        RecoveryOutcome::SwapAlreadyComplete => {
                            RecoveryExpectation::SwapAlreadyComplete
                        }
                    }
                }
            }
        }
    };
    println!("{RECOVERY_PREFIX}{}", outcome.name());
}
