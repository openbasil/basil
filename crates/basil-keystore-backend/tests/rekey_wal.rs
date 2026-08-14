// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Integration coverage for a rekey whose last committed record is still in
//! the source write-ahead log.

#![cfg(all(feature = "db-keystore", target_os = "linux"))]
#![allow(
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::panic,
    clippy::unwrap_used
)]

use std::future::Future;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::task::{Context, Poll, Waker};

use basil_keystore_backend::rekey::{
    BundleTransitionBinding, CANDIDATE_NAME, EpochPair, RekeyLock, RekeyPlan, SIDECAR_SUFFIXES,
    STAGING_DIR_NAME, SensitiveDek, finish_rekey, marker_present, rekey_to_staging, swap_candidate,
    write_intent_marker,
};
use basil_keystore_backend::{SecretStore, StoreConfig};
use db_keystore::{DbKeyStore, DbKeyStoreConfig, EncryptionOpts};
use keyring_core::api::CredentialStoreApi as _;
use rustix::fs::{Mode, OFlags};
use zero_secrets::SecretArray;
use zeroize::Zeroizing;

const DB_NAME: &str = "keystore.db";
const WRITER_NAME: &str = "writer.db";
const CIPHER: &str = "aegis256";
const OLD_DEK: [u8; 32] = [0x11; 32];
const OLD_DEK_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const NEW_DEK: [u8; 32] = [0x2f; 32];
const NEW_DEK_HEX: &str = concat!(
    "2f2f2f2f2f2f2f2f",
    "2f2f2f2f2f2f2f2f",
    "2f2f2f2f2f2f2f2f",
    "2f2f2f2f2f2f2f2f",
);
const RECORD_KEY: &str = "kv2/wal-only-018f0f65";
const RECORD_VALUE: &[u8] = b"basil-wal-secret-018f0f65";
const RECORD_UUID: &str = "018f0f65-0000-7000-8000-000000000001";
const EPOCHS: EpochPair = EpochPair { pre: 17, post: 18 };

struct TestDir {
    path: PathBuf,
    fd: OwnedFd,
}

impl TestDir {
    fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("basil-rekey-wal-{}-{sequence}", std::process::id()));
        std::fs::create_dir(&path).expect("create test directory");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .expect("protect test directory");
        let fd = rustix::fs::open(
            &path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open test directory");
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

fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = Box::pin(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn open_db_keystore(path: &Path, dek_hex: &str) -> std::sync::Arc<DbKeyStore> {
    let encryption_opts = EncryptionOpts::new(CIPHER, dek_hex).expect("encryption options");
    DbKeyStore::new(DbKeyStoreConfig {
        path: path.to_path_buf(),
        encryption_opts: Some(encryption_opts),
        ..DbKeyStoreConfig::default()
    })
    .expect("open db-keystore")
}

fn read_direct(path: &Path, dek_hex: &str) -> keyring_core::Result<Vec<u8>> {
    let store = open_db_keystore(path, dek_hex);
    store
        .build("basil", RECORD_KEY, None)
        .expect("build Basil record handle")
        .get_secret()
}

fn freeze_committed_wal(dir: &TestDir) {
    let writer = dir.path.join(WRITER_NAME);
    drop(open_db_keystore(&writer, OLD_DEK_HEX));

    let writer_text = writer.to_str().expect("UTF-8 writer path");
    let database = block_on(
        turso::Builder::new_local(writer_text)
            .experimental_encryption(true)
            .with_encryption(turso::EncryptionOpts {
                cipher: CIPHER.to_string(),
                hexkey: OLD_DEK_HEX.to_string(),
            })
            .build(),
    )
    .expect("open raw encrypted source");
    let connection = database.connect().expect("connect raw encrypted source");
    block_on(connection.execute(
        "INSERT INTO credentials (service, user, uuid, secret) VALUES (?1, ?2, ?3, ?4)",
        (
            "basil",
            RECORD_KEY,
            RECORD_UUID,
            turso::Value::Blob(RECORD_VALUE.to_vec()),
        ),
    ))
    .expect("commit Basil record to source WAL");

    let writer_wal = dir.path.join(format!("{WRITER_NAME}-wal"));
    assert!(
        writer_wal
            .metadata()
            .is_ok_and(|metadata| metadata.len() > 0),
        "test setup requires committed frames in the source WAL"
    );
    std::fs::copy(&writer, dir.db_path()).expect("freeze source database");
    std::fs::copy(&writer_wal, dir.path.join(format!("{DB_NAME}-wal")))
        .expect("freeze committed source WAL");
    drop(connection);
    drop(database);
}

fn assert_no_source_sidecars(dir: &TestDir) {
    for suffix in SIDECAR_SUFFIXES {
        let sidecar = dir.path.join(format!("{DB_NAME}{suffix}"));
        assert!(
            !sidecar.exists(),
            "old source sidecar remained after swap: {}",
            sidecar.display()
        );
    }
}

fn remove_candidate_read_sidecars(dir: &TestDir) {
    for suffix in SIDECAR_SUFFIXES {
        let sidecar = dir
            .path
            .join(STAGING_DIR_NAME)
            .join(format!("{CANDIDATE_NAME}{suffix}"));
        match std::fs::remove_file(&sidecar) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!(
                "remove test-created candidate sidecar {}: {error}",
                sidecar.display()
            ),
        }
    }
}

#[test]
fn wal_resident_basil_record_reaches_candidate_before_old_wal_is_deleted() {
    let dir = TestDir::new();
    freeze_committed_wal(&dir);
    let old_wal = dir.path.join(format!("{DB_NAME}-wal"));
    assert!(old_wal.metadata().is_ok_and(|metadata| metadata.len() > 0));

    let main_only = dir.path.join("main-only.db");
    std::fs::copy(dir.db_path(), &main_only).expect("copy main database without its WAL");
    assert!(
        read_direct(&main_only, OLD_DEK_HEX).is_err(),
        "the unique record must reside only in the committed source WAL"
    );

    let lock = RekeyLock::acquire_exclusive(dir.fd.as_fd(), DB_NAME).expect("acquire rekey lock");
    let plan = RekeyPlan {
        db_dir: dir.fd.as_fd(),
        db_name: DB_NAME,
        cipher: CIPHER,
    };
    let old_dek = SensitiveDek::from_raw(Zeroizing::new(OLD_DEK));
    let new_dek = SensitiveDek::from_raw(Zeroizing::new(NEW_DEK));
    let staged = rekey_to_staging(&plan, old_dek, &new_dek, &lock).expect("stage rekey");
    assert_eq!(staged.report().copied, 1);

    let candidate = dir.path.join(STAGING_DIR_NAME).join(CANDIDATE_NAME);
    let candidate_value = read_direct(&candidate, NEW_DEK_HEX).expect("read record from candidate");
    remove_candidate_read_sidecars(&dir);
    assert_eq!(
        candidate_value, RECORD_VALUE,
        "the new-DEK candidate must contain the WAL-resident Basil record before swap"
    );
    assert!(
        old_wal.metadata().is_ok_and(|metadata| metadata.len() > 0),
        "candidate verification must precede deletion of the old source WAL"
    );

    let binding = BundleTransitionBinding::new(
        [0x81; 16],
        "wal-test-backend",
        [0x91; 32],
        [0x92; 32],
        EPOCHS,
        staged.report().copied,
    )
    .expect("bundle binding");
    let marker = staged.intent_marker(binding).expect("build intent marker");
    write_intent_marker(dir.fd.as_fd(), DB_NAME, &marker, &lock).expect("write intent marker");
    swap_candidate(dir.fd.as_fd(), DB_NAME, &staged, &lock).expect("swap candidate");
    assert_no_source_sidecars(&dir);
    finish_rekey(dir.fd.as_fd(), DB_NAME, &lock).expect("finish rekey");
    drop(staged);
    drop(lock);

    assert!(!marker_present(dir.fd.as_fd(), DB_NAME).expect("read marker state"));
    assert!(!dir.path.join(STAGING_DIR_NAME).exists());
    assert_no_source_sidecars(&dir);

    let final_store = SecretStore::open(StoreConfig::DbKeystore {
        path: dir.db_path(),
        cipher: CIPHER.to_string(),
        dek: SecretArray::new(NEW_DEK),
    })
    .expect("open final store under new DEK");
    assert_eq!(
        final_store
            .get(RECORD_KEY)
            .expect("read final Basil record"),
        RECORD_VALUE
    );
}
