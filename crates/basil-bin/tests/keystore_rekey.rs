// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Real-binary coverage for offline `db-keystore` DEK rotation and recovery.

#![cfg(target_os = "linux")]
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::unnecessary_debug_formatting,
    clippy::panic,
    clippy::unwrap_used
)]

use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde_json::Value;

const BACKEND: &str = "local";
const KEY_ID: &str = "test.signing";
const PROCESS_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(20);
const OLD_DEK: [u8; 32] = [0x31; 32];
const NEW_DEK: [u8; 32] = [0xa7; 32];
const PASSPHRASE: &str = "basil-rekey-passphrase-SECRET-SENTINEL";
#[cfg(debug_assertions)]
const CHECKPOINT_VARIABLE: &str = "BASIL_TEST_KEYSTORE_REKEY_STOP_AFTER";
#[cfg(debug_assertions)]
const BUNDLE_ENOSPC_VARIABLE: &str = "BASIL_TEST_KEYSTORE_REKEY_BUNDLE_REPLACE_ENOSPC";
#[cfg(debug_assertions)]
const EPOCH_ENOSPC_VARIABLE: &str = "BASIL_TEST_KEYSTORE_REKEY_EPOCH_SIDECAR_ENOSPC";

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    config: PathBuf,
    catalog: PathBuf,
    policy: PathBuf,
    bundle: PathBuf,
    passphrase: PathBuf,
    old_dek: PathBuf,
    new_dek: PathBuf,
    database: PathBuf,
    socket: PathBuf,
    audit: PathBuf,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "basil-rekey-bin-{tag}-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&root).expect("create fixture directory");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("restrict fixture directory");
        let fixture = Self {
            config: root.join("config.toml"),
            catalog: root.join("catalog.json"),
            policy: root.join("policy.json"),
            bundle: root.join("bundle.sealed"),
            passphrase: root.join("passphrase-SECRET-SENTINEL.txt"),
            old_dek: root.join("old-DEK-SECRET-SENTINEL.bin"),
            new_dek: root.join("new-DEK-SECRET-SENTINEL.bin"),
            database: root.join("keystore.db"),
            socket: root.join("basil.sock"),
            audit: root.join("audit.jsonl"),
            root,
        };
        fixture.write_sources();
        fixture.create_bundle();
        fixture.start_agent_and_sign("pre-rekey");
        fixture
    }

    fn write_sources(&self) {
        write_private(&self.passphrase, format!("{PASSPHRASE}\n").as_bytes());
        write_private(&self.old_dek, &OLD_DEK);
        write_private(&self.new_dek, &NEW_DEK);

        let catalog = serde_json::json!({
            "schema": "catalog",
            "backends": {
                (BACKEND): {
                    "kind": "keystore",
                    "addr": self.database.display().to_string(),
                    "engines": ["transit", "kv2"],
                    "capabilities": [],
                    "mintKeyTypes": ["ed25519"]
                }
            },
            "keys": {
                (KEY_ID): {
                    "class": "asymmetric",
                    "keyType": "ed25519",
                    "backend": BACKEND,
                    "engine": "transit",
                    "path": "test/signing",
                    "writable": true,
                    "missing": "generate",
                    "description": "integration-test signing key"
                }
            }
        });
        std::fs::write(
            &self.catalog,
            format!("{}\n", serde_json::to_string_pretty(&catalog).unwrap()),
        )
        .expect("write catalog");

        let uid = rustix::process::geteuid().as_raw();
        let policy = serde_json::json!({
            "schema": "policy",
            "subjects": {
                "current-user": {
                    "domain": "host-process",
                    "match": { "all": [{ "process.uid": uid }] }
                }
            },
            "roles": { "signer": ["sign"] },
            "rules": [{
                "id": "current-user-signs-test-key",
                "subjects": ["current-user"],
                "action": ["role:signer"],
                "target": [KEY_ID]
            }],
            "config": {
                "names": { "users": { (uid.to_string()): "test-user" } },
                "memberships": { (uid.to_string()): [] }
            }
        });
        std::fs::write(
            &self.policy,
            format!("{}\n", serde_json::to_string_pretty(&policy).unwrap()),
        )
        .expect("write policy");
        std::fs::write(&self.config, self.config_text(&self.bundle, &self.socket))
            .expect("write schema-3 config");
    }

    fn config_text(&self, bundle: &Path, socket: &Path) -> String {
        format!(
            "schema = \"agent\"\n\
             schemaVersion = 3\n\
             socket = {socket:?}\n\
             socket-mode = \"0600\"\n\
             db-keystore-cipher = \"aegis256\"\n\
             audit-log = {audit:?}\n\
             \n\
             [import]\n\
             catalog = {catalog:?}\n\
             policy = {policy:?}\n\
             bundle = {bundle:?}\n\
             \n\
             [unlock]\n\
             unlock-passphrase-file = {passphrase:?}\n\
             unlock-passphrase-no-wipe = true\n",
            socket = socket,
            audit = self.audit,
            catalog = self.catalog,
            policy = self.policy,
            bundle = bundle,
            passphrase = self.passphrase,
        )
    }

    fn create_bundle(&self) {
        let slot = format!("passphrase:file={}", self.passphrase.display());
        let backend = format!(
            "id={BACKEND},type=db-keystore,path={},cipher=aegis256,dek-file={}",
            self.database.display(),
            self.old_dek.display()
        );
        let output = run_basil([
            "bundle".into(),
            "create".into(),
            self.bundle.as_os_str().into(),
            "--slot".into(),
            slot.into(),
            "--backend".into(),
            backend.into(),
        ]);
        assert_success(&output, "bundle create");
        assert_eq!(mode(&self.bundle), 0o600, "sealed bundle mode");
        assert_eq!(mode(&self.passphrase), 0o600, "passphrase mode");
        assert_eq!(mode(&self.old_dek), 0o600, "old DEK mode");
        assert_eq!(mode(&self.new_dek), 0o600, "new DEK mode");
    }

    fn rekey_args(&self) -> Vec<std::ffi::OsString> {
        vec![
            "keystore".into(),
            "rekey".into(),
            "--config".into(),
            self.config.as_os_str().into(),
            "--backend".into(),
            BACKEND.into(),
            "--new-dek-file".into(),
            self.new_dek.as_os_str().into(),
            "--open".into(),
            format!("passphrase:file={}", self.passphrase.display()).into(),
        ]
    }

    fn resume_args(&self) -> Vec<std::ffi::OsString> {
        vec![
            "keystore".into(),
            "rekey".into(),
            "--config".into(),
            self.config.as_os_str().into(),
            "--backend".into(),
            BACKEND.into(),
            "--resume".into(),
            "--open".into(),
            format!("passphrase:file={}", self.passphrase.display()).into(),
        ]
    }

    fn bundle_epoch(&self, bundle: &Path) -> u64 {
        let output = run_basil([
            "bundle".into(),
            "show".into(),
            bundle.as_os_str().into(),
            "--open".into(),
            format!("passphrase:file={}", self.passphrase.display()).into(),
        ]);
        assert_success(&output, "bundle show");
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .find_map(|line| line.strip_prefix("epoch: "))
            .expect("bundle show emits epoch")
            .parse()
            .expect("bundle epoch is numeric")
    }

    fn sidecar_epoch(&self) -> u64 {
        std::fs::read_to_string(suffixed(&self.bundle, ".epoch"))
            .expect("read epoch sidecar")
            .trim()
            .parse()
            .expect("sidecar epoch is numeric")
    }

    fn start_agent_and_sign(&self, payload: &str) {
        let _ = std::fs::remove_file(&self.socket);
        let log_path = self.root.join(format!("agent-{payload}.log"));
        let log = File::create(&log_path).expect("create agent log");
        let stderr = log.try_clone().expect("clone agent log");
        let child = Command::new(env!("CARGO_BIN_EXE_basil"))
            .arg("agent")
            .arg("--config")
            .arg(&self.config)
            .stdin(Stdio::null())
            .stdout(log)
            .stderr(stderr)
            .spawn()
            .expect("spawn agent");
        let mut agent = ChildGuard::new(child);
        wait_for_socket(agent.child_mut(), &self.socket, &log_path);

        let output = run_basil([
            "--socket".into(),
            self.socket.as_os_str().into(),
            "sign".into(),
            "--key-id".into(),
            KEY_ID.into(),
            payload.into(),
        ]);
        assert_success(&output, "sign through real agent");
        assert!(!output.stdout.is_empty(), "sign returns a signature");
        agent.terminate();
    }

    fn assert_old_bundle_mismatch(&self, old_bundle: &Path) {
        let old_socket = self.root.join("old-bundle.sock");
        let old_config = self.root.join("old-bundle-config.toml");
        std::fs::write(&old_config, self.config_text(old_bundle, &old_socket))
            .expect("write old-bundle config");
        let log_path = self.root.join("old-bundle-agent.log");
        let log = File::create(&log_path).expect("create old-bundle agent log");
        let stderr = log.try_clone().expect("clone old-bundle agent log");
        let child = Command::new(env!("CARGO_BIN_EXE_basil"))
            .arg("agent")
            .arg("--config")
            .arg(&old_config)
            .stdin(Stdio::null())
            .stdout(log)
            .stderr(stderr)
            .spawn()
            .expect("spawn agent with old bundle");
        let mut child = ChildGuard::new(child);
        let status = wait_for_exit(child.child_mut(), "old-bundle agent");
        child.reaped = true;
        assert!(!status.success(), "old bundle must not open the new-DEK DB");
        assert!(!old_socket.exists(), "mismatched agent never becomes ready");
    }

    fn assert_rekey_inventory_clean(&self) {
        self.assert_transaction_artifacts_clean();
        for suffix in ["-wal", "-tshm"] {
            assert!(
                !self.root.join(format!("keystore.db{suffix}")).exists(),
                "old sidecar {suffix} removed"
            );
        }
    }

    fn assert_transaction_artifacts_clean(&self) {
        assert!(!self.marker().exists(), "intent marker removed");
        assert!(
            !self.root.join(".rekey-staging").exists(),
            "staging removed"
        );
    }

    fn marker(&self) -> PathBuf {
        self.root.join("keystore.db.rekey-intent")
    }

    #[cfg(debug_assertions)]
    fn candidate(&self) -> PathBuf {
        self.root.join(".rekey-staging/candidate.db")
    }

    #[cfg(debug_assertions)]
    fn snapshot_bundle(&self, tag: &str) -> PathBuf {
        let snapshot = self.root.join(format!("{tag}.sealed"));
        std::fs::copy(&self.bundle, &snapshot).expect("snapshot sealed bundle");
        std::fs::copy(
            suffixed(&self.bundle, ".epoch"),
            suffixed(&snapshot, ".epoch"),
        )
        .expect("snapshot bundle epoch sidecar");
        snapshot
    }

    #[cfg(debug_assertions)]
    fn spawn_checkpointed_rekey(&self, checkpoint: &str) -> ChildGuard {
        let stdout = File::create(self.root.join(format!("rekey-{checkpoint}.stdout")))
            .expect("create checkpoint stdout");
        let stderr = File::create(self.root.join(format!("rekey-{checkpoint}.stderr")))
            .expect("create checkpoint stderr");
        let child = Command::new(env!("CARGO_BIN_EXE_basil"))
            .args(self.rekey_args())
            .env(CHECKPOINT_VARIABLE, checkpoint)
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .spawn()
            .expect("spawn checkpointed rekey");
        ChildGuard::new(child)
    }

    #[cfg(debug_assertions)]
    fn run_rekey_with_fault(&self, variable: &str) -> Output {
        Command::new(env!("CARGO_BIN_EXE_basil"))
            .args(self.rekey_args())
            .env(variable, "1")
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .output()
            .expect("run fault-injected rekey")
    }

    fn audit_events(&self) -> Vec<Value> {
        std::fs::read_to_string(&self.audit)
            .expect("read audit log")
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|event| event["event_kind"] == "basil.audit.keystore_rekey")
            .collect()
    }

    fn assert_audit_redacted(&self) {
        let raw = std::fs::read_to_string(&self.audit).expect("read audit bytes");
        for secret in [
            PASSPHRASE.to_owned(),
            hex_lower(&OLD_DEK),
            hex_lower(&NEW_DEK),
            self.passphrase
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            self.old_dek
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            self.new_dek
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
        ] {
            assert!(
                !raw.contains(&secret),
                "audit leaked secret sentinel `{secret}`"
            );
        }

        let safe_fields = BTreeSet::from([
            "event_kind",
            "event_version",
            "occurred_at_unix",
            "backend_id",
            "mode",
            "outcome",
            "pre_epoch",
            "post_epoch",
            "copied",
            "recovery",
        ]);
        for event in self.audit_events() {
            let found: BTreeSet<&str> = event
                .as_object()
                .expect("rekey audit event is an object")
                .keys()
                .map(String::as_str)
                .collect();
            assert_eq!(found, safe_fields, "rekey audit field set");
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

struct ChildGuard {
    child: Child,
    reaped: bool,
}

impl ChildGuard {
    const fn new(child: Child) -> Self {
        Self {
            child,
            reaped: false,
        }
    }

    const fn child_mut(&mut self) -> &mut Child {
        &mut self.child
    }

    fn terminate(&mut self) {
        if self.reaped {
            return;
        }
        signal_child(&self.child, rustix::process::Signal::TERM);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match self.child.try_wait().expect("poll child") {
                Some(_) => {
                    self.reaped = true;
                    return;
                }
                None if Instant::now() < deadline => std::thread::sleep(POLL_INTERVAL),
                None => {
                    self.child.kill().expect("kill child after TERM timeout");
                    self.child.wait().expect("reap killed child");
                    self.reaped = true;
                    return;
                }
            }
        }
    }

    fn kill_at_checkpoint(&mut self) {
        signal_child(&self.child, rustix::process::Signal::KILL);
        let status = self.child.wait().expect("reap checkpoint child");
        self.reaped = true;
        assert_eq!(status.signal(), Some(9), "checkpoint child dies by SIGKILL");
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[test]
fn fresh_rekey_rotates_real_database_and_bundle() {
    let fixture = Fixture::new("fresh");
    let pre_epoch = fixture.bundle_epoch(&fixture.bundle);
    assert_eq!(fixture.sidecar_epoch(), pre_epoch);
    let old_bundle = fixture.root.join("old-bundle.sealed");
    std::fs::copy(&fixture.bundle, &old_bundle).expect("save pre-rekey bundle");
    std::fs::copy(
        suffixed(&fixture.bundle, ".epoch"),
        suffixed(&old_bundle, ".epoch"),
    )
    .expect("save pre-rekey epoch sidecar");

    assert_argument_misuse(&fixture);
    let output = run_basil(fixture.rekey_args());
    assert_success(&output, "fresh keystore rekey");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("verified and copied"),
        "fresh output: {stdout}"
    );

    let post_epoch = fixture.bundle_epoch(&fixture.bundle);
    assert_eq!(post_epoch, pre_epoch + 1, "bundle epoch advances once");
    assert_eq!(fixture.sidecar_epoch(), post_epoch);
    fixture.assert_rekey_inventory_clean();
    fixture.assert_old_bundle_mismatch(&old_bundle);
    fixture.start_agent_and_sign("post-fresh-rekey");

    let events = fixture.audit_events();
    let fresh: Vec<&Value> = events
        .iter()
        .filter(|event| event["mode"] == "fresh")
        .collect();
    let outcomes: Vec<&str> = fresh
        .iter()
        .filter_map(|event| event["outcome"].as_str())
        .collect();
    assert_eq!(
        outcomes,
        ["started", "prepared", "bundle_committed", "completed"]
    );
    assert!(
        fresh.last().unwrap()["copied"].as_u64().unwrap() > 0,
        "the real database copied at least one record"
    );
    fixture.assert_audit_redacted();
}

#[cfg(debug_assertions)]
#[test]
fn resume_rolls_forward_after_real_bundle_commit_sigkill() {
    let fixture = Fixture::new("resume");
    let pre_epoch = fixture.bundle_epoch(&fixture.bundle);
    let mut child = fixture.spawn_checkpointed_rekey("bundle-committed");
    wait_for_stopped(child.child_mut());

    assert_eq!(
        fixture.sidecar_epoch(),
        pre_epoch,
        "checkpoint precedes epoch-sidecar update"
    );
    assert!(
        fixture.marker().is_file(),
        "intent marker fences the crash state"
    );
    assert!(fixture.root.join(".rekey-staging/candidate.db").is_file());
    child.kill_at_checkpoint();
    let post_epoch = fixture.bundle_epoch(&fixture.bundle);
    assert_eq!(
        post_epoch,
        pre_epoch + 1,
        "durable bundle commit advanced epoch"
    );

    assert_agent_fenced(&fixture);
    let output = run_basil(fixture.resume_args());
    assert_success(&output, "explicit keystore rekey resume");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("resumed_swap"), "resume output: {stdout}");
    assert_eq!(fixture.bundle_epoch(&fixture.bundle), post_epoch);
    assert_eq!(fixture.sidecar_epoch(), post_epoch);
    fixture.assert_rekey_inventory_clean();
    fixture.start_agent_and_sign("post-resume");

    let events = fixture.audit_events();
    let resumed = events.iter().find(|event| {
        event["mode"] == "resume"
            && event["outcome"] == "completed"
            && event["recovery"] == "resumed_swap"
    });
    assert!(resumed.is_some(), "resume completion is audited");
    assert!(
        resumed.unwrap()["copied"].as_u64().unwrap() > 0,
        "resume audit retains the real record count"
    );
    fixture.assert_audit_redacted();
}

#[cfg(debug_assertions)]
#[test]
fn old_dek_owners_are_cleared_before_bundle_commit() {
    let fixture = Fixture::new("old-dek-owners");
    let bundle_before = std::fs::read(&fixture.bundle).expect("read pre-rekey bundle");
    let sidecar_before =
        std::fs::read(suffixed(&fixture.bundle, ".epoch")).expect("read pre-rekey sidecar");
    let database_before = std::fs::read(&fixture.database).expect("read pre-rekey database");
    let mut child = fixture.spawn_checkpointed_rekey("old-dek-owners-cleared");
    wait_for_stopped(child.child_mut());

    assert_eq!(std::fs::read(&fixture.bundle).unwrap(), bundle_before);
    assert_eq!(
        std::fs::read(suffixed(&fixture.bundle, ".epoch")).unwrap(),
        sidecar_before
    );
    assert_eq!(std::fs::read(&fixture.database).unwrap(), database_before);
    assert!(fixture.marker().is_file(), "prepared marker is durable");
    assert!(fixture.candidate().is_file(), "staged candidate is durable");
    child.kill_at_checkpoint();

    let output = run_basil(fixture.resume_args());
    assert_success(&output, "resume after old-DEK ownership checkpoint");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("rolled_back"), "resume output: {stdout}");
    assert_eq!(std::fs::read(&fixture.bundle).unwrap(), bundle_before);
    assert_eq!(
        std::fs::read(suffixed(&fixture.bundle, ".epoch")).unwrap(),
        sidecar_before
    );
    assert_eq!(std::fs::read(&fixture.database).unwrap(), database_before);
    fixture.assert_transaction_artifacts_clean();
    fixture.start_agent_and_sign("post-old-dek-proof");
}

#[cfg(debug_assertions)]
#[test]
fn bundle_replace_enospc_preserves_precommit_state_and_rolls_back() {
    let fixture = Fixture::new("bundle-enospc");
    let bundle_before = std::fs::read(&fixture.bundle).expect("read pre-rekey bundle");
    let sidecar_before =
        std::fs::read(suffixed(&fixture.bundle, ".epoch")).expect("read pre-rekey sidecar");
    let database_before = std::fs::read(&fixture.database).expect("read pre-rekey database");

    let output = fixture.run_rekey_with_fault(BUNDLE_ENOSPC_VARIABLE);
    assert!(!output.status.success(), "injected ENOSPC must fail rekey");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("writing the replacement sealed bundle")
            && stderr.contains("No space left on device"),
        "typed bundle ENOSPC error: {stderr}"
    );
    assert_eq!(std::fs::read(&fixture.bundle).unwrap(), bundle_before);
    assert_eq!(
        std::fs::read(suffixed(&fixture.bundle, ".epoch")).unwrap(),
        sidecar_before
    );
    assert_eq!(std::fs::read(&fixture.database).unwrap(), database_before);
    assert!(fixture.marker().is_file(), "prepared marker is preserved");
    assert!(
        fixture.candidate().is_file(),
        "staged candidate is preserved"
    );
    assert_agent_fenced(&fixture);

    let output = run_basil(fixture.resume_args());
    assert_success(&output, "resume after bundle ENOSPC");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("rolled_back"), "resume output: {stdout}");
    assert_eq!(std::fs::read(&fixture.bundle).unwrap(), bundle_before);
    assert_eq!(
        std::fs::read(suffixed(&fixture.bundle, ".epoch")).unwrap(),
        sidecar_before
    );
    assert_eq!(std::fs::read(&fixture.database).unwrap(), database_before);
    fixture.assert_transaction_artifacts_clean();
    fixture.start_agent_and_sign("post-bundle-enospc-rollback");
    fixture.assert_audit_redacted();
}

#[cfg(debug_assertions)]
#[test]
fn epoch_sidecar_enospc_preserves_post_bundle_and_resumes_swap() {
    let fixture = Fixture::new("epoch-enospc");
    let pre_epoch = fixture.bundle_epoch(&fixture.bundle);
    let old_bundle = fixture.snapshot_bundle("epoch-enospc-old-bundle");
    let bundle_before = std::fs::read(&fixture.bundle).expect("read pre-rekey bundle");
    let sidecar_before =
        std::fs::read(suffixed(&fixture.bundle, ".epoch")).expect("read pre-rekey sidecar");
    let database_before = std::fs::read(&fixture.database).expect("read pre-rekey database");

    let output = fixture.run_rekey_with_fault(EPOCH_ENOSPC_VARIABLE);
    assert!(!output.status.success(), "injected ENOSPC must fail rekey");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("writing the sealed-bundle epoch sidecar")
            && stderr.contains("No space left on device"),
        "typed epoch-sidecar ENOSPC error: {stderr}"
    );
    let post_bundle = std::fs::read(&fixture.bundle).expect("read committed post bundle");
    assert_ne!(post_bundle, bundle_before, "bundle replacement is durable");
    assert_eq!(fixture.bundle_epoch(&fixture.bundle), pre_epoch + 1);
    assert_eq!(
        std::fs::read(suffixed(&fixture.bundle, ".epoch")).unwrap(),
        sidecar_before,
        "epoch sidecar remains at the pre-rekey value"
    );
    assert_eq!(std::fs::read(&fixture.database).unwrap(), database_before);
    assert!(fixture.marker().is_file(), "prepared marker is preserved");
    let candidate = std::fs::read(fixture.candidate()).expect("read staged candidate");
    assert_agent_fenced(&fixture);

    let output = run_basil(fixture.resume_args());
    assert_success(&output, "resume after epoch-sidecar ENOSPC");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("resumed_swap"), "resume output: {stdout}");
    assert_eq!(std::fs::read(&fixture.bundle).unwrap(), post_bundle);
    assert_eq!(fixture.sidecar_epoch(), pre_epoch + 1);
    assert_eq!(std::fs::read(&fixture.database).unwrap(), candidate);
    fixture.assert_rekey_inventory_clean();
    fixture.assert_old_bundle_mismatch(&old_bundle);
    fixture.start_agent_and_sign("post-epoch-enospc-resume");
    fixture.assert_audit_redacted();
}

#[cfg(debug_assertions)]
#[test]
fn resume_reports_resumed_swap_after_epoch_sidecar_sigkill() {
    let fixture = Fixture::new("epoch-sidecar-checkpoint");
    let pre_epoch = fixture.bundle_epoch(&fixture.bundle);
    let old_bundle = fixture.snapshot_bundle("epoch-checkpoint-old-bundle");
    let database_before = std::fs::read(&fixture.database).expect("read pre-rekey database");
    let mut child = fixture.spawn_checkpointed_rekey("epoch-sidecar-durable");
    wait_for_stopped(child.child_mut());

    let post_bundle = std::fs::read(&fixture.bundle).expect("read durable post bundle");
    assert_eq!(fixture.sidecar_epoch(), pre_epoch + 1);
    assert_eq!(std::fs::read(&fixture.database).unwrap(), database_before);
    assert!(
        fixture.marker().is_file(),
        "intent marker remains the fence"
    );
    let candidate = std::fs::read(fixture.candidate()).expect("read staged candidate");
    child.kill_at_checkpoint();
    assert_eq!(fixture.bundle_epoch(&fixture.bundle), pre_epoch + 1);
    assert_agent_fenced(&fixture);

    let output = run_basil(fixture.resume_args());
    assert_success(&output, "resume after epoch-sidecar checkpoint");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("resumed_swap"), "resume output: {stdout}");
    assert_eq!(fixture.bundle_epoch(&fixture.bundle), pre_epoch + 1);
    assert_eq!(std::fs::read(&fixture.bundle).unwrap(), post_bundle);
    assert_eq!(fixture.sidecar_epoch(), pre_epoch + 1);
    assert_eq!(std::fs::read(&fixture.database).unwrap(), candidate);
    fixture.assert_rekey_inventory_clean();
    fixture.assert_old_bundle_mismatch(&old_bundle);
    fixture.start_agent_and_sign("post-epoch-checkpoint-resume");
}

#[cfg(debug_assertions)]
#[test]
fn resume_reports_swap_already_complete_after_db_swap_sigkill() {
    let fixture = Fixture::new("db-swap-checkpoint");
    let pre_epoch = fixture.bundle_epoch(&fixture.bundle);
    let old_bundle = fixture.snapshot_bundle("db-swap-old-bundle");
    let database_before = std::fs::read(&fixture.database).expect("read pre-rekey database");
    let mut child = fixture.spawn_checkpointed_rekey("db-swap-durable");
    wait_for_stopped(child.child_mut());

    let post_bundle = std::fs::read(&fixture.bundle).expect("read durable post bundle");
    assert_eq!(fixture.sidecar_epoch(), pre_epoch + 1);
    assert!(
        fixture.marker().is_file(),
        "intent marker remains the fence"
    );
    assert!(
        !fixture.candidate().exists(),
        "candidate was atomically renamed"
    );
    assert!(
        fixture.root.join(".rekey-staging").is_dir(),
        "finish has not removed the staging directory"
    );
    let swapped_database = std::fs::read(&fixture.database).expect("read swapped database");
    assert_ne!(
        swapped_database, database_before,
        "database swap is visible"
    );
    for suffix in ["-wal", "-tshm"] {
        assert!(
            !fixture.root.join(format!("keystore.db{suffix}")).exists(),
            "old sidecar {suffix} was removed before the swap"
        );
    }
    child.kill_at_checkpoint();
    assert_eq!(fixture.bundle_epoch(&fixture.bundle), pre_epoch + 1);
    assert_agent_fenced(&fixture);

    let output = run_basil(fixture.resume_args());
    assert_success(&output, "resume after database-swap checkpoint");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("swap_already_complete"),
        "resume output: {stdout}"
    );
    assert_eq!(fixture.bundle_epoch(&fixture.bundle), pre_epoch + 1);
    assert_eq!(std::fs::read(&fixture.bundle).unwrap(), post_bundle);
    assert_eq!(fixture.sidecar_epoch(), pre_epoch + 1);
    assert_eq!(std::fs::read(&fixture.database).unwrap(), swapped_database);
    fixture.assert_rekey_inventory_clean();
    fixture.assert_old_bundle_mismatch(&old_bundle);
    fixture.start_agent_and_sign("post-db-swap-checkpoint-resume");
}

fn assert_argument_misuse(fixture: &Fixture) {
    let mut missing = fixture.rekey_args();
    let new_dek_flag = missing
        .iter()
        .position(|arg| arg == std::ffi::OsStr::new("--new-dek-file"))
        .expect("new-DEK flag");
    missing.drain(new_dek_flag..=new_dek_flag + 1);
    let output = run_basil(missing);
    assert!(!output.status.success(), "fresh mode requires a new DEK");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("--new-dek-file"),
        "missing-argument error names --new-dek-file"
    );

    let mut conflict = fixture.resume_args();
    conflict.extend(["--new-dek-file".into(), fixture.new_dek.as_os_str().into()]);
    let output = run_basil(conflict);
    assert!(
        !output.status.success(),
        "resume rejects a new DEK argument"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--resume") && stderr.contains("--new-dek-file"),
        "conflict error names both incompatible arguments: {stderr}"
    );
}

fn assert_agent_fenced(fixture: &Fixture) {
    let _ = std::fs::remove_file(&fixture.socket);
    let log_path = fixture.root.join("fenced-agent.log");
    let log = File::create(&log_path).expect("create fenced-agent log");
    let stderr = log.try_clone().expect("clone fenced-agent log");
    let child = Command::new(env!("CARGO_BIN_EXE_basil"))
        .arg("agent")
        .arg("--config")
        .arg(&fixture.config)
        .stdin(Stdio::null())
        .stdout(log)
        .stderr(stderr)
        .spawn()
        .expect("spawn fenced agent");
    let mut child = ChildGuard::new(child);
    let status = wait_for_exit(child.child_mut(), "fenced agent");
    child.reaped = true;
    let output = std::fs::read_to_string(log_path).expect("read fenced-agent log");
    assert!(!status.success(), "marker-fenced agent must fail startup");
    assert!(
        output.contains("rekey in progress") && output.contains("--resume"),
        "fence error names explicit recovery: {output}"
    );
}

fn wait_for_socket(child: &mut Child, socket: &Path, log: &Path) {
    let deadline = Instant::now() + PROCESS_TIMEOUT;
    loop {
        if socket.exists() {
            return;
        }
        if let Some(status) = child.try_wait().expect("poll agent") {
            let output = std::fs::read_to_string(log).unwrap_or_default();
            panic!("agent exited before socket readiness ({status}): {output}");
        }
        assert!(
            Instant::now() < deadline,
            "agent socket readiness timed out"
        );
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn wait_for_stopped(child: &mut Child) {
    let deadline = Instant::now() + PROCESS_TIMEOUT;
    let status_path = format!("/proc/{}/status", child.id());
    loop {
        let status = std::fs::read_to_string(&status_path).expect("read child proc status");
        if status.lines().any(|line| line.starts_with("State:\tT")) {
            return;
        }
        if let Some(exit) = child.try_wait().expect("poll checkpoint child") {
            panic!("rekey exited before SIGSTOP checkpoint: {exit}");
        }
        assert!(
            Instant::now() < deadline,
            "rekey SIGSTOP checkpoint timed out"
        );
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn wait_for_exit(child: &mut Child, context: &str) -> std::process::ExitStatus {
    let deadline = Instant::now() + PROCESS_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait().expect("poll child exit") {
            return status;
        }
        if Instant::now() >= deadline {
            child.kill().expect("kill timed-out child");
            let _ = child.wait();
            panic!("{context} exceeded {PROCESS_TIMEOUT:?}");
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn signal_child(child: &Child, signal: rustix::process::Signal) {
    let pid = rustix::process::Pid::from_child(child);
    rustix::process::kill_process(pid, signal).expect("signal child");
}

fn run_basil(args: impl IntoIterator<Item = std::ffi::OsString>) -> Output {
    Command::new(env!("CARGO_BIN_EXE_basil"))
        .args(args)
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .output()
        .expect("run basil binary")
}

fn assert_success(output: &Output, context: &str) {
    assert!(
        output.status.success(),
        "{context} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn write_private(path: &Path, contents: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .expect("create owner-only fixture file");
    file.write_all(contents)
        .expect("write owner-only fixture file");
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path)
        .expect("stat fixture file")
        .permissions()
        .mode()
        & 0o777
}

fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(encoded, "{byte:02x}").expect("write to String");
    }
    encoded
}
