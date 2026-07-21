// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Startup-glue smoke tests for the real `basil-measure-helper` binary.
//!
//! The library conformance suite (`basil_core::attestor_protocol::helper`)
//! exercises the serve path exhaustively, but it never runs the built binary:
//! argument parsing, the insecure-socket-mode reject, and the allowlist
//! load-failure exit are only reachable through the process entrypoint. These
//! tests drive that entrypoint end to end and assert its exit-code contract.
//!
//! They deliberately stop before the post-init lockdown (`engage`) and the
//! endpoint bind: `engage` installs a thread-synchronized seccomp filter that
//! kills on an unexpected syscall, and a positive serve is unreachable
//! unprivileged (a live unprivileged process can never present a
//! manifest-matching confinement label). Every input here therefore forces a
//! failure on a startup branch that precedes the lockdown, so the assertions
//! stay deterministic without privilege, a real socket, or seccomp support.

#![allow(clippy::unwrap_used)]

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// clap uses exit code 2 for every usage error (bad value, missing required).
const CLAP_USAGE_EXIT: i32 = 2;
/// `ExitCode::FAILURE` for a startup failure the helper handles and logs.
const STARTUP_FAILURE_EXIT: i32 = 1;

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

/// A private, owner-only scratch directory removed on drop.
struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let sequence = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "basil-measure-helper-cli-{}-{nonce}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn own_uid() -> u32 {
    rustix::process::getuid().as_raw()
}

/// Path to a directory guaranteed not to exist under the scratch root.
fn missing_dir() -> PathBuf {
    std::env::temp_dir().join(format!(
        "basil-measure-helper-cli-absent-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed),
    ))
}

/// A bad `--socket-mode` is rejected by clap's value parser before any I/O.
#[test]
fn clap_rejects_insecure_socket_mode() {
    let output = Command::new(env!("CARGO_BIN_EXE_basil-measure-helper"))
        .args(["--lockdown-generation", "1", "--socket-mode", "0666"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(CLAP_USAGE_EXIT));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("other"), "stderr: {stderr}");
}

/// The generation-binding `--lockdown-generation` is required: the helper must
/// not engage an unversioned lockdown, so clap fails closed when it is absent.
#[test]
fn clap_requires_lockdown_generation() {
    let output = Command::new(env!("CARGO_BIN_EXE_basil-measure-helper"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(CLAP_USAGE_EXIT));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("lockdown-generation"), "stderr: {stderr}");
}

/// A missing policy directory fails the allowlist load and exits nonzero
/// before the lockdown boundary.
#[test]
fn missing_policy_dir_exits_failure() {
    let absent = missing_dir();
    let output = Command::new(env!("CARGO_BIN_EXE_basil-measure-helper"))
        .args(["--lockdown-generation", "1"])
        .arg("--policy-dir")
        .arg(&absent)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(STARTUP_FAILURE_EXIT));
    // `tracing_subscriber::fmt()` writes its formatted events to stdout.
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("failed to load the installed helper allowlist"),
        "stdout: {stdout}"
    );
}

/// A policy directory whose owner is not the required trust anchor is rejected
/// as untrusted, exiting nonzero before the lockdown boundary.
#[test]
fn untrusted_policy_dir_owner_exits_failure() {
    let dir = ScratchDir::new();
    // The directory is owned by this process's UID; demand a different owner so
    // the exclusive-ownership check fails deterministically (even under root).
    let foreign_owner = own_uid().wrapping_add(1);
    let output = Command::new(env!("CARGO_BIN_EXE_basil-measure-helper"))
        .args(["--lockdown-generation", "1"])
        .arg("--policy-dir")
        .arg(&dir.0)
        .arg("--required-owner-uid")
        .arg(foreign_owner.to_string())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(STARTUP_FAILURE_EXIT));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("failed to load the installed helper allowlist"),
        "stdout: {stdout}"
    );
}

/// A malformed policy file inside a trusted directory fails validation and
/// exits nonzero before the lockdown boundary.
#[test]
fn malformed_policy_file_exits_failure() {
    let dir = ScratchDir::new();
    let policy = dir.0.join("basil-measure-policy-g1.toml");
    fs::write(&policy, "this is not a valid policy file\n").unwrap();
    fs::set_permissions(&policy, fs::Permissions::from_mode(0o600)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_basil-measure-helper"))
        .args(["--lockdown-generation", "1"])
        .arg("--policy-dir")
        .arg(&dir.0)
        .arg("--required-owner-uid")
        .arg(own_uid().to_string())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(STARTUP_FAILURE_EXIT));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("failed to load the installed helper allowlist"),
        "stdout: {stdout}"
    );
}
