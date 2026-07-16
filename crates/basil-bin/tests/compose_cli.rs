// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unwrap_used)]

use std::process::Command;

#[cfg(feature = "compose")]
use std::fs;
#[cfg(feature = "compose")]
use std::os::unix::fs::PermissionsExt as _;
#[cfg(feature = "compose")]
use std::path::PathBuf;
#[cfg(feature = "compose")]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "compose")]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "compose")]
static NEXT_FRONTEND: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "compose")]
struct TempFrontend(PathBuf);

#[cfg(feature = "compose")]
impl TempFrontend {
    fn new(body: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let sequence = NEXT_FRONTEND.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "basil-compose-cli-test-{}-{nonce}-{sequence}",
            std::process::id()
        ));
        fs::write(&path, format!("#!/usr/bin/env bash\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}

#[cfg(feature = "compose")]
impl Drop for TempFrontend {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[cfg(feature = "compose")]
#[test]
fn compose_cli_emits_only_sanitized_stdout_and_display_stderr() {
    let secret = "CLI-SENSITIVE-RENDERED-VALUE";
    let frontend = TempFrontend::new(&format!(
        r#"printf '%s' '{{"name":"cli","services":{{"api":{{"image":"example/api","environment":{{"TOKEN":"{secret}"}}}}}}}}'
printf '%s' '{secret}' >&2"#
    ));
    let output = Command::new(env!("CARGO_BIN_EXE_basil"))
        .args([
            "compose",
            "model",
            "--frontend-path",
            frontend.0.to_str().unwrap(),
            "--file",
            "compose.yaml",
            "--project-name",
            "cli",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(
        stdout,
        "{\"name\":\"cli\",\"services\":{\"api\":{\"image\":\"example/api\"}}}\n"
    );
    assert!(stderr.contains("compose"));
    assert!(stderr.contains("--no-env-resolution"));
    assert!(!stdout.contains(secret));
    assert!(!stderr.contains(secret));
}

#[cfg(feature = "compose")]
#[test]
fn compose_cli_failure_does_not_repeat_frontend_diagnostics() {
    let secret = "CLI-SENSITIVE-FAILURE";
    let frontend = TempFrontend::new(&format!("printf '%s' '{secret}' >&2\nexit 7"));
    let output = Command::new(env!("CARGO_BIN_EXE_basil"))
        .args([
            "compose",
            "model",
            "--frontend-path",
            frontend.0.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("unsuccessful status"));
    assert!(!stderr.contains(secret));
}

#[cfg(not(feature = "compose"))]
#[test]
fn feature_off_compose_command_returns_actionable_remediation() {
    let output = Command::new(env!("CARGO_BIN_EXE_basil"))
        .args(["compose", "model", "--file", "compose.yaml"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("install the standard Basil package"));
    assert!(stderr.contains("--features compose"));
}
