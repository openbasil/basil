// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

fn fixture_dir() -> PathBuf {
    let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "basil-config-source-event-{}-{sequence}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path).expect("create fixture directory");
    path
}

fn run_agent(config: &Path) -> Output {
    run_basil("agent", config)
}

fn run_basil(command: &str, config: &Path) -> Output {
    run_basil_with_args(command, &[], config)
}

fn run_basil_with_args(command: &str, args: &[&str], config: &Path) -> Output {
    let mut process = Command::new(env!("CARGO_BIN_EXE_basil"));
    process.arg(command).args(args).arg("--config").arg(config);
    process
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .output()
        .expect("run basil command")
}

fn combined_output(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn source_event_lines(output: &str) -> Vec<&str> {
    output
        .lines()
        .filter(|line| line.contains("basil.configuration.source"))
        .collect()
}

fn field<'a>(line: &'a str, name: &str) -> &'a str {
    let prefix = format!("{name}=");
    line.split_whitespace()
        .find_map(|item| item.strip_prefix(&prefix))
        .map(|value| value.trim_matches('"'))
        .expect("structured event field")
}

fn assert_source_event(line: &str, config: &Path, body: &str, operation: &str, outcome: &str) {
    assert!(line.contains(" INFO ") || line.contains("INFO "));
    assert_eq!(field(line, "event"), "basil.configuration.source");
    assert_eq!(field(line, "operation"), operation);
    assert_eq!(field(line, "slot"), "agent");
    assert_eq!(field(line, "name"), "");
    assert_eq!(field(line, "name_present"), "false");
    assert_eq!(field(line, "path"), config.display().to_string());
    assert_eq!(
        field(line, "byte_size")
            .parse::<usize>()
            .expect("byte size"),
        body.len()
    );
    assert!(
        field(line, "modified_unix_seconds")
            .parse::<i64>()
            .expect("mtime seconds")
            > 0
    );
    assert!(
        field(line, "modified_nanoseconds")
            .parse::<u32>()
            .expect("mtime nanoseconds")
            < 1_000_000_000
    );
    assert_eq!(field(line, "hash_algorithm"), "sha256");
    let hash = field(line, "hash");
    assert_eq!(hash.len(), 64);
    assert!(hash.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(field(line, "outcome"), outcome);
    assert_eq!(field(line, "active_generation"), "0");
    assert_eq!(field(line, "active_generation_present"), "false");
    assert_eq!(field(line, "prior_generation_active"), "false");
    assert!(!line.contains("source-secret-sentinel"));
    assert!(!line.contains("Some("));
    assert!(!line.contains("None"));
}

#[test]
fn rejected_readable_bootstrap_is_emitted_after_safe_logging_initializes() {
    let dir = fixture_dir();
    let config = dir.join("config.toml");
    let body = r#"schema = "agent"
schemaVersion = 2
jwt-role = "source-secret-sentinel"
[import]
catalog = "catalog.json"
policy = "policy.json"
bundle = "bundle.age"
"#;
    std::fs::write(&config, body).expect("write rejected bootstrap");

    let output = run_agent(&config);
    let combined = combined_output(&output);
    let events = source_event_lines(&combined);

    assert!(!output.status.success());
    assert_eq!(events.len(), 1, "rejected preflight emits exactly once");
    assert_source_event(
        events.first().expect("rejected source event"),
        &config,
        body,
        "startup",
        "rejected",
    );
    assert!(!combined.contains("source-secret-sentinel"));
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn accepted_bootstrap_is_emitted_once_by_post_logging_startup_load() {
    let dir = fixture_dir();
    let config = dir.join("config.toml");
    let body = r#"schema = "agent"
schemaVersion = 3
jwt-role = "source-secret-sentinel"
[import]
catalog = "missing-catalog.json"
policy = "missing-policy.json"
bundle = "missing-bundle.age"
"#;
    std::fs::write(&config, body).expect("write accepted bootstrap");

    let output = run_agent(&config);
    let combined = combined_output(&output);
    let events = source_event_lines(&combined);

    assert!(!output.status.success());
    assert_eq!(events.len(), 1, "accepted preflight is not duplicated");
    assert_source_event(
        events.first().expect("accepted source event"),
        &config,
        body,
        "startup",
        "accepted",
    );
    assert!(!combined.contains("source-secret-sentinel"));
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn logging_initialization_failure_uses_fallback_and_emits_rejection_once() {
    let dir = fixture_dir();
    let config = dir.join("config.toml");
    let body = r#"schema = "agent"
schemaVersion = 3
jwt-role = "source-secret-sentinel"
[import]
catalog = "catalog.json"
policy = "policy.json"
bundle = "bundle.age"

[logging.file]
enable = true
"#;
    std::fs::write(&config, body).expect("write logging failure bootstrap");

    let output = run_agent(&config);
    let combined = combined_output(&output);
    let events = source_event_lines(&combined);

    assert!(!output.status.success());
    assert!(combined.contains("logging.file.dir is required"));
    assert_eq!(events.len(), 1, "logging fallback emits exactly once");
    assert_source_event(
        events.first().expect("logging failure source event"),
        &config,
        body,
        "startup",
        "rejected",
    );
    assert!(!combined.contains("source-secret-sentinel"));
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn rejected_doctor_bootstrap_is_labeled_offline() {
    let dir = fixture_dir();
    let config = dir.join("config.toml");
    let body = r#"schema = "agent"
schemaVersion = 2
jwt-role = "source-secret-sentinel"
[import]
catalog = "catalog.json"
policy = "policy.json"
bundle = "bundle.age"
"#;
    std::fs::write(&config, body).expect("write rejected doctor bootstrap");

    let output = run_basil("doctor", &config);
    let combined = combined_output(&output);
    let events = source_event_lines(&combined);

    assert!(!output.status.success());
    assert_eq!(events.len(), 1, "doctor rejection emits exactly once");
    assert_source_event(
        events.first().expect("doctor source event"),
        &config,
        body,
        "offline",
        "rejected",
    );
    assert!(!combined.contains("source-secret-sentinel"));
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn doctor_json_fallbacks_keep_configuration_traces_on_stderr() {
    let cases = [
        (
            "preflight",
            r#"schema = "agent"
schemaVersion = 2
jwt-role = "source-secret-sentinel"
[import]
catalog = "catalog.json"
policy = "policy.json"
bundle = "bundle.age"
"#,
            "schemaVersion 1 and 2 are reserved pre-unification versions",
        ),
        (
            "logging",
            r#"schema = "agent"
schemaVersion = 3
jwt-role = "source-secret-sentinel"
[import]
catalog = "catalog.json"
policy = "policy.json"
bundle = "bundle.age"

[logging.file]
enable = true
"#,
            "logging.file.dir is required",
        ),
    ];

    for (case, body, expected_error) in cases {
        let dir = fixture_dir();
        let config = dir.join("config.toml");
        std::fs::write(&config, body).expect("write doctor JSON bootstrap");

        let output = run_basil_with_args("doctor", &["--json"], &config);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let events = source_event_lines(&stderr);

        assert!(!output.status.success(), "{case} fallback must fail");
        assert!(stdout.trim().is_empty(), "{case} stdout: {stdout}");
        assert!(stderr.contains(expected_error), "{case} stderr: {stderr}");
        assert_eq!(events.len(), 1, "{case} fallback emits exactly once");
        assert_source_event(
            events.first().expect("doctor JSON source event"),
            &config,
            body,
            "offline",
            "rejected",
        );
        assert!(!stderr.contains("source-secret-sentinel"));
        std::fs::remove_dir_all(dir).ok();
    }
}
