// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Cross-engine LIVE e2e for **`basil doctor`** over a dev `OpenBao` AND a dev
//! `Vault` store.
//!
//! `basil doctor` (`src/doctor.rs`, basil-f0j) runs a set of independent,
//! read-only preflight checks against a resolved daemon config and emits a
//! versioned `--json` document (`schema_version=1`): a per-check list
//! (`{name, status: ok|warn|fatal, detail, remediation}`) plus a `summary`
//! (`blocking` iff any check is FATAL). Its default mode never unlocks the bundle,
//! binds the socket, or mutates anything (it does NOT write the epoch sidecar).
//! The explicit `--keys` mode unlocks the bundle only to run the authenticated,
//! read-only per-key existence probe.
//!
//! Doctor reads config and probes the backend directly; it never talks to a live
//! broker socket. This test therefore uses `boot_dev_backend` to stand up only a
//! bare provisioned backend plus fixture files, with no `basil agent` process.
//!
//! The OFFLINE unit tests (`src/doctor.rs::tests`) cover most fail/warn arms with
//! temp files + an unreachable `127.0.0.1:1` address. Four OK arms are only
//! reachable against a live, provisioned deployment and so are exercised here:
//!   - **`backend_reachability` → ok**: needs a real dev `bao`/`vault` listening
//!     at the catalog's backend `addr` (the prefill points it at the dev server,
//!     so the unauthenticated `/v1/sys/health` probe succeeds).
//!   - **`backend_binary` → ok**: needs the matching dev backend CLI on `PATH`.
//!   - **`bundle_perms` → ok**: needs a REAL `0600` sealed bundle on disk (the
//!     prefill writes one; the offline test only fabricates a blob).
//!   - **`bundle_freshness` → ok**: needs a real bundle PLUS a matching `.epoch`
//!     sidecar (the real `bundle create` path writes it; the offline test has none,
//!     so it can only reach the "absent sidecar ⇒ warn" arm).
//!
//! `catalog_policy → ok` and `bundle_readable → ok` are also asserted (the live
//! fixtures load + the bundle is present), as is `summary.blocking == false` and
//! process exit code 0.
//!
//! Negative cross-checks pin that the OK arms are not vacuous passes. After
//! `DevBackend::kill_backend()` drops the dev engine but leaves the config +
//! bundle untouched, a second `doctor` run flips
//! `backend_reachability` to `fail`, `summary.blocking` to `true`, and the exit
//! code to nonzero, while the bundle arms stay `ok` (only reachability changed).
//! Doctor's own bounded `REACHABILITY_TIMEOUT` (3s) keeps that run from hanging.
//! Separate bundle mutations make `bundle_freshness` fail on a stale epoch
//! sidecar and `bundle_freshness` fail on corrupt bundle bytes.
//!
//! GATING: each engine leg is independently gated on its CLI (`bao`/`vault`) being
//! on PATH; an absent engine prints an EXPLICIT skip line (acceptance forbids a
//! silent `#[ignore]`). `ran_any` asserts at least one leg ran, so an all-absent
//! environment FAILS loudly rather than passing vacuously. Each leg's `VAULT_ADDR`
//! comes from `basil_tests::alloc_addr()`, which hands out a disjoint port per call /
//! per test binary so the two dev servers (and the concurrently running
//! SPIFFE/reload/health live tests) never collide on a port.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::allow_attributes,
    clippy::indexing_slicing
)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use basil_tests::{DevBackend, Engine, alloc_addr, boot_dev_backend, on_path, repo_root};

/// The schema version doctor's `--json` document pins (`DOCTOR_SCHEMA_VERSION`).
/// Hardcoded here on purpose: this is the scriptable contract an operator gates
/// on, so a bump must break this live test, not be silently tracked.
const EXPECTED_SCHEMA_VERSION: u64 = 2;

/// The parsed outcome of shelling the REAL `basil doctor --config <toml>
/// --json` binary: the process exit code plus the parsed JSON document.
struct DoctorRun {
    exit_code: i32,
    report: serde_json::Value,
}

/// Shell the REAL `basil doctor --config <toml> --json` binary (the one the
/// harness built) against the SAME config the running broker uses, and return its
/// exit code + parsed JSON document. We observe the CLI's PROCESS exit code (not
/// just the in-process report) because that is what an operator/CI gate sees.
fn run_doctor_with_args(config: &Path, extra_args: &[&str]) -> DoctorRun {
    let bin = repo_root().join("target/debug/basil");
    let out = Command::new(&bin)
        .arg("doctor")
        .arg("--config")
        .arg(config)
        .args(extra_args)
        .arg("--json")
        .output()
        .unwrap_or_else(|e| panic!("spawn {} doctor: {e}", bin.display()));
    // `doctor` exits 1 via `process::exit(1)` on a blocking failure, 0 otherwise;
    // a signal kill (no code) maps to -1.
    let exit_code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "doctor --json did not emit a parseable JSON document: {e}\nstdout:\n{stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stderr)
        )
    });
    DoctorRun { exit_code, report }
}

fn run_doctor(config: &Path) -> DoctorRun {
    run_doctor_with_args(config, &[])
}

/// Find the `status` token of the named check in a doctor report, or panic with
/// the whole report if the check row is absent (the row set is stable, so a
/// missing row is a contract regression worth failing loudly on).
fn check_status<'a>(report: &'a serde_json::Value, name: &str) -> &'a str {
    let checks = report["checks"]
        .as_array()
        .unwrap_or_else(|| panic!("doctor report has a `checks` array; got {report}"));
    checks
        .iter()
        .find(|c| c["name"] == serde_json::json!(name))
        .and_then(|c| c["status"].as_str())
        .unwrap_or_else(|| panic!("doctor report has no `{name}` check; got {report}"))
}

fn assert_nonblocking(run: &DoctorRun, name: &str, context: &str) {
    assert_eq!(
        run.report["summary"]["blocking"],
        serde_json::json!(false),
        "[{name}] {context} is non-blocking: {}",
        run.report
    );
    assert_eq!(
        run.exit_code, 0,
        "[{name}] {context} exits 0 on a non-blocking report"
    );
}

fn assert_blocking(run: &DoctorRun, name: &str, failed_arm: &str, context: &str) {
    assert_eq!(
        check_status(&run.report, failed_arm),
        "fatal",
        "[{name}] {context} is fatal on `{failed_arm}`; full report: {}",
        run.report
    );
    assert_eq!(
        run.report["summary"]["blocking"],
        serde_json::json!(true),
        "[{name}] {context} makes the doctor run blocking: {}",
        run.report
    );
    assert_ne!(
        run.exit_code, 0,
        "[{name}] {context} exits nonzero when the report is blocking"
    );
}

fn assert_bundle_arms_ok(run: &DoctorRun, name: &str, context: &str) {
    for arm in ["bundle_readable", "bundle_perms", "bundle_freshness"] {
        assert_eq!(
            check_status(&run.report, arm),
            "ok",
            "[{name}] {context}: bundle arm `{arm}` is ok; full report: {}",
            run.report
        );
    }
}

fn delete_required_transit_key(engine: Engine, addr: &str, key: &str) {
    let config_path = format!("transit/keys/{key}/config");
    let status = Command::new(engine.cli_bin())
        .env("VAULT_ADDR", addr)
        .env("VAULT_TOKEN", DevBackend::ROOT_TOKEN)
        .args(["write", &config_path, "deletion_allowed=true"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap_or_else(|e| panic!("spawn {} write {config_path}: {e}", engine.cli_bin()));
    assert!(
        status.success(),
        "[{}] enable deletion for {key}",
        engine.prefill_name()
    );

    let key_path = format!("transit/keys/{key}");
    let status = Command::new(engine.cli_bin())
        .env("VAULT_ADDR", addr)
        .env("VAULT_TOKEN", DevBackend::ROOT_TOKEN)
        .args(["delete", &key_path])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap_or_else(|e| panic!("spawn {} delete {key_path}: {e}", engine.cli_bin()));
    assert!(
        status.success(),
        "[{}] delete required transit key {key}",
        engine.prefill_name()
    );
}

fn assert_healthy_doctor(run: &DoctorRun, name: &str) {
    assert_eq!(
        run.report["schema_version"].as_u64(),
        Some(EXPECTED_SCHEMA_VERSION),
        "[{name}] doctor --json pins schema_version {EXPECTED_SCHEMA_VERSION}"
    );
    assert_nonblocking(run, name, "healthy live deployment");

    // The live-ONLY OK arms (unreachable offline): a reachable dev backend + a
    // real 0600 sealed bundle + a matching epoch sidecar.
    for arm in [
        "backend_reachability",
        "backend_binary",
        "bundle_readable",
        "bundle_perms",
        "bundle_freshness",
        "catalog_policy",
    ] {
        assert_eq!(
            check_status(&run.report, arm),
            "ok",
            "[{name}] live doctor reports `{arm}` ok; full report: {}",
            run.report
        );
    }
    eprintln!(
        "DOCTOR-OK[{name}]: exit 0, blocking=false, backend_reachability/backend_binary/bundle_readable/\
         bundle_perms/bundle_freshness/catalog_policy all ok"
    );
}

fn assert_required_key_missing_probe(
    engine: Engine,
    backend: &DevBackend,
    config: &Path,
    name: &str,
) {
    let key_probe = run_doctor_with_args(config, &["--keys"]);
    assert_nonblocking(
        &key_probe,
        name,
        "authenticated key-material probe before deletion",
    );
    assert_eq!(
        check_status(&key_probe.report, "key_material"),
        "warn",
        "[{name}] unreconciled generate keys are optional warnings before required deletion: {}",
        key_probe.report
    );

    delete_required_transit_key(engine, backend.addr(), "web-tls");
    let required_missing = run_doctor_with_args(config, &["--keys"]);
    assert_blocking(
        &required_missing,
        name,
        "key_material",
        "required key missing from backend",
    );
    assert_eq!(
        check_status(&required_missing.report, "backend_reachability"),
        "ok",
        "[{name}] deleting required key leaves backend reachability ok: {}",
        required_missing.report
    );
    assert_bundle_arms_ok(
        &required_missing,
        name,
        "required-key-missing authenticated probe",
    );
    eprintln!("DOCTOR-KEY-MISSING[{name}]: key_material=fail, blocking=true");
}

fn epoch_sidecar_path(bundle: &Path) -> PathBuf {
    let mut path = std::ffi::OsString::from(bundle.as_os_str());
    path.push(".epoch");
    PathBuf::from(path)
}

/// Drive one engine through the live doctor contract end to end.
fn drive_engine(engine: Engine, tag: &str, addr: &str) {
    let name = engine.prefill_name();
    let backend = boot_dev_backend(tag, engine, addr);
    let config = backend.config_path();
    let fixtures = backend.fixtures();
    let bundle = fixtures.join("bundle.sealed");
    let sidecar = epoch_sidecar_path(&bundle);
    assert!(
        config.is_file(),
        "[{name}] prefill wrote the config doctor reads: {}",
        config.display()
    );
    assert!(
        bundle.is_file(),
        "[{name}] prefill wrote the bundle doctor reads: {}",
        bundle.display()
    );
    assert!(
        sidecar.is_file(),
        "[{name}] bundle create wrote the epoch sidecar doctor reads: {}",
        sidecar.display()
    );

    // --- happy path: reachable backend + real sealed bundle + epoch sidecar. ---
    let healthy = run_doctor(&config);
    assert_healthy_doctor(&healthy, name);

    // --- authenticated negative: doctor --keys must catch a real required
    //     catalog key that is absent from the live backend. This is opt-in because
    //     it crosses the default doctor's secret-free/no-unlock boundary.
    assert_required_key_missing_probe(engine, &backend, &config, name);

    // --- negative: stale sidecar must block without needing a broker. ---
    let original_sidecar = fs::read(&sidecar).expect("read epoch sidecar before stale mutation");
    fs::write(&sidecar, b"999\n").expect("write stale epoch sidecar");
    let stale = run_doctor(&config);
    assert_blocking(&stale, name, "bundle_freshness", "stale bundle sidecar");
    assert_eq!(
        check_status(&stale.report, "bundle_readable"),
        "ok",
        "[{name}] stale sidecar leaves bundle_readable ok: {}",
        stale.report
    );
    assert_eq!(
        check_status(&stale.report, "bundle_perms"),
        "ok",
        "[{name}] stale sidecar leaves bundle_perms ok: {}",
        stale.report
    );
    fs::write(&sidecar, original_sidecar).expect("restore epoch sidecar");
    eprintln!("DOCTOR-STALE[{name}]: bundle_freshness=fail, blocking=true");

    // --- negative: corrupt bundle bytes must block, while the backend is still up. ---
    let original_bundle = fs::read(&bundle).expect("read sealed bundle before corrupt mutation");
    fs::write(&bundle, b"not a basil sealed bundle\n").expect("write corrupt sealed bundle");
    let corrupt = run_doctor(&config);
    assert_blocking(&corrupt, name, "bundle_freshness", "corrupt sealed bundle");
    assert_eq!(
        check_status(&corrupt.report, "bundle_readable"),
        "ok",
        "[{name}] corrupt bundle is still readable as bytes: {}",
        corrupt.report
    );
    fs::write(&bundle, original_bundle).expect("restore sealed bundle");
    eprintln!("DOCTOR-CORRUPT[{name}]: bundle_freshness=fail, blocking=true");

    // --- negative cross-check: kill the backend (broker + bundle untouched) and
    //     prove the reachability OK arm was REALLY live, it must now FAIL, flip
    //     the summary to blocking, and exit nonzero. Doctor's bounded 3s
    //     REACHABILITY_TIMEOUT keeps this from hanging on the now-dead address.
    let backend_pid = backend
        .dev_server_pid()
        .expect("dev backend pid available before kill");
    backend.kill_backend();
    eprintln!("KILL[{name}]: killed dev backend pid {backend_pid}; fixtures left in place");

    let down = run_doctor(&config);
    assert_blocking(
        &down,
        name,
        "backend_reachability",
        "backend-down live probe",
    );
    // The bundle arms are independent of backend reachability: they must STILL be
    // ok (only the reachability arm changed), confirming the kill is surgical.
    assert_bundle_arms_ok(&down, name, "backend-down live probe");
    eprintln!(
        "DOCTOR-DOWN[{name}]: exit {} (backend_reachability=fail, blocking=true), bundle arms \
         still ok",
        down.exit_code
    );

    drop(backend);
}

#[test]
fn doctor_happy_path_cross_engine() {
    let ran_bao = if on_path("bao") {
        drive_engine(Engine::OpenBao, "doctor-bao", &alloc_addr());
        true
    } else {
        eprintln!("SKIP: bao not found on PATH; live doctor happy-path e2e needs a dev OpenBao");
        false
    };

    let ran_vault = if on_path("vault") {
        drive_engine(Engine::Vault, "doctor-vault", &alloc_addr());
        true
    } else {
        eprintln!("SKIP: vault not found on PATH; live doctor happy-path e2e needs a dev Vault");
        false
    };

    assert!(
        ran_bao || ran_vault,
        "neither bao nor vault was on PATH; the live doctor happy-path e2e ran no engine leg \
         (this is a live cross-engine acceptance test; it must not pass vacuously)"
    );
}
