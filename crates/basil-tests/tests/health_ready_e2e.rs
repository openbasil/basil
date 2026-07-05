// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Cross-engine LIVE e2e for the **`basil health` / `basil ready` exit-code +
//! `--json` contract** (`basil-mil0.6`) over a dev `OpenBao` AND a dev `Vault`
//! store.
//!
//! Basil exposes two ungated admin probes over the broker unix socket:
//!   - **Health (liveness)**: is the broker *process* up and serving the
//!     socket? Does NO backend I/O. `basil health` exits 0 while the daemon
//!     answers; `--json` emits `{"alive":true,"version":...}`.
//!   - **Readiness**: can the broker actually *serve*? It runs a read-only
//!     existence probe over every catalog key (one metadata/KV read per key) and
//!     reduces it to a non-secret summary: a coarse `reason`
//!     (`ready` / `backend_unreachable` / `required_key_missing`), the active
//!     generation id, and key counts. `basil ready` exits 0 when ready, 1 when
//!     not ready; `--json` emits the summary.
//!
//! The CLI maps these onto process EXIT CODES orchestrators gate on (systemd
//! `ExecStartPost`, container `HEALTHCHECK`, k8s `exec` readiness). The exit-code
//! mapping + `--json` field set are unit-tested in `basil-bin`
//! (`tests::ready_*`/`reload_*`/`health_json_*`), without a server. THIS file is
//! the LIVE half: it shells the REAL `basil` CLI against a live broker and
//! asserts the exit codes + parsed `--json` end to end, including the
//! security/ops-relevant **health-vs-readiness distinction under backend loss**.
//!
//! Per engine, it asserts:
//!   1. **Liveness:** `basil health` → exit 0; `--json` parses with
//!      `alive == true` (liveness is up while the process serves, independent of
//!      the backend).
//!   2. **Ready (healthy):** `basil ready` → exit 0; `--json` state `READY`,
//!      `keys_present == keys_total`, the active generation id present (> 0).
//!   3. **Not-ready (backend down):** KILL the dev `bao`/`vault` backend mid-run
//!      (`Harness::kill_backend`, leaving the broker UP), WAIT OUT the ~2s
//!      readiness TTL cache (`READINESS_CACHE_TTL`, after the backend dies the
//!      broker may still serve the CACHED ready result for up to that window), and
//!      poll `basil ready` until it exits NONZERO with `--json` state
//!      `BACKEND_UNREACHABLE`. Meanwhile `basil health` STILL exits 0: liveness
//!      is unaffected by backend loss. This is the contract orchestrators gate on:
//!      don't restart-loop the broker (alive) on a transient backend blip; do
//!      pull it out of rotation (not ready).
//!
//! GATING: each engine leg is independently gated on its CLI (`bao`/`vault`)
//! being on PATH; an absent engine prints an EXPLICIT skip line (acceptance
//! forbids a silent `#[ignore]`). `ran_any` asserts at least one leg ran, so an
//! all-absent environment FAILS loudly rather than passing vacuously. Each leg's
//! `VAULT_ADDR` comes from `basil_tests::alloc_addr()`, which hands out a disjoint
//! port per call / per test binary so the two dev servers (and the concurrently
//! running SPIFFE/reload live tests) never collide on a port.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::allow_attributes,
    clippy::indexing_slicing
)]

use std::process::Command;
use std::time::{Duration, Instant};

use basil_tests::{Engine, alloc_addr, boot_basil, on_path, repo_root};

/// Bound on how long we poll `basil ready` for the not-ready transition after
/// killing the backend. Must comfortably exceed the broker's 2s readiness TTL
/// cache (`core/state.rs::READINESS_CACHE_TTL`): after the backend dies the
/// broker keeps serving the CACHED ready outcome until the window expires, so a
/// not-ready assertion must wait it out, not race it.
const NOT_READY_POLL: Duration = Duration::from_secs(15);
const POLL_TICK: Duration = Duration::from_millis(250);

/// The parsed outcome of shelling the REAL `basil <cmd> --json` CLI: the process
/// exit code plus the parsed JSON object the CLI printed (empty on a
/// connect/parse miss, the exit-code assertions still hold).
struct CliProbe {
    exit_code: i32,
    json: serde_json::Value,
}

/// Shell the REAL `basil <cmd> --json` CLI binary (the one prefill builds at
/// `target/debug/basil`) against the broker socket; return its exit code + parsed
/// JSON. This is the scriptable contract the ticket pins: we observe the CLI's
/// process exit code (not just the RPC), the same thing a systemd/k8s probe sees.
fn basil_probe(socket: &str, cmd: &str) -> CliProbe {
    let cli = repo_root().join("target/debug/basil");
    let out = Command::new(&cli)
        .args(["--socket", socket, cmd, "--json"])
        .output()
        .unwrap_or_else(|e| panic!("spawn {} {cmd}: {e}", cli.display()));
    // The probe binaries that exit NONZERO (a not-ready `basil ready`) do so via
    // `process::exit(1)`; a missing exit code (signal kill) maps to -1.
    let exit_code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout);
    // `health`/`ready` print exactly one JSON object line; on a connect failure
    // there's no stdout JSON (only stderr) and the object is Null; the caller's
    // exit-code assertion is what matters there.
    let json = stdout
        .lines()
        .rev()
        .find(|l| l.trim_start().starts_with('{'))
        .and_then(|line| serde_json::from_str(line).ok())
        .unwrap_or(serde_json::Value::Null);
    CliProbe { exit_code, json }
}

/// Drive one engine end to end through the health/readiness exit-code contract.
async fn drive_engine(engine: Engine, tag: &str, addr: &str) {
    let name = engine.prefill_name();
    let harness = boot_basil(tag, engine, addr);
    let socket = harness.socket();
    let socket_str = socket.to_str().expect("socket path is UTF-8").to_string();

    // 1. Liveness up + 2. Ready (healthy) while the backend is reachable.
    assert_healthy(&socket_str, name);
    assert_ready(&socket_str, name);

    // 3. Kill the backend mid-run (broker left UP), wait out the readiness TTL,
    //    then `basil ready` goes not-ready (BACKEND_UNREACHABLE) while `basil
    //    health` STILL exits 0, the liveness-vs-readiness distinction.
    let backend_pid = harness
        .dev_server_pid()
        .expect("dev backend pid available before kill");
    harness.kill_backend();
    eprintln!("KILL[{name}]: killed dev backend pid {backend_pid}; broker left up");
    assert_not_ready_after_kill(&socket_str, name).await;
    assert_healthy_after_kill(&socket_str, name);

    drop(harness);
}

/// Assert `basil health` exits 0 and reports `alive == true` (liveness is up
/// while the process serves the socket, independent of any backend I/O).
fn assert_healthy(socket: &str, name: &str) {
    let h = basil_probe(socket, "health");
    assert_eq!(h.exit_code, 0, "[{name}] basil health exits 0 while alive");
    assert_eq!(
        h.json["alive"],
        serde_json::json!(true),
        "[{name}] basil health --json reports alive=true"
    );
    eprintln!(
        "HEALTH[{name}]: basil health exit 0, alive={}",
        h.json["alive"]
    );
}

/// Assert `basil ready` exits 0 with state READY: no required key missing, the
/// counts partition `keys_total`, and the active generation id is present.
fn assert_ready(socket: &str, name: &str) {
    let r = basil_probe(socket, "ready");
    assert_eq!(r.exit_code, 0, "[{name}] basil ready exits 0 when ready");
    assert_eq!(
        r.json["ready"],
        serde_json::json!(true),
        "[{name}] basil ready --json reports ready=true"
    );
    assert_eq!(
        r.json["reason"],
        serde_json::json!("ready"),
        "[{name}] basil ready --json reason is the READY token"
    );
    let total = r.json["keys_total"]
        .as_u64()
        .expect("keys_total is a number");
    let present = r.json["keys_present"]
        .as_u64()
        .expect("keys_present is a number");
    let required_missing = r.json["keys_required_missing"]
        .as_u64()
        .expect("keys_required_missing is a number");
    let optional_missing = r.json["keys_optional_missing"]
        .as_u64()
        .expect("keys_optional_missing is a number");
    assert!(total > 0, "[{name}] catalog has at least one probed key");
    // READY is gated on ZERO `missing=error` keys absent, that's what makes the
    // broker serve without failing closed. `present == total` only when there are
    // also no OPTIONAL-missing (`warn`/`generate`) keys; the prefill catalog has
    // some, and those don't block readiness. So the READY invariant is:
    // required_missing == 0 AND the counts partition total.
    assert_eq!(
        required_missing, 0,
        "[{name}] a READY broker has no required (missing=error) key absent"
    );
    assert_eq!(
        present + required_missing + optional_missing,
        total,
        "[{name}] the readiness counts partition keys_total (present + required + optional missing)"
    );
    let generation = r.json["generation"]
        .as_u64()
        .expect("generation is a number");
    assert!(
        generation >= 1,
        "[{name}] the active generation id is present (>=1), saw {generation}"
    );
    eprintln!(
        "READY[{name}]: basil ready exit 0, state=ready, present={present}/{total} \
         (required_missing={required_missing}, optional_missing={optional_missing}), \
         gen={generation}"
    );
}

/// Poll `basil ready` until it exits NONZERO with state `BACKEND_UNREACHABLE`,
/// or fail after [`NOT_READY_POLL`]. The broker's 2s readiness TTL means it may
/// keep returning the CACHED ready outcome for up to that window after the
/// backend dies, so we WAIT IT OUT with a bounded deadline rather than asserting
/// on a single (possibly cached-ready) read.
async fn assert_not_ready_after_kill(socket: &str, name: &str) {
    let deadline = Instant::now() + NOT_READY_POLL;
    let not_ready = loop {
        let probe = basil_probe(socket, "ready");
        if probe.exit_code != 0 {
            break probe;
        }
        assert!(
            Instant::now() < deadline,
            "[{name}] basil ready never went not-ready within {NOT_READY_POLL:?} after the \
             backend was killed (TTL is ~2s; last state was still ready)"
        );
        tokio::time::sleep(POLL_TICK).await;
    };
    assert_ne!(
        not_ready.exit_code, 0,
        "[{name}] basil ready exits nonzero when the backend is down"
    );
    assert_eq!(
        not_ready.json["ready"],
        serde_json::json!(false),
        "[{name}] basil ready --json reports ready=false with the backend down"
    );
    assert_eq!(
        not_ready.json["reason"],
        serde_json::json!("backend_unreachable"),
        "[{name}] a down backend surfaces as the BACKEND_UNREACHABLE reason token"
    );
    eprintln!(
        "NOT-READY[{name}]: basil ready exit {} (state=backend_unreachable) after backend kill",
        not_ready.exit_code
    );
}

/// Assert `basil health` STILL exits 0 with `alive == true` AFTER the backend
/// was killed: liveness is unaffected by backend loss (the broker process is up
/// and serving the socket). This is the whole point of the health/readiness
/// split: an orchestrator must NOT restart-loop the broker on a transient
/// backend blip; only pull it out of rotation (not ready).
fn assert_healthy_after_kill(socket: &str, name: &str) {
    let h = basil_probe(socket, "health");
    assert_eq!(
        h.exit_code, 0,
        "[{name}] basil health STILL exits 0 with the backend down (liveness != readiness)"
    );
    assert_eq!(
        h.json["alive"],
        serde_json::json!(true),
        "[{name}] basil health --json still reports alive=true with the backend down"
    );
    eprintln!(
        "HEALTH-AFTER-KILL[{name}]: basil health STILL exit 0, alive={} (liveness unaffected)",
        h.json["alive"]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_ready_exit_codes_cross_engine() {
    let ran_bao = if on_path("bao") {
        drive_engine(Engine::OpenBao, "healthready-bao", &alloc_addr()).await;
        true
    } else {
        eprintln!("SKIP: bao not found on PATH; health/readiness e2e needs a live OpenBao");
        false
    };

    let ran_vault = if on_path("vault") {
        drive_engine(Engine::Vault, "healthready-vault", &alloc_addr()).await;
        true
    } else {
        eprintln!("SKIP: vault not found on PATH; health/readiness e2e needs a live Vault");
        false
    };

    assert!(
        ran_bao || ran_vault,
        "neither bao nor vault was on PATH; the health/readiness live e2e ran no engine leg \
         (this is a live cross-engine acceptance test; it must not pass vacuously)"
    );
}
