// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Cross-engine LIVE e2e for the **SIGHUP hot-reload signal path** (`basil-y3e`,
//! `basil-mil0.4`) over a dev `OpenBao` AND a dev `Vault` store.
//!
//! Production reloads the catalog/policy WITHOUT a restart or re-unseal: the
//! operator (or the Nix module's `reload` action) sends `SIGHUP`, the agent's
//! `spawn_sighup_handler` runs the shared `reload_generation` engine, which
//! re-reads the configured on-disk catalog/policy, runs the full startup/`check`
//! validation + the restart-only routing-shape guard, and, only on success,
//! atomically swaps in a new `Generation` with a bumped id. On any failure it
//! does NOT swap: the previous generation keeps serving (fail closed) and the
//! broker never panics or exits.
//!
//! The reload *engine* (`core/reload.rs::reload_generation`) is unit-tested, but
//! the SIGHUP *signal entry point* that triggers it in production
//! (`main.rs::spawn_sighup_handler` → `handle_sighup_reload`) had NO test. THIS
//! file is that coverage: it drives the real signal against a live broker and
//! observes the swap through the ungated admin `Readiness` RPC's `generation`
//! field (`basil::Client::readiness().generation`, the same value
//! `basil ready --json` prints).
//!
//! Per engine, driving the `basil` client over the broker's unix socket, it
//! asserts:
//!   1. The initial serving generation is `1` (`INITIAL_GENERATION_ID`).
//!   2. **Valid reload** (a NON-LABEL reloadable edit: remove the `test-reader`
//!      policy grant on `app.db_password`): after `kill -HUP`, the generation
//!      BUMPS 1 → 2 (polled with a bounded timeout, the handler is async), the
//!      broker did NOT restart (same pid, same socket, no re-unseal), it still
//!      serves (health alive + readiness ready), and the NEW policy content is in
//!      force: a `get` on `app.db_password` that SUCCEEDED before the reload is
//!      DENIED after it.
//!   3. **Invalid reload** (a restart-only catalog repath): after `kill -HUP`,
//!      the generation is UNCHANGED (the swap was rejected, the prior generation
//!      keeps serving) and the broker is STILL ALIVE and serving: the
//!      no-panic / fail-closed guarantee holds on a bad reload.
//!   4. **Recovery**: restore a valid catalog + a fresh valid policy edit and
//!      SIGHUP again; the generation bumps once more (2 → 3), proving a rejected
//!      reload does not wedge future reloads.
//!
//! We deliberately edit a NON-LABEL reloadable dimension (a policy grant, and for
//! recovery a key `description`): a known-open gap (`basil-zq6w`) leaves the
//! manager's per-key label view stale after a label-only reload, so a
//! label-edit valid leg would test a half-coherent path. A grant/description edit
//! exercises a fully-coherent reloadable swap.
//!
//! A SECOND cross-engine test (`reload_rpc_cli_and_parity_cross_engine`,
//! `basil-mil0.5`/`basil-ftmc`) covers the **gated admin `Reload` RPC** through the
//! real `basil reload [--check]` CLI (shelled for its exit code), plus SIGHUP-vs-RPC
//! parity. The prefill grants the running uid the dedicated `reload` op over the
//! reserved `broker.reload` target (NO data-plane grant implies it), so the CLI
//! drives an authorized reload. Per engine it asserts: a valid `basil reload`
//! applies (exit 0, gen bumps, the printed `ReloadOutcome` shows old→new); a
//! `basil reload --check` is a true dry-run (exit 0, gen UNCHANGED, then a real
//! reload applies); an INVALID on-disk candidate makes BOTH `basil reload` and
//! `basil reload --check` exit NONZERO without swapping while the broker stays alive
//! (the not-silently-exit-0-on-rejection contract); and a SIGHUP reload and an RPC
//! reload BOTH bump the generation and BOTH emit a `basil.audit.reload` JSONL event
//! of identical shape (old→new gen + outcome) differing ONLY in the actor (the
//! `signal`/`SIGHUP` actor vs the `unix_uid` attested caller uid). The unauthorized
//! deny path stays UNIT-tested (`service::admin::tests::
//! unauthorized_caller_is_denied_and_nothing_reloads`): a single peer-cred socket
//! process is one uid and cannot fake a second.
//!
//! GATING: each engine leg is independently gated on its CLI (`bao`/`vault`)
//! being on PATH; an absent engine prints an EXPLICIT skip line (acceptance
//! forbids a silent `#[ignore]`). `ran_any` asserts at least one leg ran, so an
//! all-absent environment FAILS loudly rather than passing vacuously. Each leg's
//! `VAULT_ADDR` comes from `basil_tests::alloc_addr()`, which hands out a disjoint
//! port per call / per test binary so the two dev servers (and the concurrently
//! running SPIFFE live tests) never collide on a port.

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

use basil::Client;

/// The catalog key the prefill provisions as a pre-filled KV-v2 value with a
/// `get`/`list` (reader) grant for the running uid (see
/// `scripts/prefill-test-store.sh`). We flip that grant off across a reload to
/// prove the NEW policy content serves.
const KV_KEY: &str = "app.db_password";

/// How long to wait for the async SIGHUP handler to finish a reload and the swap
/// to become observable on the readiness generation. The handler runs the full
/// validation + an atomic swap (no backend I/O), so this is generous.
const RELOAD_POLL: Duration = Duration::from_secs(10);
const RELOAD_TICK: Duration = Duration::from_millis(100);

/// Read the currently-serving generation id via the ungated admin readiness RPC.
async fn generation(client: &mut Client) -> u64 {
    client
        .readiness()
        .await
        .expect("readiness RPC succeeds")
        .generation
}

/// Poll the readiness generation until it equals `want`, or panic after
/// [`RELOAD_POLL`]. Used to wait out the async SIGHUP handler after a VALID
/// reload (the swap is not synchronous with `kill` returning).
async fn wait_for_generation(client: &mut Client, want: u64, ctx: &str) {
    let deadline = Instant::now() + RELOAD_POLL;
    loop {
        let got = generation(client).await;
        if got == want {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{ctx}: generation never reached {want} within {RELOAD_POLL:?} (last seen {got})"
        );
        tokio::time::sleep(RELOAD_TICK).await;
    }
}

/// Assert the generation stays at `want` for a settle window, used after an
/// INVALID reload, where the (async) handler MUST reject without swapping, so the
/// id must remain pinned. A single read could race ahead of the handler; we hold
/// the assertion across the window so a (buggy) late swap would still be caught.
async fn assert_generation_stays(client: &mut Client, want: u64, ctx: &str) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let got = generation(client).await;
        assert_eq!(
            got, want,
            "{ctx}: generation must stay {want} on a rejected reload (saw {got})"
        );
        if Instant::now() >= deadline {
            return;
        }
        tokio::time::sleep(RELOAD_TICK).await;
    }
}

/// Read the on-disk policy JSON and remove the `test-reader` rule (which grants
/// the running uid `role:reader` (`get`/`list`/`get_public_key`) over
/// [`KV_KEY`]). This is a NON-LABEL reloadable edit: it changes only the policy
/// grant table, never any key's routing shape, so `reload_generation` accepts it
/// and the new generation denies a `get` the old one allowed.
fn remove_reader_grant(policy_path: &std::path::Path) {
    let text = std::fs::read_to_string(policy_path).expect("read policy fixture");
    let mut policy: serde_json::Value = serde_json::from_str(&text).expect("policy is valid JSON");
    let rules = policy
        .get_mut("rules")
        .and_then(serde_json::Value::as_array_mut)
        .expect("policy has a rules array");
    let before = rules.len();
    rules.retain(|r| r.get("id").and_then(serde_json::Value::as_str) != Some("test-reader"));
    assert_eq!(
        rules.len(),
        before - 1,
        "exactly the test-reader rule was removed"
    );
    std::fs::write(
        policy_path,
        serde_json::to_vec_pretty(&policy).expect("reserialize policy"),
    )
    .expect("write edited policy fixture");
}

/// Repath [`KV_KEY`] in the on-disk catalog to a DIFFERENT backend locator. The
/// key's `path` is part of the restart-only routing shape, so `reload_generation`
/// REJECTS this candidate (`RoutingShapeChanged`) and keeps the prior generation
/// serving: the invalid-reload fail-closed path.
fn repath_key(catalog_path: &std::path::Path) {
    let text = std::fs::read_to_string(catalog_path).expect("read catalog fixture");
    let mut catalog: serde_json::Value =
        serde_json::from_str(&text).expect("catalog is valid JSON");
    let key = catalog
        .get_mut("keys")
        .and_then(|k| k.get_mut(KV_KEY))
        .expect("catalog has the kv key");
    let path = key
        .get("path")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .expect("kv key has a path");
    key["path"] = serde_json::Value::String(format!("{path}-repathed-restart-only"));
    std::fs::write(
        catalog_path,
        serde_json::to_vec_pretty(&catalog).expect("reserialize catalog"),
    )
    .expect("write edited catalog fixture");
}

/// Bump a key's `description` in the on-disk catalog: a NON-LABEL reloadable
/// edit (description is reloadable; it is not part of the routing shape). Used as
/// a clean valid edit to prove RECOVERY after a rejected reload.
fn bump_description(catalog_path: &std::path::Path) {
    let text = std::fs::read_to_string(catalog_path).expect("read catalog fixture");
    let mut catalog: serde_json::Value =
        serde_json::from_str(&text).expect("catalog is valid JSON");
    let key = catalog
        .get_mut("keys")
        .and_then(|k| k.get_mut(KV_KEY))
        .expect("catalog has the kv key");
    key["description"] = serde_json::Value::String("reloaded-description (basil-mil0.4)".into());
    std::fs::write(
        catalog_path,
        serde_json::to_vec_pretty(&catalog).expect("reserialize catalog"),
    )
    .expect("write edited catalog fixture");
}

/// Drive one engine end to end through the SIGHUP reload lifecycle.
async fn drive_engine(engine: Engine, tag: &str, addr: &str) {
    let name = engine.prefill_name();
    let harness = boot_basil(tag, engine, addr);
    let socket = harness.socket();
    let socket_str = socket.to_str().expect("socket path is UTF-8");
    let pid_before = harness.agent_pid().expect("agent pid available");

    let mut client = Client::connect(socket_str)
        .await
        .expect("connect basil client to the broker socket");

    // --- 1. initial generation is 1 (INITIAL_GENERATION_ID).
    let gen0 = generation(&mut client).await;
    assert_eq!(gen0, 1, "[{name}] initial serving generation is 1");

    // The reader grant is in force at boot: a get on the pre-filled KV value
    // succeeds. (Content the VALID reload will revoke.)
    let secret_before = client
        .get_secret(KV_KEY, None)
        .await
        .expect("get on app.db_password is granted before the reload");
    assert!(
        !secret_before.value.is_empty(),
        "[{name}] pre-filled KV value is non-empty before reload"
    );

    // --- 2. VALID reload: remove the reader grant on disk, SIGHUP, await bump.
    remove_reader_grant(&harness.policy_path());
    harness.sighup_agent();
    wait_for_generation(&mut client, 2, &format!("[{name}] valid reload")).await;

    // The broker did NOT restart: same pid, same socket, no re-unseal.
    assert_eq!(
        harness.agent_pid(),
        Some(pid_before),
        "[{name}] same agent pid after a hot reload (no restart)"
    );
    assert!(
        socket.exists(),
        "[{name}] the broker socket is still bound after the hot reload"
    );
    // It still serves: health alive + readiness ready.
    assert!(
        client.health().await.expect("health RPC").alive,
        "[{name}] broker reports alive after reload"
    );
    assert!(
        client.readiness().await.expect("readiness RPC").ready,
        "[{name}] broker reports ready after reload"
    );
    // NEW policy content is in force: the get that succeeded above is now DENIED.
    let denied = client
        .get_secret(KV_KEY, None)
        .await
        .expect_err("get on app.db_password is denied after the reader grant was revoked");
    eprintln!("RELOAD[{name}]: gen 1->2 after valid SIGHUP; get now denied: {denied}");

    // --- 3. INVALID reload: restart-only repath on disk, SIGHUP, stays at 2.
    repath_key(&harness.catalog_path());
    harness.sighup_agent();
    assert_generation_stays(&mut client, 2, &format!("[{name}] invalid reload")).await;
    // The broker survived the bad reload (no panic/exit): same pid, still serving.
    assert_eq!(
        harness.agent_pid(),
        Some(pid_before),
        "[{name}] same agent pid after a rejected reload (broker did not die)"
    );
    assert!(
        client
            .health()
            .await
            .expect("health RPC after bad reload")
            .alive,
        "[{name}] broker still alive after a rejected reload"
    );
    eprintln!("RELOAD[{name}]: gen stayed 2 after invalid SIGHUP; broker alive");

    // --- 4. RECOVERY: undo the restart-only repath (restore the ORIGINAL routing
    //         shape) and make a fresh NON-LABEL reloadable edit (a `description`
    //         bump); SIGHUP bumps again, proving a rejection doesn't wedge reloads.
    restore_path(&harness.catalog_path());
    bump_description(&harness.catalog_path());
    harness.sighup_agent();
    wait_for_generation(&mut client, 3, &format!("[{name}] recovery reload")).await;
    assert!(
        client
            .health()
            .await
            .expect("health RPC after recovery")
            .alive,
        "[{name}] broker alive after recovery reload"
    );
    eprintln!("RELOAD[{name}]: gen 2->3 after recovery SIGHUP; broker alive");

    drop(client);
    drop(harness);
}

/// Strip every `-repathed-restart-only` suffix the [`repath_key`] edits appended
/// to [`KV_KEY`]'s `path`, restoring the ORIGINAL routing shape so a following
/// reloadable edit (description bump) is accepted.
fn restore_path(catalog_path: &std::path::Path) {
    let text = std::fs::read_to_string(catalog_path).expect("read catalog fixture");
    let mut catalog: serde_json::Value =
        serde_json::from_str(&text).expect("catalog is valid JSON");
    let key = catalog
        .get_mut("keys")
        .and_then(|k| k.get_mut(KV_KEY))
        .expect("catalog has the kv key");
    let path = key
        .get("path")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .expect("kv key has a path");
    let restored = path.replace("-repathed-restart-only", "");
    key["path"] = serde_json::Value::String(restored);
    std::fs::write(
        catalog_path,
        serde_json::to_vec_pretty(&catalog).expect("reserialize catalog"),
    )
    .expect("write restored catalog fixture");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sighup_hot_reload_cross_engine() {
    let ran_bao = if on_path("bao") {
        drive_engine(Engine::OpenBao, "reload-bao", &alloc_addr()).await;
        true
    } else {
        eprintln!("SKIP: bao not found on PATH; SIGHUP reload e2e needs a live OpenBao");
        false
    };

    let ran_vault = if on_path("vault") {
        drive_engine(Engine::Vault, "reload-vault", &alloc_addr()).await;
        true
    } else {
        eprintln!("SKIP: vault not found on PATH; SIGHUP reload e2e needs a live Vault");
        false
    };

    assert!(
        ran_bao || ran_vault,
        "neither bao nor vault was on PATH; the SIGHUP reload live e2e ran no engine leg \
         (this is a live cross-engine acceptance test; it must not pass vacuously)"
    );
}

// ===========================================================================
// Admin Reload RPC + `basil reload [--check]` CLI + SIGHUP-vs-RPC parity
// (basil-mil0.5, folds in basil-ftmc).
// ===========================================================================

/// Set [`KV_KEY`]'s catalog `description` to `text`: a NON-LABEL reloadable edit
/// (description is reloadable and not part of the routing shape). Distinct from
/// [`bump_description`] so each RPC-test reload makes a fresh, genuinely-changed
/// candidate (a unique description per call) the reload engine accepts.
fn set_description(catalog_path: &std::path::Path, text: &str) {
    let raw = std::fs::read_to_string(catalog_path).expect("read catalog fixture");
    let mut catalog: serde_json::Value = serde_json::from_str(&raw).expect("catalog is valid JSON");
    let key = catalog
        .get_mut("keys")
        .and_then(|k| k.get_mut(KV_KEY))
        .expect("catalog has the kv key");
    key["description"] = serde_json::Value::String(text.to_string());
    std::fs::write(
        catalog_path,
        serde_json::to_vec_pretty(&catalog).expect("reserialize catalog"),
    )
    .expect("write edited catalog fixture");
}

/// The parsed, non-secret outcome the `basil reload [--check] --json` CLI prints.
/// Mirrors the wire `ReloadResponse` fields the CLI surfaces (`basil-atq`).
#[derive(Debug)]
struct CliReload {
    exit_code: i32,
    applied: bool,
    checked: bool,
    previous_generation: u64,
    new_generation: u64,
    rejected: bool,
}

/// Shell the REAL `basil reload [--check] --json` CLI binary against the broker
/// socket and parse its exit code + printed `ReloadOutcome`. This is the
/// exit-code contract the ticket pins: a happy reload exits 0; a rejection /
/// permission-denied exits NONZERO (never a silent exit-0). `--json` keeps the
/// stdout machine-parseable. The binary is the one the prefill builds at
/// `target/debug/basil`.
fn basil_reload(socket: &str, check: bool) -> CliReload {
    let cli = repo_root().join("target/debug/basil");
    let mut cmd = Command::new(&cli);
    cmd.args(["--socket", socket, "reload", "--json"]);
    if check {
        cmd.arg("--check");
    }
    let out = cmd
        .output()
        .unwrap_or_else(|e| panic!("spawn {} reload: {e}", cli.display()));
    let exit_code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout);
    // On exit 0 the CLI prints a JSON object; on a rejection it also prints the
    // object then exits 1; on a connect/permission error it may print only to
    // stderr (no stdout JSON). Parse the LAST JSON-looking stdout line when
    // present; absent it, the empty object's `as_*` accessors all yield the
    // no-swap defaults below (the caller's exit-code assertions still hold).
    let v: serde_json::Value = stdout
        .lines()
        .rev()
        .find(|l| l.trim_start().starts_with('{'))
        .map_or(serde_json::Value::Null, |line| {
            serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("parse `basil reload` json {line:?}: {e}"))
        });
    CliReload {
        exit_code,
        applied: v["applied"].as_bool().unwrap_or(false),
        checked: v["checked"].as_bool().unwrap_or(check),
        previous_generation: v["previous_generation"].as_u64().unwrap_or(0),
        new_generation: v["new_generation"].as_u64().unwrap_or(0),
        // A missing `rejection` field (absent JSON) reads as "rejected": no JSON
        // means no successful apply was reported.
        rejected: v.get("rejection").is_none_or(|r| !r.is_null()),
    }
}

/// Every `basil.audit.reload` event in the broker's JSONL audit file, in order.
/// Returns `[]` if the file does not exist yet (no reload has been audited).
fn read_reload_audit_events(audit_path: &std::path::Path) -> Vec<serde_json::Value> {
    let Ok(body) = std::fs::read_to_string(audit_path) else {
        return Vec::new();
    };
    body.lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v["event"]["kind"] == "basil.audit.reload")
        .collect()
}

/// Poll the broker's audit file until at least `want` `basil.audit.reload` events
/// are present (the writer thread flushes per line, but the append is async to the
/// RPC/SIGHUP returning), or panic after [`RELOAD_POLL`].
fn wait_for_reload_events(
    audit_path: &std::path::Path,
    want: usize,
    ctx: &str,
) -> Vec<serde_json::Value> {
    let deadline = Instant::now() + RELOAD_POLL;
    loop {
        let events = read_reload_audit_events(audit_path);
        if events.len() >= want {
            return events;
        }
        assert!(
            Instant::now() < deadline,
            "{ctx}: audit file never reached {want} basil.audit.reload events within \
             {RELOAD_POLL:?} (saw {})",
            events.len()
        );
        std::thread::sleep(RELOAD_TICK);
    }
}

/// The running uid (`SO_PEERCRED` principal the broker attests + the actor a
/// `basil reload` RPC reload audits under), via `id -u`.
fn running_uid() -> u32 {
    let out = Command::new("id").arg("-u").output().expect("spawn id -u");
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse::<u32>()
        .expect("id -u prints the numeric uid")
}

/// Drive one engine through the admin Reload RPC + CLI exit-code + parity legs.
// One cohesive end-to-end lifecycle (5 sequential reload legs) over a single live
// broker boot; splitting it would scatter the shared client/harness/generation
// state across helpers and obscure the ordered narrative the assertions depend on.
#[allow(clippy::too_many_lines)]
async fn drive_rpc_engine(engine: Engine, tag: &str, addr: &str) {
    let name = engine.prefill_name();
    let harness = boot_basil(tag, engine, addr);
    let socket = harness.socket();
    let socket_str = socket.to_str().expect("socket path is UTF-8").to_string();
    let catalog = harness.catalog_path();
    let audit = harness.audit_log_path();
    let pid_before = harness.agent_pid().expect("agent pid available");

    let mut client = Client::connect(&socket_str)
        .await
        .expect("connect basil client to the broker socket");

    // --- 1. initial generation is 1.
    let gen0 = generation(&mut client).await;
    assert_eq!(gen0, 1, "[{name}] initial serving generation is 1");

    // --- 2. RPC happy path: a valid description edit, `basil reload` applies.
    set_description(&catalog, "rpc-reload-1 (basil-mil0.5)");
    let r = basil_reload(&socket_str, false);
    assert_eq!(
        r.exit_code, 0,
        "[{name}] `basil reload` exits 0 on a valid apply"
    );
    assert!(
        r.applied && !r.checked && !r.rejected,
        "[{name}] reload applied: {r:?}"
    );
    assert_eq!(r.previous_generation, 1, "[{name}] CLI reports old gen 1");
    assert_eq!(r.new_generation, 2, "[{name}] CLI reports new gen 2");
    wait_for_generation(&mut client, 2, &format!("[{name}] rpc reload")).await;
    eprintln!("RELOAD-RPC[{name}]: `basil reload` gen 1->2, exit 0, outcome {r:?}");

    // --- 3. `--check` is a true dry-run: validates, NO swap; then a real reload applies.
    set_description(&catalog, "rpc-check-candidate (basil-mil0.5)");
    let c = basil_reload(&socket_str, true);
    assert_eq!(
        c.exit_code, 0,
        "[{name}] `basil reload --check` exits 0 on a valid candidate"
    );
    assert!(
        c.checked && !c.applied && !c.rejected,
        "[{name}] check validated, no swap: {c:?}"
    );
    // The gen is UNCHANGED by the dry-run (still 2).
    assert_generation_stays(&mut client, 2, &format!("[{name}] --check no swap")).await;
    // Now apply it for real: the SAME candidate now bumps the gen, proving --check
    // was a true dry-run (it did not consume/apply the candidate).
    let a = basil_reload(&socket_str, false);
    assert_eq!(a.exit_code, 0, "[{name}] real reload after --check exits 0");
    assert!(
        a.applied && !a.rejected,
        "[{name}] real reload applies after --check: {a:?}"
    );
    wait_for_generation(&mut client, 3, &format!("[{name}] apply after check")).await;
    eprintln!("RELOAD-RPC[{name}]: --check no-swap (gen stayed 2) then apply gen 2->3");

    // --- 4. Rejection → NONZERO exit, NO swap, broker still alive. Invalid
    //         candidate = a restart-only repath. Tested for BOTH reload and --check.
    repath_key(&catalog);
    let rej = basil_reload(&socket_str, false);
    assert_ne!(
        rej.exit_code, 0,
        "[{name}] `basil reload` exits NONZERO on rejection (not a silent exit-0): {rej:?}"
    );
    assert!(
        rej.rejected && !rej.applied,
        "[{name}] CLI reports the rejection: {rej:?}"
    );
    let rej_check = basil_reload(&socket_str, true);
    assert_ne!(
        rej_check.exit_code, 0,
        "[{name}] `basil reload --check` exits NONZERO on an invalid candidate: {rej_check:?}"
    );
    assert!(
        rej_check.rejected && !rej_check.applied,
        "[{name}] --check reports the rejection: {rej_check:?}"
    );
    // Gen UNCHANGED (still 3) and the broker survived the bad reloads (no panic/exit).
    assert_generation_stays(&mut client, 3, &format!("[{name}] rejected no swap")).await;
    assert_eq!(
        harness.agent_pid(),
        Some(pid_before),
        "[{name}] same agent pid after a rejected reload (broker did not die)"
    );
    assert!(
        client
            .health()
            .await
            .expect("health RPC after rejected reload")
            .alive,
        "[{name}] broker still alive + serving after a rejected reload"
    );
    eprintln!(
        "RELOAD-RPC[{name}]: reject->nonzero exit (reload + --check), gen stayed 3, broker alive"
    );
    // Restore the routing shape so the parity leg's edits are accepted.
    restore_path(&catalog);

    // --- 5. SIGHUP-vs-RPC parity + audit shape (basil-ftmc). A SIGHUP reload and an
    //         RPC reload BOTH bump the gen and BOTH emit a `basil.audit.reload`
    //         event of the SAME shape, differing only in the actor.
    set_description(&catalog, "parity-sighup (basil-ftmc)");
    harness.sighup_agent();
    wait_for_generation(&mut client, 4, &format!("[{name}] parity sighup")).await;

    set_description(&catalog, "parity-rpc (basil-ftmc)");
    let p = basil_reload(&socket_str, false);
    assert_eq!(p.exit_code, 0, "[{name}] parity RPC reload exits 0");
    assert!(p.applied, "[{name}] parity RPC reload applies: {p:?}");
    wait_for_generation(&mut client, 5, &format!("[{name}] parity rpc")).await;

    // Parse the audit JSONL. We expect AT LEAST the two applied reload events from
    // this leg (the file also carries the earlier RPC reloads' lines + per-op authz
    // lines, which read_reload_audit_events filters to reload events only).
    let events = wait_for_reload_events(&audit, 2, &format!("[{name}] parity audit"));
    // The applied 3->4 (SIGHUP) and 4->5 (RPC) events are the parity pair.
    let sighup_ev = events
        .iter()
        .find(|e| {
            e["outcome"] == "applied" && e["previous_generation"] == 3 && e["generation"] == 4
        })
        .unwrap_or_else(|| {
            panic!("[{name}] SIGHUP applied 3->4 reload event present in {events:#?}")
        });
    let rpc_ev = events
        .iter()
        .find(|e| {
            e["outcome"] == "applied" && e["previous_generation"] == 4 && e["generation"] == 5
        })
        .unwrap_or_else(|| panic!("[{name}] RPC applied 4->5 reload event present in {events:#?}"));

    // SAME shape: identical event envelope + outcome; old→new gen present on both.
    assert_eq!(
        sighup_ev["event"], rpc_ev["event"],
        "[{name}] same event envelope"
    );
    assert_eq!(sighup_ev["outcome"], "applied");
    assert_eq!(rpc_ev["outcome"], "applied");
    assert!(
        sighup_ev.get("previous_generation").is_some() && sighup_ev.get("generation").is_some()
    );
    assert!(rpc_ev.get("previous_generation").is_some() && rpc_ev.get("generation").is_some());

    // Differ ONLY in the actor: SIGHUP carries the signal actor; the RPC carries the
    // attested caller uid (unix_uid).
    assert_eq!(
        sighup_ev["actor"]["kind"], "signal",
        "[{name}] SIGHUP actor kind"
    );
    assert_eq!(
        sighup_ev["actor"]["id"], "SIGHUP",
        "[{name}] SIGHUP actor id"
    );
    assert_eq!(
        rpc_ev["actor"]["kind"], "unix_uid",
        "[{name}] RPC actor kind is the attested uid"
    );
    let uid = running_uid();
    assert_eq!(
        rpc_ev["actor"]["id"],
        uid.to_string(),
        "[{name}] RPC reload actor id is the attested running uid"
    );
    assert_ne!(
        sighup_ev["actor"], rpc_ev["actor"],
        "[{name}] only the actor differs"
    );
    eprintln!(
        "RELOAD-PARITY[{name}]: SIGHUP gen 3->4 + RPC gen 4->5 both basil.audit.reload applied; \
         actors signal/SIGHUP vs unix_uid/{uid} (else identical)"
    );

    drop(client);
    drop(harness);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reload_rpc_cli_and_parity_cross_engine() {
    let ran_bao = if on_path("bao") {
        drive_rpc_engine(Engine::OpenBao, "reload-rpc-bao", &alloc_addr()).await;
        true
    } else {
        eprintln!("SKIP: bao not found on PATH; admin reload RPC e2e needs a live OpenBao");
        false
    };

    let ran_vault = if on_path("vault") {
        drive_rpc_engine(Engine::Vault, "reload-rpc-vault", &alloc_addr()).await;
        true
    } else {
        eprintln!("SKIP: vault not found on PATH; admin reload RPC e2e needs a live Vault");
        false
    };

    assert!(
        ran_bao || ran_vault,
        "neither bao nor vault was on PATH; the admin reload RPC live e2e ran no engine leg \
         (this is a live cross-engine acceptance test; it must not pass vacuously)"
    );
}
