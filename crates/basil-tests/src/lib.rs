// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Shared live-harness for the SPIFFE Workload API integration tests.
//!
//! Extracted from `spiffe_interop.rs` (basil-dk5.11) so later test files
//! (`spiffe_wire_compat.rs`, basil-dk5.12) reuse the SAME boot path instead of
//! standing up a second parallel harness. It shells out to
//! `scripts/prefill-test-store.sh` (which boots a dev `bao`, writes the
//! catalog/policy/sealed bundle fixtures, and builds the binaries) and then runs
//! `target/debug/basil run` on a temp unix socket. The default feature set
//! includes `spiffe`, so the Workload API is served on the same socket as the
//! broker.
//!
//! GATING: callers check `on_path("bao")` and print an EXPLICIT skip line if
//! the engine binary is absent (acceptance forbids a silent `#[ignore]` skip).
//!
//! This is test-only harness code. Clippy's `allow-*-in-tests` exemption only
//! covers bodies of `#[test]` fns, not a shared module's free helper functions /
//! `Drop` impl, so the no-panic restriction lints are allowed here at the module
//! root (a failed harness step SHOULD abort the test loudly). Cargo treats only
//! `tests/*.rs` as test targets, so this file lives at `tests/common/mod.rs` and
//! is included via `mod common;`. It is NOT compiled as its own test binary.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::allow_attributes,
    clippy::missing_panics_doc,
    clippy::too_long_first_doc_paragraph,
    dead_code
)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// The trust domain the prefill fixtures configure the SPIFFE issuers for.
pub const TRUST_DOMAIN: &str = "example.org";

/// Dev-server `VAULT_ADDR` port allocation for the live SPIFFE tests.
///
/// Cargo runs each test *binary* in its own process and may run them
/// concurrently, so two boots must never land on the same `127.0.0.1:<port>`
/// or their dev `bao`/`vault` servers collide. Rather than hand-maintained
/// per-(engine,binary) port constants, [`alloc_addr`] hands out
/// `PORT_FLOOR + n * PORT_STRIDE` for a strictly monotonic `n` shared across
/// *all* concurrently-running test binaries in the run, so every boot (in any
/// binary) gets a distinct port.
///
/// **`PORT_STRIDE` is 2 on purpose.** A `bao`/`vault` dev server binds not just
/// its API port `P` but also a **cluster port at `P + 1`** (the server's
/// default `cluster_addr`). With a stride-1 counter, boot A's API port `P` and
/// boot B's API port `P + 1` would clash with A's *cluster* port: the dev
/// server fails with `address already in use` on a port nothing visibly
/// allocated. Stride 2 reserves `P` (API) and `P + 1` (cluster) per boot, so no
/// two boots' API-or-cluster ports ever overlap. (This subtlety is exactly why
/// hand-maintained constants were fragile to extend: a new test had to remember
/// to skip the cluster port too.)
///
/// The counter lives in one file (`PORT_COUNTER_FILE` under the system temp dir)
/// that all test binaries read-increment-write under an exclusive lock-file
/// (`O_CREAT|O_EXCL` spin, no extra deps, portable). This is the issue's
/// preferred "atomic counter from a base" scheme, lifted to a *cross-process*
/// counter so it also separates distinct binaries.
///
/// We deliberately do NOT probe-bind the candidate before returning it: a probe
/// `TcpListener` adds the bind-`:0` TOCTOU the issue warns about and does not
/// even see the cluster-port clash. The monotonic stride-2 counter guarantees no
/// two *live* allocations share a port; because it never re-hands a number
/// within the dense part of a run, a port a prior boot used is not reused while
/// that boot's teardown is still settling.
///
/// The window is `PORT_FLOOR .. PORT_FLOOR + PORT_SLOTS * PORT_STRIDE`
/// (8240..12336), clear of the old literals (8230..8236) and below the
/// ephemeral range (`/proc/sys/net/ipv4/ip_local_port_range` floor is 32768
/// here). The counter persists across runs and wraps within `PORT_SLOTS`, so it
/// never approaches the `u16` ceiling; a run uses only a handful of slots, far
/// fewer than the window.
const PORT_FLOOR: u16 = 8240;
const PORT_STRIDE: u16 = 2;
const PORT_SLOTS: u16 = 2048;
const PORT_COUNTER_FILE: &str = "basil-spiffe-test-portctr";
const PORT_LOCK_FILE: &str = "basil-spiffe-test-portctr.lock";

/// Cross-process cap on dev `bao`/`vault` servers booting/serving at once.
///
/// vf2 closed the PORT-collision (`alloc_addr` stride-2) and BUILD-contention
/// (`ensure_binaries_built` + `--no-build`) axes, but a third remains: cargo runs
/// integration test *binaries* concurrently AND tests *within* a binary
/// concurrently, so with 8 live binaries (some booting 2 engines, one also doing
/// a `go build`/`go run`) a dozen-plus dev servers can try to come up at once.
/// Under that stampede a dev-server/prefill startup loses the race and the boot
/// `assert!` panics. Every test passes in isolation. [`DevServerPermit`] caps the
/// number of dev servers *alive* at once (boot → test → teardown) across ALL test
/// processes via a file-lock counting semaphore, a sibling of the `alloc_addr`
/// port lock: [`DEV_SEM_PERMITS`] permit slots, each its own `O_CREAT|O_EXCL`
/// lock-file with a stale-reclaim, acquired before prefill and released (RAII) at
/// `Harness::drop`. Holding for the whole lifetime is the safest cap; the suite
/// still runs `DEV_SEM_PERMITS` servers in parallel, which is real parallelism
/// without the stampede. Override the bound with `BASIL_TEST_MAX_DEV_SERVERS`.
///
/// The default is 2, not the box's core count: the dominant destabilizer is not
/// raw CPU but the multi-step `--spiffe-boot` prefill (RSA-2048 root CA + signer
/// keygen, dozens of `bao`/`vault` CLI round-trips) racing the `jwks_oidc_e2e`
/// `go run` compile and the live broker processes. The boot helpers retry a
/// failed prefill once on a fresh port, so two dev servers can run concurrently;
/// bump it further on a beefier/dedicated box via `BASIL_TEST_MAX_DEV_SERVERS`.
const DEV_SEM_PERMITS: usize = 2;
const DEV_SEM_ENV: &str = "BASIL_TEST_MAX_DEV_SERVERS";
const DEV_SEM_LOCK_PREFIX: &str = "basil-spiffe-test-devsem";
/// A permit-slot lock older than this is presumed orphaned by a hard-killed test
/// process and is reclaimable, mirroring the `alloc_addr` stale-lock steal. The
/// ceiling is generous: a dev server's whole boot→test→teardown lifetime fits
/// well under it, so a live holder is never wrongly reclaimed.
const DEV_SEM_STALE: Duration = Duration::from_mins(10);

/// RAII: removes its lock file on drop so a panic in the critical section (or a
/// held semaphore permit) still releases the cross-process lock; otherwise the
/// next run would spin to the timeout then steal it as stale. Shared by the
/// `alloc_addr` port-counter lock and the [`DevServerPermit`] semaphore slots.
struct LockFileGuard(PathBuf);
impl Drop for LockFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// A held permit in the cross-process dev-server counting semaphore. Owning one
/// means "this process may have a dev `bao`/`vault` server alive"; dropping it
/// (including on a test panic, since it lives in [`Harness`]) frees the slot for
/// another waiting boot. See [`DEV_SEM_PERMITS`] / [`acquire_dev_server_permit`].
struct DevServerPermit(#[allow(dead_code)] LockFileGuard);

/// Effective permit count: [`DEV_SEM_ENV`] override (clamped to >= 1) else
/// [`DEV_SEM_PERMITS`].
fn dev_sem_permits() -> usize {
    std::env::var(DEV_SEM_ENV)
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .map_or(DEV_SEM_PERMITS, |n| n.max(1))
}

/// Acquire one permit before booting/prefilling a dev server, bounding the number
/// of dev servers alive concurrently across ALL test processes. Each of the N
/// permit slots is its own `O_CREAT|O_EXCL` lock-file in the temp dir; a free slot
/// is one whose file does not yet exist (or whose existing file is older than
/// [`DEV_SEM_STALE`], orphaned by a hard-killed run, reclaimed exactly like the
/// `alloc_addr` stale-lock steal). We sweep all slots, then sleep+retry on a
/// bounded deadline so a never-freeing pool aborts loudly rather than spinning
/// forever. The returned guard releases the slot on drop (RAII, panic-safe).
#[must_use]
fn acquire_dev_server_permit() -> DevServerPermit {
    let dir = std::env::temp_dir();
    let permits = dev_sem_permits();
    // Generous ceiling: a whole engine's boot+test+teardown can take many seconds
    // and up to `permits` of them serialize behind a saturated pool, so allow
    // minutes before declaring the pool wedged.
    let deadline = Instant::now() + Duration::from_mins(5);
    loop {
        for i in 0..permits {
            let slot = dir.join(format!("{DEV_SEM_LOCK_PREFIX}.{i}.lock"));
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&slot)
            {
                Ok(_) => return DevServerPermit(LockFileGuard(slot)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Reclaim an orphaned slot (holder hard-killed before Drop).
                    let stale = std::fs::metadata(&slot)
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|t| t.elapsed().ok())
                        .is_some_and(|age| age > DEV_SEM_STALE);
                    if stale {
                        let _ = std::fs::remove_file(&slot);
                    }
                }
                Err(e) => panic!("open dev-server semaphore slot {}: {e}", slot.display()),
            }
        }
        assert!(
            Instant::now() < deadline,
            "timed out acquiring a dev-server permit ({permits} permits); pool may be \
             wedged by orphaned slots under {}",
            dir.display()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Allocate a process-and-binary-globally unique `http://127.0.0.1:<port>`
/// dev-server address for a live SPIFFE boot, via a temp-dir counter shared by
/// every concurrently-running test binary (see the module-level
/// port-allocation notes). Feed the result straight to [`boot_basil`] /
/// [`boot_basil_spiffe`] as their `addr`.
#[must_use]
pub fn alloc_addr() -> String {
    let dir = std::env::temp_dir();
    let counter = dir.join(PORT_COUNTER_FILE);
    let lock = dir.join(PORT_LOCK_FILE);

    // Acquire the cross-process lock by exclusively creating the lock file; spin
    // briefly if another binary holds it (the critical section is a tiny
    // read-bump-write). A lock older than the timeout is stale (a crashed run
    // that skipped its Drop). Steal it so a stale file can't wedge future runs.
    let deadline = Instant::now() + Duration::from_secs(10);
    let _guard = loop {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock)
        {
            Ok(_) => break LockFileGuard(lock),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let stale = std::fs::metadata(&lock)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.elapsed().ok())
                    .is_some_and(|age| age > Duration::from_secs(10));
                if stale {
                    let _ = std::fs::remove_file(&lock);
                    continue;
                }
                assert!(
                    Instant::now() < deadline,
                    "timed out acquiring SPIFFE test port-counter lock ({})",
                    lock.display()
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => panic!("open port-counter lock {}: {e}", lock.display()),
        }
    };

    // Critical section (lock held; `_guard` releases on scope exit incl. panic).
    // Bump the persisted slot counter, wrapping within `PORT_SLOTS` so the port
    // never overflows `u16`. When the file is absent (clean `/tmp`, first run)
    // seed from the wall-clock so even a wiped counter doesn't restart at the
    // same ports a just-finished run used.
    let prev: u16 = std::fs::read_to_string(&counter)
        .ok()
        .and_then(|s| s.trim().parse::<u16>().ok())
        .unwrap_or_else(|| {
            let secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            u16::try_from(secs % u64::from(PORT_SLOTS)).unwrap_or(0)
        });
    let slot = (prev + 1) % PORT_SLOTS;
    std::fs::write(&counter, slot.to_string()).expect("write SPIFFE test port counter");

    // API port = floor + slot*stride; the engine's cluster port (API+1) lives in
    // the same slot, so the next slot's API port can't collide with it.
    let port = PORT_FLOOR + slot * PORT_STRIDE;
    format!("http://127.0.0.1:{port}")
}

/// Which secrets engine the prefill script and broker boot against. Each live
/// SPIFFE test binary picks an engine plus a unique `VAULT_ADDR` port so cargo
/// can run the binaries concurrently without two dev servers fighting for a
/// port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Engine {
    OpenBao,
    Vault,
}

impl Engine {
    /// The `--engine` value `scripts/prefill-test-store.sh` expects.
    #[must_use]
    pub const fn prefill_name(self) -> &'static str {
        match self {
            Self::OpenBao => "openbao",
            Self::Vault => "vault",
        }
    }

    /// The server CLI binary (`bao`/`vault`) that must be on `PATH` to run live.
    #[must_use]
    pub const fn cli_bin(self) -> &'static str {
        match self {
            Self::OpenBao => "bao",
            Self::Vault => "vault",
        }
    }
}

/// Repo root = two levels up from this crate's manifest dir (`crates/basil-agent`).
#[must_use]
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate manifest dir has a grandparent (repo root)")
        .to_path_buf()
}

/// True if `bin` is an executable file on `PATH` (the live-engine gate).
#[must_use]
pub fn on_path(bin: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|dir| dir.join(bin).is_file()))
}

/// Build the unified `basil` binary the live harness runs, **once per test
/// process**, then drive every prefill with `--no-build`. Every live broker is
/// PQC-capable; classical ops are unaffected.
///
/// Building once here, up front, removes cargo artifact contention across
/// concurrent live test binaries.
fn ensure_binaries_built(root: &Path) {
    use std::sync::OnceLock;
    static BUILT: OnceLock<()> = OnceLock::new();
    BUILT.get_or_init(|| {
        let mut args = vec!["build", "-p", "basil-bin"];
        if cfg!(feature = "http") {
            args.extend(["--features", "http"]);
        }
        let status = Command::new("cargo")
            .args(args)
            .current_dir(root)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("spawn cargo build for live-harness binaries");
        assert!(
            status.success(),
            "cargo build for live-harness binaries failed"
        );
    });
}

/// Install the process-wide pure-Rust `ring` rustls `CryptoProvider` exactly once.
///
/// `reqwest` is compiled workspace-wide with `rustls-no-provider` (its `rustls`
/// feature would pull the forbidden `aws-lc-rs` C toolchain), so building any
/// `reqwest` client (even for a plain `http` URL) panics unless a default
/// provider is already installed. The daemon does this via `basil-core`'s own
/// `ensure_crypto_provider`, but the live tests build `reqwest` clients in their
/// own process, which never runs that path. Every `boot_*` entrypoint calls this
/// first, so a later HTTP poll (Envoy admin, JWKS, OIDC discovery) just works. A
/// prior install by another component is left untouched (the returned `Err` only
/// signals that a provider was already set).
pub fn ensure_crypto_provider() {
    use std::sync::Once;
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

const PREFILL_ATTEMPTS: usize = 2;

#[derive(Clone, Copy)]
enum PrefillMode {
    Standard,
    SpiffeBoot,
}

impl PrefillMode {
    const fn label(self) -> &'static str {
        match self {
            Self::Standard => "prefill-test-store.sh",
            Self::SpiffeBoot => "prefill-test-store.sh --spiffe-boot",
        }
    }
}

fn run_prefill(
    root: &Path,
    workdir: &Path,
    engine: Engine,
    addr: &str,
    mode: PrefillMode,
) -> std::process::ExitStatus {
    let prefill = root.join("scripts/prefill-test-store.sh");
    let mut cmd = Command::new("bash");
    cmd.arg(&prefill)
        .args(["--engine", engine.prefill_name()])
        .arg("--workdir")
        .arg(workdir)
        .args(["--addr", addr]);
    if matches!(mode, PrefillMode::SpiffeBoot) {
        cmd.arg("--spiffe-boot");
    }
    cmd.arg("--no-build")
        .env("PREFILL_WORKDIR", workdir)
        .env("VAULT_ADDR", addr)
        .env("PREFILL_TOKEN", "root")
        .env("BASIL_TEST_ENGINE", engine.prefill_name())
        .current_dir(root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap_or_else(|e| panic!("spawn {}: {e}", mode.label()))
}

fn cleanup_prefill_workdir(workdir: &Path) {
    let pidfile = workdir.join("server.pid");
    if let Ok(pid_txt) = std::fs::read_to_string(&pidfile)
        && let Ok(pid) = pid_txt.trim().parse::<i32>()
    {
        #[cfg(unix)]
        reap_dev_server(pid);
    }
    let _ = std::fs::remove_dir_all(workdir);
}

fn prefill_with_retry(
    root: &Path,
    tag: &str,
    engine: Engine,
    initial_addr: &str,
    mode: PrefillMode,
) -> (PathBuf, String) {
    let workdir = std::env::temp_dir().join(format!("sv-{tag}.{}", std::process::id()));
    let mut addr = initial_addr.to_string();
    for attempt in 1..=PREFILL_ATTEMPTS {
        cleanup_prefill_workdir(&workdir);
        std::fs::create_dir_all(&workdir).expect("create prefill workdir");

        let status = run_prefill(root, &workdir, engine, &addr, mode);
        if status.success() {
            return (workdir, addr);
        }

        cleanup_prefill_workdir(&workdir);
        if attempt < PREFILL_ATTEMPTS {
            let next_addr = alloc_addr();
            eprintln!(
                "{} failed on attempt {attempt}/{PREFILL_ATTEMPTS} for {} at {addr}; \
                 retrying on {next_addr}",
                mode.label(),
                engine.prefill_name()
            );
            addr = next_addr;
        }
    }

    panic!(
        "{} failed after {PREFILL_ATTEMPTS} attempts (workdir {})",
        mode.label(),
        workdir.display()
    );
}

/// Robust teardown: SIGINT the agent + the prefill dev server, remove temp dirs.
/// Drops regardless of assertion outcome so we never leak processes/sockets.
pub struct Harness {
    workdir: PathBuf,
    agent: Option<Child>,
    server_pidfile: PathBuf,
    backend_addr: String,
    /// Cross-process dev-server semaphore permit, held for the dev server's whole
    /// lifetime (acquired before prefill, released here at teardown). Bounds the
    /// number of dev `bao`/`vault` servers alive concurrently across all test
    /// processes. See [`acquire_dev_server_permit`]. Released on Drop AFTER the
    /// dev server is reaped below so a freed permit really means a freed server.
    _dev_permit: DevServerPermit,
}

impl Harness {
    #[must_use]
    pub fn fixtures(&self) -> PathBuf {
        self.workdir.join("fixtures")
    }
    #[must_use]
    pub fn socket(&self) -> PathBuf {
        self.workdir.join("agent.sock")
    }
    /// The standard SPIFFE endpoint string a workload puts in
    /// `SPIFFE_ENDPOINT_SOCKET`; pass it to `connect_to` directly.
    #[must_use]
    pub fn endpoint(&self) -> String {
        format!("unix:{}", self.socket().display())
    }
    /// The actual dev backend address used by this boot. This may differ from
    /// the caller's requested address if the prefill retry path had to move to a
    /// fresh port after a transient boot failure.
    #[must_use]
    pub fn backend_addr(&self) -> &str {
        &self.backend_addr
    }
    /// The on-disk catalog JSON path the running broker reloads from (`basil-y3e`).
    /// This is the SAME file the boot TOML's `catalog = ...` points at, so editing
    /// it and then `SIGHUP`-ing the agent drives a real hot reload. Used by the
    /// live SIGHUP reload e2e (`reload_e2e`, basil-mil0.4).
    #[must_use]
    pub fn catalog_path(&self) -> PathBuf {
        self.fixtures().join("catalog.json")
    }
    /// The on-disk policy JSON path the running broker reloads from (`basil-y3e`).
    /// The SAME file the boot TOML's `policy = ...` points at (see
    /// [`Harness::catalog_path`]).
    #[must_use]
    pub fn policy_path(&self) -> PathBuf {
        self.fixtures().join("policy.json")
    }
    /// The JSONL audit-log path the broker is booted with (`basil-mil0.5`,
    /// `basil-ftmc`). `boot_basil` writes `audit-log = <this>` into the agent
    /// config, so a reload (SIGHUP or RPC) appends a `basil.audit.reload` line here
    /// the reload e2e parses for the parity + audit-shape assertion. The file may
    /// not exist until the first audited event lands.
    #[must_use]
    pub fn audit_log_path(&self) -> PathBuf {
        self.fixtures().join("audit.jsonl")
    }
    /// The agent config TOML path the broker was booted with (`--config <this>`).
    /// `basil doctor --config <this>` resolves the SAME catalog/policy/bundle/
    /// socket the running broker uses, so a live `doctor` run sees the real
    /// reachable backend + sealed bundle + epoch sidecar. Used by the live doctor
    /// happy-path e2e (`doctor_e2e`, basil-xpeh). NOTE: doctor reads the backend
    /// `addr` from the catalog (which the prefill points at the dev server), so no
    /// `--vault-addr` override is needed for the reachability check to hit the live
    /// engine.
    #[must_use]
    pub fn config_path(&self) -> PathBuf {
        self.workdir.join("basil-agent.toml")
    }

    /// The OS process id of the running `basil-agent`, for `kill -HUP <pid>`
    /// (the production reload trigger). `None` if the agent child is gone.
    #[must_use]
    pub fn agent_pid(&self) -> Option<i32> {
        self.agent.as_ref().map(|c| c.id().cast_signed())
    }
    /// Send `SIGHUP` to the running `basil-agent` (the operator's hot-reload
    /// trigger), shelling out to `kill -HUP <pid>` so the test stays
    /// `unsafe`-free (no libc `raise`). Panics if the agent child is gone; a
    /// caller must hold a live boot. Returns once `kill` exits; the broker's
    /// async handler then runs the reload, so callers POLL the readiness
    /// generation rather than assume the swap landed synchronously.
    #[cfg(unix)]
    pub fn sighup_agent(&self) {
        let pid = self.agent_pid().expect("agent is running for SIGHUP");
        signal(pid, "-HUP");
    }

    /// The OS process id of the prefill's dev `bao`/`vault` backend (read fresh
    /// from the pidfile the prefill writes). `None` if the pidfile is missing or
    /// unparsable. Distinct from [`Harness::agent_pid`]: this is the BACKEND
    /// process, not the broker.
    #[must_use]
    pub fn dev_server_pid(&self) -> Option<i32> {
        std::fs::read_to_string(&self.server_pidfile)
            .ok()
            .and_then(|txt| txt.trim().parse::<i32>().ok())
    }

    /// Kill JUST the dev `bao`/`vault` backend mid-run, leaving the `basil-agent`
    /// broker UP. Used by the health/readiness e2e (`basil-mil0.6`) to drive a
    /// `BACKEND_UNREACHABLE` readiness while the broker keeps serving (so liveness
    /// stays exit-0, the health-vs-readiness distinction). Reuses the same shell
    /// `kill` path as [`reap_dev_server`] (SIGINT, then SIGKILL backstop; dev
    /// servers ignore SIGTERM) so the test stays `unsafe`-free. Returns once the
    /// backend is confirmed gone; the broker's Drop still no-ops on the
    /// already-dead pidfile. Panics only if there is no dev-server pid to kill (a
    /// caller must hold a live boot). NOTE: the broker's readiness TTL cache
    /// (`READINESS_CACHE_TTL`, 2s) may still report the CACHED ready result for up
    /// to that window AFTER this returns; a not-ready assertion must wait it out.
    #[cfg(unix)]
    pub fn kill_backend(&self) {
        let pid = self
            .dev_server_pid()
            .expect("dev backend pid available to kill");
        reap_dev_server(pid);
    }
}

#[cfg(unix)]
fn signal(pid: i32, sig: &str) {
    let _ = Command::new("kill").arg(sig).arg(pid.to_string()).status();
}

/// True while `pid` is still a live process (`kill -0` succeeds).
#[cfg(unix)]
fn alive(pid: i32) -> bool {
    Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .status()
        .is_ok_and(|s| s.success())
}

/// Bulletproof stop of the prefill dev server by pid: SIGINT (dev servers ignore
/// SIGTERM), wait for exit, then SIGKILL as a backstop and wait again. Without
/// this the dev server can outlive `Harness::drop` and keep holding its listen
/// port, which a later test's freshly-allocated port could collide with.
#[cfg(unix)]
fn reap_dev_server(pid: i32) {
    signal(pid, "-INT");
    for _ in 0..50 {
        if !alive(pid) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    signal(pid, "-KILL");
    for _ in 0..20 {
        if !alive(pid) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(mut child) = self.agent.take() {
            #[cfg(unix)]
            signal(child.id().cast_signed(), "-INT");
            // Give it a moment to drain, then hard-kill as a backstop.
            for _ in 0..30 {
                if matches!(child.try_wait(), Ok(Some(_))) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Ok(pid_txt) = std::fs::read_to_string(&self.server_pidfile)
            && let Ok(pid) = pid_txt.trim().parse::<i32>()
        {
            #[cfg(unix)]
            reap_dev_server(pid);
        }
        let _ = std::fs::remove_dir_all(&self.workdir);
    }
}

/// A bare dev `bao`/`vault` server (transit + kv-v2 enabled) with **no** broker
/// attached, for tests that drive a broker they stand up THEMSELVES against a
/// live backend (e.g. the `basil init` → `bundle create` → `run` onboarding
/// e2e, basil-mil0.7). [`boot_dev_backend`] reuses the prefill script's
/// server-boot + engine-enable path (so it goes through the SAME dev-server
/// concurrency semaphore + port allocation as [`boot_basil`]) but ignores the
/// prefill's catalog/policy/bundle fixtures; the caller's own `init` scaffold
/// supplies those. The dev server is reaped (SIGINT→SIGKILL) and its workdir
/// removed on Drop, and the held dev-server permit released, exactly as
/// [`Harness`] does.
pub struct DevBackend {
    workdir: PathBuf,
    server_pidfile: PathBuf,
    /// `http://127.0.0.1:<port>` the dev server listens on (the `addr` passed in).
    addr: String,
    /// Dev-server semaphore permit, held for the server's whole lifetime and
    /// released on Drop AFTER the server is reaped (see [`acquire_dev_server_permit`]).
    _dev_permit: DevServerPermit,
}

impl DevBackend {
    /// The dev server's root token (the prefill's `-dev-root-token-id`). Use it as
    /// the `bundle create --backend id=<backend>,…,token-file=<this>` credential.
    pub const ROOT_TOKEN: &'static str = "root";

    /// The prefill fixture directory containing `catalog.json`, `policy.json`,
    /// `bundle.sealed`, the disk passphrase, and the generated config.
    #[must_use]
    pub fn fixtures(&self) -> PathBuf {
        self.workdir.join("fixtures")
    }

    /// The generated config TOML path. `basil doctor --config <this>` reads these
    /// fixture paths directly and probes this dev backend; no broker is running.
    #[must_use]
    pub fn config_path(&self) -> PathBuf {
        self.fixtures().join("basil-agent.toml")
    }

    /// The `http://127.0.0.1:<port>` the dev server listens on. Feed it to the
    /// broker config's `vault-addr` / `basil init --addr`.
    #[must_use]
    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// The OS process id of the prefill's dev `bao`/`vault` backend.
    #[must_use]
    pub fn dev_server_pid(&self) -> Option<i32> {
        std::fs::read_to_string(&self.server_pidfile)
            .ok()
            .and_then(|txt| txt.trim().parse::<i32>().ok())
    }

    /// Kill just the dev backend, leaving the fixture config and sealed bundle on
    /// disk for a follow-up doctor run.
    #[cfg(unix)]
    pub fn kill_backend(&self) {
        let pid = self
            .dev_server_pid()
            .expect("dev backend pid available to kill");
        reap_dev_server(pid);
    }
}

impl Drop for DevBackend {
    fn drop(&mut self) {
        if let Ok(pid_txt) = std::fs::read_to_string(&self.server_pidfile)
            && let Ok(pid) = pid_txt.trim().parse::<i32>()
        {
            #[cfg(unix)]
            reap_dev_server(pid);
        }
        let _ = std::fs::remove_dir_all(&self.workdir);
    }
}

/// Boot a bare dev `bao`/`vault` server (transit + kv-v2 enabled) on `addr`, with
/// NO broker attached, for tests that drive their own broker against a live
/// backend. Reuses the prefill script's server-boot + engine-enable steps (so it
/// honors the dev-server concurrency semaphore + the `--no-build` binary cache
/// just like [`boot_basil`]); the prefill's catalog/policy/bundle fixtures are
/// written but ignored (the caller's `init` scaffold supplies those). Returns
/// once the dev server answers `status`. `tag`/`addr` follow the same uniqueness
/// rules as [`boot_basil`]: draw `addr` from [`alloc_addr`].
#[must_use]
pub fn boot_dev_backend(tag: &str, engine: Engine, addr: &str) -> DevBackend {
    ensure_crypto_provider();
    let root = repo_root();
    ensure_binaries_built(&root);
    // Bound concurrent dev servers across all test processes (held to teardown).
    let dev_permit = acquire_dev_server_permit();
    let (workdir, addr) = prefill_with_retry(&root, tag, engine, addr, PrefillMode::Standard);

    let backend = DevBackend {
        workdir: workdir.clone(),
        server_pidfile: workdir.join("server.pid"),
        addr,
        _dev_permit: dev_permit,
    };
    assert!(
        backend.server_pidfile.is_file(),
        "dev server pidfile missing after prefill: {}",
        backend.server_pidfile.display()
    );

    backend
}

/// Run the prefill script + boot the agent against `engine` on `addr`; return
/// the harness once the socket binds. `tag` namespaces the temp workdir and
/// `addr` must be a unique `127.0.0.1:<port>` so two dev servers never fight for
/// the same port; obtain it from [`alloc_addr`] rather than hand-picking a
/// literal.
#[must_use]
pub fn boot_basil(tag: &str, engine: Engine, addr: &str) -> Harness {
    boot_basil_inner(tag, engine, addr, None)
}

/// Like [`boot_basil`], but writes a short `svid-ttl-secs` into the agent config.
///
/// This is only for live rotation tests that need the Workload API stream to
/// reissue X.509-SVID material in bounded CI time. Normal callers should keep
/// using [`boot_basil`] so they exercise the production default.
#[must_use]
pub fn boot_basil_with_svid_ttl(
    tag: &str,
    engine: Engine,
    addr: &str,
    svid_ttl_secs: u64,
) -> Harness {
    boot_basil_inner(tag, engine, addr, Some(svid_ttl_secs))
}

/// Boot a broker whose sealed bundle is opened ONLY by a BIP39 break-glass slot
/// (`basil-bp30`). Runs the standard prefill (which provisions the backend, the
/// catalog/policy, and the `AppRole` role/secret), re-seals that same `AppRole`
/// backend cred into a fresh bundle carrying a SINGLE BIP39 slot (a freshly
/// generated 24-word phrase), writes the phrase to a `0600` file, and boots the
/// broker with `[unlock] bip39-phrase-file = <that file>` and NO passphrase slot.
///
/// Because the bundle has only a BIP39 slot, a bound socket proves the broker
/// recovered the master KEK from the mnemonic, unsealed the `AppRole` cred, and
/// logged into the live backend end-to-end: the break-glass path the BIP39 unit
/// tests never exercise through an actual bundle unseal + broker boot.
///
/// `tag`/`addr` follow the same uniqueness rules as [`boot_basil`]. Requires the
/// `unlock-bip39` feature (enabled under `--all-features`); the harness-built
/// `basil` binary carries it by default.
#[cfg(feature = "unlock-bip39")]
#[must_use]
pub fn boot_basil_bip39(tag: &str, engine: Engine, addr: &str) -> Harness {
    ensure_crypto_provider();
    let root = repo_root();
    ensure_binaries_built(&root);
    // Bound concurrent dev servers across all test processes (held to teardown).
    let dev_permit = acquire_dev_server_permit();
    let (workdir, addr) = prefill_with_retry(&root, tag, engine, addr, PrefillMode::Standard);

    let mut harness = Harness {
        workdir: workdir.clone(),
        agent: None,
        server_pidfile: workdir.join("server.pid"),
        backend_addr: addr.clone(),
        _dev_permit: dev_permit,
    };

    let fixtures = harness.fixtures();
    let catalog = fixtures.join("catalog.json");
    let policy = fixtures.join("policy.json");
    let role_id_file = fixtures.join("approle-role-id.txt");
    let secret_id_file = fixtures.join("approle-secret-id.txt");
    for f in [&catalog, &policy, &role_id_file, &secret_id_file] {
        assert!(f.is_file(), "expected fixture missing: {}", f.display());
    }

    // --- re-seal the AppRole cred into a BIP39-only bundle via the library API.
    let bundle = fixtures.join("bundle.bip39.sealed");
    let phrase_file = fixtures.join("bip39-phrase.txt");
    seal_bip39_bundle(&role_id_file, &secret_id_file, &bundle, &phrase_file);

    // --- boot the broker on the BIP39 unlock path (no passphrase slot).
    let agent_bin = root.join("target/debug/basil");
    let broker_log = workdir.join("broker.log");
    let log = std::fs::File::create(&broker_log).expect("create broker log");
    let socket = harness.socket();
    let config = workdir.join("basil-agent.toml");
    std::fs::write(
        &config,
        format!(
            r#"catalog = "{}"
policy = "{}"
bundle = "{}"
capability-policy = "strict"

[unlock]
bip39-phrase-file = "{}"
"#,
            catalog.display(),
            policy.display(),
            bundle.display(),
            phrase_file.display()
        ),
    )
    .expect("write basil-agent bip39 config");
    let child = Command::new(&agent_bin)
        .arg("agent")
        .arg("--config")
        .arg(&config)
        .args(["--vault-addr", &addr])
        .arg("--socket")
        .arg(&socket)
        .stdout(log.try_clone().expect("clone log handle"))
        .stderr(log)
        .spawn()
        .expect("spawn basil agent (bip39 boot)");

    harness.agent = Some(child);
    wait_for_socket(&mut harness, &socket, &broker_log);
    harness
}

/// Seal a `BackendCred::VaultAppRole` (read from the prefill's `role_id`/`secret_id`
/// fixtures) into a fresh bundle under backend id `bao`, with a SINGLE BIP39 slot
/// whose 24-word phrase is freshly generated and written `0600` to `phrase_out`.
/// Also writes the matching epoch sidecar. Mirrors [`seal_spiffe_bundle`] but with
/// a break-glass BIP39 slot instead of a passphrase slot (`basil-bp30`).
#[cfg(feature = "unlock-bip39")]
fn seal_bip39_bundle(
    role_id_file: &Path,
    secret_id_file: &Path,
    bundle_out: &Path,
    phrase_out: &Path,
) {
    use basil_core::seal::{
        self, BackendCred, Bip39Method, CredBundle, SlotSpec, format, write_epoch_sidecar,
    };
    use zero_secrets::SecretString;

    let read_trimmed = |path: &Path, what: &str| -> String {
        let mut s = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {what}: {e}"));
        while s.ends_with('\n') || s.ends_with('\r') {
            s.pop();
        }
        s
    };
    let role_id = read_trimmed(role_id_file, "approle role_id");
    let secret_id = read_trimmed(secret_id_file, "approle secret_id");

    let mut creds = CredBundle::empty();
    creds.set(
        "bao",
        BackendCred::VaultAppRole {
            role_id,
            secret_id: SecretString::new(secret_id),
            // Per-cred addr override unused; the broker's `--vault-addr` applies.
            addr: None,
        },
    );

    let phrase = Bip39Method::generate_phrase().expect("generate bip39 phrase");
    let method = Bip39Method::new(phrase.clone());
    let file = seal::seal(
        &creds,
        &[SlotSpec {
            method: &method,
            label: "break-glass".to_string(),
        }],
    )
    .expect("seal BIP39 break-glass bundle");
    let parsed = format::decode(&file).expect("decode sealed BIP39 bundle");

    {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new();
        f.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            f.mode(0o600);
        }
        f.open(bundle_out)
            .expect("create sealed BIP39 bundle")
            .write_all(&file)
            .expect("write sealed BIP39 bundle");
    }

    // The operator's recovery phrase, on a 0600 file the broker reads at unlock.
    {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new();
        f.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            f.mode(0o600);
        }
        f.open(phrase_out)
            .expect("create bip39 phrase file")
            .write_all(phrase.as_bytes())
            .expect("write bip39 phrase file");
    }

    let mut sidecar = std::ffi::OsString::from(bundle_out.as_os_str());
    sidecar.push(".epoch");
    write_epoch_sidecar(Path::new(&sidecar), parsed.body.header.epoch)
        .expect("write bundle epoch sidecar");
}

fn boot_basil_inner(tag: &str, engine: Engine, addr: &str, svid_ttl_secs: Option<u64>) -> Harness {
    ensure_crypto_provider();
    let root = repo_root();
    ensure_binaries_built(&root);
    // Bound concurrent dev servers across all test processes (held to teardown).
    let dev_permit = acquire_dev_server_permit();
    let (workdir, addr) = prefill_with_retry(&root, tag, engine, addr, PrefillMode::Standard);

    let mut harness = Harness {
        workdir: workdir.clone(),
        agent: None,
        server_pidfile: workdir.join("server.pid"),
        backend_addr: addr.clone(),
        _dev_permit: dev_permit,
    };

    let fixtures = harness.fixtures();
    let catalog = fixtures.join("catalog.json");
    let policy = fixtures.join("policy.json");
    let bundle = fixtures.join("bundle.sealed");
    let pass = fixtures.join("disk-pass.txt");
    for f in [&catalog, &policy, &bundle, &pass] {
        assert!(f.is_file(), "expected fixture missing: {}", f.display());
    }

    // --- boot the broker (default features => SPIFFE Workload API served).
    let agent_bin = root.join("target/debug/basil");
    let broker_log = workdir.join("broker.log");
    let log = std::fs::File::create(&broker_log).expect("create broker log");
    let socket = harness.socket();
    let config = workdir.join("basil-agent.toml");
    let svid_ttl_line =
        svid_ttl_secs.map_or_else(String::new, |ttl| format!("svid-ttl-secs = {ttl}\n"));
    // Enable the JSONL audit sink so the reload e2e (basil-mil0.5/basil-ftmc) can
    // parse the `basil.audit.reload` events a SIGHUP and an RPC reload emit and
    // assert their parity. Purely additive; the other live tests ignore the file.
    let audit_log = harness.audit_log_path();
    std::fs::write(
        &config,
        format!(
            r#"catalog = "{}"
policy = "{}"
bundle = "{}"
capability-policy = "strict"
audit-log = "{}"
{svid_ttl_line}

[unlock]
unlock-passphrase-file = "{}"
"#,
            catalog.display(),
            policy.display(),
            bundle.display(),
            audit_log.display(),
            pass.display()
        ),
    )
    .expect("write basil-agent config");
    let child = Command::new(&agent_bin)
        .arg("agent")
        .arg("--config")
        .arg(&config)
        .args(["--vault-addr", &addr])
        .arg("--socket")
        .arg(&socket)
        .stdout(log.try_clone().expect("clone log handle"))
        .stderr(log)
        .spawn()
        .expect("spawn basil agent");

    harness.agent = Some(child);
    wait_for_socket(&mut harness, &socket, &broker_log);
    harness
}

/// Optional `[jwks]` HTTP-surface config for a SPIFFE boot (basil-uce.3).
///
/// When [`boot_basil_spiffe`] is given `Some(JwksSpec)` it writes a `[jwks]`
/// section into the agent config so the broker opens its (otherwise opt-in) JWKS
/// HTTP listener alongside the unix-socket gRPC surface. `listen` MUST be a
/// loopback `127.0.0.1:<port>` distinct from the dev-engine `addr` port; draw it
/// from a SECOND [`alloc_addr`] and strip the `http://` scheme (it is a bind
/// address, not a URL). `issuer` is the OIDC discovery base URL (so
/// `/.well-known/openid-configuration` is served and `jwks_uri` is consistent);
/// pass `http://<listen>` to point the discovery doc at this same surface.
#[derive(Clone, Debug)]
pub struct JwksSpec {
    /// `127.0.0.1:<port>` bind address for the JWKS HTTP listener.
    pub listen: String,
    /// OIDC discovery `issuer` base URL (no trailing slash), or `None` to serve
    /// only the bare JWKS endpoints.
    pub issuer: Option<String>,
}

/// Render the optional `[jwks]` agent-config table for a SPIFFE boot (basil-uce.3):
/// `Some(spec)` enables the JWKS HTTP surface bound to `spec.listen` (+ OIDC
/// discovery when `spec.issuer` is set); `None` yields the empty string (surface
/// closed). Factored out of [`boot_basil_spiffe`] to keep it under the line cap.
fn jwks_config_section(jwks: Option<&JwksSpec>) -> String {
    jwks.map_or_else(String::new, |spec| {
        let issuer_line = spec
            .issuer
            .as_deref()
            .map_or_else(String::new, |iss| format!("issuer = \"{iss}\"\n"));
        format!(
            "\n[jwks]\nenable = true\nlisten = \"{}\"\n{issuer_line}",
            spec.listen
        )
    })
}

/// Run the prefill in `--spiffe-boot` mode, seal the emitted RSA signer key +
/// SPIFFE id into a `BackendCred::SpiffeSigner` bundle (the `bundle` CLI has no
/// `SpiffeSigner` flag, so we seal via the library `seal` API), then boot the
/// broker on the **`SpiffeSigner`** path: it self-mints a `JWT-SVID` and exchanges
/// it at `auth/<mount>/login` for a short-lived backend token. Returns once the
/// socket binds: i.e. once the `JWT-SVID` login + startup reconcile (which already
/// drives real backend ops through the exchanged token) have both succeeded.
///
/// `jwks` opts the boot into the JWKS HTTP surface (basil-uce.3): `Some(spec)`
/// writes a `[jwks] enable = true` section so the broker binds `spec.listen` and
/// serves `/jwks.json` (+ discovery when `spec.issuer` is set); `None` leaves the
/// surface closed (the default for the login/x509 e2e callers).
///
/// `tag`/`addr` follow the same uniqueness rules as [`boot_basil`]. This is purely
/// additive to the `AppRole` [`boot_basil`] path; the prefill's `--spiffe-boot`
/// gate leaves that path unchanged.
///
#[must_use]
pub fn boot_basil_spiffe(
    tag: &str,
    engine: Engine,
    addr: &str,
    jwks: Option<&JwksSpec>,
) -> Harness {
    ensure_crypto_provider();
    let root = repo_root();
    ensure_binaries_built(&root);
    // Bound concurrent dev servers across all test processes (held to teardown).
    let dev_permit = acquire_dev_server_permit();
    let (workdir, addr) = prefill_with_retry(&root, tag, engine, addr, PrefillMode::SpiffeBoot);

    let mut harness = Harness {
        workdir: workdir.clone(),
        agent: None,
        server_pidfile: workdir.join("server.pid"),
        backend_addr: addr.clone(),
        _dev_permit: dev_permit,
    };

    let fixtures = harness.fixtures();
    let catalog = fixtures.join("catalog.json");
    let policy = fixtures.join("policy.json");
    let pass = fixtures.join("disk-pass.txt");
    let signer_key = fixtures.join("spiffe-signer.key.pem");
    let signer_id = fixtures.join("spiffe-signer.id.txt");
    for f in [&catalog, &policy, &pass, &signer_key, &signer_id] {
        assert!(
            f.is_file(),
            "expected spiffe fixture missing: {}",
            f.display()
        );
    }

    // --- seal the SpiffeSigner cred into a passphrase-slot bundle via the library API.
    let bundle = fixtures.join("bundle.sealed");
    seal_spiffe_bundle(&signer_key, &signer_id, &pass, &bundle);

    // --- boot the broker on the SpiffeSigner path. The jwt flags MUST match what
    //     the prefill wired (mount `jwt`, role `basil-spiffe`, audience = engine
    //     name). The broker self-mints a JWT-SVID and POSTs auth/jwt/login.
    let agent_bin = root.join("target/debug/basil");
    let broker_log = workdir.join("broker.log");
    let log = std::fs::File::create(&broker_log).expect("create broker log");
    let socket = harness.socket();
    let config = workdir.join("basil-agent.toml");
    // Optional `[jwks]` section (basil-uce.3): when requested, enable the JWKS
    // HTTP surface so the broker binds `spec.listen` and serves the issuer JWK
    // set (+ OIDC discovery when `spec.issuer` is set).
    let jwks_section = jwks_config_section(jwks);
    std::fs::write(
        &config,
        format!(
            r#"catalog = "{}"
policy = "{}"
bundle = "{}"
capability-policy = "strict"
jwt-auth-mount = "jwt"
jwt-role = "basil-spiffe"
jwt-audience = "{}"
svid-ttl-secs = 300

[unlock]
unlock-passphrase-file = "{}"
{jwks_section}"#,
            catalog.display(),
            policy.display(),
            bundle.display(),
            engine.prefill_name(),
            pass.display()
        ),
    )
    .expect("write basil-agent spiffe config");
    let child = Command::new(&agent_bin)
        .arg("agent")
        .arg("--config")
        .arg(&config)
        .args(["--vault-addr", &addr])
        .arg("--socket")
        .arg(&socket)
        .stdout(log.try_clone().expect("clone log handle"))
        .stderr(log)
        .spawn()
        .expect("spawn basil agent (spiffe boot)");

    harness.agent = Some(child);
    wait_for_socket(&mut harness, &socket, &broker_log);
    harness
}

/// Seal a `BackendCred::SpiffeSigner` (the RSA signer PEM + `spiffe_id`) into a
/// fresh passphrase-slot bundle under backend id `bao` (matching the catalog backend),
/// then write the matching epoch sidecar. Mirrors what `basil bundle create`
/// does for an `AppRole` cred, but the CLI has no `SpiffeSigner` seed flag, so we
/// build it here with the same `PassphraseMethod::new` (PRODUCTION argon params)
/// the broker's startup unlock uses.
fn seal_spiffe_bundle(signer_key: &Path, signer_id: &Path, pass_file: &Path, bundle_out: &Path) {
    use basil_core::seal::{
        self, BackendCred, CredBundle, PassphraseMethod, SlotSpec, format, write_epoch_sidecar,
    };
    use zero_secrets::SecretString;
    use zeroize::Zeroizing;

    let key_pem = std::fs::read_to_string(signer_key).expect("read spiffe signer key pem");
    let spiffe_id = std::fs::read_to_string(signer_id)
        .expect("read spiffe id")
        .trim()
        .to_string();
    let mut passphrase = std::fs::read(pass_file).expect("read passphrase");
    if passphrase.last() == Some(&b'\n') {
        passphrase.pop();
    }

    let mut creds = CredBundle::empty();
    creds.set(
        "bao",
        BackendCred::SpiffeSigner {
            key_pem: SecretString::new(key_pem),
            spiffe_id,
        },
    );

    let passphrase = PassphraseMethod::new(Zeroizing::new(passphrase));
    let file = seal::seal(
        &creds,
        &[SlotSpec {
            method: &passphrase,
            label: "passphrase".to_string(),
        }],
    )
    .expect("seal SpiffeSigner bundle");
    let parsed = format::decode(&file).expect("decode sealed SpiffeSigner bundle");

    {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new();
        f.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            f.mode(0o600);
        }
        f.open(bundle_out)
            .expect("create sealed bundle")
            .write_all(&file)
            .expect("write sealed bundle");
    }

    let mut sidecar = std::ffi::OsString::from(bundle_out.as_os_str());
    sidecar.push(".epoch");
    write_epoch_sidecar(Path::new(&sidecar), parsed.body.header.epoch)
        .expect("write bundle epoch sidecar");
}

/// Mint an RS256 JWT-SVID through the broker's SPIFFE Workload API
/// (`FetchJWTSVID`) for `audience`, returning the compact JWT string
/// (basil-uce.3).
///
/// This drives the **real** mint path the JWKS surface is meant to verify
/// against: the broker signs the SVID with its RSA JWT-SVID issuer (RS256, the
/// content-derived `kid` published in the JWKS), so the returned token's `kid`
/// resolves to a key in `/jwks.json`. The reusable seam later OIDC iterations
/// build on. `endpoint` is `harness.endpoint()` (the `unix:<socket>` string);
/// `spiffe_id` is left `None` (the default templated identity).
///
/// Deliberately minted through the Workload API rather than generic `MintJwt`
/// because this helper covers the SPIFFE JWT-SVID claim shape.
pub async fn fetch_jwt_svid(endpoint: &str, audience: &str) -> String {
    use spiffe::WorkloadApiClient;
    let client = WorkloadApiClient::connect_to(endpoint)
        .await
        .expect("WorkloadApiClient::connect_to broker for FetchJWTSVID");
    let svid = client
        .fetch_jwt_svid([audience], None)
        .await
        .expect("fetch_jwt_svid (RS256 over the RSA issuer)");
    let token = svid.token().to_string();
    assert!(!token.is_empty(), "minted JWT-SVID token is non-empty");
    token
}

/// Rotate a transit key in the dev engine **out-of-band**, exactly as an
/// operator would with the `bao`/`vault` CLI: `<cli> write -f
/// transit/<mount-relative>/keys/<key>/rotate` against the dev server `addr`
/// (the same `VAULT_ADDR` passed to [`boot_basil_spiffe`]) with the dev root
/// token. Returns once the CLI exits successfully.
///
/// This is the rotation seam the OIDC/JWKS grace e2e drives: bumping the RSA
/// JWT-SVID issuer's transit key version under the broker's feet (no broker
/// reload). The JWKS handler reads `Backend::public_keys` FRESH per request, so
/// the new version's `kid` shows up in `/jwks.json` on the very next fetch.
///
/// `engine` selects the CLI binary (`bao`/`vault`, both take identical transit
/// rotate commands); `addr` is the `http://127.0.0.1:<port>` the dev server is
/// listening on; `transit_path` is the transit-mount-relative key path
/// (e.g. `keys/spiffe-jwt`). The dev root token is `"root"` (the prefill's
/// `-dev-root-token-id`).
pub fn rotate_transit_key(engine: Engine, addr: &str, transit_path: &str) {
    let status = Command::new(engine.cli_bin())
        .args(["write", "-f", &format!("transit/{transit_path}/rotate")])
        .env("VAULT_ADDR", addr)
        .env("VAULT_TOKEN", "root")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap_or_else(|e| panic!("spawn {} transit rotate: {e}", engine.cli_bin()));
    assert!(
        status.success(),
        "{} write -f transit/{transit_path}/rotate failed (addr {addr})",
        engine.cli_bin()
    );
}

/// Wait (bounded) for the agent socket to appear; panic with the broker log on
/// timeout or early exit. Shared by both boot paths.
fn wait_for_socket(harness: &mut Harness, socket: &Path, broker_log: &Path) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if socket.exists() {
            break;
        }
        if let Some(child) = harness.agent.as_mut()
            && let Ok(Some(status)) = child.try_wait()
        {
            let log = std::fs::read_to_string(broker_log).unwrap_or_default();
            panic!("basil-agent exited before binding socket ({status}); log:\n{log}");
        }
        if Instant::now() >= deadline {
            let log = std::fs::read_to_string(broker_log).unwrap_or_default();
            panic!("basil-agent socket never appeared within 30s; log:\n{log}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
