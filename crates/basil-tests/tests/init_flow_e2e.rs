//! Cross-engine LIVE e2e for the full first-run onboarding flow (basil-mil0.7):
//! `basil config init` → `bundle create` → `check` → `run` → sign with the
//! scaffolded example key, against a live dev `bao` AND a live dev `vault`.
//!
//! `basil config init` (src/init.rs) scaffolds a "valid by construction" starter
//! deployment into a target dir: a `catalog.json` with ONE example key (a transit
//! Ed25519 signing key, `missing=generate` so startup reconcile creates it in
//! place), a least-privilege `policy.json` granting ONLY the running uid a narrow
//! `signer` role over that one key, and an agent `.toml` pointing at the
//! catalog/policy/bundle/socket, and it PRINTS the exact `bundle create` command.
//! init re-validates the pair through the real loader before writing, so the
//! scaffold is internally consistent OFFLINE (covered by unit tests in init.rs).
//!
//! THIS test proves the scaffold is consistent END-TO-END against a LIVE backend:
//!   1. `init --backend <engine> --addr <dev> --transit-mount transit
//!      --unlock passphrase --dir <tmp>` writes catalog.json / policy.json / the
//!      agent .toml (asserted on disk);
//!   2. `bundle create` (the passphrase-slot + `--backend id=primary,…,token-file=`
//!      form init prints) seals the bundle file `0600` (asserted);
//!   3. `check --require -c <toml>` loads + validates the scaffold and probes the
//!      example key against the live backend (exits 0; the key is `missing=generate`
//!      so `check` never fails on its absence; `run`'s reconcile creates it next);
//!   4. `run -c <toml>` boots: startup reconcile CREATES the `missing=generate`
//!      example key in the live transit mount, then binds the socket;
//!   5. over that socket, `basil::Client` SIGNS a message with the example key,
//!      the running uid is exactly the uid the scaffold's policy granted, so the
//!      sign is allowed, and a fresh verify accepts the signature.
//!
//! The example key path: this test passes `--passphrase-file <fixture>` to init,
//! so the generated `unlock-passphrase-file` config and the printed `bundle
//! create --slot passphrase:file=…` command are runnable without a config
//! hand-edit. The dev root token is still injected when the test runs `bundle
//! create` (written to a `0600` file for `--backend …,token-file=`).
//!
//! GATING: each engine leg is independently gated on its CLI (`bao`/`vault`) being
//! on PATH; an absent engine prints an EXPLICIT skip line (acceptance forbids a
//! silent `#[ignore]`). `ran_any` asserts at least one leg ran, so an all-absent
//! environment FAILS loudly rather than passing vacuously. Each leg's dev-server
//! `addr` comes from `basil_tests::alloc_addr()` (disjoint port per call / per binary).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::allow_attributes
)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use basil_tests::{DevBackend, Engine, alloc_addr, boot_dev_backend, on_path, repo_root};

use basil::Client;

/// The catalog key name the scaffold writes (must match `init::EXAMPLE_KEY`).
const EXAMPLE_KEY: &str = "example.signing_key";
/// The catalog backend name the scaffold writes (must match `init::BACKEND_NAME`),
/// used as the `bundle create --backend id=<backend>,…` credential id.
const BACKEND_NAME: &str = "primary";

/// Path to the built `basil` binary the live harness uses.
fn agent_bin() -> PathBuf {
    repo_root().join("target/debug/basil")
}

/// Run `basil <args...>` to completion against the dev `addr`, capturing
/// stdout/stderr. Returns `(success, combined_output)`.
fn run_agent(args: &[&str], addr: &str) -> (bool, String) {
    let out = Command::new(agent_bin())
        .args(args)
        .env("VAULT_ADDR", addr)
        .output()
        .unwrap_or_else(|e| panic!("spawn basil-agent {args:?}: {e}"));
    let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success(), combined)
}

/// Steps 1–3: `init` the scaffold against the live `backend`, resolve the
/// disk-unlock placeholder to a real passphrase, `bundle create` to seal the
/// credential bundle (0600), and `check --require` it against the live backend.
/// Returns the scaffold dir (its `basil-agent.toml` + `basil.sock` drive step 4).
// A linear step-1→2→3 onboarding script; kept as one narrative rather than split.
#[allow(clippy::too_many_lines)]
fn scaffold_and_seal(engine: Engine, backend: &DevBackend, tag: &str) -> PathBuf {
    let dir = backend_scaffold_dir(tag);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scaffold dir");
    let pass_file = dir.join("disk-pass.txt");
    write_passphrase(&pass_file, b"basil-init-flow-e2e-passphrase");

    // --- step 1: scaffold the starter set targeting the live dev backend.
    let backend_flag = match engine {
        Engine::OpenBao => "openbao",
        Engine::Vault => "vault",
    };
    let dir_str = dir.to_str().expect("scaffold dir is UTF-8");
    let pass_str = pass_file.to_str().expect("pass path is UTF-8");
    let (ok, out) = run_agent(
        &[
            "config",
            "init",
            "--backend",
            backend_flag,
            "--addr",
            backend.addr(),
            "--transit-mount",
            "transit",
            "--unlock",
            "passphrase",
            "--passphrase-file",
            pass_str,
            "--dir",
            dir_str,
        ],
        backend.addr(),
    );
    assert!(
        ok,
        "[{}] basil config init failed:\n{out}",
        engine.prefill_name()
    );

    let config = dir.join("basil-agent.toml");
    let bundle = dir.join("bundle.sealed");
    for name in ["catalog.json", "policy.json", "basil-agent.toml"] {
        let f = dir.join(name);
        assert!(
            f.is_file(),
            "[{}] init did not write {}",
            engine.prefill_name(),
            f.display()
        );
    }
    assert_config_uses_passphrase_file(&config, pass_str, engine);
    eprintln!(
        "INIT-FLOW[{}]: init scaffolded catalog/policy/config in {}",
        engine.prefill_name(),
        dir.display()
    );

    // --- step 2: seal the bundle exactly as init's printed `bundle create` says:
    //     a passphrase slot (reads `pass_file`) + the backend token credential
    //     (`--backend id=primary,type=<engine>,token-file=<dev root token>`). The
    //     only token source is `token-file=` (there is no inline token flag), so
    //     the dev root token is written to a `0600` file the create reads + trims.
    let bundle_str = bundle.to_str().expect("bundle path is UTF-8");
    let token_file = dir.join("backend-token.txt");
    // `write_passphrase` is just a `0600` byte writer; reuse it for the token file.
    write_passphrase(&token_file, DevBackend::ROOT_TOKEN.as_bytes());
    let token_file_str = token_file.to_str().expect("token file path is UTF-8");
    let passphrase_slot = format!("passphrase:file={pass_str}");
    let backend_spec = format!("id={BACKEND_NAME},type={backend_flag},token-file={token_file_str}");
    let (ok, out) = run_agent(
        &[
            "bundle",
            "create",
            bundle_str,
            "--slot",
            &passphrase_slot,
            "--backend",
            &backend_spec,
        ],
        backend.addr(),
    );
    assert!(
        ok,
        "[{}] bundle create failed:\n{out}",
        engine.prefill_name()
    );
    assert!(
        bundle.is_file(),
        "[{}] bundle create did not write {}",
        engine.prefill_name(),
        bundle.display()
    );
    assert_mode_0600(&bundle, engine);
    eprintln!(
        "INIT-FLOW[{}]: bundle create sealed {} (0600)",
        engine.prefill_name(),
        bundle.display()
    );

    // --- step 3: `check --require` loads + validates the scaffold and probes the
    //     example key against the live backend. The key is missing=generate, so
    //     --require does NOT fail on its absence (only missing=error keys do); the
    //     check exiting 0 proves the whole scaffold (catalog/policy/bundle/unlock)
    //     loads + unlocks + reaches the live backend.
    let config_str = config.to_str().expect("config path is UTF-8");
    let (ok, out) = run_agent(
        &["config", "check", "--require", "-c", config_str],
        backend.addr(),
    );
    assert!(
        ok,
        "[{}] check --require failed:\n{out}",
        engine.prefill_name()
    );
    eprintln!(
        "INIT-FLOW[{}]: check --require passed against the live backend",
        engine.prefill_name()
    );

    dir
}

/// Assert init baked the provided passphrase path into the generated config.
fn assert_config_uses_passphrase_file(config: &Path, pass_str: &str, engine: Engine) {
    let config_toml = std::fs::read_to_string(config).expect("read generated config");
    assert!(
        config_toml.contains(&format!("unlock-passphrase-file = \"{pass_str}\"")),
        "[{}] init did not bake passphrase path into config:\n{config_toml}",
        engine.prefill_name()
    );
}

/// Drive ONE engine through the whole init → bundle → check → run → sign flow.
async fn drive_engine(engine: Engine, tag: &str, addr: &str) {
    // --- live backend (transit enabled), no broker: the scaffold IS the broker.
    let backend = boot_dev_backend(tag, engine, addr);
    let dir = scaffold_and_seal(engine, &backend, tag);
    let config = dir.join("basil-agent.toml");

    // --- step 4: `run` boots: startup reconcile CREATES the missing=generate
    //     example key in the live transit mount, then binds the socket.
    let socket = dir.join("basil.sock");
    let mut agent = spawn_run(&config, &socket, backend.addr());
    wait_for_socket(&mut agent, &socket);
    eprintln!(
        "INIT-FLOW[{}]: run booted; example key reconciled (created) + socket bound",
        engine.prefill_name()
    );

    // --- step 5: sign with the example key over the socket. The running uid is
    //     exactly the uid the scaffold's policy granted role:signer, so the sign
    //     is allowed; a fresh ed25519-dalek verify accepts the signature.
    let socket_str = socket.to_str().expect("socket path is UTF-8");
    let mut client = Client::connect(socket_str)
        .await
        .expect("connect basil client to the scaffolded broker socket");
    let message = b"basil-mil0.7 init->bundle->check->run onboarding e2e";
    let signature = client
        .sign(EXAMPLE_KEY, message)
        .await
        .expect("sign with the scaffolded example key");
    assert_eq!(
        signature.len(),
        64,
        "[{}] Ed25519 signature is 64 bytes (got {})",
        engine.prefill_name(),
        signature.len()
    );

    // The broker's own verify accepts its signature, and rejects a tampered one,
    // proving the reconciled key round-trips end to end over the scaffold.
    assert!(
        client
            .verify(EXAMPLE_KEY, message, &signature)
            .await
            .expect("broker verify of its own signature"),
        "[{}] broker verify accepts its own signature",
        engine.prefill_name()
    );
    assert!(
        !client
            .verify(EXAMPLE_KEY, b"a different message", &signature)
            .await
            .expect("broker verify of a tampered message"),
        "[{}] broker verify rejects a signature over a different message",
        engine.prefill_name()
    );
    drop(client);

    eprintln!(
        "INIT-FLOW[{}]: SIGNED with the scaffolded example key; signature verified",
        engine.prefill_name()
    );

    // --- teardown: stop the broker we started, then the dev backend (Drop).
    reap_agent(agent);
    let _ = std::fs::remove_dir_all(&dir);
    drop(backend);
}

/// The temp scaffold dir for one engine leg (distinct from the dev-server workdir).
fn backend_scaffold_dir(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("basil-init-flow-{tag}.{}", std::process::id()))
}

/// Write a passphrase fixture `0600` (the passphrase slot reads it).
fn write_passphrase(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).expect("write passphrase fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod passphrase fixture");
    }
}

/// Assert a file's mode is exactly `0600` (the sealed bundle must be owner-only).
#[cfg(unix)]
fn assert_mode_0600(path: &Path, engine: Engine) {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)
        .expect("stat sealed bundle")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode,
        0o600,
        "[{}] sealed bundle {} mode is {mode:o}, expected 0600",
        engine.prefill_name(),
        path.display()
    );
}

#[cfg(not(unix))]
fn assert_mode_0600(_path: &Path, _engine: Engine) {}

/// Spawn `basil agent -c <config> --socket <socket> --vault-addr <addr>`,
/// logging to `<dir>/broker.log`.
fn spawn_run(config: &Path, socket: &Path, addr: &str) -> std::process::Child {
    let dir = config.parent().expect("config has a parent dir");
    let log = std::fs::File::create(dir.join("broker.log")).expect("create broker log");
    Command::new(agent_bin())
        .arg("agent")
        .arg("-c")
        .arg(config)
        .arg("--socket")
        .arg(socket)
        .args(["--vault-addr", addr])
        .env("VAULT_ADDR", addr)
        .stdout(log.try_clone().expect("clone log handle"))
        .stderr(log)
        .spawn()
        .expect("spawn basil agent (scaffolded broker)")
}

/// Wait (bounded) for the scaffolded broker's socket to bind; panic with the
/// broker log on timeout or an early exit.
fn wait_for_socket(agent: &mut std::process::Child, socket: &Path) {
    let log_path = socket
        .parent()
        .expect("socket has a parent dir")
        .join("broker.log");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if socket.exists() {
            return;
        }
        if let Ok(Some(status)) = agent.try_wait() {
            let log = std::fs::read_to_string(&log_path).unwrap_or_default();
            panic!("scaffolded basil-agent exited before binding socket ({status}); log:\n{log}");
        }
        if Instant::now() >= deadline {
            let log = std::fs::read_to_string(&log_path).unwrap_or_default();
            panic!("scaffolded basil-agent socket never appeared within 30s; log:\n{log}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Stop the scaffolded broker (SIGINT, then SIGKILL backstop), mirroring the
/// harness teardown so we never leak the process we started.
fn reap_agent(mut agent: std::process::Child) {
    #[cfg(unix)]
    {
        let pid = agent.id().cast_signed();
        let _ = Command::new("kill")
            .arg("-INT")
            .arg(pid.to_string())
            .status();
    }
    for _ in 0..30 {
        if matches!(agent.try_wait(), Ok(Some(_))) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = agent.kill();
    let _ = agent.wait();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn init_flow_cross_engine() {
    let ran_bao = if on_path("bao") {
        drive_engine(Engine::OpenBao, "init-flow-bao", &alloc_addr()).await;
        true
    } else {
        eprintln!("SKIP: bao not found on PATH; init-flow e2e needs a live OpenBao");
        false
    };

    let ran_vault = if on_path("vault") {
        drive_engine(Engine::Vault, "init-flow-vault", &alloc_addr()).await;
        true
    } else {
        eprintln!("SKIP: vault not found on PATH; init-flow e2e needs a live Vault");
        false
    };

    assert!(
        ran_bao || ran_vault,
        "neither bao nor vault was on PATH; the init-flow live e2e ran no engine leg \
         (this is a live cross-engine acceptance test; it must not pass vacuously)"
    );
}
