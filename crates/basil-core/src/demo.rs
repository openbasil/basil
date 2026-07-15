// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! `basil demo`: a zero-dependency, one-command guided tour.
//!
//! Scaffolds a throwaway workdir on the built-in db-keystore backend (one
//! encrypted `SQLite` file. No `OpenBao`, no Vault, no network), seals the
//! backend credential into a bundle, starts the broker on a temp socket, then
//! drives a scripted sign → verify → *denied read* → explain → encrypt → mint
//! sequence against it. Each step is printed as the exact CLI command a user
//! could copy-paste, followed by its real output, so the demo doubles as a
//! cheat sheet. It ends with the audit trail and "try it yourself" commands.
//!
//! Every beat is executed by re-invoking THIS binary (`current_exe`), so the
//! output shown is byte-for-byte what the user would see running the printed
//! command themselves. The deliberate denial (`basil get` on the signing key,
//! then `basil explain` for the why) is the differentiated moment: policy
//! saying no, with the receipt.
//!
//! The demo writes only throwaway material: a random passphrase, a random
//! keystore DEK, and generated demo keys, all under one workdir it owns (a
//! marker file guards against wiping a directory the demo did not create).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::IsTerminal as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::Args;
use rand::RngCore as _;

use crate::catalog::{
    BackendKind, BackendRef, Catalog, Class, Config, Engine, KeyAlgorithm, KeyEntry, Labels,
    MissingPolicy, NameTable, Op, PrincipalSpec, RawPolicy, RawRule, RawSubjectDefinition,
};

/// The catalog backend name the demo routes everything to.
const BACKEND_NAME: &str = "local-db";
/// The demo Ed25519 signing key.
const SIGNING_KEY: &str = "demo.signing_key";
/// The demo AES-256-GCM AEAD key.
const AEAD_KEY: &str = "demo.aead_key";
/// The policy subject bound to the invoking uid.
const SUBJECT: &str = "current-user";
/// The least-privilege demo role (use ops only; no read/write/rotate).
const ROLE: &str = "demo-user";
/// Marker file proving a directory was created by `basil demo`, so a re-run
/// may wipe it without risking user data.
const MARKER: &str = ".basil-demo-workdir";
/// `sun_path` is 108 bytes on Linux; leave margin for the NUL and renames.
const MAX_SOCKET_PATH: usize = 96;
/// How long to wait for the spawned broker to bind its socket.
const AGENT_START_TIMEOUT: Duration = Duration::from_secs(30);

/// `demo` subcommand arguments.
#[derive(Debug, Args)]
pub struct DemoArgs {
    /// Directory for the throwaway demo workdir (keystore DB, sealed bundle,
    /// socket, audit log). Kept short by default: Unix socket paths are
    /// limited to ~100 bytes.
    #[arg(long, value_name = "DIR")]
    dir: Option<PathBuf>,

    /// Human pacing: type commands out and pause between steps (for watching
    /// or recording). Default is full speed for CI and quick runs.
    #[arg(long)]
    paced: bool,

    /// Wipe an existing --dir even if it was not created by a previous demo
    /// run (without this, only directories holding the demo marker file are
    /// reused).
    #[arg(long)]
    force: bool,
}

/// Pacing profile: zero by default; `--paced` approximates a narrated take.
#[derive(Clone, Copy)]
struct Pace {
    /// Pause after a narration line.
    say: Duration,
    /// Pause after a command's output.
    beat: Duration,
    /// Per-character typing delay for the command line.
    type_char: Duration,
}

impl Pace {
    const fn new(paced: bool) -> Self {
        if paced {
            Self {
                say: Duration::from_millis(1800),
                beat: Duration::from_millis(2600),
                type_char: Duration::from_millis(28),
            }
        } else {
            Self {
                say: Duration::ZERO,
                beat: Duration::ZERO,
                type_char: Duration::ZERO,
            }
        }
    }
}

/// ANSI styling, disabled when stdout is not a terminal or `NO_COLOR` is set.
#[derive(Clone, Copy)]
struct Style {
    on: bool,
}

impl Style {
    fn detect() -> Self {
        Self {
            on: std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none(),
        }
    }

    fn caption(self, text: &str) -> String {
        if self.on {
            format!("\x1b[1;32m# {text}\x1b[0m")
        } else {
            format!("# {text}")
        }
    }

    const fn prompt(self) -> &'static str {
        if self.on { "\x1b[1;36m$ \x1b[0m" } else { "$ " }
    }

    fn payoff(self, text: &str) -> String {
        if self.on {
            format!("\x1b[1;33m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }
}

/// Everything the demo writes, all under the workdir.
struct Layout {
    dir: PathBuf,
    catalog: PathBuf,
    policy: PathBuf,
    config: PathBuf,
    bundle: PathBuf,
    socket: PathBuf,
    keystore_db: PathBuf,
    passphrase: PathBuf,
    dek: PathBuf,
    audit: PathBuf,
    agent_log: PathBuf,
    marker: PathBuf,
}

impl Layout {
    fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
            catalog: dir.join("catalog.json"),
            policy: dir.join("policy.json"),
            config: dir.join("basil-agent.toml"),
            bundle: dir.join("bundle.sealed"),
            socket: dir.join("basil.sock"),
            keystore_db: dir.join("keystore.db"),
            passphrase: dir.join("unlock-passphrase.txt"),
            dek: dir.join("keystore-dek.bin"),
            audit: dir.join("audit.jsonl"),
            agent_log: dir.join("agent.log"),
            marker: dir.join(MARKER),
        }
    }
}

/// Run `basil demo`.
pub fn run(args: &DemoArgs) -> Result<()> {
    let exe = std::env::current_exe().context("resolving the running basil binary path")?;
    let dir = args
        .dir
        .clone()
        .unwrap_or_else(|| std::env::temp_dir().join("basil-demo"));
    let layout = Layout::new(&dir);

    if layout.socket.as_os_str().len() > MAX_SOCKET_PATH {
        bail!(
            "demo dir {} makes the Unix socket path longer than {MAX_SOCKET_PATH} bytes \
             (kernel limit); pass a shorter --dir, e.g. --dir /tmp/basil-demo",
            layout.dir.display()
        );
    }

    prepare_workdir(&layout, args.force)?;
    scaffold(&layout)?;

    let style = Style::detect();
    let pace = Pace::new(args.paced);
    let narrator = Narrator { style, pace };

    narrator.say("Basil is a host-local secrets broker: your app never touches the key.");
    narrator.say(
        "From nothing to brokered crypto in one command, no vault server required. The \
         backend is Basil's built-in db-keystore: one encrypted SQLite file.",
    );

    narrator.say("Two inputs describe everything. The catalog says WHAT keys exist and where:");
    narrator.show_file(&layout.catalog)?;

    narrator.say(
        "...and the policy says WHO may use them. Default-deny; subjects are kernel-attested uids.",
    );
    narrator.show_file(&layout.policy)?;

    narrator.say(
        "Seal the keystore's data-encryption key into a bundle. It only opens with the \
         passphrase.",
    );
    let bundle_backend_spec = format!(
        "id={BACKEND_NAME},type=db-keystore,path={},dek-file={}",
        layout.keystore_db.display(),
        layout.dek.display()
    );
    narrator.exec_beat(
        &exe,
        &[
            "bundle".to_string(),
            "create".to_string(),
            layout.bundle.display().to_string(),
            "--slot".to_string(),
            format!("passphrase:file={}", layout.passphrase.display()),
            "--backend".to_string(),
            bundle_backend_spec,
        ],
        Expect::Success,
    )?;

    narrator.say(
        "Start the broker. It unlocks the bundle, generates the missing demo keys, and \
         listens on a Unix socket.",
    );
    let mut agent = spawn_agent(&exe, &layout, &narrator)?;
    let outcome = drive_beats(&exe, &layout, &narrator);
    // Stop the broker before reporting, whether the beats succeeded or not.
    let stopped = agent.stop();
    outcome?;
    stopped?;

    print_epilogue(&layout, &narrator);
    Ok(())
}

/// The beats driven against the running broker, separated so the agent is
/// stopped on the error path too.
fn drive_beats(exe: &Path, layout: &Layout, narrator: &Narrator) -> Result<()> {
    let socket = layout.socket.display().to_string();
    let sock_args = ["--socket".to_string(), socket];

    narrator.say(
        "Who am I? Basil read my uid straight from the kernel via SO_PEERCRED. No token, \
         no password, nothing to leak.",
    );
    narrator.exec_beat(
        exe,
        &[sock_args.as_slice(), &["status".to_string()]].concat(),
        Expect::Success,
    )?;

    narrator.say("What keys exist? Both were generated inside the keystore on first start.");
    narrator.exec_beat(
        exe,
        &[sock_args.as_slice(), &["list".to_string()]].concat(),
        Expect::Success,
    )?;

    narrator.say(
        "Sign a release tag. The private key never leaves the keystore; only the signature \
         comes back.",
    );
    let sign_out = narrator.exec_beat(
        exe,
        &[
            sock_args.as_slice(),
            &[
                "sign".to_string(),
                "--key-id".to_string(),
                SIGNING_KEY.to_string(),
                "release v1.0.0".to_string(),
            ],
        ]
        .concat(),
        Expect::Success,
    )?;
    let signature = sign_out.trim().to_string();
    if signature.is_empty() {
        bail!(
            "sign returned an empty signature; see {}",
            layout.agent_log.display()
        );
    }

    narrator.say("And verify it.");
    narrator.exec_beat(
        exe,
        &[
            sock_args.as_slice(),
            &[
                "verify".to_string(),
                "--key-id".to_string(),
                SIGNING_KEY.to_string(),
                "--signature".to_string(),
                signature,
                "release v1.0.0".to_string(),
            ],
        ]
        .concat(),
        Expect::Success,
    )?;

    denial_and_explain_beats(exe, layout, narrator, &sock_args)?;
    encrypt_and_mint_beats(exe, narrator, &sock_args)?;

    narrator.say(
        "Everything above is on the record: one structured audit event per decision, allow \
         AND deny.",
    );
    show_audit_lines(layout, narrator)?;

    narrator.plain("");
    narrator.payoff("Every operation was kernel-attested, policy-checked, and audited.");
    narrator.payoff("No private key ever touched disk unencrypted or crossed the socket.");
    Ok(())
}

/// The differentiated beats: a deliberate policy denial, then `explain` for
/// the deny and the allow, run offline on the same files enforcement uses.
fn denial_and_explain_beats(
    exe: &Path,
    layout: &Layout,
    narrator: &Narrator,
    sock_args: &[String],
) -> Result<()> {
    narrator.say(
        "Can I just read the private key out? No. Policy has no 'get' grant: default-deny \
         says no to everyone.",
    );
    narrator.exec_beat(
        exe,
        &[
            sock_args,
            &[
                "get".to_string(),
                "--key-id".to_string(),
                SIGNING_KEY.to_string(),
            ],
        ]
        .concat(),
        Expect::Denied,
    )?;

    narrator.say(
        "Ask the policy engine why. 'explain' runs the exact matcher enforcement uses, \
         offline, on the same files.",
    );
    let explain_common = [
        "explain".to_string(),
        "--catalog".to_string(),
        layout.catalog.display().to_string(),
        "--policy".to_string(),
        layout.policy.display().to_string(),
        "--subject".to_string(),
        SUBJECT.to_string(),
        "--key".to_string(),
        SIGNING_KEY.to_string(),
    ];
    narrator.exec_beat(
        exe,
        &[
            explain_common.as_slice(),
            &["--op".to_string(), "get".to_string()],
        ]
        .concat(),
        Expect::AnyExit,
    )?;
    narrator.exec_beat(
        exe,
        &[
            explain_common.as_slice(),
            &["--op".to_string(), "sign".to_string()],
        ]
        .concat(),
        Expect::Success,
    )?;
    Ok(())
}

/// AEAD encryption and the short-lived-credential mint.
fn encrypt_and_mint_beats(exe: &Path, narrator: &Narrator, sock_args: &[String]) -> Result<()> {
    narrator.say("Encrypt a backup. Basil owns the nonce, so you cannot reuse one by accident.");
    narrator.exec_beat(
        exe,
        &[
            sock_args,
            &[
                "encrypt".to_string(),
                "--key-id".to_string(),
                AEAD_KEY.to_string(),
                "backup-2026-07-07.tar".to_string(),
            ],
        ]
        .concat(),
        Expect::Success,
    )?;

    narrator.say("Mint a short-lived signed JWT for a service, from the same signing key.");
    narrator.exec_beat(
        exe,
        &[
            sock_args,
            &[
                "mint-jwt".to_string(),
                "--key-id".to_string(),
                SIGNING_KEY.to_string(),
                "--sub".to_string(),
                "deploy-bot".to_string(),
                "--ttl-secs".to_string(),
                "300".to_string(),
            ],
        ]
        .concat(),
        Expect::Success,
    )?;
    Ok(())
}

/// Print the last deny and allow authorization events from the audit log,
/// prefixed by the `tail`-style command a user could run themselves.
fn show_audit_lines(layout: &Layout, narrator: &Narrator) -> Result<()> {
    let audit = std::fs::read_to_string(&layout.audit)
        .with_context(|| format!("reading audit log {}", layout.audit.display()))?;
    let last = |decision: &str| -> Option<&str> {
        audit
            .lines()
            .rev()
            .find(|line| line_decision(line).as_deref() == Some(decision))
    };
    narrator.type_command(&format!("tail {}", layout.audit.display()));
    match (last("deny"), last("allow")) {
        (Some(deny), Some(allow)) => {
            narrator.plain(deny);
            narrator.plain(allow);
        }
        _ => bail!(
            "audit log {} is missing the expected allow/deny events",
            layout.audit.display()
        ),
    }
    narrator.pause_beat();
    Ok(())
}

/// Parse one audit JSONL line's `decision` field (authz events only).
fn line_decision(line: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    if value.get("event_kind")?.as_str()? != "basil.audit.authz" {
        return None;
    }
    Some(value.get("decision")?.as_str()?.to_string())
}

/// Final "try it yourself" block: restart command, three copy-paste ops, and
/// pointers to doctor + the quickstart.
fn print_epilogue(layout: &Layout, narrator: &Narrator) {
    let cfg = layout.config.display();
    let sock = layout.socket.display();
    println!();
    println!("{}", narrator.style.caption("Try it yourself:"));
    println!();
    println!("    basil agent --config {cfg} &");
    println!("    basil --socket {sock} sign --key-id {SIGNING_KEY} 'my first signature'");
    println!(
        "    basil explain --catalog {} --policy {} --subject {SUBJECT} --op rotate --key {SIGNING_KEY}",
        layout.catalog.display(),
        layout.policy.display()
    );
    println!();
    println!(
        "Edit {} to grant yourself more (the broker default-denies anything not listed).",
        layout.policy.display()
    );
    println!("If anything failed: basil doctor --keys -c {cfg}");
    println!();
    println!("The demo workdir is throwaway; re-running `basil demo` recreates it.");
    println!("Real setup for your own keys and backend: `basil init`, and the quickstart:");
    println!("    https://docs.openbasil.org/getting-started/quickstart/");
}

/// What a beat expects of its command's exit status.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Expect {
    /// Must exit zero.
    Success,
    /// Must exit NONZERO: the deliberate policy denial.
    Denied,
    /// Either way (explain exits by decision).
    AnyExit,
}

/// Caption + command narration and beat execution.
struct Narrator {
    style: Style,
    pace: Pace,
}

impl Narrator {
    /// Print a green narration caption, then pause.
    fn say(&self, text: &str) {
        println!();
        println!("{}", self.style.caption(text));
        sleep(self.pace.say);
    }

    /// Print a line verbatim.
    #[allow(clippy::unused_self)]
    fn plain(&self, text: &str) {
        println!("{text}");
    }

    /// Print a yellow payoff line.
    fn payoff(&self, text: &str) {
        println!("{}", self.style.payoff(text));
    }

    /// Print a `$ `-prefixed command line, typing it out under `--paced`.
    fn type_command(&self, command: &str) {
        print!("{}", self.style.prompt());
        if self.pace.type_char.is_zero() {
            println!("{command}");
        } else {
            for ch in command.chars() {
                print!("{ch}");
                let _ = std::io::Write::flush(&mut std::io::stdout());
                sleep(self.pace.type_char);
            }
            println!();
        }
    }

    fn pause_beat(&self) {
        sleep(self.pace.beat);
    }

    /// Show a scaffolded file as a `cat` beat.
    fn show_file(&self, path: &Path) -> Result<()> {
        self.type_command(&format!("cat {}", path.display()));
        let contents =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        print!("{contents}");
        self.pause_beat();
        Ok(())
    }

    /// Print the command as `basil <args...>`, execute it via `exe`, print its
    /// output, enforce the expectation, and return captured stdout.
    fn exec_beat(&self, exe: &Path, args: &[String], expect: Expect) -> Result<String> {
        self.type_command(&display_command(args));
        let output = Command::new(exe)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .with_context(|| format!("running basil {}", args.join(" ")))?;
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr);
        print!("{stdout}");
        if !stderr.is_empty() {
            print!("{stderr}");
        }
        match expect {
            Expect::Success if !output.status.success() => {
                bail!("`basil {}` failed unexpectedly", args.join(" "));
            }
            Expect::Denied if output.status.success() => {
                bail!(
                    "`basil {}` was expected to be DENIED but succeeded; the demo policy is \
                     broken",
                    args.join(" ")
                );
            }
            Expect::Denied => {
                println!(
                    "{}",
                    self.style
                        .caption("(denied, as designed: that grant is not in the policy)")
                );
            }
            _ => {}
        }
        self.pause_beat();
        Ok(stdout)
    }
}

/// Render the display form of a beat: `basil` + args, shell-quoting any
/// argument containing whitespace so the printed line is copy-pasteable.
fn display_command(args: &[String]) -> String {
    let mut out = String::from("basil");
    for arg in args {
        if arg.contains(char::is_whitespace) {
            let _ = write!(out, " '{arg}'");
        } else {
            let _ = write!(out, " {arg}");
        }
    }
    out
}

/// The spawned broker child, stopped on drop as a backstop.
struct AgentGuard {
    child: Option<Child>,
    log: PathBuf,
}

impl AgentGuard {
    /// SIGTERM the broker and wait bounded; SIGKILL as a last resort.
    fn stop(&mut self) -> Result<()> {
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };
        let pid = rustix::process::Pid::from_child(&child);
        let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return Ok(()),
                Ok(None) if Instant::now() < deadline => sleep(Duration::from_millis(100)),
                Ok(None) => {
                    child.kill().context("stopping the demo broker")?;
                    child.wait().context("reaping the demo broker")?;
                    return Ok(());
                }
                Err(e) => return Err(e).context("waiting for the demo broker to stop"),
            }
        }
    }
}

impl Drop for AgentGuard {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// Spawn `basil agent --config <cfg>` with output to the agent log, print the
/// command beat, and wait for the socket to bind.
fn spawn_agent(exe: &Path, layout: &Layout, narrator: &Narrator) -> Result<AgentGuard> {
    narrator.type_command(&format!(
        "basil agent --config {} &",
        layout.config.display()
    ));
    let log = std::fs::File::create(&layout.agent_log)
        .with_context(|| format!("creating {}", layout.agent_log.display()))?;
    let log_err = log
        .try_clone()
        .with_context(|| format!("cloning handle for {}", layout.agent_log.display()))?;
    let child = Command::new(exe)
        .arg("agent")
        .arg("--config")
        .arg(&layout.config)
        .stdin(Stdio::null())
        .stdout(log)
        .stderr(log_err)
        .spawn()
        .context("spawning the demo broker")?;
    let mut agent = AgentGuard {
        child: Some(child),
        log: layout.agent_log.clone(),
    };
    wait_for_socket(&mut agent, &layout.socket)?;
    narrator.pause_beat();
    Ok(agent)
}

/// Wait (bounded) for the broker socket to appear; on an early exit or a
/// timeout, surface the tail of the agent log.
fn wait_for_socket(agent: &mut AgentGuard, socket: &Path) -> Result<()> {
    let deadline = Instant::now() + AGENT_START_TIMEOUT;
    loop {
        if socket.exists() {
            return Ok(());
        }
        if let Some(child) = agent.child.as_mut()
            && let Ok(Some(status)) = child.try_wait()
        {
            bail!(
                "the demo broker exited before binding its socket ({status});\n{}",
                log_tail(&agent.log)
            );
        }
        if Instant::now() >= deadline {
            bail!(
                "the demo broker did not bind {} within {}s;\n{}",
                socket.display(),
                AGENT_START_TIMEOUT.as_secs(),
                log_tail(&agent.log)
            );
        }
        sleep(Duration::from_millis(100));
    }
}

/// The last few agent-log lines for error context.
fn log_tail(log: &Path) -> String {
    let contents = std::fs::read_to_string(log).unwrap_or_default();
    let mut lines: Vec<&str> = contents.lines().rev().take(8).collect();
    lines.reverse();
    if lines.is_empty() {
        lines.push("(agent log is empty)");
    }
    format!("agent log tail ({}):\n{}", log.display(), lines.join("\n"))
}

/// Create (or re-create) the demo workdir. A directory is only wiped when it
/// carries the demo marker file from a previous run, unless `--force`.
fn prepare_workdir(layout: &Layout, force: bool) -> Result<()> {
    if layout.dir.exists() {
        if !force && !layout.marker.exists() {
            bail!(
                "{} exists but was not created by `basil demo` (no {MARKER} marker); \
                 pass --force to wipe it or choose another --dir",
                layout.dir.display()
            );
        }
        std::fs::remove_dir_all(&layout.dir)
            .with_context(|| format!("wiping previous demo dir {}", layout.dir.display()))?;
    }
    std::fs::create_dir_all(&layout.dir)
        .with_context(|| format!("creating demo dir {}", layout.dir.display()))?;
    restrict_dir_mode(&layout.dir)?;
    std::fs::write(&layout.marker, "created by `basil demo`; safe to delete\n")
        .with_context(|| format!("writing {}", layout.marker.display()))?;
    Ok(())
}

/// Owner-only the workdir (it holds the passphrase, DEK, and keystore).
#[cfg(unix)]
fn restrict_dir_mode(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("restricting {} to 0700", dir.display()))
}

#[cfg(not(unix))]
fn restrict_dir_mode(_dir: &Path) -> Result<()> {
    Ok(())
}

/// Write catalog, policy, agent config, passphrase, and DEK into the workdir.
fn scaffold(layout: &Layout) -> Result<()> {
    let catalog = build_catalog(layout);
    let policy = build_policy(current_uid());

    // Serialize the REAL schema types, then validate the pair through the same
    // loader the broker uses: fail closed rather than demo a broken scaffold.
    let catalog_json = serde_json::to_string_pretty(&catalog).context("serializing catalog")?;
    let policy_json = serde_json::to_string_pretty(&policy).context("serializing policy")?;
    crate::load(&catalog_json, &policy_json).context(
        "the generated demo catalog/policy did not pass loader validation (internal bug)",
    )?;

    write_file(&layout.catalog, &format!("{catalog_json}\n"))?;
    write_file(&layout.policy, &format!("{policy_json}\n"))?;
    write_file(&layout.config, &build_config_toml(layout))?;
    write_secret_file(
        &layout.passphrase,
        format!("{}\n", random_hex(24)).as_bytes(),
    )?;
    write_secret_file(&layout.dek, &random_dek())?;
    Ok(())
}

/// The two-key demo catalog on the built-in keystore backend.
fn build_catalog(layout: &Layout) -> Catalog {
    let mut backends = BTreeMap::new();
    backends.insert(
        BACKEND_NAME.to_string(),
        BackendRef {
            kind: BackendKind::Keystore,
            addr: layout.keystore_db.display().to_string(),
            engines: vec![Engine::Transit, Engine::Kv2],
            capabilities: Vec::new(),
            mint_key_types: vec![KeyAlgorithm::Ed25519],
            requires: Vec::new(),
        },
    );

    let mut keys = BTreeMap::new();
    keys.insert(
        SIGNING_KEY.to_string(),
        KeyEntry {
            class: Class::Asymmetric,
            key_type: Some(KeyAlgorithm::Ed25519),
            backend: BACKEND_NAME.to_string(),
            engine: Some(Engine::Transit),
            path: "demo/signing-key".to_string(),
            public_path: None,
            writable: true,
            missing: MissingPolicy::Generate,
            generate: None,
            sealing_pin: None,
            labels: Labels::default(),
            description: "Demo Ed25519 signing key, generated on first start.".to_string(),
        },
    );
    keys.insert(
        AEAD_KEY.to_string(),
        KeyEntry {
            class: Class::Symmetric,
            key_type: Some(KeyAlgorithm::Aes256Gcm),
            backend: BACKEND_NAME.to_string(),
            engine: Some(Engine::Transit),
            path: "demo/aead-key".to_string(),
            public_path: None,
            writable: true,
            missing: MissingPolicy::Generate,
            generate: None,
            sealing_pin: None,
            labels: Labels::default(),
            description: "Demo AES-256-GCM key, generated on first start.".to_string(),
        },
    );

    Catalog {
        schema: crate::catalog::CatalogSchema::Catalog,
        backends,
        keys,
    }
}

/// The least-privilege demo policy: the invoking uid gets USE ops only (sign,
/// verify, public key, encrypt, decrypt, mint, list) over `demo.*`. No `get`,
/// no `set`, no `rotate`: the denied read is the point of the demo.
fn build_policy(uid: u32) -> RawPolicy {
    let mut roles = BTreeMap::new();
    roles.insert(
        ROLE.to_string(),
        BTreeSet::from([
            Op::List,
            Op::GetPublicKey,
            Op::Sign,
            Op::Verify,
            Op::Encrypt,
            Op::Decrypt,
            Op::Mint,
        ]),
    );

    let rule = RawRule {
        id: "current-user-can-use-demo-keys".to_string(),
        subjects: vec![SUBJECT.to_string()],
        action: vec![format!("role:{ROLE}")],
        target: vec!["demo.*".to_string()],
        comment: Some(
            "The uid that ran `basil demo` may USE the demo keys. Reading, writing, and \
             rotating them stays denied: default-deny covers everything unlisted."
                .to_string(),
        ),
    };

    let mut names = NameTable::default();
    names.users.insert(uid, "demo-user".to_string());
    let mut memberships = BTreeMap::new();
    memberships.insert(uid, BTreeSet::new());
    let mut subjects = BTreeMap::new();
    subjects.insert(
        SUBJECT.to_string(),
        RawSubjectDefinition {
            break_glass: false,
            all_of: Some(vec![PrincipalSpec::Unix {
                uid: Some(uid),
                gid: None,
            }]),
            any_of: None,
        },
    );

    RawPolicy {
        schema: crate::catalog::PolicySchema::Policy,
        subjects,
        unauthenticated_subject: None,
        roles,
        rules: vec![rule],
        config: Config { names, memberships },
    }
}

/// The demo agent config: keystore cipher, audit log, passphrase unlock.
fn build_config_toml(layout: &Layout) -> String {
    let mut out = String::new();
    out.push_str("# basil-agent config written by `basil demo` (throwaway).\n");
    out.push_str("schema = \"agent\"\nschemaVersion = 3\n");
    let _ = writeln!(out, "socket = {}", toml_str(&layout.socket));
    out.push_str("socket-mode = \"0600\"\n");
    out.push_str("db-keystore-cipher = \"aegis256\"\n");
    out.push_str("# One structured JSON event per authorization decision, allow and deny.\n");
    let _ = writeln!(out, "audit-log = {}", toml_str(&layout.audit));
    out.push_str("\n[config]\n");
    let _ = writeln!(out, "catalog = {}", toml_str(&layout.catalog));
    let _ = writeln!(out, "policy = {}", toml_str(&layout.policy));
    let _ = writeln!(out, "bundle = {}", toml_str(&layout.bundle));
    out.push('\n');
    out.push_str("[unlock]\n");
    let _ = writeln!(
        out,
        "unlock-passphrase-file = {}",
        toml_str(&layout.passphrase)
    );
    out
}

/// Random lowercase hex string of `bytes` entropy bytes (demo passphrase).
fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    let mut out = String::with_capacity(bytes * 2);
    for b in buf {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// A random 32-byte keystore DEK whose last byte is never `\n`/`\r` (`bundle
/// create` trims one trailing newline from secret files, which would leave a
/// short DEK).
fn random_dek() -> [u8; 32] {
    let mut dek = [0u8; 32];
    loop {
        rand::rngs::OsRng.fill_bytes(&mut dek);
        if !matches!(dek.last(), Some(b'\n' | b'\r')) {
            return dek;
        }
    }
}

/// Write a non-secret scaffold file.
fn write_file(path: &Path, contents: &str) -> Result<()> {
    std::fs::write(path, contents).with_context(|| format!("writing {}", path.display()))
}

/// Write a secret file at mode `0600`.
fn write_secret_file(path: &Path, contents: &[u8]) -> Result<()> {
    std::fs::write(path, contents).with_context(|| format!("writing {}", path.display()))?;
    restrict_file_mode(path)
}

#[cfg(unix)]
fn restrict_file_mode(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("restricting {} to 0600", path.display()))
}

#[cfg(not(unix))]
fn restrict_file_mode(_path: &Path) -> Result<()> {
    Ok(())
}

/// The real uid of the running process (the identity the broker attests).
fn current_uid() -> u32 {
    rustix::process::getuid().as_raw()
}

/// TOML-quote a path value.
fn toml_str(path: &Path) -> String {
    let escaped = path
        .display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn sleep(duration: Duration) {
    if !duration.is_zero() {
        std::thread::sleep(duration);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn temp_layout() -> (PathBuf, Layout) {
        let dir = std::env::temp_dir().join(format!(
            "basil-demo-test-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let layout = Layout::new(&dir);
        (dir, layout)
    }

    /// The load-bearing test: the generated demo catalog + policy pass the
    /// REAL loader, and the policy denies `get`/`rotate` while allowing the
    /// scripted ops, for the exact subject the demo evaluates.
    #[test]
    fn demo_pair_passes_loader_and_encodes_the_denial() {
        let (_dir, layout) = temp_layout();
        let catalog = build_catalog(&layout);
        let policy = build_policy(4242);

        let catalog_json = serde_json::to_string_pretty(&catalog).expect("ser catalog");
        let policy_json = serde_json::to_string_pretty(&policy).expect("ser policy");
        let loaded = crate::load(&catalog_json, &policy_json).expect("demo pair must load clean");
        assert!(loaded.3.is_empty(), "no loader warnings: {:?}", loaded.3);

        let role = policy.roles.get(ROLE).expect("demo role present");
        for denied in [Op::Get, Op::Set, Op::Rotate, Op::NewKey, Op::Import] {
            assert!(!role.contains(&denied), "{denied:?} must stay denied");
        }
        for allowed in [Op::Sign, Op::Verify, Op::Encrypt, Op::Decrypt, Op::Mint] {
            assert!(role.contains(&allowed), "{allowed:?} must be granted");
        }
    }

    /// The generated agent config parses through the real `AgentConfigFile`
    /// loader and resolves the paths the demo wrote.
    #[test]
    fn demo_config_loads_through_agent_config_file() {
        let (dir, layout) = temp_layout();
        std::fs::create_dir_all(&dir).expect("mk temp dir");
        std::fs::write(&layout.config, build_config_toml(&layout)).expect("write config");

        let overrides = crate::agent_cli::ConfigOverrides {
            config: Some(layout.config.clone()),
            values: Vec::new(),
        };
        let file =
            crate::agent_cli::load_config_file(&overrides).expect("agent parses demo config");
        assert_eq!(file.config.catalog, layout.catalog);
        assert_eq!(file.config.policy, layout.policy);
        assert_eq!(file.config.bundle, layout.bundle);
        assert_eq!(file.audit_log.as_deref(), Some(layout.audit.as_path()));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Workdir safety: an existing directory without the marker is refused
    /// (no --force), wiped with it, and re-created with the marker present.
    #[test]
    fn workdir_guard_refuses_foreign_directories() {
        let (dir, layout) = temp_layout();
        std::fs::create_dir_all(&dir).expect("mk temp dir");
        std::fs::write(dir.join("user-data.txt"), "precious").expect("plant user file");

        let err = prepare_workdir(&layout, false).expect_err("must refuse a foreign dir");
        assert!(err.to_string().contains(MARKER), "got: {err}");
        assert!(dir.join("user-data.txt").exists(), "user data untouched");

        prepare_workdir(&layout, true).expect("--force wipes");
        assert!(layout.marker.exists(), "marker written");
        assert!(!dir.join("user-data.txt").exists());

        // A second run now proceeds without --force (marker present).
        prepare_workdir(&layout, false).expect("marker allows re-run");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The DEK never ends in a byte `bundle create` would trim.
    #[test]
    fn dek_never_ends_in_newline() {
        for _ in 0..64 {
            let dek = random_dek();
            assert!(!matches!(dek.last(), Some(b'\n' | b'\r')));
        }
    }

    /// Display form quotes whitespace-bearing arguments for copy-paste.
    #[test]
    fn display_command_quotes_whitespace() {
        let cmd = display_command(&[
            "sign".to_string(),
            "--key-id".to_string(),
            SIGNING_KEY.to_string(),
            "release v1.0.0".to_string(),
        ]);
        assert_eq!(
            cmd,
            format!("basil sign --key-id {SIGNING_KEY} 'release v1.0.0'")
        );
    }

    /// The socket-length guard trips on absurdly deep dirs.
    #[test]
    fn socket_length_guard() {
        let deep = PathBuf::from(format!("/tmp/{}", "x".repeat(120)));
        let layout = Layout::new(&deep);
        assert!(layout.socket.as_os_str().len() > MAX_SOCKET_PATH);
    }
}
