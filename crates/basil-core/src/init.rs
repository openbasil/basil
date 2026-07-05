//! `basil config init`: first-run scaffolding (basil-p50).
//!
//! Generates a minimal, valid, **least-privilege** starter set into a target
//! directory so a new operator can stand up a local broker without hand-authoring
//! JSON/TOML from scratch:
//!
//! - `catalog.json`, one working example key for the chosen backend;
//! - `policy.json` grants only the running uid a narrow `signer` role over that
//!   one key, default-deny everywhere else;
//! - `basil-agent.toml` points at the catalog/policy/bundle/socket it writes;
//! - printed **next steps**: the exact `basil bundle create ...` command for the
//!   chosen unlock method, then `check` / `run` / a `basil sign` round-trip.
//!
//! `init` writes **configuration/scaffolding only**, never secret material. It
//! does NOT create the sealed bundle (that needs interactive unlock material); it
//! PRINTS the bundle-bootstrap command instead. The catalog/policy JSON are
//! produced by serializing the **real** schema/wire types (`Catalog`,
//! [`RawPolicy`](crate::catalog::RawPolicy)), so the output is valid by
//! construction and cannot drift from what [`load`](crate::catalog::load) parses.
//!
//! No-clobber: an existing target file is refused unless `--force`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::catalog::{
    BackendKind, BackendRef, Catalog, Class, Config, Engine, KeyAlgorithm, KeyEntry, Labels,
    MissingPolicy, NameTable, Op, PrincipalSpec, RawPolicy, RawRule, RawSubjectDefinition,
};
use anyhow::{Context, Result, bail};
use clap::{Args, ValueEnum};

/// The catalog key name of the scaffolded example signing key. Matches the
/// `basil` CLI's `sign --key-id` default so the printed round-trip Just Works.
const EXAMPLE_KEY: &str = "example.signing_key";
/// The catalog backend name the scaffolded key routes to.
const BACKEND_NAME: &str = "primary";
/// The least-privilege role granted to the running uid (sign + verify + the
/// public-key read needed to verify).
const SIGNER_ROLE: &str = "example-signer";

/// `init` subcommand arguments.
#[derive(Debug, Args)]
pub struct InitArgs {
    /// The backend the scaffolded broker will route its example key to.
    #[arg(long, value_enum, default_value_t = InitBackend::Openbao)]
    backend: InitBackend,

    /// The unlock method whose `bundle create` command the next-steps output prints.
    /// `init` never seals a bundle; this only selects which command to show.
    #[arg(long, value_enum, default_value_t = InitUnlock::Bip39)]
    unlock: InitUnlock,

    /// Directory to write `catalog.json`, `policy.json`, and `basil-agent.toml`
    /// into (created if absent). The sealed bundle + unix socket paths in the
    /// generated config also live under here.
    #[arg(long, value_name = "DIR", default_value = "./basil")]
    dir: PathBuf,

    /// Backend address for the `vault`/`openbao` backends (a Vault-compatible
    /// HTTP URL). Ignored for the `keystore` backend, whose `addr` is a local DB
    /// file path under the target dir.
    #[arg(long, default_value = "http://127.0.0.1:8200")]
    addr: String,

    /// Transit secrets-engine mount the example key lives under (vault/openbao
    /// only). The default matches a stock `transit` mount.
    #[arg(long, default_value = "transit")]
    transit_mount: String,

    /// Existing 0600 passphrase file to bake into the generated
    /// `unlock-passphrase-file` config and printed `bundle create --slot`
    /// command. Only valid with `--unlock passphrase`.
    #[arg(long, value_name = "PATH")]
    passphrase_file: Option<PathBuf>,

    /// Overwrite any target file that already exists. Without it, `init` refuses
    /// and reports which files are in the way (no clobber).
    #[arg(long)]
    force: bool,
}

/// The backend kind to scaffold for. `openbao` and `vault` share one wire API
/// (one [`BackendKind::Vault`]) and differ only in the bundle-bootstrap CLI; the
/// distinction is kept so the printed commands name the right binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum InitBackend {
    /// `OpenBao` (the `bao` CLI) over the Vault-compatible transit engine.
    Openbao,
    /// `HashiCorp` Vault (the `vault` CLI) over its transit engine.
    Vault,
    /// The local materialize-to-use db-keystore backend (no external server).
    Keystore,
}

/// The unlock method whose `bundle create` invocation the next-steps prints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum InitUnlock {
    /// A 24-word `BIP39` break-glass phrase (shown once at `bundle create`).
    Bip39,
    /// A production passphrase file.
    Passphrase,
    /// A TPM2 sealed slot bound to host PCR state (broker built with the
    /// `unlock-tpm` feature; sealed to the host `TPM` at `bundle create` time).
    Tpm,
    /// An age + age-plugin-yubikey hardware slot (enrolled out of band).
    AgeYubikey,
}

impl InitBackend {
    /// The catalog [`BackendKind`] this scaffolds.
    const fn kind(self) -> BackendKind {
        match self {
            Self::Openbao | Self::Vault => BackendKind::Vault,
            Self::Keystore => BackendKind::Keystore,
        }
    }

    /// The server CLI binary that bootstraps the engine + writes the cred token,
    /// for the vault-family backends. `None` for keystore (no server).
    const fn server_cli(self) -> Option<&'static str> {
        match self {
            Self::Openbao => Some("bao"),
            Self::Vault => Some("vault"),
            Self::Keystore => None,
        }
    }

    /// Human label for the next-steps banner.
    const fn label(self) -> &'static str {
        match self {
            Self::Openbao => "OpenBao",
            Self::Vault => "HashiCorp Vault",
            Self::Keystore => "db-keystore",
        }
    }
}

/// Paths of everything `init` writes, all under the target directory.
struct Layout {
    dir: PathBuf,
    catalog: PathBuf,
    policy: PathBuf,
    config: PathBuf,
    /// Where the operator is told to write the sealed bundle (init does NOT
    /// create it).
    bundle: PathBuf,
    /// The unix socket the generated config binds.
    socket: PathBuf,
    /// (keystore only) the local DB file the keystore backend `addr` points at.
    keystore_db: PathBuf,
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
        }
    }

    /// The three files `init` writes (in clobber-check order).
    fn written(&self) -> [&Path; 3] {
        [&self.catalog, &self.policy, &self.config]
    }
}

/// Run `basil config init`: build the scaffolding, refuse to clobber unless
/// `--force`, write the files, and print the next-steps summary.
pub fn run(args: &InitArgs) -> Result<()> {
    validate_args(args)?;

    let layout = Layout::new(&args.dir);

    std::fs::create_dir_all(&layout.dir)
        .with_context(|| format!("creating target dir {}", layout.dir.display()))?;

    refuse_clobber(&layout, args.force)?;

    let uid = current_uid();

    let catalog = build_catalog(args, &layout);
    let policy = build_policy(uid);

    // Serialize the REAL schema/wire types (pretty), then validate the pair
    // through the SAME loader `check`/`run` use: fail closed if the scaffold is
    // somehow invalid rather than writing a broken starter set.
    let catalog_json = serde_json::to_string_pretty(&catalog).context("serializing catalog")?;
    let policy_json = serde_json::to_string_pretty(&policy).context("serializing policy")?;
    crate::load(&catalog_json, &policy_json)
        .context("the generated catalog/policy did not pass loader validation (internal bug)")?;

    let config_toml = build_config_toml(args, &layout);

    write_file(&layout.catalog, &format!("{catalog_json}\n"))?;
    write_file(&layout.policy, &format!("{policy_json}\n"))?;
    write_file(&layout.config, &config_toml)?;

    print_next_steps(args, &layout, uid);
    Ok(())
}

/// Refuse to overwrite any existing target file unless `--force`, listing every
/// offending path so the operator sees them all at once.
fn refuse_clobber(layout: &Layout, force: bool) -> Result<()> {
    if force {
        return Ok(());
    }
    let existing: Vec<String> = layout
        .written()
        .into_iter()
        .filter(|p| p.exists())
        .map(|p| p.display().to_string())
        .collect();
    if existing.is_empty() {
        return Ok(());
    }
    bail!(
        "refusing to overwrite existing file(s): {}\n(pass --force to overwrite)",
        existing.join(", ")
    );
}

/// Build the one-key example [`Catalog`] for the chosen backend.
///
/// - vault/openbao: a **transit** Ed25519 signing key with `missing: generate`,
///   so startup reconcile creates it in place on the first run.
/// - keystore: a `kind: keystore` backend with an Ed25519 signing key over its
///   in-keystore `transit` engine, also `missing: generate`.
fn build_catalog(args: &InitArgs, layout: &Layout) -> Catalog {
    let (addr, engines) = match args.backend {
        InitBackend::Openbao | InitBackend::Vault => (args.addr.clone(), vec![Engine::Transit]),
        InitBackend::Keystore => (
            layout.keystore_db.display().to_string(),
            vec![Engine::Transit, Engine::Kv2],
        ),
    };

    let mut backends = BTreeMap::new();
    backends.insert(
        BACKEND_NAME.to_string(),
        BackendRef {
            kind: args.backend.kind(),
            addr,
            engines,
            capabilities: Vec::new(),
            mint_key_types: vec![KeyAlgorithm::Ed25519],
            requires: Vec::new(),
        },
    );

    // The transit key path: a BARE key name for vault/openbao (the transit
    // backend composes the verb sub-path `transit/<verb>/<name>` itself, and the
    // configured `transit-mount` is prepended, and a `<mount>/keys/<name>` catalog
    // path would double the mount and 404 with "unsupported path", `vault-w3n`);
    // a slugged name for the keystore. The catalog `path` is the backend-native
    // locator, opaque to policy.
    let path = match args.backend {
        InitBackend::Openbao | InitBackend::Vault => "example-signing-key".to_string(),
        InitBackend::Keystore => "example/signing-key".to_string(),
    };

    let mut keys = BTreeMap::new();
    keys.insert(
        EXAMPLE_KEY.to_string(),
        KeyEntry {
            class: Class::Asymmetric,
            key_type: Some(KeyAlgorithm::Ed25519),
            backend: BACKEND_NAME.to_string(),
            engine: Some(Engine::Transit),
            path,
            public_path: None,
            writable: true,
            // Created in place by startup reconcile on first run.
            missing: MissingPolicy::Generate,
            generate: None,
            sealing_pin: None,
            labels: Labels::default(),
            description: "Example Ed25519 signing key scaffolded by `basil config init`."
                .to_string(),
        },
    );

    Catalog {
        schema_version: 1,
        backends,
        keys,
    }
}

/// Build the least-privilege [`RawPolicy`]: one `signer` role (sign + verify +
/// the public-key read verify needs), granted to **only** the running uid over
/// **only** the one example key. Everything else is default-deny.
fn build_policy(uid: u32) -> RawPolicy {
    let mut roles = BTreeMap::new();
    roles.insert(
        SIGNER_ROLE.to_string(),
        BTreeSet::from([Op::Sign, Op::Verify, Op::GetPublicKey]),
    );

    let rule = RawRule {
        id: "running-user-may-sign-example-key".to_string(),
        subjects: vec!["init.user".to_string()],
        action: vec![format!("role:{SIGNER_ROLE}")],
        target: vec![EXAMPLE_KEY.to_string()],
        comment: Some(
            "Least-privilege: only the uid that ran `basil config init` may sign/verify \
             the one example key. Everything else is default-deny."
                .to_string(),
        ),
    };

    let mut names = NameTable::default();
    names.users.insert(uid, "init-user".to_string());
    let mut memberships = BTreeMap::new();
    memberships.insert(uid, BTreeSet::new());
    let mut subjects = BTreeMap::new();
    subjects.insert(
        "init.user".to_string(),
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
        schema_version: 2,
        subjects,
        unauthenticated_subject: None,
        roles,
        rules: vec![rule],
        config: Config { names, memberships },
    }
}

/// Build the commented TOML agent config pointing at everything `init` writes.
/// Comments are allowed in TOML (the catalog/policy JSON round-trip through the
/// real types); the keystore arm adds the `db-keystore-cipher` line.
fn build_config_toml(args: &InitArgs, layout: &Layout) -> String {
    let mut out = String::new();
    out.push_str("# basil-agent config scaffolded by `basil config init`.\n");
    out.push_str("# Edit the placeholders, create the sealed bundle (see the printed\n");
    out.push_str(
        "# next-steps), then `basil config check -c this-file` and `run -c this-file`.\n\n",
    );
    let _ = writeln!(out, "catalog = {}", toml_str(&layout.catalog));
    let _ = writeln!(out, "policy = {}", toml_str(&layout.policy));
    out.push_str("# The sealed bundle is NOT created by init. Create it with `bundle create`.\n");
    let _ = writeln!(out, "bundle = {}", toml_str(&layout.bundle));
    let _ = writeln!(out, "socket = {}", toml_str(&layout.socket));
    out.push_str("# Socket mode defaults to 0600 (owner-only); widen deliberately if a peer\n");
    out.push_str("# group must connect, e.g. socket-mode = \"0660\" + socket-group = \"basil\".\n");
    out.push_str("socket-mode = \"0600\"\n");

    if args.backend == InitBackend::Keystore {
        out.push_str("\n# db-keystore backend: the local AEAD cipher for the at-rest DB.\n");
        out.push_str("db-keystore-cipher = \"aegis256\"\n");
    } else {
        let _ = writeln!(out, "vault-addr = {}", toml_str_s(&args.addr));
        let _ = writeln!(
            out,
            "transit-mount = {}",
            toml_str_s(trim_mount(&args.transit_mount))
        );
    }

    out.push('\n');
    out.push_str("[unlock]\n");
    match args.unlock {
        InitUnlock::Bip39 => {
            out.push_str(
                "# Unlock with the `BIP39` break-glass phrase from `bundle create --slot bip39`.\n",
            );
            out.push_str(
                "# TODO: point bip39-phrase-file at a 0600 file holding the 24-word phrase.\n",
            );
            out.push_str("bip39-phrase-file = \"REPLACE_WITH_PATH_TO_BIP39_PHRASE_FILE\"\n");
        }
        InitUnlock::Passphrase => {
            out.push_str("# Unlock with a passphrase read from a 0600 file.\n");
            out.push_str("# TODO: point unlock-passphrase-file at the runtime credential file.\n");
            let passphrase_file = args.passphrase_file.as_deref().map_or_else(
                || toml_str_s("REPLACE_WITH_PATH_TO_PASSPHRASE_FILE"),
                toml_str,
            );
            let _ = writeln!(out, "unlock-passphrase-file = {passphrase_file}");
        }
        InitUnlock::Tpm => {
            out.push_str("# Unlock with a TPM2 sealed slot bound to host PCR state.\n");
            out.push_str("# Requires the broker built with --features unlock-tpm and a host TPM\n");
            out.push_str("# (/dev/tpmrm0); availability is the runtime device probe, no secret.\n");
            out.push_str("unlock-tpm = true\n");
        }
        InitUnlock::AgeYubikey => {
            out.push_str("# Unlock with an enrolled age + age-plugin-yubikey hardware slot.\n");
            out.push_str("age-yubikey = true\n");
        }
    }
    out.push('\n');
    out.push_str("[broker-identity]\n");
    out.push_str("# Required when [invocation] enable = true.\n");
    out.push_str("# id = \"basil://prod/us-east-1/agent-a\"\n");
    out.push_str("# response-signing-key-id = \"broker.response_signing.2026q3\"\n");
    out.push('\n');
    out.push_str("[invocation]\n");
    out.push_str("# Sealed bridged invocation is compiled in but disabled by default.\n");
    out.push_str("enable = false\n");
    out.push_str("# audience = [\"basil://prod/us-east-1/agent-a\"]\n");
    out.push_str("# request-encryption-key-id = \"broker.request_encryption.2026q3\"\n");
    out.push_str("# max-ttl-secs = 60\n");
    out.push_str("# clock-skew-secs = 30\n");
    out.push_str("# replay-cache-capacity = 4096\n");
    out
}

/// Print the concrete next-steps: the exact `bundle create` for the chosen unlock
/// method + backend cred, then `check`, `run`, and a `basil sign` round-trip.
fn print_next_steps(args: &InitArgs, layout: &Layout, uid: u32) {
    let cfg = layout.config.display();
    println!(
        "Scaffolded a {} starter set in {}:",
        args.backend.label(),
        layout.dir.display()
    );
    println!("  catalog: {}", layout.catalog.display());
    println!(
        "  policy:  {} (grants only uid {uid} sign/verify over `{EXAMPLE_KEY}`)",
        layout.policy.display()
    );
    println!("  config:  {cfg}");
    println!();
    println!("init writes config/scaffolding ONLY: no secret material, and NOT the sealed bundle.");
    println!();

    println!("Next steps:");
    println!();
    println!("1. Create the sealed credential bundle (init cannot: it needs unlock material):");
    print_bundle_init(args, layout);
    println!();

    if let Some(cli) = args.backend.server_cli() {
        println!(
            "   The bundle's backend credential must be a token for a running {}",
            args.backend.label()
        );
        println!(
            "   with the `{}` transit mount enabled. For a dev server:",
            trim_mount(&args.transit_mount)
        );
        println!("       {cli} secrets enable transit");
        println!(
            "   (reconcile will create the `{EXAMPLE_KEY}` key on first run, missing=generate.)"
        );
    } else {
        println!("   Build the agent with the keystore backend: --features db-keystore");
        println!("   and seed a 32-byte DEK file for the bundle's DbKeystoreDek credential.");
    }
    println!();

    println!("2. Validate the config (offline + backend probe):");
    println!("       basil config check -c {cfg}");
    println!();
    println!("3. Run the broker:");
    println!("       basil agent -c {cfg}");
    println!();
    println!("4. Exercise the example key over the socket:");
    println!(
        "       basil --socket {} sign --key-id {EXAMPLE_KEY} 'hello basil'",
        layout.socket.display()
    );
}

/// Print the exact `basil bundle create ...` command for the chosen unlock
/// method + backend, using only real flags.
fn print_bundle_init(args: &InitArgs, layout: &Layout) {
    let out = layout.bundle.display();
    let slot = bundle_init_slot_flag(args);
    let cred = match args.backend {
        InitBackend::Openbao | InitBackend::Vault => {
            format!(
                "--backend id={BACKEND_NAME},type=openbao,addr=REPLACE_WITH_BACKEND_ADDR,token-file=REPLACE_WITH_BACKEND_TOKEN_FILE"
            )
        }
        InitBackend::Keystore => {
            format!(
                "--backend id={BACKEND_NAME},type=db-keystore,path=REPLACE_WITH_DB_PATH,dek-file=REPLACE_WITH_PATH_TO_32BYTE_DEK_FILE"
            )
        }
    };
    println!("       basil bundle create {out} \\");
    println!("           --slot {slot} \\");
    println!("           {cred}");
    if args.unlock == InitUnlock::Tpm {
        println!(
            "   (the TPM slot seals to THIS host's TPM at `bundle create` time; run it on \
             the target host with /dev/tpmrm0 and a broker built with --features unlock-tpm.)"
        );
    }
    if args.unlock == InitUnlock::AgeYubikey {
        println!(
            "   (age-yubikey needs a recipient in `--slot age-yubikey:recipient=...`; \
             a bip39 break-glass slot is shown above so the bundle is creatable.)"
        );
    }
}

/// The `bundle create --slot` value the next-steps prints for the chosen unlock
/// method.
fn bundle_init_slot_flag(args: &InitArgs) -> String {
    match args.unlock {
        InitUnlock::Passphrase => {
            let path = args.passphrase_file.as_deref().map_or_else(
                || "REPLACE_WITH_PATH_TO_PASSPHRASE_FILE".to_string(),
                |path| path.display().to_string(),
            );
            format!("passphrase:file={path}")
        }
        InitUnlock::Tpm => "tpm".to_string(),
        InitUnlock::Bip39 | InitUnlock::AgeYubikey => "bip39".to_string(),
    }
}

/// Validate argument combinations before writing any scaffold files.
fn validate_args(args: &InitArgs) -> Result<()> {
    if args.passphrase_file.is_some() && args.unlock != InitUnlock::Passphrase {
        bail!("--passphrase-file can only be used with --unlock passphrase");
    }
    Ok(())
}

/// Write a scaffold file (config/catalog/policy are non-secret; default perms).
fn write_file(path: &Path, contents: &str) -> Result<()> {
    std::fs::write(path, contents).with_context(|| format!("writing {}", path.display()))
}

/// Resolve the real uid of the running process, the authorization anchor the
/// policy grant binds to, the same identity the broker proves at runtime via
/// `SO_PEERCRED`. Uses `rustix`'s safe `getuid()` so it works on Linux and
/// macOS alike (no `/proc` dependency) and never panics.
fn current_uid() -> u32 {
    rustix::process::getuid().as_raw()
}

/// Strip a single trailing `/` from a mount path so `path = "<mount>/keys/<k>"`
/// never doubles the separator.
fn trim_mount(mount: &str) -> &str {
    mount.strip_suffix('/').unwrap_or(mount)
}

/// TOML-quote a path value.
fn toml_str(path: &Path) -> String {
    toml_str_s(&path.display().to_string())
}

/// TOML-quote a string value (basic-string escaping of `\` and `"`).
fn toml_str_s(s: &str) -> String {
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args_for(backend: InitBackend, unlock: InitUnlock, dir: &Path) -> InitArgs {
        InitArgs {
            backend,
            unlock,
            dir: dir.to_path_buf(),
            addr: "http://127.0.0.1:8200".to_string(),
            transit_mount: "transit".to_string(),
            passphrase_file: None,
            force: false,
        }
    }

    fn temp_dir() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "basil-init-test-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&p).expect("mk temp dir");
        p
    }

    /// The load-bearing test: the generated catalog + policy for EVERY backend
    /// kind pass the REAL loader/validation (the same `load` path `check` uses).
    #[test]
    fn generated_pair_passes_real_loader_for_every_backend() {
        for backend in [
            InitBackend::Openbao,
            InitBackend::Vault,
            InitBackend::Keystore,
        ] {
            let dir = temp_dir();
            let layout = Layout::new(&dir);
            let args = args_for(backend, InitUnlock::Bip39, &dir);
            let catalog = build_catalog(&args, &layout);
            let policy = build_policy(4242);

            let catalog_json = serde_json::to_string_pretty(&catalog).expect("ser catalog");
            let policy_json = serde_json::to_string_pretty(&policy).expect("ser policy");
            let loaded = crate::load(&catalog_json, &policy_json)
                .unwrap_or_else(|e| panic!("{backend:?} pair must load clean: {e}"));
            let warnings = loaded.3;
            assert!(
                warnings.is_empty(),
                "{backend:?} pair should load without warnings, got {warnings:?}"
            );
            std::fs::remove_dir_all(&dir).ok();
        }
    }

    /// The policy grants ONLY the generated Unix subject for the running uid and
    /// only over the one example key.
    #[test]
    fn policy_grants_only_the_running_uid() {
        let uid = 9931;
        let policy = build_policy(uid);
        assert_eq!(policy.rules.len(), 1);
        let rule = policy.rules.first().expect("one rule");
        assert_eq!(rule.subjects, vec!["init.user".to_string()]);
        assert_eq!(rule.target, vec![EXAMPLE_KEY.to_string()]);
        assert_eq!(policy.subjects.len(), 1);
        // The signer role is sign/verify/get_public_key only. No write ops.
        let signer = policy.roles.get(SIGNER_ROLE).expect("signer role present");
        assert!(
            !signer.iter().any(|op| op.is_write()),
            "signer role must hold no write op"
        );
    }

    /// `run` refuses to clobber an existing target file without `--force`, and
    /// overwrites with it.
    #[test]
    fn refuses_to_clobber_without_force() {
        let dir = temp_dir();
        let args = args_for(InitBackend::Openbao, InitUnlock::Bip39, &dir);

        run(&args).expect("first init writes clean");
        let layout = Layout::new(&dir);
        assert!(layout.catalog.exists() && layout.policy.exists() && layout.config.exists());

        // Second run without --force must refuse (and name the offenders).
        let err = run(&args).expect_err("second init must refuse");
        let msg = err.to_string();
        assert!(msg.contains("refusing to overwrite"), "got: {msg}");

        // With --force it overwrites.
        let forced = InitArgs {
            force: true,
            ..args_for(InitBackend::Openbao, InitUnlock::Bip39, &dir)
        };
        run(&forced).expect("forced init overwrites");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The written catalog/policy files on disk reload through the real loader
    /// (end-to-end through `run`, not just the in-memory structs).
    #[test]
    fn written_files_reload_through_the_loader() {
        let dir = temp_dir();
        let args = args_for(InitBackend::Keystore, InitUnlock::Passphrase, &dir);
        run(&args).expect("init writes");
        let layout = Layout::new(&dir);

        let catalog_json = std::fs::read_to_string(&layout.catalog).expect("read catalog");
        let policy_json = std::fs::read_to_string(&layout.policy).expect("read policy");
        crate::load(&catalog_json, &policy_json).expect("written pair must reload");

        // The TOML config parses and points at the files init wrote.
        let config = std::fs::read_to_string(&layout.config).expect("read config");
        let parsed: toml::Value = toml::from_str(&config).expect("config is valid TOML");
        assert_eq!(
            parsed.get("catalog").and_then(toml::Value::as_str),
            Some(layout.catalog.display().to_string().as_str())
        );
        // Socket mode defaults to 0600 (owner-only) in the generated config.
        assert_eq!(
            parsed.get("socket-mode").and_then(toml::Value::as_str),
            Some("0600")
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The generated TOML config parses through the REAL `AgentConfigFile`
    /// loader the daemon uses (`crate::load_config_file`), and resolves to the
    /// catalog/policy/bundle/socket paths init wrote with the 0600 socket mode.
    /// The vault/openbao arm needs no feature; the keystore arm emits a
    /// feature-gated `db-keystore-cipher` so it is gated to match.
    #[test]
    fn generated_config_loads_through_agent_config_file() {
        let dir = temp_dir();
        let args = args_for(InitBackend::Openbao, InitUnlock::Bip39, &dir);
        run(&args).expect("init writes");
        let layout = Layout::new(&dir);

        let overrides = crate::agent_cli::ConfigOverrides {
            config: Some(layout.config.clone()),
            catalog: None,
            policy: None,
            bundle: None,
            socket: None,
            vault_addr: None,
        };
        let file =
            crate::agent_cli::load_config_file(&overrides).expect("agent parses generated config");
        assert_eq!(file.catalog.as_deref(), Some(layout.catalog.as_path()));
        assert_eq!(file.policy.as_deref(), Some(layout.policy.as_path()));
        assert_eq!(file.bundle.as_deref(), Some(layout.bundle.as_path()));
        assert_eq!(
            file.socket.as_deref(),
            Some(layout.socket.display().to_string().as_str())
        );
        // Socket mode default is 0600 (owner-only).
        let mode = file.socket_mode.expect("socket-mode set");
        assert_eq!(mode.0, 0o600);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(feature = "keystore-backend")]
    #[test]
    fn generated_keystore_config_loads_through_agent_config_file() {
        let dir = temp_dir();
        let args = args_for(InitBackend::Keystore, InitUnlock::AgeYubikey, &dir);
        run(&args).expect("init writes");
        let layout = Layout::new(&dir);

        let overrides = crate::agent_cli::ConfigOverrides {
            config: Some(layout.config),
            catalog: None,
            policy: None,
            bundle: None,
            socket: None,
            vault_addr: None,
        };
        crate::agent_cli::load_config_file(&overrides)
            .expect("agent parses generated keystore config (db-keystore-cipher key)");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// `--unlock tpm` generates `unlock-tpm = true` in the `[unlock]` section and
    /// the next-steps prints a `bundle create ... --slot tpm` command.
    #[test]
    fn tpm_unlock_generates_config_and_bundle_command() {
        let dir = Path::new("/unused-init-dir");
        let layout = Layout::new(dir);
        let args = args_for(InitBackend::Openbao, InitUnlock::Tpm, dir);

        let toml = build_config_toml(&args, &layout);
        assert!(
            toml.contains("unlock-tpm = true"),
            "tpm config must set unlock-tpm = true, got:\n{toml}"
        );
        assert!(!toml.contains("unlock-passphrase-file"), "got:\n{toml}");

        // The printed `bundle create` command uses the real `tpm` slot value.
        assert_eq!(bundle_init_slot_flag(&args), "tpm");
    }

    #[test]
    fn passphrase_file_is_baked_into_config_and_bundle_command() {
        let dir = Path::new("/unused-init-dir");
        let layout = Layout::new(dir);
        let passphrase = dir.join("passphrase.txt");
        let args = InitArgs {
            passphrase_file: Some(passphrase.clone()),
            ..args_for(InitBackend::Openbao, InitUnlock::Passphrase, dir)
        };

        let toml = build_config_toml(&args, &layout);
        assert!(
            toml.contains(&format!(
                "unlock-passphrase-file = \"{}\"",
                passphrase.display()
            )),
            "passphrase config must use the provided file, got:\n{toml}"
        );
        assert_eq!(
            bundle_init_slot_flag(&args),
            format!("passphrase:file={}", passphrase.display())
        );
    }

    #[test]
    fn passphrase_file_requires_passphrase_unlock() {
        let dir = temp_dir();
        let args = InitArgs {
            passphrase_file: Some(dir.join("passphrase.txt")),
            ..args_for(InitBackend::Openbao, InitUnlock::Bip39, &dir)
        };

        let err = run(&args).expect_err("invalid unlock combination must fail");
        assert!(
            err.to_string().contains("--unlock passphrase"),
            "got: {err}"
        );
    }

    #[test]
    fn current_uid_resolves_to_a_number() {
        // Smoke: the real-uid resolver returns *some* uid and never panics.
        // Mostly just asserting it ran; any u32 is acceptable.
        let _uid = current_uid();
    }
}
