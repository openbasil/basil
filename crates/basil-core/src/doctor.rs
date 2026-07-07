// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! `basil doctor`: preflight environment & deployment checks (basil-f0j).
//!
//! Doctor runs a set of **independent**, read-only diagnostics against a resolved
//! daemon config and reports each as a structured
//! [`CheckResult`] with actionable remediation. It is a pre-deploy / first-boot
//! sanity gate: it answers "will `basil agent` even get off the ground here?"
//! It has two tiers, split on whether the sealed bundle is unlocked:
//!
//! - **`basil doctor`** (OFFLINE, no unlock): catalog/policy load, backend
//!   capability enforcement, invocation broker-identity/key bindings, feature
//!   compatibility, backend binary on PATH, socket, bundle perms/freshness, and
//!   backend health reachability. It never unlocks the bundle, binds the socket,
//!   or mutates anything.
//! - **`basil doctor --keys`** (UNLOCK): additionally unlocks the sealed bundle
//!   and runs an authenticated, read-only per-key existence probe. Still never
//!   reconciles, generates, writes a sidecar, or binds the socket.
//!
//! ## Invariants (load-bearing)
//!
//! - **No panic.** Every step handles its error into a check *failure*; one check
//!   erroring never aborts the others. All results are collected, then the exit
//!   code is decided.
//! - **No secrets by default.** The bundle check reports **readability, permissions, and
//!   freshness only**, never bundle contents, key material, passphrases, or
//!   tokens. No secret byte reaches stdout, the JSON, or an error string. The
//!   bundle is parsed for its public header (epoch) but never unlocked.
//! - **No mutation.** Default doctor never unlocks; the explicit `--keys`
//!   key-material mode unlocks only to read. Neither mode reconciles, generates a
//!   key, writes a sidecar, or binds the socket. The epoch-sidecar check is
//!   read-only (unlike [`crate::seal::verify_epoch_sidecar`], which advances the
//!   sidecar).
//!
//! ## Severity & exit
//!
//! Each check is `ok` / `warn` / `fatal`. A **fatal** condition would stop the
//! broker/service from starting (catalog won't load, backend unreachable, bundle
//! won't unlock, a `missing=error` key reconcile cannot satisfy). Everything else
//! (a `missing=generate` key, an optional key absent, `bao` not on PATH, loose
//! bundle perms) is a **warning**: advisory, report-only.
//!
//! The caller maps `any fatal → nonzero exit`. Warnings alone exit `0` unless
//! `--strict` is passed, which also makes warnings exit nonzero. The return code
//! is derived from the worst severity among the checks that ran.

use std::path::Path;
use std::time::Duration;

use rand::RngCore;
use serde::Serialize;

use crate::catalog::BackendKind;

/// Stable schema version of the `--json` document. Bump on a breaking shape
/// change; operators script against this.
pub const DOCTOR_SCHEMA_VERSION: u32 = 2;

/// Bounded per-backend reachability timeout. A down backend must be FATAL for the
/// check, never hang the whole run.
const REACHABILITY_TIMEOUT: Duration = Duration::from_secs(3);

/// The outcome of a single diagnostic check.
///
/// `Ok` passes; `Warn` is advisory (exits nonzero only under `--strict`); `Fatal`
/// is blocking (the run exits nonzero, a condition that would stop the broker from
/// starting). The string tokens (`ok` / `warn` / `fatal`) are the stable JSON
/// values that operators match on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    /// The check passed.
    Ok,
    /// Advisory: a non-ideal condition that does not stop startup.
    Warn,
    /// Blocking: this would prevent (or endanger) a clean `run`.
    Fatal,
}

/// One diagnostic result: a named check, its status, a human-readable detail,
/// and (for non-ok results) actionable remediation text.
///
/// `name` is a stable machine identifier (`snake_case`, scriptable); per-key
/// probe rows carry a `key_material:<key>` name. `detail` and `remediation` are
/// operator-facing prose and may change wording freely. **No field ever carries a
/// secret** (the bundle arm reports perms/freshness only; key rows carry catalog
/// key *names*, which are public config, never key material).
#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    /// Stable machine identifier for the check (e.g. `backend_reachability`).
    pub name: String,
    /// Pass / advisory / blocking.
    pub status: CheckStatus,
    /// Human-readable description of what was found.
    pub detail: String,
    /// Actionable fix for a non-ok result (empty for `ok`).
    pub remediation: String,
}

impl CheckResult {
    pub(crate) fn ok(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: CheckStatus::Ok,
            detail: detail.into(),
            remediation: String::new(),
        }
    }

    pub(crate) fn warn(
        name: impl Into<String>,
        detail: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            status: CheckStatus::Warn,
            detail: detail.into(),
            remediation: remediation.into(),
        }
    }

    pub(crate) fn fatal(
        name: impl Into<String>,
        detail: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            status: CheckStatus::Fatal,
            detail: detail.into(),
            remediation: remediation.into(),
        }
    }
}

/// A non-secret summary of a doctor run: per-status counts and the fatal flag.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct DoctorSummary {
    /// Total number of checks run.
    pub total: usize,
    /// Count of `ok` checks.
    pub ok: usize,
    /// Count of `warn` (advisory) checks.
    pub warn: usize,
    /// Count of `fatal` (blocking) checks.
    pub fatal: usize,
    /// True iff at least one check is `fatal` (the run exits nonzero even without
    /// `--strict`).
    pub blocking: bool,
}

/// The full doctor document: a stable, versioned shape an operator scripts on.
#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    /// Stable schema version of this document.
    pub schema_version: u32,
    /// Every check result, in a deterministic order.
    pub checks: Vec<CheckResult>,
    /// Roll-up counts + the fatal flag.
    pub summary: DoctorSummary,
}

impl DoctorReport {
    /// Build a report from a set of independent results, computing the summary.
    #[must_use]
    pub fn from_checks(checks: Vec<CheckResult>) -> Self {
        let mut ok = 0;
        let mut warn = 0;
        let mut fatal = 0;
        for c in &checks {
            match c.status {
                CheckStatus::Ok => ok += 1,
                CheckStatus::Warn => warn += 1,
                CheckStatus::Fatal => fatal += 1,
            }
        }
        let summary = DoctorSummary {
            total: checks.len(),
            ok,
            warn,
            fatal,
            blocking: fatal > 0,
        };
        Self {
            schema_version: DOCTOR_SCHEMA_VERSION,
            checks,
            summary,
        }
    }

    /// Whether the caller should exit nonzero. A fatal check always trips it; a
    /// warning trips it only under `strict`. The return code is thus derived from
    /// the worst severity among the checks that ran.
    #[must_use]
    pub const fn should_exit_nonzero(&self, strict: bool) -> bool {
        self.summary.fatal > 0 || (strict && self.summary.warn > 0)
    }
}

/// The resolved, non-secret inputs a doctor run needs.
///
/// Built by the binary from the same config/override resolution `run` uses, then
/// handed here so the check logic is free of clap/config-file plumbing.
#[derive(Debug, Clone)]
pub struct DoctorInputs {
    /// Path to the exported catalog JSON.
    pub catalog: std::path::PathBuf,
    /// Path to the exported policy JSON.
    pub policy: std::path::PathBuf,
    /// Path to the `0600` sealed bundle.
    pub bundle: std::path::PathBuf,
    /// The unix socket path the daemon would bind.
    pub socket: String,
    /// The configured socket mode (octal, e.g. `0o600`).
    pub socket_mode: u32,
    /// The configured socket group (numeric gid or name), if any.
    pub socket_group: Option<String>,
    /// The backend-capability enforcement policy (`strict` / `degraded` / `off`).
    pub capability_policy: crate::CapabilityPolicy,
    /// The resolved invocation-service runtime config, for offline broker-identity
    /// and key-binding validation.
    pub invocation: crate::service::broker::InvocationRuntimeConfig,
    /// Whether a passphrase unlock file is configured.
    pub unlock_passphrase_selected: bool,
    /// Whether a bip39 break-glass phrase file is configured.
    pub unlock_bip39_selected: bool,
    /// Whether the age-yubikey unlock slot is enabled.
    pub unlock_age_yubikey_selected: bool,
}

/// Which cargo features the running binary was compiled with, captured at the
/// call site via `cfg!` so the doctor logic stays a pure function (testable for
/// both presence and absence of a feature).
///
/// Each field maps 1:1 to a cargo feature flag; a sub-struct would not group them
/// more meaningfully than this flat capture, hence the `struct_excessive_bools`
/// allow.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy)]
pub struct EnabledFeatures {
    /// `keystore-backend` is compiled in.
    pub keystore_backend: bool,
    /// `aws-kms` is compiled in.
    pub aws_kms: bool,
    /// `gcp-kms` is compiled in.
    pub gcp_kms: bool,
    /// `unlock-bip39` is compiled in.
    pub unlock_bip39: bool,
    /// `unlock-age-yubikey` is compiled in.
    pub unlock_age_yubikey: bool,
}

impl EnabledFeatures {
    /// Capture the features of the **current** build.
    #[must_use]
    pub const fn current() -> Self {
        Self {
            keystore_backend: cfg!(feature = "keystore-backend"),
            aws_kms: cfg!(feature = "aws-kms"),
            gcp_kms: cfg!(feature = "gcp-kms"),
            unlock_bip39: cfg!(feature = "unlock-bip39"),
            unlock_age_yubikey: cfg!(feature = "unlock-age-yubikey"),
        }
    }
}

/// Run every OFFLINE diagnostic and assemble the report.
///
/// Checks are independent: a check that errors becomes a `fatal`/`warn` row and
/// never aborts the rest. This never unlocks the bundle; the caller appends the
/// `--keys` per-key probe rows (see [`key_material_rows`]).
///
/// The catalog is loaded once (its own check) and, if it parses, reused to derive
/// the capability, invocation-binding, backend-binary and reachability checks. A
/// catalog that fails to load yields a `fatal` row and the catalog-dependent
/// checks degrade gracefully (they report "skipped: catalog did not load").
pub async fn run_doctor(inputs: &DoctorInputs, features: EnabledFeatures) -> DoctorReport {
    let mut checks = Vec::new();

    // Load the catalog/policy once; the result drives downstream checks.
    let loaded = load_catalog_policy(&inputs.catalog, &inputs.policy);
    checks.push(catalog_policy_check(&loaded));

    // Offline config lints that need the loaded catalog (no unlock, no backend I/O).
    if let Ok(catalog) = loaded.as_ref() {
        checks.push(capability_check(catalog, inputs.capability_policy));
        checks.push(invocation_bindings_check(&inputs.invocation, catalog));
    } else {
        checks.push(catalog_dependent_skip("capability"));
        checks.push(catalog_dependent_skip("invocation_bindings"));
    }

    let backends = loaded.as_ref().ok().map(|c| c.backends.clone());

    checks.push(feature_compatibility_check(
        inputs,
        features,
        backends.as_ref(),
    ));
    checks.push(backend_binary_check(backends.as_ref()));
    checks.push(socket_check(
        &inputs.socket,
        inputs.socket_mode,
        inputs.socket_group.as_deref(),
    ));
    checks.extend(bundle_checks(&inputs.bundle));
    checks.push(backend_reachability_check(backends.as_ref()).await);

    DoctorReport::from_checks(checks)
}

/// A stable "skipped: catalog did not load" advisory row for a check that needs
/// the loaded catalog.
fn catalog_dependent_skip(name: &'static str) -> CheckResult {
    CheckResult::warn(
        name,
        "skipped: catalog did not load",
        "Fix the catalog/policy load first (see the catalog_policy check).",
    )
}

/// Build the authenticated per-key-material rows for `doctor --keys`.
///
/// This is intentionally not part of the default [`run_doctor`] boundary: its
/// caller must have explicitly unlocked the sealed bundle and run the read-only
/// [`crate::BackendManager::check`] probe. The rows are still non-secret: they
/// report catalog key *names* and counts, never backend tokens or key material.
///
/// Returns an aggregate `key_material` summary row plus one `key_material:<key>`
/// detail row per ABSENT key, classified by its `missing` policy: a `missing=error`
/// key reconcile cannot satisfy is **fatal**; a `missing=warn`/`missing=generate`
/// absence is a **warning**. A probe that could not run at all is a single fatal
/// `key_material` row (secret-free reason).
#[must_use]
pub fn key_material_rows(probe: Result<&crate::CheckReport, String>) -> Vec<CheckResult> {
    const NAME: &str = "key_material";
    let report = match probe {
        Ok(report) => report,
        Err(reason) => {
            drop(reason);
            return vec![CheckResult::fatal(
                NAME,
                "authenticated key-material probe failed",
                "Confirm the sealed bundle unlock settings and backend credentials, then rerun `basil doctor --keys` for the detailed probe.",
            )];
        }
    };

    let total = report.keys.len();
    let present = report.present_count();
    let required_missing = report.required_missing();

    // Aggregate summary row (stable `key_material` name for scripting).
    let summary = if required_missing.is_empty() {
        let optional_missing = report.missing().count();
        if optional_missing == 0 {
            CheckResult::ok(
                NAME,
                format!("all {total} catalog key(s) are present in the backend"),
            )
        } else {
            CheckResult::warn(
                NAME,
                format!(
                    "{present}/{total} catalog key(s) present; {optional_missing} optional key(s) absent"
                ),
                "Provision optional keys if their operations should be available, or let startup reconcile generate keys declared missing=generate.",
            )
        }
    } else {
        CheckResult::fatal(
            NAME,
            format!(
                "{present}/{total} catalog key(s) present; required key(s) absent: {}",
                required_missing.join(", ")
            ),
            "Provision the missing required key material, then rerun `basil doctor --keys`.",
        )
    };

    let mut rows = vec![summary];

    // Per-key detail rows for every ABSENT key, classified by its missing policy.
    for (name, policy) in report.missing() {
        let row_name = format!("key_material:{name}");
        let row = match policy {
            crate::catalog::MissingPolicy::Error => CheckResult::fatal(
                row_name,
                format!(
                    "required key `{name}` is absent (missing=error); reconcile cannot satisfy it"
                ),
                "Provision this key in its backend before starting the broker.",
            ),
            crate::catalog::MissingPolicy::Warn => CheckResult::warn(
                row_name,
                format!(
                    "key `{name}` is absent (missing=warn); operations on it fail until provisioned"
                ),
                "Provision the key if its operations should be available.",
            ),
            crate::catalog::MissingPolicy::Generate => CheckResult::warn(
                row_name,
                format!(
                    "key `{name}` is absent (missing=generate); startup reconcile will create it"
                ),
                "No action required unless you expected the key to already exist.",
            ),
        };
        rows.push(row);
    }

    rows
}

/// Load + validate the catalog/policy via the SAME loader `check`/`run` use. A
/// load/validation error is returned verbatim for the catalog/policy check row.
fn load_catalog_policy(catalog_path: &Path, policy_path: &Path) -> Result<crate::Catalog, String> {
    let catalog_json = std::fs::read_to_string(catalog_path)
        .map_err(|e| format!("reading catalog {}: {e}", catalog_path.display()))?;
    let policy_json = std::fs::read_to_string(policy_path)
        .map_err(|e| format!("reading policy {}: {e}", policy_path.display()))?;
    let (catalog, _policy, _config, _warnings) =
        crate::catalog::load(&catalog_json, &policy_json).map_err(|e| e.to_string())?;
    Ok(catalog)
}

fn catalog_policy_check(loaded: &Result<crate::Catalog, String>) -> CheckResult {
    const NAME: &str = "catalog_policy";
    match loaded {
        Ok(c) => CheckResult::ok(
            NAME,
            format!(
                "catalog + policy load and validate; {} backend(s)",
                c.backends.len()
            ),
        ),
        Err(reason) => CheckResult::fatal(
            NAME,
            format!("catalog/policy did not load: {reason}"),
            "Fix the catalog/policy export so it validates; the loader reason above names the \
             offending field.",
        ),
    }
}

/// Offline backend-capability enforcement: does each backend PROVIDE what the
/// catalog's keys (and explicit `requires`) need? Honors `capability-policy`;
/// under a policy that makes a gap fatal, an unmet requirement would fail broker
/// startup, so it is FATAL here too. Pure and offline (no backend I/O).
fn capability_check(catalog: &crate::Catalog, policy: crate::CapabilityPolicy) -> CheckResult {
    const NAME: &str = "capability";
    match crate::enforce_capabilities(catalog, policy) {
        Ok(s) => CheckResult::ok(
            NAME,
            format!(
                "backend capabilities cover the catalog: {} enforced, {} undeclared (skipped), {} warning(s)",
                s.enforced, s.skipped_undeclared, s.warnings
            ),
        ),
        Err(e) => CheckResult::fatal(
            NAME,
            format!("backend capability gap: {e}"),
            "Grant the backend the missing capabilities, or relax `capability-policy`; under the \
             configured policy this gap would fail broker startup.",
        ),
    }
}

/// Offline invocation validation: when invocation is enabled, its broker-identity
/// and request/response key bindings must resolve to catalog keys of the right
/// class and use. A bad binding would fail broker startup, so it is FATAL. Pure
/// and offline (no bundle, no backend).
fn invocation_bindings_check(
    invocation: &crate::service::broker::InvocationRuntimeConfig,
    catalog: &crate::Catalog,
) -> CheckResult {
    const NAME: &str = "invocation_bindings";
    if !invocation.enabled {
        return CheckResult::ok(
            NAME,
            "invocation is disabled; no broker-identity/key bindings to validate",
        );
    }
    match crate::agent_cli::validate_invocation_catalog_bindings(invocation, catalog) {
        Ok(()) => CheckResult::ok(
            NAME,
            "invocation broker-identity and request/response key bindings are valid",
        ),
        Err(e) => CheckResult::fatal(
            NAME,
            format!("invocation binding invalid: {e}"),
            "Fix the invocation broker-identity/key configuration; invocation is enabled but its \
             catalog bindings would fail broker startup.",
        ),
    }
}

/// Does the running binary's feature set support what the config asks for?
///
/// - bip39 phrase configured but `unlock-bip39` absent → FATAL.
/// - age-yubikey requested but `unlock-age-yubikey` absent → FATAL.
/// - A `keystore`-kind backend in the catalog but `keystore-backend` absent → FATAL.
fn feature_compatibility_check(
    inputs: &DoctorInputs,
    features: EnabledFeatures,
    backends: Option<&std::collections::BTreeMap<String, crate::catalog::BackendRef>>,
) -> CheckResult {
    const NAME: &str = "feature_compatibility";
    let mut gaps: Vec<String> = Vec::new();

    if inputs.unlock_bip39_selected && !features.unlock_bip39 {
        gaps.push(
            "a bip39 break-glass phrase is configured but the binary lacks `unlock-bip39`"
                .to_string(),
        );
    }
    if inputs.unlock_age_yubikey_selected && !features.unlock_age_yubikey {
        gaps.push(
            "age-yubikey unlock is enabled but the binary lacks `unlock-age-yubikey`".to_string(),
        );
    }
    if let Some(backends) = backends {
        let needs_keystore = backends.values().any(|b| b.kind == BackendKind::Keystore);
        if needs_keystore && !features.keystore_backend {
            gaps.push(
                "the catalog declares a `keystore` backend but the binary lacks `keystore-backend`"
                    .to_string(),
            );
        }
        let needs_aws_kms = backends.values().any(|b| b.kind == BackendKind::AwsKms);
        if needs_aws_kms && !features.aws_kms {
            gaps.push(
                "the catalog declares an `aws-kms` backend but the binary lacks `aws-kms`"
                    .to_string(),
            );
        }
        let needs_gcp_kms = backends.values().any(|b| b.kind == BackendKind::GcpKms);
        if needs_gcp_kms && !features.gcp_kms {
            gaps.push(
                "the catalog declares a `gcp-kms` backend but the binary lacks `gcp-kms`"
                    .to_string(),
            );
        }
    }

    if gaps.is_empty() {
        CheckResult::ok(
            NAME,
            "the binary's enabled features cover the configured backend + unlock methods",
        )
    } else {
        CheckResult::fatal(
            NAME,
            format!("feature gap(s): {}", gaps.join("; ")),
            "Rebuild `basil` with the missing cargo feature(s) enabled \
             (e.g. `--features unlock-bip39,keystore-backend`), or remove the \
             corresponding config option.",
        )
    }
}

/// Is the configured backend CLI on `PATH`? For `vault`-kind backends the CLI is
/// `bao` (`OpenBao`) or `vault` (`HashiCorp`); either satisfies the check. A
/// `keystore`-kind backend needs no external CLI.
fn backend_binary_check(
    backends: Option<&std::collections::BTreeMap<String, crate::catalog::BackendRef>>,
) -> CheckResult {
    const NAME: &str = "backend_binary";
    let Some(backends) = backends else {
        return catalog_dependent_skip(NAME);
    };

    let has_vault = backends.values().any(|b| b.kind == BackendKind::Vault);
    if !has_vault {
        return CheckResult::ok(
            NAME,
            "no vault-kind backend in the catalog; no external CLI required",
        );
    }

    let bao = on_path("bao");
    let vault = on_path("vault");
    match (bao, vault) {
        (true, true) => CheckResult::ok(NAME, "both `bao` and `vault` are on PATH"),
        (true, false) => CheckResult::ok(NAME, "`bao` (OpenBao) is on PATH"),
        (false, true) => CheckResult::ok(NAME, "`vault` (HashiCorp) is on PATH"),
        (false, false) => CheckResult::warn(
            NAME,
            "neither `bao` nor `vault` is on PATH",
            "Install the OpenBao (`bao`) or Vault (`vault`) CLI on PATH for \
             out-of-band provisioning; the daemon talks HTTP and does not strictly \
             require the CLI, hence advisory.",
        ),
    }
}

/// Is `bin` an executable file on `PATH`? (Mirrors the test harness's `on_path`.)
fn on_path(bin: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|dir| dir.join(bin).is_file()))
}

/// Socket sanity: the parent dir exists and is writable, the mode is not
/// world-writable, and a configured group resolves. The socket is NOT bound. A
/// parent dir the daemon cannot bind under (missing / unwritable / unresolvable
/// group) is FATAL; a world-writable mode is an advisory posture warning.
fn socket_check(socket: &str, mode: u32, group: Option<&str>) -> CheckResult {
    const NAME: &str = "socket";
    let path = Path::new(socket);
    let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) else {
        return CheckResult::fatal(
            NAME,
            format!("socket path `{socket}` has no parent directory"),
            "Use an absolute socket path under an existing run dir, e.g. /run/basil/basil.sock.",
        );
    };

    if !parent.exists() {
        return CheckResult::fatal(
            NAME,
            format!("socket parent dir {} does not exist", parent.display()),
            format!(
                "Create the run directory (e.g. `install -d -m 0750 {}`) before starting.",
                parent.display()
            ),
        );
    }
    if !dir_is_writable(parent) {
        return CheckResult::fatal(
            NAME,
            format!("socket parent dir {} is not writable", parent.display()),
            "Make the run directory writable by the user that runs basil.",
        );
    }

    // World-writable socket mode (other-write bit set) is a posture problem.
    if mode & 0o002 != 0 {
        return CheckResult::warn(
            NAME,
            format!("configured socket mode {mode:04o} is world-writable"),
            "Tighten `socket-mode` to 0600 (owner-only) or 0660 with a `socket-group`; \
             a world-writable socket lets any local user connect.",
        );
    }

    if let Some(group) = group
        && !group_resolves(group)
    {
        return CheckResult::fatal(
            NAME,
            format!("configured socket-group `{group}` does not resolve to a gid"),
            "Create the group, or set `socket-group` to an existing group name or numeric gid.",
        );
    }

    CheckResult::ok(
        NAME,
        format!(
            "parent dir {} exists + writable; mode {mode:04o} not world-writable",
            parent.display()
        ),
    )
}

/// Can we create an entry under `dir`? Probe with an exclusively-created temp
/// file we immediately remove (never binds a socket).
fn dir_is_writable(dir: &Path) -> bool {
    for _ in 0..8 {
        let mut random = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut random);
        let name = format!(
            ".basil-doctor-{}-{}.tmp",
            std::process::id(),
            hex_lower(&random)
        );
        let probe = dir.join(name);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&probe)
        {
            Ok(_) => {
                let _ = std::fs::remove_file(&probe);
                return true;
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return false,
        }
    }
    false
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

/// Does `group` (a name or numeric gid) resolve? A numeric gid always resolves;
/// a name is looked up in `/etc/group`. Read-only; failure to read the group
/// file is treated as "cannot confirm" → does not resolve.
fn group_resolves(group: &str) -> bool {
    if group.parse::<u32>().is_ok() {
        return true;
    }
    let Ok(body) = std::fs::read_to_string("/etc/group") else {
        return false;
    };
    body.lines()
        .filter_map(|line| line.split(':').next())
        .any(|name| name == group)
}

/// Bundle diagnostics: existence + readability, `0600` perms, and epoch freshness
/// (sidecar present + not behind the bundle). Each is its own row so an operator
/// sees exactly which property failed. **Never reads/decrypts contents.**
fn bundle_checks(bundle: &Path) -> Vec<CheckResult> {
    const READ_NAME: &str = "bundle_readable";
    const PERMS_NAME: &str = "bundle_perms";
    const FRESH_NAME: &str = "bundle_freshness";

    // 1. Existence + readability (read the bytes only to confirm access; the bytes
    //    are an opaque sealed blob; we never expose them).
    let bytes = match std::fs::read(bundle) {
        Ok(b) => b,
        Err(e) => {
            let detail = format!("sealed bundle {} is not readable: {e}", bundle.display());
            // A missing/unreadable bundle blocks the perms + freshness checks too;
            // emit them as skipped so the row set is stable.
            return vec![
                CheckResult::fatal(
                    READ_NAME,
                    detail,
                    "Place the 0600 sealed bundle at the configured path and ensure the \
                     daemon user can read it.",
                ),
                CheckResult::warn(
                    PERMS_NAME,
                    "skipped: bundle not readable",
                    "Resolve bundle_readable first.",
                ),
                CheckResult::warn(
                    FRESH_NAME,
                    "skipped: bundle not readable",
                    "Resolve bundle_readable first.",
                ),
            ];
        }
    };

    let read_row = CheckResult::ok(
        READ_NAME,
        format!("sealed bundle {} exists and is readable", bundle.display()),
    );
    let perms_row = bundle_perms_check(PERMS_NAME, bundle);
    let fresh_row = bundle_freshness_check(FRESH_NAME, bundle, &bytes);
    vec![read_row, perms_row, fresh_row]
}

/// `0600` permission check on the bundle file (owner-only). Loose perms are an
/// advisory WARNING: startup only refuses them under `strict-bundle-perms`, so on
/// their own they do not stop the broker from starting.
fn bundle_perms_check(name: &'static str, bundle: &Path) -> CheckResult {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::metadata(bundle) {
            Ok(meta) => {
                let mode = meta.permissions().mode() & 0o777;
                if mode == 0o600 {
                    CheckResult::ok(name, "sealed bundle is 0600 (owner-only)")
                } else {
                    CheckResult::warn(
                        name,
                        format!("sealed bundle has mode {mode:04o}, expected 0600"),
                        format!(
                            "Run `chmod 600 {}`; broader perms leak the sealed creds. Startup \
                             refuses this only under `strict-bundle-perms`, hence advisory.",
                            bundle.display()
                        ),
                    )
                }
            }
            Err(e) => CheckResult::fatal(
                name,
                format!("cannot stat sealed bundle: {e}"),
                "Ensure the bundle path is correct and accessible.",
            ),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = bundle;
        CheckResult::warn(
            name,
            "permission check is unix-only; skipped on this platform",
            "Ensure the bundle is owner-only by your platform's equivalent.",
        )
    }
}

/// Epoch freshness: parse the bundle's PUBLIC header for its epoch, read the
/// `.epoch` sidecar (if present) and compare. Read-only: unlike
/// [`crate::seal::verify_epoch_sidecar`], doctor never writes the sidecar. The
/// only field touched is the non-secret monotonic epoch counter.
fn bundle_freshness_check(name: &'static str, bundle: &Path, bytes: &[u8]) -> CheckResult {
    let parsed = match crate::seal::format::decode(bytes) {
        Ok(p) => p,
        Err(e) => {
            return CheckResult::fatal(
                name,
                format!("sealed bundle does not parse (corrupt/wrong format): {e}"),
                "Re-export the sealed bundle; the on-disk file is not a valid basil bundle.",
            );
        }
    };
    let current = parsed.body.header.epoch;
    let sidecar = epoch_sidecar_path(bundle);

    match std::fs::read_to_string(&sidecar) {
        Ok(raw) => match raw.trim().parse::<u64>() {
            Ok(seen) if current < seen => CheckResult::fatal(
                name,
                format!(
                    "STALE bundle: epoch {current} is behind the last-seen sidecar epoch {seen}"
                ),
                "An older bundle was swapped in. Restore the current bundle, or if the \
                 rollback is intentional, remove the stale .epoch sidecar.",
            ),
            Ok(seen) => CheckResult::ok(
                name,
                format!("bundle epoch {current} is current (sidecar last-seen {seen})"),
            ),
            Err(e) => CheckResult::fatal(
                name,
                format!(
                    "epoch sidecar {} is not a valid integer: {e}",
                    sidecar.display()
                ),
                "Remove the corrupt .epoch sidecar; the daemon re-initializes it at startup.",
            ),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => CheckResult::warn(
            name,
            format!("epoch sidecar {} is absent (first boot)", sidecar.display()),
            "Expected on first boot; the daemon initializes it at startup. After the first \
             successful start it should be present.",
        ),
        Err(e) => CheckResult::fatal(
            name,
            format!("epoch sidecar {} is not readable: {e}", sidecar.display()),
            "Ensure the daemon user can read the .epoch sidecar next to the bundle.",
        ),
    }
}

/// The `.epoch` sidecar path next to a bundle (mirrors `unlock::epoch_sidecar_path`).
fn epoch_sidecar_path(bundle: &Path) -> std::path::PathBuf {
    let mut p = std::ffi::OsString::from(bundle.as_os_str());
    p.push(".epoch");
    std::path::PathBuf::from(p)
}

/// Backend reachability: a bounded, unauthenticated probe of each distinct
/// vault-kind backend address. Hits the Vault/OpenBao `/v1/sys/health` endpoint,
/// which needs no token. Unreachable within [`REACHABILITY_TIMEOUT`] → FATAL
/// (never a hang). A keystore-only catalog has nothing to probe.
async fn backend_reachability_check(
    backends: Option<&std::collections::BTreeMap<String, crate::catalog::BackendRef>>,
) -> CheckResult {
    const NAME: &str = "backend_reachability";
    let Some(backends) = backends else {
        return catalog_dependent_skip(NAME);
    };

    // Distinct vault addresses (a keystore addr is a local path, not probed here).
    let mut addrs: Vec<String> = backends
        .values()
        .filter(|b| b.kind == BackendKind::Vault)
        .map(|b| b.addr.clone())
        .collect();
    addrs.sort();
    addrs.dedup();

    if addrs.is_empty() {
        return CheckResult::ok(
            NAME,
            "no vault-kind backend to probe (keystore-only or no backends)",
        );
    }

    crate::ensure_crypto_provider();
    let client = match reqwest::Client::builder()
        .timeout(REACHABILITY_TIMEOUT)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return CheckResult::fatal(
                NAME,
                format!("could not build HTTP client for the reachability probe: {e}"),
                "This is unexpected; check the host's TLS/HTTP stack.",
            );
        }
    };

    let mut unreachable: Vec<String> = Vec::new();
    let mut reached = 0usize;
    for addr in &addrs {
        if probe_vault_health(&client, addr).await {
            reached += 1;
        } else {
            unreachable.push(addr.clone());
        }
    }

    if unreachable.is_empty() {
        CheckResult::ok(
            NAME,
            format!("all {reached} vault backend address(es) responded to /v1/sys/health"),
        )
    } else {
        CheckResult::fatal(
            NAME,
            format!(
                "{} of {} vault backend address(es) unreachable: {}",
                unreachable.len(),
                addrs.len(),
                unreachable.join(", ")
            ),
            "Start/reach the backend (OpenBao/Vault) at the configured address, or fix \
             `addr` in the catalog. The probe is unauthenticated (/v1/sys/health) with a \
             bounded timeout.",
        )
    }
}

/// Probe a single vault address's unauthenticated health endpoint. Any HTTP
/// response (even sealed/standby 5xx) proves reachability; only a transport
/// failure (connect refused / timeout / DNS) is "unreachable".
async fn probe_vault_health(client: &reqwest::Client, addr: &str) -> bool {
    let url = format!("{}/v1/sys/health", addr.trim_end_matches('/'));
    client.get(&url).send().await.is_ok()
}

/// Render the report as grouped, human-readable text to stdout.
#[must_use]
pub fn render_human(report: &DoctorReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "basil doctor - {} check(s)\n", report.checks.len());
    for c in &report.checks {
        let marker = match c.status {
            CheckStatus::Ok => "OK   ",
            CheckStatus::Warn => "WARN ",
            CheckStatus::Fatal => "FATAL",
        };
        let _ = writeln!(out, "[{marker}] {}: {}", c.name, c.detail);
        if c.status != CheckStatus::Ok && !c.remediation.is_empty() {
            let _ = writeln!(out, "       → {}", c.remediation);
        }
    }
    let s = &report.summary;
    let _ = writeln!(
        out,
        "\nsummary: {} ok, {} warn, {} fatal ({} total)",
        s.ok, s.warn, s.fatal, s.total
    );
    if s.blocking {
        let _ = writeln!(out, "result: BLOCKING, at least one check is fatal");
    } else if s.warn > 0 {
        let _ = writeln!(
            out,
            "result: OK with advisories (nonzero exit only under --strict)"
        );
    } else {
        let _ = writeln!(out, "result: OK");
    }
    out
}

/// Render the report as the stable `--json` document.
///
/// # Errors
/// Returns a serialization error only on an internal invariant failure (the shape
/// is plain data, so this is effectively infallible).
pub fn render_json(report: &DoctorReport) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(report)
}

#[cfg(test)]
mod tests {
    // Indexing into fixed test fixtures (serde_json values, result vecs) is fine;
    // the no-panic gate targets the runtime path, not assertions.
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use crate::catalog::MissingPolicy;
    use crate::{CheckReport, KeyCheck, KeyStatus};
    use std::io::Write as _;

    fn unique_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "basil-doctor-test-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_mode(path: &Path, contents: &[u8], mode: u32) {
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(contents).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = mode;
    }

    fn all_features_off() -> EnabledFeatures {
        EnabledFeatures {
            keystore_backend: false,
            aws_kms: false,
            gcp_kms: false,
            unlock_bip39: false,
            unlock_age_yubikey: false,
        }
    }

    fn base_inputs(dir: &Path) -> DoctorInputs {
        DoctorInputs {
            catalog: dir.join("catalog.json"),
            policy: dir.join("policy.json"),
            bundle: dir.join("bundle.sealed"),
            socket: dir.join("basil.sock").to_string_lossy().into_owned(),
            socket_mode: 0o600,
            socket_group: None,
            capability_policy: crate::CapabilityPolicy::Off,
            invocation: crate::service::broker::InvocationRuntimeConfig::default(),
            unlock_passphrase_selected: false,
            unlock_bip39_selected: false,
            unlock_age_yubikey_selected: false,
        }
    }

    fn key_check(name: &str, status: KeyStatus) -> KeyCheck {
        KeyCheck {
            name: name.to_string(),
            status,
        }
    }

    // --- feature compatibility ---

    #[test]
    fn feature_keystore_backend_in_catalog_without_feature_is_fatal() {
        let dir = unique_dir();
        let inputs = base_inputs(&dir);
        let mut backends = std::collections::BTreeMap::new();
        backends.insert(
            "ks".to_string(),
            serde_json::from_value::<crate::catalog::BackendRef>(serde_json::json!({
                "kind": "keystore",
                "addr": "/var/lib/basil/keystore.db"
            }))
            .unwrap(),
        );
        let res = feature_compatibility_check(&inputs, all_features_off(), Some(&backends));
        assert_eq!(res.status, CheckStatus::Fatal);
        assert!(res.detail.contains("keystore-backend"));
    }

    #[test]
    fn feature_all_satisfied_is_ok() {
        let dir = unique_dir();
        let inputs = base_inputs(&dir);
        let features = EnabledFeatures {
            keystore_backend: true,
            aws_kms: true,
            gcp_kms: true,
            unlock_bip39: true,
            unlock_age_yubikey: true,
        };
        let res = feature_compatibility_check(&inputs, features, None);
        assert_eq!(res.status, CheckStatus::Ok);
    }

    // --- socket ---

    #[test]
    fn socket_missing_parent_dir_is_fatal() {
        let res = socket_check("/nonexistent-basil-dir-xyz/basil.sock", 0o600, None);
        assert_eq!(res.status, CheckStatus::Fatal);
    }

    #[test]
    fn socket_writable_parent_owner_only_is_ok() {
        let dir = unique_dir();
        let sock = dir.join("basil.sock");
        let res = socket_check(&sock.to_string_lossy(), 0o600, None);
        assert_eq!(res.status, CheckStatus::Ok);
    }

    #[cfg(unix)]
    #[test]
    fn dir_writable_probe_does_not_follow_predictable_symlink() {
        use std::os::unix::fs::symlink;

        let dir = unique_dir();
        let target = dir.join("target");
        let predictable = dir.join(format!(".basil-doctor-{}.tmp", std::process::id()));
        std::fs::write(&target, b"keep").expect("write target");
        symlink(&target, &predictable).expect("create symlink");

        assert!(dir_is_writable(&dir));
        assert_eq!(
            std::fs::read(&target).expect("read target"),
            b"keep",
            "probe must not truncate a predictable symlink target"
        );

        let _ = std::fs::remove_file(predictable);
        let _ = std::fs::remove_file(target);
        let _ = std::fs::remove_dir(dir);
    }

    #[test]
    fn socket_world_writable_mode_warns() {
        let dir = unique_dir();
        let sock = dir.join("basil.sock");
        let res = socket_check(&sock.to_string_lossy(), 0o666, None);
        assert_eq!(res.status, CheckStatus::Warn);
    }

    #[test]
    fn socket_unresolvable_group_is_fatal() {
        let dir = unique_dir();
        let sock = dir.join("basil.sock");
        let res = socket_check(
            &sock.to_string_lossy(),
            0o660,
            Some("no-such-group-basil-zzz"),
        );
        assert_eq!(res.status, CheckStatus::Fatal);
    }

    #[test]
    fn socket_numeric_group_resolves() {
        let dir = unique_dir();
        let sock = dir.join("basil.sock");
        let res = socket_check(&sock.to_string_lossy(), 0o660, Some("0"));
        assert_eq!(res.status, CheckStatus::Ok);
    }

    // --- bundle ---

    #[test]
    fn bundle_missing_is_fatal_and_skips_dependents() {
        let dir = unique_dir();
        let bundle = dir.join("absent.sealed");
        let rows = bundle_checks(&bundle);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].status, CheckStatus::Fatal); // readable
        assert_eq!(rows[1].status, CheckStatus::Warn); // perms skipped
        assert_eq!(rows[2].status, CheckStatus::Warn); // freshness skipped
    }

    #[test]
    fn bundle_bad_perms_warns_perms_row() {
        let dir = unique_dir();
        let bundle = dir.join("bundle.sealed");
        write_mode(&bundle, b"not-a-real-bundle", 0o644);
        let row = bundle_perms_check("bundle_perms", &bundle);
        // Loose perms are advisory: startup refuses them only under
        // `strict-bundle-perms`, so on their own they do not stop startup.
        #[cfg(unix)]
        assert_eq!(row.status, CheckStatus::Warn);
        #[cfg(not(unix))]
        assert_eq!(row.status, CheckStatus::Warn);
    }

    #[test]
    fn bundle_good_perms_pass() {
        let dir = unique_dir();
        let bundle = dir.join("bundle.sealed");
        write_mode(&bundle, b"blob", 0o600);
        let row = bundle_perms_check("bundle_perms", &bundle);
        #[cfg(unix)]
        assert_eq!(row.status, CheckStatus::Ok);
    }

    #[test]
    fn bundle_freshness_unparsable_blob_is_fatal() {
        let dir = unique_dir();
        let bundle = dir.join("bundle.sealed");
        let row = bundle_freshness_check("bundle_freshness", &bundle, b"garbage-not-a-bundle");
        assert_eq!(row.status, CheckStatus::Fatal);
        assert!(row.detail.contains("does not parse"));
    }

    // --- catalog/policy ---

    #[test]
    fn catalog_unloadable_is_fatal() {
        let dir = unique_dir();
        std::fs::write(dir.join("catalog.json"), "not json").unwrap();
        std::fs::write(dir.join("policy.json"), "not json").unwrap();
        let loaded = load_catalog_policy(&dir.join("catalog.json"), &dir.join("policy.json"));
        let row = catalog_policy_check(&loaded);
        assert_eq!(row.status, CheckStatus::Fatal);
    }

    // --- summary / exit logic ---

    #[test]
    fn summary_counts_and_blocking_iff_any_fatal() {
        let checks = vec![
            CheckResult::ok("a", "fine"),
            CheckResult::warn("b", "meh", "do x"),
        ];
        let report = DoctorReport::from_checks(checks);
        assert!(!report.summary.blocking);
        assert_eq!(report.summary.warn, 1);

        let checks = vec![
            CheckResult::ok("a", "fine"),
            CheckResult::fatal("c", "broken", "fix it"),
        ];
        let report = DoctorReport::from_checks(checks);
        assert!(report.summary.blocking);
        assert_eq!(report.summary.fatal, 1);
    }

    #[test]
    fn exit_code_model_fatal_vs_warn_vs_strict() {
        // All-ok: never exits nonzero.
        let ok = DoctorReport::from_checks(vec![CheckResult::ok("a", "fine")]);
        assert!(!ok.should_exit_nonzero(false));
        assert!(!ok.should_exit_nonzero(true));

        // Warn-only: exits nonzero only under --strict.
        let warn = DoctorReport::from_checks(vec![CheckResult::warn("b", "meh", "do x")]);
        assert!(!warn.should_exit_nonzero(false));
        assert!(warn.should_exit_nonzero(true));

        // Any fatal: always exits nonzero, strict or not.
        let fatal = DoctorReport::from_checks(vec![
            CheckResult::warn("b", "meh", "do x"),
            CheckResult::fatal("c", "broken", "fix it"),
        ]);
        assert!(fatal.should_exit_nonzero(false));
        assert!(fatal.should_exit_nonzero(true));
    }

    #[test]
    fn json_shape_is_stable() {
        let report = DoctorReport::from_checks(vec![CheckResult::fatal("x", "d", "r")]);
        let json = render_json(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["schema_version"], DOCTOR_SCHEMA_VERSION);
        assert_eq!(v["checks"][0]["name"], "x");
        assert_eq!(v["checks"][0]["status"], "fatal");
        assert_eq!(v["checks"][0]["detail"], "d");
        assert_eq!(v["checks"][0]["remediation"], "r");
        assert_eq!(v["summary"]["fatal"], 1);
        assert_eq!(v["summary"]["blocking"], true);
    }

    // --- key material (--keys) per-key detail ---

    #[test]
    fn key_material_probe_failure_omits_secret_bearing_reason() {
        let rows = key_material_rows(Err(
            "reading passphrase from /run/credentials/basil/passphrase failed; \
             sealed bundle /var/lib/basil/bootstrap.bundle; \
             Authorization: Bearer vault-token-s.123; upstream body has credential"
                .to_string(),
        ));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, CheckStatus::Fatal);
        let visible = format!("{} {}", rows[0].detail, rows[0].remediation);
        for canary in [
            "/run/credentials/basil/passphrase",
            "/var/lib/basil/bootstrap.bundle",
            "vault-token-s.123",
            "upstream body has credential",
        ] {
            assert!(
                !visible.contains(canary),
                "doctor row leaked secret canary `{canary}` in `{visible}`"
            );
        }
    }

    #[test]
    fn key_material_all_present_is_single_ok_row() {
        let report = CheckReport {
            keys: vec![
                key_check("web-tls", KeyStatus::Present),
                key_check("app-sign", KeyStatus::Present),
            ],
        };
        let rows = key_material_rows(Ok(&report));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "key_material");
        assert_eq!(rows[0].status, CheckStatus::Ok);
    }

    #[test]
    fn key_material_required_missing_is_fatal_with_per_key_detail() {
        let report = CheckReport {
            keys: vec![
                key_check("present-key", KeyStatus::Present),
                key_check("req-key", KeyStatus::Missing(MissingPolicy::Error)),
                key_check("gen-key", KeyStatus::Missing(MissingPolicy::Generate)),
            ],
        };
        let rows = key_material_rows(Ok(&report));
        // aggregate + 2 per-missing-key rows.
        assert_eq!(rows.len(), 3);
        // aggregate: required missing → fatal.
        assert_eq!(rows[0].name, "key_material");
        assert_eq!(rows[0].status, CheckStatus::Fatal);
        // per-key rows, one fatal (error), one warn (generate).
        let req = rows
            .iter()
            .find(|r| r.name == "key_material:req-key")
            .expect("req-key row present");
        assert_eq!(req.status, CheckStatus::Fatal);
        let generate_row = rows
            .iter()
            .find(|r| r.name == "key_material:gen-key")
            .expect("gen-key row present");
        assert_eq!(generate_row.status, CheckStatus::Warn);
    }

    #[test]
    fn key_material_only_generate_missing_is_warn_not_fatal() {
        let report = CheckReport {
            keys: vec![
                key_check("present-key", KeyStatus::Present),
                key_check("gen-key", KeyStatus::Missing(MissingPolicy::Generate)),
            ],
        };
        let rows = key_material_rows(Ok(&report));
        assert_eq!(rows[0].status, CheckStatus::Warn); // aggregate
        let report = DoctorReport::from_checks(rows);
        assert!(!report.summary.blocking);
        assert!(!report.should_exit_nonzero(false));
        assert!(report.should_exit_nonzero(true));
    }

    #[tokio::test]
    async fn unreachable_backend_is_fatal_within_timeout() {
        let mut backends = std::collections::BTreeMap::new();
        // 127.0.0.1:1 is reserved/closed; connect is refused quickly.
        backends.insert(
            "v".to_string(),
            serde_json::from_value::<crate::catalog::BackendRef>(serde_json::json!({
                "kind": "vault",
                "addr": "http://127.0.0.1:1"
            }))
            .unwrap(),
        );
        let started = std::time::Instant::now();
        let res = backend_reachability_check(Some(&backends)).await;
        assert!(started.elapsed() < REACHABILITY_TIMEOUT * 3);
        assert_eq!(res.status, CheckStatus::Fatal);
    }

    #[tokio::test]
    async fn keystore_only_catalog_skips_reachability() {
        let mut backends = std::collections::BTreeMap::new();
        backends.insert(
            "ks".to_string(),
            serde_json::from_value::<crate::catalog::BackendRef>(serde_json::json!({
                "kind": "keystore",
                "addr": "/var/lib/basil/keystore.db"
            }))
            .unwrap(),
        );
        let res = backend_reachability_check(Some(&backends)).await;
        assert_eq!(res.status, CheckStatus::Ok);
    }
}
