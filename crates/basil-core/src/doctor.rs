// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! `basil doctor`: preflight environment & deployment checks (basil-f0j).
//!
//! Doctor runs a set of **independent**, read-only diagnostics against a resolved
//! daemon config and reports each as a structured
//! [`CheckResult`] with actionable remediation. It is a pre-deploy / first-boot
//! sanity gate: it answers "will `basil agent` even get off the ground here?"
//! without binding the socket, unlocking the bundle, or mutating anything.
//! Operators who explicitly need the authenticated key-material probe can opt in
//! at the CLI layer; the default doctor run keeps the secret-free boundary.
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
//! - **No mutation.** Default doctor never unlocks; the explicit authenticated
//!   key-material mode unlocks only to read. Neither mode reconciles, generates a
//!   key, writes a sidecar, or binds the socket. The epoch-sidecar check is
//!   read-only (unlike [`crate::seal::verify_epoch_sidecar`], which advances the
//!   sidecar).
//!
//! ## Output & exit
//!
//! Each check is `ok` / `warn` / `fail`. `fail` is **blocking**; `warn` is
//! advisory. The overall run is healthy iff no check is `fail`. The caller maps
//! `any fail → nonzero exit`, `warns-alone → zero`.

use std::path::Path;
use std::time::Duration;

use serde::Serialize;

use crate::catalog::BackendKind;

/// Stable schema version of the `--json` document. Bump on a breaking shape
/// change; operators script against this.
pub const DOCTOR_SCHEMA_VERSION: u32 = 1;

/// Bounded per-backend reachability timeout. A down backend must FAIL the check,
/// never hang the whole run.
const REACHABILITY_TIMEOUT: Duration = Duration::from_secs(3);

/// The outcome of a single diagnostic check.
///
/// `Ok` passes; `Warn` is advisory (non-blocking); `Fail` is blocking (the run
/// exits nonzero). The string tokens (`ok` / `warn` / `fail`) are the stable JSON
/// values that operators match on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    /// The check passed.
    Ok,
    /// Advisory: a non-ideal condition that does not block startup.
    Warn,
    /// Blocking: this would prevent (or endanger) a clean `run`.
    Fail,
}

/// One diagnostic result: a named check, its status, a human-readable detail,
/// and (for non-ok results) actionable remediation text.
///
/// `name` is a stable machine identifier (`snake_case`, scriptable); `detail`
/// and `remediation` are operator-facing prose and may change wording freely.
/// **No field ever carries a secret** (the bundle arm reports perms/freshness
/// only).
#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    /// Stable machine identifier for the check (e.g. `backend_reachability`).
    pub name: &'static str,
    /// Pass / advisory / blocking.
    pub status: CheckStatus,
    /// Human-readable description of what was found.
    pub detail: String,
    /// Actionable fix for a non-ok result (empty for `ok`).
    pub remediation: String,
}

impl CheckResult {
    pub(crate) fn ok(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            status: CheckStatus::Ok,
            detail: detail.into(),
            remediation: String::new(),
        }
    }

    pub(crate) fn warn(
        name: &'static str,
        detail: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self {
            name,
            status: CheckStatus::Warn,
            detail: detail.into(),
            remediation: remediation.into(),
        }
    }

    pub(crate) fn fail(
        name: &'static str,
        detail: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self {
            name,
            status: CheckStatus::Fail,
            detail: detail.into(),
            remediation: remediation.into(),
        }
    }
}

/// A non-secret summary of a doctor run: per-status counts and the blocking flag.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct DoctorSummary {
    /// Total number of checks run.
    pub total: usize,
    /// Count of `ok` checks.
    pub ok: usize,
    /// Count of `warn` (advisory) checks.
    pub warn: usize,
    /// Count of `fail` (blocking) checks.
    pub fail: usize,
    /// True iff at least one check is `fail` (the run should exit nonzero).
    pub blocking: bool,
}

/// The full doctor document: a stable, versioned shape an operator scripts on.
#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    /// Stable schema version of this document.
    pub schema_version: u32,
    /// Every check result, in a deterministic order.
    pub checks: Vec<CheckResult>,
    /// Roll-up counts + the blocking flag.
    pub summary: DoctorSummary,
}

impl DoctorReport {
    /// Build a report from a set of independent results, computing the summary.
    #[must_use]
    pub fn from_checks(checks: Vec<CheckResult>) -> Self {
        let mut ok = 0;
        let mut warn = 0;
        let mut fail = 0;
        for c in &checks {
            match c.status {
                CheckStatus::Ok => ok += 1,
                CheckStatus::Warn => warn += 1,
                CheckStatus::Fail => fail += 1,
            }
        }
        let summary = DoctorSummary {
            total: checks.len(),
            ok,
            warn,
            fail,
            blocking: fail > 0,
        };
        Self {
            schema_version: DOCTOR_SCHEMA_VERSION,
            checks,
            summary,
        }
    }

    /// Whether the run had any blocking (`fail`) check: the caller exits nonzero.
    #[must_use]
    pub const fn has_blocking_failure(&self) -> bool {
        self.summary.blocking
    }
}

/// The resolved, non-secret inputs a doctor run needs.
///
/// Built by the binary from the same config/override resolution `run`/`check`
/// use, then handed here so the check logic is free of clap/config-file plumbing.
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

/// Run every diagnostic and assemble the report. Checks are independent: a check
/// that errors becomes a `fail`/`warn` row and never aborts the rest.
///
/// The catalog is loaded once (its own check) and, if it parses, reused to derive
/// the backend-binary and reachability checks. A catalog that fails to load
/// yields a `fail` row and the backend checks degrade gracefully (they report
/// "skipped: catalog did not load").
pub async fn run_doctor(inputs: &DoctorInputs, features: EnabledFeatures) -> DoctorReport {
    let mut checks = Vec::new();

    // Load the catalog/policy once; the result drives downstream checks.
    let loaded = load_catalog_policy(&inputs.catalog, &inputs.policy);
    checks.push(catalog_policy_check(&loaded));

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

/// Build the optional authenticated key-material row for `doctor --check-keys`.
///
/// This row is intentionally not part of the default [`run_doctor`] boundary:
/// its caller must have explicitly unlocked the sealed bundle and run the
/// read-only [`crate::BackendManager::check`] probe. The result is still
/// non-secret: it reports catalog key names and counts, never backend tokens or
/// key material.
#[must_use]
pub fn key_material_check(probe: Result<&crate::CheckReport, String>) -> CheckResult {
    const NAME: &str = "key_material";
    probe.map_or_else(
        |reason| {
            drop(reason);
            CheckResult::fail(
                NAME,
                "authenticated key-material probe failed",
                "Confirm the sealed bundle unlock settings and backend credentials, then rerun `basil config check --require` for the detailed probe.",
            )
        },
        |report| {
            let total = report.keys.len();
            let present = report.present_count();
            let required_missing = report.required_missing();
            if required_missing.is_empty() {
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
                CheckResult::fail(
                    NAME,
                    format!(
                        "{present}/{total} catalog key(s) present; required key(s) absent: {}",
                        required_missing.join(", ")
                    ),
                    "Provision the missing required key material, then rerun `basil doctor --check-keys` or `basil config check --require`.",
                )
            }
        },
    )
}

/// The subset of a loaded catalog the downstream checks need (the backend table).
struct LoadedCatalog {
    backends: std::collections::BTreeMap<String, crate::catalog::BackendRef>,
}

/// Load + validate the catalog/policy via the SAME loader `check`/`run` use. A
/// load/validation error is returned verbatim for the catalog/policy check row.
fn load_catalog_policy(catalog_path: &Path, policy_path: &Path) -> Result<LoadedCatalog, String> {
    let catalog_json = std::fs::read_to_string(catalog_path)
        .map_err(|e| format!("reading catalog {}: {e}", catalog_path.display()))?;
    let policy_json = std::fs::read_to_string(policy_path)
        .map_err(|e| format!("reading policy {}: {e}", policy_path.display()))?;
    let (catalog, _policy, _config, _warnings) =
        crate::catalog::load(&catalog_json, &policy_json).map_err(|e| e.to_string())?;
    Ok(LoadedCatalog {
        backends: catalog.backends,
    })
}

fn catalog_policy_check(loaded: &Result<LoadedCatalog, String>) -> CheckResult {
    const NAME: &str = "catalog_policy";
    match loaded {
        Ok(c) => CheckResult::ok(
            NAME,
            format!(
                "catalog + policy load and validate; {} backend(s)",
                c.backends.len()
            ),
        ),
        Err(reason) => CheckResult::fail(
            NAME,
            format!("catalog/policy did not load: {reason}"),
            "Fix the catalog/policy export so it validates (run `basil config check`); the \
             loader reason above names the offending field.",
        ),
    }
}

/// Does the running binary's feature set support what the config asks for?
///
/// - bip39 phrase configured but `unlock-bip39` absent → FAIL.
/// - age-yubikey requested but `unlock-age-yubikey` absent → FAIL.
/// - A `keystore`-kind backend in the catalog but `keystore-backend` absent → FAIL.
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
        CheckResult::fail(
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
        return CheckResult::warn(
            NAME,
            "skipped: catalog did not load, cannot determine backend kinds",
            "Fix the catalog/policy load first (see the catalog_policy check).",
        );
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
/// world-writable, and a configured group resolves. The socket is NOT bound.
fn socket_check(socket: &str, mode: u32, group: Option<&str>) -> CheckResult {
    const NAME: &str = "socket";
    let path = Path::new(socket);
    let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) else {
        return CheckResult::fail(
            NAME,
            format!("socket path `{socket}` has no parent directory"),
            "Use an absolute socket path under an existing run dir, e.g. /run/basil/basil.sock.",
        );
    };

    if !parent.exists() {
        return CheckResult::fail(
            NAME,
            format!("socket parent dir {} does not exist", parent.display()),
            format!(
                "Create the run directory (e.g. `install -d -m 0750 {}`) before starting.",
                parent.display()
            ),
        );
    }
    if !dir_is_writable(parent) {
        return CheckResult::fail(
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
        return CheckResult::fail(
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

/// Can we create an entry under `dir`? Probe with a temp file we immediately
/// remove (never binds a socket). On non-unix or any error, fall back to a
/// permissions-bit heuristic.
fn dir_is_writable(dir: &Path) -> bool {
    let probe = dir.join(format!(".basil-doctor-{}.tmp", std::process::id()));
    match std::fs::File::create(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
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

/// Bundle diagnostics: existence + readability, strict `0600` perms, and epoch
/// freshness (sidecar present + not behind the bundle). Each is its own row so an
/// operator sees exactly which property failed. **Never reads/decrypts contents.**
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
                CheckResult::fail(
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

/// Strict `0600` permission check on the bundle file (owner-only).
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
                    CheckResult::fail(
                        name,
                        format!("sealed bundle has mode {mode:04o}, expected 0600"),
                        format!(
                            "Run `chmod 600 {}`; broaden perms leak the sealed creds.",
                            bundle.display()
                        ),
                    )
                }
            }
            Err(e) => CheckResult::fail(
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
            return CheckResult::fail(
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
            Ok(seen) if current < seen => CheckResult::fail(
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
            Err(e) => CheckResult::fail(
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
        Err(e) => CheckResult::fail(
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
/// which needs no token. Unreachable within [`REACHABILITY_TIMEOUT`] → FAIL
/// (never a hang). A keystore-only catalog has nothing to probe.
async fn backend_reachability_check(
    backends: Option<&std::collections::BTreeMap<String, crate::catalog::BackendRef>>,
) -> CheckResult {
    const NAME: &str = "backend_reachability";
    let Some(backends) = backends else {
        return CheckResult::warn(
            NAME,
            "skipped: catalog did not load, no backend addresses to probe",
            "Fix the catalog/policy load first (see the catalog_policy check).",
        );
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
            return CheckResult::fail(
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
        CheckResult::fail(
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
            CheckStatus::Ok => "OK  ",
            CheckStatus::Warn => "WARN",
            CheckStatus::Fail => "FAIL",
        };
        let _ = writeln!(out, "[{marker}] {}: {}", c.name, c.detail);
        if c.status != CheckStatus::Ok && !c.remediation.is_empty() {
            let _ = writeln!(out, "       → {}", c.remediation);
        }
    }
    let s = &report.summary;
    let _ = writeln!(
        out,
        "\nsummary: {} ok, {} warn, {} fail ({} total)",
        s.ok, s.warn, s.fail, s.total
    );
    if s.blocking {
        let _ = writeln!(out, "result: BLOCKING, at least one check failed");
    } else if s.warn > 0 {
        let _ = writeln!(out, "result: OK with advisories");
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
            unlock_passphrase_selected: false,
            unlock_bip39_selected: false,
            unlock_age_yubikey_selected: false,
        }
    }

    // --- feature compatibility ---

    #[test]
    fn feature_keystore_backend_in_catalog_without_feature_fails() {
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
        assert_eq!(res.status, CheckStatus::Fail);
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
    fn socket_missing_parent_dir_fails() {
        let res = socket_check("/nonexistent-basil-dir-xyz/basil.sock", 0o600, None);
        assert_eq!(res.status, CheckStatus::Fail);
    }

    #[test]
    fn socket_writable_parent_owner_only_is_ok() {
        let dir = unique_dir();
        let sock = dir.join("basil.sock");
        let res = socket_check(&sock.to_string_lossy(), 0o600, None);
        assert_eq!(res.status, CheckStatus::Ok);
    }

    #[test]
    fn socket_world_writable_mode_warns() {
        let dir = unique_dir();
        let sock = dir.join("basil.sock");
        let res = socket_check(&sock.to_string_lossy(), 0o666, None);
        assert_eq!(res.status, CheckStatus::Warn);
    }

    #[test]
    fn socket_unresolvable_group_fails() {
        let dir = unique_dir();
        let sock = dir.join("basil.sock");
        let res = socket_check(
            &sock.to_string_lossy(),
            0o660,
            Some("no-such-group-basil-zzz"),
        );
        assert_eq!(res.status, CheckStatus::Fail);
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
    fn bundle_missing_fails_and_skips_dependents() {
        let dir = unique_dir();
        let bundle = dir.join("absent.sealed");
        let rows = bundle_checks(&bundle);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].status, CheckStatus::Fail); // readable
        assert_eq!(rows[1].status, CheckStatus::Warn); // perms skipped
        assert_eq!(rows[2].status, CheckStatus::Warn); // freshness skipped
    }

    #[test]
    fn bundle_bad_perms_fails_perms_row() {
        let dir = unique_dir();
        let bundle = dir.join("bundle.sealed");
        write_mode(&bundle, b"not-a-real-bundle", 0o644);
        let row = bundle_perms_check("bundle_perms", &bundle);
        #[cfg(unix)]
        assert_eq!(row.status, CheckStatus::Fail);
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
    fn bundle_freshness_unparsable_blob_fails() {
        let dir = unique_dir();
        let bundle = dir.join("bundle.sealed");
        let row = bundle_freshness_check("bundle_freshness", &bundle, b"garbage-not-a-bundle");
        assert_eq!(row.status, CheckStatus::Fail);
        assert!(row.detail.contains("does not parse"));
    }

    // --- catalog/policy ---

    #[test]
    fn catalog_unloadable_fails() {
        let dir = unique_dir();
        std::fs::write(dir.join("catalog.json"), "not json").unwrap();
        std::fs::write(dir.join("policy.json"), "not json").unwrap();
        let loaded = load_catalog_policy(&dir.join("catalog.json"), &dir.join("policy.json"));
        let row = catalog_policy_check(&loaded);
        assert_eq!(row.status, CheckStatus::Fail);
    }

    // --- summary / exit logic ---

    #[test]
    fn summary_blocking_iff_any_fail() {
        let checks = vec![
            CheckResult::ok("a", "fine"),
            CheckResult::warn("b", "meh", "do x"),
        ];
        let report = DoctorReport::from_checks(checks);
        assert!(!report.has_blocking_failure());
        assert_eq!(report.summary.warn, 1);

        let checks = vec![
            CheckResult::ok("a", "fine"),
            CheckResult::fail("c", "broken", "fix it"),
        ];
        let report = DoctorReport::from_checks(checks);
        assert!(report.has_blocking_failure());
        assert_eq!(report.summary.fail, 1);
    }

    #[test]
    fn json_shape_is_stable() {
        let report = DoctorReport::from_checks(vec![CheckResult::fail("x", "d", "r")]);
        let json = render_json(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["schema_version"], DOCTOR_SCHEMA_VERSION);
        assert_eq!(v["checks"][0]["name"], "x");
        assert_eq!(v["checks"][0]["status"], "fail");
        assert_eq!(v["checks"][0]["detail"], "d");
        assert_eq!(v["checks"][0]["remediation"], "r");
        assert_eq!(v["summary"]["fail"], 1);
        assert_eq!(v["summary"]["blocking"], true);
    }

    #[test]
    fn key_material_probe_failure_omits_secret_bearing_reason() {
        let row = key_material_check(Err(
            "reading passphrase from /run/credentials/basil/passphrase failed; \
             sealed bundle /var/lib/basil/bootstrap.bundle; \
             Authorization: Bearer vault-token-s.123; upstream body has credential"
                .to_string(),
        ));
        assert_eq!(row.status, CheckStatus::Fail);
        let visible = format!("{} {}", row.detail, row.remediation);
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

    #[tokio::test]
    async fn unreachable_backend_fails_within_timeout() {
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
        assert_eq!(res.status, CheckStatus::Fail);
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
