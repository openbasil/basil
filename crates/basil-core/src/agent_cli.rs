// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! `basil-agent`: the standalone Basil daemon.
//!
//! It loads a **`0600` sealed bundle** of the broker's own bootstrap credentials
//! (vault-vh1, `designs/unlock-and-bundle.html`), unlocks it via an enabled +
//! available slot, hands each backend its credential, zeroizes the plaintext,
//! and hands off to [`crate::run_grpc`].
//!
//! The old plaintext bootstrap paths (`--vault-token` / `$VAULT_TOKEN` /
//! `~/.vault-token` and the implicit-SPIFFE flags) are **gone**: the sealed
//! bundle is the only supported source of bootstrap creds, with no fallback.
//!
//! The top-level `basil bundle` subcommand creates and manages sealed bundles.
//! Core broker logic lives in this crate's library.

// `indexing_slicing` gate has no test-allow config option, unlike unwrap/expect.
// Tests index `serde_json::Value` (e.g. `doc["decision"]`) by construction.
#![cfg_attr(test, allow(clippy::indexing_slicing))]

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::catalog::{Class, KeyAlgorithm};
use crate::seal::{BackendCred, CredBundle};
use crate::service::broker::{BrokerIdentityRuntimeConfig, InvocationRuntimeConfig};
use crate::{
    AuditLog, Backend, BackendKind, BackendManager, BrokerLimits, BrokerState, CapabilityPolicy,
    DEFAULT_MAX_ENCRYPT_SIZE, DEFAULT_MAX_PAYLOAD_SIZE, DEFAULT_ROTATION_GRACE_VERSIONS,
    DEFAULT_SOCKET_MODE, DEFAULT_SVID_TTL_SECS, JwtRevocationStore, ReloadActor, ReloadInputs,
    ServerConfig, SpiffeConfig, SpiffeVaultBackend, VaultBackend, enforce_capabilities, load,
    reload_generation, run_grpc,
};
use crate::{bundle_cli, doctor, init, unlock};
use anyhow::{Context, Result, bail};
#[cfg(feature = "keystore-backend")]
use basil_keystore_backend::StoreConfig;
#[cfg(feature = "otlp")]
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
#[cfg(feature = "otlp")]
use opentelemetry_otlp::{Protocol, WithExportConfig};
#[cfg(feature = "otlp")]
use opentelemetry_sdk::logs::SdkLoggerProvider;
use serde::Deserialize;
use serde::de::{self, Visitor};
use tokio::signal::unix::{SignalKind, signal};
use tracing::{info, warn};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

const MAX_INVOCATION_TTL_SECS: u32 = 300;
const MAX_INVOCATION_CLOCK_SKEW_SECS: u32 = 300;
const MAX_INVOCATION_REPLAY_CACHE_CAPACITY: usize = 1_000_000;
const BROKER_KEY_USE_LABEL: &str = "broker_key_use";
const BROKER_RESPONSE_SIGNING_USE: &str = "response-signing";
const BROKER_REQUEST_ENCRYPTION_USE: &str = "request-encryption";

/// basil agent: a signing proxy over a Vault transit engine (Vault or `OpenBao`).
///
/// `run` launches the broker daemon.
/// Arguments for the daemon (`run`) path.
#[derive(Debug, clap::Args)]
pub struct RunArgs {
    #[command(flatten)]
    overrides: ConfigOverrides,
}

/// Arguments for the unified policy **`explain`** verb (`basil-1zx.3`).
///
/// One command, two sources of truth for the same subject/op/key → allow/deny
/// question:
///
/// * **Default (offline dry-run, `basil-4vf`):** loads ONLY the catalog + policy
///   JSON (no sealed bundle, no backend, no socket), builds the real
///   [`Pdp`](crate::catalog::Pdp), and evaluates the proposed tuple through the
///   SAME matcher enforcement uses. It NEVER performs the op, reads a secret, or
///   talks to a backend: safe to run anywhere, before rollout. `--effective`
///   previews every grant for the subject.
/// * **`--live`:** queries the RUNNING broker's serving generation over the
///   global `--socket` (needs the `explain` admin permission). The offline
///   config-override paths are irrelevant here, and `--effective` is offline-only.
///
/// What the PDP matches on: authorization binds to a registered **subject**.
/// The offline tool evaluates that subject name directly; Unix uid/gid
/// resolution is covered by the loader and runtime actor-resolution tests.
#[derive(Debug, clap::Args)]
pub struct ExplainArgs {
    /// The policy subject to evaluate.
    #[arg(long)]
    subject: String,

    /// The op to evaluate (`get`, `list`, `sign`, `set`, `mint`, ...). Required
    /// unless `--effective` is given.
    #[arg(long, value_parser = parse_op, required_unless_present = "effective")]
    op: Option<crate::catalog::Op>,

    /// The catalog key/target to evaluate. Required unless `--effective`.
    #[arg(long, required_unless_present = "effective")]
    key: Option<String>,

    /// Preview EVERY `(key, op)` the subject is granted across the whole catalog,
    /// instead of a single tuple. Ignores `--op`/`--key`. Offline-only.
    #[arg(long)]
    effective: bool,

    /// Query the RUNNING broker's serving generation over the global `--socket`
    /// (needs the `explain` admin permission) instead of an offline file dry-run.
    /// The config-override paths (catalog/policy/config/bundle) are ignored on the
    /// live path; `--effective` is offline-only and conflicts with `--live`.
    #[arg(long, conflicts_with = "effective")]
    live: bool,

    /// Emit a stable machine-readable JSON object instead of human-readable text.
    #[arg(long)]
    json: bool,

    #[command(flatten)]
    overrides: ConfigOverrides,
}

impl ExplainArgs {
    /// True when `--live` was given: query the running broker rather than files.
    #[must_use]
    pub const fn is_live(&self) -> bool {
        self.live
    }

    /// The registered subject to evaluate.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// The stable op token to evaluate, when `--op` was given. Always present on
    /// the live path, where `--effective` (the only thing that makes `--op`
    /// optional) is rejected by clap.
    #[must_use]
    pub fn op_token(&self) -> Option<&'static str> {
        self.op.map(crate::catalog::Op::token)
    }

    /// The catalog key/target to evaluate, when `--key` was given.
    #[must_use]
    pub fn key(&self) -> Option<&str> {
        self.key.as_deref()
    }

    /// Whether `--json` machine-readable output was requested.
    #[must_use]
    pub const fn json(&self) -> bool {
        self.json
    }
}

/// clap value parser for a policy [`Op`](crate::catalog::Op).
fn parse_op(s: &str) -> Result<crate::catalog::Op, String> {
    crate::catalog::Op::parse(s).map_err(|e| e.to_string())
}

const MAX_ROOTLESS_EXPECTED_CONTAINERS: u32 = 1_000;

fn parse_rootless_expected_containers(value: &str) -> Result<u32, String> {
    let count = value
        .parse::<u32>()
        .map_err(|err| format!("expected container count must be an integer: {err}"))?;
    if !(1..=MAX_ROOTLESS_EXPECTED_CONTAINERS).contains(&count) {
        return Err(format!(
            "expected container count must be between 1 and {MAX_ROOTLESS_EXPECTED_CONTAINERS}"
        ));
    }
    Ok(count)
}

/// Arguments for the preflight **`doctor`** path (`basil-f0j`).
///
/// Resolves the same catalog/policy/bundle/socket config `run` uses, then runs a
/// set of independent read-only diagnostics: catalog/policy load, backend
/// capability enforcement, invocation broker-identity/key bindings, feature
/// compatibility, backend binary on PATH, socket, bundle perms/freshness, and
/// backend reachability. By default it NEVER unlocks the bundle, binds the socket,
/// or mutates anything. `--keys` explicitly adds an authenticated read-only
/// per-key existence probe that unlocks the bundle but still never
/// reconciles/generates/mutates.
///
/// Exit model: non-zero only for FATAL conditions (those that would stop the
/// broker from starting). Warnings are report-only and exit 0, unless `--strict`
/// is given, which makes warnings exit non-zero too.
#[derive(Debug, clap::Args)]
pub struct DoctorArgs {
    /// Emit a stable machine-readable JSON document instead of human-readable text.
    #[arg(long)]
    json: bool,

    /// Unlock the sealed bundle and run the authenticated read-only per-key
    /// existence probe (an authenticated tier on top of the offline checks).
    #[arg(long)]
    keys: bool,

    /// Expected rootless container count for the Linux keyring quota readiness
    /// check. Omit this flag to omit the check entirely (for example on a
    /// rootful-only host).
    #[arg(
        long,
        value_name = "COUNT",
        value_parser = parse_rootless_expected_containers
    )]
    rootless_expected_containers: Option<u32>,

    /// Treat warnings as failures: exit non-zero if any check is a warning, not
    /// just on a fatal condition.
    #[arg(long)]
    strict: bool,

    #[command(flatten)]
    overrides: ConfigOverrides,
}

impl DoctorArgs {
    /// Expected rootless container count requested for the keyring quota check.
    /// `None` means the check is omitted entirely.
    #[must_use]
    pub const fn rootless_expected_containers(&self) -> Option<u32> {
        self.rootless_expected_containers
    }
}

/// Backend-connection defaults applied to every cred that pins none of its own:
/// the fallback Vault address and transit mount, plus the JWT-auth parameters a
/// [`BackendCred::SpiffeSigner`] needs to exchange its self-minted SVID for a
/// short-lived backend token. Threaded from [`SetupArgs`] to each constructor.
struct BackendDefaults<'a> {
    /// Fallback Vault address used when a cred pins no `addr`.
    vault_addr: &'a str,
    /// Transit secrets-engine mount path.
    transit_mount: &'a str,
    /// JWT auth-method mount path (`auth/<mount>/login`).
    jwt_auth_mount: &'a str,
    /// Vault jwt role bound to the broker's SPIFFE id (empty ⇒ unset).
    jwt_role: &'a str,
    /// Audience the jwt role's `bound_audiences` expects.
    jwt_audience: &'a str,
    /// Lifetime of each self-minted JWT-SVID.
    svid_ttl: Duration,
    /// db-keystore encryption cipher.
    #[cfg(feature = "db-keystore")]
    db_keystore_cipher: &'a str,
    /// Default `1Password` provider URI when the sealed cred leaves it empty.
    #[cfg(feature = "keystore-backend")]
    onepassword_provider_uri: &'a str,
    /// Default `1Password` project when the sealed cred leaves it empty.
    #[cfg(feature = "keystore-backend")]
    onepassword_project: &'a str,
    /// Default `1Password` profile when the sealed cred leaves it empty.
    #[cfg(feature = "keystore-backend")]
    onepassword_profile: &'a str,
}

/// Build a [`Backend`] from a single decrypted [`BackendCred`].
///
/// `VaultToken` is used directly; `VaultAppRole` is exchanged at the bao `AppRole`
/// login endpoint for a short-lived token first; `SpiffeSigner` boots a
/// [`SpiffeVaultBackend`] that self-mints a JWT-SVID and exchanges it at the
/// jwt-auth login endpoint. Other variants are not yet wired to a backend
/// constructor (logged OFIs) and fail closed.
async fn backend_from_cred(
    name: &str,
    backend_ref: &crate::catalog::BackendRef,
    cred: &BackendCred,
    defaults: &BackendDefaults<'_>,
) -> Result<Box<dyn Backend>> {
    match (backend_ref.kind, cred) {
        (BackendKind::Keystore, _) => backend_from_keystore_cred(name, backend_ref, cred, defaults),
        (BackendKind::AwsKms, cred) => backend_from_aws_kms_cred(name, cred).await,
        (BackendKind::GcpKms, cred) => backend_from_gcp_kms_cred(name, cred).await,
        (
            BackendKind::Vault,
            BackendCred::DbKeystoreDek { .. }
            | BackendCred::OnePassword { .. }
            | BackendCred::AwsKms { .. }
            | BackendCred::GcpKms { .. },
        ) => {
            bail!("backend `{name}`: non-vault credential cannot construct a vault backend")
        }
        (BackendKind::Vault, cred) => backend_from_vault_cred(name, cred, defaults).await,
    }
}

/// Build an AWS KMS transit backend from an [`BackendCred::AwsKms`] cred.
#[cfg(feature = "aws-kms")]
async fn backend_from_aws_kms_cred(name: &str, cred: &BackendCred) -> Result<Box<dyn Backend>> {
    match cred {
        BackendCred::AwsKms { region, profile } => {
            let backend = crate::core::backend::aws_kms::AwsKmsBackend::new(region, profile)
                .await
                .with_context(|| format!("building aws-kms backend for `{name}`"))?;
            Ok(Box::new(backend))
        }
        _ => bail!("backend `{name}`: kind `aws-kms` requires an `AwsKms` credential"),
    }
}

#[cfg(not(feature = "aws-kms"))]
#[allow(clippy::unused_async)]
async fn backend_from_aws_kms_cred(name: &str, _cred: &BackendCred) -> Result<Box<dyn Backend>> {
    bail!("backend `{name}`: kind `aws-kms` requires the aws-kms feature")
}

/// Build a GCP Cloud KMS transit backend from a [`BackendCred::GcpKms`] cred.
#[cfg(feature = "gcp-kms")]
async fn backend_from_gcp_kms_cred(name: &str, cred: &BackendCred) -> Result<Box<dyn Backend>> {
    match cred {
        BackendCred::GcpKms {
            project,
            location,
            key_ring,
            service_account_json,
        } => {
            let backend = crate::core::backend::gcp_kms::GcpKmsBackend::new(
                project,
                location,
                key_ring,
                service_account_json
                    .as_ref()
                    .map(zero_secrets::SecretString::expose_secret),
            )
            .await
            .with_context(|| format!("building gcp-kms backend for `{name}`"))?;
            Ok(Box::new(backend))
        }
        _ => bail!("backend `{name}`: kind `gcp-kms` requires a `GcpKms` credential"),
    }
}

#[cfg(not(feature = "gcp-kms"))]
#[allow(clippy::unused_async)]
async fn backend_from_gcp_kms_cred(name: &str, _cred: &BackendCred) -> Result<Box<dyn Backend>> {
    bail!("backend `{name}`: kind `gcp-kms` requires the gcp-kms feature")
}

async fn backend_from_vault_cred(
    name: &str,
    cred: &BackendCred,
    defaults: &BackendDefaults<'_>,
) -> Result<Box<dyn Backend>> {
    match cred {
        BackendCred::VaultToken { token, addr } => {
            let addr = addr.as_deref().unwrap_or(defaults.vault_addr);
            let backend = VaultBackend::new(addr, token.expose_secret(), defaults.transit_mount)
                .with_context(|| format!("building token backend for `{name}`"))?;
            Ok(Box::new(backend))
        }
        BackendCred::VaultAppRole {
            role_id,
            secret_id,
            addr,
        } => {
            let addr = addr.as_deref().unwrap_or(defaults.vault_addr);
            let token = unlock::approle_login(addr, role_id, secret_id.expose_secret())
                .await
                .with_context(|| format!("AppRole login for backend `{name}`"))?;
            let backend = VaultBackend::new(addr, token.as_str(), defaults.transit_mount)
                .with_context(|| format!("building approle backend for `{name}`"))?;
            Ok(Box::new(backend))
        }
        BackendCred::SpiffeSigner { key_pem, spiffe_id } => {
            // The jwt role is a deployment artifact with no safe default; an empty
            // role would make every login fail at the backend. Fail closed at
            // startup with an actionable error instead.
            anyhow::ensure!(
                !defaults.jwt_role.trim().is_empty(),
                "backend `{name}`: SpiffeSigner cred requires a jwt role \
                 (config key `jwt-role`); none set, failing closed"
            );
            let cfg = SpiffeConfig {
                vault_addr: defaults.vault_addr.to_string(),
                transit_mount: defaults.transit_mount.to_string(),
                jwt_auth_mount: defaults.jwt_auth_mount.to_string(),
                role: defaults.jwt_role.to_string(),
                spiffe_id: spiffe_id.clone(),
                audience: defaults.jwt_audience.to_string(),
                svid_ttl: defaults.svid_ttl,
            };
            let backend = SpiffeVaultBackend::from_signer(key_pem.expose_secret(), cfg)
                .with_context(|| format!("building spiffe-signer backend for `{name}`"))?;
            Ok(Box::new(backend))
        }
        BackendCred::DbKeystoreDek { .. }
        | BackendCred::OnePassword { .. }
        | BackendCred::AwsKms { .. }
        | BackendCred::GcpKms { .. } => {
            bail!("backend `{name}`: non-vault credential cannot construct a vault backend")
        }
        BackendCred::Opaque { kind, .. } => bail!(
            "backend `{name}`: opaque cred of kind `{kind}` has no backend constructor; fail closed"
        ),
    }
}

#[cfg(feature = "keystore-backend")]
fn backend_from_keystore_cred(
    name: &str,
    backend_ref: &crate::catalog::BackendRef,
    cred: &BackendCred,
    defaults: &BackendDefaults<'_>,
) -> Result<Box<dyn Backend>> {
    #[cfg(not(feature = "db-keystore"))]
    let _ = backend_ref;

    match cred {
        #[cfg(feature = "db-keystore")]
        BackendCred::DbKeystoreDek { dek } => {
            let backend = crate::KeystoreBackend::open(StoreConfig::DbKeystore {
                path: PathBuf::from(&backend_ref.addr),
                cipher: defaults.db_keystore_cipher.to_string(),
                dek: dek.clone(),
            })
            .with_context(|| format!("building db-keystore backend for `{name}`"))?;
            Ok(Box::new(backend))
        }
        #[cfg(not(feature = "db-keystore"))]
        BackendCred::DbKeystoreDek { .. } => {
            bail!("backend `{name}`: DbKeystoreDek requires the db-keystore feature")
        }
        #[cfg(feature = "onepassword")]
        BackendCred::OnePassword {
            provider_uri,
            project,
            profile,
        } => {
            let provider_uri = default_if_empty(provider_uri, defaults.onepassword_provider_uri);
            let project = default_if_empty(project, defaults.onepassword_project);
            let profile = default_if_empty(profile, defaults.onepassword_profile);
            anyhow::ensure!(
                !provider_uri.trim().is_empty(),
                "backend `{name}`: `OnePassword` cred requires provider_uri or config key \
                 `onepassword-provider-uri`"
            );
            let backend = crate::KeystoreBackend::open(StoreConfig::OnePassword {
                provider_uri: provider_uri.to_string(),
                project: project.to_string(),
                profile: profile.to_string(),
            })
            .with_context(|| format!("building onepassword backend for `{name}`"))?;
            Ok(Box::new(backend))
        }
        #[cfg(not(feature = "onepassword"))]
        BackendCred::OnePassword { .. } => {
            bail!("backend `{name}`: `OnePassword` requires the onepassword feature")
        }
        BackendCred::VaultToken { .. }
        | BackendCred::VaultAppRole { .. }
        | BackendCred::SpiffeSigner { .. } => {
            bail!("backend `{name}`: vault credential cannot construct a keystore backend")
        }
        BackendCred::AwsKms { .. } | BackendCred::GcpKms { .. } => {
            bail!("backend `{name}`: KMS credential cannot construct a keystore backend")
        }
        BackendCred::Opaque { kind, .. } => bail!(
            "backend `{name}`: opaque cred of kind `{kind}` has no keystore constructor; fail closed"
        ),
    }
}

#[cfg(not(feature = "keystore-backend"))]
fn backend_from_keystore_cred(
    name: &str,
    _backend_ref: &crate::catalog::BackendRef,
    _cred: &BackendCred,
    _defaults: &BackendDefaults<'_>,
) -> Result<Box<dyn Backend>> {
    bail!("backend `{name}`: kind `keystore` requires the keystore-backend feature")
}

#[cfg(feature = "keystore-backend")]
fn default_if_empty<'a>(value: &'a str, default: &'a str) -> &'a str {
    if value.trim().is_empty() {
        default
    } else {
        value
    }
}

/// Build the manager from the catalog + the decrypted creds. Every catalog
/// backend name must have a matching cred in the bundle (fail closed otherwise).
async fn build_manager(
    defaults: &BackendDefaults<'_>,
    catalog: crate::Catalog,
    creds: &CredBundle,
) -> Result<(BackendManager, String)> {
    anyhow::ensure!(
        !catalog.backends.is_empty(),
        "catalog declares no backends; nothing to route to"
    );

    let mut backends: BTreeMap<String, Box<dyn Backend>> = BTreeMap::new();
    let mut label: Option<String> = None;
    for (name, backend_ref) in &catalog.backends {
        let cred = creds.backends.get(name).with_context(|| {
            format!("sealed bundle has no credential for catalog backend `{name}`")
        })?;
        let backend = backend_from_cred(name, backend_ref, cred, defaults).await?;
        if label.is_none() {
            label = Some(backend.kind().to_string());
        }
        backends.insert(name.clone(), backend);
    }
    let backend_label = label.unwrap_or_else(|| "unknown".to_string());

    let manager = BackendManager::new(catalog, backends)
        .context("constructing backend manager from catalog")?;
    Ok((manager, backend_label))
}

/// The only startup settings that may be supplied outside the config file.
#[derive(Debug, Clone, clap::Args)]
pub struct ConfigOverrides {
    /// Path to the TOML daemon config file.
    #[arg(short = 'c', long, env = "BASIL_CONFIG")]
    pub(crate) config: Option<PathBuf>,

    /// Path to the exported **catalog** JSON (the key inventory + routing table).
    #[arg(long, env = "BASIL_CATALOG")]
    pub(crate) catalog: Option<PathBuf>,

    /// Path to the exported **policy** JSON (the authorization allow-list).
    #[arg(long, env = "BASIL_POLICY")]
    pub(crate) policy: Option<PathBuf>,

    /// Path to the `0600` sealed credential bundle (vault-vh1).
    #[arg(long, env = "BASIL_BUNDLE")]
    pub(crate) bundle: Option<PathBuf>,

    /// Unix socket to listen on.
    #[arg(long, env = "BASIL_SOCKET")]
    pub(crate) socket: Option<String>,

    /// Default Vault address (used when a cred pins no `addr`).
    #[arg(long, env = "VAULT_ADDR")]
    pub(crate) vault_addr: Option<String>,
}

/// TOML startup config for `run` and `check`.
///
/// Top-level keys intentionally mirror the former long flag names, e.g.
/// `vault-addr`, `max-encrypt-size`, and `capability-policy`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct AgentConfigFile {
    pub(crate) catalog: Option<PathBuf>,
    pub(crate) policy: Option<PathBuf>,
    pub(crate) bundle: Option<PathBuf>,
    pub(crate) socket: Option<String>,
    pub(crate) socket_mode: Option<SocketMode>,
    pub(crate) socket_group: Option<String>,
    pub(crate) vault_addr: Option<String>,
    pub(crate) transit_mount: Option<String>,
    pub(crate) jwt_auth_mount: Option<String>,
    pub(crate) jwt_role: Option<String>,
    pub(crate) jwt_audience: Option<String>,
    pub(crate) svid_ttl_secs: Option<u64>,
    pub(crate) capability_policy: Option<String>,
    #[cfg(feature = "keystore-backend")]
    pub(crate) db_keystore_cipher: Option<String>,
    #[cfg(feature = "keystore-backend")]
    pub(crate) onepassword_provider_uri: Option<String>,
    #[cfg(feature = "keystore-backend")]
    pub(crate) onepassword_project: Option<String>,
    #[cfg(feature = "keystore-backend")]
    pub(crate) onepassword_profile: Option<String>,
    pub(crate) max_encrypt_size: Option<usize>,
    pub(crate) max_payload_size: Option<usize>,
    pub(crate) grace_versions: Option<u32>,
    pub(crate) retain_versions: Option<u32>,
    pub(crate) retention_sweep_secs: Option<u64>,
    pub(crate) audit_log: Option<PathBuf>,
    pub(crate) no_reconcile: Option<bool>,
    pub(crate) logging: LoggingConfigFile,
    pub(crate) unlock: UnlockConfigFile,
    pub(crate) broker_identity: BrokerIdentityConfigFile,
    pub(crate) invocation: InvocationConfigFile,
    pub(crate) jwks: JwksConfigFile,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct LoggingConfigFile {
    stdout: StdoutLoggingSinkConfigFile,
    journald: LoggingSinkConfigFile,
    file: FileLoggingConfigFile,
    opentelemetry: OpenTelemetryLoggingConfigFile,
}

impl Default for LoggingConfigFile {
    fn default() -> Self {
        Self {
            stdout: StdoutLoggingSinkConfigFile::default(),
            journald: LoggingSinkConfigFile { enable: true },
            file: FileLoggingConfigFile::default(),
            opentelemetry: OpenTelemetryLoggingConfigFile::default(),
        }
    }
}

impl LoggingConfigFile {
    fn stdout_enabled(&self) -> bool {
        self.stdout.enable.unwrap_or(!self.file.enable)
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
struct StdoutLoggingSinkConfigFile {
    enable: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
struct LoggingSinkConfigFile {
    enable: bool,
}

impl Default for LoggingSinkConfigFile {
    fn default() -> Self {
        Self { enable: true }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
struct FileLoggingConfigFile {
    enable: bool,
    #[serde(alias = "path")]
    dir: Option<PathBuf>,
    prefix: String,
    rotation: FileLoggingRotation,
}

impl Default for FileLoggingConfigFile {
    fn default() -> Self {
        Self {
            enable: false,
            dir: None,
            prefix: "basil-agent-".to_owned(),
            rotation: FileLoggingRotation::Daily,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum FileLoggingRotation {
    None,
    Hourly,
    Daily,
    Weekly,
}

impl From<FileLoggingRotation> for tracing_appender::rolling::Rotation {
    fn from(rotation: FileLoggingRotation) -> Self {
        match rotation {
            FileLoggingRotation::None => Self::NEVER,
            FileLoggingRotation::Hourly => Self::HOURLY,
            FileLoggingRotation::Daily => Self::DAILY,
            FileLoggingRotation::Weekly => Self::WEEKLY,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
struct OpenTelemetryLoggingConfigFile {
    enable: bool,
    endpoint: Option<String>,
    protocol: OpenTelemetryProtocol,
}

impl Default for OpenTelemetryLoggingConfigFile {
    fn default() -> Self {
        Self {
            enable: false,
            endpoint: None,
            protocol: OpenTelemetryProtocol::Grpc,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum OpenTelemetryProtocol {
    Grpc,
    HttpBinary,
    HttpJson,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SocketMode(pub(crate) u32);

impl SocketMode {
    const MAX: u32 = 0o7777;
}

impl<'de> Deserialize<'de> for SocketMode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(SocketModeVisitor)
    }
}

struct SocketModeVisitor;

impl Visitor<'_> for SocketModeVisitor {
    type Value = SocketMode;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("an octal socket mode string like \"0660\" or integer mode")
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let mode = u32::try_from(value).map_err(|_| E::custom("socket mode is too large"))?;
        validate_socket_mode(mode)
            .map(SocketMode)
            .map_err(E::custom)
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let mode = u32::try_from(value).map_err(|_| E::custom("socket mode must be positive"))?;
        validate_socket_mode(mode)
            .map(SocketMode)
            .map_err(E::custom)
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        parse_socket_mode(value).map(SocketMode).map_err(E::custom)
    }
}

fn parse_socket_mode(value: &str) -> Result<u32, String> {
    let trimmed = value.trim();
    let octal = trimmed.strip_prefix("0o").unwrap_or(trimmed);
    if octal.is_empty() {
        return Err("socket mode must not be empty".to_string());
    }
    if !octal.chars().all(|c| matches!(c, '0'..='7')) {
        return Err(format!("socket mode `{value}` must be octal"));
    }
    let mode = u32::from_str_radix(octal, 8)
        .map_err(|err| format!("socket mode `{value}` is invalid: {err}"))?;
    validate_socket_mode(mode)
}

fn validate_socket_mode(mode: u32) -> Result<u32, String> {
    if mode > SocketMode::MAX {
        return Err(format!("socket mode {mode:o} exceeds 07777"));
    }
    Ok(mode)
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct UnlockConfigFile {
    age_yubikey: Option<bool>,
    bip39_phrase_file: Option<PathBuf>,
    unlock_tpm: Option<bool>,
    unlock_passphrase_file: Option<PathBuf>,
    unlock_passphrase_no_wipe: Option<bool>,
    strict_bundle_perms: Option<bool>,
}

/// The `[broker-identity]` config section for response protection.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct BrokerIdentityConfigFile {
    /// Stable broker identity / audience URI.
    id: Option<String>,
    /// Catalog key id used to sign invocation responses.
    response_signing_key_id: Option<String>,
}

/// The `[invocation]` config section for the sealed invocation gRPC service.
///
/// `enable` defaults to `false`: the service is registered so clients get a
/// stable method, but it rejects all requests unless an operator explicitly
/// enables bridged sealed invocations.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct InvocationConfigFile {
    /// Accept sealed invocation requests. Default `false`.
    enable: bool,
    /// Accepted broker audiences for sealed invocations.
    audience: Vec<String>,
    /// Catalog key id whose public half receives sealed invocation requests.
    request_encryption_key_id: Option<String>,
    /// Maximum accepted signed request TTL in seconds.
    max_ttl_secs: u32,
    /// Allowed clock skew in seconds.
    clock_skew_secs: u32,
    /// Maximum in-memory replay-cache entries.
    replay_cache_capacity: usize,
}

impl Default for InvocationConfigFile {
    fn default() -> Self {
        Self {
            enable: false,
            audience: Vec::new(),
            request_encryption_key_id: None,
            max_ttl_secs: basil_proto::invocation::DEFAULT_EXPIRES_AFTER_SECS,
            clock_skew_secs: 30,
            replay_cache_capacity: 4096,
        }
    }
}

/// The `[jwks]` config section: the **opt-in** JWKS HTTP surface (`basil-uce.1`).
///
/// `enable` **defaults to `false`**: the HTTP port is NOT opened unless an
/// operator explicitly turns it on. This is the broker's first HTTP endpoint in
/// an otherwise gRPC-over-unix-socket system, so it is strictly opt-in. When
/// enabled, a standard verifier can fetch the issuer JWK set (public keys only)
/// and validate Basil-minted JWT-SVID signatures without SPIFFE plumbing.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct JwksConfigFile {
    /// Open the JWKS HTTP listener. Default `false` (no port opened).
    enable: bool,
    /// Address to bind when `enable` is true. Default `127.0.0.1:8201`.
    listen: String,
    /// Public base URL the surface is reachable at (no trailing slash), used as
    /// the OIDC discovery `issuer` and the base for `jwks_uri`. When unset, the
    /// `/.well-known/openid-configuration` discovery document is **not** served
    /// (the bare JWKS endpoints still are). Example: `https://basil.example.com`.
    issuer: Option<String>,
    /// Optional native TLS listener settings.
    tls: JwksTlsConfigFile,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct JwksTlsConfigFile {
    /// Serve the JWKS surface over TLS. Requires the `http-tls` cargo feature.
    enable: bool,
    /// PEM certificate chain file for the TLS listener.
    cert_file: Option<PathBuf>,
    /// PEM private-key file for the TLS listener.
    key_file: Option<PathBuf>,
}

impl Default for JwksConfigFile {
    fn default() -> Self {
        Self {
            enable: false,
            listen: "127.0.0.1:8201".to_string(),
            issuer: None,
            tls: JwksTlsConfigFile::default(),
        }
    }
}

/// Resolved JWKS HTTP-surface settings threaded into [`RunConfig`].
#[cfg(feature = "http")]
#[derive(Debug, Clone)]
struct JwksConfig {
    enable: bool,
    listen: std::net::SocketAddr,
    issuer: Option<String>,
    tls: Option<crate::jwks::JwksTlsConfig>,
}

/// The setup inputs shared by every subcommand that needs a live
/// [`BackendManager`].
#[derive(Debug, Clone)]
struct SetupArgs {
    catalog: PathBuf,
    policy: PathBuf,
    bundle: PathBuf,
    vault_addr: String,
    transit_mount: String,
    jwt_auth_mount: String,
    jwt_role: String,
    jwt_audience: String,
    svid_ttl_secs: u64,
    capability_policy: CapabilityPolicy,
    #[cfg(feature = "db-keystore")]
    db_keystore_cipher: String,
    #[cfg(feature = "keystore-backend")]
    onepassword_provider_uri: String,
    #[cfg(feature = "keystore-backend")]
    onepassword_project: String,
    #[cfg(feature = "keystore-backend")]
    onepassword_profile: String,
    unlock: unlock::UnlockArgs,
}

#[derive(Debug, Clone)]
struct RunConfig {
    socket: Option<String>,
    socket_mode: u32,
    socket_group: Option<String>,
    max_encrypt_size: usize,
    max_payload_size: usize,
    grace_versions: u32,
    retain_versions: Option<u32>,
    retention_sweep_secs: u64,
    audit_log: Option<PathBuf>,
    no_reconcile: bool,
    invocation: InvocationRuntimeConfig,
    #[cfg(feature = "http")]
    jwks: JwksConfig,
    setup: SetupArgs,
}

/// clap value parser for [`CapabilityPolicy`] (`strict` | `degraded` | `off`).
fn parse_capability_policy(s: &str) -> Result<CapabilityPolicy, String> {
    s.parse()
}

fn load_run_config(overrides: &ConfigOverrides) -> Result<RunConfig> {
    let file = load_config_file(overrides)?;
    let setup = build_setup(&file, overrides)?;
    #[cfg(feature = "http")]
    let jwks = resolve_jwks_config(&file.jwks)?;
    #[cfg(not(feature = "http"))]
    reject_jwks_config(&file.jwks)?;
    Ok(RunConfig {
        socket: overrides.socket.clone().or(file.socket),
        socket_mode: file.socket_mode.map_or(DEFAULT_SOCKET_MODE, |mode| mode.0),
        socket_group: file.socket_group,
        max_encrypt_size: file.max_encrypt_size.unwrap_or(DEFAULT_MAX_ENCRYPT_SIZE),
        max_payload_size: file.max_payload_size.unwrap_or(DEFAULT_MAX_PAYLOAD_SIZE),
        grace_versions: file
            .grace_versions
            .unwrap_or(DEFAULT_ROTATION_GRACE_VERSIONS),
        retain_versions: file.retain_versions,
        retention_sweep_secs: file.retention_sweep_secs.unwrap_or(3600),
        audit_log: file.audit_log,
        no_reconcile: file.no_reconcile.unwrap_or(false),
        invocation: resolve_invocation_config(&file.broker_identity, &file.invocation)?,
        #[cfg(feature = "http")]
        jwks,
        setup,
    })
}

fn resolve_invocation_config(
    identity_file: &BrokerIdentityConfigFile,
    file: &InvocationConfigFile,
) -> Result<InvocationRuntimeConfig> {
    if file.max_ttl_secs == 0 {
        bail!("invocation.max-ttl-secs must be greater than zero");
    }
    if file.max_ttl_secs > MAX_INVOCATION_TTL_SECS {
        bail!("invocation.max-ttl-secs must be at most {MAX_INVOCATION_TTL_SECS} seconds");
    }
    if file.clock_skew_secs > MAX_INVOCATION_CLOCK_SKEW_SECS {
        bail!(
            "invocation.clock-skew-secs must be at most {MAX_INVOCATION_CLOCK_SKEW_SECS} seconds"
        );
    }
    if file.replay_cache_capacity == 0 {
        bail!("invocation.replay-cache-capacity must be greater than zero");
    }
    if file.replay_cache_capacity > MAX_INVOCATION_REPLAY_CACHE_CAPACITY {
        bail!(
            "invocation.replay-cache-capacity must be at most {MAX_INVOCATION_REPLAY_CACHE_CAPACITY}"
        );
    }
    let broker_identity = resolve_broker_identity_config(identity_file)?;
    let request_encryption_key_id = optional_nonempty_config(
        "invocation.request-encryption-key-id",
        file.request_encryption_key_id.as_ref(),
    )?;
    let mut audiences = Vec::with_capacity(file.audience.len());
    for audience in &file.audience {
        let trimmed = audience.trim();
        if trimmed.is_empty() {
            bail!("invocation.audience must not contain blank values");
        }
        validate_basil_identity_uri("invocation.audience", trimmed)?;
        audiences.push(trimmed.to_string());
    }
    audiences.sort();
    audiences.dedup();
    if file.enable && audiences.is_empty() {
        bail!("invocation.audience must be set when invocation.enable is true");
    }
    if file.enable && broker_identity.is_none() {
        bail!(
            "broker-identity.id and broker-identity.response-signing-key-id are required when invocation.enable is true"
        );
    }
    if file.enable && request_encryption_key_id.is_none() {
        bail!("invocation.request-encryption-key-id is required when invocation.enable is true");
    }
    Ok(InvocationRuntimeConfig {
        enabled: file.enable,
        broker_identity,
        audiences,
        request_encryption_key_id,
        max_ttl_secs: file.max_ttl_secs,
        clock_skew_secs: file.clock_skew_secs,
        replay_cache_capacity: file.replay_cache_capacity,
        now_unix_override: None,
    })
}

fn resolve_broker_identity_config(
    file: &BrokerIdentityConfigFile,
) -> Result<Option<BrokerIdentityRuntimeConfig>> {
    let id = optional_nonempty_config("broker-identity.id", file.id.as_ref())?;
    let response_signing_key_id = optional_nonempty_config(
        "broker-identity.response-signing-key-id",
        file.response_signing_key_id.as_ref(),
    )?;
    match (id, response_signing_key_id) {
        (None, None) => Ok(None),
        (Some(id), Some(response_signing_key_id)) => {
            validate_basil_identity_uri("broker-identity.id", &id)?;
            Ok(Some(BrokerIdentityRuntimeConfig {
                id,
                response_signing_key_id,
            }))
        }
        (None, Some(_)) | (Some(_), None) => {
            bail!(
                "broker-identity.id and broker-identity.response-signing-key-id must be set together"
            )
        }
    }
}

fn optional_nonempty_config(field: &str, value: Option<&String>) -> Result<Option<String>> {
    let Some(raw) = value else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("{field} must not be empty");
    }
    Ok(Some(trimmed.to_string()))
}

fn validate_basil_identity_uri(field: &str, value: &str) -> Result<()> {
    let parsed =
        reqwest::Url::parse(value).with_context(|| format!("parsing {field} `{value}`"))?;
    if parsed.scheme() != "basil" {
        bail!("{field} must use the basil:// scheme");
    }
    if parsed.host_str().is_none_or(str::is_empty) {
        bail!("{field} must include a host component");
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        bail!("{field} must not include userinfo");
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        bail!("{field} must not include query or fragment components");
    }
    if parsed.path() == "/" || parsed.path().trim_matches('/').is_empty() {
        bail!("{field} must include a non-empty path component");
    }
    Ok(())
}

pub(crate) fn validate_invocation_catalog_bindings(
    invocation: &InvocationRuntimeConfig,
    catalog: &crate::Catalog,
) -> Result<()> {
    if !invocation.enabled {
        return Ok(());
    }
    let identity = invocation
        .broker_identity
        .as_ref()
        .context("broker identity is required when invocation is enabled")?;
    validate_response_signing_key(catalog, &identity.response_signing_key_id)?;
    let request_encryption_key_id = invocation
        .request_encryption_key_id
        .as_deref()
        .context("request encryption key is required when invocation is enabled")?;
    validate_request_encryption_key(catalog, request_encryption_key_id)
}

fn catalog_key<'a>(
    catalog: &'a crate::Catalog,
    key_id: &str,
    field: &'static str,
) -> Result<&'a crate::catalog::KeyEntry> {
    catalog
        .keys
        .get(key_id)
        .with_context(|| format!("{field} references unknown catalog key `{key_id}`"))
}

fn validate_response_signing_key(catalog: &crate::Catalog, key_id: &str) -> Result<()> {
    let key = catalog_key(catalog, key_id, "broker-identity.response-signing-key-id")?;
    if key.class != Class::Asymmetric {
        bail!("broker response-signing key `{key_id}` must be class `asymmetric`");
    }
    let Some(algorithm) = key.key_type else {
        bail!("broker response-signing key `{key_id}` must declare keyType");
    };
    if !is_broker_response_signing_algorithm(algorithm) {
        bail!(
            "broker response-signing key `{key_id}` has unsupported keyType `{}`",
            algorithm.token()
        );
    }
    validate_broker_key_use(
        key_id,
        key,
        BROKER_RESPONSE_SIGNING_USE,
        "broker response-signing key",
    )
}

fn validate_request_encryption_key(catalog: &crate::Catalog, key_id: &str) -> Result<()> {
    let key = catalog_key(catalog, key_id, "invocation.request-encryption-key-id")?;
    if key.class != Class::Sealing {
        bail!("broker request-encryption key `{key_id}` must be class `sealing`");
    }
    validate_broker_key_use(
        key_id,
        key,
        BROKER_REQUEST_ENCRYPTION_USE,
        "broker request-encryption key",
    )
}

fn validate_broker_key_use(
    key_id: &str,
    key: &crate::catalog::KeyEntry,
    expected: &str,
    role: &str,
) -> Result<()> {
    match key.labels.get(BROKER_KEY_USE_LABEL) {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => bail!(
            "{role} `{key_id}` must carry label `{BROKER_KEY_USE_LABEL}={expected}`, got `{actual}`"
        ),
        None => bail!("{role} `{key_id}` must carry label `{BROKER_KEY_USE_LABEL}={expected}`"),
    }
}

const fn is_broker_response_signing_algorithm(algorithm: KeyAlgorithm) -> bool {
    matches!(
        algorithm,
        KeyAlgorithm::Ed25519
            | KeyAlgorithm::Rsa2048
            | KeyAlgorithm::EcdsaP256
            | KeyAlgorithm::MlDsa44
            | KeyAlgorithm::MlDsa65
            | KeyAlgorithm::MlDsa87
    )
}

/// Resolve the `[jwks]` section, parsing `listen` to a [`SocketAddr`] so a
/// malformed address fails closed at startup rather than at bind time. The
/// `listen` value is parsed even when `enable` is false (config validity is
/// independent of whether the listener will be opened).
#[cfg(feature = "http")]
fn resolve_jwks_config(file: &JwksConfigFile) -> Result<JwksConfig> {
    let listen = file
        .listen
        .parse::<std::net::SocketAddr>()
        .with_context(|| format!("parsing jwks.listen `{}`", file.listen))?;
    // Normalize the issuer base URL: must be absolute http(s), trailing slash
    // stripped so `issuer + path` is well-formed. A malformed value fails closed
    // at startup rather than serving an inconsistent discovery document.
    let issuer = match file.issuer.as_deref().map(str::trim) {
        Some(s) if !s.is_empty() => Some(
            parse_public_http_url("jwks.issuer", s)?
                .to_string()
                .trim_end_matches('/')
                .to_string(),
        ),
        _ => None,
    };
    Ok(JwksConfig {
        enable: file.enable,
        listen,
        issuer,
        tls: resolve_jwks_tls_config(&file.tls)?,
    })
}

#[cfg(not(feature = "http"))]
fn reject_jwks_config(file: &JwksConfigFile) -> Result<()> {
    if file.enable {
        bail!("jwks.enable requires the http cargo feature");
    }
    if file.tls.enable {
        bail!("jwks.tls.enable requires the http cargo feature");
    }
    Ok(())
}

#[cfg(feature = "http")]
fn resolve_jwks_tls_config(file: &JwksTlsConfigFile) -> Result<Option<crate::jwks::JwksTlsConfig>> {
    if !file.enable {
        return Ok(None);
    }
    #[cfg(not(feature = "http-tls"))]
    {
        anyhow::bail!("jwks.tls.enable requires the http-tls cargo feature");
    }
    #[cfg(feature = "http-tls")]
    {
        let cert_file = file
            .cert_file
            .clone()
            .context("jwks.tls.cert-file is required when jwks.tls.enable = true")?;
        let key_file = file
            .key_file
            .clone()
            .context("jwks.tls.key-file is required when jwks.tls.enable = true")?;
        Ok(Some(crate::jwks::JwksTlsConfig {
            cert_file,
            key_file,
        }))
    }
}

#[cfg(any(feature = "http", feature = "otlp"))]
fn parse_public_http_url(field: &str, value: &str) -> Result<reqwest::Url> {
    let parsed =
        reqwest::Url::parse(value).with_context(|| format!("parsing {field} `{value}`"))?;
    match parsed.scheme() {
        "http" | "https" => {}
        scheme => bail!("{field} must use http or https, got `{scheme}`"),
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        bail!("{field} must not include userinfo");
    }
    if parsed.fragment().is_some() {
        bail!("{field} must not include a fragment");
    }
    reject_metadata_host(field, &parsed)?;
    Ok(parsed)
}

#[cfg(any(feature = "http", feature = "otlp"))]
fn reject_metadata_host(field: &str, parsed: &reqwest::Url) -> Result<()> {
    let Some(host) = parsed.host_str() else {
        return Ok(());
    };
    if host.eq_ignore_ascii_case("metadata.google.internal") {
        bail!("{field} must not target cloud instance metadata hosts");
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>()
        && is_metadata_ip(ip)
    {
        bail!("{field} must not target link-local or cloud instance metadata addresses");
    }
    Ok(())
}

#[cfg(any(feature = "http", feature = "otlp"))]
fn is_metadata_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(addr) => addr.is_link_local() || addr.octets() == [100, 100, 100, 200],
        std::net::IpAddr::V6(addr) => addr.is_unicast_link_local(),
    }
}

/// True when `addr` is a plaintext `http://` URL whose host is not a literal
/// loopback IP. The URL is parsed rather than substring-matched, so a host like
/// `127.0.0.1.evil.example` cannot suppress the plaintext warning; hostnames
/// (`localhost` included) count as non-loopback because name resolution is not
/// under our control. An unparsable `http://`-prefixed address still warns.
fn is_plaintext_non_loopback_http(addr: &str) -> bool {
    let Ok(parsed) = url::Url::parse(addr) else {
        return addr.starts_with("http://");
    };
    if parsed.scheme() != "http" {
        return false;
    }
    match parsed.host() {
        Some(url::Host::Ipv4(ip)) => !ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => !ip.is_loopback(),
        Some(url::Host::Domain(_)) | None => true,
    }
}

/// Resolve the setup `doctor --keys` unlocks with. The authenticated key probe is
/// a preflight read; it must not consume a passphrase file that the subsequent
/// agent start needs, so it sets `passphrase_no_wipe`.
fn load_key_probe_config(overrides: &ConfigOverrides) -> Result<SetupArgs> {
    let file = load_config_file(overrides)?;
    let mut setup = build_setup(&file, overrides)?;
    setup.unlock.passphrase_no_wipe = true;
    Ok(setup)
}

pub(crate) fn load_config_file(overrides: &ConfigOverrides) -> Result<AgentConfigFile> {
    let Some(path) = &overrides.config else {
        return Ok(AgentConfigFile::default());
    };
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading config from {}", path.display()))?;
    toml::from_str(&raw).with_context(|| format!("parsing config from {}", path.display()))
}

struct LoggingGuards {
    file_guard: Option<tracing_appender::non_blocking::WorkerGuard>,
    #[cfg(feature = "otlp")]
    otel_provider: Option<SdkLoggerProvider>,
}

#[cfg(feature = "otlp")]
type OtelTracingLayer =
    OpenTelemetryTracingBridge<SdkLoggerProvider, opentelemetry_sdk::logs::SdkLogger>;
#[cfg(feature = "otlp")]
type OptionalOtelLayer = (Option<OtelTracingLayer>, Option<SdkLoggerProvider>);

#[cfg(feature = "otlp")]
impl LoggingGuards {
    fn shutdown(self) {
        let Self {
            file_guard,
            otel_provider,
        } = self;
        drop(file_guard);
        if let Some(provider) = otel_provider
            && let Err(err) = provider.shutdown()
        {
            warn!(error = %err, "failed to shut down OpenTelemetry logger provider");
        }
    }
}

#[cfg(not(feature = "otlp"))]
impl LoggingGuards {
    fn shutdown(self) {
        let Self { file_guard } = self;
        drop(file_guard);
    }
}

/// Resolution of the journald log sink.
///
/// Journald is the right default for the systemd-managed daemon, but a journal
/// socket is absent on minimal hosts (containers, initramfs, CI) where the
/// offline `basil doctor`/`explain` commands run. An unavailable socket is
/// reported once to stderr, but it must not install a duplicate stderr log sink.
enum JournaldSink {
    /// Journald disabled in config; no journald sink.
    Disabled,
    /// Journald socket opened; emit through this layer.
    Active(tracing_journald::Layer),
    /// Journald requested but the socket is unavailable.
    Unavailable(String),
}

fn journald_sink(enabled: bool) -> JournaldSink {
    if !enabled {
        return JournaldSink::Disabled;
    }
    match tracing_journald::layer() {
        Ok(layer) => JournaldSink::Active(layer),
        Err(err) => JournaldSink::Unavailable(err.to_string()),
    }
}

fn init_logging(config: &LoggingConfigFile) -> Result<LoggingGuards> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let stdout_layer = config.stdout_enabled().then(fmt::layer);

    let (journald_layer, journald_error) = match journald_sink(config.journald.enable) {
        JournaldSink::Disabled => (None, None),
        JournaldSink::Active(layer) => (Some(layer), None),
        JournaldSink::Unavailable(err) => (None, Some(err)),
    };

    let (file_writer, file_guard) = build_file_writer(&config.file)?;
    let file_layer = file_writer.map(|writer| fmt::layer().with_writer(writer));

    #[cfg(feature = "otlp")]
    let (otel_layer, otel_provider) = build_otel_layer(&config.opentelemetry)?;
    #[cfg(not(feature = "otlp"))]
    ensure_otel_disabled(&config.opentelemetry)?;

    let subscriber = tracing_subscriber::registry()
        .with(env_filter)
        .with(stdout_layer)
        .with(journald_layer)
        .with(file_layer);
    #[cfg(feature = "otlp")]
    let subscriber = subscriber.with(otel_layer);
    subscriber
        .try_init()
        .context("initializing tracing subscriber")?;

    if let Some(err) = journald_error {
        eprintln!("journald log sink unavailable: {err}");
    }

    Ok(LoggingGuards {
        file_guard,
        #[cfg(feature = "otlp")]
        otel_provider,
    })
}

type FileMakeWriter = tracing_appender::non_blocking::NonBlocking;

fn build_file_writer(
    config: &FileLoggingConfigFile,
) -> Result<(
    Option<FileMakeWriter>,
    Option<tracing_appender::non_blocking::WorkerGuard>,
)> {
    if !config.enable {
        return Ok((None, None));
    }

    let Some(dir) = config.dir.as_deref() else {
        bail!("logging.file.dir is required when logging.file.enable=true");
    };

    let appender = match tracing_appender::rolling::RollingFileAppender::builder()
        .rotation(config.rotation.into())
        .filename_prefix(config.prefix.clone())
        .build(dir)
    {
        Ok(appender) => appender,
        Err(err) => {
            eprintln!("file log sink unavailable at {}: {err}", dir.display());
            return Ok((None, None));
        }
    };

    let writer = ReportingWriter::new(appender);
    let (non_blocking, guard) = tracing_appender::non_blocking(writer);
    Ok((Some(non_blocking), Some(guard)))
}

struct ReportingWriter<W> {
    inner: W,
}

impl<W> ReportingWriter<W> {
    const fn new(inner: W) -> Self {
        Self { inner }
    }
}

impl<W: Write> Write for ReportingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.inner.write(buf) {
            Ok(size) => Ok(size),
            Err(err) => {
                eprintln!("failed to write to file log sink: {err}");
                Err(err)
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.inner.flush() {
            Ok(()) => Ok(()),
            Err(err) => {
                eprintln!("failed to flush file log sink: {err}");
                Err(err)
            }
        }
    }
}

#[cfg(not(feature = "otlp"))]
fn ensure_otel_disabled(config: &OpenTelemetryLoggingConfigFile) -> Result<()> {
    if config.enable {
        bail!(
            "logging.opentelemetry.enable=true but this basil binary was built without the `otlp` feature"
        );
    }
    Ok(())
}

#[cfg(feature = "otlp")]
fn build_otel_layer(config: &OpenTelemetryLoggingConfigFile) -> Result<OptionalOtelLayer> {
    if !config.enable {
        return Ok((None, None));
    }
    let endpoint = required_otel_endpoint(config)?;
    let exporter = match config.protocol {
        OpenTelemetryProtocol::Grpc => opentelemetry_otlp::LogExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .build(),
        OpenTelemetryProtocol::HttpBinary => opentelemetry_otlp::LogExporter::builder()
            .with_http()
            .with_protocol(Protocol::HttpBinary)
            .with_endpoint(endpoint)
            .build(),
        OpenTelemetryProtocol::HttpJson => opentelemetry_otlp::LogExporter::builder()
            .with_http()
            .with_protocol(Protocol::HttpJson)
            .with_endpoint(endpoint)
            .build(),
    }
    .context("building OpenTelemetry log exporter")?;
    let provider = SdkLoggerProvider::builder()
        .with_batch_exporter(exporter)
        .build();
    let layer = OpenTelemetryTracingBridge::new(&provider);
    Ok((Some(layer), Some(provider)))
}

#[cfg(feature = "otlp")]
fn required_otel_endpoint(config: &OpenTelemetryLoggingConfigFile) -> Result<String> {
    let endpoint = config
        .endpoint
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .context(
            "logging.opentelemetry.endpoint is required when OpenTelemetry logging is enabled",
        )?;
    Ok(parse_public_http_url("logging.opentelemetry.endpoint", endpoint)?.to_string())
}

fn build_setup(file: &AgentConfigFile, overrides: &ConfigOverrides) -> Result<SetupArgs> {
    let catalog = required_path(
        overrides.catalog.clone().or_else(|| file.catalog.clone()),
        "catalog",
    )?;
    let policy = required_path(
        overrides.policy.clone().or_else(|| file.policy.clone()),
        "policy",
    )?;
    let bundle = required_path(
        overrides.bundle.clone().or_else(|| file.bundle.clone()),
        "bundle",
    )?;
    let vault_addr = overrides
        .vault_addr
        .clone()
        .or_else(|| file.vault_addr.clone())
        .unwrap_or_else(|| "http://127.0.0.1:8200".to_string());
    let capability_policy = file
        .capability_policy
        .as_deref()
        .map_or(Ok(CapabilityPolicy::Strict), parse_capability_policy)
        .map_err(|err| anyhow::anyhow!("parsing config key `capability-policy`: {err}"))?;

    Ok(SetupArgs {
        catalog,
        policy,
        bundle,
        vault_addr,
        transit_mount: file
            .transit_mount
            .clone()
            .unwrap_or_else(|| "transit".to_string()),
        jwt_auth_mount: file
            .jwt_auth_mount
            .clone()
            .unwrap_or_else(|| "jwt".to_string()),
        jwt_role: file.jwt_role.clone().unwrap_or_default(),
        jwt_audience: file
            .jwt_audience
            .clone()
            .unwrap_or_else(|| "openbao".to_string()),
        svid_ttl_secs: file.svid_ttl_secs.unwrap_or(DEFAULT_SVID_TTL_SECS),
        capability_policy,
        #[cfg(feature = "db-keystore")]
        db_keystore_cipher: file
            .db_keystore_cipher
            .clone()
            .unwrap_or_else(|| "aegis256".to_string()),
        #[cfg(feature = "keystore-backend")]
        onepassword_provider_uri: file.onepassword_provider_uri.clone().unwrap_or_default(),
        #[cfg(feature = "keystore-backend")]
        onepassword_project: file.onepassword_project.clone().unwrap_or_default(),
        #[cfg(feature = "keystore-backend")]
        onepassword_profile: file.onepassword_profile.clone().unwrap_or_default(),
        unlock: unlock::UnlockArgs {
            age_yubikey: file.unlock.age_yubikey.unwrap_or(false),
            bip39_phrase_file: file.unlock.bip39_phrase_file.clone(),
            tpm: file.unlock.unlock_tpm.unwrap_or(false),
            passphrase_file: file.unlock.unlock_passphrase_file.clone(),
            passphrase_no_wipe: file.unlock.unlock_passphrase_no_wipe.unwrap_or(false),
            strict_bundle_perms: file.unlock.strict_bundle_perms.unwrap_or(false),
        },
    })
}

fn required_path(path: Option<PathBuf>, name: &str) -> Result<PathBuf> {
    path.with_context(|| {
        format!(
            "`{name}` is required; set it in the config file or pass --{name} / the BASIL_{} env var",
            name.to_ascii_uppercase()
        )
    })
}

/// The loaded, validated catalog/policy plus a live [`BackendManager`] over the
/// unlocked creds: the common ground both `run` (serve) and `check` (lint)
/// stand on.
struct Prepared {
    catalog: Arc<crate::Catalog>,
    policy: crate::ResolvedPolicy,
    config: crate::Config,
    manager: BackendManager,
    backend_label: String,
}

/// Load + validate the exported catalog/policy, unlock the sealed bundle, and
/// build the routed [`BackendManager`] over the decrypted creds. The shared
/// startup pipeline for `run` and `check`; fails closed (clean non-zero, no
/// panic) at every step. The plaintext [`CredBundle`] is zeroized before return;
/// each backend holds only its own cred.
async fn prepare_manager(setup: &SetupArgs) -> Result<Prepared> {
    if is_plaintext_non_loopback_http(&setup.vault_addr) {
        warn!(addr = %setup.vault_addr, "talking to vault over plaintext HTTP");
    }

    // Load + validate the exported catalog & policy.
    let catalog_json = std::fs::read_to_string(&setup.catalog)
        .with_context(|| format!("reading catalog from {}", setup.catalog.display()))?;
    let policy_json = std::fs::read_to_string(&setup.policy)
        .with_context(|| format!("reading policy from {}", setup.policy.display()))?;
    let (catalog, policy, config, warnings) =
        load(&catalog_json, &policy_json).context("loading catalog/policy")?;
    for w in &warnings {
        warn!(warning = %w, "catalog/policy load warning");
    }
    info!(
        keys = catalog.keys.len(),
        backends = catalog.backends.len(),
        "loaded catalog + policy",
    );

    // Unlock the sealed bundle -> CredBundle (KEK zeroized inside `open`).
    let creds = unlock::open_bundle_at_startup(&setup.bundle, &setup.unlock)
        .context("unlocking sealed credential bundle")?;
    info!(
        backend_creds = creds.backends.len(),
        "sealed bundle unlocked",
    );

    // Build the manager from catalog + creds, then drop (zeroize) the CredBundle.
    let defaults = BackendDefaults {
        vault_addr: &setup.vault_addr,
        transit_mount: &setup.transit_mount,
        jwt_auth_mount: &setup.jwt_auth_mount,
        jwt_role: &setup.jwt_role,
        jwt_audience: &setup.jwt_audience,
        svid_ttl: Duration::from_secs(setup.svid_ttl_secs),
        #[cfg(feature = "db-keystore")]
        db_keystore_cipher: &setup.db_keystore_cipher,
        #[cfg(feature = "keystore-backend")]
        onepassword_provider_uri: &setup.onepassword_provider_uri,
        #[cfg(feature = "keystore-backend")]
        onepassword_project: &setup.onepassword_project,
        #[cfg(feature = "keystore-backend")]
        onepassword_profile: &setup.onepassword_profile,
    };
    let (manager, backend_label) = build_manager(&defaults, catalog, &creds).await?;
    let catalog = manager.catalog();
    drop(creds); // ZEROIZE the CredBundle: every backend now holds its own cred.

    Ok(Prepared {
        catalog,
        policy,
        config,
        manager,
        backend_label,
    })
}

fn enforce_startup_capabilities(catalog: &crate::Catalog, policy: CapabilityPolicy) -> Result<()> {
    let cap = enforce_capabilities(catalog, policy).context("backend capability check failed")?;
    info!(
        policy = %policy,
        enforced = cap.enforced,
        skipped_undeclared = cap.skipped_undeclared,
        warnings = cap.warnings,
        "capability check complete",
    );
    Ok(())
}

/// Run the broker daemon: load catalog/policy + the sealed bundle, unlock,
/// construct backends from the decrypted creds, then serve.
async fn run_daemon(args: RunArgs, version: &'static str) -> Result<()> {
    let run_config = load_run_config(&args.overrides)?;
    // Shared setup: load catalog/policy, unlock the bundle, build the manager
    // (the CredBundle is zeroized inside `prepare_manager`).
    let Prepared {
        catalog,
        policy,
        config,
        manager,
        backend_label,
    } = prepare_manager(&run_config.setup).await?;

    validate_invocation_catalog_bindings(&run_config.invocation, &catalog)
        .context("validating invocation broker identity and keys")?;

    // Capability enforcement: does each backend PROVIDE what the catalog's keys
    // (+ explicit `requires`) need? A pure, offline catalog check (no backend
    // I/O, no extra Vault privilege), gated by `capability-policy` (default
    // `strict`, fail closed). Runs independently of `no-reconcile`.
    enforce_startup_capabilities(&catalog, run_config.setup.capability_policy)?;

    // Startup reconcile (vault-zrg): apply each key's `missing` policy against its
    // backend BEFORE binding the socket. A required key absent (or a backend
    // unreachable during the probe) is a clean fail-closed startup error (the `?`
    // propagates a non-zero exit, no panic). `no-reconcile` is a recovery hatch.
    if run_config.no_reconcile {
        warn!("startup reconcile skipped (no-reconcile); missing keys will fail at request time");
    } else {
        let summary = manager
            .reconcile()
            .await
            .context("reconciling catalog against backends")?;
        info!(
            present = summary.present,
            generated = summary.generated,
            warned = summary.warned,
            "catalog reconcile complete",
        );
    }

    let limits = BrokerLimits {
        max_encrypt_size: run_config.max_encrypt_size,
        max_payload_size: run_config.max_payload_size,
        grace_versions: run_config.grace_versions,
        svid_ttl_secs: run_config.setup.svid_ttl_secs,
        retain_versions: run_config.retain_versions,
    };
    let jwt_revocations = JwtRevocationStore::load_from_manager(&manager)
        .await
        .context("loading JWT-SVID revocation deny-list")?;
    let mut state =
        BrokerState::with_limits(catalog, policy, config, manager, backend_label, limits)
            // Report the shipped binary's version in `status`/`health`, not this
            // library crate's (they coincide today via the workspace version).
            .with_version(version)
            .with_jwt_revocations(jwt_revocations)
            // The SIGHUP reload engine (basil-y3e.2) re-reads from the SAME
            // configured catalog/policy paths startup used, never the wire.
            .with_reload_inputs(ReloadInputs {
                catalog_path: run_config.setup.catalog.clone(),
                policy_path: run_config.setup.policy.clone(),
            });

    // Optional JSONL audit sink (`vault-vq5`): open the append-only file ONCE at
    // startup so a permissions/path error fails closed here rather than per-op. A
    // per-op append is best-effort thereafter (the sink logs-and-continues).
    let audit_reopen = if let Some(audit_path) = &run_config.audit_log {
        let audit = Arc::new(
            AuditLog::open(audit_path)
                .with_context(|| format!("opening audit log at {}", audit_path.display()))?,
        );
        info!(path = %audit_path.display(), "JSONL audit log enabled");
        state = state.with_audit_log(Arc::clone(&audit));
        Some(audit)
    } else {
        None
    };

    let state = Arc::new(state);
    spawn_sighup_handler(Arc::clone(&state), audit_reopen);
    spawn_retention_sweep(Arc::clone(&state), run_config.retention_sweep_secs);

    let socket_path = run_config
        .socket
        .unwrap_or_else(|| crate::DEFAULT_SOCKET_PATH.to_string());
    let server_config = ServerConfig {
        socket_path,
        socket_mode: run_config.socket_mode,
        socket_group: run_config.socket_group,
        invocation: run_config.invocation,
    };

    // Opt-in JWKS HTTP surface (basil-uce.1). When `[jwks] enable` is false (the
    // default) NO listener is bound: the broker stays gRPC-over-unix-socket only.
    // When enabled, bind here so a bind failure is a clean fail-closed startup
    // error (before the gRPC server starts serving), never a mid-run panic. The
    // server is tied to the SAME lifecycle as the gRPC server: when the gRPC
    // server returns (on its shutdown signal), we trigger the JWKS shutdown and
    // await it, so the HTTP surface never outlives the broker.
    #[cfg(feature = "http")]
    let jwks_shutdown = run_config.jwks.enable.then(|| {
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let http_state = Arc::clone(&state);
        let listen = run_config.jwks.listen;
        let http_config = crate::jwks::JwksHttpConfig {
            issuer: run_config.jwks.issuer.clone(),
            tls: run_config.jwks.tls.clone(),
        };
        let handle = tokio::spawn(async move {
            let shutdown = async {
                let _ = rx.await;
            };
            if let Err(err) = crate::jwks::serve(http_state, listen, http_config, shutdown).await {
                warn!(error = %err, "JWKS HTTP surface terminated with error");
            }
        });
        (tx, handle)
    });

    let grpc_result = run_grpc(server_config, state).await;

    #[cfg(feature = "http")]
    if let Some((tx, handle)) = jwks_shutdown {
        // Signal the HTTP surface to drain and wait for it before returning, so it
        // never keeps serving after the broker stops.
        let _ = tx.send(());
        if let Err(err) = handle.await {
            warn!(error = %err, "JWKS HTTP surface task join failed");
        }
    }

    grpc_result?;
    Ok(())
}

/// Install the SIGHUP handler. SIGHUP is the operational "reload" signal: it
/// (1) hot-reloads the catalog/policy generation (`basil-y3e`) and then
/// (2) reopens the JSONL audit log (rotation). It is installed
/// **unconditionally** (even when no audit log is configured) so that SIGHUP
/// can never fall through to its default disposition (terminate the process).
/// This matters because the Nix module wires `systemctl reload`
/// (`nixos-rebuild switch` on a catalog/policy edit) to `kill -HUP $MAINPID`; the
/// broker must absorb that and reload in place, not die or re-unlock.
///
/// The reload is the shared [`reload_generation`] engine: it re-reads the
/// configured catalog/policy paths, runs the full startup/`check` validation, and
/// on success atomically swaps in a new generation. On **any** failure it fails
/// closed (the previous generation keeps serving) and the rejection is audited;
/// the broker never panics. Reload runs **before** the audit-log reopen so the
/// reload outcome lands in the current log segment. With no audit log configured,
/// the reload still runs (it is signal-driven, not audit-driven).
fn spawn_sighup_handler(state: Arc<BrokerState>, audit: Option<Arc<AuditLog>>) {
    let handle = tokio::spawn(async move {
        let mut hangup = match signal(SignalKind::hangup()) {
            Ok(signal) => signal,
            Err(err) => {
                warn!(error = %err, "SIGHUP handler disabled");
                return;
            }
        };
        while hangup.recv().await.is_some() {
            // 1. Reload the catalog/policy generation (fail-closed: a rejection
            //    keeps the previous generation serving; both outcomes audited).
            handle_sighup_reload(&state).await;
            // 2. Reopen the audit log (rotation), if one is configured.
            if let Some(audit) = &audit {
                audit.request_reopen();
                info!("SIGHUP: requested audit log reopen");
            }
        }
    });
    std::mem::drop(handle);
}

/// Run one SIGHUP-driven reload via the shared [`reload_generation`] engine and
/// audit the outcome. Never panics; on rejection the previous generation keeps
/// serving and the reason is recorded.
async fn handle_sighup_reload(state: &BrokerState) {
    match reload_generation(state) {
        Ok(outcome) => {
            info!(
                previous_generation = outcome.previous_generation,
                generation = outcome.new_generation,
                keys = outcome.key_count,
                grants = outcome.grant_count,
                "SIGHUP: catalog/policy reload applied",
            );
            state.record_reload(
                outcome.previous_generation,
                outcome.new_generation,
                "applied",
                "signal",
                ReloadActor::Sighup,
            );
            if let Err(err) = state.refresh_jwt_revocations().await {
                warn!(
                    error = %err,
                    generation = outcome.new_generation,
                    "SIGHUP: JWT-SVID revocation deny-list refresh failed; previous in-memory set still serving",
                );
                state.record_reload(
                    outcome.new_generation,
                    outcome.new_generation,
                    "revocation_refresh_failed",
                    "signal",
                    ReloadActor::Sighup,
                );
            }
        }
        Err(err) => {
            let active = state.active_generation_id();
            warn!(
                error = %err,
                generation = active,
                "SIGHUP: catalog/policy reload rejected; previous generation still serving",
            );
            state.record_reload(
                active,
                active,
                "rejected",
                err.audit_reason(),
                ReloadActor::Sighup,
            );
        }
    }
}

fn spawn_retention_sweep(state: Arc<BrokerState>, interval_secs: u64) {
    let limits = state.limits();
    if limits.retain_versions.is_none() || interval_secs == 0 {
        return;
    }
    let handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        loop {
            interval.tick().await;
            if let Err(err) = state.manager().sweep_all_retention(limits).await {
                warn!(error = %err, "retention sweep failed");
            }
        }
    });
    std::mem::drop(handle);
}

/// Build the resolved [`doctor::DoctorInputs`] from the config file + overrides,
/// using the same path/socket resolution `run` uses. A missing required path
/// (catalog/policy/bundle) is a clean config error (non-zero exit): that is a
/// usage error, distinct from a diagnostic failure.
fn load_doctor_inputs(
    overrides: &ConfigOverrides,
    rootless_expected_containers: Option<u32>,
) -> Result<doctor::DoctorInputs> {
    let file = load_config_file(overrides)?;
    let invocation = resolve_invocation_config(&file.broker_identity, &file.invocation)?;
    let setup = build_setup(&file, overrides)?;
    let socket = overrides
        .socket
        .clone()
        .or(file.socket)
        .unwrap_or_else(|| crate::DEFAULT_SOCKET_PATH.to_string());
    let socket_mode = file.socket_mode.map_or(DEFAULT_SOCKET_MODE, |mode| mode.0);
    let capability_policy = setup.capability_policy;
    let unlock_passphrase_selected = setup.unlock.passphrase_file.is_some();
    let unlock_bip39_selected = setup.unlock.bip39_phrase_file.is_some();
    let unlock_age_yubikey_selected = setup.unlock.age_yubikey;

    Ok(doctor::DoctorInputs {
        catalog: setup.catalog,
        policy: setup.policy,
        bundle: setup.bundle,
        socket,
        socket_mode,
        socket_group: file.socket_group,
        capability_policy,
        invocation,
        unlock_passphrase_selected,
        unlock_bip39_selected,
        unlock_age_yubikey_selected,
        rootless_expected_containers,
    })
}

/// Run the preflight **doctor** (`basil-f0j`): resolve config, run every
/// independent read-only check, print the report (human or `--json`), and exit
/// per the fatal-vs-warning model. The default path never unlocks the bundle,
/// binds the socket, or mutates anything; `--keys` explicitly unlocks only to run
/// the authenticated read-only per-key existence probe.
async fn run_doctor(args: DoctorArgs) -> Result<()> {
    let inputs = load_doctor_inputs(&args.overrides, args.rootless_expected_containers)?;
    let mut report = doctor::run_doctor(&inputs, doctor::EnabledFeatures::current()).await;
    if args.keys {
        let mut key_rows = doctor_key_material_rows(&args.overrides).await;
        report.checks.append(&mut key_rows);
        report = doctor::DoctorReport::from_checks(report.checks);
    }

    if args.json {
        println!("{}", doctor::render_json(&report)?);
    } else {
        print!("{}", doctor::render_human(&report));
    }

    if report.should_exit_nonzero(args.strict) {
        // A blocking misconfiguration exits non-zero, but cleanly: the report has
        // already been printed, so suppress the redundant anyhow error chain.
        std::process::exit(1);
    }
    Ok(())
}

/// Unlock the sealed bundle and run the authenticated read-only per-key existence
/// probe for `doctor --keys`, mapping the [`crate::CheckReport`] into per-key
/// [`doctor::CheckResult`] rows. Every failure path is folded into a secret-free
/// key-material row so one bad probe never aborts the rest of the report.
async fn doctor_key_material_rows(overrides: &ConfigOverrides) -> Vec<doctor::CheckResult> {
    let setup = match load_key_probe_config(overrides) {
        Ok(setup) => setup,
        Err(err) => {
            return doctor::key_material_rows(Err(format!(
                "could not resolve key-probe configuration: {err:#}"
            )));
        }
    };
    let Prepared { manager, .. } = match prepare_manager(&setup).await {
        Ok(prepared) => prepared,
        Err(err) => {
            return doctor::key_material_rows(Err(format!(
                "could not build authenticated backend manager: {err:#}"
            )));
        }
    };
    match manager.check().await {
        Ok(report) => doctor::key_material_rows(Ok(&report)),
        Err(err) => doctor::key_material_rows(Err(err.to_string())),
    }
}

/// Run the offline policy dry-run/explainer (`basil-4vf`).
///
/// Loads the catalog + policy from files, builds the REAL PDP, evaluates the
/// proposed tuple (or the `--effective` preview), and prints the result.
/// Entirely offline: no bundle, no backend, no socket, no secret material.
/// Default-deny holds exactly as in enforcement.
///
/// This is the default (non-`--live`) path of `basil explain`; the live path is
/// `client_cli::explain_live`, which queries the running broker over the socket.
pub fn run_explain(args: &ExplainArgs) -> Result<()> {
    use crate::catalog::Pdp;

    let file = load_config_file(&args.overrides)?;
    let catalog_path = required_path(
        args.overrides
            .catalog
            .clone()
            .or_else(|| file.catalog.clone()),
        "catalog",
    )?;
    let policy_path = required_path(
        args.overrides
            .policy
            .clone()
            .or_else(|| file.policy.clone()),
        "policy",
    )?;

    let catalog_json = std::fs::read_to_string(&catalog_path)
        .with_context(|| format!("reading catalog from {}", catalog_path.display()))?;
    let policy_json = std::fs::read_to_string(&policy_path)
        .with_context(|| format!("reading policy from {}", policy_path.display()))?;
    let (catalog, policy, config, warnings) =
        load(&catalog_json, &policy_json).context("loading catalog/policy")?;
    for w in &warnings {
        warn!(warning = %w, "catalog/policy load warning");
    }

    let pdp = Pdp::new(&catalog, &policy, &config);

    if args.effective {
        return print_effective(&pdp, &args.subject, args.json);
    }

    // Single-tuple explain. clap guarantees op/key are present here (required
    // unless --effective), but handle their absence fail-safe rather than unwrap.
    let (Some(op), Some(key)) = (args.op, args.key.as_deref()) else {
        bail!("--op and --key are required unless --effective is given");
    };
    print_explanation(&pdp, &args.subject, op, key, args.json)
}

/// Print the "preview effective permissions" view for an identity to stdout.
fn print_effective(pdp: &crate::catalog::Pdp, subject: &str, json: bool) -> Result<()> {
    let mut out = std::io::stdout().lock();
    render_effective(&mut out, pdp, subject, json)
}

/// Render the "preview effective permissions" view into `out`.
///
/// The render seam (separate from [`print_effective`]) so the stable `--json`
/// shape and the human text can be asserted without capturing the process's real
/// stdout. Production simply renders into a locked `stdout`.
fn render_effective(
    out: &mut impl std::io::Write,
    pdp: &crate::catalog::Pdp,
    subject: &str,
    json: bool,
) -> Result<()> {
    let grants = pdp.effective(subject);
    if json {
        let rows: Vec<serde_json::Value> = grants
            .iter()
            .map(|g| {
                serde_json::json!({
                    "key": g.key,
                    "op": g.op.token(),
                    "via": allow_via_json(&g.via),
                    "rule": g.rule_id,
                })
            })
            .collect();
        let doc = serde_json::json!({ "subject": subject, "effective": rows });
        writeln!(out, "{}", serde_json::to_string_pretty(&doc)?)?;
        return Ok(());
    }
    writeln!(
        out,
        "effective permissions for subject {subject}: {} grant(s)",
        grants.len()
    )?;
    for g in &grants {
        let rule = g.rule_id.as_deref().unwrap_or("<public-class>");
        writeln!(
            out,
            "  ALLOW  {}  {}  via {} [{rule}]",
            g.op.token(),
            g.key,
            allow_via_json(&g.via),
        )?;
    }
    if grants.is_empty() {
        writeln!(out, "  (none: default-deny)")?;
    }
    Ok(())
}

/// Print a single-tuple explanation (decision + matched rule / denial reason) to
/// stdout.
fn print_explanation(
    pdp: &crate::catalog::Pdp,
    subject: &str,
    op: crate::catalog::Op,
    key: &str,
    json: bool,
) -> Result<()> {
    let mut out = std::io::stdout().lock();
    render_explanation(&mut out, pdp, subject, op, key, json)
}

/// Render a single-tuple explanation into `out`.
///
/// The render seam (separate from [`print_explanation`]) so the stable `--json`
/// allow/deny shape can be asserted without the process's real stdout.
fn render_explanation(
    out: &mut impl std::io::Write,
    pdp: &crate::catalog::Pdp,
    subject: &str,
    op: crate::catalog::Op,
    key: &str,
    json: bool,
) -> Result<()> {
    use crate::catalog::Decision;
    let ex = pdp.explain_subject(subject, op, key);

    if json {
        let mut obj = serde_json::Map::new();
        obj.insert("subject".into(), subject.into());
        obj.insert("op".into(), op.token().into());
        obj.insert("key".into(), key.into());
        match &ex.decision {
            Decision::Allow { via } => {
                obj.insert("decision".into(), "allow".into());
                obj.insert("via".into(), allow_via_json(via).into());
                let matched = ex.matched.as_ref().map_or(serde_json::Value::Null, |m| {
                    serde_json::json!({
                        "rule": m.rule_id,
                        "via": allow_via_json(&m.via),
                        "subject": m.subject,
                        "action": m.action,
                        "target": m.target,
                    })
                });
                obj.insert("matched_rule".into(), matched);
            }
            Decision::Deny { reason } => {
                obj.insert("decision".into(), "deny".into());
                obj.insert("reason".into(), deny_reason_json(*reason).into());
            }
        }
        writeln!(
            out,
            "{}",
            serde_json::to_string_pretty(&serde_json::Value::Object(obj))?
        )?;
        return Ok(());
    }

    match &ex.decision {
        Decision::Allow { via } => {
            writeln!(
                out,
                "ALLOW  subject {subject}  {}  {key}  (via {})",
                op.token(),
                allow_via_json(via)
            )?;
            match &ex.matched {
                Some(m) => writeln!(
                    out,
                    "  matched subject `{}` (rule `{}`): action `{}` over target `{}`",
                    m.subject, m.rule_id, m.action, m.target
                )?,
                None => {
                    writeln!(
                        out,
                        "  matched the world-readable public-class rule (no policy rule needed)"
                    )?;
                }
            }
        }
        Decision::Deny { reason } => {
            writeln!(
                out,
                "DENY   subject {subject}  {}  {key}  ({})",
                op.token(),
                deny_reason_json(*reason)
            )?;
            writeln!(out, "  {}", deny_explanation(*reason))?;
        }
    }
    Ok(())
}

/// Stable JSON/string token for a [`AllowVia`](crate::catalog::AllowVia).
fn allow_via_json(via: &crate::catalog::AllowVia) -> String {
    use crate::catalog::AllowVia;
    match via {
        AllowVia::Subject(subject) => format!("subject:{subject}"),
        AllowVia::PublicClass => "public_class".to_string(),
    }
}

/// Stable JSON/string token for a [`DenyReason`](crate::catalog::DenyReason).
const fn deny_reason_json(reason: crate::catalog::DenyReason) -> &'static str {
    use crate::catalog::DenyReason;
    match reason {
        DenyReason::UnknownKey => "unknown_key",
        DenyReason::NotWritable => "not_writable",
        DenyReason::IssuerRawSign => "issuer_raw_sign",
        DenyReason::NotPermitted => "not_permitted",
    }
}

/// A human sentence for each deny reason.
const fn deny_explanation(reason: crate::catalog::DenyReason) -> &'static str {
    use crate::catalog::DenyReason;
    match reason {
        DenyReason::UnknownKey => "key is not in the catalog",
        DenyReason::NotWritable => {
            "the key is not writable (write hard-cap), denied regardless of policy"
        }
        DenyReason::IssuerRawSign => {
            "raw sign on a credential-issuer key (issuer hard-cap), denied regardless of policy; \
             use sign_nats_jwt/mint"
        }
        DenyReason::NotPermitted => "no policy grant matches this (subject, op, key): default-deny",
    }
}

/// Run the broker daemon behind `basil agent`.
///
/// `version` is the shipped binary's version (`basil-bin`'s
/// `CARGO_PKG_VERSION`), threaded through so `status`/`health` report the
/// `basil` binary's version rather than this library crate's.
pub async fn run_agent(args: RunArgs, version: &'static str) -> Result<()> {
    let overrides = args.overrides.clone();
    // `Box::pin`: with the cloud-KMS features the daemon future is large; this is
    // a once-per-process cold path, so the heap indirection is free.
    Box::pin(run_with_config_logging(
        &overrides,
        run_daemon(args, version),
    ))
    .await
}

/// Run the preflight doctor behind `basil doctor`.
pub async fn run_doctor_command(args: DoctorArgs) -> Result<()> {
    let overrides = args.overrides.clone();
    if args.json {
        let mut logging = logging_config_for_overrides(&overrides)?;
        logging.stdout.enable = Some(false);
        let logging_guards = init_logging(&logging)?;
        let result = run_doctor(args).await;
        logging_guards.shutdown();
        result
    } else {
        Box::pin(run_with_config_logging(&overrides, run_doctor(args))).await
    }
}

/// Run first-run config scaffolding behind top-level `basil init`.
///
/// `socket` is the resolved global `--socket <path>` flag (clap folds
/// `BASIL_SOCKET` into it); it is threaded into the generated config's
/// `socket = ...` line. See [`init::run`] for the full precedence.
pub fn run_init(socket: Option<&str>, args: &init::InitArgs) -> Result<()> {
    let logging_guards = init_logging(&LoggingConfigFile::default())?;
    let result = init::run(args, socket);
    logging_guards.shutdown();
    result
}

/// Run sealed-bundle operations behind top-level `basil bundle`.
pub fn run_bundle(command: bundle_cli::BundleCommand) -> Result<()> {
    let logging_guards = init_logging(&LoggingConfigFile::default())?;
    let result = bundle_cli::run(command);
    logging_guards.shutdown();
    result
}

async fn run_with_config_logging(
    overrides: &ConfigOverrides,
    fut: impl std::future::Future<Output = Result<()>>,
) -> Result<()> {
    let logging = logging_config_for_overrides(overrides)?;
    let logging_guards = init_logging(&logging)?;
    let result = fut.await;
    logging_guards.shutdown();
    result
}

fn logging_config_for_overrides(overrides: &ConfigOverrides) -> Result<LoggingConfigFile> {
    Ok(load_config_file(overrides)?.logging)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::catalog::MissingPolicy;
    use clap::Parser as _;

    fn temp_config(contents: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "basil-agent-config-test-{}-{}.toml",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::write(&path, contents).expect("write temp config");
        path
    }

    #[test]
    fn plaintext_http_warning_requires_a_literal_loopback_ip() {
        // Warns: plaintext to a non-loopback destination, including hosts that
        // merely *contain* a loopback address as a substring, and hostnames.
        for addr in [
            "http://vault.internal:8200",
            "http://127.0.0.1.evil.example:8200",
            "http://10.0.0.1:8200",
            "http://localhost:8200",
            "http://not a url",
        ] {
            assert!(is_plaintext_non_loopback_http(addr), "{addr} must warn");
        }
        // Silent: literal loopback IPs and any https destination.
        for addr in [
            "http://127.0.0.1:8200",
            "http://127.8.8.8:8200",
            "http://[::1]:8200",
            "https://vault.internal:8200",
            "https://127.0.0.1:8200",
        ] {
            assert!(
                !is_plaintext_non_loopback_http(addr),
                "{addr} must not warn"
            );
        }
    }

    fn overrides_for(config: PathBuf) -> ConfigOverrides {
        ConfigOverrides {
            config: Some(config),
            catalog: None,
            policy: None,
            bundle: None,
            socket: None,
            vault_addr: None,
        }
    }

    fn catalog_with_invocation_keys(
        response_signing: crate::catalog::KeyEntry,
        request_encryption: crate::catalog::KeyEntry,
    ) -> crate::Catalog {
        let mut backends = BTreeMap::new();
        backends.insert(
            "bao".to_string(),
            crate::catalog::BackendRef {
                kind: crate::catalog::BackendKind::Vault,
                addr: "http://127.0.0.1:8200".to_string(),
                engines: Vec::new(),
                capabilities: Vec::new(),
                mint_key_types: Vec::new(),
                requires: Vec::new(),
            },
        );
        let mut keys = BTreeMap::new();
        keys.insert("broker.response".to_string(), response_signing);
        keys.insert("broker.request".to_string(), request_encryption);
        crate::Catalog {
            schema_version: 1,
            backends,
            keys,
        }
    }

    fn catalog_key(
        class: Class,
        key_type: Option<KeyAlgorithm>,
        labels: &[&str],
    ) -> crate::catalog::KeyEntry {
        crate::catalog::KeyEntry {
            class,
            key_type,
            backend: "bao".to_string(),
            engine: None,
            path: "path".to_string(),
            public_path: matches!(class, Class::Sealing).then(|| "public/path".to_string()),
            writable: false,
            missing: MissingPolicy::Error,
            generate: None,
            sealing_pin: None,
            labels: crate::catalog::Labels(labels.iter().map(ToString::to_string).collect()),
            description: "test key".to_string(),
        }
    }

    #[cfg(feature = "keystore-backend")]
    #[test]
    #[allow(clippy::too_many_lines)]
    fn run_config_file_supplies_all_startup_settings() {
        let config = temp_config(
            r#"
catalog = "/cfg/catalog.json"
policy = "/cfg/policy.json"
bundle = "/cfg/bundle.sealed"
socket = "/run/basil.sock"
vault-addr = "http://vault.internal:8200"
transit-mount = "basil-transit"
jwt-auth-mount = "jwt-basil"
jwt-role = "basil-agent"
jwt-audience = "openbao-prod"
svid-ttl-secs = 120
capability-policy = "degraded"
db-keystore-cipher = "aegis256"
onepassword-provider-uri = "onepassword://basil"
onepassword-project = "prod"
onepassword-profile = "agent"
max-encrypt-size = 4096
max-payload-size = 8192
grace-versions = 2
retain-versions = 5
retention-sweep-secs = 60
audit-log = "/var/log/basil/audit.jsonl"
no-reconcile = true

[logging.stdout]
enable = false

[logging.journald]
enable = true

[logging.file]
enable = true
dir = "/var/log/basil"
prefix = "agent-"
rotation = "weekly"

[logging.opentelemetry]
enable = true
endpoint = "http://localhost:4317"
protocol = "grpc"

[unlock]
age-yubikey = true
bip39-phrase-file = "/secure/recovery.txt"
unlock-tpm = true
unlock-passphrase-file = "/secure/passphrase.txt"
unlock-passphrase-no-wipe = true
strict-bundle-perms = true
"#,
        );
        let args = ConfigOverrides {
            config: Some(config.clone()),
            catalog: None,
            policy: None,
            bundle: None,
            socket: None,
            vault_addr: None,
        };

        let loaded_file = load_config_file(&args).expect("load config file");
        let loaded = load_run_config(&args).expect("load run config");

        assert_eq!(loaded.setup.catalog, PathBuf::from("/cfg/catalog.json"));
        assert_eq!(loaded.setup.policy, PathBuf::from("/cfg/policy.json"));
        assert_eq!(loaded.setup.bundle, PathBuf::from("/cfg/bundle.sealed"));
        assert_eq!(loaded.socket.as_deref(), Some("/run/basil.sock"));
        assert_eq!(loaded.setup.vault_addr, "http://vault.internal:8200");
        assert_eq!(loaded.setup.transit_mount, "basil-transit");
        assert_eq!(loaded.setup.jwt_auth_mount, "jwt-basil");
        assert_eq!(loaded.setup.jwt_role, "basil-agent");
        assert_eq!(loaded.setup.jwt_audience, "openbao-prod");
        assert_eq!(loaded.setup.svid_ttl_secs, 120);
        assert_eq!(loaded.setup.capability_policy, CapabilityPolicy::Degraded);
        #[cfg(feature = "db-keystore")]
        assert_eq!(loaded.setup.db_keystore_cipher, "aegis256");
        assert_eq!(loaded.setup.onepassword_provider_uri, "onepassword://basil");
        assert_eq!(loaded.setup.onepassword_project, "prod");
        assert_eq!(loaded.setup.onepassword_profile, "agent");
        assert_eq!(loaded.max_encrypt_size, 4096);
        assert_eq!(loaded.max_payload_size, 8192);
        assert_eq!(loaded.grace_versions, 2);
        assert_eq!(loaded.retain_versions, Some(5));
        assert_eq!(loaded.retention_sweep_secs, 60);
        assert_eq!(
            loaded.audit_log.as_deref(),
            Some(Path::new("/var/log/basil/audit.jsonl"))
        );
        assert!(loaded.no_reconcile);
        assert_eq!(loaded_file.logging.stdout.enable, Some(false));
        assert!(!loaded_file.logging.stdout_enabled());
        assert!(loaded_file.logging.journald.enable);
        assert!(loaded_file.logging.file.enable);
        assert_eq!(
            loaded_file.logging.file.dir.as_deref(),
            Some(Path::new("/var/log/basil"))
        );
        assert_eq!(loaded_file.logging.file.prefix, "agent-");
        assert_eq!(
            loaded_file.logging.file.rotation,
            FileLoggingRotation::Weekly
        );
        assert!(loaded_file.logging.opentelemetry.enable);
        assert_eq!(
            (
                loaded_file.logging.opentelemetry.endpoint.as_deref(),
                loaded_file.logging.opentelemetry.protocol
            ),
            (Some("http://localhost:4317"), OpenTelemetryProtocol::Grpc)
        );
        assert!(loaded.setup.unlock.age_yubikey);
        assert!(loaded.setup.unlock.tpm);
        assert_eq!(
            loaded.setup.unlock.bip39_phrase_file.as_deref(),
            Some(Path::new("/secure/recovery.txt"))
        );
        assert_eq!(
            loaded.setup.unlock.passphrase_file.as_deref(),
            Some(Path::new("/secure/passphrase.txt"))
        );
        assert!(loaded.setup.unlock.passphrase_no_wipe);
        assert!(loaded.setup.unlock.strict_bundle_perms);

        std::fs::remove_file(config).expect("remove temp config");
    }

    #[test]
    fn socket_mode_config_accepts_octal_string_and_rejects_bad_values() {
        assert_eq!(parse_socket_mode("0600").expect("0600 parses"), 0o600);
        assert_eq!(parse_socket_mode("0o660").expect("0o660 parses"), 0o660);
        assert!(parse_socket_mode("").is_err());
        assert!(parse_socket_mode("0888").is_err());
        assert!(parse_socket_mode("10000").is_err());
    }

    #[test]
    fn run_config_file_supplies_socket_ownership_settings() {
        let config = temp_config(
            r#"
catalog = "/cfg/catalog.json"
policy = "/cfg/policy.json"
bundle = "/cfg/bundle.sealed"
socket-mode = "0660"
socket-group = "basil-edge"
"#,
        );
        let args = ConfigOverrides {
            config: Some(config.clone()),
            catalog: None,
            policy: None,
            bundle: None,
            socket: None,
            vault_addr: None,
        };

        let loaded = load_run_config(&args).expect("load run config");

        assert_eq!(loaded.socket_mode, 0o660);
        assert_eq!(loaded.socket_group.as_deref(), Some("basil-edge"));

        std::fs::remove_file(config).expect("remove temp config");
    }

    #[test]
    fn socket_mode_defaults_to_owner_only() {
        let config = temp_config(
            r#"
catalog = "/cfg/catalog.json"
policy = "/cfg/policy.json"
bundle = "/cfg/bundle.sealed"
"#,
        );
        let args = ConfigOverrides {
            config: Some(config.clone()),
            catalog: None,
            policy: None,
            bundle: None,
            socket: None,
            vault_addr: None,
        };

        let loaded = load_run_config(&args).expect("load run config");

        assert_eq!(loaded.socket_mode, DEFAULT_SOCKET_MODE);
        assert!(loaded.socket_group.is_none());

        std::fs::remove_file(config).expect("remove temp config");
    }

    #[test]
    fn logging_defaults_stdout_and_journald_on_otel_off() {
        let config = AgentConfigFile::default();
        assert_eq!(config.logging.stdout.enable, None);
        assert!(config.logging.stdout_enabled());
        assert!(config.logging.journald.enable);
        assert!(!config.logging.file.enable);
        assert!(config.logging.file.dir.is_none());
        assert_eq!(config.logging.file.prefix, "basil-agent-");
        assert_eq!(config.logging.file.rotation, FileLoggingRotation::Daily);
        assert!(!config.logging.opentelemetry.enable);
        assert_eq!(
            config.logging.opentelemetry.protocol,
            OpenTelemetryProtocol::Grpc
        );
        assert!(config.logging.opentelemetry.endpoint.is_none());
    }

    #[test]
    fn stdout_defaults_off_when_file_logging_enabled() {
        let config: AgentConfigFile = toml::from_str(
            r#"
[logging.file]
enable = true
dir = "/var/log/basil"
"#,
        )
        .expect("parse config");
        assert_eq!(config.logging.stdout.enable, None);
        assert!(!config.logging.stdout_enabled());
    }

    #[test]
    fn stdout_explicit_config_overrides_file_logging_default() {
        let stdout_on: AgentConfigFile = toml::from_str(
            r#"
[logging.stdout]
enable = true

[logging.file]
enable = true
dir = "/var/log/basil"
"#,
        )
        .expect("parse stdout-on config");
        assert_eq!(stdout_on.logging.stdout.enable, Some(true));
        assert!(stdout_on.logging.stdout_enabled());

        let stdout_off: AgentConfigFile = toml::from_str(
            r"
[logging.stdout]
enable = false
",
        )
        .expect("parse stdout-off config");
        assert_eq!(stdout_off.logging.stdout.enable, Some(false));
        assert!(!stdout_off.logging.stdout_enabled());
    }

    #[test]
    fn file_logging_path_alias_populates_dir() {
        let config: AgentConfigFile = toml::from_str(
            r#"
[logging.file]
enable = true
path = "/var/log/basil"
"#,
        )
        .expect("parse file config");
        assert_eq!(
            config.logging.file.dir.as_deref(),
            Some(Path::new("/var/log/basil"))
        );
    }

    #[test]
    fn file_logging_requires_dir_when_enabled() {
        let config: AgentConfigFile = toml::from_str(
            r"
[logging.file]
enable = true
",
        )
        .expect("parse file config");
        let err = build_file_writer(&config.logging.file).expect_err("missing dir rejects");
        assert!(
            err.to_string()
                .contains("logging.file.dir is required when logging.file.enable=true")
        );
    }

    #[test]
    fn file_logging_constructs_non_blocking_writer() {
        let dir = std::env::temp_dir().join(format!(
            "basil-agent-log-test-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&dir).expect("create log dir");
        let config = FileLoggingConfigFile {
            enable: true,
            dir: Some(dir.clone()),
            prefix: "agent-test".to_owned(),
            rotation: FileLoggingRotation::None,
        };
        let (writer, guard) = build_file_writer(&config).expect("build file writer");
        assert!(writer.is_some());
        drop(writer);
        drop(guard);
        std::fs::remove_dir_all(dir).expect("remove log dir");
    }

    #[test]
    fn journald_disabled_produces_no_sink() {
        assert!(matches!(journald_sink(false), JournaldSink::Disabled));
    }

    #[test]
    fn journald_without_socket_is_non_fatal_without_stderr_sink() {
        // Portability guarantee (basil-ftfj): requesting journald on a host with
        // no journal socket (containers, minimal VMs, CI) must NOT abort the
        // offline `basil doctor`/`explain` commands. It resolves to either an active
        // journald layer (socket present) or a one-time stderr diagnostic (socket
        // absent): never a hard error or duplicate stderr log sink.
        match journald_sink(true) {
            JournaldSink::Active(_) | JournaldSink::Unavailable(_) => {}
            JournaldSink::Disabled => panic!("enabled journald must not resolve to Disabled"),
        }
    }

    #[cfg(feature = "http")]
    #[test]
    fn jwks_http_surface_is_disabled_by_default_no_port_opened() {
        // The acceptance bar (basil-uce.1): with no `[jwks]` section the surface
        // is OFF: `enable` is false, so `run_daemon` never spawns the listener
        // task (the `then(...)` guard is not taken). The documented default
        // listen address still parses (config validity is independent of enable).
        let defaults = JwksConfigFile::default();
        assert!(!defaults.enable, "JWKS surface must default to disabled");
        assert_eq!(defaults.listen, "127.0.0.1:8201");

        let config = temp_config(
            r#"
catalog = "/cfg/catalog.json"
policy = "/cfg/policy.json"
bundle = "/cfg/bundle.sealed"
"#,
        );
        let args = ConfigOverrides {
            config: Some(config.clone()),
            catalog: None,
            policy: None,
            bundle: None,
            socket: None,
            vault_addr: None,
        };
        let loaded = load_run_config(&args).expect("load run config");
        assert!(
            !loaded.jwks.enable,
            "default config leaves the JWKS port closed"
        );
        assert_eq!(
            loaded.jwks.listen,
            "127.0.0.1:8201".parse().expect("default listen")
        );

        std::fs::remove_file(config).expect("remove temp config");
    }

    #[test]
    fn invocation_service_requires_explicit_config_enable() {
        let defaults = InvocationConfigFile::default();
        assert!(
            !defaults.enable,
            "InvocationService must default to rejecting requests"
        );
        assert_eq!(defaults.max_ttl_secs, 60);
        assert_eq!(defaults.clock_skew_secs, 30);
        assert_eq!(defaults.replay_cache_capacity, 4096);

        let config = temp_config(
            r#"
catalog = "/cfg/catalog.json"
policy = "/cfg/policy.json"
bundle = "/cfg/bundle.sealed"
"#,
        );
        let args = overrides_for(config.clone());
        let loaded = load_run_config(&args).expect("load run config");
        assert!(!loaded.invocation.enabled);
        assert!(loaded.invocation.broker_identity.is_none());
        assert!(loaded.invocation.request_encryption_key_id.is_none());
        std::fs::remove_file(config).expect("remove temp config");

        let config = temp_config(
            r#"
catalog = "/cfg/catalog.json"
policy = "/cfg/policy.json"
bundle = "/cfg/bundle.sealed"

[broker-identity]
id = "basil://prod/us-east-1/agent-a"
response-signing-key-id = "broker.response"

[invocation]
enable = true
audience = ["basil://prod/us-east-1/agent-a"]
request-encryption-key-id = "broker.request"
max-ttl-secs = 45
clock-skew-secs = 7
replay-cache-capacity = 128
"#,
        );
        let args = overrides_for(config.clone());
        let loaded = load_run_config(&args).expect("load run config");
        assert!(loaded.invocation.enabled);
        let identity = loaded
            .invocation
            .broker_identity
            .as_ref()
            .expect("broker identity");
        assert_eq!(identity.id, "basil://prod/us-east-1/agent-a");
        assert_eq!(identity.response_signing_key_id, "broker.response");
        assert_eq!(
            loaded.invocation.request_encryption_key_id.as_deref(),
            Some("broker.request")
        );
        assert_eq!(
            loaded.invocation.audiences,
            vec!["basil://prod/us-east-1/agent-a".to_string()]
        );
        assert_eq!(loaded.invocation.max_ttl_secs, 45);
        assert_eq!(loaded.invocation.clock_skew_secs, 7);
        assert_eq!(loaded.invocation.replay_cache_capacity, 128);

        std::fs::remove_file(config).expect("remove temp config");

        let config = temp_config(
            r#"
catalog = "/cfg/catalog.json"
policy = "/cfg/policy.json"
bundle = "/cfg/bundle.sealed"

[invocation]
enable = true
"#,
        );
        let args = overrides_for(config.clone());
        let err = load_run_config(&args).expect_err("enabled invocation requires audience");
        assert!(
            err.to_string()
                .contains("invocation.audience must be set when invocation.enable is true")
        );

        std::fs::remove_file(config).expect("remove temp config");
    }

    #[test]
    fn invocation_config_rejects_missing_keys_invalid_identity_and_bounds() {
        let config = temp_config(
            r#"
catalog = "/cfg/catalog.json"
policy = "/cfg/policy.json"
bundle = "/cfg/bundle.sealed"

[broker-identity]
id = "https://not-basil.example/agent-a"
response-signing-key-id = "broker.response"

[invocation]
enable = true
audience = ["basil://prod/us-east-1/agent-a"]
request-encryption-key-id = "broker.request"
"#,
        );
        let err = load_run_config(&overrides_for(config.clone()))
            .expect_err("non-basil broker id rejects");
        assert!(
            err.to_string()
                .contains("broker-identity.id must use the basil:// scheme")
        );
        std::fs::remove_file(config).expect("remove temp config");

        let config = temp_config(
            r#"
catalog = "/cfg/catalog.json"
policy = "/cfg/policy.json"
bundle = "/cfg/bundle.sealed"

[broker-identity]
id = "basil://prod/us-east-1/agent-a"
response-signing-key-id = "broker.response"

[invocation]
enable = true
audience = ["basil://prod/us-east-1/agent-a"]
max-ttl-secs = 301
"#,
        );
        let err =
            load_run_config(&overrides_for(config.clone())).expect_err("excessive ttl rejects");
        assert!(
            err.to_string()
                .contains("invocation.max-ttl-secs must be at most 300 seconds")
        );
        std::fs::remove_file(config).expect("remove temp config");

        let config = temp_config(
            r#"
catalog = "/cfg/catalog.json"
policy = "/cfg/policy.json"
bundle = "/cfg/bundle.sealed"

[broker-identity]
id = "basil://prod/us-east-1/agent-a"
response-signing-key-id = "broker.response"

[invocation]
enable = true
audience = ["basil://prod/us-east-1/agent-a"]
"#,
        );
        let err = load_run_config(&overrides_for(config.clone()))
            .expect_err("enabled invocation requires request encryption key");
        assert!(
            err.to_string()
                .contains("invocation.request-encryption-key-id is required")
        );
        std::fs::remove_file(config).expect("remove temp config");
    }

    #[test]
    fn invocation_catalog_bindings_require_expected_class_and_use() {
        let invocation = InvocationRuntimeConfig {
            enabled: true,
            broker_identity: Some(BrokerIdentityRuntimeConfig {
                id: "basil://prod/us-east-1/agent-a".to_string(),
                response_signing_key_id: "broker.response".to_string(),
            }),
            audiences: vec!["basil://prod/us-east-1/agent-a".to_string()],
            request_encryption_key_id: Some("broker.request".to_string()),
            max_ttl_secs: 60,
            clock_skew_secs: 30,
            replay_cache_capacity: 4096,
            now_unix_override: None,
        };
        let valid = catalog_with_invocation_keys(
            catalog_key(
                Class::Asymmetric,
                Some(KeyAlgorithm::Ed25519),
                &["broker_key_use=response-signing"],
            ),
            catalog_key(
                Class::Sealing,
                Some(KeyAlgorithm::X25519),
                &["broker_key_use=request-encryption"],
            ),
        );
        validate_invocation_catalog_bindings(&invocation, &valid).expect("valid keys pass");

        let wrong_response_class = catalog_with_invocation_keys(
            catalog_key(
                Class::Sealing,
                Some(KeyAlgorithm::X25519),
                &["broker_key_use=response-signing"],
            ),
            catalog_key(
                Class::Sealing,
                Some(KeyAlgorithm::X25519),
                &["broker_key_use=request-encryption"],
            ),
        );
        let err = validate_invocation_catalog_bindings(&invocation, &wrong_response_class)
            .expect_err("wrong response signing class rejects");
        assert!(
            err.to_string().contains(
                "broker response-signing key `broker.response` must be class `asymmetric`"
            )
        );

        let wrong_request_use = catalog_with_invocation_keys(
            catalog_key(
                Class::Asymmetric,
                Some(KeyAlgorithm::Ed25519),
                &["broker_key_use=response-signing"],
            ),
            catalog_key(
                Class::Sealing,
                Some(KeyAlgorithm::X25519),
                &["broker_key_use=response-signing"],
            ),
        );
        let err = validate_invocation_catalog_bindings(&invocation, &wrong_request_use)
            .expect_err("wrong request encryption use rejects");
        assert!(err.to_string().contains(
            "broker request-encryption key `broker.request` must carry label `broker_key_use=request-encryption`"
        ));
    }

    #[cfg(feature = "http")]
    #[test]
    fn jwks_http_surface_enables_and_parses_listen_from_config() {
        let config = temp_config(
            r#"
catalog = "/cfg/catalog.json"
policy = "/cfg/policy.json"
bundle = "/cfg/bundle.sealed"

[jwks]
enable = true
listen = "0.0.0.0:9443"
"#,
        );
        let args = ConfigOverrides {
            config: Some(config.clone()),
            catalog: None,
            policy: None,
            bundle: None,
            socket: None,
            vault_addr: None,
        };
        let loaded = load_run_config(&args).expect("load run config");
        assert!(loaded.jwks.enable);
        assert_eq!(
            loaded.jwks.listen,
            "0.0.0.0:9443".parse().expect("custom listen")
        );

        std::fs::remove_file(config).expect("remove temp config");
    }

    #[cfg(feature = "http")]
    #[test]
    fn jwks_listen_must_be_a_valid_socket_addr() {
        let bad = JwksConfigFile {
            enable: true,
            listen: "not-an-addr".to_string(),
            issuer: None,
            tls: JwksTlsConfigFile::default(),
        };
        assert!(
            resolve_jwks_config(&bad).is_err(),
            "a malformed jwks.listen fails closed at startup"
        );
    }

    #[cfg(feature = "http")]
    #[test]
    fn jwks_issuer_must_be_absolute_http_url_or_unset() {
        // Unset issuer: discovery doc simply isn't served (ok).
        let none = JwksConfigFile {
            enable: true,
            listen: "127.0.0.1:8201".to_string(),
            issuer: None,
            tls: JwksTlsConfigFile::default(),
        };
        assert!(resolve_jwks_config(&none).expect("ok").issuer.is_none());

        // A relative / schemeless issuer fails closed.
        let bad = JwksConfigFile {
            enable: true,
            listen: "127.0.0.1:8201".to_string(),
            issuer: Some("basil.example.com".to_string()),
            tls: JwksTlsConfigFile::default(),
        };
        assert!(
            resolve_jwks_config(&bad).is_err(),
            "a non-http(s) issuer fails closed at startup"
        );

        // A valid https issuer with a trailing slash is normalized.
        let good = JwksConfigFile {
            enable: true,
            listen: "127.0.0.1:8201".to_string(),
            issuer: Some("https://basil.example.com/".to_string()),
            tls: JwksTlsConfigFile::default(),
        };
        assert_eq!(
            resolve_jwks_config(&good).expect("ok").issuer.as_deref(),
            Some("https://basil.example.com")
        );
    }

    #[cfg(feature = "http")]
    #[test]
    fn jwks_issuer_rejects_ssrf_prone_url_shapes() {
        for issuer in [
            "//basil.example.com",
            "ftp://basil.example.com",
            "file:///etc/passwd",
            "unix:///run/basil-jwks.sock",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "https://user:pass@basil.example.com",
            "https://basil.example.com/#fragment",
        ] {
            let bad = JwksConfigFile {
                enable: true,
                listen: "127.0.0.1:8201".to_string(),
                issuer: Some(issuer.to_string()),
                tls: JwksTlsConfigFile::default(),
            };
            assert!(
                resolve_jwks_config(&bad).is_err(),
                "jwks.issuer `{issuer}` should fail closed"
            );
        }
    }

    #[cfg(feature = "http")]
    #[test]
    fn jwks_tls_defaults_to_disabled() {
        let defaults = JwksConfigFile::default();
        assert!(resolve_jwks_config(&defaults).expect("ok").tls.is_none());
    }

    #[cfg(all(feature = "http", not(feature = "http-tls")))]
    #[test]
    fn jwks_tls_requires_cargo_feature() {
        let config = JwksConfigFile {
            enable: true,
            listen: "127.0.0.1:8201".to_string(),
            issuer: Some("https://basil.example.com".to_string()),
            tls: JwksTlsConfigFile {
                enable: true,
                cert_file: Some("/etc/basil/jwks-cert.pem".into()),
                key_file: Some("/etc/basil/jwks-key.pem".into()),
            },
        };
        let err = resolve_jwks_config(&config).expect_err("feature missing");
        assert!(err.to_string().contains("http-tls"));
    }

    #[cfg(not(feature = "http"))]
    #[test]
    fn jwks_enable_requires_http_feature() {
        let config = temp_config(
            r#"
catalog = "/cfg/catalog.json"
policy = "/cfg/policy.json"
bundle = "/cfg/bundle.sealed"

[jwks]
enable = true
"#,
        );
        let err = load_run_config(&overrides_for(config.clone())).expect_err("feature missing");
        assert!(err.to_string().contains("http cargo feature"));
        std::fs::remove_file(config).expect("remove temp config");
    }

    #[cfg(feature = "http-tls")]
    #[test]
    fn jwks_tls_requires_cert_and_key_when_enabled() {
        let missing_key = JwksConfigFile {
            enable: true,
            listen: "127.0.0.1:8201".to_string(),
            issuer: Some("https://basil.example.com".to_string()),
            tls: JwksTlsConfigFile {
                enable: true,
                cert_file: Some("/etc/basil/jwks-cert.pem".into()),
                key_file: None,
            },
        };
        let err = resolve_jwks_config(&missing_key).expect_err("key required");
        assert!(err.to_string().contains("key-file"));
    }

    #[cfg(feature = "otlp")]
    #[test]
    fn otel_logging_requires_non_empty_http_endpoint_when_enabled() {
        let missing = OpenTelemetryLoggingConfigFile {
            enable: true,
            endpoint: None,
            protocol: OpenTelemetryProtocol::Grpc,
        };
        assert!(required_otel_endpoint(&missing).is_err());

        let empty = OpenTelemetryLoggingConfigFile {
            enable: true,
            endpoint: Some("   ".to_string()),
            protocol: OpenTelemetryProtocol::Grpc,
        };
        assert!(required_otel_endpoint(&empty).is_err());

        let unix = OpenTelemetryLoggingConfigFile {
            enable: true,
            endpoint: Some("unix:///run/otel.sock".to_string()),
            protocol: OpenTelemetryProtocol::Grpc,
        };
        assert!(required_otel_endpoint(&unix).is_err());

        for endpoint in [
            "//otel.example.com:4317",
            "ftp://otel.example.com:4317",
            "file:///tmp/otel.sock",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "https://user:pass@otel.example.com:4317",
            "https://otel.example.com:4317/#fragment",
        ] {
            let bad = OpenTelemetryLoggingConfigFile {
                enable: true,
                endpoint: Some(endpoint.to_string()),
                protocol: OpenTelemetryProtocol::Grpc,
            };
            assert!(
                required_otel_endpoint(&bad).is_err(),
                "OpenTelemetry endpoint `{endpoint}` should fail closed"
            );
        }

        let http = OpenTelemetryLoggingConfigFile {
            enable: true,
            endpoint: Some("http://localhost:4317".to_string()),
            protocol: OpenTelemetryProtocol::Grpc,
        };
        assert_eq!(
            required_otel_endpoint(&http).expect("valid endpoint"),
            "http://localhost:4317/"
        );
    }

    #[test]
    fn cli_overrides_win_over_config_file() {
        let config = temp_config(
            r#"
catalog = "/cfg/catalog.json"
policy = "/cfg/policy.json"
bundle = "/cfg/bundle.sealed"
socket = "/cfg/basil.sock"
vault-addr = "http://cfg-vault:8200"
"#,
        );
        let args = ConfigOverrides {
            config: Some(config.clone()),
            catalog: Some(PathBuf::from("/cli/catalog.json")),
            policy: Some(PathBuf::from("/cli/policy.json")),
            bundle: Some(PathBuf::from("/cli/bundle.sealed")),
            socket: Some("/cli/basil.sock".to_string()),
            vault_addr: Some("http://cli-vault:8200".to_string()),
        };

        let loaded = load_run_config(&args).expect("load run config");

        assert_eq!(loaded.setup.catalog, PathBuf::from("/cli/catalog.json"));
        assert_eq!(loaded.setup.policy, PathBuf::from("/cli/policy.json"));
        assert_eq!(loaded.setup.bundle, PathBuf::from("/cli/bundle.sealed"));
        assert_eq!(loaded.socket.as_deref(), Some("/cli/basil.sock"));
        assert_eq!(loaded.setup.vault_addr, "http://cli-vault:8200");

        std::fs::remove_file(config).expect("remove temp config");
    }

    #[test]
    fn run_cli_rejects_removed_startup_overrides() {
        #[derive(Debug, clap::Parser)]
        struct TestCli {
            #[command(flatten)]
            args: RunArgs,
        }

        let err = TestCli::try_parse_from([
            "basil-agent-run",
            "--catalog",
            "/tmp/catalog.json",
            "--policy",
            "/tmp/policy.json",
            "--bundle",
            "/tmp/bundle.sealed",
            "--capability-policy",
            "off",
        ])
        .expect_err("removed flag rejected");
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    // ---- explain / effective CLI rendering (basil-4vf) ----------------------

    /// A small catalog + least-privilege policy reused by the explain tests: uid
    /// 9002 is a `reader` of `grafana.admin_password` (user rule); gid 10 is an
    /// `operator` of `grafana.**` (group rule). The loader builds the same real
    /// types enforcement uses.
    mod explain {
        use super::*;
        use crate::catalog::{Op, Pdp, load};

        const CATALOG: &str = r#"{
          "schemaVersion": 1,
          "backends": { "bao": { "kind": "vault", "addr": "https://127.0.0.1:8200" } },
          "keys": {
            "grafana.admin_password": {
              "class": "value", "backend": "bao", "engine": "kv2",
              "path": "secret/data/grafana/admin", "writable": true,
              "missing": "error", "description": "grafana admin value"
            }
          }
        }"#;

        const POLICY: &str = r#"{
          "schemaVersion": 2,
          "subjects": {
            "svc.grafana": { "allOf": [ { "kind": "unix", "uid": 9002 } ] },
            "ops.wheel": { "allOf": [ { "kind": "unix", "gid": 10 } ] }
          },
          "roles": { "reader": ["get", "list"], "operator": ["set", "rotate"] },
          "rules": [
            { "id": "grafana-reader",  "subjects": ["svc.grafana"], "action": ["role:reader"],   "target": ["grafana.admin_password"] },
            { "id": "wheel-operator",  "subjects": ["ops.wheel"],   "action": ["role:operator"], "target": ["grafana.**"] }
          ],
          "config": {
            "names": { "users": { "9002": "svc-grafana" }, "groups": { "10": "wheel" } },
            "memberships": { "9002": [9002] }
          }
        }"#;

        /// Owned `(Catalog, ResolvedPolicy, Config)` via the loader, so a `Pdp` can
        /// borrow them.
        fn loaded() -> (
            crate::catalog::Catalog,
            crate::catalog::ResolvedPolicy,
            crate::catalog::Config,
        ) {
            let (catalog, policy, config, _w) = load(CATALOG, POLICY).expect("fixture loads");
            (catalog, policy, config)
        }

        fn render_explanation_to_string(
            pdp: &Pdp,
            subject: &str,
            op: Op,
            key: &str,
            json: bool,
        ) -> String {
            let mut buf = Vec::new();
            render_explanation(&mut buf, pdp, subject, op, key, json).expect("render");
            String::from_utf8(buf).expect("utf8")
        }

        #[test]
        fn json_allow_shape_carries_matched_rule_fields() {
            let (c, p, cfg) = loaded();
            let pdp = Pdp::new(&c, &p, &cfg);
            let out = render_explanation_to_string(
                &pdp,
                "svc.grafana",
                Op::Get,
                "grafana.admin_password",
                true,
            );
            let doc: serde_json::Value = serde_json::from_str(&out).expect("json");
            assert_eq!(doc["decision"], "allow");
            assert_eq!(doc["subject"], "svc.grafana");
            assert_eq!(doc["op"], "get");
            assert_eq!(doc["key"], "grafana.admin_password");
            assert_eq!(doc["via"], "subject:svc.grafana");
            assert_eq!(doc["matched_rule"]["rule"], "grafana-reader");
            assert_eq!(doc["matched_rule"]["via"], "subject:svc.grafana");
            assert!(doc["matched_rule"]["action"].is_string());
            assert!(doc["matched_rule"]["target"].is_string());
        }

        #[test]
        fn json_deny_shape_carries_default_deny_reason() {
            let (c, p, cfg) = loaded();
            let pdp = Pdp::new(&c, &p, &cfg);
            // `svc.grafana` is a reader only: `set` is not granted (default-deny).
            let out = render_explanation_to_string(
                &pdp,
                "svc.grafana",
                Op::Set,
                "grafana.admin_password",
                true,
            );
            let doc: serde_json::Value = serde_json::from_str(&out).expect("json");
            assert_eq!(doc["decision"], "deny");
            assert_eq!(doc["reason"], "not_permitted");
            // A deny must NOT leak an allow `via`/`matched_rule`.
            assert!(doc.get("via").is_none());
            assert!(doc.get("matched_rule").is_none());

            // An unknown key denies with the unknown-key reason.
            let unknown =
                render_explanation_to_string(&pdp, "svc.grafana", Op::Get, "no.such.key", true);
            let doc: serde_json::Value = serde_json::from_str(&unknown).expect("json");
            assert_eq!(doc["decision"], "deny");
            assert_eq!(doc["reason"], "unknown_key");
        }

        #[test]
        fn subject_name_selects_the_rule_to_explain() {
            let (c, p, cfg) = loaded();
            let pdp = Pdp::new(&c, &p, &cfg);
            let denied = render_explanation_to_string(
                &pdp,
                "svc.grafana",
                Op::Set,
                "grafana.admin_password",
                true,
            );
            let doc: serde_json::Value = serde_json::from_str(&denied).expect("json");
            assert_eq!(doc["decision"], "deny", "reader subject cannot set");

            let allowed = render_explanation_to_string(
                &pdp,
                "ops.wheel",
                Op::Set,
                "grafana.admin_password",
                true,
            );
            let doc: serde_json::Value = serde_json::from_str(&allowed).expect("json");
            assert_eq!(doc["decision"], "allow", "operator subject can set");
            assert_eq!(doc["via"], "subject:ops.wheel");
            assert_eq!(doc["matched_rule"]["rule"], "wheel-operator");
        }

        #[test]
        fn effective_mode_renders_granted_key_op_set() {
            let (c, p, cfg) = loaded();
            let pdp = Pdp::new(&c, &p, &cfg);
            let mut buf = Vec::new();
            render_effective(&mut buf, &pdp, "ops.wheel", true).expect("render effective");
            let doc: serde_json::Value = serde_json::from_slice(&buf).expect("effective json");
            assert_eq!(doc["subject"], "ops.wheel");
            let rows = doc["effective"].as_array().expect("effective rows");
            let pairs: Vec<(&str, &str)> = rows
                .iter()
                .filter_map(|r| Some((r["key"].as_str()?, r["op"].as_str()?)))
                .collect();
            assert!(
                pairs.contains(&("grafana.admin_password", "set")),
                "operator set granted: {pairs:?}"
            );
            assert!(
                pairs.contains(&("grafana.admin_password", "rotate")),
                "operator rotate granted: {pairs:?}"
            );
            assert!(
                rows.iter().all(|r| r["via"] == "subject:ops.wheel"),
                "every grant is via the wheel subject"
            );

            // An unknown subject renders an empty effective set (default-deny),
            // not an error and not a spurious allow.
            let mut buf = Vec::new();
            render_effective(&mut buf, &pdp, "missing.subject", true).expect("render effective");
            let doc: serde_json::Value = serde_json::from_slice(&buf).expect("json");
            assert!(
                doc["effective"].as_array().expect("rows").is_empty(),
                "no grants -> empty effective set"
            );
        }

        /// The fail-safe bail: `run_explain` WITHOUT `--op`/`--key` (and not in
        /// `--effective` mode) must error cleanly, never panic, never emit a
        /// misleading allow. Driven through the real handler with temp catalog/policy
        /// files so the bail at the end of `run_explain` is reached.
        #[test]
        fn missing_op_key_without_effective_bails_cleanly() {
            let dir = std::env::temp_dir();
            let stamp = format!("{}-{}", std::process::id(), uuid::Uuid::new_v4());
            let catalog_path = dir.join(format!("basil-explain-cat-{stamp}.json"));
            let policy_path = dir.join(format!("basil-explain-pol-{stamp}.json"));
            std::fs::write(&catalog_path, CATALOG).expect("write catalog");
            std::fs::write(&policy_path, POLICY).expect("write policy");

            let args = ExplainArgs {
                subject: "svc.grafana".to_string(),
                op: None,
                key: None,
                effective: false,
                live: false,
                json: true,
                overrides: ConfigOverrides {
                    config: None,
                    catalog: Some(catalog_path.clone()),
                    policy: Some(policy_path.clone()),
                    bundle: None,
                    socket: None,
                    vault_addr: None,
                },
            };

            let err = run_explain(&args).expect_err("missing op/key must bail");
            assert!(
                err.to_string().contains("--op and --key are required"),
                "clean bail, not a panic: {err}"
            );

            std::fs::remove_file(&catalog_path).ok();
            std::fs::remove_file(&policy_path).ok();
        }
    }
}
