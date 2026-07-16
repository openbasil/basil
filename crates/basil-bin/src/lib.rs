// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Library surface for the unified `basil` binary.
//!
//! This crate is primarily a binary (`basil`), but it also exposes its
//! command-line definition as a library so tooling, notably the `xtask`
//! man-page generator, can render the command tree without launching the
//! process. [`cli`] returns the fully assembled clap command.

#![cfg_attr(test, allow(clippy::indexing_slicing))]

pub mod client_cli;

#[cfg(feature = "keystore-backend")]
use basil_core::demo;
use basil_core::{agent_cli, bundle_cli, init};
#[cfg(feature = "compose")]
use clap::ValueEnum;
use clap::{Args, CommandFactory, Parser, Subcommand};
use std::path::PathBuf;

/// The shipped `basil` binary version.
///
/// Captured in this crate so it is `basil-bin`'s `CARGO_PKG_VERSION` (the same
/// value `--version` prints via clap), which the agent threads into
/// `status`/`health`keeping the reported version in lockstep with the binary
/// even if `basil-core` is versioned separately.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Top-level `basil` command-line interface.
#[derive(Debug, Parser)]
#[command(
    name = "basil",
    version,
    about = "Basil broker and operator tool",
    long_about = "Basil is a host-local secrets broker: your app never touches the key. The \
                  kernel attests who's calling, a default-deny policy decides, the key is used \
                  where it lives (OpenBao/Vault, KMS, or a sealed local store), and every \
                  operation is audited.\n\nThe one `basil` binary is the broker daemon (`basil \
                  agent`), the offline operator tooling (`init`, `bundle`, `explain`, `doctor`, \
                  `demo`), and the over-socket client for every broker operation."
)]
pub struct Cli {
    /// Path to the agent's Unix socket for over-socket commands.
    #[arg(long, env = "BASIL_SOCKET", global = true)]
    pub socket: Option<String>,

    #[command(subcommand)]
    pub command: Command,
}

/// Top-level `basil` subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Scaffold a first-run starter set (config, catalog, policy).
    Init(Box<init::InitArgs>),
    /// Manage the selected schema-3 configuration corpus.
    #[command(subcommand)]
    Config(ConfigCommand),
    /// Inspect or generate Basil integration for a Compose project.
    #[cfg(feature = "compose")]
    #[command(subcommand)]
    Compose(ComposeCommand),
    /// Report how to install or build Compose integration support.
    #[cfg(not(feature = "compose"))]
    Compose(ComposeUnavailableArgs),
    /// Run a zero-dependency guided tour: scaffold a throwaway broker on the
    /// built-in keystore backend, start it, and drive a scripted
    /// sign → verify → denied read → explain → encrypt → mint sequence with
    /// the audit trail, ending with copy-paste commands to try yourself.
    #[cfg(feature = "keystore-backend")]
    Demo(demo::DemoArgs),
    /// Print a shell completion script for `basil` to stdout. Install it,
    /// e.g. `basil completions bash > /etc/bash_completion.d/basil` or
    /// `basil completions fish > ~/.config/fish/completions/basil.fish`.
    Completions(CompletionsArgs),
    /// Run the broker daemon.
    Agent(agent_cli::RunArgs),
    /// Create and manage a sealed credential bundle.
    #[command(subcommand)]
    Bundle(Box<bundle_cli::BundleCommand>),
    /// Explain a policy decision: why a subject would be allowed or denied an op
    /// on a key. By DEFAULT this is an offline dry-run: it builds the PDP from
    /// the catalog + policy FILES on disk and evaluates the tuple through the same
    /// matcher enforcement uses (no socket, no backend, no secrets). With `--live`
    /// it instead queries the RUNNING broker's serving generation over the global
    /// `--socket` (needs the `explain` admin permission). `--effective` previews
    /// every grant for the subject and is offline-only.
    Explain(agent_cli::ExplainArgs),
    /// Preflight environment and deployment checks.
    Doctor(agent_cli::DoctorArgs),
    /// Inspect or prune the private persistent OCI evidence cache.
    Cache(agent_cli::CacheArgs),
    #[command(flatten)]
    Client(client_cli::Command),
}

/// Compose integration commands.
#[cfg(feature = "compose")]
#[derive(Debug, Subcommand)]
pub enum ComposeCommand {
    /// Render a bounded, secret-discarding effective-model projection.
    Model(ComposeModelArgs),
}

/// Arguments accepted by a build which omits Compose integration.
#[cfg(not(feature = "compose"))]
#[derive(Debug, Args)]
pub struct ComposeUnavailableArgs {
    /// Uninterpreted Compose arguments, retained only so remediation can be shown.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub arguments: Vec<std::ffi::OsString>,
}

/// Compose frontend family used to render the effective model.
#[cfg(feature = "compose")]
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum ComposeFrontend {
    /// Docker with the integrated Compose v2 plugin.
    Docker,
    /// Rootless Podman with an explicitly pinned Docker Compose v2 provider.
    Podman,
}

/// Arguments for bounded effective-model projection.
#[cfg(feature = "compose")]
#[derive(Debug, Args)]
pub struct ComposeModelArgs {
    /// Selected frontend family.
    #[arg(long, value_enum, default_value_t = ComposeFrontend::Docker)]
    pub frontend: ComposeFrontend,
    /// Absolute path to the selected Docker or Podman executable.
    #[arg(long)]
    pub frontend_path: PathBuf,
    /// Absolute Docker Compose v2 provider path required with Podman.
    #[arg(long, required_if_eq("frontend", "podman"))]
    pub provider: Option<PathBuf>,
    /// Compose file; repeat in workload-launch merge order.
    #[arg(long = "file", short = 'f')]
    pub files: Vec<PathBuf>,
    /// Enabled profile; repeat in workload-launch order.
    #[arg(long = "profile")]
    pub profiles: Vec<String>,
    /// Compose environment file; repeat in workload-launch precedence order.
    #[arg(long = "env-file")]
    pub environment_files: Vec<PathBuf>,
    /// Explicit effective project name.
    #[arg(long)]
    pub project_name: Option<String>,
    /// Explicit project directory for relative path resolution.
    #[arg(long)]
    pub project_directory: Option<PathBuf>,
}

/// Configuration-corpus maintenance commands.
#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Install a reviewed named Compose document into the protected config area.
    InstallCompose(InstallComposeArgs),
}

/// Arguments for protected Compose-document installation.
#[derive(Debug, Args)]
pub struct InstallComposeArgs {
    /// Selected schema-3 bootstrap.
    #[arg(long)]
    pub config: PathBuf,
    /// Stable Compose document name.
    #[arg(long)]
    pub name: String,
    /// Reviewed or staged source document.
    #[arg(long)]
    pub source: PathBuf,
    /// Protected destination beside or below the bootstrap.
    #[arg(long)]
    pub destination: PathBuf,
}

/// `completions` subcommand arguments.
#[derive(Debug, Args)]
pub struct CompletionsArgs {
    /// The shell to emit a completion script for.
    #[arg(value_enum)]
    pub shell: clap_complete::Shell,
}

/// Returns the fully assembled top-level clap [`Command`](clap::Command) for the
/// `basil` binary, for tooling such as man-page and shell-completion generation.
#[must_use]
pub fn cli() -> clap::Command {
    Cli::command()
}

/// Render the completion script for `shell` and write it to `out`.
///
/// Generation goes through an in-memory buffer so a closed pipe (`basil
/// completions bash | head`) surfaces as an `Err` instead of a panic inside
/// the generator.
pub fn write_completions(
    shell: clap_complete::Shell,
    out: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    let mut buf = Vec::new();
    clap_complete::generate(shell, &mut cli(), "basil", &mut buf);
    out.write_all(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("parse cli")
    }

    #[test]
    fn bundle_is_top_level_command() {
        let cli = parse(&[
            "basil",
            "bundle",
            "verify",
            "creds.sealed",
            "--open",
            "passphrase:file=/run/pass",
        ]);
        assert!(matches!(cli.command, Command::Bundle(_)));
    }

    #[test]
    fn old_config_bundle_path_is_not_user_facing() {
        let err = Cli::try_parse_from(["basil", "config", "bundle", "verify"])
            .expect_err("config bundle must not remain as a compatibility command");
        assert!(
            err.to_string().contains("unrecognized subcommand")
                || err.to_string().contains("invalid subcommand"),
            "{err}"
        );
    }

    #[cfg(feature = "compose")]
    #[test]
    fn compose_model_requires_pinned_provider_for_podman() {
        let error = Cli::try_parse_from([
            "basil",
            "compose",
            "model",
            "--frontend",
            "podman",
            "--frontend-path",
            "/usr/bin/podman",
        ])
        .expect_err("Podman must not resolve an arbitrary provider from PATH");
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[cfg(not(feature = "compose"))]
    #[test]
    fn feature_off_build_accepts_compose_for_actionable_dispatch() {
        let cli = parse(&["basil", "compose", "model", "--file", "compose.yaml"]);
        assert!(matches!(cli.command, Command::Compose(_)));
    }

    #[test]
    fn set_backend_accepts_structured_backend_value() {
        let cli = parse(&[
            "basil",
            "bundle",
            "set-backend",
            "creds.sealed",
            "--backend",
            "id=aws1,type=aws-kms,region=us-east-1,profile=prod",
            "--open",
            "passphrase:file=/run/pass",
        ]);
        assert!(matches!(cli.command, Command::Bundle(_)));
    }

    #[test]
    fn doctor_rootless_expected_containers_is_absent_by_default() {
        let cli = parse(&["basil", "doctor"]);
        let Command::Doctor(args) = cli.command else {
            panic!("doctor command expected");
        };
        assert_eq!(args.rootless_expected_containers(), None);
    }

    #[test]
    fn doctor_rootless_expected_containers_accepts_boundaries() {
        for count in ["1", "1000"] {
            let cli = parse(&["basil", "doctor", "--rootless-expected-containers", count]);
            let Command::Doctor(args) = cli.command else {
                panic!("doctor command expected");
            };
            assert_eq!(
                args.rootless_expected_containers(),
                count.parse::<u32>().ok()
            );
        }
    }

    #[test]
    fn doctor_rootless_expected_containers_rejects_out_of_range() {
        for count in ["0", "1001"] {
            let err =
                Cli::try_parse_from(["basil", "doctor", "--rootless-expected-containers", count])
                    .expect_err("out-of-range rootless container count must reject");
            assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
        }
    }

    #[test]
    fn cache_check_and_preview_first_prune_are_user_facing() {
        assert!(matches!(
            parse(&["basil", "cache", "--check", "--age", "60d", "-q"]).command,
            Command::Cache(_)
        ));
        assert!(matches!(
            parse(&[
                "basil",
                "cache",
                "prune",
                "registry.example/team/app:stable"
            ])
            .command,
            Command::Cache(_)
        ));
        assert!(matches!(
            parse(&[
                "basil",
                "cache",
                "prune",
                "--force",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            ])
            .command,
            Command::Cache(_)
        ));
    }

    #[test]
    fn cache_prune_rejects_empty_selector_input() {
        let error = Cli::try_parse_from(["basil", "cache", "prune"])
            .expect_err("empty prune selectors must fail closed");
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }
}
