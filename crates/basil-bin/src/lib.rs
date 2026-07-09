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
use clap::{Args, CommandFactory, Parser, Subcommand};

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
    #[command(flatten)]
    Client(client_cli::Command),
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
}
