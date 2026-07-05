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

use basil_core::{agent_cli, bundle_cli, init};
use clap::{CommandFactory, Parser, Subcommand};

/// Top-level `basil` command-line interface.
#[derive(Debug, Parser)]
#[command(name = "basil", version, about = "Basil broker and operator tool")]
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
    /// Run the broker daemon.
    Agent(agent_cli::RunArgs),
    /// Create and manage a sealed credential bundle.
    #[command(subcommand)]
    Bundle(Box<bundle_cli::BundleCommand>),
    /// Offline config and policy operations.
    #[command(subcommand)]
    Config(Box<ConfigCommand>),
    /// Preflight environment and deployment checks.
    Doctor(agent_cli::DoctorArgs),
    #[command(flatten)]
    Client(client_cli::Command),
}

/// Offline `basil config` subcommands.
#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Scaffold a first-run starter set.
    Init(init::InitArgs),
    /// Evaluate a proposed policy decision offline.
    Explain(agent_cli::ExplainArgs),
}

/// Returns the fully assembled top-level clap [`Command`](clap::Command) for the
/// `basil` binary, for tooling such as man-page and shell-completion generation.
#[must_use]
pub fn cli() -> clap::Command {
    Cli::command()
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
