// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Unified `basil` binary: daemon, offline config tools, and socket client.
//!
//! The command-line definition lives in the crate library (`basil_bin::cli`) so
//! tooling can render man pages; this entry point only parses and dispatches.

use anyhow::Result;
use basil_bin::{Cli, Command, ConfigCommand, client_cli};
use basil_core::agent_cli;
use clap::Parser;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Agent(args) => agent_cli::run_agent(args).await,
        Command::Bundle(command) => agent_cli::run_bundle(*command),
        Command::Config(command) => match *command {
            ConfigCommand::Init(args) => agent_cli::run_config_init(&args),
            ConfigCommand::Explain(args) => agent_cli::run_config_explain(&args),
        },
        Command::Doctor(args) => agent_cli::run_doctor_command(args).await,
        Command::Client(command) => {
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
                )
                .init();
            client_cli::run(cli.socket, command).await
        }
    }
}
