// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Unified `basil` binary: daemon, offline config tools, and socket client.
//!
//! The command-line definition lives in the crate library (`basil_bin::cli`) so
//! tooling can render man pages; this entry point only parses and dispatches.

use anyhow::Result;
use basil_bin::{Cli, Command, client_cli};
use basil_core::agent_cli;
use clap::Parser;

// With `db-keystore` enabled, turso (its SQLite engine) already installs a
// mimalloc `#[global_allocator]`, and a crate graph can only declare one; the
// process still runs on mimalloc either way, and `secure-alloc`
// (`mimalloc/secure`) applies to turso's instance too via feature unification.
#[cfg(not(feature = "db-keystore"))]
#[global_allocator]
static GLOBAL_ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init(args) => agent_cli::run_init(cli.socket.as_deref(), &args),
        #[cfg(feature = "keystore-backend")]
        Command::Demo(args) => basil_core::demo::run(&args),
        Command::Completions(args) => {
            basil_bin::write_completions(args.shell, &mut std::io::stdout())
                .map_err(anyhow::Error::from)
        }
        Command::Agent(args) => agent_cli::run_agent(args, basil_bin::VERSION).await,
        Command::Bundle(command) => agent_cli::run_bundle(*command),
        // Unified `explain`: offline file dry-run by default; `--live` queries the
        // running broker over the global `--socket` (needs the `explain` perm).
        Command::Explain(args) => {
            if args.is_live() {
                init_client_tracing();
                client_cli::explain_live(cli.socket.as_deref(), &args).await
            } else {
                agent_cli::run_explain(&args)
            }
        }
        Command::Doctor(args) => agent_cli::run_doctor_command(args).await,
        Command::Client(command) => {
            init_client_tracing();
            client_cli::run(cli.socket, command).await
        }
    }
}

/// Install the stderr `fmt` subscriber the over-socket client paths use (level
/// from `RUST_LOG`, defaulting to `warn`).
fn init_client_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();
}
