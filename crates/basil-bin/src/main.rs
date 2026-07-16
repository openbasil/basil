// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Unified `basil` binary: daemon, offline config tools, and socket client.
//!
//! The command-line definition lives in the crate library (`basil_bin::cli`) so
//! tooling can render man pages; this entry point only parses and dispatches.

use anyhow::Result;
use basil_bin::{Cli, Command, ConfigCommand, client_cli};
#[cfg(feature = "compose")]
use basil_bin::{ComposeCommand, ComposeFrontend, ComposeModelArgs};
use basil_core::agent_cli;
use clap::Parser;
#[cfg(feature = "compose")]
use std::io::Write as _;

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
        Command::Config(ConfigCommand::InstallCompose(args)) => {
            match basil_core::install_compose_document(
                &args.config,
                &args.name,
                &args.source,
                &args.destination,
            )? {
                basil_core::ComposeInstallOutcome::Installed { destination } => {
                    println!("installed {}", destination.display());
                }
                basil_core::ComposeInstallOutcome::Staged {
                    staged_copy,
                    command,
                } => {
                    println!("staged {}", staged_copy.display());
                    println!("{command}");
                }
            }
            Ok(())
        }
        #[cfg(feature = "compose")]
        Command::Compose(ComposeCommand::Model(args)) => run_compose_model(args).await,
        #[cfg(not(feature = "compose"))]
        Command::Compose(_) => anyhow::bail!(
            "Compose support is not included in this Basil build; install the standard Basil package or rebuild basil-bin with --features compose"
        ),
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

#[cfg(feature = "compose")]
async fn run_compose_model(args: ComposeModelArgs) -> Result<()> {
    let frontend = match args.frontend {
        ComposeFrontend::Docker => basil_compose::Frontend::Docker {
            executable: args.frontend_path,
        },
        ComposeFrontend::Podman => basil_compose::Frontend::Podman {
            executable: args.frontend_path,
            provider: args.provider.ok_or_else(|| {
                anyhow::anyhow!("the Podman frontend requires an explicit provider")
            })?,
        },
    };
    let invocation = basil_compose::Invocation {
        files: args.files,
        profiles: args.profiles,
        environment_files: args.environment_files,
        project_name: args.project_name,
        project_directory: args.project_directory,
    };
    let command = basil_compose::command_spec(&frontend, &invocation)?;
    {
        let mut stderr = std::io::stderr().lock();
        writeln!(stderr, "{}", command.display())?;
    }
    let model = basil_compose::project(&frontend, &invocation).await?;
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &model)?;
    writeln!(stdout)?;
    Ok(())
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
