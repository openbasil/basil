//! `cargo xtask` automation for the Basil workspace.
//!
//! One command today: render roff man pages for the shipped binaries
//! (`basil`, `basil-nats-bridge`) with `clap_mangen`. Each binary's top-level
//! page plus one page per (recursively nested) subcommand is written to the
//! output directory, so `man basil-agent`, `man basil-config-bundle`, and so on
//! resolve once the pages are installed under `share/man/man1`.
//!
//! Run it via the `xtask` cargo alias (`cargo xtask -o <dir>`) or the
//! `just man-pages` recipe.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;

/// Command-line arguments for the `xtask` runner.
#[derive(Debug, Parser)]
#[command(name = "xtask", about = "Basil workspace automation tasks")]
struct Cli {
    /// Directory to write generated man pages into (created if absent).
    #[arg(short, long, default_value = "target/man")]
    out: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    fs::create_dir_all(&cli.out)
        .with_context(|| format!("creating output directory {}", cli.out.display()))?;

    let mut count = 0usize;
    count += render_tree(&basil_bin::cli(), &cli.out)?;
    count += render_tree(&basil_nats_bridge::cli(), &cli.out)?;

    println!("wrote {count} man page(s) to {}", cli.out.display());
    Ok(())
}

/// Render `command` and every nested subcommand under `dir`, one `.1` roff file
/// each. The top-level page keeps the binary name; subcommand pages are named
/// `<parent>-<sub>.1` (matching the `man basil-agent` lookup convention).
fn render_tree(command: &clap::Command, dir: &Path) -> Result<usize> {
    render_named(command, command.get_name(), dir)
}

/// Render a single command as `<full_name>.1`, then recurse into its visible
/// subcommands with the dashed name prefix.
fn render_named(command: &clap::Command, full_name: &str, dir: &Path) -> Result<usize> {
    // Retitle the command so the `.TH` header and synopsis read as the fully
    // qualified path (e.g. `basil-agent`) rather than the bare leaf name.
    let titled = command.clone().name(full_name.to_owned());
    let mut buffer: Vec<u8> = Vec::new();
    clap_mangen::Man::new(titled)
        .render(&mut buffer)
        .with_context(|| format!("rendering man page for {full_name}"))?;
    let path = dir.join(format!("{full_name}.1"));
    fs::write(&path, &buffer).with_context(|| format!("writing {}", path.display()))?;

    let mut count = 1usize;
    for sub in command.get_subcommands() {
        // Skip clap's synthetic `help` subcommand and any hidden commands: they
        // carry no documentation worth a standalone page.
        if sub.is_hide_set() || sub.get_name() == "help" {
            continue;
        }
        let child_name = format!("{full_name}-{}", sub.get_name());
        count += render_named(sub, &child_name, dir)?;
    }
    Ok(count)
}
