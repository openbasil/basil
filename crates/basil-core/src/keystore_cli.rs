// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Reserved offline `basil keystore` command surface.

use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::Subcommand;

/// Stable rejection returned before any configuration, logging, secret, bundle,
/// database, lock, marker, or filesystem access.
pub const REKEY_DISABLED: &str = "db-keystore DEK rotation is disabled pending basil-w37e";

/// `keystore` subcommands.
#[derive(Debug, Subcommand)]
pub enum KeystoreCommand {
    /// Reserved DEK-rotation surface; currently fails closed without I/O.
    Rekey(RekeyArgs),
}

/// Reserved arguments for the future coupled `db-keystore` rekey command.
#[derive(Debug, clap::Args)]
pub struct RekeyArgs {
    /// Agent configuration that will select the database and sealed bundle.
    #[arg(short = 'c', long = "config", env = "BASIL_CONFIG")]
    config: Option<PathBuf>,

    /// Catalog backend id to rotate.
    #[arg(long)]
    backend: String,

    /// Owner-only file that will contain the replacement raw 32-byte DEK.
    #[arg(long, value_name = "FILE")]
    new_dek_file: PathBuf,

    /// Existing bundle unlock method. Repeat for independent slots.
    #[arg(long = "open", value_name = "METHOD", required = true)]
    open: Vec<String>,
}

/// Reject the reserved command before inspecting any supplied input.
///
/// # Errors
///
/// Always returns the stable [`REKEY_DISABLED`] rejection.
pub fn run(command: KeystoreCommand) -> Result<()> {
    let KeystoreCommand::Rekey(_args) = command;
    bail!(REKEY_DISABLED)
}
