// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use basil_nats_bridge::{Args, Config, run};
use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let config = Config::from_path(&args.config)
        .await
        .with_context(|| format!("loading config {}", args.config.display()))?;
    run(config).await.context("running Basil NATS bridge")
}
