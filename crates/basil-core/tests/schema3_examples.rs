// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::unwrap_used
)]

use std::path::{Path, PathBuf};

use basil_core::{load_bootstrap, load_documents};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root resolves")
}

#[test]
fn minimal_schema3_example_loads() {
    validate_example("docs/examples/schema-3/minimal/config.toml", ["web"]);
}

#[test]
fn full_schema3_example_loads() {
    validate_example("docs/examples/schema-3/full/config.toml", ["payments"]);
}

fn validate_example<const N: usize>(relative_config: &str, compose_names: [&str; N]) {
    let config = repo_root().join(relative_config);
    // Release/package source filters omit the documentation tree. The examples
    // are still checked in repository and workspace test runs, where their
    // source bytes are present.
    if !config.exists() {
        return;
    }
    let bootstrap = load_bootstrap(Some(&config), &[]).expect("bootstrap loads");

    let documents = load_documents(&bootstrap.sources).expect("documents load");

    for name in compose_names {
        assert!(
            documents.compose.contains_key(name),
            "Compose document `{name}` is loaded"
        );
    }
    assert!(
        bootstrap.sources.bundle.exists(),
        "example bundle placeholder exists"
    );
}
