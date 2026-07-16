// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::indexing_slicing, clippy::unwrap_used)]

use basil_compose::{Build, Frontend, Invocation, project, project_json};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const QUALIFICATION: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/qualification/docker-compose-5.3.1"
);

fn artifact(name: &str) -> Vec<u8> {
    fs::read(Path::new(QUALIFICATION).join(name)).unwrap()
}

#[test]
fn qualified_outputs_cover_files_interpolation_name_profiles_and_local_builds() {
    let multi_file = project_json(&artifact("multi-file.json")).unwrap();
    assert_eq!(multi_file.name, "qualified-payments");
    assert_eq!(multi_file.services.len(), 2);
    assert_eq!(
        multi_file.services["api"].image.as_deref(),
        Some("registry.example/api:2026-07-16-prod")
    );
    let sanitized = serde_json::to_string(&multi_file).unwrap();
    assert!(!sanitized.contains("rendered-sensitive-value"));
    assert!(!sanitized.contains("REMAINS_UNRESOLVED"));

    let profiled = project_json(&artifact("prod-profile.json")).unwrap();
    assert_eq!(profiled.services.len(), 4);
    assert_eq!(profiled.services["worker"].profiles, ["prod"]);
    assert_eq!(
        profiled.services["worker"].build,
        Some(Build {
            context: Some("/opt/basil-compose-qualification/worker".into()),
            dockerfile: Some("Containerfile".into()),
        })
    );
    assert_eq!(
        profiled.services["worker"].image.as_deref(),
        Some("local-worker:2026-07-16")
    );
    assert!(profiled.services["prebuilt"].build.is_none());
    assert!(
        !serde_json::to_string(&profiled)
            .unwrap()
            .contains("PRIVATE_BUILD_ARG")
    );
}

#[test]
fn qualification_hashes_and_frontend_provenance_are_pinned() {
    let sums = String::from_utf8(artifact("SHA256SUMS")).unwrap();
    let mut checked = BTreeSet::new();
    for line in sums.lines() {
        let (expected, name) = line.split_once("  ").unwrap();
        let bytes = artifact(name);
        let actual = hex::encode(Sha256::digest(bytes));
        assert_eq!(actual, expected, "hash mismatch for {name}");
        assert!(checked.insert(name));
    }
    let required = BTreeSet::from([
        "Containerfile",
        "capture.sh",
        "compose.prod.yaml",
        "compose.yaml",
        "fake-docker-compose-provider.sh",
        "fake-podman.sh",
        "multi-file.json",
        "prod-profile.json",
        "prod.env",
        "provenance.json",
        "real-podman-provider-argv.txt",
    ]);
    assert_eq!(checked, required);

    let provenance: Value = serde_json::from_slice(&artifact("provenance.json")).unwrap();
    assert_eq!(
        provenance["docker"]["resolvedExecutable"],
        "/nix/store/5y9rr0pvw0x1c912lhnpwv1glnj9hjxq-docker-29.6.1/bin/docker"
    );
    assert_eq!(
        provenance["docker"]["composeVersion"],
        "Docker Compose version 5.3.1"
    );
    assert_eq!(
        provenance["podman"]["resolvedExecutable"],
        "/nix/store/w4mhgz9r2zq7f1lmzgg3wlj7pwncdg3j-podman-5.8.4/bin/podman"
    );
    let capture = String::from_utf8(artifact("capture.sh")).unwrap();
    assert!(capture.contains(provenance["docker"]["resolvedExecutable"].as_str().unwrap()));
    assert!(capture.contains("config --format json --no-env-resolution"));
}

#[tokio::test]
async fn deterministic_podman_lane_selects_absolute_provider_and_exact_argv() {
    let root = PathBuf::from(QUALIFICATION);
    let model = project(
        &Frontend::Podman {
            executable: root.join("fake-podman.sh"),
            provider: root.join("fake-docker-compose-provider.sh"),
        },
        &Invocation {
            files: vec![root.join("compose.yaml"), root.join("compose.prod.yaml")],
            profiles: vec!["prod".into()],
            environment_files: vec![root.join("prod.env")],
            project_name: Some("qualified-payments".into()),
            project_directory: Some(root),
        },
    )
    .await
    .unwrap();
    assert_eq!(model.name, "qualified-payments");
    assert_eq!(model.services.len(), 4);
    assert_eq!(
        model.services["worker"].image.as_deref(),
        Some("local-worker:2026-07-16")
    );
}
