// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! ES256 `COSE_Sign1` interop with `veraison/go-cose` (br basil-c033).
//!
//! Two directions, both gated on Go being installed:
//! - Basil produces a deterministic ES256 `COSE_Sign1` (the checked-in
//!   fixture); go-cose verifies it and re-encodes byte-identically.
//! - go-cose produces an ES256 `COSE_Sign1` from the same P-256 key; Basil's
//!   [`P256Verifier`] accepts it.
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::task::{Context, Poll, Waker};

use basil_cose::{ExternalAad, KeyId, P256Verifier, VerifySignedParams, verify_signed};
use basil_tests::on_path;
use serde_json::Value;

const CRATE_DIR: &str = env!("CARGO_MANIFEST_DIR");

fn block_on<F: Future>(fut: F) -> F::Output {
    let mut cx = Context::from_waker(Waker::noop());
    let mut fut = std::pin::pin!(fut);
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("local future pended"),
    }
}

fn repo_root() -> PathBuf {
    Path::new(CRATE_DIR)
        .parent()
        .expect("crate dir has workspace parent")
        .parent()
        .expect("crates dir has repo parent")
        .to_path_buf()
}

fn es256_fixture() -> Value {
    let path = Path::new(CRATE_DIR)
        .parent()
        .expect("crate dir has workspace parent")
        .join("basil-proto/fixtures/cose-es256-sign1-v1.json");
    serde_json::from_slice(&std::fs::read(path).expect("ES256 fixture readable"))
        .expect("ES256 fixture is JSON")
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn go_interop_dir() -> PathBuf {
    repo_root().join("crates/basil-tests/tests/cose_go_interop")
}

fn fixture_verifier(doc: &Value) -> P256Verifier {
    let key = &doc["key"];
    let public = unhex(key["public_sec1_hex"].as_str().expect("public sec1 hex"));
    P256Verifier::from_sec1(
        KeyId::from_text(key["key_id"].as_str().expect("key id")).unwrap(),
        &public,
    )
    .unwrap()
}

#[test]
fn go_cose_verifies_basil_es256_fixture() {
    if !on_path("go") {
        eprintln!("SKIP: go not found on PATH; ES256 go-cose interop needs Go");
        return;
    }
    let status = Command::new("go")
        .arg("test")
        .arg("-run")
        .arg("TestGoCoseVerifiesBasilEs256Sign1|TestGoCoseRejectsTamperedBasilEs256Sign1")
        .arg(".")
        .current_dir(go_interop_dir())
        .status()
        .expect("run go test for ES256 interop");
    assert!(status.success(), "go-cose ES256 fixture interop failed");
}

#[test]
fn basil_verifies_go_cose_produced_es256_sign1() {
    if !on_path("go") {
        eprintln!("SKIP: go not found on PATH; ES256 go-cose producer interop needs Go");
        return;
    }
    let output = Command::new("go")
        .arg("run")
        .arg("./cmd/es256produce")
        .current_dir(go_interop_dir())
        .output()
        .expect("run go-cose ES256 producer");
    assert!(
        output.status.success(),
        "go-cose ES256 producer failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let produced = String::from_utf8(output.stdout).expect("producer emits UTF-8 hex");
    let bytes = unhex(produced.trim());
    let doc = es256_fixture();
    let verified = block_on(verify_signed(
        &bytes,
        &fixture_verifier(&doc),
        &VerifySignedParams {
            external_aad: ExternalAad::empty(),
            validation: None,
        },
    ))
    .expect("Basil verifies go-cose ES256 Sign1");
    assert_eq!(
        verified.content_type.as_str(),
        "application/basil.go-es256-interop"
    );
    assert_eq!(verified.payload, b"go-cose es256 payload");
}
