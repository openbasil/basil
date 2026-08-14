// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! COSE fixture interop and strictness checks for the sealed-invocation profile.
//!
//! This suite intentionally triages `cose_minicbor` as a second Rust COSE
//! implementation. Version 0.1.1 cannot verify Basil's suite: it models
//! Ed25519 signatures as private algorithm `-19` instead of standard COSE
//! `EdDSA` `-8`, and has no X25519 ECDH-ES decrypt backend. Those gaps are
//! asserted here; independent signature verification and byte-identical
//! re-encoding are covered by `veraison/go-cose`, and Go-side decrypt is
//! covered by an independent parser plus `x/crypto`.
//!
//! Published inbound vectors are selected from cose-wg/Examples:
//! - `sign1-tests/sign-pass-01.json` is an ES256 `COSE_Sign1`; Basil must
//!   reject it because the profile is EdDSA-only.
//! - `X25519-tests/x25519-hkdf-256-direct.json` is X25519 ECDH-ES with A128GCM;
//!   Basil must reject it because the v1 profile requires A256GCM or
//!   `ChaCha20`-`Poly1305` plus Basil private labels/claims. Basil fixture
//!   decrypt is covered separately by the Go interop module.
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::task::{Context, Poll, Waker};

use basil_cose::{
    ClaimsError, DecodeError, Ed25519Verifier, ExternalAad, KeyId, MessageRole, Subject, UnixTime,
    ValidationParams, VerifyError, VerifySealedParams, VerifySignedParams, verify_sealed,
    verify_signed,
};
use basil_tests::on_path;
use cose_minicbor::cose::CoseSign1;
use cose_minicbor::cose_keys::{CoseAlg, CoseKey, CoseKeySetBuilder, Curve, KeyType};
use serde_json::Value;
use std::collections::BTreeSet;
use std::convert::TryInto as _;
use std::time::Duration;

const COSE_SIGN1_TAG: u8 = 0xD2;
const CRATE_DIR: &str = env!("CARGO_MANIFEST_DIR");

fn block_on<F: Future>(fut: F) -> F::Output {
    let mut cx = Context::from_waker(Waker::noop());
    let mut fut = std::pin::pin!(fut);
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("local future pended"),
    }
}

fn fixture_path() -> PathBuf {
    Path::new(CRATE_DIR)
        .parent()
        .expect("crate dir has workspace parent")
        .join("basil-proto/fixtures/cose-sealed-invocation-v1.json")
}

fn repo_root() -> PathBuf {
    Path::new(CRATE_DIR)
        .parent()
        .expect("crate dir has workspace parent")
        .parent()
        .expect("crates dir has repo parent")
        .to_path_buf()
}

fn fixture_doc() -> Value {
    serde_json::from_slice(&std::fs::read(fixture_path()).expect("fixture readable"))
        .expect("fixture is JSON")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn reject<'a>(doc: &'a Value, name: &str) -> &'a Value {
    doc["rejects"]
        .as_array()
        .expect("rejects array")
        .iter()
        .find(|v| v["name"] == name)
        .unwrap_or_else(|| panic!("missing reject {name}"))
}

fn cose_key_set(doc: &Value, signer: &str) -> Vec<u8> {
    let key = &doc["keys"][signer];
    let mut builder: CoseKeySetBuilder<512> = CoseKeySetBuilder::try_new().unwrap();
    let mut cose_key = CoseKey::new(KeyType::Okp);
    cose_key.alg(CoseAlg::ED25519);
    cose_key.crv(Curve::Ed25519).unwrap();
    let public = unhex(key["public_hex"].as_str().expect("public hex"));
    cose_key.x(&public).unwrap();
    cose_key.kid(key["key_id"].as_str().expect("key id").as_bytes());
    builder.push_key(cose_key).unwrap();
    builder.into_bytes().unwrap().to_vec()
}

fn minicbor_decode_sign1(tagged: &[u8]) -> CoseSign1<'_> {
    assert_eq!(tagged[0], COSE_SIGN1_TAG, "fixture is tagged COSE_Sign1");
    minicbor::decode(&tagged[1..]).expect("counterparty decodes COSE_Sign1 body")
}

fn basil_verifier(doc: &Value, signer: &str) -> Ed25519Verifier {
    let key = &doc["keys"][signer];
    let public: [u8; 32] = unhex(key["public_hex"].as_str().unwrap())
        .try_into()
        .expect("ed25519 public key is 32 bytes");
    Ed25519Verifier::from_key(
        KeyId::from_text(key["key_id"].as_str().unwrap()).unwrap(),
        &public,
    )
    .unwrap()
}

fn validation(role: MessageRole) -> ValidationParams {
    ValidationParams {
        now: UnixTime(1_782_740_010),
        max_clock_skew: Duration::from_secs(30),
        max_ttl: Duration::from_mins(5),
        default_ttl: Duration::from_mins(1),
        allowed_audiences: BTreeSet::from([
            Subject::new("basil://broker.test".to_string()).expect("valid audience")
        ]),
        role,
    }
}

#[test]
fn cose_minicbor_gap_for_basil_eddsa_suite_is_explicit() {
    let doc = fixture_doc();
    let mut rejected = Vec::new();
    for entry in doc["vectors"].as_array().expect("vectors array") {
        let bytes = unhex(entry["cose_sign1_hex"].as_str().expect("cose bytes"));
        let signer = entry["signer"].as_str().expect("signer");
        let msg = minicbor_decode_sign1(&bytes);
        let err = msg
            .suit_verify_cose_sign1(None, &cose_key_set(&doc, signer))
            .expect_err("cose_minicbor should not claim support for Basil EdDSA suite");
        rejected.push(format!("{}:{err:?}", entry["name"].as_str().unwrap()));
    }
    assert_eq!(rejected.len(), doc["vectors"].as_array().unwrap().len());
}

#[test]
fn cose_minicbor_rejects_signature_and_structure_tamper_vectors() {
    let doc = fixture_doc();
    for name in ["tampered-signature", "wrong-outer-tag", "truncated"] {
        let entry = reject(&doc, name);
        let bytes = unhex(entry["cose_sign1_hex"].as_str().expect("cose bytes"));
        let result = if bytes.first() == Some(&COSE_SIGN1_TAG) {
            minicbor::decode::<CoseSign1<'_>>(&bytes[1..])
                .map_err(|e| format!("decode: {e:?}"))
                .and_then(|msg| {
                    msg.suit_verify_cose_sign1(
                        None,
                        &cose_key_set(&doc, entry["verifier"].as_str().unwrap()),
                    )
                    .map_err(|e| format!("verify: {e:?}"))
                })
        } else {
            Err("decode: wrong tag".to_string())
        };
        assert!(result.is_err(), "{name}: counterparty accepted tamper");
    }

    // These Basil rejects are semantic/profile checks outside the counterparty
    // signature scope: claims expiry, role shape, and encryption external AAD.
    for name in ["expired-request", "aad-mismatch", "role-mismatch"] {
        assert!(
            reject(&doc, name)["description"].as_str().is_some(),
            "{name} remains documented in the Basil fixture set"
        );
    }
}

#[test]
fn go_cose_verifies_and_reencodes_basil_fixtures() {
    if !on_path("go") {
        eprintln!("SKIP: go not found on PATH; go-cose fixture interop needs Go");
        return;
    }
    let status = Command::new("go")
        .arg("test")
        .arg(".")
        .current_dir(repo_root().join("crates/basil-tests/tests/cose_go_interop"))
        .status()
        .expect("run go test for COSE interop");
    assert!(status.success(), "go-cose fixture interop failed");
}

#[test]
fn basil_verifies_go_cose_produced_sign1() {
    if !on_path("go") {
        eprintln!("SKIP: go not found on PATH; go-cose producer interop needs Go");
        return;
    }
    let output = Command::new("go")
        .arg("run")
        .arg("./cmd/produce")
        .current_dir(repo_root().join("crates/basil-tests/tests/cose_go_interop"))
        .output()
        .expect("run go-cose producer");
    assert!(
        output.status.success(),
        "go-cose producer failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let produced = String::from_utf8(output.stdout).expect("producer emits UTF-8 hex");
    let bytes = unhex(produced.trim());
    let doc = fixture_doc();
    let verified = block_on(verify_signed(
        &bytes,
        &basil_verifier(&doc, "client-signing"),
        &VerifySignedParams {
            external_aad: ExternalAad::empty(),
            validation: None,
        },
    ))
    .expect("Basil verifies go-cose Sign1");
    assert_eq!(
        verified.content_type.as_str(),
        "application/basil.go-interop"
    );
    assert_eq!(verified.payload, b"go-cose signed payload");
}

#[test]
fn published_cose_wg_vectors_are_rejected_by_basil_profile() {
    // cose-wg/Examples sign1-tests/sign-pass-01.json, output.cbor.
    let es256_sign1 = unhex(
        "D28441A0A201260442313154546869732069732074686520636F6E742E584087DB0D2E5571843B78AC33ECB2830DF7B6E0A4D5B7376DE336B23C591C90C425317E56127FBE04370097CE347087B233BF722B64072BEB4486BDA4031D27244F",
    );
    let doc = fixture_doc();
    let err = block_on(verify_sealed(
        &es256_sign1,
        &basil_verifier(&doc, "client-signing"),
        &VerifySealedParams {
            signature_aad: ExternalAad::empty(),
            validation: &validation(MessageRole::Request),
        },
    ))
    .expect_err("ES256 COSE WG Sign1 is outside Basil EdDSA sealed profile");
    assert!(matches!(
        err,
        VerifyError::Decode(DecodeError::WrongTag { .. } | DecodeError::Malformed)
            | VerifyError::SignatureInvalid
            | VerifyError::Claims(ClaimsError::MissingClaim { .. })
    ));

    // cose-wg/Examples X25519-tests/x25519-hkdf-256-direct.json, output.cbor.
    let x25519_a128gcm_encrypt = unhex(
        "D8608443A10101A1054C9862E02EC874A0DF9FB123385824D2B07042F7BA47C61646CCA83AB97FD23AF21F0D2AC75DCB47A9FC293015D8F098AE9C1B818344A1013818A220A30101200421582072FC171C21BF5C682C64D2EF3A71AC877B40013D3754F63D4C3C3A965F1BA77604485832353531392D3140",
    );
    let err = block_on(verify_sealed(
        &x25519_a128gcm_encrypt,
        &basil_verifier(&doc, "client-signing"),
        &VerifySealedParams {
            signature_aad: ExternalAad::empty(),
            validation: &validation(MessageRole::Request),
        },
    ))
    .expect_err("COSE WG encrypt vector is not a signed Basil sealed invocation");
    assert!(matches!(
        err,
        VerifyError::Decode(DecodeError::WrongTag { .. } | DecodeError::EmbeddedNotEncrypt)
    ));
}

#[test]
fn x25519_decrypt_counterparty_gap_is_explicit() {
    let doc = fixture_doc();
    for entry in doc["vectors"].as_array().expect("vectors array") {
        let algorithm = entry["content_algorithm"]
            .as_i64()
            .expect("content algorithm codepoint");
        assert!(
            matches!(algorithm, 3 | 24),
            "{} pins Basil decrypt KAT bytes for algorithms supported by the profile",
            entry["name"]
        );
    }
}

#[test]
fn fixture_names_are_unique_and_hex_is_lowercase() {
    let doc = fixture_doc();
    let mut names = BTreeSet::new();
    for section in ["vectors", "rejects"] {
        for entry in doc[section].as_array().expect("fixture section array") {
            let name = entry["name"].as_str().expect("fixture name");
            assert!(names.insert(name.to_string()), "duplicate fixture {name}");
            let bytes = entry["cose_sign1_hex"].as_str().expect("cose hex");
            assert_eq!(bytes, hex(&unhex(bytes)), "{name}: non-canonical hex");
        }
    }
}
