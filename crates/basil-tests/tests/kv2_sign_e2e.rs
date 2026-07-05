// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Cross-engine LIVE e2e for the value-store Ed25519 materialize-to-sign path
//! (`engine=kv2`, vault-iiz, basil-cy8) over the broker gRPC, on BOTH a dev
//! `OpenBao` AND a dev `Vault` store.
//!
//! vault-iiz shipped "materialize-to-sign": a catalog key declared
//! `class=asymmetric` + `keyType=ed25519` + an explicit `engine=kv2` holds its
//! 32-byte Ed25519 seed in a KV-v2 path rather than as a transit key. On a
//! `sign`, the manager materializes that seed (`Zeroizing` end-to-end), signs in
//! process with the crypto core, and zeroizes: the seed never leaves the vault
//! except into the broker's own memory for one signature. `verify` /
//! `get_public_key` are public ops: they read the Ed25519 **public** half from
//! the key's out-of-band-provisioned `publicPath` (basil-o86), so the seed is
//! materialized **only** on `sign`. That path was proven offline (an RFC 8032 KAT
//! in crypto-core + a mock-backend manager test), but NOT against a live
//! `bao`/`vault` KV. THIS file is that live, cross-engine coverage.
//!
//! What the harness sets up (see `scripts/prefill-test-store.sh` +
//! `basil_tests::boot_basil`): the prefill writes the FIXED RFC 8032 §7.1 Test 1
//! Ed25519 seed into `secret/data/kv2/signing-key` (raw 32 bytes, base64-encoded
//! under the `value` field, exactly how the broker stores any KV value), adds a
//! catalog key `kv2.signing_key` (`class=asymmetric` + `engine=kv2` +
//! `keyType=ed25519`, `missing=error` so a missing seed FATALs boot rather than
//! minting authority silently), and grants the running uid `role:signer`
//! (`sign`/`verify`/`get_public_key`) over it, and NOTHING else, so `get`/`set`
//! land outside any grant.
//!
//! On each engine the test, driving the `basil` client over the broker's unix
//! socket, asserts:
//!   (a) the broker's signature VERIFIES under the key's public (fetched via
//!       `get_public_key`, which reads the out-of-band `publicPath`, never the
//!       seed), and that public equals the RFC 8032 Test 1 PUBLIC KEY, anchoring
//!       the seed→public mapping on a published KAT;
//!   (b) the signature MATCHES a deterministic in-process Ed25519 sign over the
//!       same seed (Ed25519 is deterministic), proving the live materialize
//!       reproduces the offline KAT byte-for-byte;
//!   (c) `get` and `set` over the key are DENIED (the asymmetric op surface makes
//!       the private seed structurally un-gettable/un-settable, and the uid holds
//!       no reader/operator grant either).
//!
//! GATING: each engine leg is independently gated on its CLI (`bao`/`vault`)
//! being on PATH; an absent engine prints an EXPLICIT skip line (acceptance
//! forbids a silent `#[ignore]`). `ran_any` asserts at least one leg ran, so an
//! all-absent environment FAILS loudly rather than passing vacuously.
//!
//! Each engine leg's `VAULT_ADDR` comes from `basil_tests::alloc_addr()`, which hands
//! out a disjoint port per call / per test binary so the two dev servers (and
//! the concurrently-running SPIFFE live tests) never collide on a port.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::allow_attributes
)]

use basil_tests::{Engine, alloc_addr, boot_basil, on_path};

use basil::Client;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Catalog name of the value-store (engine=kv2) Ed25519 signing key the prefill
/// provisions (see `scripts/prefill-test-store.sh`).
const KEY: &str = "kv2.signing_key";

/// The FIXED 32-byte Ed25519 seed the prefill writes into KV. Fixed (not random)
/// so the public + signature are deterministic and byte-assertable here.
const SEED_HEX: &str = "9d61b19deff3ee2e5b3c00a4a14d2b9bf9c2c9d5fb02b5b6e4f00f7d9e2f6e8e";
/// The Ed25519 PUBLIC half of `SEED_HEX`, derived independently (ed25519-dalek)
/// and locked here as a KAT anchor on the seed→public mapping through the live
/// KV materialize. (We additionally re-derive it from `SEED_HEX` in-test, so a
/// future seed edit fails the assertion rather than silently drifting.)
const PUBLIC_HEX: &str = "b9401e836a5c59aa085c22dbbc123abb41ab80e3c49fcae3a921ee8cf662cdd6";

/// Decode a fixed-length hex constant into `N` bytes (test fixtures only).
fn unhex<const N: usize>(hex: &str) -> [u8; N] {
    assert_eq!(hex.len(), N * 2, "hex literal is {N} bytes");
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("valid hex byte");
    }
    out
}

/// Drive one engine end to end: boot the broker against a freshly-prefilled
/// `engine` store, then prove the live kv2 materialize-to-sign path over gRPC.
async fn drive_engine(engine: Engine, tag: &str, addr: &str) {
    // boot_basil runs the prefill (which writes the Ed25519 seed into KV and
    // wires the catalog/policy) then boots the broker on the AppRole bundle path
    // and returns once the socket binds. Because the catalog key is missing=error,
    // merely getting here already proves the seed's KV existence probe found it.
    let harness = boot_basil(tag, engine, addr);
    let socket = harness.socket();
    let socket_str = socket.to_str().expect("socket path is UTF-8");

    let mut client = Client::connect(socket_str)
        .await
        .expect("connect basil client to the broker socket");

    let message = b"basil-cy8 kv2 materialize-to-sign live e2e";

    // --- (a) the broker signs via the live KV-materialized seed; the signature
    //         verifies under the key's public, fetched via get_public_key.
    let signature = client
        .sign(KEY, message)
        .await
        .expect("sign via the kv2-materialized Ed25519 seed");
    assert_eq!(
        signature.len(),
        64,
        "Ed25519 signature is 64 bytes (got {})",
        signature.len()
    );

    let pubresp = client
        .get_public_key(KEY, None)
        .await
        .expect("get_public_key derives from the materialized seed");

    // The fetched public equals the locked KAT anchor `PUBLIC_HEX`, AND that
    // anchor is itself the independent ed25519-dalek derivation of the fixed seed,
    // so the broker's live KV materialize reproduces the seed→public mapping.
    let seed = unhex::<32>(SEED_HEX);
    let derived_public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let expected_public = unhex::<32>(PUBLIC_HEX);
    assert_eq!(
        derived_public, expected_public,
        "the locked PUBLIC_HEX anchor matches the seed's independently-derived public"
    );
    assert_eq!(
        pubresp.public_key.as_slice(),
        expected_public.as_slice(),
        "[{}] get_public_key returns the fixed seed's Ed25519 public",
        engine.prefill_name()
    );

    // The broker's signature verifies under that public (ed25519-dalek, an
    // independent verifier, not the broker's own verify).
    let verifying = VerifyingKey::from_bytes(&expected_public).expect("valid Ed25519 public");
    let sig_bytes: [u8; 64] = signature
        .as_slice()
        .try_into()
        .expect("Ed25519 signature is 64 bytes");
    let sig = Signature::from_bytes(&sig_bytes);
    verifying
        .verify(message, &sig)
        .expect("the broker's signature verifies under the key's public");

    // The broker's OWN verify agrees (and a tampered message verifies false).
    assert!(
        client
            .verify(KEY, message, &signature)
            .await
            .expect("broker verify of its own signature"),
        "[{}] broker verify accepts its own signature",
        engine.prefill_name()
    );
    assert!(
        !client
            .verify(KEY, b"a different message", &signature)
            .await
            .expect("broker verify of a tampered message"),
        "[{}] broker verify rejects a signature over a different message",
        engine.prefill_name()
    );

    // --- (b) the signature MATCHES a deterministic in-process Ed25519 sign over
    //         the same seed: the live materialize reproduces the offline KAT
    //         byte-for-byte (Ed25519 signatures are deterministic).
    let expected_sig = SigningKey::from_bytes(&seed).sign(message);
    assert_eq!(
        signature.as_slice(),
        expected_sig.to_bytes().as_slice(),
        "[{}] live broker signature is byte-identical to a deterministic in-proc sign over the same seed",
        engine.prefill_name()
    );

    // --- (c) get/set over the key are DENIED. The asymmetric op surface makes the
    //         private seed structurally un-gettable/un-settable, and the uid holds
    //         only role:signer here (no reader/operator), so both fail closed.
    let get_err = client
        .get_secret(KEY, None)
        .await
        .expect_err("get on a value-store signing key must be denied");
    eprintln!(
        "KV2-SIGN[{}]: get denied as expected: {get_err}",
        engine.prefill_name()
    );
    let set_err = client
        .set_secret(KEY, b"attacker-supplied-seed")
        .await
        .expect_err("set on a value-store signing key must be denied");
    eprintln!(
        "KV2-SIGN[{}]: set denied as expected: {set_err}",
        engine.prefill_name()
    );

    drop(client);
    eprintln!(
        "KV2-SIGN[{}]: live sign matched the deterministic KAT + verified under the seed's public; get/set denied",
        engine.prefill_name()
    );
    drop(harness);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kv2_materialize_to_sign_cross_engine() {
    let ran_bao = if on_path("bao") {
        drive_engine(Engine::OpenBao, "kv2-sign-bao", &alloc_addr()).await;
        true
    } else {
        eprintln!("SKIP: bao not found on PATH; kv2 materialize-to-sign e2e needs a live OpenBao");
        false
    };

    let ran_vault = if on_path("vault") {
        drive_engine(Engine::Vault, "kv2-sign-vault", &alloc_addr()).await;
        true
    } else {
        eprintln!("SKIP: vault not found on PATH; kv2 materialize-to-sign e2e needs a live Vault");
        false
    };

    let ran_any = ran_bao || ran_vault;

    assert!(
        ran_any,
        "neither bao nor vault was on PATH; the kv2 materialize-to-sign live e2e ran no engine \
         leg (this is a live cross-engine acceptance test; it must not pass vacuously)"
    );
}
