// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! LIVE cross-engine e2e for the BIP39 break-glass unlock slot (basil-bp30).
//!
//! The BIP39 slot had only KDF-level unit coverage (`seal/unlock/bip39.rs`:
//! `phrase_to_kek_round_trip` / `wrong_phrase_fails_closed` /
//! `malformed_phrase_is_auth_failed`). What was missing is an actual BUNDLE
//! unseal + broker boot from a mnemonic: the break-glass path an operator would
//! take. `init_flow_e2e` wires only the passphrase slot into the full
//! scaffold->seal->unlock flow.
//!
//! This test closes that gap. The `boot_basil_bip39` harness helper:
//!   1. runs the standard prefill (live `bao`/`vault` + an `AppRole` role/secret),
//!   2. re-seals that SAME `AppRole` backend cred into a fresh bundle carrying a
//!      SINGLE BIP39 slot (a freshly generated 24-word phrase),
//!   3. boots the broker with `[unlock] bip39-phrase-file` and NO passphrase slot.
//!
//! Because the bundle opens ONLY via the BIP39 slot, a bound socket already proves
//! the broker recovered the master KEK from the mnemonic (Argon2id over the phrase
//! entropy), unsealed the `AppRole` cred, and logged into the live backend. We then
//! drive a real `sign`/`verify` over the socket to confirm the unlocked broker
//! serves end to end.
//!
//! GATING: each engine leg is gated on its CLI (`bao`/`vault`) being on PATH; an
//! absent engine prints an EXPLICIT skip line and `ran_any` fails an all-absent
//! environment loudly. Requires the `unlock-bip39` feature (on under
//! `--all-features`).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::significant_drop_tightening
)]

use basil::Client;
use basil_tests::{Engine, alloc_addr, boot_basil_bip39, on_path};

/// A pre-filled transit signing key the running uid holds `role:signer` over
/// (prefill `test-signer` rule). It exists at boot, so `sign`/`verify` need no
/// reconcile.
const SIGNING_KEY: &str = "web.tls.signing_key";

async fn run_engine(engine: Engine) {
    let addr = alloc_addr();
    let harness = boot_basil_bip39(&format!("bip39-{}", engine.prefill_name()), engine, &addr);

    // The socket is bound => the BIP39 slot already unsealed the bundle and the
    // broker logged into the live backend. Exercise a real op to be thorough.
    let socket = harness.socket();
    let mut client = Client::connect(socket.to_str().expect("utf-8 socket path"))
        .await
        .expect("connect basil client over the BIP39-unlocked broker");

    let message = b"break-glass signed this";
    let signature = client
        .sign(SIGNING_KEY, message)
        .await
        .expect("sign over the BIP39-unlocked broker");
    assert!(!signature.is_empty(), "signature is non-empty");

    let verified = client
        .verify(SIGNING_KEY, message, &signature)
        .await
        .expect("verify over the BIP39-unlocked broker");
    assert!(
        verified,
        "signature verifies over the BIP39-unlocked broker"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bip39_break_glass_unlocks_bundle_and_serves_cross_engine() {
    let mut ran_any = false;
    for engine in [Engine::OpenBao, Engine::Vault] {
        if !on_path(engine.cli_bin()) {
            eprintln!(
                "SKIP bip39 break-glass unlock e2e for {}: {} not on PATH",
                engine.prefill_name(),
                engine.cli_bin()
            );
            continue;
        }
        run_engine(engine).await;
        ran_any = true;
    }
    assert!(
        ran_any,
        "no engine CLI (bao/vault) on PATH; bip39 break-glass unlock e2e ran vacuously"
    );
}
