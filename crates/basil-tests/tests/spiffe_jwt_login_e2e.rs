//! Live `SpiffeSigner` broker-boot e2e (basil-dk5.4).
//!
//! Proves the broker boots on the **`SpiffeVaultBackend`** path: it self-mints a
//! JWT-SVID with its RSA issuer key, POSTs `auth/<mount>/login` to the engine's
//! `jwt` auth method, obtains a short-lived backend token, and then serves real
//! broker operations through that exchanged token. This is the only live
//! coverage of the self-minted-SVID → `auth/jwt/login` → backend-op flow
//! (`core::backend::spiffe::SpiffeVaultBackend`).
//!
//! What the harness sets up (see `scripts/prefill-test-store.sh --spiffe-boot`
//! and `basil_tests::boot_basil_spiffe`):
//!   1. an RSA-2048 JWT-SVID issuer key (the broker holds it; signs its SVID in
//!      process), sealed as a `BackendCred::SpiffeSigner` under backend `bao`;
//!   2. a `jwt` auth mount whose `jwt_validation_pubkeys` is that key's public
//!      half, with a role bound to the SVID's audience + subject → a policy that
//!      grants the broker's transit/kv/pki needs;
//!   3. `basil agent --jwt-auth-mount jwt --jwt-role basil-spiffe
//!      --jwt-audience <engine> ...`.
//!
//! The broker binding its socket already proves the login worked: startup
//! reconcile drives backend writes (generating `nats.account` + `app.aead`)
//! through the exchanged token, and that runs before the socket binds. This test
//! then makes the proof explicit by driving sign/verify + a KV read over the
//! `basil` client, every one of which authenticates to the engine with the
//! JWT-exchanged token.
//!
//! GATING: if the engine binary is not on PATH this prints an EXPLICIT skip line
//! and returns (acceptance forbids a silent `#[ignore]` skip). When present it
//! runs for real and MUST pass.
//!
//! Each leg's `VAULT_ADDR` is drawn from `basil_tests::alloc_addr()` (a process-wide
//! allocator keyed per test binary), so the `OpenBao` and Vault dev servers
//! never fight for a port and no hand-maintained literal is needed. The
//! jwt-auth provisioning is
//! engine-portable (identical jwt auth method API on bao and vault, dk5.3/dk5.10
//! proved cross-engine parity), so both legs run the same flow.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::allow_attributes
)]

use basil_tests::on_path;

use basil::Client;
use basil_tests::{Engine, alloc_addr, boot_basil_spiffe};

/// Drive one engine end to end: boot the broker on the `SpiffeSigner` path, then
/// prove the JWT-exchanged token serves real broker ops.
async fn drive_engine(engine: Engine, tag: &str, addr: &str) {
    // boot_basil_spiffe only returns once the socket binds: i.e. the broker has
    // ALREADY self-minted a JWT-SVID, exchanged it at auth/jwt/login for a backend
    // token, and run the startup reconcile (which writes nats.account + app.aead
    // through that token). So merely getting here proves the login flow works.
    let harness = boot_basil_spiffe(tag, engine, addr, None);
    let socket = harness.socket();
    let socket_str = socket.to_str().expect("socket path is UTF-8");

    let mut client = Client::connect(socket_str)
        .await
        .expect("connect basil client to the SpiffeSigner-booted broker");

    // status round-trip, the broker reports the spiffe-vault backend label, which
    // is only reachable because the JWT-SVID login produced a usable token.
    let status = client.status().await.expect("broker status round-trip");
    assert_eq!(
        status.backend, "spiffe-vault",
        "broker booted on the SpiffeSigner (spiffe-vault) backend path (got {})",
        status.backend
    );
    eprintln!(
        "SPIFFE-LOGIN[{}]: broker up; backend={} version={}",
        engine.prefill_name(),
        status.backend,
        status.version
    );

    // sign + verify over the pre-filled transit key: every transit call carries
    // the JWT-exchanged backend token. A correct payload verifies true; a tampered
    // one verifies false, proving the token authorizes real signing operations.
    let key = "web.tls.signing_key";
    let message = b"basil-dk5.4 spiffe-jwt-login proof";
    let signature = client
        .sign(key, message)
        .await
        .expect("sign via the JWT-exchanged token");
    assert!(!signature.is_empty(), "signature is non-empty");

    let ok = client
        .verify(key, message, &signature)
        .await
        .expect("verify via the JWT-exchanged token");
    assert!(ok, "the broker's own signature verifies true");

    let tampered = client
        .verify(key, b"a different message", &signature)
        .await
        .expect("verify (tampered) via the JWT-exchanged token");
    assert!(
        !tampered,
        "a signature over a different message verifies false"
    );

    // a KV read through the same token: the pre-filled app.db_password value the
    // policy grants the running uid `reader` over. Proves a non-signing engine
    // path (kv-v2) also rides the JWT-exchanged token.
    let secret = client
        .get_secret("app.db_password", None)
        .await
        .expect("get_secret via the JWT-exchanged token");
    assert_eq!(
        secret.value, b"prefilled-db-pa55",
        "the pre-filled kv-v2 value round-trips through the SpiffeSigner backend"
    );
    // Close the client connection before tearing the broker down (tightens the
    // client's significant Drop to its last use).
    drop(client);

    eprintln!(
        "SPIFFE-LOGIN[{}]: sign/verify + kv read OK via JWT-exchanged token",
        engine.prefill_name()
    );

    // harness Drop tears down the agent + dev server + temp dir.
    drop(harness);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spiffe_signer_boot_openbao() {
    if !on_path("bao") {
        eprintln!("SKIP: bao not found on PATH; SpiffeSigner boot e2e needs a live engine");
        return;
    }
    drive_engine(Engine::OpenBao, "spiffe-jwt-login-bao", &alloc_addr()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spiffe_signer_boot_vault() {
    if !on_path("vault") {
        eprintln!("SKIP: vault not found on PATH; SpiffeSigner boot e2e needs a live engine");
        return;
    }
    drive_engine(Engine::Vault, "spiffe-jwt-login-vault", &alloc_addr()).await;
}
