//! Cross-engine LIVE-crypto e2e for ECDSA P-384 (ES384) and P-521 (ES512) over
//! the broker gRPC, on BOTH a dev `OpenBao` AND a dev `Vault` store (basil-0jkw).
//!
//! The unit layer is solid but MOCK-backed: `manager.rs`
//! `ecdsa_p384_sign_and_verify_use_es384_transit_options` /
//! `ecdsa_p521_sign_and_verify_use_es512_transit_options` only assert the
//! `SignOptions` handed to a mock backend: no REAL ES384/ES512 signature is ever
//! produced or verified against a live transit engine, and no P-384/P-521 key is
//! generated against a real backend. THIS file closes that live-crypto gap.
//!
//! What the harness sets up (see `scripts/prefill-test-store.sh` +
//! `basil_tests::boot_basil`): the backend declares `ecdsa-p384`/`ecdsa-p521` in
//! `mintKeyTypes`; the catalog carries `ecdsa.p384` + `ecdsa.p521` (transit,
//! absent at boot, `missing=generate`, `writable=true`): startup reconcile
//! LIVE-generates each transit key at its catalog path; the running uid holds
//! `role:signer` + `role:minter` + `op:new_key` over both.
//!
//! On each engine the test, driving the `basil` client over the broker's unix
//! socket:
//!   (P-384)
//!     1. confirms the catalog key exists (reconcile LIVE-generated it at boot)
//!        via `GetPublicKey`, and separately exercises the request-time `NewKey`
//!        RPC for the curve (a fresh, distinct backend-generated P-384 key);
//!     2. does a REAL ES384 transit sign/verify round-trip (raw 96-byte JOSE
//!        signature), and asserts the broker rejects a tampered message;
//!     3. mints an ES384 JWT via the generic `MintJwt` path and INDEPENDENTLY
//!        verifies it with the `jsonwebtoken` crate (`Algorithm::ES384`) using the
//!        key's `SubjectPublicKeyInfo` fetched via `GetPublicKey`, proving the
//!        curve/alg is genuinely exercised, not skipped.
//!   (P-521)
//!     4. confirms the reconcile-generated catalog key + a fresh `NewKey` P-521 key;
//!     5. does a REAL ES512 transit sign/verify round-trip (raw 132-byte JOSE
//!        signature) + a tampered-message rejection;
//!     6. asserts `MintJwt` FAILS CLOSED on P-521: ES512 is not a SPIFFE JWT-SVID
//!        profile alg and the Rust verifier stack cannot validate it, so the
//!        generic JWT path must refuse it rather than emit a mistyped token.
//!
//! GATING: each engine leg is independently gated on its CLI (`bao`/`vault`)
//! being on PATH; an absent engine prints an EXPLICIT skip line (acceptance
//! forbids a silent `#[ignore]`). `ran_any` asserts at least one leg ran, so an
//! all-absent environment FAILS loudly rather than passing vacuously.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::allow_attributes,
    clippy::indexing_slicing
)]

use basil_tests::{Engine, alloc_addr, boot_basil, on_path};

use basil::{Client, KeyType};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};

/// Wrap an EC `SubjectPublicKeyInfo` (the format `GetPublicKey` returns for a
/// transit ECDSA key: PEM from the engine, occasionally raw DER) into a
/// `jsonwebtoken` decoding key. `from_ec_pem` parses the SPKI and extracts the
/// EC point, so a DER SPKI is re-wrapped into PEM first.
fn ec_decoding_key(spki: &[u8]) -> DecodingKey {
    if spki.starts_with(b"-----BEGIN") {
        DecodingKey::from_ec_pem(spki).expect("EC SubjectPublicKeyInfo PEM")
    } else {
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            B64.encode(spki)
        );
        DecodingKey::from_ec_pem(pem.as_bytes()).expect("EC SubjectPublicKeyInfo (DER->PEM)")
    }
}

/// Flip the first char of a compact JWS signature segment so the signature no
/// longer validates while the header/claims stay intact.
fn tamper_jwt_signature(token: &str) -> String {
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(
        parts.len(),
        3,
        "a compact JWS has three dot-separated parts"
    );
    let sig = parts[2];
    assert!(!sig.is_empty(), "JWS signature segment is non-empty");
    let mut chars = sig.chars();
    let first = chars.next().expect("non-empty signature has a first char");
    let replacement = if first == 'A' { 'B' } else { 'A' };
    let flipped: String = std::iter::once(replacement).chain(chars).collect();
    format!("{}.{}.{}", parts[0], parts[1], flipped)
}

/// Real ES384 sign/verify + ES384 JWT mint/verify against the live backend.
async fn drive_p384(engine: Engine, client: &mut Client) {
    const KEY: &str = "ecdsa.p384";
    let eng = engine.prefill_name();

    // (1) The catalog key was LIVE-generated at boot by startup reconcile
    //     (missing=generate -> create_named_key type=ecdsa-p384). GetPublicKey
    //     succeeding proves the transit key exists at its catalog path.
    let pubresp = client
        .get_public_key(KEY, None)
        .await
        .expect("GetPublicKey for the reconcile-generated P-384 key");
    assert!(
        !pubresp.public_key.is_empty(),
        "[{eng}] GetPublicKey returns the P-384 SubjectPublicKeyInfo"
    );

    // Separately exercise the request-time NewKey RPC for the curve: the backend
    // generates a FRESH P-384 key (backend-assigned id), distinct from the catalog
    // key: a second, explicit proof of live P-384 generation against the backend.
    let handle = client
        .new_key(KEY, KeyType::EcdsaP384)
        .await
        .expect("NewKey generates a fresh P-384 key against the live backend");
    assert!(
        !handle.public_key.is_empty(),
        "[{eng}] NewKey returns a P-384 public key"
    );
    assert_ne!(
        handle.public_key, pubresp.public_key,
        "[{eng}] NewKey generated a fresh P-384 key distinct from the catalog key"
    );

    // (2) Real ES384 transit sign/verify round-trip (raw JOSE r||s = 96 bytes).
    let message = b"basil-0jkw ES384 live sign/verify";
    let signature = client
        .sign(KEY, message)
        .await
        .expect("real ES384 sign via the live transit engine");
    assert_eq!(
        signature.len(),
        96,
        "[{eng}] ES384 raw JOSE signature is 96 bytes (P-384 r||s), got {}",
        signature.len()
    );
    assert!(
        client
            .verify(KEY, message, &signature)
            .await
            .expect("broker verify of its own ES384 signature"),
        "[{eng}] live ES384 verify accepts the broker's own signature"
    );
    assert!(
        !client
            .verify(KEY, b"a different message", &signature)
            .await
            .expect("broker verify of a tampered ES384 message"),
        "[{eng}] live ES384 verify rejects a signature over a different message"
    );

    // (3) Mint an ES384 JWT via the generic MintJwt path and INDEPENDENTLY verify
    //     it with jsonwebtoken (Algorithm::ES384) off the key's SPKI.
    let minted = client
        .mint_jwt(
            KEY,
            "spiffe://example.org/es384-workload",
            Some(600),
            serde_json::json!({ "scope": "es384-e2e" }),
        )
        .await
        .expect("mint an ES384 JWT over the live P-384 key");
    let header = decode_header(&minted.token).expect("decode minted JWT header");
    assert_eq!(
        header.alg,
        Algorithm::ES384,
        "[{eng}] generic MintJwt over a P-384 key stamps alg=ES384 (got {:?})",
        header.alg
    );

    let decoding_key = ec_decoding_key(&pubresp.public_key);
    let mut validation = Validation::new(Algorithm::ES384);
    validation.validate_aud = false;
    validation.set_required_spec_claims(&["exp", "sub"]);
    let claims = decode::<serde_json::Value>(&minted.token, &decoding_key, &validation)
        .expect("ES384 JWT validates against the key's SPKI with an independent verifier");
    assert_eq!(
        claims
            .claims
            .get("scope")
            .and_then(serde_json::Value::as_str),
        Some("es384-e2e"),
        "[{eng}] the verified ES384 JWT carries the caller claim"
    );

    // A signature-tampered ES384 JWT MUST NOT validate: proves the verifier
    // checks the ES384 signature, not just structural shape.
    let tampered = tamper_jwt_signature(&minted.token);
    assert!(
        decode::<serde_json::Value>(&tampered, &decoding_key, &validation).is_err(),
        "[{eng}] a signature-tampered ES384 JWT is rejected"
    );

    eprintln!(
        "ECDSA-E2E[{eng}]: P-384 generated + ES384 sign/verify + ES384 JWT independently verified"
    );
}

/// Real ES512 sign/verify against the live backend, plus proof that the generic
/// JWT path fails closed on P-521 (ES512 is not a JWT-SVID profile alg).
async fn drive_p521(engine: Engine, client: &mut Client) {
    const KEY: &str = "ecdsa.p521";
    let eng = engine.prefill_name();

    // (4) The catalog key was LIVE-generated at boot (missing=generate ->
    //     create_named_key type=ecdsa-p521); GetPublicKey confirms it exists.
    let pubresp = client
        .get_public_key(KEY, None)
        .await
        .expect("GetPublicKey for the reconcile-generated P-521 key");
    assert!(
        !pubresp.public_key.is_empty(),
        "[{eng}] GetPublicKey returns the P-521 SubjectPublicKeyInfo"
    );

    // Exercise the request-time NewKey RPC for the curve: a fresh backend-generated
    // P-521 key, distinct from the catalog key.
    let handle = client
        .new_key(KEY, KeyType::EcdsaP521)
        .await
        .expect("NewKey generates a fresh P-521 key against the live backend");
    assert!(
        !handle.public_key.is_empty(),
        "[{eng}] NewKey returns a P-521 public key"
    );
    assert_ne!(
        handle.public_key, pubresp.public_key,
        "[{eng}] NewKey generated a fresh P-521 key distinct from the catalog key"
    );

    // (5) Real ES512 transit sign/verify round-trip (raw JOSE r||s = 132 bytes).
    let message = b"basil-0jkw ES512 live sign/verify";
    let signature = client
        .sign(KEY, message)
        .await
        .expect("real ES512 sign via the live transit engine");
    assert_eq!(
        signature.len(),
        132,
        "[{eng}] ES512 raw JOSE signature is 132 bytes (P-521 r||s), got {}",
        signature.len()
    );
    assert!(
        client
            .verify(KEY, message, &signature)
            .await
            .expect("broker verify of its own ES512 signature"),
        "[{eng}] live ES512 verify accepts the broker's own signature"
    );
    assert!(
        !client
            .verify(KEY, b"a different message", &signature)
            .await
            .expect("broker verify of a tampered ES512 message"),
        "[{eng}] live ES512 verify rejects a signature over a different message"
    );

    // (6) The generic MintJwt path has no ES512/P-521 JWT-SVID profile alg, so it
    //     MUST fail closed rather than emit a mistyped token.
    let jwt = client
        .mint_jwt(
            KEY,
            "spiffe://example.org/es512-workload",
            Some(600),
            serde_json::Value::Null,
        )
        .await;
    assert!(
        jwt.is_err(),
        "[{eng}] MintJwt over a P-521 key must fail closed (ES512 is not a JWT profile alg)"
    );

    eprintln!(
        "ECDSA-E2E[{eng}]: P-521 generated + ES512 sign/verify round-trip; MintJwt fails closed on ES512"
    );
}

/// Drive one engine end to end for both curves.
async fn drive_engine(engine: Engine, tag: &str, addr: &str) {
    let harness = boot_basil(tag, engine, addr);
    let socket = harness.socket();
    let socket_str = socket.to_str().expect("socket path is UTF-8");

    let mut client = Client::connect(socket_str)
        .await
        .expect("connect basil client to the broker socket");

    drive_p384(engine, &mut client).await;
    drive_p521(engine, &mut client).await;

    drop(client);
    drop(harness);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ecdsa_p384_p521_live_crypto_cross_engine() {
    let ran_bao = if on_path("bao") {
        drive_engine(Engine::OpenBao, "ecdsa-hc-bao", &alloc_addr()).await;
        true
    } else {
        eprintln!(
            "SKIP: bao not found on PATH; ECDSA P-384/P-521 live-crypto e2e needs a live OpenBao"
        );
        false
    };

    let ran_vault = if on_path("vault") {
        drive_engine(Engine::Vault, "ecdsa-hc-vault", &alloc_addr()).await;
        true
    } else {
        eprintln!(
            "SKIP: vault not found on PATH; ECDSA P-384/P-521 live-crypto e2e needs a live Vault"
        );
        false
    };

    assert!(
        ran_bao || ran_vault,
        "neither bao nor vault was on PATH; the ECDSA P-384/P-521 live-crypto e2e ran no engine \
         leg (this is a live cross-engine acceptance test; it must not pass vacuously)"
    );
}
