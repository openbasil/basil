//! External-consumer interop test (basil-dk5.11).
//!
//! Proves the STANDARD Rust SPIFFE client crate (`spiffe`, aka rust-spiffe)
//! works UNMODIFIED against a live Basil Workload API unix socket. We boot a
//! real Basil agent over a pre-filled `OpenBao` store and drive it with the
//! public `spiffe` client API only: no Basil-specific SPIFFE client, no
//! vendored rust-spiffe logic.
//!
//! Live test: it shells out to `scripts/prefill-test-store.sh` (which boots a
//! dev `bao`, writes fixtures + a sealed `AppRole` bundle) and then runs
//! `target/debug/basil run` on a temp socket. The default feature set
//! includes `spiffe`, so the Workload API is served on the same socket as the
//! broker.
//!
//! GATING: if `bao` is not on PATH this prints an EXPLICIT skip line and
//! returns (the acceptance forbids a silent `#[ignore]` skip). When `bao` is
//! present it runs for real and MUST pass.
//!
//! The live boot harness (`boot_basil`, `Harness`, `repo_root`, `on_path`) lives
//! in `tests/common/mod.rs` so the wire-compat test (`spiffe_wire_compat.rs`)
//! reuses the SAME boot path instead of a second parallel harness.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::allow_attributes
)]

use basil_tests::{Engine, TRUST_DOMAIN, alloc_addr, boot_basil, on_path};
use spiffe::{JwtSourceBuilder, WorkloadApiClient, X509SourceBuilder};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rust_spiffe_client_interops_with_basil_workload_api() {
    if !on_path("bao") {
        eprintln!("SKIP: bao not found on PATH; SPIFFE interop needs a live engine");
        return;
    }

    let harness = boot_basil("spiffe-interop", Engine::OpenBao, &alloc_addr());
    // The standard SPIFFE endpoint string a Rust workload would put in
    // SPIFFE_ENDPOINT_SOCKET. We pass it to `connect_to` directly (equivalent to
    // `connect_env()` after `set_var`), avoiding the forbidden `unsafe` set_var.
    let endpoint = harness.endpoint();

    // ---- 1) WorkloadApiClient (the standard one-shot client) ----------------
    let client = WorkloadApiClient::connect_to(&endpoint)
        .await
        .expect("WorkloadApiClient::connect_to against Basil");

    // X.509 context -> default SVID in trust domain example.org, non-empty chain.
    let ctx = client
        .fetch_x509_context()
        .await
        .expect("fetch_x509_context");
    let svid = ctx
        .default_svid()
        .expect("X.509 context has a default SVID");
    let issued_id = svid.spiffe_id().to_string();
    assert_eq!(
        svid.spiffe_id().trust_domain_name(),
        TRUST_DOMAIN,
        "default SVID is in the configured trust domain (got {issued_id})"
    );
    assert!(
        !svid.cert_chain().is_empty(),
        "default SVID cert chain is non-empty"
    );
    eprintln!("INTEROP: Basil issued X.509-SVID id = {issued_id}");

    // fetch_x509_svid directly, too.
    let direct = client.fetch_x509_svid().await.expect("fetch_x509_svid");
    let direct_id = direct.spiffe_id().to_string();
    assert!(
        direct_id.starts_with("spiffe://example.org/"),
        "direct X.509-SVID is a SPIFFE ID in example.org (got {direct_id})"
    );

    // X.509 bundles -> non-empty bundle set.
    let x509_bundles = client
        .fetch_x509_bundles()
        .await
        .expect("fetch_x509_bundles");
    assert!(
        !x509_bundles.is_empty(),
        "X.509 bundle set is non-empty (len {})",
        x509_bundles.len()
    );

    // JWT-SVID for an audience -> a non-empty token. The client method takes an
    // optional explicit SPIFFE ID; None => the default (templated) identity.
    let jwt = client
        .fetch_jwt_svid(["my-audience"], None)
        .await
        .expect("fetch_jwt_svid");
    assert!(!jwt.token().is_empty(), "JWT-SVID token is non-empty");
    assert_eq!(
        jwt.spiffe_id().trust_domain_name(),
        TRUST_DOMAIN,
        "JWT-SVID is in the configured trust domain"
    );

    // JWT bundles -> non-empty JWKS bundle set.
    let jwt_bundles = client.fetch_jwt_bundles().await.expect("fetch_jwt_bundles");
    assert!(
        !jwt_bundles.is_empty(),
        "JWT bundle set is non-empty (len {})",
        jwt_bundles.len()
    );

    // ---- 2) X509Source / JwtSource (the streaming watchers) -----------------
    let x509_source = X509SourceBuilder::new()
        .endpoint(&endpoint)
        .build()
        .await
        .expect("X509Source builds against Basil");
    let source_svid = x509_source
        .svid()
        .expect("X509Source observes an initial SVID");
    assert_eq!(
        source_svid.spiffe_id().trust_domain_name(),
        TRUST_DOMAIN,
        "X509Source SVID is in the configured trust domain"
    );
    let source_bundles = x509_source
        .bundle_set()
        .expect("X509Source observes an initial bundle set");
    assert!(
        !source_bundles.is_empty(),
        "X509Source bundle set is non-empty"
    );

    let jwt_source = JwtSourceBuilder::new()
        .endpoint(&endpoint)
        .build()
        .await
        .expect("JwtSource builds against Basil");
    let jwt_source_svid = jwt_source
        .fetch_jwt_svid(["my-audience"])
        .await
        .expect("JwtSource fetches a JWT-SVID");
    assert!(
        !jwt_source_svid.token().is_empty(),
        "JwtSource JWT-SVID token is non-empty"
    );
    let jwt_source_bundles = jwt_source
        .bundle_set()
        .expect("JwtSource observes an initial JWT bundle set");
    assert!(
        !jwt_source_bundles.is_empty(),
        "JwtSource bundle set is non-empty"
    );

    // harness Drop tears down the agent + dev server + temp dir.
    drop(harness);
}
