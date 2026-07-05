// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! LIVE cross-engine e2e for JWT-SVID revocation (basil-4gcn).
//!
//! Unit coverage already proves the deny-list store in isolation
//! (`core/revocation.rs`) and that an authorized `Revoke` publishes a `Revoked`
//! event (`service/admin.rs`). What was missing is the END-TO-END loop against a
//! live broker: mint a real JWT-SVID, prove it verifies, revoke it over the admin
//! socket, and prove the SAME token is then REJECTED by the verification path.
//!
//! This test ties that loop together over the SPIFFE Workload API + the broker
//! admin socket:
//!   1. `FetchJWTSVID` mints an RS256 JWT-SVID (via the shared `fetch_jwt_svid`
//!      harness helper), and we decode its `jti` (the deny-list key).
//!   2. `ValidateJWTSVID` accepts the fresh token (returns its SPIFFE id).
//!   3. `basil::Client::revoke(trust_domain, jti, exp)` adds it to the deny-list;
//!      the receipt reports `persisted = true` (the prefill now configures a
//!      `revocation_store=jwt-svid` value key at `spiffe.jwt_revocations`, and the
//!      running uid holds the `op:revoke` grant over `broker.revoke`).
//!   4. `ValidateJWTSVID` on the SAME token now FAILS: the verification path
//!      reflects the revocation.
//!
//! GATING: each engine leg is gated on its CLI (`bao`/`vault`) being on PATH; an
//! absent engine prints an EXPLICIT skip line, and `ran_any` fails an all-absent
//! environment loudly. Each leg draws a disjoint dev-server `addr` from
//! `alloc_addr()`.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::significant_drop_tightening,
    clippy::too_many_lines
)]

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tonic::Request;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

use basil_proto::spiffe::ValidateJwtsvidRequest;
use basil_proto::spiffe::spiffe_workload_api_client::SpiffeWorkloadApiClient;

use basil_tests::{Engine, TRUST_DOMAIN, alloc_addr, boot_basil_spiffe, fetch_jwt_svid, on_path};

/// Audience the SVID is minted for and validated against (caller-chosen; the
/// broker mints and validates against whatever audience the workload requests).
const AUDIENCE: &str = "revocation-e2e";

/// Attach the mandatory `workload.spiffe.io: true` metadata header the raw tonic
/// Workload API client does not send automatically (the server fail-closes without
/// it). The high-level `spiffe` client sets it; the raw client is used here so we
/// can drive `ValidateJWTSVID`, which the high-level client does not expose.
fn workload_request<T>(msg: T) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut().insert(
        "workload.spiffe.io",
        "true".parse().expect("static metadata value"),
    );
    req
}

/// A raw tonic channel over Basil's unix socket (the same connector shape the
/// `basil` client uses), so the generated SPIFFE client speaks to the live agent.
async fn uds_channel(path: std::path::PathBuf) -> Channel {
    Endpoint::try_from("http://[::]:50051")
        .expect("static endpoint")
        .connect_with_connector(service_fn(move |_: Uri| {
            let path = path.clone();
            async move { UnixStream::connect(path).await.map(TokioIo::new) }
        }))
        .await
        .expect("connect raw tonic channel to Basil unix socket")
}

/// Decode the `jti` claim out of a compact JWT WITHOUT verifying it: the broker
/// keys its deny-list on this exact `(trust_domain, jti)` tuple.
fn jti_of(token: &str) -> String {
    let payload = token.split('.').nth(1).expect("jwt has a claims segment");
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .expect("claims segment is base64url");
    let claims: serde_json::Value = serde_json::from_slice(&bytes).expect("claims are JSON");
    claims
        .get("jti")
        .and_then(serde_json::Value::as_str)
        .expect("JWT-SVID carries a jti")
        .to_string()
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

async fn run_engine(engine: Engine) {
    let addr = alloc_addr();
    let harness = boot_basil_spiffe(
        &format!("jwtrevoke-{}", engine.prefill_name()),
        engine,
        &addr,
        None,
    );
    let endpoint = harness.endpoint();
    let socket = harness.socket();

    // 1. Mint a JWT-SVID over the Workload API and pull out its jti.
    let token = fetch_jwt_svid(&endpoint, AUDIENCE).await;
    let jti = jti_of(&token);

    // 2. It validates cleanly BEFORE revocation.
    let mut workload = SpiffeWorkloadApiClient::new(uds_channel(socket.clone()).await);
    let ok = workload
        .validate_jwtsvid(workload_request(ValidateJwtsvidRequest {
            audience: AUDIENCE.to_string(),
            svid: token.clone(),
        }))
        .await
        .expect("fresh JWT-SVID validates before revocation")
        .into_inner();
    assert!(
        !ok.spiffe_id.is_empty(),
        "validation returns the SPIFFE id for the fresh token"
    );

    // 3. Revoke it by (trust_domain, jti) over the broker admin socket.
    let socket_str = socket.to_str().expect("utf-8 socket path");
    let mut admin = basil::Client::connect(socket_str)
        .await
        .expect("connect basil admin client");
    let receipt = admin
        .revoke(TRUST_DOMAIN, &jti, now_unix().saturating_add(3600))
        .await
        .expect("revoke JWT-SVID succeeds (op:revoke granted + store configured)");
    assert_eq!(receipt.jti, jti, "receipt echoes the revoked jti");
    assert_eq!(receipt.trust_domain, TRUST_DOMAIN);
    assert!(
        receipt.persisted,
        "revocation persisted to the configured revocation_store=jwt-svid value key"
    );

    // 4. The SAME token is now REJECTED by the verification path: the deny-list
    //    is consulted on every ValidateJWTSVID.
    let denied = workload
        .validate_jwtsvid(workload_request(ValidateJwtsvidRequest {
            audience: AUDIENCE.to_string(),
            svid: token.clone(),
        }))
        .await;
    assert!(
        denied.is_err(),
        "revoked JWT-SVID must be rejected after revocation (was accepted)"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn jwt_svid_revocation_denies_after_revoke_cross_engine() {
    let mut ran_any = false;
    for engine in [Engine::OpenBao, Engine::Vault] {
        if !on_path(engine.cli_bin()) {
            eprintln!(
                "SKIP jwt-svid revocation e2e for {}: {} not on PATH",
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
        "no engine CLI (bao/vault) on PATH; JWT-SVID revocation e2e ran vacuously"
    );
}
