// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! A web service that issues signed JWTs **without ever holding the signing
//! key**. Your app can't leak a key it never held.
//!
//! The service asks the local Basil broker to mint each token; the Ed25519
//! key lives in Basil's backend and signs in place. Basil attests THIS
//! process by its kernel-verified identity (`SO_PEERCRED` uid), and policy
//! grants it exactly two operations on `web.signing_key`: `mint` and
//! `get_public_key`. There is no key in this process, its environment, or
//! its config to steal. `run.sh` shows that even a plain read of the same
//! key under the same uid is denied.

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use basil::Client;

/// Catalog id of the signing key. The service knows the key's NAME only;
/// the material never crosses the socket.
const SIGNING_KEY: &str = "web.signing_key";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Where the Basil agent listens; injected by the environment (run.sh, a
    // systemd unit, a pod spec). This socket path is the service's ONLY
    // crypto wiring: no key file, no secret env var.
    let socket = std::env::var("BASIL_SOCKET")?;
    let bind = std::env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8095".into());

    // One broker client shared across requests. It multiplexes a single gRPC
    // channel and is cheap to clone, so it doubles as the axum state.
    let client = Client::connect(&socket).await?;

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/token", post(mint_token))
        .with_state(client);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    println!("listening on http://{bind} (broker: {socket})");
    axum::serve(listener, app).await?;
    Ok(())
}

/// `POST /token`: mint a short-lived JWT for the caller.
///
/// The broker builds and signs the token in place and returns only the
/// compact JWT. Policy, not application code, decides whether this process
/// may mint under `web.signing_key`.
async fn mint_token(State(mut client): State<Client>) -> Result<String, (StatusCode, String)> {
    let minted = client
        .mint_jwt(
            SIGNING_KEY,
            "web-service-axum-demo",              // the JWT `sub` claim
            Some(300),                            // 5-minute TTL: expires on its own
            serde_json::json!({"scope": "demo"}), // extra, non-reserved claims
        )
        .await
        // Any broker refusal (policy deny, unknown key, agent down) surfaces
        // as a plain 502: the service has no fallback key to sign with.
        .map_err(|err| (StatusCode::BAD_GATEWAY, format!("mint refused: {err}")))?;
    Ok(minted.token)
}
