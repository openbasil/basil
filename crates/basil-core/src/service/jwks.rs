// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The JWKS + OIDC-discovery HTTP surface (`basil-uce.1`, `basil-uce.2`).
//!
//! This is the **first and only** HTTP endpoint in an otherwise
//! gRPC-over-unix-socket, peer-cred-attested broker, so it is **strictly
//! opt-in**: the listener is bound only when the operator sets `[jwks] enable =
//! true` in the daemon config (default `false`: no port is opened). See
//! [`serve`] and the `run_daemon` wiring in `main.rs`.
//!
//! The endpoint serves a standard RFC 7517 JSON Web Key Set built from the
//! **public** halves of the configured JWT-SVID issuer keys: the same keys,
//! `kid`s, and `alg`s the SPIFFE Workload API publishes (both reuse the shared
//! [`crate::minter::jwt_svid_jwks_grace`] generator, so the two surfaces never
//! diverge). **No private or secret material can reach this surface by
//! construction**: the handler only ever reads the **public** halves
//! ([`crate::backend::Backend::public_keys`]) and serializes the public
//! modulus/exponent. The endpoint is unauthenticated, which is correct for a JWKS:
//! a JWKS is meant to be world-readable, and it serves public keys only.
//!
//! The JWK set is cached briefly per generation after it is built from the live
//! backend manager and reflects the **rotation grace window**: one JWK per issuer
//! key version still inside `[grace_floor ..= latest]`, so a verifier can
//! validate a token signed by a recently rotated-away version, and a version is
//! dropped once it falls below the floor (`basil-uce.2`).
//!
//! When an `issuer` (public base URL) is configured, the OIDC discovery document
//! is served at [`OIDC_DISCOVERY_PATH`] with a `jwks_uri` consistent with
//! `issuer` and the JWKS path. Basil-minted JWT-SVIDs carry a **SPIFFE** `iss`
//! (`spiffe://<trust domain>`), so a verifier keyed off the discovery document
//! validates the **signature + `kid` + `aud`** and does **not** assert `iss`
//! against `issuer`. See [`discovery_document`].

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use sha2::{Digest as _, Sha256};
use tracing::{info, warn};

use crate::catalog::{Class, KeyAlgorithm};
use crate::core::catalog::schema::KeyEntry;
use crate::minter::{SvidAlg, jwt_svid_jwks_grace};
use crate::state::BrokerState;

/// `Content-Type` for a JSON Web Key Set (RFC 7517 §8.5.1).
const JWKS_CONTENT_TYPE: &str = "application/jwk-set+json";

/// `Cache-Control` max-age for the JWKS document, in seconds.
///
/// Five minutes balances rotation freshness against load: a rotated issuer's new
/// `kid` is picked up by verifiers within this window, while ordinary verifiers
/// avoid re-fetching on every token. The document is also `ETag`-tagged so a
/// conditional refetch is cheap.
const JWKS_MAX_AGE_SECS: u32 = 300;

/// The conventional JWKS path (the `jwks_uri` the discovery doc advertises).
pub const JWKS_PATH: &str = "/jwks.json";

/// The well-known JWKS path, served identically.
pub const JWKS_WELL_KNOWN_PATH: &str = "/.well-known/jwks.json";

/// The OIDC discovery document path (`RFC 8414` / `OpenID` Connect Discovery).
pub const OIDC_DISCOVERY_PATH: &str = "/.well-known/openid-configuration";

/// `Content-Type` for the OIDC discovery document (a plain JSON object).
const OIDC_CONTENT_TYPE: &str = "application/json";

/// JWS algorithms this build can mint and validate for JWT-SVID issuer keys.
const ID_TOKEN_SIGNING_ALGS_SUPPORTED: [&str; 3] = ["RS256", "ES256", "ES384"];

/// Resolved HTTP-surface settings beyond the bind address: currently the OIDC
/// discovery `issuer` (public base URL). Cheap to clone into the axum state.
///
/// When `issuer` is `None` the `/.well-known/openid-configuration` route is not
/// mounted (the bare JWKS endpoints are always served). This keeps the discovery
/// document honest: it is only published when the operator has told the broker the
/// public URL it is reachable at, so `issuer`/`jwks_uri` are real and consistent.
#[derive(Debug, Clone, Default)]
pub struct JwksHttpConfig {
    /// Public base URL the surface is reachable at (no trailing slash).
    pub issuer: Option<String>,
    /// Optional native TLS configuration for direct HTTPS exposure.
    pub tls: Option<JwksTlsConfig>,
}

/// Native rustls settings for the opt-in JWKS listener.
#[derive(Debug, Clone, Default)]
pub struct JwksTlsConfig {
    /// PEM certificate chain file served by the JWKS listener.
    pub cert_file: PathBuf,
    /// PEM private key file served by the JWKS listener.
    pub key_file: PathBuf,
}

/// The axum state shared by the JWKS + discovery handlers: the broker state plus
/// the resolved HTTP config (the discovery `issuer`).
#[derive(Clone)]
struct HttpState {
    broker: Arc<BrokerState>,
    config: Arc<JwksHttpConfig>,
}

/// Build the read-only JWKS + OIDC-discovery router over the shared broker state.
///
/// Both [`JWKS_PATH`] and [`JWKS_WELL_KNOWN_PATH`] serve the same JWK set. When
/// `config.issuer` is set, [`OIDC_DISCOVERY_PATH`] serves the OIDC discovery
/// document; with no issuer that route is omitted. The router is `GET`-only; any
/// other method/path falls through to axum's default `405`/`404`.
pub fn router(state: Arc<BrokerState>, config: JwksHttpConfig) -> Router {
    let http = HttpState {
        broker: state,
        config: Arc::new(config),
    };
    let mut router = Router::new()
        .route(JWKS_PATH, get(jwks_handler))
        .route(JWKS_WELL_KNOWN_PATH, get(jwks_handler));
    if http.config.issuer.is_some() {
        router = router.route(OIDC_DISCOVERY_PATH, get(discovery_handler));
    }
    router.with_state(http)
}

/// Bind `listen` and serve the JWKS router until `shutdown` resolves.
///
/// A bind failure is returned as a clean `Err` (the caller turns it into a
/// fail-closed startup error); this function never panics. On `shutdown` the
/// server drains in-flight requests and returns.
///
/// # Errors
///
/// Returns an error if the TCP listener cannot bind `listen`, or if the server
/// loop terminates with an I/O error.
pub async fn serve(
    state: Arc<BrokerState>,
    listen: SocketAddr,
    config: JwksHttpConfig,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(listen).await?;
    let local = listener.local_addr().unwrap_or(listen);
    let tls = config.tls.clone();
    let scheme = if tls.is_some() { "https" } else { "http" };
    info!(addr = %local, path = JWKS_PATH, scheme, "JWKS HTTP surface listening");
    let app = router(state, config);
    let result = if let Some(tls) = tls {
        serve_tls(listener, app, tls, shutdown).await
    } else {
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown)
            .await
    };
    info!(addr = %local, "JWKS HTTP surface stopped");
    result
}

// The stub matches the real (`http-tls`) signature (both are `async` and the
// caller awaits this future unconditionally), so it never awaits; that is the
// point of the cfg-gated fail-closed stub.
#[cfg(not(feature = "http-tls"))]
#[allow(clippy::unused_async)]
async fn serve_tls(
    _listener: tokio::net::TcpListener,
    _app: Router,
    _tls: JwksTlsConfig,
    _shutdown: impl Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "jwks tls requires the http-tls cargo feature",
    ))
}

#[cfg(feature = "http-tls")]
async fn serve_tls(
    listener: tokio::net::TcpListener,
    app: Router,
    tls: JwksTlsConfig,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder;
    use hyper_util::service::TowerToHyperService;
    use tokio::sync::watch;

    let acceptor = tls_acceptor_from_files(&tls)?;
    let (signal_tx, signal_rx) = watch::channel(());
    let signal_tx = Arc::new(signal_tx);
    tokio::spawn(async move {
        shutdown.await;
        drop(signal_rx);
    });
    let (close_tx, close_rx) = watch::channel(());

    loop {
        let (tcp_stream, remote_addr) = tokio::select! {
            conn = listener.accept() => conn?,
            () = signal_tx.closed() => break,
        };
        if let Err(err) = tcp_stream.set_nodelay(true) {
            warn!(%remote_addr, %err, "could not set TCP_NODELAY on JWKS TLS connection");
        }
        let acceptor = acceptor.clone();
        let service = app.clone().into_service::<hyper::body::Incoming>();
        let signal_tx = Arc::clone(&signal_tx);
        let close_rx = close_rx.clone();
        tokio::spawn(async move {
            let Ok(tls_stream) = acceptor.accept(tcp_stream).await else {
                drop(close_rx);
                return;
            };
            let hyper_service = TowerToHyperService::new(service);
            let builder = Builder::new(TokioExecutor::new());
            let conn =
                builder.serve_connection_with_upgrades(TokioIo::new(tls_stream), hyper_service);
            tokio::pin!(conn);
            let mut signal_closed = std::pin::pin!(signal_tx.closed());
            loop {
                tokio::select! {
                    result = conn.as_mut() => {
                        if let Err(err) = result {
                            warn!(%remote_addr, %err, "JWKS TLS connection failed");
                        }
                        break;
                    }
                    () = &mut signal_closed => {
                        conn.as_mut().graceful_shutdown();
                    }
                }
            }
            drop(close_rx);
        });
    }

    drop(close_rx);
    drop(listener);
    close_tx.closed().await;
    Ok(())
}

#[cfg(feature = "http-tls")]
fn tls_acceptor_from_files(tls: &JwksTlsConfig) -> io::Result<tokio_rustls::TlsAcceptor> {
    use rustls::ServerConfig as RustlsServerConfig;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _};

    let cert_pem = std::fs::read(&tls.cert_file).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!(
                "reading jwks.tls.cert-file {}: {err}",
                tls.cert_file.display()
            ),
        )
    })?;
    let key_pem = std::fs::read(&tls.key_file).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!(
                "reading jwks.tls.key-file {}: {err}",
                tls.key_file.display()
            ),
        )
    })?;
    let certs = CertificateDer::pem_reader_iter(&mut std::io::Cursor::new(cert_pem))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("parsing jwks tls certificate chain: {err}"),
            )
        })?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "jwks.tls.cert-file did not contain a certificate",
        ));
    }
    let key =
        PrivateKeyDer::from_pem_reader(&mut std::io::Cursor::new(key_pem)).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("parsing jwks tls private key: {err}"),
            )
        })?;
    let server_config =
        RustlsServerConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_safe_default_protocol_versions()
            .map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("selecting jwks tls protocol versions: {err}"),
                )
            })?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("building jwks tls config: {err}"),
                )
            })?;
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(server_config)))
}

/// The `GET /jwks.json` handler: serialize the live issuer JWK set.
///
/// Reads the **current** set of JWT-SVID issuers off the backend manager and
/// their **public** halves fresh, so the response tracks issuer rotation. On any
/// backend error it returns `503 Service Unavailable` with a non-secret body,
/// never a panic, never any key material in the error.
async fn jwks_handler(headers: HeaderMap, State(state): State<HttpState>) -> Response {
    match cached_or_build_jwks(&state.broker).await {
        Ok(cached) => {
            if headers
                .get(header::IF_NONE_MATCH)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|tag| {
                    tag.split(',')
                        .any(|candidate| candidate.trim() == cached.etag)
                })
            {
                return (
                    StatusCode::NOT_MODIFIED,
                    [
                        (
                            header::CACHE_CONTROL,
                            format!("public, max-age={JWKS_MAX_AGE_SECS}"),
                        ),
                        (header::ETAG, cached.etag),
                    ],
                )
                    .into_response();
            }
            jwks_response(cached.body, cached.etag)
        }
        Err(reason) => {
            warn!(%reason, "JWKS request failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                "jwks temporarily unavailable\n",
            )
                .into_response()
        }
    }
}

/// The `GET /.well-known/openid-configuration` handler: serve the OIDC discovery
/// document built from the configured `issuer`.
///
/// Only mounted when an `issuer` is configured, so `config.issuer` is always
/// `Some` here; the `None` arm is a defensive `503` (never a panic). The document
/// is a static, public, cacheable JSON object: no backend I/O, no key material.
async fn discovery_handler(State(state): State<HttpState>) -> Response {
    let Some(issuer) = state.config.issuer.as_deref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            "discovery not configured\n",
        )
            .into_response();
    };
    discovery_response(&discovery_document(issuer))
}

/// Build the OIDC discovery document (a minimal, spec-valid JSON object).
///
/// `issuer` is the configured public base URL (no trailing slash). `jwks_uri` is
/// the `issuer` concatenated with [`JWKS_PATH`], so it is **consistent** with
/// `issuer` (same scheme/host/base) and points at the JWKS this same surface
/// actually serves.
///
/// Basil-minted JWT-SVIDs carry a **SPIFFE** `iss` claim (`spiffe://<trust
/// domain>`), not this URL (a SPIFFE-compatibility requirement), so a verifier
/// keyed off this document validates the **signature + `kid` + `aud`** and does
/// **not** assert `iss` against `issuer`. The discovery `issuer` exists to make
/// the document self-consistent (it is the base its own well-known path is served
/// from) and to advertise `jwks_uri`; it is not asserted against token `iss`.
fn discovery_document(issuer: &str) -> serde_json::Value {
    serde_json::json!({
        "issuer": issuer,
        "jwks_uri": format!("{issuer}{JWKS_PATH}"),
        "id_token_signing_alg_values_supported": ID_TOKEN_SIGNING_ALGS_SUPPORTED,
        // Honest minimal values: Basil mints signed JWTs, not OIDC ID tokens via
        // an authorization endpoint, but these fields are required by the spec.
        "response_types_supported": ["id_token"],
        "subject_types_supported": ["public"],
    })
}

/// The cacheable OIDC discovery response: body + `Content-Type` + `Cache-Control`
/// + a content-addressed `ETag`. A `200`.
fn discovery_response(doc: &serde_json::Value) -> Response {
    let body = serde_json::to_vec(doc).unwrap_or_else(|_| b"{}".to_vec());
    let etag = etag_for(&body);
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, OIDC_CONTENT_TYPE.to_string()),
            (
                header::CACHE_CONTROL,
                format!("public, max-age={JWKS_MAX_AGE_SECS}"),
            ),
            (header::ETAG, etag),
        ],
        body,
    )
        .into_response()
}

/// Construct the cacheable JWKS response: body + `Content-Type` + `Cache-Control`
/// + a content-addressed `ETag` (SHA-256 of the body, base16). A `200`.
fn jwks_response(body: Vec<u8>, etag: String) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, JWKS_CONTENT_TYPE.to_string()),
            (
                header::CACHE_CONTROL,
                format!("public, max-age={JWKS_MAX_AGE_SECS}"),
            ),
            (header::ETAG, etag),
        ],
        body,
    )
        .into_response()
}

async fn cached_or_build_jwks(state: &BrokerState) -> Result<crate::state::CachedJwks, String> {
    if let Some(cached) = state.cached_jwks() {
        return Ok(cached);
    }
    let generation = state.active_generation_id();
    let body = build_jwks(state).await?;
    let etag = etag_for(&body);
    state.cache_jwks(generation, body, etag);
    state
        .cached_jwks()
        .ok_or_else(|| "jwks cache unavailable".to_string())
}

/// A strong `ETag` derived from the response body (`"<hex sha256>"`).
fn etag_for(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    let mut hex = String::with_capacity(2 + digest.len() * 2 + 1);
    hex.push('"');
    for byte in digest {
        use std::fmt::Write as _;
        // Writing to a String never fails; ignore the formatter Result.
        let _ = write!(hex, "{byte:02x}");
    }
    hex.push('"');
    hex
}

/// Whether a catalog entry is a JWT-SVID **issuer** whose public key belongs in
/// the JWKS: an `Asymmetric` key labelled `svid_kind = jwt` with a SPIFFE
/// JWT-SVID profile algorithm (RSA → RS256, P-256 → ES256). This mirrors the SPIFFE service's
/// `is_jwt_svid_issuer` predicate so the JWKS and the Workload API agree on the
/// published key set. A `trust_domain` label is **not** required here: the JWKS
/// is a flat key set keyed only by `kid`, with no per-trust-domain partition.
fn is_jwks_issuer(entry: &KeyEntry) -> bool {
    entry.class == Class::Asymmetric
        && entry.labels.get("svid_kind") == Some("jwt")
        && entry
            .key_type
            .is_some_and(KeyAlgorithm::is_spiffe_jwt_svid_profile)
}

/// Map an issuer's key algorithm to its JWS `alg`. Only the SPIFFE JWT-SVID
/// profile algorithms reach here (the [`is_jwks_issuer`] filter excludes the
/// rest); a non-profile type returns `None` so it is skipped rather than panics.
const fn issuer_alg(key_type: Option<KeyAlgorithm>) -> Option<SvidAlg> {
    match key_type {
        Some(KeyAlgorithm::Rsa2048) => Some(SvidAlg::Rs256),
        Some(KeyAlgorithm::EcdsaP256) => Some(SvidAlg::Es256),
        Some(KeyAlgorithm::EcdsaP384) => Some(SvidAlg::Es384),
        _ => None,
    }
}

/// Build the combined JWK set body from every configured JWT-SVID issuer,
/// reflecting the rotation grace window.
///
/// Each issuer publishes one JWK **per key version still inside the grace
/// window** (`[grace_floor ..= latest]`) via the shared
/// [`jwt_svid_jwks_grace`] generator, the same generator the gRPC Workload-API
/// JWKS uses, so the two surfaces are byte-identical for one issuer. A
/// recently-rotated-away version stays published (a verifier can still validate a
/// token it signed) until it drops below the floor. The per-issuer sets are
/// merged into one `{"keys":[...]}`, de-duplicated by `kid` (the `kid` is
/// content-derived). An empty issuer set yields a valid empty key set
/// (`{"keys":[]}`) rather than an error.
async fn build_jwks(state: &BrokerState) -> Result<Vec<u8>, String> {
    // Snapshot the issuer (name, alg) list first so we don't hold a borrow of the
    // manager's keys across the `await` on each backend.
    let issuers: Vec<(String, SvidAlg)> = state
        .manager()
        .keys()
        .filter(|(_, entry)| is_jwks_issuer(entry))
        .filter_map(|(name, entry)| issuer_alg(entry.key_type).map(|alg| (name.clone(), alg)))
        .collect();

    let limits = state.limits();
    // Build each issuer's grace-window JWK set fresh from its backend (public
    // material only: `public_keys` returns the per-version public halves, never
    // any private material) and merge them, de-duplicated by `kid`.
    let mut keys: Vec<serde_json::Value> = Vec::with_capacity(issuers.len());
    let mut seen_kids: Vec<String> = Vec::with_capacity(issuers.len());
    for (name, alg) in issuers {
        let routed = state
            .manager()
            .resolve(&name)
            .map_err(|e| format!("resolving issuer: {e}"))?;
        let bytes = jwt_svid_jwks_grace(routed.backend, routed.path(), alg, |latest| {
            limits.grace_floor(latest)
        })
        .await
        .map_err(|e| format!("building issuer jwks: {e}"))?;
        merge_jwk_set(&bytes, &mut keys, &mut seen_kids)?;
    }

    serde_json::to_vec(&serde_json::json!({ "keys": keys }))
        .map_err(|e| format!("serializing jwks: {e}"))
}

/// Merge the JWK set `bytes` (as produced by the shared
/// [`jwt_svid_jwks_grace`] generator) into `keys`, skipping any `kid` already in
/// `seen_kids`.
fn merge_jwk_set(
    bytes: &[u8],
    keys: &mut Vec<serde_json::Value>,
    seen_kids: &mut Vec<String>,
) -> Result<(), String> {
    let parsed: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| format!("parsing jwk set: {e}"))?;
    let Some(arr) = parsed.get("keys").and_then(serde_json::Value::as_array) else {
        return Err("jwk set has no `keys` array".to_string());
    };
    for jwk in arr {
        let kid = jwk
            .get("kid")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string();
        if seen_kids.iter().any(|seen| seen == &kid) {
            continue;
        }
        seen_kids.push(kid);
        keys.push(jwk.clone());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Merge already-fetched issuer `(public_key, alg)` pairs into one JWK set
    /// body (the merge the HTTP handler does, minus the backend I/O). A test-only
    /// helper so the JWK-assembly path can be exercised against the RSA fixtures
    /// without standing up a backend manager.
    fn assemble_jwks(public_keys: &[(Vec<u8>, SvidAlg)]) -> Result<Vec<u8>, String> {
        use crate::minter::jwt_svid_jwks_from_public_key;
        let mut keys: Vec<serde_json::Value> = Vec::new();
        let mut seen_kids: Vec<String> = Vec::new();
        for (public_key, alg) in public_keys {
            let bytes = jwt_svid_jwks_from_public_key(public_key, *alg)
                .map_err(|e| format!("building jwk: {e}"))?;
            merge_jwk_set(&bytes, &mut keys, &mut seen_kids)?;
        }
        serde_json::to_vec(&serde_json::json!({ "keys": keys }))
            .map_err(|e| format!("serializing jwks: {e}"))
    }

    #[test]
    fn etag_is_quoted_hex_and_stable() {
        let a = etag_for(b"hello");
        let b = etag_for(b"hello");
        assert_eq!(a, b);
        assert!(a.starts_with('"') && a.ends_with('"'));
        assert_ne!(a, etag_for(b"world"));
        // 32-byte digest -> 64 hex chars + 2 quotes.
        assert_eq!(a.len(), 66);
    }

    #[test]
    fn merge_dedups_by_kid_and_collects() {
        let mut keys = Vec::new();
        let mut seen = Vec::new();
        let one = br#"{"keys":[{"kid":"a","kty":"RSA"}]}"#;
        let dup = br#"{"keys":[{"kid":"a","kty":"RSA"}]}"#;
        let two = br#"{"keys":[{"kid":"b","kty":"RSA"}]}"#;
        merge_jwk_set(one, &mut keys, &mut seen).expect("merge one");
        merge_jwk_set(dup, &mut keys, &mut seen).expect("merge dup");
        merge_jwk_set(two, &mut keys, &mut seen).expect("merge two");
        assert_eq!(keys.len(), 2);
        assert_eq!(seen, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn empty_issuer_set_yields_a_valid_empty_jwk_set() {
        let body = assemble_jwks(&[]).expect("assemble empty");
        let parsed: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert!(parsed["keys"].as_array().expect("keys array").is_empty());
    }

    #[test]
    fn jwks_response_carries_cache_headers_and_content_type() {
        let body = assemble_jwks(&[]).expect("assemble");
        let etag = etag_for(&body);
        let resp = jwks_response(body, etag);
        assert_eq!(resp.status(), StatusCode::OK);
        let headers = resp.headers();
        assert_eq!(
            headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some(JWKS_CONTENT_TYPE)
        );
        let cache = headers
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
            .expect("cache-control");
        assert!(cache.contains("max-age=300"), "cache-control: {cache}");
        let etag = headers
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok())
            .expect("etag");
        assert!(etag.starts_with('"') && etag.ends_with('"'));
    }

    #[cfg(feature = "http-tls")]
    #[test]
    fn jwks_tls_acceptor_builds_from_pem_files() {
        let dir = std::env::temp_dir().join(format!("basil-jwks-tls-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).expect("create temp dir");
        let cert_file = dir.join("cert.pem");
        let key_file = dir.join("key.pem");
        std::fs::write(&cert_file, include_str!("../../testdata/jwks_tls_cert.pem"))
            .expect("write cert");
        std::fs::write(&key_file, include_str!("../../testdata/jwks_tls_key.pem"))
            .expect("write key");

        let config = JwksTlsConfig {
            cert_file: cert_file.clone(),
            key_file: key_file.clone(),
        };
        tls_acceptor_from_files(&config).expect("build tls acceptor");

        std::fs::remove_file(cert_file).expect("remove cert");
        std::fs::remove_file(key_file).expect("remove key");
        std::fs::remove_dir(dir).expect("remove temp dir");
    }

    /// The acceptance bar (`basil-uce.1`): a standard `jsonwebtoken` verifier
    /// validates a **Basil-minted** JWT-SVID signature against a key parsed from
    /// the served JWKS. We build the JWKS from the issuer's RSA public half, mint
    /// a JWT-SVID through the crate's own minter, then decode the token with a
    /// `DecodingKey` reconstructed from the JWK's `n`/`e`, proving an ordinary
    /// verifier needs only the JWKS (no SPIFFE plumbing) to validate the token.
    #[tokio::test]
    #[allow(clippy::too_many_lines)] // inline RSA-backend fixture + full mint→verify loop
    async fn served_jwks_verifies_a_basil_minted_jwt_svid() {
        use async_trait::async_trait;
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use rsa::pkcs1::EncodeRsaPrivateKey as _;
        use rsa::pkcs8::{EncodePublicKey as _, LineEnding};

        use crate::backend::{Backend, BackendError, NewKey, SignOptions};
        use crate::minter::mint_svid;
        use basil_proto::KeyType;

        /// An RS256 signing backend (the same shape the minter tests use): signs
        /// the JWS signing input with the RSA private key and returns the issuer's
        /// SPKI DER public half from `public_key`.
        struct RsaBackend {
            encoding_key: jsonwebtoken::EncodingKey,
            public_der: Vec<u8>,
        }
        impl RsaBackend {
            fn rs256_sign(&self, input: &[u8]) -> Result<Vec<u8>, BackendError> {
                let b64 = jsonwebtoken::crypto::sign(
                    input,
                    &self.encoding_key,
                    jsonwebtoken::Algorithm::RS256,
                )
                .map_err(|e| BackendError::Backend(e.to_string()))?;
                URL_SAFE_NO_PAD
                    .decode(b64)
                    .map_err(|e| BackendError::Backend(e.to_string()))
            }
        }
        #[async_trait]
        impl Backend for RsaBackend {
            fn kind(&self) -> &'static str {
                "rsa-test"
            }
            async fn new_key(&self, _key_type: KeyType) -> Result<NewKey, BackendError> {
                Err(BackendError::Unsupported("new_key"))
            }
            async fn public_key(&self, _key_id: &str) -> Result<Vec<u8>, BackendError> {
                Ok(self.public_der.clone())
            }
            async fn sign(&self, _key_id: &str, input: &[u8]) -> Result<Vec<u8>, BackendError> {
                self.rs256_sign(input)
            }
            async fn sign_with_options(
                &self,
                _key_id: &str,
                input: &[u8],
                options: SignOptions,
            ) -> Result<Vec<u8>, BackendError> {
                if options != SignOptions::Rs256Pkcs1v15Sha256 {
                    return Err(BackendError::Unsupported("rsa test sign options"));
                }
                self.rs256_sign(input)
            }
            async fn verify(
                &self,
                _key_id: &str,
                _message: &[u8],
                _signature: &[u8],
            ) -> Result<bool, BackendError> {
                Err(BackendError::Unsupported("verify"))
            }
        }

        // RSA-2048 issuer (jsonwebtoken's ring backend requires >= 2048 bits).
        let mut rng = rand::thread_rng();
        let private = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
        let public = rsa::RsaPublicKey::from(&private);
        let private_pem = private.to_pkcs1_pem(LineEnding::LF).expect("pkcs1 pem");
        let public_der = public
            .to_public_key_der()
            .expect("spki der")
            .as_bytes()
            .to_vec();
        let backend = RsaBackend {
            encoding_key: jsonwebtoken::EncodingKey::from_rsa_pem(private_pem.as_bytes())
                .expect("encoding key"),
            public_der: public_der.clone(),
        };

        // Build the JWKS the HTTP surface would serve, from the public half only.
        let body = assemble_jwks(&[(public_der.clone(), SvidAlg::Rs256)]).expect("assemble jwks");
        let jwks: serde_json::Value = serde_json::from_slice(&body).expect("jwks json");
        let key = jwks["keys"]
            .as_array()
            .and_then(|a| a.first())
            .expect("one jwk");

        // The published JWK is the public RSA key with the SPIFFE-profile metadata.
        assert_eq!(key["kty"], "RSA");
        assert_eq!(key["alg"], "RS256");
        assert_eq!(key["use"], "sig");
        let jwk_kid = key["kid"].as_str().expect("kid");

        // Mint a JWT-SVID through Basil's own minter.
        let token = mint_svid(
            &backend,
            "rsa-issuer",
            "spiffe://example.org",
            SvidAlg::Rs256,
            "spiffe://example.org/db-01",
            "vault",
            Some(300),
            &serde_json::Value::Null,
        )
        .await
        .expect("mint svid");

        // The token's `kid` selects this JWK (a verifier picks the key by `kid`).
        let header = jsonwebtoken::decode_header(&token).expect("decode header");
        assert_eq!(header.kid.as_deref(), Some(jwk_kid));

        // Reconstruct a DecodingKey from the JWK's n/e (exactly what a standard
        // verifier does with a fetched JWKS) and validate the signature.
        let n = key["n"].as_str().expect("n");
        let e = key["e"].as_str().expect("e");
        let decoding_key = jsonwebtoken::DecodingKey::from_rsa_components(n, e).expect("decoding");
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_issuer(&["spiffe://example.org"]);
        validation.set_audience(&["vault"]);
        validation.set_required_spec_claims(&["exp", "iss", "sub", "aud"]);
        let data = jsonwebtoken::decode::<serde_json::Value>(&token, &decoding_key, &validation)
            .expect("verify against jwks-derived key");
        assert_eq!(data.claims["sub"], "spiffe://example.org/db-01");
    }

    #[test]
    fn discovery_document_is_consistent_and_minimal() {
        let doc = discovery_document("https://basil.example.com");
        assert_eq!(doc["issuer"], "https://basil.example.com");
        // jwks_uri MUST be issuer + the real JWKS path (same scheme/host/base).
        assert_eq!(
            doc["jwks_uri"],
            format!("https://basil.example.com{JWKS_PATH}")
        );
        let jwks_uri = doc["jwks_uri"].as_str().expect("jwks_uri str");
        assert!(
            jwks_uri.starts_with(doc["issuer"].as_str().expect("issuer str")),
            "jwks_uri must share the issuer base"
        );
        assert_eq!(
            doc["id_token_signing_alg_values_supported"],
            serde_json::json!(ID_TOKEN_SIGNING_ALGS_SUPPORTED)
        );
        let algs = doc["id_token_signing_alg_values_supported"]
            .as_array()
            .expect("alg list");
        assert!(!algs.iter().any(|alg| alg == "ES512"));
        assert!(!algs.iter().any(|alg| alg == "PS256"));
        assert!(doc["response_types_supported"].is_array());
        assert!(doc["subject_types_supported"].is_array());
    }

    #[test]
    fn discovery_response_carries_cache_headers_and_json_content_type() {
        let resp = discovery_response(&discovery_document("https://b.example"));
        assert_eq!(resp.status(), StatusCode::OK);
        let headers = resp.headers();
        assert_eq!(
            headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some(OIDC_CONTENT_TYPE)
        );
        let cache = headers
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
            .expect("cache-control");
        assert!(cache.contains("max-age=300"), "cache-control: {cache}");
        assert!(headers.get(header::ETAG).is_some());
    }

    /// Live-path tests for the REAL [`build_jwks`] + the axum handler: the
    /// issuer-**selection** seam ([`is_jwks_issuer`]/[`issuer_alg`]) and the
    /// backend fan-out, which the [`assemble_jwks`] helper above deliberately
    /// bypasses. These pin two security invariants by construction:
    ///
    /// 1. **Selection**: only an `Asymmetric` + `svid_kind=jwt` + SPIFFE-profile
    ///    key is published; value/symmetric/sealing, a non-`jwt` asymmetric key,
    ///    and a non-profile (`ed25519`) `svid_kind=jwt` key are all excluded.
    /// 2. **Public-keys-only**: the live path reads **only** [`Backend::public_keys`],
    ///    never a private/secret read (`public_key`/`kv_get`/`kv_get_secret`/
    ///    `sign`). The mock fails the test (poisons a flag and errs) on any such
    ///    call, so "no secret material reaches JWKS" is enforced, not assumed.
    mod live_path {
        use std::collections::BTreeMap;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        use async_trait::async_trait;
        use axum::body::Body;
        use axum::http::{Method, Request, StatusCode, header};
        use rsa::pkcs8::EncodePublicKey as _;
        use tower::ServiceExt as _;

        use super::super::{
            JWKS_PATH, JWKS_WELL_KNOWN_PATH, JwksHttpConfig, build_jwks, is_jwks_issuer,
            issuer_alg, router,
        };
        use crate::backend::{Backend, BackendError, NewKey};
        use crate::catalog::{Catalog, KeyAlgorithm};
        use crate::manager::BackendManager;
        use crate::minter::SvidAlg;
        use crate::state::BrokerState;
        use basil_proto::KeyType;

        const SECRET_BACKEND_ERROR: &str =
            "backend body Authorization: Bearer vault-token-s.123 -----BEGIN PRIVATE KEY-----";

        /// A public-only mock backend: `public_keys` returns a seeded
        /// version→SPKI-DER map (the only sanctioned read on the JWKS path).
        /// **Every** material-bearing read (`public_key`, `kv_get`,
        /// `kv_get_secret`, `sign`) trips `forbidden_called` and returns an error,
        /// so a test can assert the live path NEVER touched a private/secret seam.
        struct PubKeysBackend {
            /// version → SPKI-DER public-key bytes (RSA), served by `public_keys`.
            versions: BTreeMap<u32, Vec<u8>>,
            /// Count of `public_keys` calls (asserts the live path read the
            /// public map and how many issuers it fanned out to).
            public_keys_calls: AtomicUsize,
            /// Set true if ANY private/secret read was attempted. Must stay false.
            forbidden_called: AtomicBool,
            /// When true, `public_keys` errors (drives the handler's 503 arm).
            fail: bool,
        }

        impl PubKeysBackend {
            fn new(versions: BTreeMap<u32, Vec<u8>>) -> Arc<Self> {
                Arc::new(Self {
                    versions,
                    public_keys_calls: AtomicUsize::new(0),
                    forbidden_called: AtomicBool::new(false),
                    fail: false,
                })
            }

            fn failing() -> Arc<Self> {
                Arc::new(Self {
                    versions: BTreeMap::new(),
                    public_keys_calls: AtomicUsize::new(0),
                    forbidden_called: AtomicBool::new(false),
                    fail: true,
                })
            }

            fn forbidden(&self) {
                self.forbidden_called.store(true, Ordering::SeqCst);
            }
        }

        /// Box an `Arc<PubKeysBackend>` into the manager's `Box<dyn Backend>` map
        /// while the test keeps the `Arc` to inspect the call counters.
        struct Handle(Arc<PubKeysBackend>);

        #[async_trait]
        impl Backend for Handle {
            fn kind(&self) -> &'static str {
                "pubkeys-test"
            }
            async fn new_key(&self, _key_type: KeyType) -> Result<NewKey, BackendError> {
                Err(BackendError::Unsupported("new_key"))
            }
            async fn public_keys(
                &self,
                _key_id: &str,
            ) -> Result<BTreeMap<u32, Vec<u8>>, BackendError> {
                self.0.public_keys_calls.fetch_add(1, Ordering::SeqCst);
                if self.0.fail {
                    return Err(BackendError::Backend(SECRET_BACKEND_ERROR.into()));
                }
                Ok(self.0.versions.clone())
            }
            // ---- forbidden on the JWKS path: any call is a leak of intent. ----
            async fn public_key(&self, _key_id: &str) -> Result<Vec<u8>, BackendError> {
                self.0.forbidden();
                Err(BackendError::Backend(
                    "public_key must not be called".into(),
                ))
            }
            async fn kv_get(
                &self,
                _key_id: &str,
                _version: Option<u32>,
            ) -> Result<crate::backend::KvValue, BackendError> {
                self.0.forbidden();
                Err(BackendError::Backend("kv_get must not be called".into()))
            }
            async fn kv_get_secret(
                &self,
                _key_id: &str,
                _version: Option<u32>,
            ) -> Result<crate::backend::KvSecret, BackendError> {
                self.0.forbidden();
                Err(BackendError::Backend(
                    "kv_get_secret must not be called".into(),
                ))
            }
            async fn sign(&self, _key_id: &str, _message: &[u8]) -> Result<Vec<u8>, BackendError> {
                self.0.forbidden();
                Err(BackendError::Backend("sign must not be called".into()))
            }
            async fn verify(
                &self,
                _key_id: &str,
                _message: &[u8],
                _signature: &[u8],
            ) -> Result<bool, BackendError> {
                self.0.forbidden();
                Err(BackendError::Backend("verify must not be called".into()))
            }
        }

        /// A real RSA-2048 SPKI-DER public key (`jwk_for_public_key` parses it into
        /// the `n`/`e` JWK; the minter's ring backend also wants >= 2048 bits).
        fn rsa_public_der() -> Vec<u8> {
            let mut rng = rand::thread_rng();
            let private = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
            rsa::RsaPublicKey::from(&private)
                .to_public_key_der()
                .expect("spki der")
                .as_bytes()
                .to_vec()
        }

        /// Deserialize a catalog from camelCase JSON **without** the loader's
        /// validation, so a test can place keys the loader would reject at load
        /// (e.g. an `ed25519` `svid_kind=jwt` key; the loader's fail-closed
        /// guardrail is exercised in `catalog::loader`'s own tests). The selection
        /// predicate under test here lives in [`build_jwks`], not the loader.
        fn catalog_from_json(json: &str) -> Catalog {
            serde_json::from_str(json).expect("catalog json")
        }

        /// Get a real `ResolvedPolicy` + `Config` (neither is trivially
        /// `Default`-constructible) from the loader, then thread the test's own
        /// (possibly loader-rejected) catalog through `BrokerState`. `build_jwks`
        /// reads `state.manager().keys()`, which is the manager's catalog, so the
        /// manager and `BrokerState` are both built from `catalog`.
        fn state_with(
            catalog: Catalog,
            backends_map: Vec<(&str, Arc<PubKeysBackend>)>,
        ) -> BrokerState {
            state_with_grace(
                catalog,
                backends_map,
                crate::state::DEFAULT_ROTATION_GRACE_VERSIONS,
            )
        }

        /// Like [`state_with`] but with an explicit rotation grace window (in key
        /// versions), so a test can drive the real [`build_jwks`] grace floor
        /// (`latest - grace_versions`) across different window widths.
        fn state_with_grace(
            catalog: Catalog,
            backends_map: Vec<(&str, Arc<PubKeysBackend>)>,
            grace_versions: u32,
        ) -> BrokerState {
            const MINIMAL_CATALOG: &str = r#"{
              "schemaVersion": 1,
              "backends": { "b": { "kind": "vault", "addr": "http://127.0.0.1:8200" } },
              "keys": {}
            }"#;
            const EMPTY_POLICY: &str = r#"{
              "roles": {},
              "rules": [],
              "config": { "names": { "users": {}, "groups": {} }, "memberships": {} }
            }"#;
            let (_minimal, policy, config, _warnings) =
                crate::catalog::load(MINIMAL_CATALOG, EMPTY_POLICY).expect("load minimal");
            let mut backends: BTreeMap<String, Box<dyn Backend>> = BTreeMap::new();
            for (name, handle) in backends_map {
                backends.insert(name.to_string(), Box::new(Handle(handle)));
            }
            let manager = BackendManager::new(catalog.clone(), backends).expect("manager builds");
            let limits = crate::state::BrokerLimits {
                grace_versions,
                ..crate::state::BrokerLimits::default()
            };
            BrokerState::with_limits(catalog, policy, config, manager, "vault", limits)
        }

        /// Distinct `kid`s in a JWK set body.
        fn kids(body: &[u8]) -> Vec<String> {
            let parsed: serde_json::Value = serde_json::from_slice(body).expect("jwks json");
            parsed["keys"]
                .as_array()
                .expect("keys array")
                .iter()
                .filter_map(|k| k["kid"].as_str().map(str::to_string))
                .collect()
        }

        /// The `is_jwks_issuer`/`issuer_alg` predicates accept exactly the
        /// SPIFFE profile + `svid_kind=jwt` + `Asymmetric` shape. A direct unit
        /// check of the selection seam, independent of I/O.
        #[test]
        fn selection_predicate_admits_only_profile_jwt_asymmetric() {
            let cat = catalog_from_json(SELECTION_CATALOG);
            let want = |name: &str| {
                cat.keys
                    .get(name)
                    .is_some_and(|e| is_jwks_issuer(e) && issuer_alg(e.key_type).is_some())
            };
            assert!(want("rsa.issuer"), "RSA jwt asymmetric is an issuer");
            assert!(!want("ed.issuer"), "ed25519 jwt is not RSA-profile");
            assert!(
                !want("plain.signer"),
                "asymmetric w/o svid_kind=jwt excluded"
            );
            assert!(!want("the.value"), "value key excluded (wrong class)");
            assert!(!want("the.sealing"), "sealing key excluded (wrong class)");
            assert_eq!(
                issuer_alg(Some(KeyAlgorithm::Rsa2048)),
                Some(SvidAlg::Rs256)
            );
            assert_eq!(
                issuer_alg(Some(KeyAlgorithm::EcdsaP256)),
                Some(SvidAlg::Es256)
            );
            assert_eq!(
                issuer_alg(Some(KeyAlgorithm::EcdsaP384)),
                Some(SvidAlg::Es384)
            );
            assert_eq!(issuer_alg(Some(KeyAlgorithm::EcdsaP521)), None);
            assert_eq!(issuer_alg(Some(KeyAlgorithm::Ed25519)), None);
        }

        /// A mix of keys: only the RSA `svid_kind=jwt` asymmetric issuer's key is
        /// served; the ed25519-jwt, the plain (non-jwt) asymmetric, the value, and
        /// the sealing keys are all excluded. Asserts EXACTLY the RSA issuer's one
        /// version is published, AND that `public_keys` was the only read (no
        /// private/secret seam touched on any backend).
        #[tokio::test]
        async fn build_jwks_serves_only_the_rsa_jwt_issuer() {
            let cat = catalog_from_json(SELECTION_CATALOG);
            let rsa = PubKeysBackend::new(BTreeMap::from([(1, rsa_public_der())]));
            // The excluded keys route to a backend that ERRS on `public_keys`: if
            // selection were wrong and one of them were fanned out, the build would
            // fail: a second guard on top of the kid-count assertion.
            let other = PubKeysBackend::failing();
            let state = state_with(
                cat,
                vec![("rsa", Arc::clone(&rsa)), ("other", Arc::clone(&other))],
            );

            let body = build_jwks(&state).await.expect("build jwks");
            assert_eq!(kids(&body).len(), 1, "exactly the RSA issuer's one key");

            // Public-keys-only: the RSA issuer was read once via `public_keys`, the
            // excluded keys' backend was never fanned out, and NO private/secret
            // read happened on either backend.
            assert_eq!(rsa.public_keys_calls.load(Ordering::SeqCst), 1);
            assert_eq!(
                other.public_keys_calls.load(Ordering::SeqCst),
                0,
                "excluded keys are never fanned out to a backend"
            );
            assert!(
                !rsa.forbidden_called.load(Ordering::SeqCst)
                    && !other.forbidden_called.load(Ordering::SeqCst),
                "no private/secret read on the JWKS live path"
            );
        }

        /// Two RSA `svid_kind=jwt` issuers → the served set carries BOTH issuers'
        /// keys, deduplicated by `kid` (distinct public keys → distinct kids; none
        /// dropped, none duplicated).
        #[tokio::test]
        async fn build_jwks_merges_two_issuers_deduped_by_kid() {
            let cat = catalog_from_json(MULTI_ISSUER_CATALOG);
            let one = PubKeysBackend::new(BTreeMap::from([(1, rsa_public_der())]));
            let two = PubKeysBackend::new(BTreeMap::from([(1, rsa_public_der())]));
            let state = state_with(
                cat,
                vec![("one", Arc::clone(&one)), ("two", Arc::clone(&two))],
            );

            let body = build_jwks(&state).await.expect("build jwks");
            let mut got = kids(&body);
            got.sort();
            got.dedup();
            assert_eq!(got.len(), 2, "both issuers' keys present, deduped by kid");
            assert_eq!(one.public_keys_calls.load(Ordering::SeqCst), 1);
            assert_eq!(two.public_keys_calls.load(Ordering::SeqCst), 1);
            assert!(
                !one.forbidden_called.load(Ordering::SeqCst)
                    && !two.forbidden_called.load(Ordering::SeqCst),
                "merge path reads only public keys"
            );
        }

        /// Two issuers whose public keys are IDENTICAL collapse to ONE JWK: the
        /// `kid` is content-derived, so the duplicate is dropped (not double-served).
        #[tokio::test]
        async fn build_jwks_dedups_identical_issuer_keys() {
            let cat = catalog_from_json(MULTI_ISSUER_CATALOG);
            let shared = rsa_public_der();
            let one = PubKeysBackend::new(BTreeMap::from([(1, shared.clone())]));
            let two = PubKeysBackend::new(BTreeMap::from([(1, shared)]));
            let state = state_with(
                cat,
                vec![("one", Arc::clone(&one)), ("two", Arc::clone(&two))],
            );

            let body = build_jwks(&state).await.expect("build jwks");
            assert_eq!(
                kids(&body).len(),
                1,
                "identical public keys dedup to one kid"
            );
        }

        /// The rotation grace window over the REAL [`build_jwks`] (not the
        /// `jwt_svid_jwks_grace` generator in isolation): a multi-version issuer
        /// backend publishes one JWK per version inside `[grace_floor ..= latest]`
        /// and DROPS every version below the floor. Drives the manager-resolve +
        /// `state.limits()` grace-floor + merge path end to end across three window
        /// widths, asserting kids for out-of-window versions are absent (and that
        /// the live path stays public-keys-only).
        #[tokio::test]
        async fn build_jwks_grace_window_drops_versions_below_the_floor() {
            // Content-derived `kid` for one issuer public half, via the single-key
            // generator, so a version's presence/absence in the set is checkable.
            let kid_of = |der: &[u8]| -> String {
                let body = crate::minter::jwt_svid_jwks_from_public_key(der, SvidAlg::Rs256)
                    .expect("single-key jwks");
                kids(&body).first().cloned().expect("one kid")
            };

            let der_v1 = rsa_public_der();
            let der_v2 = rsa_public_der();
            let der_v3 = rsa_public_der();
            let kid_v1 = kid_of(&der_v1);
            let kid_v2 = kid_of(&der_v2);
            let kid_v3 = kid_of(&der_v3);
            // Distinct public keys → distinct content-derived kids, so an absent
            // kid genuinely means that version was dropped, not merely deduped.
            assert!(
                kid_v1 != kid_v2 && kid_v2 != kid_v3 && kid_v1 != kid_v3,
                "three distinct RSA keys yield three distinct kids"
            );
            let versions = BTreeMap::from([(1, der_v1), (2, der_v2), (3, der_v3)]);

            // Build the issuer JWKS at a given grace window and return its sorted
            // kids, re-asserting public-keys-only each time.
            let served_kids = |grace_versions: u32| {
                let versions = versions.clone();
                async move {
                    let rsa = PubKeysBackend::new(versions);
                    let other = PubKeysBackend::failing();
                    let state = state_with_grace(
                        catalog_from_json(SELECTION_CATALOG),
                        vec![("rsa", Arc::clone(&rsa)), ("other", Arc::clone(&other))],
                        grace_versions,
                    );
                    let body = build_jwks(&state).await.expect("build jwks");
                    assert_eq!(
                        rsa.public_keys_calls.load(Ordering::SeqCst),
                        1,
                        "issuer read exactly once via public_keys"
                    );
                    assert_eq!(
                        other.public_keys_calls.load(Ordering::SeqCst),
                        0,
                        "excluded backend never fanned out"
                    );
                    assert!(
                        !rsa.forbidden_called.load(Ordering::SeqCst)
                            && !other.forbidden_called.load(Ordering::SeqCst),
                        "grace path reads only public keys"
                    );
                    let mut got = kids(&body);
                    got.sort();
                    got
                }
            };

            // Default window (grace_versions = 1): latest = 3, floor = 2 → v2+v3
            // publish, v1 drops below the floor.
            let mut want = vec![kid_v2.clone(), kid_v3.clone()];
            want.sort();
            let got = served_kids(1).await;
            assert_eq!(got, want, "default grace publishes v2+v3, drops v1");
            assert!(
                !got.contains(&kid_v1),
                "v1 is below the grace floor and absent from the JWKS"
            );

            // Wider window (grace_versions = 2): floor = 1 → all three publish.
            let mut want_all = vec![kid_v1.clone(), kid_v2.clone(), kid_v3.clone()];
            want_all.sort();
            assert_eq!(
                served_kids(2).await,
                want_all,
                "grace=2 publishes all three in-window versions"
            );

            // Panic/compromise window (grace_versions = 0): floor = latest = 3 →
            // only the newest version publishes; both older versions drop.
            assert_eq!(
                served_kids(0).await,
                vec![kid_v3],
                "grace=0 publishes only the latest version"
            );
        }

        /// The axum handler maps a backend error to `503 Service Unavailable` with a
        /// stable, non-secret text body, never a panic, never a `500`, never any
        /// key material in the response.
        #[tokio::test]
        async fn handler_returns_503_on_backend_error() {
            let cat = catalog_from_json(SELECTION_CATALOG);
            let rsa = PubKeysBackend::failing();
            let other = PubKeysBackend::failing();
            let state = state_with(cat, vec![("rsa", Arc::clone(&rsa)), ("other", other)]);

            let app = router(Arc::new(state), JwksHttpConfig::default());
            let resp = app
                .oneshot(
                    Request::builder()
                        .uri(JWKS_PATH)
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("handler does not panic");
            assert_eq!(resp.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);

            let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
                .await
                .expect("read body");
            let text = String::from_utf8(body.to_vec()).expect("utf8 body");
            assert_eq!(
                text, "jwks temporarily unavailable\n",
                "stable non-secret body"
            );
            assert!(!text.contains("vault-token-s.123"));
            assert!(!text.contains("PRIVATE KEY"));
            // The failing backend's `public_keys` was the only seam touched: no
            // material read even on the error path.
            assert!(!rsa.forbidden_called.load(Ordering::SeqCst));
        }

        /// A `BrokerState` with one healthy RSA issuer (one published version), so
        /// the JWKS routes serve a `200` with a non-empty key set. Used by the
        /// router-shape tests below.
        fn healthy_state() -> BrokerState {
            let cat = catalog_from_json(SELECTION_CATALOG);
            let rsa = PubKeysBackend::new(BTreeMap::from([(1, rsa_public_der())]));
            let other = PubKeysBackend::failing();
            state_with(cat, vec![("rsa", rsa), ("other", other)])
        }

        /// `method path` against `router(state, config)`.
        async fn route_request(
            state: BrokerState,
            config: JwksHttpConfig,
            method: &str,
            target: &str,
        ) -> axum::response::Response {
            let app = router(Arc::new(state), config);
            app.oneshot(
                Request::builder()
                    .method(method)
                    .uri(target)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("router does not panic")
        }

        /// `GET path` against `router(state, config)`, returning the response status.
        async fn get_status(
            state: BrokerState,
            config: JwksHttpConfig,
            method: &str,
            path: &str,
        ) -> axum::http::StatusCode {
            route_request(state, config, method, path).await.status()
        }

        async fn response_body(resp: axum::response::Response) -> String {
            let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
                .await
                .expect("read response body");
            String::from_utf8(bytes.to_vec()).expect("utf8 response")
        }

        /// Both JWKS paths serve the key set; an unknown path is `404` and a `POST`
        /// to a `GET`-only route is `405` (axum's method-not-allowed fall-through).
        #[tokio::test]
        async fn router_serves_both_jwks_paths_and_falls_through_404_405() {
            assert_eq!(
                get_status(healthy_state(), JwksHttpConfig::default(), "GET", JWKS_PATH).await,
                axum::http::StatusCode::OK,
                "/jwks.json serves the key set"
            );
            assert_eq!(
                get_status(
                    healthy_state(),
                    JwksHttpConfig::default(),
                    "GET",
                    JWKS_WELL_KNOWN_PATH
                )
                .await,
                axum::http::StatusCode::OK,
                "/.well-known/jwks.json serves the same key set"
            );
            assert_eq!(
                get_status(healthy_state(), JwksHttpConfig::default(), "GET", "/nope").await,
                axum::http::StatusCode::NOT_FOUND,
                "unknown path is 404"
            );
            assert_eq!(
                get_status(
                    healthy_state(),
                    JwksHttpConfig::default(),
                    "POST",
                    JWKS_PATH
                )
                .await,
                axum::http::StatusCode::METHOD_NOT_ALLOWED,
                "POST to a GET-only route is 405"
            );
        }

        /// Adversarial request targets and methods stay local to the static axum
        /// router. The surface never follows a supplied URL, decodes traversal into
        /// a real route, or reflects request metadata into a backend lookup.
        #[tokio::test]
        async fn router_rejects_adversarial_targets_and_methods_locally() {
            for target in [
                "/%2e%2e/jwks.json",
                "/.well-known/%2e%2e/jwks.json",
                "/jwks.json/%2e%2e",
                "//evil.example/jwks.json",
            ] {
                assert_eq!(
                    get_status(healthy_state(), JwksHttpConfig::default(), "GET", target).await,
                    StatusCode::NOT_FOUND,
                    "{target} is not routed"
                );
            }

            for method in [Method::POST, Method::PUT, Method::DELETE, Method::PATCH] {
                assert_eq!(
                    get_status(
                        healthy_state(),
                        JwksHttpConfig::default(),
                        method.as_str(),
                        JWKS_PATH
                    )
                    .await,
                    StatusCode::METHOD_NOT_ALLOWED,
                    "{method} is rejected on the JWKS route"
                );
            }

            assert_eq!(
                get_status(
                    healthy_state(),
                    JwksHttpConfig::default(),
                    "GET",
                    "http://evil.example/jwks.json"
                )
                .await,
                StatusCode::OK,
                "absolute-form request targets are resolved only by local path"
            );
            assert_eq!(
                get_status(
                    healthy_state(),
                    JwksHttpConfig::default(),
                    "GET",
                    "/jwks.json?next=http%3A%2F%2F169.254.169.254%2Flatest&kid=%3Cscript%3E"
                )
                .await,
                StatusCode::OK,
                "query strings do not change the static JWKS route"
            );
        }

        /// Host and forwarding headers are untrusted request metadata. OIDC
        /// discovery must publish only the configured issuer, never caller-supplied
        /// authority, proto, query, or absolute-form target data.
        #[tokio::test]
        async fn discovery_does_not_reflect_host_or_forwarded_headers() {
            let config = JwksHttpConfig {
                issuer: Some("https://issuer.example/base".to_string()),
                tls: None,
            };
            let app = router(Arc::new(healthy_state()), config);
            let resp = app
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("http://evil.example/.well-known/openid-configuration?issuer=evil")
                        .header(header::HOST, "evil.example")
                        .header("x-forwarded-host", "metadata.google.internal")
                        .header("x-forwarded-proto", "http")
                        .header("x-forwarded-uri", "/jwks.json?issuer=evil")
                        .header("x-real-ip", "169.254.169.254")
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("router does not panic");
            assert_eq!(resp.status(), StatusCode::OK);

            let body = response_body(resp).await;
            let doc: serde_json::Value = serde_json::from_str(&body).expect("discovery json");
            assert_eq!(doc["issuer"], "https://issuer.example/base");
            assert_eq!(
                doc["jwks_uri"],
                format!("https://issuer.example/base{JWKS_PATH}")
            );
            for untrusted in [
                "evil.example",
                "metadata.google.internal",
                "169.254.169.254",
                "x-forwarded",
            ] {
                assert!(
                    !body.contains(untrusted),
                    "discovery body reflected untrusted metadata: {untrusted}"
                );
            }
        }

        /// Oversized headers and cache validators cannot influence the response
        /// body or secret-read behavior. They are treated as ordinary request
        /// metadata by the in-process router.
        #[tokio::test]
        async fn jwks_etag_is_stable_under_untrusted_headers() {
            let app = router(Arc::new(healthy_state()), JwksHttpConfig::default());
            let first = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(JWKS_PATH)
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("router does not panic");
            assert_eq!(first.status(), StatusCode::OK);
            let first_etag = first.headers().get(header::ETAG).cloned().expect("etag");

            let second = app
                .oneshot(
                    Request::builder()
                        .uri(format!(
                            "{JWKS_WELL_KNOWN_PATH}?cache-bust=http://127.0.0.1"
                        ))
                        .header(header::IF_NONE_MATCH, first_etag.clone())
                        .header(header::HOST, "attacker.example")
                        .header("x-forwarded-host", "attacker.example")
                        .header("x-oversized-adversarial", "a".repeat(16 * 1024))
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("router does not panic");
            assert_eq!(second.status(), StatusCode::NOT_MODIFIED);
            assert_eq!(second.headers().get(header::ETAG), Some(&first_etag));
            assert!(
                response_body(second).await.is_empty(),
                "conditional JWKS hit returns 304 without a body"
            );
        }

        /// The discovery route is mounted IFF an `issuer` is configured: present
        /// (`200`) when `issuer` is `Some`, `404` when `issuer` is `None` (the route
        /// is not mounted, so the defensive `503` arm is structurally unreachable).
        #[tokio::test]
        async fn discovery_route_mounted_iff_issuer_configured() {
            use super::super::OIDC_DISCOVERY_PATH;

            // issuer = None: the route is not mounted -> 404 (not the 503 arm, which
            // is unreachable because the route only exists when issuer is Some).
            assert_eq!(
                get_status(
                    healthy_state(),
                    JwksHttpConfig::default(),
                    "GET",
                    OIDC_DISCOVERY_PATH
                )
                .await,
                axum::http::StatusCode::NOT_FOUND,
                "no issuer -> discovery route absent (404)"
            );

            // issuer = Some: the route is mounted and serves the discovery doc.
            let config = JwksHttpConfig {
                issuer: Some("https://basil.example.com".to_string()),
                tls: None,
            };
            assert_eq!(
                get_status(healthy_state(), config, "GET", OIDC_DISCOVERY_PATH).await,
                axum::http::StatusCode::OK,
                "issuer set -> discovery route serves 200"
            );
        }

        /// One RSA `svid_kind=jwt` asymmetric issuer [INCLUDED]; an `ed25519`
        /// `svid_kind=jwt` asymmetric key [EXCLUDED: non-profile]; a plain asymmetric
        /// signer with NO `svid_kind` [EXCLUDED]; a `value` key and a `sealing` key
        /// [EXCLUDED, wrong class]. The ed25519-jwt key is loader-rejected, so this
        /// catalog is deserialized directly (see `catalog_from_json`).
        const SELECTION_CATALOG: &str = r#"{
          "schemaVersion": 1,
          "backends": { "rsa": { "kind": "vault", "addr": "http://127.0.0.1:8200" },
                        "other": { "kind": "vault", "addr": "http://127.0.0.1:8200" } },
          "keys": {
            "rsa.issuer": {
              "class": "asymmetric", "keyType": "rsa-2048", "backend": "rsa",
              "path": "rsa-issuer", "writable": false,
              "labels": ["svid_kind=jwt"], "description": "an RSA JWT-SVID issuer"
            },
            "ed.issuer": {
              "class": "asymmetric", "keyType": "ed25519", "backend": "other",
              "path": "ed-issuer", "writable": false,
              "labels": ["svid_kind=jwt"], "description": "a non-profile jwt key (excluded)"
            },
            "plain.signer": {
              "class": "asymmetric", "keyType": "ed25519", "backend": "other",
              "path": "plain-signer", "writable": false,
              "description": "an asymmetric key with no svid_kind (excluded)"
            },
            "the.value": {
              "class": "value", "backend": "other", "engine": "kv2",
              "path": "secret/data/the/value", "writable": true,
              "description": "a value key (excluded)"
            },
            "the.sealing": {
              "class": "sealing", "keyType": "x25519", "backend": "other", "engine": "kv2",
              "path": "secret/data/the/sealing", "publicPath": "secret/data/the/sealing-pub",
              "writable": false, "description": "a sealing key (excluded)"
            }
          }
        }"#;

        /// Two RSA `svid_kind=jwt` asymmetric issuers on separate backends.
        const MULTI_ISSUER_CATALOG: &str = r#"{
          "schemaVersion": 1,
          "backends": { "one": { "kind": "vault", "addr": "http://127.0.0.1:8200" },
                        "two": { "kind": "vault", "addr": "http://127.0.0.1:8200" } },
          "keys": {
            "issuer.one": {
              "class": "asymmetric", "keyType": "rsa-2048", "backend": "one",
              "path": "issuer-one", "writable": false,
              "labels": ["svid_kind=jwt"], "description": "RSA JWT-SVID issuer one"
            },
            "issuer.two": {
              "class": "asymmetric", "keyType": "rsa-2048", "backend": "two",
              "path": "issuer-two", "writable": false,
              "labels": ["svid_kind=jwt"], "description": "RSA JWT-SVID issuer two"
            }
          }
        }"#;
    }

    /// The acceptance bar (`basil-uce.2`): a standard `jsonwebtoken` verifier
    /// validates Basil JWTs **across a key rotation** using ONLY a key selected
    /// from the published JWKS by `kid`.
    ///
    /// Issuer is at v1 → mint JWT-A; rotate to v2 → mint JWT-B. While both are in
    /// grace (grace floor = `latest - 1`): the JWKS publishes BOTH v1+v2 JWKs
    /// (distinct kids) and the verifier validates BOTH tokens by selecting the JWK
    /// matching each token's `kid`. Then the grace floor advances past v1 (latest
    /// jumps to v3, floor = 2): the JWKS DROPS v1 and a v1-keyed token no longer
    /// resolves.
    #[tokio::test]
    #[allow(clippy::too_many_lines)] // multi-version RSA fixture + full rotate→verify loop
    async fn served_jwks_verifies_basil_jwts_across_a_rotation() {
        use std::collections::BTreeMap;
        use std::sync::Mutex;

        use async_trait::async_trait;
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use rsa::pkcs1::EncodeRsaPrivateKey as _;
        use rsa::pkcs8::EncodePublicKey as _;

        use crate::backend::{Backend, BackendError, KeyMetadata, NewKey, SignOptions};
        use crate::minter::{jwt_svid_jwks_grace, mint_svid};
        use basil_proto::KeyType;

        /// A multi-version RSA issuer: each `rotate` adds a fresh RSA-2048
        /// version; `public_keys` returns the SPKI-DER public half of every
        /// version, and `sign` signs with the **latest** version (what the minter
        /// targets), so a token always carries the latest version's `kid`.
        struct RotatingRsaBackend {
            versions: Mutex<Vec<(jsonwebtoken::EncodingKey, Vec<u8>)>>,
        }
        impl RotatingRsaBackend {
            fn new() -> Self {
                let mut me = Self {
                    versions: Mutex::new(Vec::new()),
                };
                me.add_version();
                me
            }
            fn add_version(&mut self) {
                let mut rng = rand::thread_rng();
                let private = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
                let public = rsa::RsaPublicKey::from(&private);
                let private_pem = private
                    .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
                    .expect("pem");
                let public_der = public.to_public_key_der().expect("der").as_bytes().to_vec();
                let key = jsonwebtoken::EncodingKey::from_rsa_pem(private_pem.as_bytes())
                    .expect("encoding key");
                self.versions
                    .get_mut()
                    .expect("lock")
                    .push((key, public_der));
            }
            fn latest_der(&self) -> Vec<u8> {
                let v = self.versions.lock().expect("lock");
                v.last().expect("at least one version").1.clone()
            }
        }
        #[async_trait]
        impl Backend for RotatingRsaBackend {
            fn kind(&self) -> &'static str {
                "rotating-rsa-test"
            }
            async fn new_key(&self, _key_type: KeyType) -> Result<NewKey, BackendError> {
                Err(BackendError::Unsupported("new_key"))
            }
            async fn public_key(&self, _key_id: &str) -> Result<Vec<u8>, BackendError> {
                Ok(self.latest_der())
            }
            async fn key_metadata(&self, _key_id: &str) -> Result<KeyMetadata, BackendError> {
                let n = u32::try_from(self.versions.lock().expect("lock").len()).unwrap_or(1);
                Ok(KeyMetadata {
                    key_type: Some(KeyType::Rsa2048),
                    latest_version: n,
                })
            }
            async fn public_keys(
                &self,
                _key_id: &str,
            ) -> Result<BTreeMap<u32, Vec<u8>>, BackendError> {
                let v = self.versions.lock().expect("lock");
                Ok(v.iter()
                    .enumerate()
                    .map(|(i, (_, der))| (u32::try_from(i + 1).unwrap_or(u32::MAX), der.clone()))
                    .collect())
            }
            async fn rotate(&self, _key_id: &str) -> Result<u32, BackendError> {
                let mut v = self.versions.lock().expect("lock");
                let mut rng = rand::thread_rng();
                let private = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
                let public = rsa::RsaPublicKey::from(&private);
                let private_pem = private
                    .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
                    .expect("pem");
                let public_der = public.to_public_key_der().expect("der").as_bytes().to_vec();
                let key = jsonwebtoken::EncodingKey::from_rsa_pem(private_pem.as_bytes())
                    .expect("encoding key");
                v.push((key, public_der));
                u32::try_from(v.len()).map_err(|_| BackendError::Backend("overflow".into()))
            }
            async fn sign_with_options(
                &self,
                _key_id: &str,
                input: &[u8],
                options: SignOptions,
            ) -> Result<Vec<u8>, BackendError> {
                if options != SignOptions::Rs256Pkcs1v15Sha256 {
                    return Err(BackendError::Unsupported("rsa test sign options"));
                }
                let key = {
                    let v = self.versions.lock().expect("lock");
                    v.last().expect("a version").0.clone()
                };
                let b64 = jsonwebtoken::crypto::sign(input, &key, jsonwebtoken::Algorithm::RS256)
                    .map_err(|e| BackendError::Backend(e.to_string()))?;
                URL_SAFE_NO_PAD
                    .decode(b64)
                    .map_err(|e| BackendError::Backend(e.to_string()))
            }
            async fn sign(&self, key_id: &str, input: &[u8]) -> Result<Vec<u8>, BackendError> {
                self.sign_with_options(key_id, input, SignOptions::Rs256Pkcs1v15Sha256)
                    .await
            }
            async fn verify(
                &self,
                _key_id: &str,
                _message: &[u8],
                _signature: &[u8],
            ) -> Result<bool, BackendError> {
                Err(BackendError::Unsupported("verify"))
            }
        }

        /// Mint a JWT-SVID through Basil's minter against the issuer's latest
        /// version.
        async fn mint(backend: &dyn Backend) -> String {
            mint_svid(
                backend,
                "rsa-issuer",
                "spiffe://example.org",
                SvidAlg::Rs256,
                "spiffe://example.org/db-01",
                "vault",
                Some(300),
                &serde_json::Value::Null,
            )
            .await
            .expect("mint svid")
        }

        /// Resolve a token against the served JWKS by `kid`, then verify the
        /// signature + `aud` (NOT `iss`: Basil JWT-SVIDs carry a SPIFFE `iss`,
        /// per the discovery-doc decision). Returns `true` only if a JWK matched
        /// the `kid` AND the signature validated.
        fn verify_via_jwks(token: &str, jwks: &serde_json::Value) -> bool {
            let Ok(header) = jsonwebtoken::decode_header(token) else {
                return false;
            };
            let Some(kid) = header.kid else { return false };
            let Some(keys) = jwks["keys"].as_array() else {
                return false;
            };
            let Some(jwk) = keys
                .iter()
                .find(|k| k["kid"].as_str() == Some(kid.as_str()))
            else {
                return false; // kid not published → cannot resolve
            };
            let (Some(n), Some(e)) = (jwk["n"].as_str(), jwk["e"].as_str()) else {
                return false;
            };
            let Ok(decoding_key) = jsonwebtoken::DecodingKey::from_rsa_components(n, e) else {
                return false;
            };
            let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
            validation.set_audience(&["vault"]);
            validation.validate_aud = true;
            validation.set_required_spec_claims(&["exp", "sub", "aud"]);
            jsonwebtoken::decode::<serde_json::Value>(token, &decoding_key, &validation).is_ok()
        }

        /// Number of distinct `kid`s in a JWK set.
        fn published_kid_count(jwks: &serde_json::Value) -> usize {
            jwks["keys"]
                .as_array()
                .expect("keys array")
                .iter()
                .filter_map(|k| k["kid"].as_str())
                .count()
        }

        // grace floor = latest - 1 (the broker default), clamped to >= 1.
        let grace_floor = |latest: u32| latest.saturating_sub(1).max(1);
        let backend = RotatingRsaBackend::new();

        // v1: mint JWT-A.
        let jwt_a = mint(&backend).await;
        // rotate to v2: mint JWT-B.
        backend.rotate("rsa-issuer").await.expect("rotate to v2");
        let jwt_b = mint(&backend).await;

        // (a) JWKS publishes BOTH v1 and v2 while both are in grace (floor = 1).
        let bytes = jwt_svid_jwks_grace(&backend, "rsa-issuer", SvidAlg::Rs256, grace_floor)
            .await
            .expect("grace jwks");
        let jwks: serde_json::Value = serde_json::from_slice(&bytes).expect("jwks json");
        assert_eq!(
            published_kid_count(&jwks),
            2,
            "both v1 and v2 published while in grace"
        );

        // (b) the standard verifier validates BOTH tokens via the JWKS by kid.
        assert!(verify_via_jwks(&jwt_a, &jwks), "JWT-A validates in grace");
        assert!(verify_via_jwks(&jwt_b, &jwks), "JWT-B validates in grace");

        // (c) advance the grace floor past v1: rotate to v3 (floor = 2). The JWKS
        // drops v1's JWK and JWT-A (keyed to v1) no longer resolves; JWT-B (v2)
        // still does (still in grace), and a freshly minted JWT-C (v3) does too.
        backend.rotate("rsa-issuer").await.expect("rotate to v3");
        let jwt_c = mint(&backend).await;
        let bytes = jwt_svid_jwks_grace(&backend, "rsa-issuer", SvidAlg::Rs256, grace_floor)
            .await
            .expect("grace jwks after second rotation");
        let jwks: serde_json::Value = serde_json::from_slice(&bytes).expect("jwks json");
        assert_eq!(
            published_kid_count(&jwks),
            2,
            "only v2 and v3 published (v1 dropped)"
        );
        assert!(
            !verify_via_jwks(&jwt_a, &jwks),
            "JWT-A (v1) no longer resolves after the floor advanced past v1"
        );
        assert!(verify_via_jwks(&jwt_b, &jwks), "JWT-B (v2) still in grace");
        assert!(verify_via_jwks(&jwt_c, &jwks), "JWT-C (v3) validates");
    }
}
