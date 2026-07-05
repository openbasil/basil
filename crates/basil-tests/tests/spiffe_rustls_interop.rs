//! External `spiffe-rustls` mTLS consumer interop test (basil-dk5.13).
//!
//! Proves the STANDARD SPIFFE-aware rustls integration crate (`spiffe-rustls`,
//! same upstream repo as rust-spiffe) builds working `rustls::ClientConfig` /
//! `rustls::ServerConfig` UNMODIFIED on top of a `spiffe::X509Source` whose
//! material is provided by a live Basil Workload API unix socket, no
//! Basil-specific TLS adapter, no vendored spiffe-rustls / rust-spiffe logic.
//!
//! What this exercises end to end:
//!   1. Build BOTH a server and a client `rustls` config with spiffe-rustls'
//!      `mtls_server` / `mtls_client` builders, fed by a Basil-backed
//!      `X509Source`.
//!   2. Run a REAL loopback mTLS handshake over `tokio-rustls` and verify it
//!      succeeds when both ends authorize the peer's exact Basil-issued SPIFFE
//!      ID.
//!   3. Verify SPIFFE-ID authorization FAILS (handshake errors) when an end
//!      authorizes only a wrong/unauthorized peer ID.
//!   4. Verify an ALPN config suitable for gRPC/HTTP2 (`h2`) negotiates over the
//!      handshake.
//!   5. Verify the live material watcher: a config built from the SAME live
//!      `X509Source` observes the CURRENT Basil material on a fresh handshake,
//!      and the source exposes its rotation channel (`updated()`) that
//!      spiffe-rustls' internal `MaterialWatcher` subscribes to: i.e. new
//!      handshakes pick up rotated Basil material with NO Basil-specific adapter.
//!
//! Live test: it reuses the shared boot harness (`tests/common/mod.rs`), which
//! shells out to `scripts/prefill-test-store.sh` (boots a dev `bao`, writes
//! fixtures + a sealed `AppRole` bundle) and runs `target/debug/basil run`
//! on a temp socket. The Workload API is served on the same socket as the broker.
//!
//! GATING: if `bao` is not on PATH this prints an EXPLICIT skip line and returns
//! (acceptance forbids a silent `#[ignore]` skip). When `bao` is present it runs
//! for real and MUST pass.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::allow_attributes
)]

use std::sync::Arc;

use basil_tests::{Engine, TRUST_DOMAIN, alloc_addr, boot_basil_with_svid_ttl, on_path};
use rustls::pki_types::ServerName;
use spiffe::{X509Source, X509SourceBuilder, X509SourceUpdates};
use spiffe_rustls::{authorizer, mtls_client, mtls_server};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// Expected outcome of one loopback mTLS case.
///
/// SPIFFE-ID authorization runs after cryptographic verification, on whichever
/// end holds the rejecting authorizer: when the SERVER rejects the client's
/// SPIFFE ID, the server's `accept()` errors and alerts the peer; when the
/// CLIENT rejects the server's SPIFFE ID, the client's `connect()` errors. So
/// the negative variants name the side that must observe the failure (matching
/// the directionality of the upstream spiffe-rustls integration test).
enum Expect {
    /// Handshake completes on both ends.
    Success,
    /// Handshake completes and the negotiated ALPN equals this protocol.
    SuccessAlpn(&'static [u8]),
    /// The client side of the handshake errors (it denied the server's ID).
    ClientFails,
    /// The server side of `accept()` errors (it denied the client's ID).
    ServerFails,
}

/// One loopback mTLS case: the two ends' exact-match allow-lists, optional ALPN,
/// and the expected outcome.
struct Case<'a> {
    name: &'a str,
    server_allows: &'a [&'a str],
    client_allows: &'a [&'a str],
    alpn: Option<&'static [u8]>,
    expect: Expect,
}

/// Build a Basil-backed `X509Source` over the harness Workload API endpoint.
/// This is the EXACT public path a real `spiffe-rustls` consumer uses; we pass
/// the endpoint explicitly (equivalent to `X509Source::new()` after setting
/// `SPIFFE_ENDPOINT_SOCKET`), avoiding the forbidden `unsafe` env `set_var`.
async fn basil_x509_source(endpoint: &str) -> X509Source {
    X509SourceBuilder::new()
        .endpoint(endpoint)
        .build()
        .await
        .expect("X509Source builds against Basil Workload API")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spiffe_rustls_mtls_interops_with_basil_x509_source() {
    if !on_path("bao") {
        eprintln!("SKIP: bao not found on PATH; spiffe-rustls mTLS interop needs a live engine");
        return;
    }

    // Unique 127.0.0.1 port per test BINARY (cargo runs binaries concurrently):
    // drawn from `basil_tests::alloc_addr()`, which keys a disjoint port window per
    // binary so no two dev servers ever collide.
    let harness =
        boot_basil_with_svid_ttl("spiffe-rustls-interop", Engine::OpenBao, &alloc_addr(), 4);
    let endpoint = harness.endpoint();

    // The single Basil workload identity both ends present. We learn the exact
    // issued (templated) SPIFFE ID at runtime to drive the exact-match
    // authorizers; the wrong-ID case uses a deliberately-unauthorized ID.
    let source = basil_x509_source(&endpoint).await;
    let svid = source
        .svid()
        .expect("X509Source observes an initial Basil SVID");
    let issued_id = svid.spiffe_id().to_string();
    assert_eq!(
        svid.spiffe_id().trust_domain_name(),
        TRUST_DOMAIN,
        "Basil SVID is in the configured trust domain (got {issued_id})"
    );
    assert!(
        issued_id.starts_with("spiffe://example.org/"),
        "Basil-issued SPIFFE ID is in example.org (got {issued_id})"
    );
    eprintln!("INTEROP(spiffe-rustls): Basil-issued X.509-SVID id = {issued_id}");

    // A SPIFFE ID that Basil does NOT issue here, used to prove authorization
    // (not just authentication) is enforced by the spiffe-rustls verifier.
    let wrong_id = "spiffe://example.org/definitely-not-this-workload";
    assert_ne!(
        issued_id, wrong_id,
        "the negative-case ID must differ from the real Basil identity"
    );

    // ---- 1) Positive: both ends authorize the exact Basil SPIFFE ID ---------
    handshake_case(
        &source,
        &Case {
            name: "exact-id authorize on both ends succeeds",
            server_allows: &[&issued_id],
            client_allows: &[&issued_id],
            alpn: None,
            expect: Expect::Success,
        },
    )
    .await;

    // ---- 2) ALPN for gRPC/HTTP2 (h2) negotiates -----------------------------
    handshake_case(
        &source,
        &Case {
            name: "h2 ALPN suitable for gRPC negotiates",
            server_allows: &[&issued_id],
            client_allows: &[&issued_id],
            alpn: Some(b"h2"),
            expect: Expect::SuccessAlpn(b"h2"),
        },
    )
    .await;

    // ---- 3) Negative: server authorizes only a wrong client ID => accept fails
    handshake_case(
        &source,
        &Case {
            name: "server authorizes only a wrong client id => server accept fails",
            server_allows: &[wrong_id],
            client_allows: &[&issued_id],
            alpn: None,
            expect: Expect::ServerFails,
        },
    )
    .await;

    // ---- 4) Negative: client authorizes only a wrong server ID => connect fails
    handshake_case(
        &source,
        &Case {
            name: "client authorizes only a wrong server id => client connect fails",
            server_allows: &[&issued_id],
            client_allows: &[wrong_id],
            alpn: None,
            expect: Expect::ClientFails,
        },
    )
    .await;

    // ---- 5) Live material watcher --------------------------------------------
    assert_live_material_watcher(&source, &issued_id).await;

    source.shutdown().await;
    // harness Drop tears down the agent + dev server + temp dir.
    drop(harness);
}

async fn assert_live_material_watcher(source: &X509Source, issued_id: &str) {
    // Build configs ONCE from the live source, then wait for Basil to reissue a
    // short-TTL X.509-SVID on the Workload API stream. spiffe-rustls' internal
    // MaterialWatcher must update those already-built configs so the next
    // handshake presents the new leaf without any config rebuild.
    let watcher_case = Case {
        name: "already-built configs pick up rotated Basil X.509-SVID material",
        server_allows: &[issued_id],
        client_allows: &[issued_id],
        alpn: None,
        expect: Expect::Success,
    };
    let initial_leaf = source_leaf_der(source);
    let mut updates = source.updated();
    let (acceptor, connector) = tls_pair(source, &watcher_case);
    let first = run_handshake(acceptor.clone(), connector.clone(), &watcher_case)
        .await
        .expect("initial watcher handshake succeeds");
    assert_eq!(
        first.client_observed_server_leaf, initial_leaf,
        "client saw the initial Basil leaf before rotation"
    );
    assert_eq!(
        first.server_observed_client_leaf, initial_leaf,
        "server saw the initial Basil leaf before rotation"
    );

    let rotated_leaf = wait_for_rotated_leaf(source, &mut updates, &initial_leaf).await;
    let second =
        wait_for_rotated_handshake(&acceptor, &connector, &watcher_case, &rotated_leaf).await;
    assert_eq!(
        second.client_observed_server_leaf, rotated_leaf,
        "client saw the rotated Basil leaf without rebuilding config"
    );
    assert_eq!(
        second.server_observed_client_leaf, rotated_leaf,
        "server saw the rotated Basil leaf without rebuilding config"
    );
}

async fn handshake_case(source: &X509Source, case: &Case<'_>) {
    eprintln!("INTEROP(spiffe-rustls): case '{}'", case.name);
    let (acceptor, connector) = tls_pair(source, case);
    let _ = run_handshake(acceptor, connector, case).await;
}

fn tls_pair(source: &X509Source, case: &Case<'_>) -> (TlsAcceptor, TlsConnector) {
    // spiffe-rustls builds standard rustls configs from a (cloneable, Arc-backed)
    // X509Source; both ends share the SAME live Basil source.
    let server_auth = authorizer::exact(case.server_allows.iter().copied())
        .expect("server allow-list parses as SPIFFE IDs");
    let client_auth = authorizer::exact(case.client_allows.iter().copied())
        .expect("client allow-list parses as SPIFFE IDs");

    let mut server_builder = mtls_server(source.clone()).authorize(server_auth);
    let mut client_builder = mtls_client(source.clone())
        .authorize(client_auth)
        .with_config_customizer(|cfg| {
            cfg.resumption = rustls::client::Resumption::disabled();
        });
    if let Some(proto) = case.alpn {
        server_builder = server_builder.with_alpn_protocols([proto]);
        client_builder = client_builder.with_alpn_protocols([proto]);
    }
    let server_cfg = server_builder
        .build()
        .expect("spiffe-rustls ServerConfig builds");
    let client_cfg = client_builder
        .build()
        .expect("spiffe-rustls ClientConfig builds");

    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
    let connector = TlsConnector::from(Arc::new(client_cfg));
    (acceptor, connector)
}

struct HandshakeSuccess {
    client_observed_server_leaf: Vec<u8>,
    server_observed_client_leaf: Vec<u8>,
}

async fn run_handshake(
    acceptor: TlsAcceptor,
    connector: TlsConnector,
    case: &Case<'_>,
) -> Option<HandshakeSuccess> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback listener");
    let addr = listener.local_addr().expect("listener local addr");

    // Server task: accept one connection, complete the TLS handshake, echo a byte.
    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await?;
        let mut tls = acceptor.accept(tcp).await?;
        // Capture the negotiated ALPN before any I/O races teardown.
        let alpn = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
        let peer_leaf = peer_leaf_der(
            tls.get_ref()
                .1
                .peer_certificates()
                .expect("client certificate chain"),
        );
        let mut buf = [0u8; 1];
        let _ = tls.read_exact(&mut buf).await;
        let _ = tls.write_all(&buf).await;
        let _ = tls.shutdown().await;
        Ok::<(Option<Vec<u8>>, Vec<u8>), std::io::Error>((alpn, peer_leaf))
    });

    // Client side: connect + TLS connect. For outbound TLS, spiffe-rustls keys
    // peer identity off the URI SAN, so any ServerName works against loopback.
    let server_name = ServerName::try_from("basil.example").expect("server name");
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    let client_res = connector.connect(server_name, tcp).await;

    match &case.expect {
        Expect::Success => {
            let mut tls =
                client_res.unwrap_or_else(|e| panic!("{}: client handshake: {e}", case.name));
            let client_peer_leaf = peer_leaf_der(
                tls.get_ref()
                    .1
                    .peer_certificates()
                    .expect("server certificate chain"),
            );
            tls.write_all(b"x").await.expect("client write");
            let mut buf = [0u8; 1];
            tls.read_exact(&mut buf).await.expect("client read echo");
            assert_eq!(&buf, b"x", "{}: echoed byte round-trips", case.name);
            let _ = tls.shutdown().await;
            let (_server_alpn, server_peer_leaf) = server_task
                .await
                .expect("server task join")
                .unwrap_or_else(|e| panic!("{}: server accept: {e}", case.name));
            Some(HandshakeSuccess {
                client_observed_server_leaf: client_peer_leaf,
                server_observed_client_leaf: server_peer_leaf,
            })
        }
        Expect::SuccessAlpn(expected) => {
            let mut tls =
                client_res.unwrap_or_else(|e| panic!("{}: client handshake: {e}", case.name));
            let client_peer_leaf = peer_leaf_der(
                tls.get_ref()
                    .1
                    .peer_certificates()
                    .expect("server certificate chain"),
            );
            let client_alpn = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
            assert_eq!(
                client_alpn.as_deref(),
                Some(*expected),
                "{}: client negotiated the requested ALPN",
                case.name
            );
            tls.write_all(b"x").await.expect("client write");
            let mut buf = [0u8; 1];
            tls.read_exact(&mut buf).await.expect("client read echo");
            let _ = tls.shutdown().await;
            let (server_alpn, server_peer_leaf) = server_task
                .await
                .expect("server task join")
                .expect("server accept");
            assert_eq!(
                server_alpn.as_deref(),
                Some(*expected),
                "{}: server negotiated the requested ALPN",
                case.name
            );
            Some(HandshakeSuccess {
                client_observed_server_leaf: client_peer_leaf,
                server_observed_client_leaf: server_peer_leaf,
            })
        }
        Expect::ClientFails => {
            // The client rejected the server's SPIFFE ID: connect() must error.
            client_res
                .err()
                .unwrap_or_else(|| panic!("{}: expected the client handshake to FAIL", case.name));
            // Drain the server task so it doesn't outlive the case; its accept
            // may have errored too (broken pipe / alert), which is fine here.
            let _ = server_task.await;
            None
        }
        Expect::ServerFails => {
            // The server rejected the client's SPIFFE ID: accept() must error.
            // Drop the client side first so the server isn't blocked on I/O.
            drop(client_res);
            let server_res = server_task.await.expect("server task join");
            server_res
                .err()
                .unwrap_or_else(|| panic!("{}: expected the server accept to FAIL", case.name));
            None
        }
    }
}

fn source_leaf_der(source: &X509Source) -> Vec<u8> {
    source
        .svid()
        .expect("X509Source has a Basil SVID")
        .leaf()
        .as_bytes()
        .to_vec()
}

fn peer_leaf_der(certs: &[rustls::pki_types::CertificateDer<'_>]) -> Vec<u8> {
    certs
        .first()
        .expect("peer certificate leaf")
        .as_ref()
        .to_vec()
}

async fn wait_for_rotated_leaf(
    source: &X509Source,
    updates: &mut X509SourceUpdates,
    initial_leaf: &[u8],
) -> Vec<u8> {
    let deadline = std::time::Duration::from_secs(12);
    tokio::time::timeout(deadline, async {
        loop {
            updates
                .changed()
                .await
                .expect("X509Source update channel stays open");
            let leaf = source_leaf_der(source);
            if leaf != initial_leaf {
                return leaf;
            }
        }
    })
    .await
    .expect("Basil reissued an X.509-SVID before the rotation deadline")
}

async fn wait_for_rotated_handshake(
    acceptor: &TlsAcceptor,
    connector: &TlsConnector,
    case: &Case<'_>,
    rotated_leaf: &[u8],
) -> HandshakeSuccess {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let handshake = run_handshake(acceptor.clone(), connector.clone(), case)
            .await
            .expect("post-rotation watcher handshake succeeds");
        if handshake.client_observed_server_leaf == rotated_leaf
            && handshake.server_observed_client_leaf == rotated_leaf
        {
            return handshake;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "spiffe-rustls configs did not present the rotated Basil leaf before the deadline"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}
