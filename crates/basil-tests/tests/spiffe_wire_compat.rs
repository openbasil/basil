// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Workload API wire-compatibility lock for Rust SPIFFE consumers (basil-dk5.12).
//!
//! The interop test (`spiffe_interop.rs`) proves the high-level `spiffe` client
//! can drive Basil end to end. This file goes one layer DOWN: it reads the RAW
//! protobuf bytes Basil emits on `FetchX509SVID` / `FetchX509Bundles` and asserts
//! they satisfy the exact encoding assumptions rust-spiffe relies on when it
//! parses them. A regression in Basil's Workload API encoding (DER ordering,
//! PKCS#8 framing, URI-SAN shape, leaf key-usage, bundle-map keys) then fails
//! HERE, locally, before any external interop runs.
//!
//! We drive the LIVE Workload API with the generated tonic client from
//! `basil-proto` (not the high-level `spiffe` client) precisely because the
//! high-level client decodes and hides the wire bytes; the contract under test
//! IS those bytes. The decoders mirror rust-spiffe's own parsing:
//!   - `x509-parser` walks the leaf-first DER chain (`SAN` / `KeyUsage` / `BasicConstraints`),
//!   - `pkcs8::PrivateKeyInfo::try_from` is the SAME call rust-spiffe makes on
//!     `x509_svid_key` (see spiffe `cert::PrivateKey`), so a key that parses here
//!     parses there.
//!
//! GATING: if `bao` is not on PATH this prints an EXPLICIT skip line and returns
//! (acceptance forbids a silent `#[ignore]` skip). With `bao` present it runs for
//! real and MUST pass.
//!
//! The boot harness lives in `tests/common/mod.rs`; see that file for the
//! crate-root no-panic-in-harness lint rationale.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::allow_attributes,
    // Raw-wire decoding indexes into DER chains / SVID lists; a panic on a
    // malformed shape IS the intended test failure (same rationale as the
    // panic/unwrap allows above, these only fire outside `#[test]` bodies).
    clippy::indexing_slicing,
    clippy::string_slice
)]

use basil_tests::{TRUST_DOMAIN, alloc_addr, boot_basil, on_path};

use basil_proto::spiffe::spiffe_workload_api_client::SpiffeWorkloadApiClient;
use basil_proto::spiffe::{JwtsvidRequest, X509BundlesRequest, X509svidRequest};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tonic::Request;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

use pkcs8::PrivateKeyInfo;
use x509_parser::prelude::FromDer;
use x509_parser::{
    certificate::X509Certificate, extensions::GeneralName, prelude::parse_x509_certificate,
};

/// Wrap a Workload API request with the mandatory `workload.spiffe.io: true`
/// gRPC metadata header. The high-level `spiffe` client sets this automatically;
/// the raw tonic client does not, and the server fail-closes without it.
fn workload_request<T>(msg: T) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut().insert(
        "workload.spiffe.io",
        "true".parse().expect("static metadata value"),
    );
    req
}

/// A raw tonic channel over Basil's unix socket: the same connector shape the
/// `basil` client uses (`uds_channel`), so the generated SPIFFE client speaks to
/// the live agent and hands back undecoded protobuf bytes.
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

/// Split a concatenated DER certificate sequence into its individual DER blobs,
/// preserving order. Each element is one `Certificate` SEQUENCE; we parse one,
/// note how many bytes it consumed, and advance. This is exactly how rust-spiffe
/// (and Go's `x509.ParseCertificates`) walk a concatenated DER chain/bundle.
fn split_der_certs(mut der: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while !der.is_empty() {
        let (rest, _cert) =
            parse_x509_certificate(der).expect("each element is a parseable DER certificate");
        let consumed = der.len() - rest.len();
        assert!(consumed > 0, "DER parse made no progress");
        out.push(der[..consumed].to_vec());
        der = rest;
    }
    out
}

/// Assert the issued leaf satisfies the X.509-SVID profile rust-spiffe enforces:
/// exactly one URI SAN that is the workload's SPIFFE ID with a non-root path,
/// `digitalSignature` key usage, and NO CA / keyCertSign / cRLSign leaf usage.
fn assert_leaf_is_valid_x509_svid(leaf: &X509Certificate<'_>) {
    // --- URI SAN: exactly one, a SPIFFE ID in the trust domain, non-root path.
    let san = leaf
        .subject_alternative_name()
        .expect("SAN extension parses")
        .expect("leaf has a SubjectAlternativeName extension");
    let uris: Vec<&str> = san
        .value
        .general_names
        .iter()
        .filter_map(|gn| match gn {
            GeneralName::URI(u) => Some(*u),
            _ => None,
        })
        .collect();
    assert_eq!(
        uris.len(),
        1,
        "X.509-SVID leaf MUST carry exactly one URI SAN (got {uris:?})"
    );
    let spiffe_id = uris[0];
    let prefix = format!("spiffe://{TRUST_DOMAIN}/");
    assert!(
        spiffe_id.starts_with(&prefix),
        "URI SAN is a SPIFFE ID in {TRUST_DOMAIN} (got {spiffe_id})"
    );
    assert!(
        spiffe_id.len() > prefix.len(),
        "SPIFFE ID path is non-root (got {spiffe_id})"
    );

    // --- KeyUsage: digitalSignature set; keyCertSign / cRLSign clear.
    let ku = leaf
        .key_usage()
        .expect("KeyUsage extension parses")
        .expect("leaf has a KeyUsage extension")
        .value;
    assert!(
        ku.digital_signature(),
        "X.509-SVID leaf MUST assert digitalSignature key usage"
    );
    assert!(
        !ku.key_cert_sign(),
        "X.509-SVID leaf MUST NOT assert keyCertSign"
    );
    assert!(!ku.crl_sign(), "X.509-SVID leaf MUST NOT assert cRLSign");

    // --- BasicConstraints: not a CA.
    assert!(!leaf.is_ca(), "X.509-SVID leaf MUST NOT be a CA cert");
    if let Some(bc) = leaf.basic_constraints().expect("BasicConstraints parses") {
        assert!(
            !bc.value.ca,
            "X.509-SVID leaf BasicConstraints CA flag MUST be false"
        );
    }
}

/// Every element of a concatenated DER CA bundle parses and is a CA cert.
fn assert_der_ca_bundle(label: &str, der: &[u8]) -> usize {
    let certs = split_der_certs(der);
    assert!(
        !certs.is_empty(),
        "{label} decodes to a non-empty DER CA bundle"
    );
    for (i, ca_der) in certs.iter().enumerate() {
        let (_, ca) = X509Certificate::from_der(ca_der).expect("bundle element parses");
        assert!(ca.is_ca(), "{label} element {i} is a CA certificate");
    }
    certs.len()
}

type Client = SpiffeWorkloadApiClient<Channel>;

/// `FetchX509SVID`: assert the first streamed `X509SVIDResponse` encodes its leaf
/// chain leaf-first, its key as unencrypted PKCS#8, and its bundle as DER CAs.
async fn assert_fetch_x509svid_wire(client: &mut Client) {
    let mut stream = client
        .fetch_x509svid(workload_request(X509svidRequest {}))
        .await
        .expect("FetchX509SVID")
        .into_inner();
    let resp = stream
        .message()
        .await
        .expect("read first X509SVIDResponse")
        .expect("X509SVIDResponse stream is non-empty");
    assert!(
        !resp.svids.is_empty(),
        "X509SVIDResponse carries at least one SVID"
    );
    let entry = &resp.svids[0];

    // spiffe_id field is a SPIFFE ID in the trust domain.
    assert!(
        entry
            .spiffe_id
            .starts_with(&format!("spiffe://{TRUST_DOMAIN}/")),
        "X509SVID.spiffe_id is a SPIFFE ID in {TRUST_DOMAIN} (got {})",
        entry.spiffe_id
    );

    // x509_svid: concatenated DER, LEAF FIRST.
    let chain = split_der_certs(&entry.x509_svid);
    assert!(
        !chain.is_empty(),
        "X509SVID.x509_svid decodes to a non-empty DER chain"
    );
    let (_, leaf) = X509Certificate::from_der(&chain[0]).expect("first chain element parses");
    assert_leaf_is_valid_x509_svid(&leaf);
    // Any further elements are intermediates/roots: they MUST be CAs, confirming
    // the leaf genuinely came first rather than a CA incorrectly ordered ahead of it.
    for (i, ca_der) in chain.iter().enumerate().skip(1) {
        let (_, ca) = X509Certificate::from_der(ca_der).expect("issuer chain element parses");
        assert!(
            ca.is_ca(),
            "x509_svid chain element {i} after the leaf is a CA (leaf-first ordering)"
        );
    }

    // x509_svid_key: UNENCRYPTED PKCS#8 DER (the exact rust-spiffe parse).
    assert!(
        !entry.x509_svid_key.is_empty(),
        "X509SVID.x509_svid_key is non-empty"
    );
    PrivateKeyInfo::try_from(entry.x509_svid_key.as_slice())
        .expect("X509SVID.x509_svid_key is unencrypted PKCS#8 DER (PrivateKeyInfo)");

    // bundle: concatenated DER CA bundle.
    let bundle_len = assert_der_ca_bundle("X509SVID.bundle", &entry.bundle);

    eprintln!(
        "WIRE-COMPAT: X509SVID id={} chain_len={} bundle_certs={bundle_len}",
        entry.spiffe_id,
        chain.len(),
    );
}

/// `FetchX509Bundles`: assert the bundle map is keyed by trust-domain SPIFFE IDs
/// and every value is a concatenated DER CA bundle.
async fn assert_fetch_x509_bundles_wire(client: &mut Client) {
    let mut stream = client
        .fetch_x509_bundles(workload_request(X509BundlesRequest {}))
        .await
        .expect("FetchX509Bundles")
        .into_inner();
    let resp = stream
        .message()
        .await
        .expect("read first X509BundlesResponse")
        .expect("X509BundlesResponse stream is non-empty");
    assert!(
        !resp.bundles.is_empty(),
        "X509BundlesResponse carries at least one bundle"
    );
    let td_key = format!("spiffe://{TRUST_DOMAIN}");
    assert!(
        resp.bundles.contains_key(&td_key),
        "X509BundlesResponse map is keyed by trust-domain SPIFFE ID '{td_key}' (got keys {:?})",
        resp.bundles.keys().collect::<Vec<_>>()
    );
    for (key, der) in &resp.bundles {
        assert!(
            key.starts_with("spiffe://"),
            "X509BundlesResponse map key is a SPIFFE trust-domain ID (got {key})"
        );
        assert_der_ca_bundle(&format!("X509BundlesResponse[{key}]"), der);
    }
    eprintln!(
        "WIRE-COMPAT: X509Bundles keys={:?}",
        resp.bundles.keys().collect::<Vec<_>>()
    );
}

/// `FetchJWTSVID`: assert the minted JWT-SVID's JWS header uses a SPIFFE
/// JWT-SVID profile algorithm: specifically `RS256` (NOT `EdDSA`, which every
/// standard SPIFFE client rejects), and carries a `kid` (without it rust-spiffe
/// rejects the token with `MissingKeyId`). We decode only the JOSE header
/// (first dot-segment, base64url) rather than verify, since the contract under
/// test is the wire encoding, not the signature.
async fn assert_fetch_jwtsvid_alg(client: &mut Client) {
    let resp = client
        .fetch_jwtsvid(workload_request(JwtsvidRequest {
            audience: vec!["my-audience".to_string()],
            spiffe_id: String::new(),
        }))
        .await
        .expect("FetchJWTSVID")
        .into_inner();
    assert!(
        !resp.svids.is_empty(),
        "JWTSVIDResponse carries at least one JWT-SVID"
    );
    let token = &resp.svids[0].svid;
    let header_b64 = token
        .split('.')
        .next()
        .expect("JWS compact serialization has a header segment");
    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .expect("JWS header is base64url");
    let header: serde_json::Value =
        serde_json::from_slice(&header_bytes).expect("JWS header is JSON");

    let alg = header
        .get("alg")
        .and_then(serde_json::Value::as_str)
        .expect("JWS header has an alg");
    assert_eq!(
        alg, "RS256",
        "JWT-SVID alg MUST be RS256 (SPIFFE JWT-SVID profile; EdDSA is rejected by rust-spiffe)"
    );
    let kid = header
        .get("kid")
        .and_then(serde_json::Value::as_str)
        .expect("JWS header has a kid (rust-spiffe rejects MissingKeyId)");
    assert!(!kid.is_empty(), "JWT-SVID kid is non-empty");

    eprintln!("WIRE-COMPAT: JWT-SVID alg={alg} kid={kid}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn workload_api_x509_wire_is_rust_spiffe_compatible() {
    if !on_path("bao") {
        eprintln!("SKIP: bao not found on PATH; SPIFFE wire-compat needs a live engine");
        return;
    }

    let harness = boot_basil(
        "spiffe-wire-compat",
        basil_tests::Engine::OpenBao,
        &alloc_addr(),
    );
    let mut client = SpiffeWorkloadApiClient::new(uds_channel(harness.socket()).await);

    assert_fetch_x509svid_wire(&mut client).await;
    assert_fetch_x509_bundles_wire(&mut client).await;
    assert_fetch_jwtsvid_alg(&mut client).await;

    drop(harness);
}
