// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Cross-engine SPIFFE X509-SVID (URI-SAN) issuance + x509 bundle/CRL e2e
//! over the live Workload API (basil-dk5.10).
//!
//! The SPIFFE URI-SAN X.509-SVID path (`Backend::issue_x509_svid`) and the
//! x509 bundle/CRL read are reachable ONLY through the `spiffe`-gated Workload
//! API streaming RPCs `FetchX509SVID` / `FetchX509Bundles`: the unary
//! `IssueCertificate` carries `common_name`/`dns_sans`/`ip_sans`/`ttl` only, no
//! URI-SAN. The interop test (`spiffe_interop.rs`, dk5.11) proves the high-level
//! rust-spiffe client drives Basil; the wire-compat test
//! (`spiffe_wire_compat.rs`, dk5.12) locks the raw protobuf encoding: both on
//! `OpenBao` only. THIS file is the CROSS-ENGINE acceptance: it boots a live
//! Basil agent over BOTH a dev `OpenBao` AND a dev `Vault` store and asserts, on each
//! engine independently, that:
//!
//!   - `FetchX509SVID` returns a leaf with a URI SAN `spiffe://example.org/<non-root>`,
//!     a leaf-first DER chain, `KeyUsage` `digitalSignature`, CA:FALSE.
//!   - `FetchX509Bundles` returns concatenated DER CA bundle(s) keyed by the
//!     trust-domain SPIFFE ID `spiffe://example.org` (no path, no trailing slash).
//!   - The CRL surface the Workload API exposes (`X509BundlesResponse.crl`) is
//!     exercised: each CRL blob, if present, is a parseable DER CRL. We record
//!     whether `OpenBao` vs `Vault` populates it on a fresh single-root mount.
//!   - The SAME issued material is parseable by the STANDARD rust-spiffe client
//!     (`spiffe::WorkloadApiClient`), proving downstream-consumer validity on
//!     both engines.
//!
//! We drive each engine with BOTH clients: the raw `basil-proto` tonic
//! `SpiffeWorkloadApiClient` (the high-level `spiffe` client decodes and HIDES
//! the `X509BundlesResponse.crl` field, so the CRL surface is only observable at
//! the raw boundary) AND the high-level `spiffe` client (for rust-spiffe
//! parseability). The raw client must attach the mandatory
//! `workload.spiffe.io: true` gRPC metadata header itself; the high-level client
//! adds it automatically.
//!
//! GATING: each engine leg is independently gated on its CLI (`bao`/`vault`)
//! being on PATH; an absent engine prints an EXPLICIT skip line (acceptance
//! forbids a silent `#[ignore]`). Both present => the test runs for real and
//! MUST pass on both.
//!
//! The boot harness lives in `tests/common/mod.rs`; see that file for the
//! crate-root no-panic-in-harness lint rationale. Each engine leg's `VAULT_ADDR`
//! comes from `basil_tests::alloc_addr()`, which hands out a disjoint port per call /
//! per test binary so the two dev servers never collide.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::allow_attributes,
    // The raw-wire decoders index into DER chains / SVID lists; a panic on a
    // malformed shape IS the intended test failure (same rationale as the
    // panic/unwrap allows, these fire only outside `#[test]` bodies).
    clippy::indexing_slicing,
    clippy::string_slice
)]

use basil_tests::{Engine, Harness, TRUST_DOMAIN, alloc_addr, boot_basil, on_path};

use basil_proto::spiffe::spiffe_workload_api_client::SpiffeWorkloadApiClient;
use basil_proto::spiffe::{X509BundlesRequest, X509svidRequest};

use hyper_util::rt::TokioIo;
use spiffe::WorkloadApiClient;
use tokio::net::UnixStream;
use tonic::Request;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

use x509_parser::prelude::FromDer;
use x509_parser::revocation_list::CertificateRevocationList;
use x509_parser::{
    certificate::X509Certificate, extensions::GeneralName, prelude::parse_x509_certificate,
};

type RawClient = SpiffeWorkloadApiClient<Channel>;

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

/// A raw tonic channel over Basil's unix socket (same connector shape the
/// `basil` client's `uds_channel` uses) so the generated SPIFFE client speaks to
/// the live agent and hands back undecoded protobuf bytes, including the
/// `X509BundlesResponse.crl` field the high-level client drops.
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
/// preserving order, exactly how rust-spiffe (and Go's `x509.ParseCertificates`)
/// walk a concatenated DER chain/bundle.
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
/// Returns the SPIFFE ID URI SAN.
fn assert_leaf_is_valid_x509_svid(engine: Engine, leaf: &X509Certificate<'_>) -> String {
    let san = leaf
        .subject_alternative_name()
        .expect("SAN extension parses")
        .unwrap_or_else(|| panic!("[{engine:?}] leaf has a SubjectAlternativeName extension"));
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
        "[{engine:?}] X.509-SVID leaf MUST carry exactly one URI SAN (got {uris:?})"
    );
    let spiffe_id = uris[0];
    let prefix = format!("spiffe://{TRUST_DOMAIN}/");
    assert!(
        spiffe_id.starts_with(&prefix),
        "[{engine:?}] URI SAN is a SPIFFE ID in {TRUST_DOMAIN} (got {spiffe_id})"
    );
    assert!(
        spiffe_id.len() > prefix.len(),
        "[{engine:?}] SPIFFE ID path is non-root (got {spiffe_id})"
    );

    let ku = leaf
        .key_usage()
        .expect("KeyUsage extension parses")
        .unwrap_or_else(|| panic!("[{engine:?}] leaf has a KeyUsage extension"))
        .value;
    assert!(
        ku.digital_signature(),
        "[{engine:?}] X.509-SVID leaf MUST assert digitalSignature key usage"
    );
    assert!(
        !ku.key_cert_sign(),
        "[{engine:?}] X.509-SVID leaf MUST NOT assert keyCertSign"
    );
    assert!(
        !ku.crl_sign(),
        "[{engine:?}] X.509-SVID leaf MUST NOT assert cRLSign"
    );

    assert!(
        !leaf.is_ca(),
        "[{engine:?}] X.509-SVID leaf MUST NOT be a CA cert"
    );
    if let Some(bc) = leaf.basic_constraints().expect("BasicConstraints parses") {
        assert!(
            !bc.value.ca,
            "[{engine:?}] X.509-SVID leaf BasicConstraints CA flag MUST be false"
        );
    }
    spiffe_id.to_string()
}

/// Every element of a concatenated DER CA bundle parses and is a CA cert.
fn assert_der_ca_bundle(engine: Engine, label: &str, der: &[u8]) -> usize {
    let certs = split_der_certs(der);
    assert!(
        !certs.is_empty(),
        "[{engine:?}] {label} decodes to a non-empty DER CA bundle"
    );
    for (i, ca_der) in certs.iter().enumerate() {
        let (_, ca) = X509Certificate::from_der(ca_der).expect("bundle element parses");
        assert!(
            ca.is_ca(),
            "[{engine:?}] {label} element {i} is a CA certificate"
        );
    }
    certs.len()
}

/// `FetchX509SVID` at the raw boundary: leaf-first DER chain, valid X.509-SVID
/// leaf, concatenated DER bundle. Returns the issued SPIFFE ID.
async fn assert_fetch_x509svid(engine: Engine, client: &mut RawClient) -> String {
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
        "[{engine:?}] X509SVIDResponse carries at least one SVID"
    );
    let entry = &resp.svids[0];

    assert!(
        entry
            .spiffe_id
            .starts_with(&format!("spiffe://{TRUST_DOMAIN}/")),
        "[{engine:?}] X509SVID.spiffe_id is a SPIFFE ID in {TRUST_DOMAIN} (got {})",
        entry.spiffe_id
    );

    let chain = split_der_certs(&entry.x509_svid);
    assert!(
        !chain.is_empty(),
        "[{engine:?}] X509SVID.x509_svid decodes to a non-empty DER chain"
    );
    let (_, leaf) = X509Certificate::from_der(&chain[0]).expect("first chain element parses");
    let leaf_id = assert_leaf_is_valid_x509_svid(engine, &leaf);
    assert_eq!(
        leaf_id, entry.spiffe_id,
        "[{engine:?}] leaf URI SAN matches the X509SVID.spiffe_id field"
    );
    // Post-leaf elements MUST be CAs, confirming leaf-first ordering.
    for (i, ca_der) in chain.iter().enumerate().skip(1) {
        let (_, ca) = X509Certificate::from_der(ca_der).expect("issuer chain element parses");
        assert!(
            ca.is_ca(),
            "[{engine:?}] x509_svid chain element {i} after the leaf is a CA (leaf-first ordering)"
        );
    }

    let bundle_len = assert_der_ca_bundle(engine, "X509SVID.bundle", &entry.bundle);
    eprintln!(
        "DK5.10 [{engine:?}]: FetchX509SVID id={} chain_len={} bundle_certs={bundle_len}",
        entry.spiffe_id,
        chain.len(),
    );
    leaf_id
}

/// `FetchX509Bundles` at the raw boundary: bundle map keyed by trust-domain
/// SPIFFE ID, concatenated DER CA values, and the CRL surface the Workload API
/// exposes (`X509BundlesResponse.crl`). Returns how many CRL blobs were present
/// so the caller can record per-engine CRL behavior.
async fn assert_fetch_x509_bundles(engine: Engine, client: &mut RawClient) -> usize {
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
        "[{engine:?}] X509BundlesResponse carries at least one bundle"
    );
    let td_key = format!("spiffe://{TRUST_DOMAIN}");
    assert!(
        resp.bundles.contains_key(&td_key),
        "[{engine:?}] X509BundlesResponse map keyed by trust-domain SPIFFE ID '{td_key}' (keys {:?})",
        resp.bundles.keys().collect::<Vec<_>>()
    );
    for (key, der) in &resp.bundles {
        assert!(
            key.starts_with("spiffe://"),
            "[{engine:?}] X509BundlesResponse map key is a SPIFFE trust-domain ID (got {key})"
        );
        assert!(
            !key.ends_with('/'),
            "[{engine:?}] trust-domain bundle key has no trailing slash (got {key})"
        );
        assert_der_ca_bundle(engine, &format!("X509BundlesResponse[{key}]"), der);
    }

    // CRL surface: the Workload API exposes CRLs via X509BundlesResponse.crl
    // (a Vec of DER blobs). On a fresh single-root PKI mount with no revocations
    // the engine may publish an EMPTY CRL, in which case the backend drops it and
    // this Vec is empty. That is a valid Workload API response. Whatever IS
    // present MUST be a parseable DER CertificateRevocationList.
    for (i, crl_der) in resp.crl.iter().enumerate() {
        assert!(
            !crl_der.is_empty(),
            "[{engine:?}] X509BundlesResponse.crl[{i}] is non-empty if present"
        );
        let (_, crl) = CertificateRevocationList::from_der(crl_der).unwrap_or_else(|e| {
            panic!("[{engine:?}] X509BundlesResponse.crl[{i}] is a parseable DER CRL: {e}")
        });
        // A fresh root's CRL lists no revoked certs.
        assert_eq!(
            crl.iter_revoked_certificates().count(),
            0,
            "[{engine:?}] fresh-root CRL lists no revoked certificates"
        );
    }

    eprintln!(
        "DK5.10 [{engine:?}]: FetchX509Bundles keys={:?} crl_blobs={}",
        resp.bundles.keys().collect::<Vec<_>>(),
        resp.crl.len(),
    );
    resp.crl.len()
}

/// Prove the issued material is valid to the STANDARD rust-spiffe client on this
/// engine: a default X.509-SVID in the trust domain with a non-empty chain, and
/// a non-empty X.509 bundle set. (The high-level client decodes/validates the
/// leaf the same way a downstream workload would.)
async fn assert_rust_spiffe_consumes(engine: Engine, harness: &Harness) {
    let endpoint = harness.endpoint();
    let client = WorkloadApiClient::connect_to(&endpoint)
        .await
        .expect("rust-spiffe WorkloadApiClient::connect_to Basil");

    let ctx = client
        .fetch_x509_context()
        .await
        .expect("fetch_x509_context");
    let svid = ctx
        .default_svid()
        .expect("rust-spiffe X.509 context has a default SVID");
    assert_eq!(
        svid.spiffe_id().trust_domain_name(),
        TRUST_DOMAIN,
        "[{engine:?}] rust-spiffe default SVID is in the configured trust domain"
    );
    assert!(
        !svid.cert_chain().is_empty(),
        "[{engine:?}] rust-spiffe default SVID cert chain is non-empty"
    );
    let id = svid.spiffe_id().to_string();
    assert!(
        id.starts_with(&format!("spiffe://{TRUST_DOMAIN}/"))
            && id.len() > format!("spiffe://{TRUST_DOMAIN}/").len(),
        "[{engine:?}] rust-spiffe SVID id is a non-root SPIFFE ID (got {id})"
    );

    let bundles = client
        .fetch_x509_bundles()
        .await
        .expect("fetch_x509_bundles");
    assert!(
        !bundles.is_empty(),
        "[{engine:?}] rust-spiffe X.509 bundle set is non-empty"
    );
    eprintln!("DK5.10 [{engine:?}]: rust-spiffe consumed X.509-SVID id={id}");
}

/// Full cross-engine drive for one engine: boot Basil over a fresh dev store,
/// then assert the X509-SVID + bundle/CRL Workload API surface (raw boundary)
/// and rust-spiffe parseability. Returns the count of CRL blobs surfaced.
async fn drive_engine(engine: Engine, tag: &str, addr: &str) -> usize {
    let harness = boot_basil(tag, engine, addr);

    let mut raw = SpiffeWorkloadApiClient::new(uds_channel(harness.socket()).await);
    let svid_id = assert_fetch_x509svid(engine, &mut raw).await;
    let crl_blobs = assert_fetch_x509_bundles(engine, &mut raw).await;
    drop(raw);

    assert_rust_spiffe_consumes(engine, &harness).await;

    eprintln!("DK5.10 [{engine:?}]: PASS (svid={svid_id}, crl_blobs={crl_blobs})");
    drop(harness);
    crl_blobs
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn x509_svid_uri_san_and_bundle_crl_e2e_cross_engine() {
    let mut ran_any = false;

    // ---- OpenBao leg -------------------------------------------------------
    let bao_crl = if on_path(Engine::OpenBao.cli_bin()) {
        ran_any = true;
        Some(drive_engine(Engine::OpenBao, "dk5.10-bao", &alloc_addr()).await)
    } else {
        eprintln!("SKIP: bao not on PATH; OpenBao SPIFFE X509-SVID leg skipped");
        None
    };

    // ---- Vault leg ---------------------------------------------------------
    let vault_crl = if on_path(Engine::Vault.cli_bin()) {
        ran_any = true;
        Some(drive_engine(Engine::Vault, "dk5.10-vault", &alloc_addr()).await)
    } else {
        eprintln!("SKIP: vault not on PATH; Vault SPIFFE X509-SVID leg skipped");
        None
    };

    // Cross-check the CRL surface behavior between engines when both ran. The
    // X509-SVID leaf / bundle / DER shapes are asserted identical-by-contract in
    // each leg above (same assertions on both engines). The CRL surface is the
    // one place a fresh-root engine divergence could show, so record it.
    if let (Some(b), Some(v)) = (bao_crl, vault_crl) {
        eprintln!("DK5.10 CROSS-ENGINE: OpenBao crl_blobs={b}, Vault crl_blobs={v}");
    }

    assert!(
        ran_any,
        "neither bao nor vault on PATH; cannot run cross-engine SPIFFE X509-SVID e2e"
    );
}
