// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Cross-engine LIVE e2e for DNS/IP-SAN X.509 TLS leaf issuance from a real
//! backend PKI engine (basil-0jkw / basil-5qur) over the broker gRPC, on BOTH a
//! dev `OpenBao` AND a dev `Vault` store.
//!
//! The routing layer (`manager.issue_x509_cert` -> `pki/issue/<role>`) is
//! unit-tested against a mock backend (`manager.rs`
//! `issue_x509_cert_routes_to_pki_issue_path_with_sans`), but nothing issued a
//! REAL leaf from a live engine PKI and PARSED it to confirm the requested DNS
//! names and IP addresses actually land in the certificate's `SubjectAltName`.
//! The SPIFFE X509-SVID e2e (`spiffe_x509_svid_e2e.rs`) only covers URI-SAN
//! (SPIFFE ID) leaves: the unary `IssueCertificate` RPC carries
//! `common_name`/`dns_sans`/`ip_sans`/`ttl` and no URI SAN. THIS file is that
//! DNS/IP-SAN acceptance.
//!
//! What the harness sets up (see `scripts/prefill-test-store.sh` +
//! `basil_tests::boot_basil`): the prefill enables a `pki` engine, generates an
//! internal root CA, and creates an issue role (`pki/issue/basil-leaf`) that
//! allows the `example.org` domain + subdomains AND IP SANs. The catalog key
//! `web.tls.cert_issuer` routes to that role, and the running uid holds
//! `role:minter` (`mint`) over it. The CA private key stays in the engine; the
//! broker brokers issuance and releases only the leaf + its private key.
//!
//! On each engine the test, driving the `basil` client over the broker's unix
//! socket, issues a leaf carrying BOTH DNS SANs (subdomains of `example.org`)
//! AND IP SANs, then parses the returned leaf DER and asserts:
//!   (a) every requested DNS name is present in the leaf's `SubjectAltName`;
//!   (b) every requested IP address is present in the leaf's `SubjectAltName`;
//!   (c) the leaf is an end-entity TLS cert (CA:FALSE, `digitalSignature`);
//!   (d) the returned chain + issuing-CA bundle parse as real certificates and
//!       the leaf private key is released (a TLS server needs it).
//!
//! GATING: each engine leg is independently gated on its CLI (`bao`/`vault`)
//! being on PATH; an absent engine prints an EXPLICIT skip line (acceptance
//! forbids a silent `#[ignore]`). `ran_any` asserts at least one leg ran, so an
//! all-absent environment FAILS loudly rather than passing vacuously.
//!
//! Each engine leg's `VAULT_ADDR` comes from `basil_tests::alloc_addr()`, which
//! hands out a disjoint port per call / per test binary so the two dev servers
//! (and the concurrently-running live tests) never collide on a port.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::allow_attributes,
    // The DER decoders index into chains; a panic on a malformed shape IS the
    // intended test failure (same rationale as the panic/unwrap allows).
    clippy::indexing_slicing
)]

use basil_tests::{Engine, alloc_addr, boot_basil, on_path};

use basil::Client;

use std::net::Ipv4Addr;

use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, parse_x509_certificate};

/// Catalog name of the PKI issue-role key the prefill provisions for DNS/IP-SAN
/// TLS leaf issuance (see `scripts/prefill-test-store.sh`, `pki/issue/basil-leaf`).
const ISSUER: &str = "web.tls.cert_issuer";

/// DNS SANs to request: subdomains of the prefill role's `allowed_domains`
/// (`example.org`, `allow_subdomains=true`), so issuance is authorized.
const DNS_SANS: [&str; 2] = ["svc.example.org", "api.example.org"];

/// IP SANs to request: the prefill role sets `allow_ip_sans=true`, so any IP is
/// authorized. One loopback + one private-range address to prove multiple land.
const IP_SANS: [Ipv4Addr; 2] = [Ipv4Addr::LOCALHOST, Ipv4Addr::new(10, 9, 8, 7)];

/// Collect the DNS names and IPv4 addresses from a leaf's `SubjectAltName`.
fn leaf_sans(leaf: &X509Certificate<'_>) -> (Vec<String>, Vec<Ipv4Addr>) {
    let san = leaf
        .subject_alternative_name()
        .expect("SAN extension parses")
        .expect("leaf has a SubjectAlternativeName extension");
    let mut dns = Vec::new();
    let mut ips = Vec::new();
    for gn in &san.value.general_names {
        match gn {
            GeneralName::DNSName(name) => dns.push((*name).to_string()),
            GeneralName::IPAddress(bytes) => {
                let octets: [u8; 4] = (*bytes)
                    .try_into()
                    .expect("IPv4 SAN is 4 bytes (this test only requests IPv4)");
                ips.push(Ipv4Addr::from(octets));
            }
            _ => {}
        }
    }
    (dns, ips)
}

/// Drive one engine end to end: boot the broker against a freshly-prefilled
/// `engine` store, issue a DNS+IP-SAN TLS leaf from the live PKI engine, and
/// prove the requested SANs actually land in the issued certificate.
async fn drive_engine(engine: Engine, tag: &str, addr: &str) {
    let harness = boot_basil(tag, engine, addr);
    let socket = harness.socket();
    let socket_str = socket.to_str().expect("socket path is UTF-8");

    let mut client = Client::connect(socket_str)
        .await
        .expect("connect basil client to the broker socket");

    let dns_req: Vec<String> = DNS_SANS.iter().map(|s| (*s).to_string()).collect();
    let ip_req: Vec<String> = IP_SANS
        .iter()
        .map(std::string::ToString::to_string)
        .collect();

    let issued = client
        .issue_certificate(ISSUER, DNS_SANS[0], &dns_req, &ip_req, 3600)
        .await
        .expect("issue a DNS/IP-SAN TLS leaf from the live PKI engine");

    // (d) The broker released a leaf-first chain, an issuing-CA bundle, and the
    //     leaf private key (a TLS server needs the key to terminate).
    assert!(
        !issued.cert_chain_der.is_empty(),
        "[{}] issued cert chain is non-empty",
        engine.prefill_name()
    );
    assert!(
        !issued.private_key_der.is_empty(),
        "[{}] the leaf private key is released to the caller",
        engine.prefill_name()
    );
    assert!(
        !issued.ca_chain_der.is_empty(),
        "[{}] the issuing-CA / trust bundle is returned",
        engine.prefill_name()
    );
    for (i, ca_der) in issued.ca_chain_der.iter().enumerate() {
        let (_, ca) = X509Certificate::from_der(ca_der)
            .unwrap_or_else(|e| panic!("ca_chain_der[{i}] is a parseable DER certificate: {e}"));
        assert!(
            ca.is_ca(),
            "[{}] ca_chain_der[{i}] is a CA certificate",
            engine.prefill_name()
        );
    }

    let (_, leaf) = parse_x509_certificate(&issued.cert_chain_der[0])
        .expect("issued leaf (chain element 0) is a parseable DER certificate");

    // (a) + (b) Every requested DNS name AND IP address is in the leaf SAN.
    let (dns, ips) = leaf_sans(&leaf);
    for want in DNS_SANS {
        assert!(
            dns.iter().any(|d| d.as_str() == want),
            "[{}] issued leaf SAN carries requested DNS name {want} (got DNS {dns:?})",
            engine.prefill_name()
        );
    }
    for want in IP_SANS {
        assert!(
            ips.contains(&want),
            "[{}] issued leaf SAN carries requested IP address {want} (got IP {ips:?})",
            engine.prefill_name()
        );
    }

    // (c) The leaf is an end-entity TLS cert: CA:FALSE + digitalSignature usage.
    assert!(
        !leaf.is_ca(),
        "[{}] issued TLS leaf MUST NOT be a CA cert",
        engine.prefill_name()
    );
    if let Some(ku) = leaf.key_usage().expect("KeyUsage parses") {
        assert!(
            ku.value.digital_signature(),
            "[{}] issued TLS leaf asserts digitalSignature key usage",
            engine.prefill_name()
        );
    }

    drop(client);
    eprintln!(
        "PKI-LEAF-SAN[{}]: issued leaf carries DNS {dns:?} + IP {ips:?} (CA:FALSE), SANs verified",
        engine.prefill_name()
    );
    drop(harness);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pki_dns_ip_san_leaf_issuance_cross_engine() {
    let ran_bao = if on_path("bao") {
        drive_engine(Engine::OpenBao, "pki-leaf-bao", &alloc_addr()).await;
        true
    } else {
        eprintln!("SKIP: bao not found on PATH; PKI DNS/IP-SAN leaf e2e needs a live OpenBao");
        false
    };

    let ran_vault = if on_path("vault") {
        drive_engine(Engine::Vault, "pki-leaf-vault", &alloc_addr()).await;
        true
    } else {
        eprintln!("SKIP: vault not found on PATH; PKI DNS/IP-SAN leaf e2e needs a live Vault");
        false
    };

    assert!(
        ran_bao || ran_vault,
        "neither bao nor vault was on PATH; the PKI DNS/IP-SAN leaf live e2e ran no engine leg \
         (this is a live cross-engine acceptance test; it must not pass vacuously)"
    );
}
