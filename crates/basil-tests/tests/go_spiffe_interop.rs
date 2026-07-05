//! External go-spiffe Workload API probe (basil-mmfy.1).
//!
//! Boots a live Basil agent with the shared harness, runs a small Go program
//! that uses `github.com/spiffe/go-spiffe/v2/workloadapi` directly, and asserts
//! the structured JSON result. The Go probe exercises the standard client path
//! that attaches `workload.spiffe.io: true` for every Workload API RPC.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::allow_attributes
)]

use std::process::Command;

use basil_tests::{
    Engine, TRUST_DOMAIN, alloc_addr, boot_basil, boot_basil_with_svid_ttl, on_path, repo_root,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ProbeResult {
    trust_domain: String,
    #[serde(flatten)]
    x509: X509ProbeResult,
    #[serde(flatten)]
    jwt: JwtProbeResult,
    standard_client_header_path: bool,
}

#[derive(Debug, Deserialize)]
struct X509ProbeResult {
    #[serde(rename = "x509_context_ok")]
    context_ok: bool,
    #[serde(rename = "x509_context_svids")]
    context_svids: usize,
    #[serde(rename = "x509_context_bundles")]
    context_bundles: usize,
    #[serde(rename = "x509_svid_id")]
    svid_id: String,
    #[serde(rename = "x509_svid_chain_len")]
    svid_chain_len: usize,
    #[serde(rename = "x509_svid_has_private_key")]
    svid_has_private_key: bool,
    #[serde(rename = "x509_bundles")]
    bundles: usize,
}

#[derive(Debug, Deserialize)]
struct JwtProbeResult {
    #[serde(rename = "jwt_svid_id")]
    svid_id: String,
    #[serde(rename = "jwt_svid_audience_ok")]
    svid_audience_ok: bool,
    #[serde(rename = "jwt_svid_token_non_empty")]
    svid_token_non_empty: bool,
    #[serde(rename = "jwt_bundles")]
    bundles: usize,
    #[serde(rename = "validate_jwt_svid_ok")]
    validate_svid_ok: bool,
    #[serde(rename = "validate_jwt_svid_id")]
    validate_svid_id: String,
}

#[derive(Debug, Deserialize)]
struct ExampleProbeResult {
    #[serde(flatten)]
    x509_source: ExampleX509SourceResult,
    #[serde(flatten)]
    jwt_source: ExampleJwtSourceResult,
    #[serde(flatten)]
    mtls: ExampleMtlsResult,
    #[serde(flatten)]
    jwt: ExampleJwtResult,
    configurable_socket_and_ids: bool,
    used_standard_example_surfaces: bool,
}

#[derive(Debug, Deserialize)]
struct ExampleX509SourceResult {
    #[serde(rename = "x509_source_initial_update")]
    initial_update: bool,
    #[serde(rename = "x509_source_rotation_update")]
    rotation_update: bool,
    #[serde(rename = "x509_source_rotated_leaf")]
    rotated_leaf: bool,
    #[serde(rename = "x509_source_svid_id")]
    svid_id: String,
}

#[derive(Debug, Deserialize)]
struct ExampleJwtSourceResult {
    #[serde(rename = "jwt_source_initial_update")]
    initial_update: bool,
}

#[derive(Debug, Deserialize)]
struct ExampleMtlsResult {
    #[serde(rename = "mtls_success")]
    success: bool,
    #[serde(rename = "mtls_rejected_wrong_server_id")]
    rejected_wrong_server_id: bool,
    #[serde(rename = "mtls_rejected_wrong_client_id")]
    rejected_wrong_client_id: bool,
    #[serde(rename = "mtls_peer_id")]
    peer_id: String,
}

#[derive(Debug, Deserialize)]
struct ExampleJwtResult {
    #[serde(rename = "jwt_http_success")]
    http_success: bool,
    #[serde(rename = "jwt_wrong_audience_rejected")]
    wrong_audience_rejected: bool,
    #[serde(rename = "jwt_validated_subject")]
    validated_subject: String,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn go_spiffe_workload_api_probe_interops_with_basil() {
    if !on_path("go") {
        eprintln!("SKIP: go not found on PATH; go-spiffe interop probe needs Go");
        return;
    }
    if !on_path("bao") {
        eprintln!("SKIP: bao not found on PATH; go-spiffe interop probe needs a live engine");
        return;
    }

    let harness = boot_basil("go-spiffe-interop", Engine::OpenBao, &alloc_addr());
    let result = run_probe(&harness.endpoint());

    assert_eq!(result.trust_domain, TRUST_DOMAIN);
    assert!(result.x509.context_ok, "FetchX509Context succeeded");
    assert!(result.x509.context_svids >= 1, "x509 context has SVIDs");
    assert!(result.x509.context_bundles >= 1, "x509 context has bundles");
    assert!(
        result.x509.svid_id.starts_with("spiffe://example.org/"),
        "x509 SVID ID is in trust domain: {}",
        result.x509.svid_id
    );
    assert!(result.x509.svid_chain_len >= 1, "x509 SVID has a chain");
    assert!(
        result.x509.svid_has_private_key,
        "standard Workload API returns the workload's own private key"
    );
    assert!(result.x509.bundles >= 1, "x509 bundle set is non-empty");
    assert!(
        result.jwt.svid_id.starts_with("spiffe://example.org/"),
        "JWT-SVID ID is in trust domain: {}",
        result.jwt.svid_id
    );
    assert!(
        result.jwt.svid_audience_ok,
        "JWT-SVID includes requested audience"
    );
    assert!(
        result.jwt.svid_token_non_empty,
        "JWT-SVID token is non-empty"
    );
    assert!(result.jwt.bundles >= 1, "JWT bundle set is non-empty");
    assert!(result.jwt.validate_svid_ok, "ValidateJWTSVID succeeded");
    assert_eq!(result.jwt.validate_svid_id, result.jwt.svid_id);
    assert!(
        result.standard_client_header_path,
        "go-spiffe standard client attached the required Workload API metadata"
    );

    drop(harness);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn go_spiffe_example_probes_interop_with_basil() {
    if !on_path("go") {
        eprintln!("SKIP: go not found on PATH; go-spiffe example probes need Go");
        return;
    }
    if !on_path("bao") {
        eprintln!("SKIP: bao not found on PATH; go-spiffe example probes need a live engine");
        return;
    }

    let harness = boot_basil_with_svid_ttl(
        "go-spiffe-examples-interop",
        Engine::OpenBao,
        &alloc_addr(),
        4,
    );
    let result = run_example_probe(&harness.endpoint());

    assert!(
        result.x509_source.initial_update,
        "X509Source observed initial Workload API update"
    );
    assert!(
        result.x509_source.rotation_update,
        "X509Source observed short-TTL rotation update"
    );
    assert!(
        result.x509_source.rotated_leaf,
        "X509Source leaf changed after rotation"
    );
    assert!(
        result
            .x509_source
            .svid_id
            .starts_with("spiffe://example.org/"),
        "X509Source SVID ID is in trust domain: {}",
        result.x509_source.svid_id
    );
    assert!(
        result.jwt_source.initial_update,
        "JWTSource observed initial bundle update"
    );
    assert!(result.mtls.success, "go-spiffe mTLS request succeeded");
    assert_eq!(result.mtls.peer_id, result.x509_source.svid_id);
    assert!(
        result.mtls.rejected_wrong_server_id,
        "mTLS client rejected an unexpected server SPIFFE ID"
    );
    assert!(
        result.mtls.rejected_wrong_client_id,
        "mTLS server rejected an unexpected client SPIFFE ID"
    );
    assert!(
        result.jwt.http_success,
        "JWT-SVID HTTP example request succeeded"
    );
    assert_eq!(result.jwt.validated_subject, result.x509_source.svid_id);
    assert!(
        result.jwt.wrong_audience_rejected,
        "JWT-SVID HTTP server rejected a wrong-audience token"
    );
    assert!(
        result.configurable_socket_and_ids,
        "probe used runtime socket and SPIFFE IDs"
    );
    assert!(
        result.used_standard_example_surfaces,
        "probe used go-spiffe source/tlsconfig/jwtsvid surfaces"
    );

    drop(harness);
}

fn run_probe(endpoint: &str) -> ProbeResult {
    run_go_probe(endpoint, &[])
}

fn run_example_probe(endpoint: &str) -> ExampleProbeResult {
    run_go_probe(endpoint, &["examples"])
}

fn run_go_probe<T>(endpoint: &str, args: &[&str]) -> T
where
    T: serde::de::DeserializeOwned,
{
    let root = repo_root();
    let probe_dir = root.join("interop-tests/go-spiffe");
    let mut command_args = vec!["run", "."];
    command_args.extend_from_slice(args);
    let output = Command::new("go")
        .args(command_args)
        .current_dir(&probe_dir)
        .env("SPIFFE_ENDPOINT_SOCKET", endpoint)
        .env("BASIL_SPIFFE_TRUST_DOMAIN", TRUST_DOMAIN)
        .env("BASIL_SPIFFE_AUDIENCE", "basil-go-spiffe-probe")
        .output()
        .expect("spawn go-spiffe probe");

    assert!(
        output.status.success(),
        "go-spiffe probe failed with status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "go-spiffe probe output was not JSON: {err}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}
