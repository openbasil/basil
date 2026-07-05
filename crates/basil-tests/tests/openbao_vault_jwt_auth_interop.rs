//! OpenBao/Vault JWT auth interop for Basil-published JWT-SVID JWKS.
//!
//! This lane configures a live engine's JWT auth method to validate Basil
//! JWT-SVIDs from the broker's opt-in `/jwks.json` surface. It proves the
//! engine accepts a correctly-audienced Basil-minted token and rejects
//! wrong-audience and tampered tokens.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::allow_attributes
)]

use std::process::{Command, Stdio};

use basil_tests::{
    Engine, JwksSpec, TRUST_DOMAIN, alloc_addr, boot_basil_spiffe, fetch_jwt_svid, on_path,
};
use serde::Deserialize;

const AUTH_MOUNT: &str = "basil-jwt-svid";
const AUTH_ROLE: &str = "basil-jwt-svid";
const AUDIENCE: &str = "basil-jwt-auth-interop";
const TEST_POLICY: &str = "basil-prefill-test";

#[derive(Debug, Deserialize)]
struct LoginResponse {
    auth: LoginAuth,
}

#[derive(Debug, Deserialize)]
struct LoginAuth {
    client_token: String,
    policies: Vec<String>,
}

fn bind_addr(alloc: &str) -> String {
    alloc
        .strip_prefix("http://")
        .expect("alloc_addr returns http://host:port")
        .to_string()
}

async fn wait_for_jwks(client: &reqwest::Client, jwks_url: &str) {
    let mut last_err = None;
    for _ in 0..50 {
        match client.get(jwks_url).send().await {
            Ok(resp) if resp.status().is_success() => return,
            Ok(resp) => last_err = Some(format!("status {}", resp.status())),
            Err(err) => last_err = Some(err.to_string()),
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("JWKS endpoint never served {jwks_url}: {last_err:?}");
}

async fn drive_engine(engine: Engine, tag: &str) {
    let dev_addr = alloc_addr();
    let listen = bind_addr(&alloc_addr());
    let issuer = format!("http://{listen}");
    let jwks_spec = JwksSpec {
        listen,
        issuer: Some(issuer.clone()),
    };
    let harness = boot_basil_spiffe(tag, engine, &dev_addr, Some(&jwks_spec));
    let endpoint = harness.endpoint();
    let jwks_url = format!("{issuer}/jwks.json");
    wait_for_jwks(&reqwest::Client::new(), &jwks_url).await;

    configure_jwt_auth(engine, harness.backend_addr(), &jwks_url);

    let good = fetch_jwt_svid(&endpoint, AUDIENCE).await;
    let login =
        login_with_jwt(engine, harness.backend_addr(), &good).expect("good JWT-SVID logs in");
    assert!(
        !login.auth.client_token.is_empty(),
        "engine returned a client token"
    );
    assert!(
        login
            .auth
            .policies
            .iter()
            .any(|policy| policy == TEST_POLICY),
        "login token carries expected policy {TEST_POLICY}: {:?}",
        login.auth.policies
    );

    let wrong_audience = fetch_jwt_svid(&endpoint, "basil-jwt-auth-wrong-audience").await;
    assert!(
        login_with_jwt(engine, harness.backend_addr(), &wrong_audience).is_err(),
        "engine rejects JWT-SVID minted for the wrong audience"
    );

    let tampered = tamper_jwt_signature(&good);
    assert!(
        login_with_jwt(engine, harness.backend_addr(), &tampered).is_err(),
        "engine rejects a tampered JWT-SVID signature"
    );

    drop(harness);
}

fn configure_jwt_auth(engine: Engine, addr: &str, jwks_url: &str) {
    let cli = engine.cli_bin();
    let _ = Command::new(cli)
        .args(["auth", "disable", AUTH_MOUNT])
        .env("VAULT_ADDR", addr)
        .env("VAULT_TOKEN", "root")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    let enable = Command::new(cli)
        .args(["auth", "enable", &format!("-path={AUTH_MOUNT}"), "jwt"])
        .env("VAULT_ADDR", addr)
        .env("VAULT_TOKEN", "root")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap_or_else(|err| panic!("spawn {cli} auth enable: {err}"));
    assert!(enable.success(), "{cli} auth enable {AUTH_MOUNT} failed");

    let config = Command::new(cli)
        .args([
            "write",
            &format!("auth/{AUTH_MOUNT}/config"),
            &format!("jwks_url={jwks_url}"),
        ])
        .env("VAULT_ADDR", addr)
        .env("VAULT_TOKEN", "root")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap_or_else(|err| panic!("spawn {cli} jwt config: {err}"));
    assert!(config.success(), "{cli} jwt config failed");

    let expected_subject = format!("spiffe://{TRUST_DOMAIN}/test-runner");
    let role = Command::new(cli)
        .args([
            "write",
            &format!("auth/{AUTH_MOUNT}/role/{AUTH_ROLE}"),
            "role_type=jwt",
            "user_claim=sub",
            &format!("bound_subject={expected_subject}"),
            &format!("bound_audiences={AUDIENCE}"),
            &format!("token_policies={TEST_POLICY}"),
            "token_ttl=5m",
            "token_max_ttl=15m",
        ])
        .env("VAULT_ADDR", addr)
        .env("VAULT_TOKEN", "root")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap_or_else(|err| panic!("spawn {cli} jwt role: {err}"));
    assert!(role.success(), "{cli} jwt role failed");
}

fn login_with_jwt(engine: Engine, addr: &str, token: &str) -> Result<LoginResponse, String> {
    let cli = engine.cli_bin();
    let output = Command::new(cli)
        .args([
            "write",
            "-format=json",
            &format!("auth/{AUTH_MOUNT}/login"),
            &format!("role={AUTH_ROLE}"),
            &format!("jwt={token}"),
        ])
        .env("VAULT_ADDR", addr)
        .env("VAULT_TOKEN", "root")
        .output()
        .map_err(|err| format!("spawn {cli} jwt login: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "status {:?}\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    serde_json::from_slice(&output.stdout).map_err(|err| {
        format!(
            "decode jwt login JSON: {err}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn tamper_jwt_signature(token: &str) -> String {
    let mut parts: Vec<String> = token.split('.').map(ToString::to_string).collect();
    assert_eq!(parts.len(), 3, "JWT has three segments");
    let sig = parts
        .get_mut(2)
        .expect("signature segment exists after length check");
    let first = sig
        .as_bytes()
        .first()
        .copied()
        .expect("signature segment is non-empty");
    sig.replace_range(0..1, if first == b'A' { "B" } else { "A" });
    parts.join(".")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn basil_jwt_svid_logs_into_openbao_or_vault_jwt_auth() {
    let ran_bao = if on_path("bao") {
        drive_engine(Engine::OpenBao, "jwt-auth-interop-bao").await;
        true
    } else {
        eprintln!("SKIP[openbao]: bao not on PATH; JWT auth interop needs a live engine");
        false
    };

    let ran_vault = if on_path("vault") {
        drive_engine(Engine::Vault, "jwt-auth-interop-vault").await;
        true
    } else {
        eprintln!("SKIP[vault]: vault not on PATH; JWT auth interop needs a live engine");
        false
    };

    assert!(
        ran_bao || ran_vault,
        "neither bao nor vault was on PATH; JWT auth interop ran no engine leg"
    );
}
