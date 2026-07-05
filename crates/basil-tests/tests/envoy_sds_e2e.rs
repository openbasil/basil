// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Live Envoy SDS validation against Basil's Envoy SDS adapter.
//!
//! This test boots the existing live OpenBao-backed Basil harness, hot-reloads
//! two SDS resource labels onto the X.509-SVID issuer, then starts Envoy with a
//! downstream TLS context whose certificate and validation-context secrets come
//! from Basil over SDS on the broker Unix socket. The assertion is Envoy-side:
//! its admin config dump must show active dynamic secrets for both configured
//! resources.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::allow_attributes
)]

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use basil::Client;
use basil_tests::{Engine, alloc_addr, boot_basil, on_path};

const CERT_RESOURCE: &str = "default";
const BUNDLE_RESOURCE: &str = "ROOTCA";
const RELOAD_POLL: Duration = Duration::from_secs(10);
const ENVOY_POLL: Duration = Duration::from_secs(20);
const TICK: Duration = Duration::from_millis(100);

struct EnvoyChild {
    child: Child,
}

impl Drop for EnvoyChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn generation(client: &mut Client) -> u64 {
    client
        .readiness()
        .await
        .expect("readiness RPC succeeds")
        .generation
}

async fn wait_for_generation(client: &mut Client, want: u64) {
    let deadline = Instant::now() + RELOAD_POLL;
    loop {
        let got = generation(client).await;
        if got == want {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "generation never reached {want} within {RELOAD_POLL:?} (last seen {got})"
        );
        tokio::time::sleep(TICK).await;
    }
}

fn add_sds_labels(catalog_path: &Path) {
    let text = std::fs::read_to_string(catalog_path).expect("read catalog fixture");
    let mut catalog: serde_json::Value =
        serde_json::from_str(&text).expect("catalog is valid JSON");
    let labels = catalog
        .get_mut("keys")
        .and_then(|keys| keys.get_mut("spiffe.x509_issuer"))
        .and_then(|key| key.get_mut("labels"))
        .and_then(serde_json::Value::as_array_mut)
        .expect("spiffe.x509_issuer has labels");
    for label in [
        format!("envoy_sds_certificate_resource={CERT_RESOURCE}"),
        format!("envoy_sds_validation_context_resource={BUNDLE_RESOURCE}"),
    ] {
        if !labels
            .iter()
            .any(|value| value.as_str() == Some(label.as_str()))
        {
            labels.push(serde_json::Value::String(label));
        }
    }
    std::fs::write(
        catalog_path,
        serde_json::to_vec_pretty(&catalog).expect("reserialize catalog"),
    )
    .expect("write edited catalog fixture");
}

fn port_from_alloc_addr(addr: &str) -> u16 {
    addr.rsplit_once(':')
        .expect("allocated addr has a port")
        .1
        .parse()
        .expect("allocated port is numeric")
}

fn envoy_config(basil_socket: &Path, admin_port: u16, listener_port: u16, config_path: &Path) {
    let socket = basil_socket.display();
    let config = format!(
        r#"
node:
  id: envoy-sds-e2e
  cluster: basil-tests

admin:
  address:
    socket_address:
      address: 127.0.0.1
      port_value: {admin_port}

static_resources:
  clusters:
  - name: basil_sds
    type: STATIC
    connect_timeout: 1s
    http2_protocol_options: {{}}
    load_assignment:
      cluster_name: basil_sds
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              pipe:
                path: "{socket}"

  listeners:
  - name: sds_acceptance
    address:
      socket_address:
        address: 127.0.0.1
        port_value: {listener_port}
    filter_chains:
    - transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          common_tls_context:
            tls_certificate_sds_secret_configs:
            - name: {CERT_RESOURCE}
              sds_config:
                resource_api_version: V3
                api_config_source:
                  api_type: GRPC
                  transport_api_version: V3
                  grpc_services:
                  - envoy_grpc:
                      cluster_name: basil_sds
            validation_context_sds_secret_config:
              name: {BUNDLE_RESOURCE}
              sds_config:
                resource_api_version: V3
                api_config_source:
                  api_type: GRPC
                  transport_api_version: V3
                  grpc_services:
                  - envoy_grpc:
                      cluster_name: basil_sds
      filters:
      - name: envoy.filters.network.tcp_proxy
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
          stat_prefix: sds_acceptance
          cluster: basil_sds
"#
    );
    std::fs::write(config_path, config).expect("write Envoy config");
}

fn spawn_envoy(config_path: &Path, log_path: &Path) -> EnvoyChild {
    let log = std::fs::File::create(log_path).expect("create Envoy log");
    let child = Command::new("envoy")
        .arg("-c")
        .arg(config_path)
        .args(["--log-level", "warning"])
        .stdout(Stdio::from(log.try_clone().expect("clone Envoy log")))
        .stderr(Stdio::from(log))
        .spawn()
        .expect("spawn Envoy");
    EnvoyChild { child }
}

async fn wait_for_envoy_sds(admin_port: u16, log_path: &Path) {
    let url = format!("http://127.0.0.1:{admin_port}/config_dump");
    let deadline = Instant::now() + ENVOY_POLL;
    loop {
        if let Ok(resp) = reqwest::get(&url).await
            && let Ok(body) = resp.text().await
            && body.contains("dynamic_active_secrets")
            && body.contains(CERT_RESOURCE)
            && body.contains(BUNDLE_RESOURCE)
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "Envoy did not publish active SDS secrets within {ENVOY_POLL:?}; log: {}",
            std::fs::read_to_string(log_path).unwrap_or_else(|_| "<unreadable>".to_string())
        );
        tokio::time::sleep(TICK).await;
    }
}

#[tokio::test]
async fn envoy_fetches_basil_sds_leaf_key_and_bundle() {
    if !on_path(Engine::OpenBao.cli_bin()) {
        eprintln!("SKIP envoy_sds_e2e: bao not on PATH");
        return;
    }
    if !on_path("envoy") {
        eprintln!("SKIP envoy_sds_e2e: envoy not on PATH");
        return;
    }

    let harness = boot_basil("envoy-sds", Engine::OpenBao, &alloc_addr());
    let socket = harness.socket();
    let mut client = Client::connect(socket.to_str().expect("socket path is UTF-8"))
        .await
        .expect("connect basil client to broker socket");
    assert_eq!(generation(&mut client).await, 1);

    add_sds_labels(&harness.catalog_path());
    harness.sighup_agent();
    wait_for_generation(&mut client, 2).await;

    let admin_port = port_from_alloc_addr(&alloc_addr());
    let listener_port = port_from_alloc_addr(&alloc_addr());
    let config_path = harness.fixtures().join("envoy-sds.yaml");
    let log_path = harness.fixtures().join("envoy-sds.log");
    envoy_config(&socket, admin_port, listener_port, &config_path);
    let _envoy = spawn_envoy(&config_path, &log_path);

    wait_for_envoy_sds(admin_port, &log_path).await;
}
