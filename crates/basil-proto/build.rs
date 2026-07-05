// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protos = [
        "proto/basil/broker/v1/broker.proto",
        "proto/google/rpc/status.proto",
        "proto/spiffe/workloadapi.proto",
        "proto/envoy/config/core/v3/address.proto",
        "proto/envoy/config/core/v3/backoff.proto",
        "proto/envoy/config/core/v3/extension.proto",
        "proto/envoy/config/core/v3/health_check.proto",
        "proto/envoy/config/endpoint/v3/endpoint.proto",
        "proto/envoy/config/route/v3/route_components.proto",
        "proto/envoy/extensions/transport_sockets/tls/v3/secret.proto",
        "proto/envoy/service/secret/v3/sds.proto",
    ];

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&protos, &["proto"])?;

    println!("cargo:rerun-if-changed=proto/basil/broker/v1/broker.proto");
    println!("cargo:rerun-if-changed=proto/google/rpc/status.proto");
    println!("cargo:rerun-if-changed=proto/spiffe/workloadapi.proto");
    println!("cargo:rerun-if-changed=proto/envoy/config/core/v3/base.proto");
    println!("cargo:rerun-if-changed=proto/envoy/config/core/v3/address.proto");
    println!("cargo:rerun-if-changed=proto/envoy/config/core/v3/backoff.proto");
    println!("cargo:rerun-if-changed=proto/envoy/config/core/v3/extension.proto");
    println!("cargo:rerun-if-changed=proto/envoy/config/core/v3/health_check.proto");
    println!("cargo:rerun-if-changed=proto/envoy/config/endpoint/v3/endpoint.proto");
    println!("cargo:rerun-if-changed=proto/envoy/config/route/v3/route_components.proto");
    println!("cargo:rerun-if-changed=proto/envoy/extensions/transport_sockets/tls/v3/common.proto");
    println!("cargo:rerun-if-changed=proto/envoy/extensions/transport_sockets/tls/v3/secret.proto");
    println!("cargo:rerun-if-changed=proto/envoy/service/discovery/v3/discovery.proto");
    println!("cargo:rerun-if-changed=proto/envoy/service/secret/v3/sds.proto");
    println!("cargo:rerun-if-changed=proto/xds/core/v3/resource.proto");

    Ok(())
}
