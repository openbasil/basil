// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

use prost::Message as _;

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

    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR")?);

    let broker_descriptor = out_dir.join("broker_descriptor.bin");
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        // Emit the compiled `FileDescriptorSet` so downstream crates can key
        // compiled per-method registries (work-class classification, admission)
        // on the same generated service/method names tonic routes by, instead
        // of hand-typed path strings.
        .file_descriptor_set_path(&broker_descriptor)
        // broker.proto uses proto3 `optional` fields. protoc stabilized these in
        // 3.15, but older toolchains (e.g. Ubuntu 22.04's apt protoc 3.12.4)
        // reject them unless this flag is set. Newer protoc accept it as a no-op,
        // so passing it unconditionally keeps the build working across every
        // runner and the Nix flake without depending on the installed protoc.
        .protoc_arg("--experimental_allow_proto3_optional")
        .compile_protos(&protos, &["proto"])?;

    let nix_out_dir = out_dir.join("nix_cache");
    std::fs::create_dir_all(&nix_out_dir)?;
    let nix_descriptor = out_dir.join("nix_cache_descriptor.bin");
    tonic_prost_build::configure()
        .build_server(false)
        .build_client(false)
        .out_dir(&nix_out_dir)
        .file_descriptor_set_path(&nix_descriptor)
        .compile_protos(&["proto/basil/broker/v1/nix_cache.proto"], &["proto"])?;

    let mut descriptors =
        prost_types::FileDescriptorSet::decode(std::fs::read(broker_descriptor)?.as_slice())?;
    let nix_descriptors =
        prost_types::FileDescriptorSet::decode(std::fs::read(nix_descriptor)?.as_slice())?;
    descriptors.file.extend(nix_descriptors.file);
    std::fs::write(
        out_dir.join("basil_descriptor.bin"),
        descriptors.encode_to_vec(),
    )?;

    let method = |name: &str, route_name: &str, input: &str, output: &str| {
        tonic_build::manual::Method::builder()
            .name(name)
            .route_name(route_name)
            .input_type(input)
            .output_type(output)
            .codec_path("crate::codec::StrictProstCodec")
            .build()
    };
    let nix_cache_service = tonic_build::manual::Service::builder()
        .name("NixCacheService")
        .package("basil.broker.v1")
        .method(method(
            "describe_nix_cache_key",
            "DescribeNixCacheKey",
            "super::DescribeNixCacheKeyRequest",
            "super::DescribeNixCacheKeyResponse",
        ))
        .method(method(
            "enroll_nix_cache_key",
            "EnrollNixCacheKey",
            "super::EnrollNixCacheKeyRequest",
            "super::EnrollNixCacheKeyResponse",
        ))
        .method(method(
            "sign_nix_cache_fingerprint",
            "SignNixCacheFingerprint",
            "super::SignNixCacheFingerprintRequest",
            "super::SignNixCacheFingerprintResponse",
        ))
        .build();
    tonic_build::manual::Builder::new().compile(&[nix_cache_service]);

    println!("cargo:rerun-if-changed=proto/basil/broker/v1/broker.proto");
    println!("cargo:rerun-if-changed=proto/basil/broker/v1/nix_cache.proto");
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
