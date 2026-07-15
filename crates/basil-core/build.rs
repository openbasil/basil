// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protocol = "proto/basil/attestor/v1/attestor.proto";

    tonic_prost_build::configure()
        .build_server(false)
        .build_client(false)
        .compile_protos(&[protocol], &["proto"])?;

    println!("cargo:rerun-if-changed={protocol}");
    Ok(())
}
