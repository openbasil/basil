#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

cargo test -p basil-core transport::grpc_server::tests --all-features
cargo test -p basil-core transport::grpc_server::tests --no-default-features
cargo test -p basil-core service::spiffe::tests::fetch_jwtsvid --all-features
cargo test -p basil-core service::spiffe::tests::fetch_x509 --all-features
cargo test -p basil-core service::spiffe::tests::validate_jwtsvid --all-features

# Live cross-engine SPIFFE X509-SVID (URI-SAN) issuance + x509 bundle/CRL drive
# over the Workload API (basil-dk5.10). The test boots a real dev OpenBao AND a
# real dev Vault and self-skips each engine leg whose CLI (`bao`/`vault`) is
# absent (it prints an explicit SKIP line and still passes if neither is present).
cargo test -p basil-tests --features live-e2e --test spiffe_x509_svid_e2e -- --nocapture
