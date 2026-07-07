<!--
SPDX-FileCopyrightText: 2026 OpenBasil Contributors

SPDX-License-Identifier: Apache-2.0
-->

# basil-tests

Test harness, and Live and interop integration tests for Basil.
This crate is not published (`publish = false`) and has no public API.

## The harness

`src/lib.rs` is a shared live harness. It uses `scripts/prefill-test-store.sh` to
boot a dev `bao` (OpenBao), write catalog / policy / sealed-bundle fixtures, and build the
binaries; then it runs `target/debug/basil run` on a temporary Unix socket.

## What is covered

- **COSE interop**: Rust round trips (`cose_interop`, `cose_es256_interop`) and cross-language
  fixtures against the Go helper (`cose_go_interop/`, `nats_bridge_cose_e2e`).
- **SPIFFE**: Workload API interop (`spiffe_interop`, `spiffe_wire_compat`), X.509 and JWT SVIDs
  (`spiffe_x509_svid_e2e`, `spiffe_jwt_login_e2e`, `jwt_svid_revocation_e2e`), rustls and
  go-spiffe clients (`spiffe_rustls_interop`, `go_spiffe_interop`), and the OIDC verifier
  (`oidc_verifier_go/`, `jwks_oidc_e2e`).
- **Broker paths end to end**: `kv2_sign_e2e`, `pki_leaf_san_e2e`, `ecdsa_p384_p521_e2e`,
  `pqc_e2e`, `envoy_sds_e2e`, `openbao_vault_jwt_auth_interop`.
- **Operations**: `init_flow_e2e`, `reload_e2e`, `doctor_e2e`, `health_ready_e2e`,
  `bip39_unlock_e2e`.

## Features

| Feature        | Enables                                                                                  |
| -------------- | ---------------------------------------------------------------------------------------- |
| `live-e2e`     | The tests that boot live OpenBao/Vault dev servers.                                      |
| `http`         | Live tests needing the broker's JWKS/OIDC HTTP surface (builds `basil-bin` with `http`). |
| `unlock-bip39` | The BIP39 break-glass harness helpers and `bip39_unlock_e2e`.                            |

All are additive and on under `--all-features`. Run from the workspace root so the harness can
find `scripts/` and the built binaries.
