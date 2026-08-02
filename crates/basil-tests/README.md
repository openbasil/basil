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

`boot_basil_invocation` layers the sealed-invocation surface on top of those
fixtures without editing the prefill script: it provisions the broker
response-signing transit key and the out-of-band public halves in the running
dev engine, extends `catalog.json` with the three broker keys (each labelled
with the `broker_key_use` its role requires), extends `policy.json` with a
subject bound to a caller-supplied invocation signature key, and writes an agent
config carrying `[broker-identity]`, `[invocation]`, and the `[federation]` rule
for the requested `ProviderArm`. The X25519 private halves are deliberately never
provisioned, so a booted broker in this lane cannot open a request body.

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
- **Proof-bound sealed invocations**: `ci_federation_proof_matrix` drives an adversarial
  corpus (malformed proof `COSE_Key`s, `crit` enforcement for `-70007`, algorithm
  confusion, proof-key and response-key substitution, COSE mutation) over the real
  `Invoke` RPC, parametrized over provider arm. The GitHub arm runs; the Forgejo arm
  ships `#[ignore]` and is activated by `basil-jjgi.3.5`.
- **Freshness challenges and per-run quota**: `ci_challenge_lifecycle_matrix` drives the
  broker's challenge state machine over the real `GetInvocationChallenge` + `Invoke` RPCs
  (issuance shape, single-use and concurrent-duplicate consumption, expiry boundary,
  wrong-`jkt` without burning the rightful holder's record, wrong-generation across a live
  SIGHUP reload, restart invalidation, instance-prefix routing, per-`jkt`/per-source/global
  issuance limits with an outstanding challenge still consuming under pressure).
  `ci_run_quota_matrix` covers the per-run quota state machine (exhaustion, reset on
  `run_attempt`/restart, generation-scoped reload reset, allowance pressure) against the
  public `RunQuotaTable` API — quota-over-RPC needs a hermetic provider seam
  (`basil-abdh`).

## Features

| Feature        | Enables                                                                                  |
| -------------- | ---------------------------------------------------------------------------------------- |
| `live-e2e`     | The tests that boot live OpenBao/Vault dev servers.                                      |
| `http`         | Live tests needing the broker's JWKS/OIDC HTTP surface (builds `basil-bin` with `http`). |
| `unlock-bip39` | The BIP39 break-glass harness helpers and `bip39_unlock_e2e`.                            |

All are additive and on under `--all-features`. Run from the workspace root so the harness can
find `scripts/` and the built binaries.

## Jujutsu workspaces

Fresh `jj` workspaces leave the `clients/go` Git submodule empty. The interop
recipes reuse the populated main checkout through the workspace's
`.beads/redirect`, while Rust binaries and fixtures still come from the active
workspace. The Go checkout is mounted read-only for the live Go harness. Do not
copy or force-track the ignored submodule. Set
`BASIL_GO_CLIENT_DIR` to an absolute populated checkout only when using a
different workspace layout.
