<!--
SPDX-FileCopyrightText: 2026 OpenBasil Contributors

SPDX-License-Identifier: Apache-2.0
-->

# basil-core

The [Basil daemon](https://github.com/openbasil/basil) as a library: broker core, backend adapters, gRPC services, transport, and the
offline operator command implementations. The [`basil-bin`](../basil-bin) binary is a thin
cli wrapper over this crate; embedders and the integration tests link it directly.

Basil's job is to let workloads use keys and secrets without holding them. `basil-core` is where
that promise is enforced: every request is attributed to a kernel-attested peer, evaluated against
a default-deny policy, executed against a backend where the key material stays put, and written to
a structured audit record.

## Layout

| Module                                                                        | Owns                                                                                                                            |
| ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `core::catalog`                                                               | The key inventory and authorization policy loaded at startup: what exists, who may do what to it.                               |
| `core::state`                                                                 | The loaded policy + backend manager bundle shared across services; reload swaps it atomically (`core::reload`).                 |
| `core::backend`                                                               | Backend adapters (table below).                                                                                                 |
| `core::audit`, `core::decision`                                               | Decision records: subject, action, target, outcome, policy generation.                                                          |
| `core::seal`, `x25519_seal`, `ed25519_sign`, `ml_dsa_sign`, `ml_kem_envelope` | Local crypto used for sealed invocations and materialize-to-use operations.                                                     |
| `core::minter`, `core::revocation`                                            | JWT/SVID minting and revocation state.                                                                                          |
| `service`                                                                     | tonic service adapters: `broker`, `signing`, `aead`, `secret`, `minting`, `invocation`, `admin`, `jwks`, `spiffe`, `sds`.       |
| `transport`                                                                   | tonic wiring over the Unix socket, `SO_PEERCRED` peer extraction, and authorization helpers.                                    |
| `init`, `bundle_cli`, `agent_cli`, `doctor`, `unlock`                         | Offline operator commands: scaffolding, sealed credential bundles, run/explain/doctor, and the fail-closed startup unlock path. |

## Backends

The backend decides *where keys live*; policy decides *who may use them*. In-place backends never
release private key material; the keystore backends materialize a key locally for exactly one
operation and zeroize it.

| Backend                         | Kind                                                                                                                                                           |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `vault`                         | OpenBao / HashiCorp Vault, used in place. Composes the `transit` client (signing, AEAD, BYOK import, kv2 secret access) and the `pki` client (X.509 issuance). |
| `spiffe` / `svid`               | SPIFFE Workload API surface and SVID issuance over the Vault backend.                                                                                          |
| `aws_kms`, `gcp_kms` (features) | Cloud KMS, used in place.                                                                                                                                      |
| `keystore` (feature)            | Materialize-to-use stores from [`basil-keystore-backend`](../basil-keystore-backend): the built-in encrypted `db-keystore` and 1Password.                      |

## Feature flags

`http` (JWKS/OIDC surface, default) and `http-tls`; `keystore-backend` with `db-keystore` and
`onepassword`; `aws-kms` and `gcp-kms` (large SDKs); unlock methods `unlock-age-yubikey`
(default, experimental), `unlock-bip39` (default), `unlock-tpm` and `tpm2` (experimental);
`otlp` telemetry export; `live-e2e` is test-only and boots live OpenBao/Vault dev servers.

## Using it

Most consumers should not depend on this crate. Run the [`basil-bin`](../basil-bin) binary and
talk to it with the [`basil`](../basil-client) client crate. Use `basil-core` if you are
embedding the broker in another process, building an alternative binary, or writing integration
tests that need the daemon in-process.
