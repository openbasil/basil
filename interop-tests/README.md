<!--
SPDX-FileCopyrightText: 2026 OpenBasil Contributors

SPDX-License-Identifier: Apache-2.0
-->

# Basil interop tests

This directory holds foreign-language fixtures, tool configs, and provider
assets used by Basil's interop test suite.

Most tests are driven by the rust integration crate `crates/basil-tests`,
which boots Basil, allocates sockets/ports, applies skip policy,
launches external processes, and verifies results.

`interop-tests/` (this directory) has what's being driven: Go modules, Envoy/Traefik
configs, provider fixtures, and short runbooks.

New harness or driver code should be Rust unless it must be part of the
foreign client under test.

Interop tests are skipped if any dependencies are not present: a required external binary,
credential, fixture, or network connectivity. Skipped tests are logged with a warning.

## Matrix

| Target                 | Fixture home                                                                                | Driver                                             | Coverage goal                                                                                                                                                          | Prerequisites                                                          | Status                                         |
| ---------------------- | ------------------------------------------------------------------------------------------- | -------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- | ---------------------------------------------- |
| go-spiffe Workload API | `interop-tests/go-spiffe/`                                                                  | Rust test launches Go probe                        | `FetchX509SVID`, `FetchX509Context`, `FetchX509Bundles`, `FetchJWTSVID`, `FetchJWTBundles`, `ValidateJWTSVID`, required Workload API metadata                          | `go`, live Basil harness, OpenBao or Vault dev engine                  | Implemented (`go_spiffe_interop`)              |
| go-spiffe examples     | `interop-tests/go-spiffe/`                                                                  | Rust test launches Go client/server probes         | Deterministic X.509 source watcher rotation, mTLS client/server authorization success/failure, and JWT-SVID HTTP success/wrong-audience failure with structured output | `go`, live Basil harness, OpenBao dev engine                           | Implemented (`go_spiffe_interop`)              |
| rust-spiffe            | `crates/basil-tests/tests/`                                                                 | Native Rust tests                                  | Standard `spiffe` client one-shot calls and watched sources, raw Workload API wire compatibility, X.509 profile checks, and `spiffe-rustls` mTLS/rotation              | Rust devshell, live Basil harness, OpenBao or Vault dev engine         | Implemented; listed below                      |
| Envoy                  | `interop-tests/envoy/`                                                                      | Rust test launches Envoy and optional Rust adapter | X.509-SVID delivery, SDS secret fetch/update, mTLS peer authorization, rotation without restart, fail-closed denial                                                    | `envoy`, Basil SDS surface or tracked adapter, live Basil harness      | Planned after SDS basics                       |
| Traefik                | `interop-tests/traefik/`                                                                    | Rust test launches Traefik and local workloads     | Consume Basil-issued SPIFFE material for TLS/mTLS or an adapter path; verify routing and denied peer behavior                                                          | `traefik`, live Basil harness, agreed integration mode                 | Planned investigation                          |
| AWS KMS                | `interop-tests/cloud-kms/aws/`                                                              | Rust test uses provider fixture                    | Backend/provider interop for signing/encryption once AWS KMS custody is supported; fail-closed credential gating                                                       | AWS credentials in explicit env vars                                   | Future/provider-gated                          |
| Google Cloud KMS       | `interop-tests/cloud-kms/gcp/`                                                              | Rust test uses provider fixture                    | Backend/provider interop for signing/encryption once Cloud KMS custody is supported; fail-closed credential gating                                                     | GCP credentials in explicit env vars                                   | Future/provider-gated                          |
| OpenBao/Vault JWT auth | Existing live fixtures                                                                      | Rust test drives engine config                     | Engine JWT auth configured against Basil-published JWKS; successful Basil JWT-SVID login plus wrong-audience and tampered-token rejection                              | `bao` and/or `vault`, live Basil harness                               | Implemented (`openbao_vault_jwt_auth_interop`) |
| SPIRE parity scenarios | `interop-tests/spire-parity/`                                                               | Rust test or fixture scripts                       | Adapt selected SPIRE integration scenarios where useful: X.509 fetch, JWT fetch, bundle updates, rotation semantics                                                    | No SPIRE server required unless explicitly running side-by-side parity | Planned later                                  |
| Workload API hardening | `crates/basil-core/src/service/spiffe.rs`, `crates/basil-core/src/transport/grpc_server.rs` | Native Rust tests                                  | Bad/missing/duplicated gRPC metadata, invalid SPIFFE request shapes, oversized metadata, wrong service/header combinations, and fail-closed error mapping              | Rust devshell                                                          | Implemented first pass                         |
| HTTP surface hardening | `crates/basil-core/src/service/jwks.rs`                                                     | Native Rust tests                                  | SSRF-style inputs, spoofed `Host`/`X-Forwarded-*` headers, absolute-form request targets, path traversal, oversized headers, and JWKS/OIDC surface behavior            | Rust devshell; live Basil harness only when HTTP surfaces are enabled  | Implemented first pass                         |

## Layout Conventions

- Go fixtures should be ordinary Go modules under `interop-tests/go-spiffe/`.
  Keep probe outputs machine-readable, preferably one JSON object per run.
- Tool configs should be checked in under their target directory with a README
  explaining required binaries, ports, sockets, and expected skip behavior.
- Cloud provider tests must be opt-in through explicit environment variables.
  Agents must never search silently for other credentials.
- Rust driver helpers should live under `crates/basil-tests/src/interop/`.
  Individual tests live under `crates/basil-tests/tests/`.
- If a feature change is needed to make an interop test possible, track that as
  a separate Basil implementation issue and make the interop issue depend on it.

## Rust SPIFFE compatibility

The Rust SPIFFE coverage is split into named Cargo tests:

| Test                   | Command                                                                      | Coverage                                                                                                                                       |
| ---------------------- | ---------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| Standard rust-spiffe   | `cargo test -p basil-tests --features live-e2e --test spiffe_interop`        | `spiffe::WorkloadApiClient`, `X509Source`, `JwtSource`, X.509/JWT SVID fetches, X.509/JWT bundles, and standard metadata injection.            |
| Raw wire compatibility | `cargo test -p basil-tests --features live-e2e --test spiffe_wire_compat`    | Protobuf shape and DER/JWT profile constraints the standard `spiffe` crate relies on, including X.509-SVID keys and RS256 JWT-SVID headers.    |
| X.509 profile e2e      | `cargo test -p basil-tests --features live-e2e --test spiffe_x509_svid_e2e`  | Cross-engine X.509-SVID issuance, bundle/CRL reads, URI SAN shape, and parseability by the standard `spiffe` client.                           |
| spiffe-rustls mTLS     | `cargo test -p basil-tests --features live-e2e --test spiffe_rustls_interop` | `spiffe-rustls` client/server configs over Basil `X509Source`, exact-ID authorization failures, ALPN, and short-TTL rotation without rebuilds. |

These complement the Go probes: Rust keeps byte-level and crate-native
coverage close to Basil, while Go proves independent standard-client behavior
against the same live Workload API surface.

## Hardening

Hardening tests are not interoperability tests, but they share the same
external-surface conventions. Track them in the interop matrix so new HTTP
and gRPC capabilities get adversarial coverage.

Initial hardening areas:

| Target                     | Test location                                                                                                                                                                                  | Checks                                                                                                                                                                                             |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Workload metadata gate     | `service::spiffe::{workload_header_requires_true, workload_header_rejects_duplicates_binary_and_malformed_values}`                                                                             | Missing, `false`, mixed-case, whitespace, duplicate, binary, and oversized `workload.spiffe.io` metadata fail closed.                                                                              |
| Workload request shapes    | `service::spiffe::{workload_api_methods_reject_missing_header_consistently, fetch_jwtsvid_rejects_malformed_spiffe_ids_and_audiences, validate_jwtsvid_rejects_malformed_inputs_consistently}` | Every Workload API method requires metadata, malformed SPIFFE IDs/audiences are rejected, and validation rejects blank/malformed token inputs.                                                     |
| Cross-service metadata use | `transport::grpc_server::{broker_grpc_serves_status_on_unix_socket, broker_and_spiffe_services_share_one_unix_socket}`                                                                         | Broker/Admin RPCs ignore Workload API metadata while Workload API RPCs reject missing, duplicate, or binary metadata.                                                                              |
| JWKS/OIDC HTTP surface     | `service::jwks::live_path::{router_rejects_adversarial_targets_and_methods_locally, discovery_does_not_reflect_host_or_forwarded_headers, jwks_etag_is_stable_under_untrusted_headers}`        | GET-only static routing, absolute-form targets, encoded traversal, spoofed Host/forwarding headers, query injection, ETag handling, and oversized headers.                                         |
| URL/config guardrails      | `agent_cli::{jwks_issuer_rejects_ssrf_prone_url_shapes, otel_logging_requires_non_empty_http_endpoint_when_enabled}`                                                                           | URL-bearing startup config rejects schemeless, non-HTTP, file/unix, userinfo, fragment, and cloud metadata hosts where Basil parses a public HTTP URL.                                             |
| Error no-leak guardrails   | `service::{broker,spiffe,jwks,admin}` and `doctor` no-leak tests                                                                                                                               | Denied requests and upstream/probe failures use fixed, non-secret response text and omit vault tokens, authorization metadata, passphrase/bundle paths, private-key material, and upstream bodies. |

Future hardening tests should keep the same shape: explicit fail-closed
assertions, no network downloads in test bodies, and no error output that echoes
secrets, backend tokens, request metadata, sealed-material paths, or upstream
credential-bearing bodies.

### URL-Bearing Fields

Basil has no request parameter that makes the broker fetch an arbitrary URL.
The URL-like fields below are either operator startup config, local bind
addresses, or claim payloads:

| Field                                          | Purpose                                                                                                            | Allowed shape                                                                                                                                                                                          |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `[jwks].issuer`                                | Advertised OIDC issuer base used to build discovery metadata; Basil does not fetch it.                             | Absolute `http` or `https`; no userinfo, fragment, schemeless URL, non-HTTP scheme, `file`/`unix` URL, or cloud metadata host. Loopback is allowed for explicitly enabled local deployments and tests. |
| `[jwks].listen`                                | Local bind address for the opt-in JWKS/OIDC HTTP surface.                                                          | `SocketAddr` parsed at startup; malformed values fail before bind.                                                                                                                                     |
| `[logging.opentelemetry].endpoint`             | Outbound OTLP collector endpoint when the `otlp` feature and logging config are enabled.                           | Absolute `http` or `https`; no userinfo, fragment, schemeless URL, non-HTTP scheme, `file`/`unix` URL, or cloud metadata host. Loopback is allowed for local collectors.                               |
| `vault-addr` / backend catalog `addr`          | Operator-selected Vault/OpenBao-compatible backend address used for unlock, health checks, and backend operations. | Intended outbound backend target; not derived from workload input. Operators should point it at a trusted backend URL.                                                                                 |
| `onepassword-provider-uri`                     | 1Password keystore adapter URI (`op` CLI).                                                                         | Adapter-owned URI, not a broker HTTP fetch target in the core runtime path.                                                                                                                            |
| `aws-kms` cred `region`                        | AWS KMS endpoint region for the in-place transit backend.                                                          | Outbound target is the provider-owned `kms.<region>.amazonaws.com`; auth is the ambient AWS chain, not workload input.                                                                                 |
| `gcp-kms` cred `project`/`location`/`key_ring` | GCP Cloud KMS addressing for the in-place transit backend.                                                         | Outbound target is the provider-owned `cloudkms.googleapis.com` (gRPC); auth is ADC, not workload input.                                                                                               |
| NATS `account_server_url`                      | Optional URL claim embedded in minted NATS JWTs.                                                                   | Claim payload only; Basil does not fetch it.                                                                                                                                                           |

## First Pass

Start with go-spiffe because it gives broad standard-client coverage without a
new Basil protocol surface. The first test boots Basil through the existing live
harness, runs a Go Workload API probe against the Basil Unix socket, and asserts
structured results in Rust.

The second go-spiffe test adapts the examples into deterministic probes: one
X.509 source watcher/update probe, one mTLS probe, and one JWT-SVID HTTP probe.
They use runtime socket paths and the Basil-issued SPIFFE ID instead of hardcoded
`unix:///tmp/agent.sock` and fixed peer IDs.
