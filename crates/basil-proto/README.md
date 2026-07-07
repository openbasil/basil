<!--
SPDX-FileCopyrightText: 2026 OpenBasil Contributors

SPDX-License-Identifier: Apache-2.0
-->

# basil-proto

The gRPC contracts shared by the Basil broker, the client crates, and the couriers. If you are
looking for what actually crosses Basil's Unix socket, it is defined here and nowhere else.

## What is generated

`build.rs` compiles the vendored `.proto` sources under `proto/` with `tonic-prost-build` at
build time (server and client stubs both):

| Module       | Source                               | Purpose                                                                                                                                 |
| ------------ | ------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------- |
| `broker`     | `proto/basil/broker/v1/broker.proto` | Basil's own broker API: signing, AEAD, secrets, minting, admin, and the sealed-invocation carrier (`SealedRequest` / `SealedResponse`). |
| `spiffe`     | `proto/spiffe/workloadapi.proto`     | The upstream SPIFFE Workload API, vendored unmodified so SVID clients interoperate.                                                     |
| Envoy SDS    | `proto/envoy/**`, `proto/xds/**`     | The Envoy secret discovery service surface Basil serves for TLS material delivery.                                                      |
| `google.rpc` | `proto/google/rpc/status.proto`      | Structured error details.                                                                                                               |

Vendoring the protos keeps builds hermetic: no network fetch, no drift against an upstream tag you
did not choose.

## What is hand-written

Two modules are code, not codegen:

- `types`: common Basil domain types shared by the client and agent internals
- `invocation`: the sealed-invocation plaintext body schemas and Basil's registered COSE content
  types (the RFC 9052 protected header 3 values that select a body schema), their deterministic
  CBOR codecs, and `InvocationStatus`. Envelope canonicalization itself lives in
  [`basil-cose`](../basil-cose); this module owns only what is Basil-specific.

`fixtures/` and `tests/` pin the wire encodings so a contract change is a visible diff, not a
silent break.

## Compatibility

The broker API is versioned in the proto package path (`basil.broker.v1`). Wire-visible changes
belong in the proto files with fixtures updated in the same change; do not edit generated output.
