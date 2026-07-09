<!--
SPDX-FileCopyrightText: 2026 OpenBasil Contributors

SPDX-License-Identifier: Apache-2.0
-->

# python-grpc

> **Basil is a host-local secrets broker: your app never touches the key.** The kernel attests who's
> calling, a default-deny policy decides, the key is used where it lives (OpenBao/Vault, KMS, or a
> sealed local store), and every operation is audited.

Drive a running Basil agent from Python with nothing but `grpcio`. The agent
socket speaks **standard gRPC from any language**.

## Why

Basil ships Rust and Go client libraries, but the contract underneath them is
just `crates/basil-proto/proto/basil/broker/v1/broker.proto` served over a
Unix-domain socket. Any language with a gRPC stack can generate stubs from
that file and talk to the broker directly. No Basil dependency, sidecar,
or bearer token is needed. Authorization comes from the kernel: the broker attests the
calling process by its `SO_PEERCRED` uid, so the Python program presents no
credential at all. A packaged Python client library is on the roadmap; this
example shows the raw wire surface it will wrap.

## What it demonstrates

1. **Runtime codegen from the canonical proto**: `main.py` invokes
   `grpc_tools.protoc` against the repo's proto root and imports the generated
   stubs, with the same contract the Rust and Go clients are built from.
2. **Standard gRPC over the agent socket**: a plain
   `grpc.insecure_channel("unix:///…")` (with a pinned `:authority`) reaches
   the broker; `AdminService.Status` reports the backend/version/protocol.
3. **Brokered signing from Python**: `SigningService.Sign` returns a detached
   64-byte Ed25519 signature made in place in the backend; `Verify` confirms
   it and authoritatively rejects a one-bit tamper (`valid=false` is an
   answer, not an error).

## Basil pillars

- **Attestation**: no token, no TLS client cert. The policy subject is the
  caller's kernel-verified uid.
- **Secrets**: the signing key never crosses the socket; Python sees only the
  signature.
- **Least privilege**: the policy grants this uid `sign`/`verify`/
  `get_public_key` on the one demo key and nothing else.

## Prerequisites

- `python3` with the gRPC toolchain: `pip install grpcio grpcio-tools`
  (without them `run.sh` boots the broker as a smoke test and exits `0` with a
  `SKIP` message)
- A `basil` binary: `BASIL_BIN`, `basil` on `PATH`, or a prior workspace debug
  build at `../../target/debug/basil` (default features include the
  zero-dependency `db-keystore` backend. Vault/OpenBao are not required)

## How to run

```bash
examples/python-grpc/run.sh
```

The script scaffolds a throwaway db-keystore broker (catalog, policy for your
uid, sealed bundle), starts `basil agent` on a Unix socket, then runs
`main.py` against it. Stubs are generated under the workdir. It cleans up the
agent it started, even on failure.

Environment overrides (all optional): `PYTHON_GRPC_WORKDIR` (default
`/tmp/basil-pygrpc`), `BASIL_BIN`.

To run `main.py` by hand against your own agent:

```bash
pip install grpcio grpcio-tools
python3 main.py /path/to/agent.sock   # stubs land in ./gen by default
```

## Expected output

```
== python example ==
PASS status backend=keystore version=0.7.1 protocol=1
PASS sign demo.signing_key signature_len=64
PASS verify valid=true
PASS verify tampered=rejected
python-grpc: all assertions passed

workdir: /tmp/basil-pygrpc
PASS
```

Without `grpcio` installed the run ends `SKIP: python gRPC deps not installed
(pip install grpcio grpcio-tools)` and exits `0`.

## See also

- [`examples/web-service-axum`](../web-service-axum) and
  [`clients/go/examples/web-service`](../../clients/go/examples/web-service):
  the packaged Rust and Go clients over the same socket.
- [`examples/db-keystore`](../db-keystore): the zero-dependency backend this
  example runs on, driven through the `basil` CLI.
- `crates/basil-proto/proto/basil/broker/v1/broker.proto`: the canonical,
  stable gRPC contract.
