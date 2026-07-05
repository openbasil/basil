<!--
SPDX-FileCopyrightText: 2026 OpenBasil Contributors

SPDX-License-Identifier: Apache-2.0
-->

# Example suite: three Rust + three Go runnable examples (2026-07)

Design for six new runnable examples, three per language, one per language demonstrating
COSE over NATS. Rust examples live under `examples/<name>/` as standalone crates (the
`examples/cose-nats-demo` pattern); Go examples live under `clients/go/examples/<name>/`
inside the Go module (the `nats-cose-courier` pattern).

The existing `examples/cose-nats-demo` (Rust) and `clients/go/examples/nats-cose-courier`
(Go) showcase **sealed invocations via `basil-nats-bridge`**. The new COSE-over-NATS
examples are deliberately different: **bare `COSE_Sign1` application messaging** between
two directly-connected NATS clients, with Basil minting the NATS credentials (leases) and
signing in place (secrets). New READMEs must cross-reference the bridge demos.

## Conventions (all six)

- Each example directory contains: the program source, `README.md`, and `run.sh`.
- `run.sh` contract:
  - `#!/usr/bin/env bash`, `set -euo pipefail`, cleanup `trap` that kills every daemon it
    started (bao, nats-server, basil agent) even on failure.
  - Boots everything it needs (OpenBao dev server, `basil agent`, `nats-server` where
    used), provisions catalog/policy fixtures, runs the example, and **asserts** the
    result (round-trip equality, verification true, deny observed, …). Exit 0 only when
    every assertion passed; nonzero with a clear message otherwise.
  - Env overrides, all optional: `<EX>_WORKDIR` (default under `/tmp/`), `BASIL_BIN`
    (path to a prebuilt `basil` binary; default: build via cargo from the repo root),
    port variables with per-example defaults so two examples can run simultaneously.
  - Required tools documented in the README (`bao`, `nats-server`, `cargo` or `go`).
- Rust example crates: `[workspace]` empty table (opt out of the root workspace),
  `publish = false`, path deps into `../../crates/*`, edition 2024, rustfmt-clean.
  They are NOT workspace members, so workspace deny-lints do not apply; still write
  idiomatically clean code (anyhow for errors is fine in examples).
- Go examples: packages inside the `clients/go` module; `gofmt`-clean, `go vet`-clean.
  Example-only deps in `go.mod` are acceptable (nats.go already is one). Pin
  `veraison/go-cose` to the same version as `crates/basil-tests/tests/cose_go_interop/go.mod`.
- Provisioning cribs: `scripts/prefill-test-store.sh`, `examples/cose-nats-demo/run.sh`,
  `clients/go/scripts/interop-agent.sh`, and the live tests in `crates/basil-tests/tests/`
  (notably `nats_bridge_cose_e2e.rs`).

## Rust examples (`examples/`)

### 1. `examples/artifact-signing`
Sign and verify a release artifact without ever holding the key.
- Connect over the agent socket (`basil` client crate), sign the bytes of a small release
  manifest with a transit-backed Ed25519 catalog key, verify through the broker, fetch
  the public key and ALSO verify locally with `ed25519-dalek` to prove the signature is
  standard.
- Demonstrate least privilege: attempt to sign with a key the policy does not grant this
  process and show the typed deny error (assert on the deny).
- Acceptance: broker verify true; local dalek verify true; deny case observed; exit 0.

### 2. `examples/stream-file-encryption`
Encrypt a large file with `basil::stream` (Basil owns every nonce).
- Generate a multi-chunk (few MiB) input; encrypt AEAD (AES-256-GCM, generated CEK),
  decrypt, compare byte-for-byte. Then an ML-KEM-768 pass where CEK recovery goes
  through the broker (custodied KEM key), mirroring the Go `stream` subpackage.
- Tamper demo: flip one ciphertext byte, assert decryption fails closed.
- Acceptance: both round-trips byte-identical; tamper decrypt errors; exit 0.

### 3. `examples/cose-nats-telemetry`  (the Rust COSE-over-NATS example)
Two services exchange COSE-signed telemetry over NATS; nothing but leases and in-place
signatures.
- Basil mints the NATS operator/account/user chain; `nats-server` runs in operator mode
  with the account preloaded in the memory resolver.
- The publisher authenticates with the basil-minted **user JWT + in-place nonce
  signing** (the NKey seed never leaves the vault; see the `basil-nats` crate and the
  async-nats jwt-with-callback auth path).
- The publisher builds a bare `COSE_Sign1` (basil-cose `build_signed`) over a telemetry
  payload using a broker-backed `Signer` (basil-cose AFIT trait awaiting
  `sign_with_algorithm`); the subscriber verifies with the public key fetched from the
  broker (`verify_signed`), checks the request-hash/claims, and asserts payload equality.
- Acceptance: NATS connection authenticated via minted JWT; COSE verify true on the
  subscriber; a tampered message is rejected; exit 0.

## Go examples (`clients/go/examples/`)

### 4. `clients/go/examples/secrets-and-aead`
The KV + AEAD data plane in one tour.
- `GetSecret`/`SetSecret`/`RotateSecret` on a KV-v2 secret (assert the version cycle),
  then `Encrypt`/`Decrypt` with AAD on an AEAD catalog key (broker-owned nonce), plus an
  AAD-mismatch negative that must fail.
- Acceptance: version increments observed; round-trip equality; AAD negative errors; exit 0.

### 5. `clients/go/examples/stream-file-encryption`
The Go `stream` subpackage over a real file, mirroring Rust example 2.
- AES-256-GCM with generated CEK round-trip on a multi-chunk file; ML-KEM-768 with
  `NewBrokerCEKRecovery` (custodied key); one tamper fail-closed assertion.
- README notes the container is byte-identical to Rust `basil::stream`
  (`docs/specs/streaming-encryption-format.md`).
- Acceptance: round-trips byte-identical; tamper fails closed; exit 0.

### 6. `clients/go/examples/cose-nats-telemetry`  (the Go COSE-over-NATS example)
Go mirror of example 3: COSE-signed telemetry over NATS with basil-minted credentials.
- Mint the operator/account/user chain via the Go client (`MintNatsOperator` /
  `MintNatsAccount` / `MintNatsUser`); operator-mode `nats-server` with memory resolver.
- Connect with nats.go using the minted user JWT and a signature callback that routes
  the server nonce through `SignWithAlgorithm` (in-place NKey signing, no seed released).
- Sign the payload as bare `COSE_Sign1` via `veraison/go-cose` with a remote-signer
  adapter over `client.Sign`/`SignWithAlgorithm` (crib:
  `crates/basil-tests/tests/cose_go_interop/`); subscriber verifies against
  `GetPublicKey` and asserts payload equality; tampered message rejected.
- Acceptance: authenticated connect; verify true; tamper rejected; exit 0.

## Test isolation (for CI-less local runs)

Default ports must not collide across examples so any two can run at once. Assigned
defaults: artifact-signing bao `8220`; stream-file-encryption (rs) bao `8221`;
cose-nats-telemetry (rs) bao `8222` / nats `4240`; secrets-and-aead bao `8230`;
stream-file-encryption (go) bao `8231`; cose-nats-telemetry (go) bao `8232` / nats `4250`.

## Documentation

Each example's README covers: what it demonstrates (lead with why, security-first),
prerequisites, how to run, expected output, and how it maps to the Basil pillars
(attestation / secrets / identity / leases). basil-doc example pages are handled by a
`docs`-labelled br ticket, not in this change.
