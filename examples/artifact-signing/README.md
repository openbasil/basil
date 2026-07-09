<!--
SPDX-FileCopyrightText: 2026 OpenBasil Contributors

SPDX-License-Identifier: Apache-2.0
-->

# artifact-signing

> **Basil is a host-local secrets broker: your app never touches the key.** The kernel attests who's
> calling, a default-deny policy decides, the key is used where it lives (OpenBao/Vault, KMS, or a
> sealed local store), and every operation is audited.

Sign and verify a release artifact **without the signing key ever leaving the
vault**.

## Why

A release-signing key is one of the highest-value secrets an organization holds:
whoever can read it can forge trusted builds forever. The usual mitigations
(an HSM, a KMS, a CI secret) still hand *some* process the raw key or a
key-shaped handle it can misuse. Basil removes the key from the blast radius
entirely: the private key stays in the backend (here an OpenBao `transit`
engine) and Basil brokers the **operation**, returning only a detached
signature. The caller never holds, and cannot exfiltrate, the key.

Because the signature is a standard Ed25519 signature, anyone can verify it with
any off-the-shelf library, needing no Basil dependency at verification time.
This example proves that end to end, then proves the other half of "secure by
default": a process that is not *granted* signing rights on a key is **denied**,
even though the key exists and the process is otherwise authenticated.

## What it demonstrates

1. **Sign in place**: a small release manifest is signed with a transit-backed
   Ed25519 catalog key (`release.signing`). Basil returns the signature; the key
   material never crosses the socket.
2. **Broker verify**: the same broker verifies the signature (`verify`).
3. **Standard, interoperable signature**: the public half is fetched
   (`get_public_key`) and the signature is verified **locally with
   `ed25519-dalek`**, proving Basil produced a plain RFC 8032 Ed25519 signature.
   A one-bit tamper is shown to fail that same local verifier.
4. **Least privilege / typed deny**: signing with a key the policy does not
   grant this process (`forbidden.key`) returns a typed `PermissionDenied`.
   Being able to read or use one key never implies authority over another.

## Basil pillars

- **Attestation** authorizes the request against the caller's
  kernel-verified Unix identity (`SO_PEERCRED` uid), matched by the policy
  subject.
- **Secrets**: the sign/verify operations are brokered; the key stays in the
  vault and is used in place.
- **Least privilege** keeps reading and signing as distinct grants; `forbidden.key`
  proves an ungranted operation fails closed.

## Prerequisites

- [`bao`](https://openbao.org) (OpenBao) or [`vault`](https://developer.hashicorp.com/vault) on `PATH`
- `cargo` (the script builds the `basil` agent and this example)

## How to run

```bash
examples/artifact-signing/run.sh
```

The script boots an OpenBao dev server and a `basil agent`, provisions the
catalog + policy, then runs the example against the agent socket. It exits `0`
only if every assertion passes.

Environment overrides (all optional): `ARTIFACT_SIGNING_WORKDIR` (default
`/tmp/basil-artifact-signing`), `ARTIFACT_SIGNING_BAO_PORT` (default `8220`),
`BASIL_BIN` (path to a prebuilt `basil` binary; otherwise built from the repo
root).

## Expected output

```
signed 133 manifest bytes with release.signing
broker verify: true
dalek verify: true
dalek verify (tampered): rejected
deny observed: PermissionDenied/UNAUTHORIZED
artifact-signing: all assertions passed
PASS
```

## See also

- [`examples/stream-file-encryption`](../stream-file-encryption) covers large-file
  AEAD + ML-KEM streaming where Basil owns every nonce.
- [`examples/cose-nats-telemetry`](../cose-nats-telemetry): bare `COSE_Sign1`
  telemetry over NATS with Basil-minted credentials and in-place signatures.
- [`examples/cose-nats-demo`](../cose-nats-demo): the sealed-invocation COSE
  messaging demo carried by `basil-nats-bridge` (a different construction: sealed
  peer messages via the bridge, versus this example's direct broker signing).
