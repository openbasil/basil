<!--
SPDX-FileCopyrightText: 2026 OpenBasil Contributors

SPDX-License-Identifier: Apache-2.0
-->

# cose-nats-telemetry

Two services exchange **COSE-signed telemetry over NATS** using nothing but
Basil-minted **leases** and **in-place signatures**. No long-lived secret is
ever held by either service.

## Why

Message-level signing and transport authentication are usually solved with
static secrets: an NKey seed baked into a config file, an API token in an
environment variable, a signing key on disk. Each one is a standing credential
that leaks, gets committed, and outlives its purpose. Basil replaces both with
authority that is scoped and short-lived:

- The NATS **operator → account → user** NKey seeds stay custodied in the vault.
  Each service authenticates with a **user JWT lease** (minutes, not forever) and
  a signature callback that routes the server's connection nonce through
  `SignWithAlgorithm` (`ED25519_NKEY`): the seed is used in place and never
  released.
- The telemetry itself is a bare `COSE_Sign1` signed by a transit Ed25519 key
  through a **broker-backed signer**; the subscriber verifies against the public
  key it fetches from the broker. The signing key never leaves the vault either.

The result: a workload proves who it is and signs what it says, and if a service
is compromised there is no seed and no long-lived token to steal, only a lease
that expires on its own.

## Relationship to `cose-nats-demo`

This example is deliberately different from
[`examples/cose-nats-demo`](../cose-nats-demo). That demo carries **sealed
invocations** over the `basil-nats-bridge`: Alice reaches the broker *through*
NATS to perform a sealed `Sign`. Here there is **no bridge**: two NATS clients
connect **directly** to `nats-server` and exchange **bare `COSE_Sign1`**
application messages, with Basil providing the NATS credentials (leases) and the
in-place signatures (secrets). Read both to see the two COSE-over-NATS shapes
side by side.

## What it demonstrates

1. **Minted credential chain**: Basil mints the operator JWT (self-signed),
   the account JWT, and two short-lived user JWTs. `nats-server` runs in operator
   mode with the account preloaded in the memory resolver.
2. **In-place NKey auth**: both services connect with a minted user JWT and sign
   the server nonce via the broker (`ED25519_NKEY`); the seed stays custodied.
3. **Signed telemetry**: the publisher builds a bare `COSE_Sign1`
   (`build_signed`) over a telemetry payload with a `BrokerSigner`; the subscriber
   verifies it (`verify_signed`), checks the claims, and asserts payload equality.
4. **Tamper rejection**: a message with one flipped signature byte is rejected
   (`signature verification failed`).

## Basil pillars

- **Attestation** authorizes the local process against its `SO_PEERCRED`
  Unix identity before Basil will mint or sign anything.
- **Secrets**: both the COSE signature and every NATS nonce signature are
  brokered; the transit and NKey seeds are used in place.
- **Identity / Leases** mint the operator/account/user chain on demand;
  the user credentials are short-lived JWTs scoped with pub/sub permissions
  (`telemetry.>` and `_INBOX.>`), not standing secrets.

## Prerequisites

- [`bao`](https://openbao.org) (OpenBao) and
  [`nats-server`](https://nats.io) on `PATH`
- `cargo` (the script builds the `basil` agent and this example)

## How to run

```bash
examples/cose-nats-telemetry/run.sh
```

The script boots OpenBao, a `basil agent`, and an operator-mode `nats-server`,
then runs the two-service exchange. It exits `0` only if every assertion passes.

Environment overrides (all optional): `COSE_NATS_TELEMETRY_WORKDIR` (default
`/tmp/basil-cose-nats-telemetry`), `COSE_NATS_TELEMETRY_BAO_PORT` (default
`8222`), `COSE_NATS_TELEMETRY_NATS_PORT` (default `4240`), `BASIL_BIN` (path to a
prebuilt `basil` binary).

## Expected output

```
subscriber: authenticated to NATS with minted user JWT
publisher: authenticated to NATS with minted user JWT
subscriber: COSE verify true (payload matched)
subscriber: tampered message rejected (rejected:signature verification failed)
cose-nats-telemetry: all assertions passed
PASS
```

## NOTE: account JWT limits

`mint_nats_account` now mints an account JWT with an **unlimited** limits block
(`-1` connection/subscription/account limits, `JetStream` left disabled),
matching a standard `nsc` account, so an account minted with it connects fine.
Earlier it emitted an all-zero limits block, which `nats-server` reads as
**deny all** (only `-1` means unlimited), rejecting every connection with
`maximum account active connections exceeded` / `maximum subscriptions
exceeded`; that deny-all default was fixed in br `basil-1qvt`.

This example still builds the **account JWT** through the caller-supplied-claims
path (`sign_nats_jwt`) so it can pin an explicit limits block: `mint_nats_account`
defaults to unlimited but exposes no parameter to set custom limits. Reach for
`Client::mint_nats_account` when the unlimited defaults suit you, and
`sign_nats_jwt` when you need to shape the limits yourself. (The user JWTs from
`mint_nats_user` connect fine either way: absent user-level limits are treated as
unlimited.)

## See also

- [`examples/artifact-signing`](../artifact-signing): in-place signing and the
  typed deny path.
- [`examples/stream-file-encryption`](../stream-file-encryption) covers large-file
  AEAD + ML-KEM streaming where Basil owns every nonce.
- [`examples/cose-nats-demo`](../cose-nats-demo): the sealed-invocation COSE
  messaging demo carried by `basil-nats-bridge`.
- The Go mirror of this example lives at
  `clients/go/examples/cose-nats-telemetry`.
