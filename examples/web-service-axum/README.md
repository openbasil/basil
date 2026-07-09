<!--
SPDX-FileCopyrightText: 2026 OpenBasil Contributors

SPDX-License-Identifier: Apache-2.0
-->

# web-service-axum

> **Basil is a host-local secrets broker: your app never touches the key.** The kernel attests who's
> calling, a default-deny policy decides, the key is used where it lives (OpenBao/Vault, KMS, or a
> sealed local store), and every operation is audited.

A small [axum](https://github.com/tokio-rs/axum) web service that issues signed
JWTs. **Your app can't leak a key it never held**.

## Why

The classic way a service signs tokens is to mount the signing key into the
process: a PEM file, a `JWT_SECRET` env var, a cloud credential. From that
moment every dependency, log line, memory dump, and path traversal bug in the
service is one hop from the key. Basil inverts this: the key stays in the
broker's backend and the service asks Basil to **mint** the token. The service
holds a socket path, nothing else. Compromise the whole web process and there
is still no key material to steal. The standing authority is only "mint
short-lived tokens under policy", which expires with each token.

## What it demonstrates

1. **A keyless token endpoint**: `POST /token` calls the broker's `mint_jwt`
   with the catalog id `web.signing_key`. Basil builds and signs the JWT in
   place and returns only the compact token (three base64url segments, which
   `run.sh` asserts).
2. **Attested, not configured, identity**: the broker authorizes the request by
   the service's kernel-verified uid (`SO_PEERCRED`); the service presents no
   API key or password.
3. **Least privilege, proven**: policy grants the service role exactly `mint` +
   `get_public_key` on `web.signing_key`. `run.sh` then runs
   `basil get --key-id web.signing_key` under the **same uid** and asserts it
   fails with a typed `PermissionDenied`. Minting under a key never implies
   reading it.

## Basil pillars

- **Attestation**: the policy subject matches the caller's `SO_PEERCRED` uid;
  there is no credential to configure or leak.
- **Secrets**: the Ed25519 key lives in the (db-keystore) backend and signs in
  place; the operation is brokered, never the key.
- **Leases**: `POST /token` returns a 5-minute JWT, authority that expires on
  its own instead of a standing secret.
- **Least privilege**: `mint` and `get` are distinct grants; the deny half of
  the run proves an ungranted read fails closed.

## Prerequisites

- `cargo` (builds this example crate in its own detached workspace)
- `curl`
- A `basil` binary: `BASIL_BIN`, `basil` on `PATH`, or a prior workspace debug
  build at `../../target/debug/basil` (default features include the
  zero-dependency `db-keystore` backend this example runs on. Vault/OpenBao
  are not required)

## How to run

```bash
examples/web-service-axum/run.sh
```

The script renders the catalog/policy templates for your uid, seals a bundle,
starts `basil agent` on a Unix socket, builds and starts the web service with
`BASIL_SOCKET` set, curls `POST /token`, and finally demonstrates the denial.
It cleans up every process it started, even on failure.

Environment overrides (all optional): `WEB_SERVICE_AXUM_WORKDIR` (default
`/tmp/basil-web-axum`), `WEB_SERVICE_AXUM_PORT` (default `8095`), `BASIL_BIN`.

## Expected output

```
== mint: POST /token returns a broker-signed JWT ==
token: eyJhbGciOiJFZERTQSIsImtpZCI6...<snip>...XMUDH6XAA
token shape: OK (header.claims.signature)

== deny: the same uid may NOT read the key it mints under ==
deny observed: Error: agent status [PermissionDenied/UNAUTHORIZED]: not authorized

workdir: /tmp/basil-web-axum
PASS
```

## See also

- [`examples/artifact-signing`](../artifact-signing): brokered sign/verify of a
  release manifest, with the same deny-by-default proof against an ungranted key.
- [`examples/db-keystore`](../db-keystore): the zero-dependency backend this
  example runs on, driven entirely through the `basil` CLI.
- [`clients/go/examples/web-service`](../../clients/go/examples/web-service):
  the same keyless token service in Go `net/http`.
