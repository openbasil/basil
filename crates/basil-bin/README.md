<!--
SPDX-FileCopyrightText: 2026 OpenBasil Contributors

SPDX-License-Identifier: Apache-2.0
-->

# basil-bin

> **Basil is a host-local secrets broker: your app never touches the key.** The kernel attests who's
> calling, a default-deny policy decides, the key is used where it lives (OpenBao/Vault, KMS, or a
> sealed local store), and every operation is audited.

The unified `basil` binary: one signed binary is broker service (`basil agent`), the operator
tools (`basil init`, `basil bundle`, `basil explain`, `basil doctor`, `basil cache`) and the client used
to invoke the broker over its Unix socket (`basil sign`, `basil get`, and the other client commands).

When used as a client, it attests as whatever Unix identity invoked it (`SO_PEERCRED`).
The CLI cannot impersonate a subject; to fetch a secret as a service, run the
command as that service's uid/gid. Running as root doesn't give permissions for more secrets
or operations, though: any process's access is still limited by the active [policy](https://docs.openbasil.org/configuration/policy/).

## Commands

Online docs: **[CLI overview](https://docs.openbasil.org/cli/overview/)** and **[command reference](https://docs.openbasil.org/cli/command-reference/)**

| Command           | Role                                                                                                                                                                                                                                           |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `basil init`      | Scaffold a first-run starter set: config, catalog, policy.                                                                                                                                                                                     |
| `basil agent`     | Run the broker daemon.                                                                                                                                                                                                                         |
| `basil compose …` | Project a selected frontend's effective Compose model into bounded, secret-discarding JSON.                                                                                                                                                    |
| `basil bundle …`  | Create and manage the sealed credential bundle (seal, verify, `set-backend`, …).                                                                                                                                                               |
| `basil explain`   | Explain a policy decision offline from the catalog + policy files; `--live` asks the running broker instead.                                                                                                                                   |
| `basil doctor`    | Preflight environment and deployment checks.                                                                                                                                                                                                   |
| `basil cache …`   | Inspect the private OCI evidence cache or preview and confirm exact-ID/reference pruning.                                                                                                                                                      |
| client commands   | `new-key`, `import`, `import-set`, `sign`, `verify`, `encrypt`, `decrypt`, `get`, `set`, `rotate`, `list`, `mint-jwt`, `mint-nats-user`, `sign-nats-jwt`, `issue-nats-creds`, `issue-cert`, `status`, `health`, `ready`, `reload`, `revoke`, … |

`basil cache --check` is an integrity check as well as an inventory: it removes
safely identified corrupt regular entries as cache misses. Use `basil doctor`
when the cache must be inspected without repair.

Client commands take the socket from `--socket` or `BASIL_SOCKET`. `basil --help` is the
authoritative command reference; man pages are rendered from this crate's library surface
([`cli()`]) by the workspace `xtask`, so the shipped documentation should always be in sync with the parser.

## basil-measure-helper

This crate also builds `basil-measure-helper`, the root-owned, capability-minimized
measurement helper for attestor realms (one per host, on a single shared
`SOCK_SEQPACKET` endpoint). It serves broker measurement requests under a root-owned,
generation-versioned allowlist and holds no runtime API, key, or policy authority; see
`docs/attestor-realm-contract/` for the protocol contract. It is installed and confined
by enrollment/packaging, not run by hand.

## basil-attestor

This crate also builds `basil-attestor`, the per-realm, per-generation runtime-attestor
process the generation-qualified `basil-attestor-<realm>-g<gen>.service` unit starts
(packaged at `/usr/libexec/basil/basil-attestor`). Startup follows the lockdown
contract: create every thread and long-lived descriptor, engage the post-init lockdown
boundary (`basil-rslz`), then bind the realm control socket and advertise `Type=notify`
readiness — there is deliberately no socket unit, so `SO_PEERCRED`/`SO_PEERPIDFD` name
the attestor process itself. The listener enforces the enrolled broker UID before any
protocol byte; until attestor-side session authentication lands (`basil-daaf`) every
accepted connection is then rejected fail-closed. Installed and confined by
enrollment/packaging, not run by hand.

## Feature flags

Features forward to `basil-core` and select which backends and unlock methods are compiled in.
Builds without `compose` retain the `basil compose` command and report how to install the standard
package or rebuild with the feature.

| Feature               | Default | Adds                                                                       |
| --------------------- | ------- | -------------------------------------------------------------------------- |
| `compose`             | yes     | Bounded Docker Compose v2 effective-model projection.                      |
| `db-keystore`         | yes     | Built-in encrypted keystore backend (SQLite via turso).                    |
| `onepassword`         | yes     | 1Password materialize-to-use backend (`op` CLI).                           |
| `unlock-age-yubikey`  | yes     | age/YubiKey bundle unlock (experimental).                                  |
| `unlock-bip39`        | yes     | BIP39 break-glass bundle unlock.                                           |
| `http` / `http-tls`   | no      | JWKS/OIDC HTTP surface, optionally with TLS.                               |
| `aws-kms` / `gcp-kms` | no      | In-place cloud KMS backends. Each adds roughly 10 MB of SDK to the binary. |
| `unlock-tpm`, `tpm2`  | no      | TPM-based unlock (experimental).                                           |
| `otlp`                | no      | OpenTelemetry OTLP export.                                                 |
| `secure-alloc`        | no      | mimalloc `secure` hardening for the allocator.                             |
