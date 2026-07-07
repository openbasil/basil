<!--
SPDX-FileCopyrightText: 2026 OpenBasil Contributors

SPDX-License-Identifier: Apache-2.0
-->

# basil-bin

The unified `basil` binary: one signed binary is broker service (`basil agent`), the operator
tools (`basil init`, `basil bundle`, `basil explain`, `basil doctor`) and the client used
to invoke the broker over its Unix socket (`basil sign`, `basil get`, and the other client commands).

When used as a client, it attests as whatever Unix identity invoked it (`SO_PEERCRED`).
The CLI cannot impersonate a subject; to fetch a secret as a service, run the
command as that service's uid/gid. Running as root doesn't give permissions for more secrets
or operations, though: any process's access is still limited by the active [policy](https://docs.openbasil.org/configuration/policy/).

## Commands

Online docs: **[CLI overview](https://docs.openbasil.org/cli/overview/)** and **[command reference](https://docs.openbasil.org/cli/command-reference/)**

| Command          | Role                                                                                                                                                                                                                                           |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `basil init`     | Scaffold a first-run starter set: config, catalog, policy.                                                                                                                                                                                     |
| `basil agent`    | Run the broker daemon.                                                                                                                                                                                                                         |
| `basil bundle …` | Create and manage the sealed credential bundle (seal, verify, `set-backend`, …).                                                                                                                                                               |
| `basil explain`  | Explain a policy decision offline from the catalog + policy files; `--live` asks the running broker instead.                                                                                                                                   |
| `basil doctor`   | Preflight environment and deployment checks.                                                                                                                                                                                                   |
| client commands  | `new-key`, `import`, `import-set`, `sign`, `verify`, `encrypt`, `decrypt`, `get`, `set`, `rotate`, `list`, `mint-jwt`, `mint-nats-user`, `sign-nats-jwt`, `issue-nats-creds`, `issue-cert`, `status`, `health`, `ready`, `reload`, `revoke`, … |

Client commands take the socket from `--socket` or `BASIL_SOCKET`. `basil --help` is the
authoritative command reference; man pages are rendered from this crate's library surface
([`cli()`]) by the workspace `xtask`, so the shipped documentation should always be in sync with the from the parser.

## Feature flags

Features forward to `basil-core` and select which backends and unlock methods are compiled in.

| Feature               | Default | Adds                                                                       |
| --------------------- | ------- | -------------------------------------------------------------------------- |
| `db-keystore`         | yes     | Built-in encrypted keystore backend (SQLite via turso).                    |
| `onepassword`         | yes     | 1Password materialize-to-use backend (`op` CLI).                           |
| `unlock-age-yubikey`  | yes     | age/YubiKey bundle unlock (experimental).                                  |
| `unlock-bip39`        | yes     | BIP39 break-glass bundle unlock.                                           |
| `http` / `http-tls`   | no      | JWKS/OIDC HTTP surface, optionally with TLS.                               |
| `aws-kms` / `gcp-kms` | no      | In-place cloud KMS backends. Each adds roughly 10 MB of SDK to the binary. |
| `unlock-tpm`, `tpm2`  | no      | TPM-based unlock (experimental).                                           |
| `otlp`                | no      | OpenTelemetry OTLP export.                                                 |
| `secure-alloc`        | no      | mimalloc `secure` hardening for the allocator.                             |
