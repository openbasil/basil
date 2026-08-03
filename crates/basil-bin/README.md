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

| Command                  | Role                                                                                                                                                                                                                                                                   |
| ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `basil init`             | Scaffold a first-run starter set: config, catalog, policy.                                                                                                                                                                                                             |
| `basil agent`            | Run the broker daemon.                                                                                                                                                                                                                                                 |
| `basil compose …`        | Project a selected frontend's effective Compose model into bounded, secret-discarding JSON.                                                                                                                                                                            |
| `basil bundle …`         | Create and manage the sealed credential bundle (seal, verify, `set-backend`, …).                                                                                                                                                                                       |
| `basil nix key …`        | Enroll or inspect a Nix binary-cache signing key held in backend custody. The commands return public material only.                                                                                                                                                    |
| `basil nix signer serve` | Serve one backend-custodied Nix cache key through the purpose-specific local external-signer protocol.                                                                                                                                                                 |
| `basil nix cache …`      | Add, replace, or remove signatures in a local binary-cache directory with byte-preserving, atomic-per-record updates.                                                                                                                                                  |
| `basil explain`          | Explain a policy decision offline from the catalog + policy files; `--live` asks the running broker instead.                                                                                                                                                           |
| `basil doctor`           | Preflight environment and deployment checks.                                                                                                                                                                                                                           |
| `basil cache …`          | Inspect the private OCI evidence cache or preview and confirm exact-ID/reference pruning.                                                                                                                                                                              |
| client commands          | `new-key`, `import`, `import-set`, `sign`, `verify`, `encrypt`, `decrypt`, `get`, `set`, `rotate`, `list`, `mint-jwt`, `mint-nats-user`, `sign-nats-jwt`, `issue-nats-creds`, `issue-cert`, `status`, `health`, `ready`, `reload`, `revoke`, `invocation-challenge`, … |

`basil cache --check` is an integrity check as well as an inventory: it removes
safely identified corrupt regular entries as cache misses. Use `basil doctor`
when the cache must be inspected without repair.

Client commands take the socket from `--socket` or `BASIL_SOCKET`. `basil --help` is the
authoritative command reference; man pages are rendered from this crate's library surface
([`cli()`]) by the workspace `xtask`, so the shipped documentation should always be in sync with the parser.

Nix cache keys are declared in the catalog before enrollment. Generate the backend-custodied key
with `basil nix key generate-cache-key --key-id ID`; use `--json` for stable automation output.
After recording the returned public identity in the catalog and reloading Basil, read it with
`basil nix key public --key-id ID`. `convert-secret-to-public` is an alias for `public` and also
accepts a catalog key ID. Neither command accepts secret bytes or a private-key file.

Run `basil nix signer serve --key-id ID --listen ABSOLUTE_SOCKET` as the dedicated cache-publisher
user to expose one enrolled key to a local Nix client. The socket parent must be a real directory
owned by that user with mode `0700`; Basil publishes the socket at mode `0600` and admits only peers
with the same effective UID. Requests contain canonical public fingerprints only. Private key bytes
stay in backend custody.

Maintain a local cache with `basil nix cache sign`, `replace`, or `remove`.
Select canonical `/nix/store` paths with repeated `--path`, or use `--all`;
destructive `replace --all` and `remove --all` require `--yes`. A dry run
performs safe, bounded preview reads without taking or creating the cache
mutation lock. Signing and replacement verify existing signatures for the
selected key and every returned signature locally against the enrolled public
key before any record changes.
Cache mutation supports local directories only, preserves unrecognized
`.narinfo` fields byte for byte, and commits each record atomically so a failed
batch can be rerun safely.

### Nix cache mutation audit events

Each cache mutation writes best-effort JSON Lines records to standard error for
capture by journald or a CI log sink. The `basil.audit.nix_cache_mutation` v1
schema has `batch_start`, `path_commit`, `batch_failure`, `batch_cancellation`,
and `batch_completion` phases. Every record identifies the operation, selection
mode, dry-run policy, and the batch's raw 16-byte correlation ID rendered as 32
lowercase hexadecimal characters. A signing `path_commit` also has the raw sign
request ID in the same form, which joins the CLI record to the broker sign audit.

A `path_commit` appears only after the `.narinfo` rename and directory flush
succeed. Directory-flush uncertainty produces a batch failure without a path
commit. The record separates `signature_source` (`produced`, `reused`, or
`not_applicable`) from the installed or removed mutation, while terminal counts
also report unchanged and dry-run preview outcomes. Store paths and fingerprints
are represented only by SHA-256 digests rendered as 64 lowercase hexadecimal
characters. The schema excludes cache paths, payloads, signatures, fingerprints,
and private material.

Emission is not atomic with cache mutation and does not create an audit database.
An absent record proves nothing, including that no mutation committed. Operators
retain standard error in durable journald or CI storage according to their own
retention policy and rescan the cache after a failed or cancelled batch. Catchable
`SIGINT` and `SIGTERM` signals identify the cancellation; dropped asynchronous work
uses `task_cancelled`. Cancellation is observed while connecting to Basil, while
waiting for the cache lock, and between selected records. No new record begins after
the cancellation is observed. Forced termination can leave no terminal record.

## basil-measure-helper

This crate also builds `basil-measure-helper`, the root-owned, capability-minimized
measurement helper for attestor realms (one per host, on a single shared
`SOCK_SEQPACKET` endpoint). It serves broker measurement requests under a root-owned,
generation-versioned allowlist and holds no runtime API, key, or policy authority; see
`docs/attestor-realm-contract/` for the protocol contract. Startup follows the lockdown
contract (`basil-rslz`): the allowlist and manifest stores load first, then the process
engages the post-init lockdown (non-dumpable + thread-synchronized seccomp; the helper
profile denies all `clone`), and only the returned guard can bind the endpoint. The
required `--lockdown-generation` binds the engaged
`basil-measure-helper-lockdown-g<gen>` profile identity to the installed authority
generation (an explicit `--lockdown-profile` override must still validate as exactly
that identity shape). It is installed and confined by enrollment/packaging, not run by
hand.

## basil-attestor

This crate also builds `basil-attestor`, the per-realm, per-generation runtime-attestor
process the generation-qualified `basil-attestor-<realm>-g<gen>.service` unit starts
(packaged at `/usr/libexec/basil/basil-attestor`). Startup follows the lockdown
contract: create every thread and long-lived descriptor, engage the post-init lockdown
boundary (`basil-rslz`: non-dumpable + thread-synchronized seccomp; the engaged
`basil-attestor-lockdown-g<gen>` profile identity is generation-bound, and only the
returned guard can bind), then bind the realm control socket and advertise `Type=notify`
readiness — there is deliberately no socket unit, so `SO_PEERCRED`/`SO_PEERPIDFD` name
the attestor process itself. The bind validates the SPEC rev-1.2 listener topology:
the runtime directory must carry the root owner installed by the authority transaction
(`--directory-owner-uid`, default 0) while a stale socket is removed only when owned by
the separately declared socket owner (`--socket-owner-uid`, default the attestor's own
UID). The enrollment-installed `/etc/basil/attestors/<realm>/broker.toml` trust anchor
(schema `basil-attestor-broker-trust` v1) must load at startup; each accepted
connection's kernel credentials, race-free `SO_PEERPIDFD` pidfd, PID/start time, and
exact broker system unit are verified against it and bound into a `VerifiedPeerBinding`
before any protocol byte — with no broker executable measurement or release admission.
Until session construction on that binding lands (`basil-agrz`) every verified
connection is then rejected fail-closed. Installed and confined by
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
