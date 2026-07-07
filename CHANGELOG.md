<!--
SPDX-FileCopyrightText: 2026 OpenBasil Contributors

SPDX-License-Identifier: Apache-2.0
-->

# Changelog

## 0.6.1

- renamed basil-client crate to basil
- Security review fixes: 1Password updates now avoid secret argv exposure, redact
  token-bearing debug output, and keep 1Password secret material in zeroizing
  owners.
- Security review fixes: reloads are serialized, catalog/policy parsing fails
  closed on unknown fields, raw issuer-key signing is denied, audit text values
  are escaped, JWKS responses are cached with conditional `304` support, and
  JWT-SVID requests are limited to the caller identity by default.
- Security review fixes: the NATS JWT validation API only exposes
  `matched_signer` for valid tokens, the NATS bridge processes requests with a
  bounded concurrency limit, BYOK `KeyMaterial` redacts and zeroizes private
  bytes, the COSE-over-NATS demo uses subscription readiness instead of a sleep,
  and the streaming encryption format now has a normative spec.
- Security review fixes: zeroization gaps closed on four secondary paths —
  deposit credential fingerprinting no longer parses the full secret JSON and
  hashes through a zeroizing buffer, value-class `get_secret` reads flow through
  the same zeroizing chain as the seed path, X.509 leaf private keys are moved
  (not copied) into wire messages that now zeroize on drop (also `get_secret`
  and `issue_certificate` responses), and the Vault `AppRole` login response is
  parsed through typed zeroizing storage instead of a JSON value tree.
- Security review fixes: `sign`/`verify` messages and signatures are bounded by
  `max_payload_size` and the NATS curve `encrypt`/`decrypt` payloads by
  `max_encrypt_size`; `validate_nats_jwt` now requires a peer that resolves to a
  policy subject and caps the presented token length; Argon2 slot parameters
  from the on-disk bundle are rejected outside a sane band before any memory is
  allocated; an oversized deposit log invalidates only its excess tail instead
  of every deposit; and a JWT-SVID without a `jti` fails validation so
  revocation always holds.
- Security review fixes: readiness classifies absent keys against the currently
  serving generation, so a hot reload flipping a key's `missing` policy takes
  effect without a restart; the admin `Watch` stream closes with `DATA_LOSS`
  when a slow watcher overflows the event buffer instead of silently skipping
  events; `Watch` subscriptions are gated by a new dedicated `op:watch` admin
  grant over `broker.watch` and audited per subscription; `status` requires a
  peer that resolves to a policy subject (it names the backend kind); and the
  ungated SDS `ValidationContext` trust bundle is documented as intentionally
  public (the same bytes the SPIFFE `FetchX509Bundles` serves ungated).
- Nix example hardening: the example package now defaults to the local flake
  instead of a remote repository.

## 0.6.0 2026-07-06

### basil-nats can build no_std

- basil-nats can now build `no_std` + `alloc` compatible: the crate source is `#![no_std]` (`extern crate alloc`) and gains `std` (default) / `alloc` cargo features; build the minimal target with `cargo build -p basil-nats --no-default-features --features alloc`
- **Breaking**: `basil_nats::seal_nats_curve` now takes an explicit `rng: &mut impl RngCore` parameter instead of calling `rand::thread_rng()` internally; pass `rand::thread_rng()` under `std`

### basil-bin (cli & basil-agent) and basil-nats-bridge new allocator

- basil and basil-nats-bridge use mimalloc as the global allocator.
  A feature flat "secure-alloc" enables mimalloc's secure mode, which enables guard pages,
  randomized allocation, and encrypted free lists; and is estimated to cause about 10% performance decrease
  (mimalloc's estimate). We'll leave the feature flag off by default uniil we do more benchmarking and testing.

### Updated Nix options & service definition

- nix/basil-options.nix
  - policyOpType - added the 5 ops the binary accepts but the enum omitted: sign_nats_jwt, validate_nats_jwt, encrypt_nats_curve, decrypt_nats_curve, use_software_custody (+ updated the rule-action doc).
  - keyEntryType.publicPath - added (required for sealing X25519 / KV-backed Ed25519).
  - policy.unauthenticatedSubject + documented the { kind = "unauthenticated"; } principal.
  - backendKindType - added the real aws-kms / gcp-kms in-place transit kinds (+ kind description).
  - settings.uid / settings.gid - nullable, for stable ownership of persistent broker state (edge's uids.basil
    lesson, upstream-friendly).
  - keystore.* - now null-defaulted (was "aegis256" / ""), so they're omitted on a stock build.
  - unlock - dropped dead insecureTestUnlock; added real unlockTpm and unlockPassphraseNoWipe.

- nix/basil-agent.nix
  - Bug fix: passphrase-file → unlock-passphrase-file (with deny_unknown_fields, the old key made any disk-passphrase config fail at startup).
  - Wired unlock-tpm / unlock-passphrase-no-wipe; keystore keys now strip to nothing when null (fixes startup failure of the default keystore-less package).
  - uid/gid pinning in users.users/users.groups; StateDirectoryMode = "0700".

- nix/backend-capabilities.nix - added accurate AWS_KMS / GCP_KMS presets (algorithms cross-checked against aws_kms.rs/gcp_kms.rs).

#### github workflows

- CI: Go unit tests and the Rust<->Go stream interop suite over the clients/go submodule (basil-ubd)
- Nix: per-architecture build targets `basil-x86_64-linux`, `basil-aarch64-linux`, `basil-aarch64-darwin`
- workflow `build.yml`: reproducible per-arch Nix builds, manual dispatch (choose architecture + branch) and automatic on `basil-v*` tags (all three platforms, tags must be on main)
- Arch Linux aarch64 package alongside x86_64 (basil-60f)
- `scripts/pin-github-actions.sh` and `just pin-actions`: pin GitHub Actions to commit SHAs, run automatically from `gen-release-workflow` (basil-yko)

### File logging

- New: option in basil-agent.toml: file logging using non-blocking, rolling file appender. Documented in basil-doc
- logging.stdout is enabled by default, unless file logging is enabled.
- Fix: If journald logger fails to connect to journald, it prints an error to stderr and stops logging.
  Previously, if journald failed to connect, it redirected the entire stream to stderr, which would be redundant with stdout logging.

### Cli simplifications

- breaking: CLI flattening: the `basil config` namespace is removed; its subcommands are promoted to top-level verbs (`basil doctor`, `basil init`, `basil explain`). There is no `basil config` command any more
- breaking: `basil config check` → `basil doctor`. Its offline capability enforcement and invocation broker-identity/key-binding validation become offline `doctor` checks; per-key present/missing detail moves under `basil doctor --keys` (per-key `key_material:<key>` rows); flag `--check-keys` → `--keys` and the `--require` gate → `--strict`. `doctor` adopts a fatal-vs-warning exit model: non-zero exit only for FATAL conditions (those that would stop the broker from starting: catalog won't load, backend unreachable, bundle won't unlock/is stale, a `missing=error` key reconcile cannot satisfy); everything else (a `missing=generate` key, an optional key absent, `bao` not on PATH, loose bundle perms) is a report-only WARNING, and `--strict` additionally fails on warnings. `DOCTOR_SCHEMA_VERSION` bumps to 2 (`status` token `fail` → `fatal`; summary gains a `fatal` count)
- breaking: `basil config init` → `basil init` (idiomatic, like `git init` / `cargo init`). `basil init` now honors the socket path (basil-u00): the generated `basil-agent.toml` `socket = ...` line follows precedence explicit `--socket <path>` > `BASIL_SOCKET` env var > `<dir>/basil.sock`, instead of always writing `<dir>/basil.sock`
- breaking: `basil config explain` → `basil explain`. `basil explain` now runs an offline policy dry-run against catalog+policy files by DEFAULT and `--live` queries the running broker; the separate over-socket `explain` verb is folded into this and removed

### Other

- bumped getrandom to 0.4.3, rand_core 0.10.1. Some crypto deps still transitively pull in getrandom 0.2.17
- Added SPDX headers
- added SECURITY.md, CODE_OF_CONDUCT.md
- added cargo aliases: 'cargo install-basil','cargo install-bridge' installs basil binary & basil-nats-bridge
- fix: add SSL_CERT_FILE in flake.nix, needed by reqwest's rustls-no-provider

---

## 2026-07-04 (0.5.4) Moved to github

- renamed crate basil to basil-client to avoid crates.io name collision
- first published on crates.io
- docs published on docs.openbasil.org
