<!--
SPDX-FileCopyrightText: 2026 OpenBasil Contributors

SPDX-License-Identifier: Apache-2.0
-->

# Changelog

## Unreleased

### Added

- 2026-07-05
  - SPDX headers
  - cargo aliases: 'cargo install-basil','cargo install-bridge' installs basil binary & basil-nats-bridge
  - CI: Go unit tests and the Rust<->Go stream interop suite over the clients/go submodule (basil-ubd)
  - Nix: per-architecture build targets `basil-x86_64-linux`, `basil-aarch64-linux`, `basil-aarch64-darwin`
  - workflow `build.yml`: reproducible per-arch Nix builds — manual dispatch (choose architecture + branch) and automatic on `basil-v*` tags (all three platforms, tags must be on main)
  - Arch Linux aarch64 package alongside x86_64 (basil-60f)
  - `scripts/pin-github-actions.sh` and `just pin-actions`: pin GitHub Actions to commit SHAs, run automatically from `gen-release-workflow` (basil-yko)

- 2026-07-04
  - added SECURITY.md, CODE_OF_CONDUCT.md

### Changed

- 2026-07-05
  - basil-nats is now `no_std` + `alloc` compatible: the crate source is `#![no_std]` (`extern crate alloc`) and gains `std` (default) / `alloc` cargo features; build the minimal target with `cargo build -p basil-nats --no-default-features --features alloc`
  - breaking (pre-announcement): `basil_nats::seal_nats_curve` now takes an explicit `rng: &mut impl RngCore` parameter instead of calling `rand::thread_rng()` internally; pass `rand::thread_rng()` under `std`
  - breaking (pre-announcement): CLI: `basil config check` is removed, folded into `basil doctor`. Its offline capability enforcement and invocation broker-identity/key binding validation are now offline `doctor` checks; its per-key present/missing detail moves under `basil doctor --keys` (per-key `key_material:<key>` rows). The `doctor --check-keys` flag is renamed `--keys`. The old `--require` gate is replaced by `--strict`
  - breaking (pre-announcement): `basil doctor` adopts a fatal-vs-warning exit model: non-zero exit only for FATAL conditions (those that would stop the broker from starting — catalog won't load, backend unreachable, bundle won't unlock/is stale, a `missing=error` key reconcile cannot satisfy); everything else (a `missing=generate` key, an optional key absent, `bao` not on PATH, loose bundle perms) is a report-only WARNING. `--strict` also fails on warnings. `DOCTOR_SCHEMA_VERSION` bumps to 2 (`status` token `fail` → `fatal`; summary gains a `fatal` count)
  - breaking (pre-announcement): CLI: `basil config init` is promoted to the first-tier `basil init` (idiomatic, like `git init` / `cargo init`); `basil config init` no longer exists (`basil config explain` is unchanged)
  - fix: `basil init` now honors the socket path (basil-u00): the generated `basil-agent.toml` `socket = ...` line follows precedence explicit `--socket <path>` > `BASIL_SOCKET` env var > `<dir>/basil.sock`, instead of always writing `<dir>/basil.sock`

- 2026-07-04
  - renamed basil to basil-client to avoid crates.io name collision
  - fix: add SSL_CERT_FILE in flake.nix, needed by reqwest's rustls-no-provider

## Moved to github

- 2026-07-04
  - tag: basil-v0.5.4
  - first published on crates.io
  - moved to github
  - docs published on docs.openbasil.org
