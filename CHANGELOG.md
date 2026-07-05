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

- 2026-07-04
  - renamed basil to basil-client to avoid crates.io name collision
  - fix: add SSL_CERT_FILE in flake.nix, needed by reqwest's rustls-no-provider

## Moved to github

- 2026-07-04
  - tag: basil-v0.5.4
  - first published on crates.io
  - moved to github
  - docs published on docs.openbasil.org
