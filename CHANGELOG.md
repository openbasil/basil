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
