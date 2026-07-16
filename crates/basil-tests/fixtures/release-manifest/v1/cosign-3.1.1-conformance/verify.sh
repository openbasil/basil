#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [[ $# -ne 1 ]]; then
  printf 'usage: %s /absolute/path/to/cosign\n' "$0" >&2
  exit 64
fi

cosign_bin=$1
if [[ $cosign_bin != /* || ! -x $cosign_bin ]]; then
  printf 'cosign path must be absolute and executable: %s\n' "$cosign_bin" >&2
  exit 64
fi

version=$($cosign_bin version 2>&1)
if [[ $version != *'GitVersion:    v3.1.1'* ]]; then
  printf 'fixture requires cosign v3.1.1\n' >&2
  exit 65
fi

fixture_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)

check_hash() {
  local expected=$1
  local file=$2
  local actual

  actual=$(sha256sum -- "$file")
  actual=${actual%% *}
  if [[ $actual != "$expected" ]]; then
    printf 'fixture hash mismatch: %s\n' "$file" >&2
    exit 66
  fi
}

check_hash a0cfc71271d6e278e57cd332ff957c3f7043fdda354c4cbb190a30d56efa01bf \
  "$fixture_dir/a.txt"
check_hash 82382358bdf586d1a184820ac0d0ff06eb737f459fe03baebbbd2c76e80b54a9 \
  "$fixture_dir/bundle.sigstore.json"
check_hash 4364d7724c04cc912ce2a6c45ed2610e8d8d1c4dc857fb500292738d4d9c8d2c \
  "$fixture_dir/trusted-root.json"

exec "$cosign_bin" verify-blob \
  --bundle="$fixture_dir/bundle.sigstore.json" \
  --trusted-root="$fixture_dir/trusted-root.json" \
  --certificate-identity=https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --timeout=30s \
  "$fixture_dir/a.txt"
