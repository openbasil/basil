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

check_hash ae1ecd212663f3693ad9edf8b1a183900c9a52d3155ba6e354237f9a0f6463fc \
  "$cosign_bin"

check_hash a0cfc71271d6e278e57cd332ff957c3f7043fdda354c4cbb190a30d56efa01bf \
  "$fixture_dir/a.txt"
check_hash 82382358bdf586d1a184820ac0d0ff06eb737f459fe03baebbbd2c76e80b54a9 \
  "$fixture_dir/bundle.sigstore.json"
check_hash 4364d7724c04cc912ce2a6c45ed2610e8d8d1c4dc857fb500292738d4d9c8d2c \
  "$fixture_dir/trusted-root.json"
check_hash 517bccb951bf552b326513e5b807b34dca32eea313e9e94da55568c735e10763 \
  "$fixture_dir/pinned-payload.json"
check_hash 322d9871840bfb4fb20deaf0ee0b63137381b922145e2f3c2c20e699f7320d12 \
  "$fixture_dir/pinned-cosign.pub"
check_hash 72317bf3990661087d8b93634812f9fe0b373e6b18d94589d860a013e68162b9 \
  "$fixture_dir/pinned-bundle.sigstore.json"
check_hash b8bed7d9428761ffd1a180b81fabf6ab0215adc8fcf3777ea547552525b463b8 \
  "$fixture_dir/pinned-config.json"
check_hash 05cc270278271fe266f155ec2a47703127c5874237b0a12f2e8a146531fd9a4e \
  "$fixture_dir/pinned-manifest.json"

"$cosign_bin" verify-blob \
  --bundle="$fixture_dir/bundle.sigstore.json" \
  --trusted-root="$fixture_dir/trusted-root.json" \
  --certificate-identity=https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --timeout=30s \
  "$fixture_dir/a.txt"

exec "$cosign_bin" verify-blob \
  --bundle="$fixture_dir/pinned-bundle.sigstore.json" \
  --key="$fixture_dir/pinned-cosign.pub" \
  --insecure-ignore-tlog \
  --timeout=30s \
  "$fixture_dir/pinned-payload.json"
