#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

root=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
docker=/nix/store/5y9rr0pvw0x1c912lhnpwv1glnj9hjxq-docker-29.6.1/bin/docker
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

"$docker" compose \
  --file "$root/compose.yaml" \
  --file "$root/compose.prod.yaml" \
  --env-file "$root/prod.env" \
  --project-name qualified-payments \
  --project-directory "$root" \
  config --format json --no-env-resolution >"$tmp/multi-file.json"
printf '\n' >>"$tmp/multi-file.json"

"$docker" compose \
  --file "$root/compose.yaml" \
  --file "$root/compose.prod.yaml" \
  --profile prod \
  --env-file "$root/prod.env" \
  --project-name qualified-payments \
  --project-directory "$root" \
  config --format json --no-env-resolution >"$tmp/prod-profile.json"
printf '\n' >>"$tmp/prod-profile.json"

cmp "$root/multi-file.json" "$tmp/multi-file.json"
cmp "$root/prod-profile.json" "$tmp/prod-profile.json"
