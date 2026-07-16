#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

root=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
expected=(
  --file "$root/compose.yaml"
  --file "$root/compose.prod.yaml"
  --profile prod
  --env-file "$root/prod.env"
  --project-name qualified-payments
  --project-directory "$root"
  config --format json --no-env-resolution
)
actual=("$@")
if (( ${#actual[@]} != ${#expected[@]} )); then
  printf 'provider argv length mismatch\n' >&2
  exit 64
fi
for ((index = 0; index < ${#expected[@]}; index++)); do
  if [[ ${actual[index]} != "${expected[index]}" ]]; then
    printf 'provider argv mismatch at index %d\n' "$index" >&2
    exit 64
  fi
done
while IFS= read -r line || [[ -n $line ]]; do
  printf '%s\n' "$line"
done <"$root/prod-profile.json"
