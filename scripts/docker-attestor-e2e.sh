#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
# SPDX-License-Identifier: Apache-2.0

# Build the current `basil-core` test binary, stage its exact Nix runtime
# closure, and run the retained Ubuntu Docker-attestor acceptance suite.

set -euo pipefail
IFS=$'\n\t'
umask 077

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
readonly SCRIPT_DIR
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
readonly REPO_ROOT
readonly EVIDENCE="$SCRIPT_DIR/compose-phase1-evidence.sh"

home=$(getent passwd "$(id -u)" | cut -d: -f6)
[[ -n $home && -d $home ]] || { printf 'cannot resolve home directory\n' >&2; exit 20; }
staging="$home/.cache/basil/compose-phase1/docker-attestor-acceptance-staging"
temporary="${staging}.tmp.$$"
trap 'rm -rf -- "$temporary"' EXIT
mkdir -p "$temporary"

cd "$REPO_ROOT"
binary=$(cargo test -p basil-core --lib --no-run --message-format=json 2>/dev/null \
  | jq -r 'select(.reason == "compiler-artifact" and .target.name == "basil_core"
      and .profile.test == true) | .executable // empty' \
  | tail -1)
[[ -n $binary && -x $binary ]] || { printf 'basil-core test binary was not produced\n' >&2; exit 20; }
install -m 0755 -- "$binary" "$temporary/basil-core-test"
strip --strip-debug "$temporary/basil-core-test"

ldd "$temporary/basil-core-test" \
  | awk '/=> \/nix\/store\//{print $3} /^[[:space:]]*\/nix\/store\//{print $1}' \
  | cut -d/ -f1-4 | sort -u >"$temporary/store-paths.txt"
[[ -s $temporary/store-paths.txt ]] \
  || { printf 'test binary has no discoverable Nix runtime closure\n' >&2; exit 20; }
mapfile -t direct_stores <"$temporary/store-paths.txt"
rootlesskit_store=$(nix build --inputs-from "path:$REPO_ROOT" --no-write-lock-file \
  nixpkgs#rootlesskit --no-link --print-out-paths)
rootlesskit="$rootlesskit_store/bin/rootlesskit"
[[ $rootlesskit == /nix/store/*/bin/rootlesskit && -x $rootlesskit ]] \
  || { printf 'RootlessKit binary was not produced\n' >&2; exit 20; }
direct_stores+=("$rootlesskit_store")
shadow_store=$(nix build --inputs-from "path:$REPO_ROOT" --no-write-lock-file \
  nixpkgs#shadow --no-link --print-out-paths \
  | while IFS= read -r path; do [[ -x $path/bin/newuidmap ]] && printf '%s\n' "$path"; done \
  | tail -1)
newuidmap="$shadow_store/bin/newuidmap"
newgidmap="$shadow_store/bin/newgidmap"
[[ -x $newuidmap && -x $newgidmap ]] \
  || { printf 'Nix uidmap helpers were not produced\n' >&2; exit 20; }
direct_stores+=("$shadow_store")
nix-store -qR "${direct_stores[@]}" | sort -u >"$temporary/store-paths.closure"
mv -- "$temporary/store-paths.closure" "$temporary/store-paths.txt"
while IFS= read -r store; do
  [[ $store == /nix/store/* && -d $store && ! -L $store ]] \
    || { printf 'invalid runtime store path: %s\n' "$store" >&2; exit 20; }
done <"$temporary/store-paths.txt"
binary_sha256=$(sha256sum -- "$temporary/basil-core-test" | cut -d ' ' -f1)
interpreter=$(readelf -l "$temporary/basil-core-test" \
  | awk '/Requesting program interpreter:/{value=$NF; gsub(/[][]/, "", value); print value}')
[[ $interpreter == /nix/store/* ]] \
  || { printf 'invalid test interpreter: %s\n' "$interpreter" >&2; exit 20; }
{
  printf 'binary_sha256\t%s\n' "$binary_sha256"
  printf 'interpreter\t%s\n' "$interpreter"
  printf 'rootlesskit\t%s\n' "$rootlesskit"
  printf 'newuidmap\t%s\n' "$newuidmap"
  printf 'newgidmap\t%s\n' "$newgidmap"
} >"$temporary/manifest.tsv"
rm -rf -- "$staging"
mv -- "$temporary" "$staging"
trap - EXIT

run_id=$($EVIDENCE prepare --lane ubuntu-24.04-x86_64 \
  --suite docker-attestor-acceptance --development)
set +e
$EVIDENCE run --run "$run_id"
run_rc=$?
set -e
$EVIDENCE collect --run "$run_id" || true
$EVIDENCE verify-run --run "$run_id" || true
printf 'run_id=%s status_rc=%s\n' "$run_id" "$run_rc"
exit "$run_rc"
