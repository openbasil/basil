#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
# SPDX-License-Identifier: Apache-2.0

# Provisioning helper for the Ubuntu 24.04 aarch64 FUNCTIONAL-ONLY (TCG) lane
# driver `ubuntu-2404-arm64`. Run once, WITH network. It stages a small offline
# runtime payload used by the lane's architecture-sensitive container check:
#
#   * crun            -- a daemonless OCI container runtime, official static
#                        aarch64 release binary, pinned by sha256;
#   * rootfs.tar.gz   -- an aarch64 root filesystem taken verbatim from the
#                        already-pinned `workload-alpine` OCI layout (its
#                        arm64/linux layer blob, which self-addresses), so the
#                        rootfs carries the same provenance anchor as the lane's
#                        verified workload artifact and needs no new download.
#
# The two are assembled into a deterministic `payload.tar`, whose sha256 is the
# single operational trust anchor the driver re-verifies before use (OCI-digest
# discipline). The payload is staged read-only under the artifact cache at
#   <cache>/ubuntu-24.04-arm64-runtime-payload/payload.tar
# and the expected hashes live in drivers/ubuntu-2404-arm64.pins.
#
# This lane is architecture-emulation evidence only: nothing here supports a
# performance, capacity, timing, or native-host claim.

set -euo pipefail
IFS=$'\n\t'
umask 077

SELF="$(readlink -f "${BASH_SOURCE[0]}")"
FIXTURE_ROOT="$(cd "$(dirname "$SELF")" && pwd)"
readonly PINS_FILE="$FIXTURE_ROOT/drivers/ubuntu-2404-arm64.pins"
readonly WORKLOAD_LAYOUT="${BASIL_PHASE1_CACHE:-$HOME/.cache/basil/compose-phase1}/workload-alpine/image"
readonly CACHE="${BASIL_PHASE1_CACHE:-$HOME/.cache/basil/compose-phase1}"
readonly STAGING="$CACHE/ubuntu-24.04-arm64-runtime-payload"

log() { printf '[arm64-prep] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

pins_get() { grep -m1 "^$1=" "$PINS_FILE" 2>/dev/null | cut -d= -f2- || true; }

# curl helper: prefer a PATH curl, fall back to `nix run nixpkgs#curl`.
fetch() {
  local url=$1 out=$2
  if command -v curl >/dev/null 2>&1; then
    curl -sSL --max-time 300 -o "$out" "$url"
  else
    nix run nixpkgs#curl -- -sSL --max-time 300 -o "$out" "$url"
  fi
}

main() {
  [[ -f $PINS_FILE ]] || die "pins file missing: $PINS_FILE"
  local crun_sha crun_src layer_sha want_payload
  crun_sha=$(pins_get crun_sha256)
  crun_src=$(pins_get crun_source)
  layer_sha=$(pins_get rootfs_layer_sha256)
  want_payload=$(pins_get payload_sha256)
  [[ -n $crun_sha && -n $crun_src && -n $layer_sha ]] || die "pins file incomplete"

  local work
  work=$(mktemp -d)
  # shellcheck disable=SC2064
  trap "rm -rf '$work'" EXIT

  log "fetching crun ($crun_src)"
  fetch "$crun_src" "$work/crun"
  local got_crun
  got_crun=$(sha256sum "$work/crun" | cut -d' ' -f1)
  [[ $got_crun == "$crun_sha" ]] || die "crun sha256 mismatch: got $got_crun want $crun_sha"
  chmod 0755 "$work/crun"

  log "extracting aarch64 rootfs from pinned workload-alpine layer"
  local layer_blob="$WORKLOAD_LAYOUT/blobs/sha256/$layer_sha"
  [[ -f $layer_blob ]] || die "workload-alpine arm64 layer not cached: $layer_blob (fetch workload-alpine first)"
  local got_layer
  got_layer=$(sha256sum "$layer_blob" | cut -d' ' -f1)
  [[ $got_layer == "$layer_sha" ]] || die "workload-alpine arm64 layer does not self-address"
  cp "$layer_blob" "$work/rootfs.tar.gz"

  log "assembling deterministic payload.tar"
  tar --sort=name --owner=0 --group=0 --numeric-owner --mtime='UTC 2026-01-01' \
    -C "$work" -cf "$work/payload.tar" crun rootfs.tar.gz
  local got_payload
  got_payload=$(sha256sum "$work/payload.tar" | cut -d' ' -f1)
  if [[ -n $want_payload && $got_payload != "$want_payload" ]]; then
    die "payload sha256 mismatch: got $got_payload want $want_payload (update the pins file if the inputs changed intentionally)"
  fi

  mkdir -p "$STAGING"
  chmod 0700 "$STAGING"
  install -m 0600 "$work/payload.tar" "$STAGING/payload.tar"
  log "staged $STAGING/payload.tar (sha256 $got_payload)"
}

main "$@"
