#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
# SPDX-License-Identifier: Apache-2.0

# Provisioning helper for the Compose Phase 1 `wrapper-feasibility` suite branch
# (br basil-9tj.6). Run once, WITH network. It stages the loadable workload image
# archives and the static helper binary the x86_64 lane drivers deliver into their
# guests to prototype wrapper / raw secret delivery across image families:
#
#   * images-amd64/<family>.tar.gz  -- a gzip-compressed docker-archive of each
#       pinned workload image, selected for linux/amd64 from the already-pinned
#       multi-arch OCI layout (verified by scripts/compose-phase1-artifacts.sh):
#           alpine (musl), debian (glibc), distroless/static (no shell),
#           postgres:18 (the unmodified-image acceptance target).
#       Both rootless Podman (Fedora) and rootful Docker (Ubuntu) `load` a
#       gzipped docker-archive; gzip keeps the SSH transfer into the guest small.
#   * busybox.amd64  -- a static (musl) busybox, injected read-only into the
#       shell-free distroless container so a shell-free image can still run the
#       entrypoint-interposition wrapper (the "interesting" distroless case).
#
# Each staged file is pinned by sha256 in drivers/wrapper-feasibility.pins; the
# lane drivers re-verify before delivery (OCI-digest discipline). The docker
# archives are repacked deterministically (sorted, fixed mtime/owner) and gzipped
# with `-n` so re-running this prep reproduces identical hashes.
#
# The aarch64 FUNCTIONAL-ONLY lane reuses the existing pinned crun + Alpine arm64
# rootfs payload (ubuntu-24.04-arm64-runtime-payload) and needs nothing from here.

set -euo pipefail
IFS=$'\n\t'
umask 077

SELF="$(readlink -f "${BASH_SOURCE[0]}")"
FIXTURE_ROOT="$(cd "$(dirname "$SELF")" && pwd)"
readonly PINS_FILE="$FIXTURE_ROOT/drivers/wrapper-feasibility.pins"
readonly CACHE="${BASIL_PHASE1_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/basil/compose-phase1}"
readonly STAGING="$CACHE/wrapper-feasibility-staging"
REPO_ROOT="$(cd "$FIXTURE_ROOT/../.." && pwd)"
readonly REPO_ROOT
readonly ARTIFACTS_TOOL="$REPO_ROOT/scripts/compose-phase1-artifacts.sh"
readonly IMAGE_REF_PREFIX="basil.local/wf"

# family -> workload artifact id (the pinned multi-arch OCI layout).
readonly IMAGES=(
  "alpine:workload-alpine"
  "debian:workload-debian"
  "distroless:workload-distroless"
  "postgres:workload-postgres"
)

log() { printf '[wf-prep] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }
pins_get() { grep -m1 "^$1=" "$PINS_FILE" 2>/dev/null | cut -d= -f2- || true; }

# Resolve skopeo: PATH first, else `nix shell nixpkgs#skopeo`. Emits a command
# prefix (one word per line) suitable for expansion as "${SKOPEO[@]}".
resolve_skopeo() {
  if command -v skopeo >/dev/null 2>&1; then printf 'skopeo\n'; return 0; fi
  if command -v nix >/dev/null 2>&1; then
    printf 'nix\nshell\nnixpkgs#skopeo\n--command\nskopeo\n'; return 0
  fi
  return 1
}

main() {
  command -v sha256sum >/dev/null 2>&1 || die "sha256sum required"
  command -v tar >/dev/null 2>&1 || die "tar required"
  command -v gzip >/dev/null 2>&1 || die "gzip required"
  [[ -f $ARTIFACTS_TOOL ]] || die "artifacts tool not found: $ARTIFACTS_TOOL"

  local -a SKOPEO
  mapfile -t SKOPEO < <(resolve_skopeo) || die "skopeo unavailable (install or provide nix)"
  [[ ${#SKOPEO[@]} -gt 0 ]] || die "skopeo unavailable"

  # skopeo 1.23 refuses a v1 registries.conf; provide a minimal v2 file. Digest-
  # and layout-qualified refs make search config irrelevant, but the parser still
  # rejects a v1 file if present.
  local reg; reg=$(mktemp)
  printf 'unqualified-search-registries=["docker.io"]\n' >"$reg"
  export CONTAINERS_REGISTRIES_CONF="$reg"
  local policy; policy=$(mktemp)
  printf '{"default":[{"type":"insecureAcceptAnything"}]}\n' >"$policy"

  mkdir -p "$STAGING/images-amd64"
  chmod 0700 "$STAGING"

  local work; work=$(mktemp -d)
  # shellcheck disable=SC2064
  trap "rm -rf '$work' '$reg' '$policy'" EXIT

  local entry family artifact layout
  for entry in "${IMAGES[@]}"; do
    family=${entry%%:*}
    artifact=${entry#*:}
    layout="$CACHE/$artifact/image"
    if [[ ! -d $layout ]]; then
      log "fetching $artifact (not cached)"
      "$ARTIFACTS_TOOL" fetch "$artifact" >&2 || die "fetch failed: $artifact"
    fi
    [[ -d $layout ]] || die "OCI layout missing after fetch: $layout"

    log "converting $family (linux/amd64) -> docker-archive"
    local da="$work/$family.docker.tar"
    "${SKOPEO[@]}" --policy "$policy" copy --override-arch amd64 --override-os linux \
      "oci:$layout" "docker-archive:$da:$IMAGE_REF_PREFIX/$family:wf" >&2 \
      || die "skopeo copy failed for $family"

    # Repack deterministically, then gzip -n for a reproducible pinned archive.
    local ex="$work/$family.ex"
    mkdir -p "$ex"
    tar -C "$ex" -xf "$da"
    local det="$work/$family.tar"
    tar --sort=name --owner=0 --group=0 --numeric-owner --mtime='UTC 2026-01-01' \
      -C "$ex" -cf "$det" .
    gzip -n -6 -c "$det" >"$STAGING/images-amd64/$family.tar.gz"
    local h
    h=$(sha256sum "$STAGING/images-amd64/$family.tar.gz" | cut -d' ' -f1)
    local want; want=$(pins_get "${family}_amd64_sha256")
    if [[ -n $want && $want != "$h" ]]; then
      die "$family amd64 archive sha256 mismatch: got $h want $want (update pins if inputs changed)"
    fi
    log "staged images-amd64/$family.tar.gz sha256 $h"
    printf '%s_amd64_sha256=%s\n' "$family" "$h"
    rm -rf "$ex" "$da" "$det"
  done

  # Static busybox for the shell-free (distroless) entrypoint-interposition case.
  log "building static busybox (nixpkgs#pkgsStatic.busybox)"
  local bbpath
  bbpath=$(nix build nixpkgs#pkgsStatic.busybox --no-link --print-out-paths 2>/dev/null | tail -1) \
    || die "nix build pkgsStatic.busybox failed"
  [[ -x $bbpath/bin/busybox ]] || die "static busybox not found under $bbpath/bin"
  install -m 0755 "$bbpath/bin/busybox" "$STAGING/busybox.amd64"
  local bbh
  bbh=$(sha256sum "$STAGING/busybox.amd64" | cut -d' ' -f1)
  local bbwant; bbwant=$(pins_get busybox_amd64_sha256)
  if [[ -n $bbwant && $bbwant != "$bbh" ]]; then
    die "busybox amd64 sha256 mismatch: got $bbh want $bbwant"
  fi
  log "staged busybox.amd64 sha256 $bbh"
  printf 'busybox_amd64_sha256=%s\n' "$bbh"

  log "staging complete under $STAGING"
}

main "$@"
