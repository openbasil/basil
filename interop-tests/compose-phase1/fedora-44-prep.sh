#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
# SPDX-License-Identifier: Apache-2.0

# Fedora 44 lane offline-payload preparation tool (network-using, host-side).
#
# This is a checked-in recovery/reproduction script for the Fedora
# `selinux-rootless` lane. It boots the verified, cached Fedora 44 cloud image
# once with network access, resolves and downloads the EXACT package delta that
# `dnf install podman docker-compose jq` adds on top of that image, validates the
# delta online (install plus a rootless Podman container and a Compose provider
# run), pulls the pinned Alpine workload image for offline `podman load`, and
# stages a single verified payload tarball plus a pins record. The
# network-isolated lane driver (`drivers/fedora-selinux-rootless.sh`) later
# replays that exact delta offline on a fresh boot of the same base image.
#
# It never weakens SELinux and never installs an unpinned runtime payload into
# the retained lane path; all lane bytes are pinned by the emitted pins file.

set -euo pipefail
IFS=$'\n\t'
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
readonly REPO_ROOT
readonly ARTIFACT_TOOL="$REPO_ROOT/scripts/compose-phase1-artifacts.sh"
readonly PINS_FILE="$SCRIPT_DIR/drivers/fedora-selinux-rootless.pins"

readonly BASE_ARTIFACT_ID="fedora-44-cloud-x86_64"
readonly ALPINE_INDEX_DIGEST="14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce"
readonly WORKLOAD_TAG="localhost/basil-phase1/workload:alpine"

CACHE_ROOT="${BASIL_COMPOSE_ARTIFACT_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/basil/compose-phase1}"
readonly CACHE_ROOT
readonly PAYLOAD_ROOT="$CACHE_ROOT/fedora-selinux-rootless-payload"

WORK="${BASIL_FEDORA_PREP_WORK:-$(mktemp -d)}"
readonly WORK
readonly SSH_PORT="${BASIL_FEDORA_PREP_SSH_PORT:-2201}"
readonly BOOT_TIMEOUT=300
readonly PROVISION_TIMEOUT=1800

QEMU_PID=""

log() { printf '[fedora-prep] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

cleanup() {
  if [[ -n $QEMU_PID ]] && kill -0 "$QEMU_PID" 2>/dev/null; then
    kill -TERM "$QEMU_PID" 2>/dev/null || true
    for _ in $(seq 1 30); do kill -0 "$QEMU_PID" 2>/dev/null || break; sleep 0.2; done
    kill -KILL "$QEMU_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

resolve_xorriso() {
  if command -v xorriso >/dev/null 2>&1; then command -v xorriso; return 0; fi
  local pinned="/nix/store/fq867bilvp0xr0h2xafpsad44h8rl6sm-libisoburn-1.5.8.pl02/bin/xorriso"
  if [[ -x $pinned ]]; then printf '%s\n' "$pinned"; return 0; fi
  local out
  out=$(nix build --no-link --print-out-paths nixpkgs#xorriso 2>/dev/null | tail -1) || return 1
  [[ -x "$out/bin/xorriso" ]] || return 1
  printf '%s/bin/xorriso\n' "$out"
}

base_image_path() {
  local dir="$CACHE_ROOT/$BASE_ARTIFACT_ID"
  local f
  f=$(find "$dir" -maxdepth 1 -type f -name '*.qcow2' | head -1) || true
  [[ -n $f ]] || die "base image not found under $dir; run artifacts.sh fetch $BASE_ARTIFACT_ID"
  printf '%s\n' "$f"
}

ssh_opts=()
ssh_run() {
  # Remote command is intentionally expanded/interpreted on the guest side.
  # shellcheck disable=SC2029
  ssh "${ssh_opts[@]}" prep@127.0.0.1 "$@"
}

main() {
  command -v qemu-system-x86_64 >/dev/null || die "qemu-system-x86_64 not found"
  command -v qemu-img >/dev/null || die "qemu-img not found"
  command -v ssh >/dev/null || die "ssh not found"
  command -v ssh-keygen >/dev/null || die "ssh-keygen not found"
  [[ -r /dev/kvm ]] || die "/dev/kvm not available"

  log "verifying base image artifact"
  "$ARTIFACT_TOOL" verify "$BASE_ARTIFACT_ID" >/dev/null || die "base image failed verification"
  local base; base=$(base_image_path)
  log "base image: $base"

  local xorriso; xorriso=$(resolve_xorriso) || die "xorriso unavailable"
  log "xorriso: $xorriso"

  mkdir -p "$WORK"
  find "$WORK" -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null || true
  local key="$WORK/id_ed25519" seed="$WORK/seed.iso" overlay="$WORK/overlay.qcow2"
  local serial="$WORK/serial.log" known="$WORK/known_hosts"
  ssh-keygen -q -t ed25519 -N '' -C basil-fedora-prep -f "$key"
  local pub; pub=$(<"$key.pub")

  log "writing cloud-init seed"
  mkdir -p "$WORK/cidata"
  cat >"$WORK/cidata/meta-data" <<EOF
instance-id: basil-fedora-prep-$(date -u +%Y%m%d%H%M%S)
local-hostname: basil-fedora-prep
EOF
  # Quoted heredoc: nothing here is expanded on the host. The guest evaluates the
  # runcmd command substitutions; __PUBKEY__ is substituted below.
  cat >"$WORK/cidata/user-data" <<'EOF'
#cloud-config
preserve_hostname: false
hostname: basil-fedora-prep
ssh_pwauth: false
disable_root: true
users:
  - default
  - name: prep
    gecos: Fedora lane prep
    groups: [wheel]
    sudo: 'ALL=(ALL) NOPASSWD:ALL'
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
      - __PUBKEY__
runcmd:
  - [usermod, --add-subuids, '100000-165535', --add-subgids, '100000-165535', prep]
  - [loginctl, enable-linger, prep]
  - /bin/sh -c 'echo BASIL_CLOUDINIT_DONE > /dev/console'
EOF
  local pub_escaped
  pub_escaped=$(printf '%s' "$pub" | sed -e 's/[\/&]/\\&/g')
  sed -i "s/__PUBKEY__/$pub_escaped/" "$WORK/cidata/user-data"
  "$xorriso" -as mkisofs -quiet -V cidata -J -r -o "$seed" "$WORK/cidata" \
    || die "seed ISO build failed"

  log "creating overlay"
  qemu-img create -q -f qcow2 -F qcow2 -b "$base" "$overlay" >/dev/null

  log "booting prep VM (network-enabled)"
  : >"$serial"
  qemu-system-x86_64 \
    -nodefaults -no-user-config \
    -machine q35,accel=kvm -cpu host -m 4096 -smp 4 -nographic \
    -serial "file:$serial" \
    -drive "if=virtio,id=overlay,file=$overlay,format=qcow2" \
    -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22" \
    -device virtio-net-pci,netdev=net0 \
    -drive "if=virtio,format=raw,readonly=on,file=$seed" \
    >"$WORK/qemu.stderr.log" 2>&1 &
  QEMU_PID=$!

  log "waiting for cloud-init done marker"
  local waited=0 ready=0
  while (( waited < BOOT_TIMEOUT )); do
    if grep -q BASIL_CLOUDINIT_DONE "$serial" 2>/dev/null; then ready=1; break; fi
    kill -0 "$QEMU_PID" 2>/dev/null || die "qemu exited early; see $WORK/qemu.stderr.log and $serial"
    sleep 2; waited=$((waited + 2))
  done
  (( ready == 1 )) || die "cloud-init did not finish within ${BOOT_TIMEOUT}s"

  # Throwaway prep VM (not the retained lane): trust-on-first-use to a private,
  # writable known_hosts is acceptable here; the retained lane driver pins the
  # serial-established host key instead.
  : >"$known"
  ssh_opts=(
    -F /dev/null
    -p "$SSH_PORT"
    -i "$key"
    -o StrictHostKeyChecking=accept-new
    -o "UserKnownHostsFile=$known"
    -o GlobalKnownHostsFile=/dev/null
    -o PasswordAuthentication=no
    -o IdentitiesOnly=yes
    -o BatchMode=yes
    -o ConnectTimeout=10
    -o ForwardAgent=no
  )

  log "waiting for ssh"
  local ok=0
  for _ in $(seq 1 60); do
    if ssh_run true 2>/dev/null; then ok=1; break; fi
    sleep 2
  done
  (( ok == 1 )) || die "ssh never came up"

  log "running guest provisioning + online validation (this downloads packages)"
  ssh_run 'ALPINE_DIGEST='"$ALPINE_INDEX_DIGEST"' WORKLOAD_TAG='"$WORKLOAD_TAG"' bash -s' \
    <"$SCRIPT_DIR/drivers/lib/fedora-guest-provision.sh" >"$WORK/provision.out" 2>&1 &
  local prov_pid=$!
  local pw=0
  while kill -0 "$prov_pid" 2>/dev/null; do
    (( pw >= PROVISION_TIMEOUT )) && die "provisioning timed out"
    sleep 5; pw=$((pw + 5))
  done
  wait "$prov_pid" || { tail -40 "$WORK/provision.out" >&2; die "guest provisioning failed"; }
  log "guest provisioning + online validation succeeded"

  log "copying payload out"
  mkdir -p "$PAYLOAD_ROOT"
  scp "${ssh_opts[@]/#-p/-P}" -q prep@127.0.0.1:/tmp/payload.tar "$PAYLOAD_ROOT/payload.tar"
  scp "${ssh_opts[@]/#-p/-P}" -q prep@127.0.0.1:/tmp/payload.meta.json "$PAYLOAD_ROOT/payload.meta.json"

  local payload_sha; payload_sha=$(sha256sum "$PAYLOAD_ROOT/payload.tar" | cut -d' ' -f1)
  chmod 0644 "$PAYLOAD_ROOT/payload.tar" "$PAYLOAD_ROOT/payload.meta.json"

  log "writing pins file"
  {
    printf '# SPDX-FileCopyrightText: 2026 OpenBasil Contributors\n'
    printf '# SPDX-License-Identifier: Apache-2.0\n'
    printf '# Fedora 44 selinux-rootless lane package pins (generated by fedora-44-prep.sh).\n'
    printf '# The lane driver verifies payload_sha256 against the staged payload before boot.\n'
    printf 'schema=basil.compose.phase1.fedora-pins\n'
    printf 'schema_version=1\n'
    printf 'base_artifact=%s\n' "$BASE_ARTIFACT_ID"
    printf 'compose_provider=podman-compose\n'
    printf 'alpine_index_digest=sha256:%s\n' "$ALPINE_INDEX_DIGEST"
    printf 'workload_tag=%s\n' "$WORKLOAD_TAG"
    printf 'payload_sha256=%s\n' "$payload_sha"
    jq -r '
      "podman_nevra=" + .podman,
      "podman_compose_nevra=" + .podman_compose,
      "jq_nevra=" + .jq,
      "compose_provider_version=" + .compose_provider_version,
      "podman_version=" + .podman_version,
      "repomd_fedora_sha256=" + .repomd_fedora_sha256,
      "repomd_updates_sha256=" + .repomd_updates_sha256,
      "delta_rpm_count=" + (.delta_rpm_count|tostring)
    ' "$PAYLOAD_ROOT/payload.meta.json"
  } >"$PINS_FILE"
  chmod 0644 "$PINS_FILE"

  log "DONE. payload_sha256=$payload_sha"
  log "pins written to $PINS_FILE"
  log "payload staged under $PAYLOAD_ROOT"
}

main "$@"
