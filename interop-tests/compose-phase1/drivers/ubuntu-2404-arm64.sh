#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
# SPDX-License-Identifier: Apache-2.0

# Compose Phase 1 retained lane driver: Ubuntu 24.04 aarch64, FUNCTIONAL-ONLY
# architecture emulation (QEMU TCG). Selected by the `ubuntu-2404-arm64`
# allowlist entry and the `driver` field of lane `ubuntu-24.04-aarch64`.
#
# WHY FUNCTIONAL-ONLY: aarch64-on-x86_64 is cross-architecture emulation. QEMU
# runs it under TCG unconditionally -- KVM cannot accelerate a foreign guest
# architecture, so `/dev/kvm` is irrelevant here. Every result this driver
# reports is a FUNCTIONAL result: it proves an aarch64 guest boots from the
# verified image and can run architecture-sensitive wrapper/platform and
# container-runtime checks. It carries NO performance, capacity, timing, or
# native-host claim, and it makes NO LSM-enforcement qualification claim.
#
# Contract (see interop-tests/compose-phase1/README.md): the driver runs under
# the runner's read-only Bubblewrap view with only its scratch directory
# writable, a fresh network namespace (QEMU user-mode slirp is entirely
# in-namespace), a cleared environment, and a timeout. It communicates ONLY by
# writing the bounded result contract at $BASIL_DRIVER_RESULT; it writes no
# JSONL events, manifests, or sequence numbers. The runner alone emits events,
# owns the `lane.artifacts` terminal, and finalizes.
#
# The container-runtime check uses a small offline payload (a daemonless OCI
# runtime `crun` plus an aarch64 rootfs) staged and pinned out of band by
# `ubuntu-2404-arm64-prep.sh` under the artifact cache at
#   <cache>/ubuntu-24.04-arm64-runtime-payload/payload.tar
# and verified here against drivers/ubuntu-2404-arm64.pins before use. The
# bootable base image is additionally gated by the runner through the lane's
# `artifacts` list before this driver ever runs.

set -euo pipefail
IFS=$'\n\t'
umask 077

SELF="$(readlink -f "${BASH_SOURCE[0]}")"
readonly SELF
DRIVER_DIR="$(cd "$(dirname "$SELF")" && pwd)"
readonly DRIVER_DIR
readonly LIB_DIR="$DRIVER_DIR/lib"
readonly PINS_FILE="$DRIVER_DIR/ubuntu-2404-arm64.pins"
readonly DRIVER_NAME="ubuntu-2404-arm64"

readonly RESULT="${BASIL_DRIVER_RESULT:?BASIL_DRIVER_RESULT must be set by the runner}"
readonly SCRATCH="${BASIL_DRIVER_SCRATCH:?BASIL_DRIVER_SCRATCH must be set by the runner}"
readonly RESULT_SCHEMA="${BASIL_DRIVER_RESULT_SCHEMA:-basil.compose.phase1.driver-result}"
readonly RESULT_SCHEMA_VERSION="${BASIL_DRIVER_RESULT_SCHEMA_VERSION:-1}"

# aarch64 firmware and emulator pins (nix store). command -v / a bounded search
# are tried first; these are the fallbacks so the driver works when the tools
# are not on the runner's PATH (qemu-system-aarch64 is not on PATH here).
readonly QEMU_PIN="/nix/store/4vm2irmnc2kfgkn827kbq7rhcn3a6dqb-qemu-10.2.2/bin/qemu-system-aarch64"
readonly FW_CODE_PIN="/nix/store/4vm2irmnc2kfgkn827kbq7rhcn3a6dqb-qemu-10.2.2/share/qemu/edk2-aarch64-code.fd"
readonly FW_VARS_PIN="/nix/store/4vm2irmnc2kfgkn827kbq7rhcn3a6dqb-qemu-10.2.2/share/qemu/edk2-arm-vars.fd"
readonly XORRISO_PIN="/nix/store/fq867bilvp0xr0h2xafpsad44h8rl6sm-libisoburn-1.5.8.pl02/bin/xorriso"

readonly SSH_USER=basil-ci
readonly SSH_HOST=127.0.0.1

# Wall-clock deadlines (SECONDS-based, per note: TCG boots are slow; iteration
# counts expire before a slow guest is reachable). A verified reference boot to
# SSH took ~124s under 4-vcpu TCG; these leave generous headroom under the
# runner's 900s driver cap.
readonly BOOT_MARKER_TIMEOUT=600
readonly SSH_UP_TIMEOUT=240

# The four FUNCTIONAL tests this driver owns (see the arm64 functional-smoke
# suite). `lane.artifacts` is runner-owned and intentionally absent here.
readonly TESTS=(
  lane.boot
  lane.arch
  lane.cgroup-v2
  lane.container-runtime
)

declare -A ST RE MS
for _t in "${TESTS[@]}"; do ST[$_t]=INFRA_ERROR; RE[$_t]=DRIVER_DID_NOT_RUN; MS[$_t]=""; done

QEMU_PID=""
GUEST_LOG="$SCRATCH/guest-events.jsonl"

log() { printf '[arm64-driver] %s\n' "$*" >&2; }
set_res() { ST[$1]=$2; RE[$1]=$3; MS[$1]=${4:-}; }

guest_fact() {
  # Non-secret fact for private raw evidence (collected as raw/guest-events.jsonl).
  jq -cn --arg t "$1" --arg s "$2" --arg d "${3:-}" \
    '{fact:$t,status:$s,detail:$d}' >>"$GUEST_LOG" 2>/dev/null || true
}

emit_result() {
  local tmp="$SCRATCH/.results.jsonl" t
  : >"$tmp"
  for t in "${TESTS[@]}"; do
    jq -cn --arg id "$t" --arg s "${ST[$t]}" --arg r "${RE[$t]}" --arg m "${MS[$t]}" \
      '{test_id:$id,status:$s,reason_code:$r} + (if $m=="" then {} else {message:($m[0:480])} end)' \
      >>"$tmp"
  done
  jq -s --arg schema "$RESULT_SCHEMA" --argjson ver "$RESULT_SCHEMA_VERSION" \
    --arg drv "$DRIVER_NAME" \
    '{schema:$schema,schema_version:$ver,driver:$drv,results:.}' "$tmp" >"$RESULT"
  rm -f "$tmp"
}

fail_all() {
  local reason=$1 message=$2 t
  for t in "${TESTS[@]}"; do set_res "$t" INFRA_ERROR "$reason" "$message"; done
}

cleanup() {
  if [[ -n $QEMU_PID ]] && kill -0 "$QEMU_PID" 2>/dev/null; then
    kill -TERM "$QEMU_PID" 2>/dev/null || true
    for _ in $(seq 1 25); do kill -0 "$QEMU_PID" 2>/dev/null || break; sleep 0.2; done
    kill -KILL "$QEMU_PID" 2>/dev/null || true
  fi
}
trap 'cleanup' EXIT

pins_get() { grep -m1 "^$1=" "$PINS_FILE" 2>/dev/null | cut -d= -f2- || true; }

real_home() {
  local uid home _l _p _u _g _c
  uid=$(id -u)
  while IFS=: read -r _l _p _u _g _c home _; do
    [[ $_u == "$uid" ]] && { printf '%s\n' "$home"; return 0; }
  done </etc/passwd
  return 1
}

# Resolve a required tool: PATH first, then a pinned nix-store path, then a
# bounded store search. Echoes the resolved absolute path or returns non-zero.
resolve_bin() {
  local name=$1 pin=$2 hit
  if command -v "$name" >/dev/null 2>&1; then command -v "$name"; return 0; fi
  [[ -x $pin ]] && { printf '%s\n' "$pin"; return 0; }
  hit=$(find /nix/store -maxdepth 2 -name "$name" -type f 2>/dev/null | head -1)
  [[ -n $hit && -x $hit ]] && { printf '%s\n' "$hit"; return 0; }
  return 1
}

resolve_firmware() {
  local pin=$1 base=$2 hit
  [[ -f $pin ]] && { printf '%s\n' "$pin"; return 0; }
  hit=$(find /nix/store -maxdepth 3 -name "$base" -type f 2>/dev/null | head -1)
  [[ -n $hit && -f $hit ]] && { printf '%s\n' "$hit"; return 0; }
  return 1
}

# Build the boundary-conforming unprivileged aarch64 QEMU argv. The shared
# qemu-unpriv.sh builder hardcodes qemu-system-x86_64, so the aarch64 argv is
# assembled here; the SAME shared qemu_unpriv_assert_boundary() re-checks it
# against the forbidden surface (fs shares, tap/bridge net, privilege re-entry).
build_aarch64_argv() {
  local out_name=$1 qemu=$2 machine=$3 mem=$4 vcpus=$5
  local fw_code=$6 fw_vars=$7 base=$8 overlay=$9 serial=${10} qmp=${11}
  local seed=${12} ssh_port=${13}
  local -n out=$out_name
  # shellcheck disable=SC2034  # nameref: assigns through to the caller's array.
  out=(
    "$qemu"
    -nodefaults
    -no-user-config
    -machine "$machine"
    -cpu max
    -m "$mem"
    -smp "$vcpus"
    -nographic
    -serial "file:$serial"
    -qmp "unix:$qmp,server=on,wait=off"
    -drive "if=pflash,format=raw,unit=0,readonly=on,file=$fw_code"
    -drive "if=pflash,format=raw,unit=1,file=$fw_vars"
    -drive "if=none,id=base,file=$base,format=qcow2,readonly=on"
    -drive "if=virtio,id=overlay,file=$overlay,format=qcow2,backing.file.filename=$base"
    -netdev "user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:$ssh_port-:22"
    -device "virtio-net-pci,netdev=net0"
    -drive "if=virtio,format=raw,readonly=on,file=$seed"
  )
}

# The guest-side program (run as root via sudo). Installs the daemonless OCI
# runtime + rootfs from the pre-verified payload, then runs an architecture-
# sensitive container that prints its own machine type. Emits one
# `RESULT <test> <STATUS> <REASON>` line per guest-owned test plus FACT lines.
guest_program() {
  cat <<'GUEST_EOF'
#!/usr/bin/env bash
set -u
IN=/home/basil-ci/in
emit() { printf 'RESULT %s %s %s\n' "$1" "$2" "$3"; }
fact() { printf 'FACT %s\n' "$*"; }

# lane.arch: the emulated guest genuinely reports aarch64.
m=$(uname -m 2>/dev/null || echo unknown)
fact "uname_m=$m"
if [ "$m" = aarch64 ]; then emit lane.arch PASS ARCH_AARCH64
else emit lane.arch TEST_FAIL ARCH_NOT_AARCH64; fi

# lane.cgroup-v2: architecture-neutral platform fact.
cg=$(stat -fc %T /sys/fs/cgroup 2>/dev/null || echo unknown)
fact "cgroup_fs=$cg"
if [ "$cg" = cgroup2fs ]; then emit lane.cgroup-v2 PASS CGROUP_V2_PRESENT
else emit lane.cgroup-v2 TEST_FAIL CGROUP_V2_ABSENT; fi

# lane.container-runtime: run an aarch64 container with a daemonless OCI runtime.
crc=1; cout=""; cver=""
if [ -f "$IN/payload.tar" ]; then
  rm -rf "$IN/rt"; mkdir -p "$IN/rt/bundle/rootfs"
  tar -C "$IN/rt" -xf "$IN/payload.tar" 2>/dev/null
  chmod +x "$IN/rt/crun" 2>/dev/null
  tar -C "$IN/rt/bundle/rootfs" -xzf "$IN/rt/rootfs.tar.gz" 2>/dev/null
  cver=$("$IN/rt/crun" --version 2>/dev/null | awk 'NR==1{print $3}')
  cat >"$IN/rt/bundle/config.json" <<'SPEC'
{
  "ociVersion": "1.0.2",
  "process": {
    "terminal": false,
    "user": {"uid": 0, "gid": 0},
    "args": ["/bin/busybox", "uname", "-m"],
    "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/"],
    "cwd": "/",
    "capabilities": {"bounding": ["CAP_KILL"], "effective": ["CAP_KILL"], "permitted": ["CAP_KILL"]},
    "noNewPrivileges": true
  },
  "root": {"path": "rootfs", "readonly": true},
  "hostname": "basil-arm64-probe",
  "mounts": [
    {"destination": "/proc", "type": "proc", "source": "proc"},
    {"destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "mode=755"]}
  ],
  "linux": {
    "namespaces": [
      {"type": "pid"}, {"type": "ipc"}, {"type": "uts"}, {"type": "mount"}
    ]
  }
}
SPEC
  cout=$(cd "$IN/rt/bundle" && "$IN/rt/crun" run --no-pivot basil-arm64-probe 2>/tmp/crun.err)
  crc=$?
  [ "$crc" -eq 0 ] || fact "crun_err=$(tr -d '\n' </tmp/crun.err 2>/dev/null | tail -c 200)"
else
  fact "payload_missing"
fi
fact "container_runtime=crun ${cver} container_arch=${cout}"
if [ "$crc" -eq 0 ] && [ "$cout" = aarch64 ]; then
  emit lane.container-runtime PASS CONTAINER_RAN_AARCH64
else
  emit lane.container-runtime TEST_FAIL CONTAINER_RUN_FAILED
fi
GUEST_EOF
}

main() {
  : >"$GUEST_LOG"

  # Self-locate the run root from fixed contract inputs (scratch is
  # <run>/transient/driver/scratch).
  local run
  run=$(realpath -e -- "$SCRATCH/../../.." 2>/dev/null) \
    || { fail_all RUN_DIR_UNRESOLVED "$SCRATCH"; emit_result; return 0; }
  [[ -f $run/meta/run.json ]] \
    || { fail_all RUN_METADATA_MISSING "$run"; emit_result; return 0; }
  local fixture_root
  fixture_root=$(cd "$DRIVER_DIR/.." && pwd)

  # Host tools.
  local tool
  for tool in jq qemu-img ssh scp sed awk sha256sum; do
    command -v "$tool" >/dev/null 2>&1 \
      || { fail_all TOOL_MISSING "missing $tool"; emit_result; return 0; }
  done
  local qemu xorriso fw_code fw_vars
  qemu=$(resolve_bin qemu-system-aarch64 "$QEMU_PIN") \
    || { fail_all TOOL_MISSING "qemu-system-aarch64 unavailable"; emit_result; return 0; }
  xorriso=$(resolve_bin xorriso "$XORRISO_PIN") \
    || { fail_all TOOL_MISSING "xorriso unavailable"; emit_result; return 0; }
  fw_code=$(resolve_firmware "$FW_CODE_PIN" edk2-aarch64-code.fd) \
    || { fail_all FIRMWARE_MISSING "aarch64 UEFI code firmware unavailable"; emit_result; return 0; }
  fw_vars=$(resolve_firmware "$FW_VARS_PIN" edk2-arm-vars.fd) \
    || { fail_all FIRMWARE_MISSING "aarch64 UEFI vars template unavailable"; emit_result; return 0; }

  # Lane configuration travels in run metadata (`.lane` is the full lock row).
  local memory_mib vcpus machine cloud_init_rel
  memory_mib=$(jq -er '.lane.memory_mib' "$run/meta/run.json") \
    || { fail_all LANE_MEMORY_UNSET ""; emit_result; return 0; }
  vcpus=$(jq -er '.lane.vcpus' "$run/meta/run.json") \
    || { fail_all LANE_VCPUS_UNSET ""; emit_result; return 0; }
  machine=$(jq -er '.lane.machine' "$run/meta/run.json") \
    || { fail_all LANE_MACHINE_UNSET ""; emit_result; return 0; }
  cloud_init_rel=$(jq -er '.lane.cloud_init' "$run/meta/run.json") \
    || { fail_all LANE_CLOUDINIT_UNSET ""; emit_result; return 0; }
  local cloud_init_template="$fixture_root/$cloud_init_rel"
  [[ -f $cloud_init_template ]] \
    || { fail_all CLOUDINIT_TEMPLATE_MISSING "$cloud_init_rel"; emit_result; return 0; }

  # Cache + verified base image (from the lane's cloud artifact id).
  local home cache
  home=$(real_home) || { fail_all ENV_UNRESOLVED "cannot resolve home"; emit_result; return 0; }
  cache="$home/.cache/basil/compose-phase1"
  local cloud_id base_image
  cloud_id=$(jq -r '.lane.artifacts[] | select(test("cloud"))' "$run/meta/run.json" | head -1)
  [[ -n $cloud_id ]] || { fail_all CLOUD_ARTIFACT_UNLISTED ""; emit_result; return 0; }
  base_image=$(find "$cache/$cloud_id" -maxdepth 1 -type f \( -name '*.img' -o -name '*.qcow2' \) 2>/dev/null | head -1)
  [[ -n $base_image && -f $base_image ]] \
    || { fail_all BASE_IMAGE_MISSING "$cache/$cloud_id"; emit_result; return 0; }

  # Pinned offline runtime payload (fail closed on hash mismatch).
  local want_payload staging payload
  want_payload=$(pins_get payload_sha256)
  [[ -n $want_payload ]] \
    || { fail_all PAYLOAD_UNPINNED "pins file missing payload_sha256"; emit_result; return 0; }
  staging="$cache/ubuntu-24.04-arm64-runtime-payload"
  payload="$staging/payload.tar"
  [[ -f $payload ]] \
    || { fail_all PAYLOAD_MISSING "staged payload not found; run ubuntu-2404-arm64-prep.sh"; emit_result; return 0; }
  local got_payload
  got_payload=$(sha256sum "$payload" | cut -d' ' -f1)
  [[ $got_payload == "$want_payload" ]] \
    || { fail_all PAYLOAD_UNVERIFIED "payload sha256 mismatch"; emit_result; return 0; }
  guest_fact payload.verified PASS "$got_payload"

  # Per-run SSH material (prepared by the runner).
  local ssh_key="$run/transient/ssh/id_ed25519"
  local ssh_pub="$run/meta/ssh-public-key"
  [[ -f $ssh_key ]] || { fail_all SSH_KEY_MISSING "$ssh_key"; emit_result; return 0; }
  [[ -f $ssh_pub ]] || { fail_all SSH_PUBLIC_KEY_MISSING "$ssh_pub"; emit_result; return 0; }

  # Build the writable per-run VM state inside scratch.
  local overlay="$SCRATCH/overlay.qcow2"
  local fw_vars_rw="$SCRATCH/vars.fd"
  local serial="$SCRATCH/serial.log"
  local qmp="q.sock"
  local seed="$SCRATCH/seed.iso"
  local known="$SCRATCH/known_hosts"
  local cidata="$SCRATCH/cidata"

  if ! cp -f "$fw_vars" "$fw_vars_rw" || ! chmod u+w "$fw_vars_rw"; then
    fail_all FIRMWARE_VARS_COPY_FAILED ""; emit_result; return 0
  fi
  qemu-img create -q -f qcow2 -F qcow2 -b "$base_image" "$overlay" 16G >/dev/null \
    || { fail_all OVERLAY_FAILED "qemu-img create failed"; emit_result; return 0; }

  mkdir -p "$cidata"
  local pub_escaped
  pub_escaped=$(sed -e 's/[\/&|]/\\&/g' "$ssh_pub")
  sed "s|__BASIL_PHASE1_SSH_PUBLIC_KEY__|$pub_escaped|" "$cloud_init_template" >"$cidata/user-data" \
    || { fail_all CLOUDINIT_RENDER_FAILED ""; emit_result; return 0; }
  printf 'instance-id: %s\nlocal-hostname: basil-phase1-ubuntu2404-arm64\n' \
    "basil-phase1-${BASIL_RUN_ID:-run}" >"$cidata/meta-data"
  "$xorriso" -as mkisofs -quiet -V CIDATA -J -r -o "$seed" "$cidata" \
    || { fail_all SEED_BUILD_FAILED "xorriso failed"; emit_result; return 0; }

  local ssh_port
  ssh_port=$(( (RANDOM % 20000) + 30000 ))

  # Assemble the aarch64 argv and fail closed if it violates the VM boundary.
  # shellcheck source=lib/qemu-unpriv.sh disable=SC1091
  source "$LIB_DIR/qemu-unpriv.sh" \
    || { fail_all QEMU_LIB_MISSING ""; emit_result; return 0; }
  local -a qargv=()
  build_aarch64_argv qargv \
    "$qemu" "$machine" "$memory_mib" "$vcpus" \
    "$fw_code" "$fw_vars_rw" "$base_image" "$overlay" "$serial" "$qmp" \
    "$seed" "$ssh_port"
  qemu_unpriv_assert_boundary "${qargv[@]}" \
    || { fail_all BOUNDARY_REJECTED "aarch64 argv failed the VM boundary assertion"; emit_result; return 0; }

  log "booting aarch64 guest under TCG (functional-only; KVM cannot accelerate a foreign arch)"
  : >"$serial"
  "${qargv[@]}" >"$SCRATCH/qemu.stderr.log" 2>&1 &
  QEMU_PID=$!

  # Serial-established ed25519 host key (cloud-init prints host keys to console).
  local hostkey="" deadline=$((SECONDS + BOOT_MARKER_TIMEOUT))
  local marker='Basil Compose Phase 1 Ubuntu arm64 functional foundation ready'
  local saw_marker=no
  while (( SECONDS < deadline )); do
    if grep -qa "$marker" "$serial" 2>/dev/null; then saw_marker=yes; fi
    if grep -aq 'BEGIN SSH HOST KEY KEYS' "$serial" 2>/dev/null; then
      hostkey=$(sed -n '/BEGIN SSH HOST KEY KEYS/,/END SSH HOST KEY KEYS/p' "$serial" \
        | tr -d '\r' | awk '/^ssh-ed25519 /{print $1" "$2; exit}')
      [[ $hostkey == ssh-ed25519\ * && $saw_marker == yes ]] && break
      [[ $saw_marker == yes ]] || hostkey=""
    fi
    kill -0 "$QEMU_PID" 2>/dev/null \
      || { fail_all VM_EXITED "qemu exited during boot"; emit_result; return 0; }
    sleep 5
  done
  [[ -n $hostkey ]] \
    || { fail_all VM_BOOT_TIMEOUT "no serial host key/marker within ${BOOT_MARKER_TIMEOUT}s"; emit_result; return 0; }
  printf '[%s]:%s %s\n' "$SSH_HOST" "$ssh_port" "$hostkey" >"$known"
  guest_fact hostkey.pinned PASS serial-established

  # -F /dev/null: skip user AND system ssh configs (nix-store ssh_config.d
  # drop-ins fail OpenSSH's ownership check inside the runner's user namespace).
  local -a ssh_base=(ssh -F /dev/null -i "$ssh_key" -p "$ssh_port"
    -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$known"
    -o GlobalKnownHostsFile=/dev/null -o IdentitiesOnly=yes
    -o BatchMode=yes -o PasswordAuthentication=no -o ConnectTimeout=10)
  local -a scp_base=(scp -F /dev/null -i "$ssh_key" -P "$ssh_port"
    -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$known"
    -o GlobalKnownHostsFile=/dev/null -o IdentitiesOnly=yes
    -o BatchMode=yes -o PasswordAuthentication=no)

  local up=no ssh_deadline=$((SECONDS + SSH_UP_TIMEOUT))
  while (( SECONDS < ssh_deadline )); do
    if "${ssh_base[@]}" "$SSH_USER@$SSH_HOST" true 2>/dev/null; then up=yes; break; fi
    kill -0 "$QEMU_PID" 2>/dev/null \
      || { fail_all VM_EXITED "qemu exited before ssh"; emit_result; return 0; }
    sleep 5
  done
  [[ $up == yes ]] \
    || { fail_all SSH_UNAVAILABLE "ssh never came up within ${SSH_UP_TIMEOUT}s"; emit_result; return 0; }

  # The aarch64 guest booted from the verified image and is reachable.
  set_res lane.boot PASS BOOT_FROM_VERIFIED_IMAGE "serial marker + ssh reachable"
  guest_fact boot PASS reachable

  # Stage the pinned payload and run the guest checks as root.
  "${ssh_base[@]}" "$SSH_USER@$SSH_HOST" 'mkdir -p /home/basil-ci/in' 2>/dev/null \
    || { fail_all GUEST_STAGE_MKDIR_FAILED ""; emit_result; return 0; }
  "${scp_base[@]}" "$payload" "$SSH_USER@$SSH_HOST:/home/basil-ci/in/payload.tar" >/dev/null 2>&1 \
    || { fail_all GUEST_PAYLOAD_COPY_FAILED ""; emit_result; return 0; }
  guest_program | "${ssh_base[@]}" "$SSH_USER@$SSH_HOST" 'cat >/home/basil-ci/in/checks.sh' 2>/dev/null \
    || { fail_all GUEST_CHECK_COPY_FAILED ""; emit_result; return 0; }

  local guest_out
  guest_out=$("${ssh_base[@]}" "$SSH_USER@$SSH_HOST" 'sudo -n bash /home/basil-ci/in/checks.sh' 2>&1) || true
  printf '%s\n' "$guest_out" | grep -E '^(FACT|RESULT) ' >>"$SCRATCH/guest.transcript" 2>/dev/null || true

  local produced=no tag test_id status reason
  while IFS=' ' read -r tag test_id status reason; do
    [[ $tag == RESULT ]] || continue
    [[ -n $test_id && -n $status && -n $reason ]] || continue
    set_res "$test_id" "$status" "$reason"
    guest_fact "$test_id" "$status" "$reason"
    produced=yes
  done < <(printf '%s\n' "$guest_out")
  [[ $produced == yes ]] \
    || { fail_all GUEST_CHECKS_PRODUCED_NO_RESULT ""; emit_result; return 0; }

  # Graceful guest shutdown before the trap reaps QEMU.
  "${ssh_base[@]}" "$SSH_USER@$SSH_HOST" 'sudo -n poweroff' 2>/dev/null || true

  emit_result
  log "checks complete"
}

main "$@"
