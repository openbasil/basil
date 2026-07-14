#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
# SPDX-License-Identifier: Apache-2.0

# Compose Phase 1 retained lane driver: Fedora 44 x86_64, SELinux enforcing,
# rootless Podman, two lingering rootless owners, pinned rootless Compose
# provider. Selected by the `fedora-selinux-rootless` allowlist entry and the
# `driver` field of lane `fedora-44-x86_64`.
#
# Contract (see interop-tests/compose-phase1/README.md): this driver runs under
# the runner's read-only Bubblewrap view with only its scratch directory
# writable, a fresh network namespace (no host network; QEMU user-mode slirp is
# entirely in-namespace), a cleared environment, and a timeout. It communicates
# ONLY by writing the bounded result contract at $BASIL_DRIVER_RESULT; it writes
# no JSONL events, manifests, or sequence numbers. The runner alone emits events
# and finalizes.
#
# It boots the verified, cached Fedora 44 cloud image (immutable read-only
# backing plus a per-run qcow2 overlay) via cloud-init, installs ONLY the pinned,
# pre-verified offline payload (Podman + podman-compose + jq) delivered read-only
# on the seed disk, and never weakens SELinux. Because the sandbox exposes no
# /dev/kvm, QEMU runs under TCG emulation; results are functional, not timing
# claims. The offline payload is staged and pinned by fedora-44-prep.sh.

set -euo pipefail
IFS=$'\n\t'
umask 077

SELF="$(readlink -f "${BASH_SOURCE[0]}")"
readonly SELF
DRIVER_DIR="$(cd "$(dirname "$SELF")" && pwd)"
readonly DRIVER_DIR
FIXTURE_ROOT="$(cd "$DRIVER_DIR/.." && pwd)"
readonly FIXTURE_ROOT
REPO_ROOT="$(cd "$FIXTURE_ROOT/../.." && pwd)"
readonly REPO_ROOT
readonly LIB_DIR="$DRIVER_DIR/lib"
readonly PINS_FILE="$DRIVER_DIR/fedora-selinux-rootless.pins"
readonly CLOUD_INIT="$FIXTURE_ROOT/cloud-init/fedora-44.yaml"
readonly ARTIFACT_TSV="$REPO_ROOT/scripts/compose-phase1-artifacts.lock.tsv"
readonly BASE_ARTIFACT_ID="fedora-44-cloud-x86_64"

readonly RESULT="${BASIL_DRIVER_RESULT:?BASIL_DRIVER_RESULT must be set by the runner}"
readonly SCRATCH="${BASIL_DRIVER_SCRATCH:?BASIL_DRIVER_SCRATCH must be set by the runner}"
readonly RESULT_SCHEMA="${BASIL_DRIVER_RESULT_SCHEMA:-basil.compose.phase1.driver-result}"
readonly RESULT_SCHEMA_VERSION="${BASIL_DRIVER_RESULT_SCHEMA_VERSION:-1}"
readonly DRIVER_NAME="fedora-selinux-rootless"

# Fixed lane resources; mirror phase1.lock.toml [lanes.fedora-44-x86_64]. The
# host is shared, so the guest stays modest. accel=kvm:tcg uses KVM when the
# runner sandbox exposes /dev/kvm and degrades to TCG functional-only emulation
# when it does not (the stock sandbox's --dev /dev omits /dev/kvm; basil-k78).
readonly MEMORY_MIB=4096
readonly VCPUS=4
readonly MACHINE="q35,accel=kvm:tcg"
readonly BOOT_MARKER_TIMEOUT=480
readonly SSH_UP_TIMEOUT=240

# Suite selection (exported by the runner as BASIL_DRIVER_SUITE). The
# capacity-preflight suite (basil-ge9) reports the four preflight.* terminals
# by running guest/capacity-preflight.sh inside the booted guest; every other
# suite keeps the original fedora-smoke lane test set unchanged.
readonly SUITE="${BASIL_DRIVER_SUITE:-fedora-smoke}"
if [[ $SUITE == capacity-preflight ]]; then
  readonly TESTS=(
    preflight.host-baseline
    preflight.runtime-baseline
    preflight.evidence-retention
    preflight.stop-conditions
  )
else
  # The 7 lane-smoke tests this driver owns (see [suites.fedora-smoke]).
  readonly TESTS=(
    lane.cgroup-v2
    lane.lsm-enforcing
    lane.runtime-mode
    lane.rootless-owner-a
    lane.rootless-owner-b
    lane.compose-provider
    lane.network-isolation
  )
fi

declare -A ST RE MS
for _t in "${TESTS[@]}"; do ST[$_t]=INFRA_ERROR; RE[$_t]=DRIVER_DID_NOT_RUN; MS[$_t]=""; done

QEMU_PID=""
GUEST_LOG="$SCRATCH/guest-events.jsonl"

log() { printf '[fedora-driver] %s\n' "$*" >&2; }

set_res() { ST[$1]=$2; RE[$1]=$3; MS[$1]=${4:-}; }

guest_fact() {
  # Append a non-secret fact line for private raw evidence (collected by the
  # runner as raw/guest-events.jsonl). Never authoritative; result.json decides.
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

cleanup() {
  if [[ -n $QEMU_PID ]] && kill -0 "$QEMU_PID" 2>/dev/null; then
    kill -TERM "$QEMU_PID" 2>/dev/null || true
    for _ in $(seq 1 25); do kill -0 "$QEMU_PID" 2>/dev/null || break; sleep 0.2; done
    kill -KILL "$QEMU_PID" 2>/dev/null || true
  fi
}
trap 'cleanup' EXIT

fail_all() {
  local reason=$1 message=$2 t
  for t in "${TESTS[@]}"; do set_res "$t" INFRA_ERROR "$reason" "$message"; done
}

pins_get() { grep -m1 "^$1=" "$PINS_FILE" 2>/dev/null | cut -d= -f2- || true; }

real_home() {
  local uid home _l _p _u _g _c
  uid=$(id -u)
  while IFS=: read -r _l _p _u _g _c home _; do
    [[ $_u == "$uid" ]] && { printf '%s\n' "$home"; return 0; }
  done </etc/passwd
  return 1
}

base_image_path() {
  local cache=$1 id fname _s _st _k _pl _rest name=""
  while IFS=$'\t' read -r _s id _st _k _pl fname _rest; do
    [[ $id == "$BASE_ARTIFACT_ID" ]] && { name=$fname; break; }
  done <"$ARTIFACT_TSV"
  [[ -n $name ]] || return 1
  printf '%s/%s/%s\n' "$cache" "$BASE_ARTIFACT_ID" "$name"
}

resolve_xorriso() {
  if command -v xorriso >/dev/null 2>&1; then command -v xorriso; return 0; fi
  local pinned="/nix/store/fq867bilvp0xr0h2xafpsad44h8rl6sm-libisoburn-1.5.8.pl02/bin/xorriso"
  [[ -x $pinned ]] && { printf '%s\n' "$pinned"; return 0; }
  return 1
}

# ---- SSH helpers (strict host-key pinning from the serial console) ----------
SSH_PORT=""
KEY="$SCRATCH/id_ed25519"
KNOWN="$SCRATCH/known_hosts"
ssh_base=()

# Remote command strings are intentionally interpreted on the guest side.
# shellcheck disable=SC2029
ssh_user() { local u=$1; shift; ssh "${ssh_base[@]}" "$u@127.0.0.1" "$@"; }
# shellcheck disable=SC2029
ssh_script() { local u=$1 envp=${2:-}; ssh "${ssh_base[@]}" "$u@127.0.0.1" "$envp bash -s"; }

main() {
  : >"$GUEST_LOG"
  for tool in qemu-system-x86_64 qemu-img ssh ssh-keygen jq; do
    command -v "$tool" >/dev/null 2>&1 || { fail_all TOOL_MISSING "missing $tool"; emit_result; return 0; }
  done

  local xorriso; xorriso=$(resolve_xorriso) \
    || { fail_all TOOL_MISSING "xorriso unavailable in sandbox PATH"; emit_result; return 0; }

  local home cache payload_root payload_tar base
  home=$(real_home) || { fail_all ENV_UNRESOLVED "cannot resolve home"; emit_result; return 0; }
  cache="$home/.cache/basil/compose-phase1"
  payload_root="$cache/fedora-selinux-rootless-payload"
  payload_tar="$payload_root/payload.tar"

  # Pinned payload verification (fail closed).
  local want_sha; want_sha=$(pins_get payload_sha256)
  local wtag; wtag=$(pins_get workload_tag)
  [[ -n $want_sha && -n $wtag ]] \
    || { fail_all PAYLOAD_UNPINNED "pins file missing payload_sha256/workload_tag"; emit_result; return 0; }
  [[ -f $payload_tar ]] \
    || { fail_all PAYLOAD_MISSING "staged payload not found; run fedora-44-prep.sh"; emit_result; return 0; }
  local got_sha; got_sha=$(sha256sum "$payload_tar" | cut -d' ' -f1)
  [[ $got_sha == "$want_sha" ]] \
    || { fail_all PAYLOAD_UNVERIFIED "payload sha256 mismatch"; emit_result; return 0; }
  guest_fact payload.verified PASS "$got_sha"

  base=$(base_image_path "$cache") \
    || { fail_all BASE_UNRESOLVED "base image row not found"; emit_result; return 0; }
  [[ -f $base ]] \
    || { fail_all BASE_MISSING "verified base image not in cache"; emit_result; return 0; }

  # Extract payload into the writable scratch, build the cloud-init seed tree.
  local cidata="$SCRATCH/cidata"
  mkdir -p "$cidata/payload"
  tar -C "$cidata/payload" -xf "$payload_tar"

  ssh-keygen -q -t ed25519 -N '' -C "$DRIVER_NAME" -f "$KEY"
  local pub; pub=$(<"$KEY.pub")
  local pub_escaped; pub_escaped=$(printf '%s' "$pub" | sed -e 's/[\/&]/\\&/g')
  sed "s/__BASIL_PHASE1_SSH_PUBLIC_KEY__/$pub_escaped/g" "$CLOUD_INIT" >"$cidata/user-data"
  printf 'instance-id: %s\nlocal-hostname: basil-phase1-fedora44\n' \
    "basil-phase1-${BASIL_RUN_ID:-run}" >"$cidata/meta-data"

  local seed="$SCRATCH/seed.iso"
  "$xorriso" -as mkisofs -quiet -V cidata -J -r -o "$seed" "$cidata" \
    || { fail_all SEED_BUILD_FAILED "xorriso failed"; emit_result; return 0; }

  local overlay="$SCRATCH/overlay.qcow2"
  qemu-img create -q -f qcow2 -F qcow2 -b "$base" "$overlay" >/dev/null \
    || { fail_all OVERLAY_FAILED "qemu-img create failed"; emit_result; return 0; }

  SSH_PORT=$(( (RANDOM % 20000) + 30000 ))
  # QMP is unused by this driver, but the boundary builder always adds it. Use a
  # short RELATIVE socket name: QEMU's cwd is the scratch dir (bwrap --chdir), so
  # the socket lands in scratch while staying under the 108-byte AF_UNIX sun_path
  # limit that an absolute evidence-root path would exceed.
  local serial="$SCRATCH/serial.log" qmp="qmp.sock"
  : >"$serial"

  # Boundary-conforming unprivileged QEMU argv (restrict=on loopback user net).
  # shellcheck source=lib/qemu-unpriv.sh disable=SC1091
  source "$LIB_DIR/qemu-unpriv.sh"
  local -a qargv=()
  qemu_unpriv_build_argv qargv \
    "$base" "$overlay" "$serial" "$qmp" "$SSH_PORT" "$seed" \
    "$MEMORY_MIB" "$VCPUS" "$MACHINE" \
    || { fail_all BOUNDARY_REJECTED "qemu argv builder rejected inputs"; emit_result; return 0; }
  if ! qemu_unpriv_assert_boundary "${qargv[@]}"; then
    fail_all BOUNDARY_REJECTED "qemu argv failed the VM boundary assertion"
    emit_result; return 0
  fi
  # The structural network-isolation assertion (loopback-only user networking,
  # restrict=on, no host bridge/tap/fs share) is now proven for this boot.
  # Only the lane-smoke suite reports this terminal.
  if [[ $SUITE != capacity-preflight ]]; then
    set_res lane.network-isolation PASS NETWORK_LOOPBACK_ONLY "restrict=on loopback user-net"
  fi

  if [[ -e /dev/kvm ]]; then
    log "booting guest (accel=kvm:tcg; /dev/kvm present in sandbox)"
  else
    log "booting guest (accel=kvm:tcg degrades to TCG; no /dev/kvm in sandbox, functional-only)"
  fi
  "${qargv[@]}" >"$SCRATCH/qemu.stderr.log" 2>&1 &
  QEMU_PID=$!

  # Pin the serial-established ed25519 host key (wall-clock deadline).
  local hostkey="" deadline=$((SECONDS + BOOT_MARKER_TIMEOUT))
  while (( SECONDS < deadline )); do
    if grep -aq '^BASIL_HOSTKEY_ED25519 ' "$serial" 2>/dev/null; then
      hostkey=$(grep -a -m1 '^BASIL_HOSTKEY_ED25519 ' "$serial" | tr -d '\r' | cut -d' ' -f2-)
      [[ $hostkey == ssh-ed25519\ * ]] && break
      hostkey=""
    fi
    kill -0 "$QEMU_PID" 2>/dev/null || { fail_all VM_EXITED "qemu exited during boot"; emit_result; return 0; }
    sleep 3
  done
  [[ -n $hostkey ]] || { fail_all VM_BOOT_TIMEOUT "no serial host key within ${BOOT_MARKER_TIMEOUT}s"; emit_result; return 0; }
  printf '[127.0.0.1]:%s %s\n' "$SSH_PORT" "$hostkey" >"$KNOWN"
  guest_fact hostkey.pinned PASS "serial-established"

  # -F /dev/null: skip user AND system ssh configs. Inside the runner's user
  # namespace, nix-store ssh_config.d drop-ins fail OpenSSH's strict ownership
  # check ("Bad owner or permissions") and abort the client outright.
  ssh_base=(
    -F /dev/null
    -p "$SSH_PORT" -i "$KEY"
    -o StrictHostKeyChecking=yes
    -o "UserKnownHostsFile=$KNOWN"
    -o GlobalKnownHostsFile=/dev/null
    -o PasswordAuthentication=no
    -o IdentitiesOnly=yes
    -o BatchMode=yes
    -o ConnectTimeout=10
    -o ForwardAgent=no
    -o ServerAliveInterval=15
  )

  local up=0 ssh_deadline=$((SECONDS + SSH_UP_TIMEOUT))
  while (( SECONDS < ssh_deadline )); do
    if ssh_user phase1-a true 2>/dev/null; then up=1; break; fi
    kill -0 "$QEMU_PID" 2>/dev/null || { fail_all VM_EXITED "qemu exited before ssh"; emit_result; return 0; }
    sleep 4
  done
  (( up == 1 )) || { fail_all SSH_UNAVAILABLE "ssh never came up within ${SSH_UP_TIMEOUT}s"; emit_result; return 0; }

  # Let cloud-init finish the offline install if it hasn't yet.
  ssh_user phase1-a 'cloud-init status --wait >/dev/null 2>&1 || true' 2>/dev/null || true

  if [[ $SUITE == capacity-preflight ]]; then
    run_capacity_preflight
  else
    run_checks "$wtag"
  fi
  emit_result
  log "checks complete"
}

# Capacity-preflight suite (basil-ge9): inject guest/capacity-preflight.sh into
# the booted guest over ssh stdin, run it as rootless owner A, retain its full
# bounded JSONL as raw evidence, and map it onto the four preflight.* terminals.
# This is environment-readiness EVIDENCE COLLECTION, not the basil-9tj.4
# measurement: each terminal asserts that a readiness fact set was collected
# completely (and, for the runtime, that the lane's required mode was observed);
# the guest's ready/blocker verdict is carried in the bounded messages and the
# retained raw JSONL, never converted into or hidden behind a pass.
run_capacity_preflight() {
  local pf="$FIXTURE_ROOT/guest/capacity-preflight.sh"
  local out="$SCRATCH/preflight.jsonl" rc=0
  if [[ ! -f $pf ]]; then
    fail_all PREFLIGHT_SOURCE_MISSING "guest/capacity-preflight.sh not found"
    return 0
  fi
  # Pipe over ssh stdin (never scp: its port flag differs) and run with the
  # rootless user manager runtime dir so podman info works.
  if ! ssh_user phase1-a 'cat >/tmp/capacity-preflight.sh' <"$pf" 2>/dev/null; then
    fail_all PREFLIGHT_INJECT_FAILED "could not copy preflight into guest"
    return 0
  fi
  # shellcheck disable=SC2016  # $(id -u) must expand on the GUEST side.
  ssh_user phase1-a 'export XDG_RUNTIME_DIR=/run/user/$(id -u); bash /tmp/capacity-preflight.sh --runtime podman --lane-id fedora-44-x86_64 --evidence-root /tmp --run-id capacity-preflight' \
    >"$out" 2>"$SCRATCH/preflight.stderr.log" || rc=$?
  # rc 1 = readiness blockers reported (expected in a deliberately small guest);
  # anything else without parseable output is an infrastructure failure.
  if [[ ! -s $out ]] || ! jq -e -s 'length >= 3 and all(.[]; type == "object")' "$out" >/dev/null 2>&1; then
    fail_all GUEST_PREFLIGHT_NO_OUTPUT "preflight produced no parseable JSONL (rc=$rc)"
    return 0
  fi
  cat "$out" >>"$GUEST_LOG" 2>/dev/null || true

  local ready blockers
  ready=$(jq -r -s '[.[] | select(.event == "end")][0].data.ready // false' "$out" 2>/dev/null) || ready=false
  blockers=$(jq -r -s '[.[] | select(.event == "end")][0].data.block_reasons // [] | [.[].code] | unique | join(",")' "$out" 2>/dev/null) || blockers=""
  blockers=${blockers:0:300}

  # preflight.host-baseline: the full host fact set was collected in-guest.
  if jq -e -s '[.[] | select(.event == "host_snapshot")][0].data
      | (.cgroup.version_2 == true)
      and (.logical_cpus | type == "number")
      and (.memory.available_bytes | type == "number")
      and (.file_descriptors.soft | test("^[0-9]+$"))
      and (.processes.pid_max | test("^[0-9]+$"))
      and (.namespace_limits | type == "object")' "$out" >/dev/null 2>&1; then
    set_res preflight.host-baseline PASS GUEST_HOST_BASELINE_RECORDED \
      "readiness verdict ready=$ready blockers=${blockers:-none}"
  else
    set_res preflight.host-baseline TEST_FAIL GUEST_HOST_BASELINE_INCOMPLETE \
      "host snapshot missing or missing required fact groups"
  fi

  # preflight.runtime-baseline: rootless Podman on cgroup v2 observed PASS.
  if jq -e -s '[.[] | select(.event == "runtime_snapshot" and .runtime == "podman")][0]
      | (.status == "PASS") and (.data.mode == "rootless")
      and (.data.info.host.cgroup_version | tostring | IN("2","v2"))' "$out" >/dev/null 2>&1; then
    local locks
    locks=$(jq -r -s '[.[] | select(.event == "runtime_snapshot" and .runtime == "podman")][0].data.lock_readiness.free_locks // "unknown"' "$out" 2>/dev/null) || locks=unknown
    set_res preflight.runtime-baseline PASS GUEST_RUNTIME_BASELINE_RECORDED \
      "rootless podman on cgroup v2; free_locks=$locks"
  else
    set_res preflight.runtime-baseline TEST_FAIL GUEST_RUNTIME_BASELINE_MISMATCH \
      "rootless podman snapshot missing or not PASS"
  fi

  # preflight.evidence-retention: the ladder retention projection was computed.
  if jq -e -s '[.[] | select(.event == "capacity_projection")][0].data.evidence_projection
      | (.per_container_event_bytes > 0) and (.bytes_at_target_run > 0)
      and (.total_ladder_bytes > 0)' "$out" >/dev/null 2>&1; then
    local total fits
    total=$(jq -r -s '[.[] | select(.event == "capacity_projection")][0].data.evidence_projection.total_ladder_bytes' "$out" 2>/dev/null) || total=unknown
    fits=$(jq -r -s '[.[] | select(.event == "capacity_projection")][0].data.evidence_projection.fits' "$out" 2>/dev/null) || fits=unknown
    set_res preflight.evidence-retention PASS LADDER_RETENTION_PROJECTED \
      "total_ladder_bytes=$total guest_fs_fits=$fits; host-side retention sized by the host preflight"
  else
    set_res preflight.evidence-retention TEST_FAIL LADDER_RETENTION_NOT_PROJECTED \
      "capacity_projection event missing or incomplete"
  fi

  # preflight.stop-conditions: measured thresholds + all stop categories derived.
  if jq -e -s '[.[] | select(.event == "capacity_projection")][0].data.derived_stop_thresholds
      | has("memory_floor_bytes") and has("disk_floor_bytes")
      and has("fd_soft_headroom") and has("pid_headroom")
      and has("per_step_latency_ceiling_ms") and has("evidence_reserve_bytes")' "$out" >/dev/null 2>&1 \
    && jq -e -s '[.[] | select(.event == "end")][0].data.scale_ladder_stop_conditions
      | type == "array" and length == 7' "$out" >/dev/null 2>&1; then
    set_res preflight.stop-conditions PASS STOP_CONDITIONS_DERIVED \
      "7 stop-condition categories with measured floors/ceilings"
  else
    set_res preflight.stop-conditions TEST_FAIL STOP_CONDITIONS_MISSING \
      "derived stop thresholds or stop-condition categories missing"
  fi
}

run_checks() {
  local wtag=$1 out rc

  # cgroup v2
  out=$(ssh_user phase1-a 'stat -fc %T /sys/fs/cgroup' 2>/dev/null || true)
  if [[ $out == cgroup2fs ]]; then
    set_res lane.cgroup-v2 PASS CGROUP_V2_PRESENT "$out"; guest_fact cgroup PASS "$out"
  else
    set_res lane.cgroup-v2 TEST_FAIL CGROUP_V2_ABSENT "${out:-none}"; guest_fact cgroup FAIL "${out:-none}"
  fi

  # SELinux enforcing (confirmed from inside the guest)
  out=$(ssh_user phase1-a 'getenforce' 2>/dev/null || true)
  if [[ $out == Enforcing ]]; then
    set_res lane.lsm-enforcing PASS SELINUX_ENFORCING "$out"; guest_fact selinux PASS "$out"
  else
    set_res lane.lsm-enforcing TEST_FAIL SELINUX_NOT_ENFORCING "${out:-unknown}"; guest_fact selinux FAIL "${out:-unknown}"
  fi

  # rootless Podman with SELinux integration
  out=$(ssh_script phase1-a <<'EOS'
export XDG_RUNTIME_DIR=/run/user/$(id -u)
r=$(podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null)
s=$(podman info --format '{{.Host.Security.SELinuxEnabled}}' 2>/dev/null)
v=$(podman --version 2>/dev/null | awk '{print $3}')
printf '%s|%s|%s' "$r" "$s" "$v"
EOS
) || out=""
  local rl sel ver
  IFS='|' read -r rl sel ver <<<"$out"
  if [[ $rl == true && $sel == true && -n $ver ]]; then
    set_res lane.runtime-mode PASS PODMAN_ROOTLESS_SELINUX "$out"; guest_fact runtime PASS "$out"
  else
    set_res lane.runtime-mode TEST_FAIL PODMAN_MODE_MISMATCH "${out:-none}"; guest_fact runtime FAIL "${out:-none}"
  fi

  # rootless owner A runs a Podman container under enforcement
  owner_check phase1-a lane.rootless-owner-a "$wtag"
  # rootless owner B runs a Podman container under enforcement
  owner_check phase1-b lane.rootless-owner-b "$wtag"

  # rootless Compose provider functions (as owner A)
  out=$(ssh_script phase1-a "WTAG=$wtag" <<'EOS'
export XDG_RUNTIME_DIR=/run/user/$(id -u)
cd /tmp
cf=/run/basil-payload/payload/compose.yaml
podman load -i /run/basil-payload/payload/workload-alpine.tar >/dev/null 2>&1 || true
if ! podman-compose -f "$cf" up -d >/tmp/compose.log 2>&1; then
  echo "up-failed:$(tail -c 200 /tmp/compose.log | tr '\n' ' ')"; exit 1
fi
sleep 1
names=$(podman ps --format '{{.Names}}' 2>/dev/null | tr '\n' ',')
podman-compose -f "$cf" down >>/tmp/compose.log 2>&1 || true
pv=$(podman-compose --version 2>&1 | grep -m1 -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
[ -n "$names" ] || { echo "no-container"; exit 1; }
echo "podman-compose ${pv} ran ${names}"
EOS
) ; rc=$?
  if (( rc == 0 )); then
    set_res lane.compose-provider PASS COMPOSE_PROVIDER_OK "$out"; guest_fact compose PASS "$out"
  else
    set_res lane.compose-provider TEST_FAIL COMPOSE_PROVIDER_FAILED "${out:-error}"; guest_fact compose FAIL "${out:-error}"
  fi

  # network isolation: structurally proven above; additionally confirm the guest
  # cannot reach an external host under restrict=on.
  out=$(ssh_user phase1-a "timeout 5 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' >/dev/null 2>&1 && echo REACHED || echo BLOCKED" 2>/dev/null || echo BLOCKED)
  if [[ $out == BLOCKED ]]; then
    guest_fact netprobe PASS blocked
  else
    set_res lane.network-isolation TEST_FAIL NETWORK_NOT_ISOLATED "guest reached external host"
    guest_fact netprobe FAIL reached
  fi
}

owner_check() {
  local user=$1 test_id=$2 wtag=$3 out rc
  out=$(ssh_script "$user" "WTAG=$wtag" <<'EOS'
export XDG_RUNTIME_DIR=/run/user/$(id -u)
podman load -i /run/basil-payload/payload/workload-alpine.tar >/dev/null 2>&1 || { echo load-failed; exit 1; }
cid=$(podman run -d --name "basil-$(id -un)-probe" "$WTAG" sleep 5) || { echo run-failed; exit 1; }
lbl=$(podman inspect --format '{{.ProcessLabel}}' "$cid" 2>/dev/null)
rl=$(podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null)
podman rm -f "$cid" >/dev/null 2>&1 || true
[ "$rl" = true ] || { echo not-rootless; exit 1; }
case "$lbl" in *container_t*) : ;; *) echo "no-selinux-label:[$lbl]"; exit 1;; esac
echo "rootless container ran; label=${lbl}"
EOS
) ; rc=$?
  if (( rc == 0 )); then
    set_res "$test_id" PASS ROOTLESS_CONTAINER_OK "$out"; guest_fact "$test_id" PASS "$out"
  else
    set_res "$test_id" TEST_FAIL ROOTLESS_CONTAINER_FAILED "${out:-error}"; guest_fact "$test_id" FAIL "${out:-error}"
  fi
}

main "$@"
