#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
# SPDX-License-Identifier: Apache-2.0

# Ubuntu 24.04 x86_64 lane driver for the Compose Phase 1 evidence runner.
#
# It boots the verified Ubuntu 24.04 cloud image as an unprivileged QEMU guest
# (via the shared boundary library), provisions rootful Docker Engine plus the
# pinned Compose plugin OFFLINE from staged, digest-pinned Debian packages, and
# proves AppArmor confinement WITHOUT selecting an unconfined profile: cgroup v2,
# AppArmor enforcing with the `docker-default` profile actually applied to a
# running container, rootful Docker with no user-namespace remap, and a Compose
# invocation that runs a container under the same confinement.
#
# Contract: this driver speaks to the runner ONLY by writing the bounded result
# file at $BASIL_DRIVER_RESULT. It never writes JSONL events, manifests, or
# sequence numbers, and never sources guest output into runner events. It runs
# inside the runner's read-only Bubblewrap view (only its scratch is writable,
# a fresh network namespace, cleared environment). Any infrastructure failure is
# reported as `INFRA_ERROR`; nothing degrades into a false pass.
#
# Guest inputs are staged out of band (fetched and pinned by the provisioning
# issue basil-y0f) under the artifact cache at
#   <cache>/ubuntu-24.04-docker-lane-staging/
# holding debs/ (the pinned Docker packages), workload/alpine-amd64.tar (the
# pinned Alpine workload as a docker-archive), compose/compose.yaml, and a
# toolbox/ containing an ISO builder (genisoimage) for the NoCloud seed. The
# bootable base image and the workload image are additionally gated by the
# runner through the lane's `artifacts` list before this driver ever runs.

set -euo pipefail
IFS=$'\n\t'
umask 077

readonly SSH_USER=basil-ci
readonly SSH_HOST=127.0.0.1
readonly SSH_PORT=2222
# Suite selection (exported by the runner as BASIL_DRIVER_SUITE). The
# capacity-preflight suite (basil-ge9) reports the four preflight.* terminals
# by running guest/capacity-preflight.sh inside the booted guest; every other
# suite keeps the original ubuntu-2404-lane-smoke test set unchanged.
readonly SUITE="${BASIL_DRIVER_SUITE:-ubuntu-2404-lane-smoke}"
if [[ $SUITE == capacity-preflight ]]; then
  readonly REQUIRED_TESTS=(
    preflight.host-baseline
    preflight.runtime-baseline
    preflight.evidence-retention
    preflight.stop-conditions
  )
elif [[ $SUITE == runtime-evidence ]]; then
  # Runtime-evidence prototype (basil-9tj.2): five fail-closed terminals mapped
  # from guest/runtime-evidence.sh run in-guest against rootful Docker (root, one
  # host-wide owner; same-UID isolation is proven intra-owner between two
  # root-owned containers distinguished by cgroup instance scope).
  readonly REQUIRED_TESTS=(
    runtime.peer-correlation
    runtime.pid-start-time
    runtime.same-uid-isolation
    runtime.realm-overlap
    runtime.stale-and-conflicting
  )
else
  # The suite `ubuntu-2404-lane-smoke` must require exactly these test ids.
  readonly REQUIRED_TESTS=(
    lane.cgroup-v2
    lane.lsm-enforcing
    lane.runtime-mode
    lane.container-confinement
    lane.compose-plugin
  )
fi

log() { printf '%s\n' "$*"; }
err() { printf '%s\n' "$*" >&2; }

# Collected per-test verdicts, keyed by test id -> "STATUS REASON [message]".
declare -A VERDICT=()

set_verdict() {
  local test_id=$1 status=$2 reason=$3 message=${4:-}
  VERDICT["$test_id"]="$status"$'\t'"$reason"$'\t'"$message"
}

# Write the bounded result contract from the collected verdicts. Every required
# test that has no verdict is filled as INFRA_ERROR so the runner never sees
# incomplete coverage as anything other than an infrastructure failure.
write_result() {
  local schema=${BASIL_DRIVER_RESULT_SCHEMA:-basil.compose.phase1.driver-result}
  local version=${BASIL_DRIVER_RESULT_SCHEMA_VERSION:-1}
  local out=${BASIL_DRIVER_RESULT:?BASIL_DRIVER_RESULT must be set by the runner}
  local -a objects=()
  local test_id status reason message entry
  for test_id in "${REQUIRED_TESTS[@]}"; do
    entry=${VERDICT["$test_id"]:-$'INFRA_ERROR\tDRIVER_TEST_NOT_REACHED\t'}
    IFS=$'\t' read -r status reason message <<<"$entry"
    objects+=("$(jq -n -c \
      --arg test_id "$test_id" --arg status "$status" \
      --arg reason "$reason" --arg message "$message" \
      '{test_id:$test_id,status:$status,reason_code:$reason}
       + (if $message == "" then {} else {message:$message} end)')")
  done
  local results
  results=$(printf '%s\n' "${objects[@]}" | jq -s -c .)
  jq -n -c --arg schema "$schema" --argjson version "$version" \
    --argjson results "$results" \
    '{schema:$schema,schema_version:$version,driver:"ubuntu-2404",results:$results}' >"$out"
}

# Mark every unresolved required test as an infrastructure error, write the
# result, and exit 0 so the runner ingests the typed INFRA_ERROR verdicts (a
# nonzero exit would instead collapse everything to a single opaque failure).
fail_infra() {
  local reason=$1 message=${2:-}
  local test_id
  for test_id in "${REQUIRED_TESTS[@]}"; do
    [[ -n ${VERDICT["$test_id"]:-} ]] || set_verdict "$test_id" INFRA_ERROR "$reason" "$message"
  done
  err "INFRA_ERROR: $reason ${message}"
  write_result
  exit 0
}

QEMU_PID=""
cleanup() {
  # Best-effort guest shutdown, then reap the recorded QEMU child by PID.
  if [[ -n $QEMU_PID && -e /proc/$QEMU_PID/stat ]]; then
    kill -TERM "$QEMU_PID" 2>/dev/null || true
    local _i
    for _i in $(seq 1 30); do
      [[ -e /proc/$QEMU_PID/stat ]] || break
      sleep 0.2
    done
    [[ -e /proc/$QEMU_PID/stat ]] && kill -KILL "$QEMU_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# The guest-side provisioning-and-check program. Runs as root inside the guest;
# installs the staged Docker packages offline, exercises rootful Docker and the
# Compose plugin under AppArmor, and prints one `RESULT <test> <STATUS> <REASON>`
# line per lane test plus non-secret `FACT` lines. It emits no secrets.
guest_program() {
  cat <<'GUEST_EOF'
#!/usr/bin/env bash
set -u
IN=/home/basil-ci/in
emit() { printf 'RESULT %s %s %s\n' "$1" "$2" "$3"; }
fact() { printf 'FACT %s\n' "$*"; }

cg=$(stat -fc %T /sys/fs/cgroup 2>/dev/null || echo unknown)
fact "cgroup_fs=$cg"
if [ "$cg" = cgroup2fs ]; then emit lane.cgroup-v2 PASS CGROUP_V2_PRESENT
else emit lane.cgroup-v2 TEST_FAIL CGROUP_V2_ABSENT; fi

if ! command -v docker >/dev/null 2>&1; then
  dpkg -i "$IN"/debs/*.deb >/tmp/basil-dpkg.log 2>&1 || fact "dpkg_install_failed"
fi
systemctl start docker >/dev/null 2>&1 || true
for _ in $(seq 1 30); do docker info >/dev/null 2>&1 && break; sleep 1; done

sv=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "")
cli=$(docker version --format '{{.Client.Version}}' 2>/dev/null || echo "")
cgv=$(docker info --format '{{.CgroupVersion}}' 2>/dev/null || echo "")
secopt=$(docker info --format '{{json .SecurityOptions}}' 2>/dev/null || echo '[]')
fact "docker_server=$sv docker_client=$cli docker_cgroup=$cgv"
fact "docker_security_options=$secopt"
has_apparmor=$(printf '%s' "$secopt" | grep -c 'name=apparmor' || true)
has_userns=$(printf '%s' "$secopt" | grep -c 'name=userns' || true)
is_rootless=$(printf '%s' "$secopt" | grep -c 'name=rootless' || true)
if [ -n "$sv" ] && [ "$has_apparmor" -ge 1 ] && [ "$has_userns" -eq 0 ] && [ "$is_rootless" -eq 0 ]; then
  emit lane.runtime-mode PASS DOCKER_ROOTFUL_NO_USERNS
else
  emit lane.runtime-mode TEST_FAIL DOCKER_MODE_MISMATCH
fi

docker load -i "$IN"/alpine-amd64.tar >/dev/null 2>&1 || fact "image_load_failed"
docker rm -f basilsmoke >/dev/null 2>&1 || true
docker run -d --name basilsmoke basil-smoke/alpine:smoke sleep 180 >/dev/null 2>&1 || fact "container_run_failed"
prof=$(docker inspect --format '{{.AppArmorProfile}}' basilsmoke 2>/dev/null || echo "")
attr=$(docker exec basilsmoke cat /proc/1/attr/current 2>/dev/null | tr -d '\000' || echo "")
fact "container_apparmor_profile=$prof"
fact "container_proc1_attr=$attr"
case "$attr" in
  *unconfined*) emit lane.container-confinement TEST_FAIL CONTAINER_UNCONFINED ;;
  docker-default*)
    if [ "$prof" = docker-default ] && printf '%s' "$attr" | grep -q 'enforce'; then
      emit lane.container-confinement PASS CONTAINER_DOCKER_DEFAULT_ENFORCE
    else
      emit lane.container-confinement TEST_FAIL CONTAINER_PROFILE_MISMATCH
    fi ;;
  *) emit lane.container-confinement TEST_FAIL CONTAINER_NOT_CONFINED ;;
esac

aae=$(tr -d '\n' </sys/module/apparmor/parameters/enabled 2>/dev/null || echo "")
enf=$(aa-status 2>/dev/null | awk '/in enforce mode/{print $1; exit}')
[ -n "$enf" ] || enf=0
ddef=$(aa-status 2>/dev/null | grep -c 'docker-default' || true)
fact "apparmor_enabled=$aae enforce_profiles=$enf docker_default_matches=$ddef"
if [ "$aae" = Y ] && [ "$enf" -ge 1 ] && [ "$ddef" -ge 1 ]; then
  emit lane.lsm-enforcing PASS APPARMOR_ENFORCING_DOCKER_DEFAULT
else
  emit lane.lsm-enforcing TEST_FAIL APPARMOR_NOT_ENFORCING
fi

cv=$(docker compose version --short 2>/dev/null || echo "")
fact "compose_version=$cv"
cout=$(cd "$IN"/compose && docker compose up --abort-on-container-exit --exit-code-from smoke 2>&1)
crc=$?
docker compose -f "$IN"/compose/compose.yaml down >/dev/null 2>&1 || true
if [ -n "$cv" ] && [ "$crc" -eq 0 ] \
  && printf '%s' "$cout" | grep -q 'COMPOSE_SMOKE_OK' \
  && printf '%s' "$cout" | grep -q 'docker-default (enforce)'; then
  emit lane.compose-plugin PASS COMPOSE_CONFINED_INVOCATION
else
  emit lane.compose-plugin TEST_FAIL COMPOSE_INVOCATION_FAILED
fi

docker rm -f basilsmoke >/dev/null 2>&1 || true
GUEST_EOF
}

# Guest program for the capacity-preflight suite: provision rootful Docker
# offline from the staged pinned debs exactly as the smoke program does, then
# exec the injected readiness preflight. Its stdout is pure bounded JSONL; all
# provisioning output goes to guest-local files.
capacity_guest_program() {
  cat <<'GUEST_EOF'
#!/usr/bin/env bash
set -u
IN=/home/basil-ci/in
if ! command -v docker >/dev/null 2>&1; then
  dpkg -i "$IN"/debs/*.deb >/tmp/basil-dpkg.log 2>&1 || true
fi
systemctl start docker >/dev/null 2>&1 || true
for _ in $(seq 1 30); do docker info >/dev/null 2>&1 && break; sleep 1; done
exec bash "$IN"/capacity-preflight.sh --runtime docker --lane-id ubuntu-24.04-x86_64 --evidence-root /tmp --run-id capacity-preflight
GUEST_EOF
}

# Capacity-preflight suite (basil-ge9): inject guest/capacity-preflight.sh,
# run it as root against rootful Docker, retain its full bounded JSONL as raw
# evidence, and map it onto the four preflight.* terminals. This is
# environment-readiness EVIDENCE COLLECTION, not the basil-9tj.4 measurement:
# each terminal asserts a readiness fact set was collected completely (and, for
# the runtime, that the lane's required mode was observed); the guest's
# ready/blocker verdict travels in the bounded messages and raw JSONL, never
# converted into or hidden behind a pass. Uses main's ssh_base (dynamic scope).
run_capacity_preflight() {
  local fixture_root=$1 scratch=$2
  local pf="$fixture_root/guest/capacity-preflight.sh"
  local out="$scratch/preflight.jsonl" rc=0
  [[ -f $pf ]] || fail_infra PREFLIGHT_SOURCE_MISSING "$pf"
  # Pipe over ssh stdin (never scp for scripts: its port flag differs).
  "${ssh_base[@]}" "$SSH_USER@$SSH_HOST" 'cat >/home/basil-ci/in/capacity-preflight.sh' <"$pf" 2>/dev/null \
    || fail_infra PREFLIGHT_INJECT_FAILED ""
  capacity_guest_program | "${ssh_base[@]}" "$SSH_USER@$SSH_HOST" 'cat >/home/basil-ci/in/capacity.sh' 2>/dev/null \
    || fail_infra PREFLIGHT_PROGRAM_COPY_FAILED ""
  "${ssh_base[@]}" "$SSH_USER@$SSH_HOST" 'sudo -n bash /home/basil-ci/in/capacity.sh' \
    >"$out" 2>"$scratch/preflight.stderr.log" || rc=$?
  # rc 1 = readiness blockers reported (expected in a deliberately small guest);
  # anything without parseable JSONL is an infrastructure failure.
  if [[ ! -s $out ]] || ! jq -e -s 'length >= 3 and all(.[]; type == "object")' "$out" >/dev/null 2>&1; then
    fail_infra GUEST_PREFLIGHT_NO_OUTPUT "rc=$rc"
  fi
  # Retain the full bounded preflight JSONL as raw evidence (collected by the
  # runner as raw/guest-events.jsonl).
  cp "$out" "$scratch/guest-events.jsonl" 2>/dev/null || true

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
    set_verdict preflight.host-baseline PASS GUEST_HOST_BASELINE_RECORDED \
      "readiness verdict ready=$ready blockers=${blockers:-none}"
  else
    set_verdict preflight.host-baseline TEST_FAIL GUEST_HOST_BASELINE_INCOMPLETE \
      "host snapshot missing or missing required fact groups"
  fi

  # preflight.runtime-baseline: rootful Docker on cgroup v2 observed PASS.
  if jq -e -s '[.[] | select(.event == "runtime_snapshot" and .runtime == "docker")][0]
      | (.status == "PASS") and (.data.mode == "rootful")
      and (.data.info.cgroup_version | tostring | IN("2","v2"))' "$out" >/dev/null 2>&1; then
    local driver_name
    driver_name=$(jq -r -s '[.[] | select(.event == "runtime_snapshot" and .runtime == "docker")][0].data.info.storage_driver // "unknown"' "$out" 2>/dev/null) || driver_name=unknown
    set_verdict preflight.runtime-baseline PASS GUEST_RUNTIME_BASELINE_RECORDED \
      "rootful docker on cgroup v2; storage_driver=$driver_name"
  else
    set_verdict preflight.runtime-baseline TEST_FAIL GUEST_RUNTIME_BASELINE_MISMATCH \
      "rootful docker snapshot missing or not PASS"
  fi

  # preflight.evidence-retention: the ladder retention projection was computed.
  if jq -e -s '[.[] | select(.event == "capacity_projection")][0].data.evidence_projection
      | (.per_container_event_bytes > 0) and (.bytes_at_target_run > 0)
      and (.total_ladder_bytes > 0)' "$out" >/dev/null 2>&1; then
    local total fits
    total=$(jq -r -s '[.[] | select(.event == "capacity_projection")][0].data.evidence_projection.total_ladder_bytes' "$out" 2>/dev/null) || total=unknown
    fits=$(jq -r -s '[.[] | select(.event == "capacity_projection")][0].data.evidence_projection.fits' "$out" 2>/dev/null) || fits=unknown
    set_verdict preflight.evidence-retention PASS LADDER_RETENTION_PROJECTED \
      "total_ladder_bytes=$total guest_fs_fits=$fits; host-side retention sized by the host preflight"
  else
    set_verdict preflight.evidence-retention TEST_FAIL LADDER_RETENTION_NOT_PROJECTED \
      "capacity_projection event missing or incomplete"
  fi

  # preflight.stop-conditions: measured thresholds + all stop categories derived.
  if jq -e -s '[.[] | select(.event == "capacity_projection")][0].data.derived_stop_thresholds
      | has("memory_floor_bytes") and has("disk_floor_bytes")
      and has("fd_soft_headroom") and has("pid_headroom")
      and has("per_step_latency_ceiling_ms") and has("evidence_reserve_bytes")' "$out" >/dev/null 2>&1 \
    && jq -e -s '[.[] | select(.event == "end")][0].data.scale_ladder_stop_conditions
      | type == "array" and length == 7' "$out" >/dev/null 2>&1; then
    set_verdict preflight.stop-conditions PASS STOP_CONDITIONS_DERIVED \
      "7 stop-condition categories with measured floors/ceilings"
  else
    set_verdict preflight.stop-conditions TEST_FAIL STOP_CONDITIONS_MISSING \
      "derived stop thresholds or stop-condition categories missing"
  fi
}

# Guest provisioning wrapper for the runtime-evidence suite: install rootful
# Docker offline from the staged pinned debs, start it, then exec the injected
# runtime-evidence prototype against Docker. Its stdout is pure bounded JSONL.
runtime_evidence_guest_program() {
  cat <<'GUEST_EOF'
#!/usr/bin/env bash
set -u
IN=/home/basil-ci/in
if ! command -v docker >/dev/null 2>&1; then
  dpkg -i "$IN"/debs/*.deb >/tmp/basil-dpkg.log 2>&1 || true
fi
systemctl start docker >/dev/null 2>&1 || true
for _ in $(seq 1 30); do docker info >/dev/null 2>&1 && break; sleep 1; done
exec bash "$IN"/runtime-evidence.sh --runtime docker --lane-id ubuntu-24.04-x86_64 \
  --run-id runtime-evidence --image basil-smoke/alpine:smoke \
  --image-tar "$IN"/alpine-amd64.tar
GUEST_EOF
}

# Runtime-evidence suite (basil-9tj.2): stage the prototype script and the pinned
# Alpine workload into the guest, run it as root against rootful Docker, retain
# its bounded JSONL as raw evidence, and map its end event onto the five
# runtime.* terminals. Uses main's ssh_base/scp_base (dynamic scope).
run_runtime_evidence() {
  local fixture_root=$1 scratch=$2 workload=$3
  local re="$fixture_root/guest/runtime-evidence.sh"
  local out="$scratch/runtime-evidence.jsonl" rc=0
  [[ -f $re ]] || fail_infra RUNTIME_EVIDENCE_SOURCE_MISSING "$re"
  "${ssh_base[@]}" "$SSH_USER@$SSH_HOST" 'cat >/home/basil-ci/in/runtime-evidence.sh' <"$re" 2>/dev/null \
    || fail_infra RUNTIME_EVIDENCE_INJECT_FAILED ""
  "${scp_base[@]}" "$workload" "$SSH_USER@$SSH_HOST:/home/basil-ci/in/alpine-amd64.tar" >/dev/null 2>&1 \
    || fail_infra RUNTIME_EVIDENCE_WORKLOAD_COPY_FAILED ""
  runtime_evidence_guest_program | "${ssh_base[@]}" "$SSH_USER@$SSH_HOST" 'cat >/home/basil-ci/in/re.sh' 2>/dev/null \
    || fail_infra RUNTIME_EVIDENCE_PROGRAM_COPY_FAILED ""
  "${ssh_base[@]}" "$SSH_USER@$SSH_HOST" 'sudo -n bash /home/basil-ci/in/re.sh' \
    >"$out" 2>"$scratch/runtime-evidence.stderr.log" || rc=$?
  if [[ ! -s $out ]] || ! jq -e -s 'length >= 1 and all(.[]; type=="object")' "$out" >/dev/null 2>&1; then
    fail_infra RUNTIME_EVIDENCE_NO_OUTPUT "rc=$rc"
  fi
  cp "$out" "$scratch/guest-events.jsonl" 2>/dev/null || true
  local end t v reason
  end=$(jq -s -c '[.[] | select(.event=="end")][0] // empty' "$out" 2>/dev/null) || end=""
  if [[ -z $end ]]; then
    fail_infra RUNTIME_EVIDENCE_NO_END "rc=$rc"
  fi
  for t in "${REQUIRED_TESTS[@]}"; do
    v=$(jq -r --arg k "$t" '.data.verdicts[$k].verdict // "MISSING"' <<<"$end" 2>/dev/null) || v=MISSING
    reason=$(jq -r --arg k "$t" '.data.verdicts[$k].reason // ""' <<<"$end" 2>/dev/null) || reason=""
    reason=${reason:0:400}
    case "$v" in
      PASS) set_verdict "$t" PASS RUNTIME_EVIDENCE_FAIL_CLOSED_OK "$reason" ;;
      MISSING) set_verdict "$t" INFRA_ERROR RUNTIME_EVIDENCE_VERDICT_MISSING "terminal absent from end event" ;;
      *) set_verdict "$t" TEST_FAIL RUNTIME_EVIDENCE_NOT_FAIL_CLOSED "$reason" ;;
    esac
  done
}

main() {
  local scratch=${BASIL_DRIVER_SCRATCH:?BASIL_DRIVER_SCRATCH must be set by the runner}
  : "${BASIL_DRIVER_RESULT:?BASIL_DRIVER_RESULT must be set by the runner}"
  local tool
  for tool in jq qemu-system-x86_64 qemu-img ssh scp sed awk getent; do
    command -v "$tool" >/dev/null 2>&1 || fail_infra HOST_TOOL_MISSING "$tool"
  done

  # Self-locate the run and fixture roots from fixed contract inputs only.
  local run driver_path driver_dir fixture_root
  run=$(realpath -e -- "$scratch/../../.." 2>/dev/null) \
    || fail_infra RUN_DIR_UNRESOLVED "$scratch"
  [[ -f $run/meta/run.json ]] || fail_infra RUN_METADATA_MISSING "$run"
  driver_path=$(realpath -e -- "${BASH_SOURCE[0]}") || fail_infra DRIVER_PATH_UNRESOLVED ""
  driver_dir=$(dirname -- "$driver_path")
  fixture_root=$(dirname -- "$driver_dir")

  # Lane configuration travels in the run metadata (`.lane` is the full lock row).
  local memory_mib vcpus machine cloud_init_rel
  memory_mib=$(jq -er '.lane.memory_mib' "$run/meta/run.json") || fail_infra LANE_MEMORY_UNSET ""
  vcpus=$(jq -er '.lane.vcpus' "$run/meta/run.json") || fail_infra LANE_VCPUS_UNSET ""
  machine=$(jq -er '.lane.machine' "$run/meta/run.json") || fail_infra LANE_MACHINE_UNSET ""
  cloud_init_rel=$(jq -er '.lane.cloud_init' "$run/meta/run.json") || fail_infra LANE_CLOUDINIT_UNSET ""
  local cloud_init_template="$fixture_root/$cloud_init_rel"
  [[ -f $cloud_init_template ]] || fail_infra CLOUDINIT_TEMPLATE_MISSING "$cloud_init_rel"

  # The runner's sandbox clears the environment, so recover the invoking user's
  # cache root from the password database (same default artifacts.sh computes).
  local home cache staging
  home=$(getent passwd "$(id -u)" | cut -d: -f6)
  [[ -n $home && -d $home ]] || fail_infra HOME_UNRESOLVED ""
  cache="$home/.cache/basil/compose-phase1"
  staging="$cache/ubuntu-24.04-docker-lane-staging"
  [[ -d $staging ]] || fail_infra STAGING_MISSING "$staging"

  # Make the staged ISO-builder toolbox reachable, then require an ISO tool.
  [[ -d $staging/toolbox ]] && PATH="$staging/toolbox:$PATH"
  local geniso=""
  local candidate
  for candidate in genisoimage mkisofs xorrisofs; do
    if command -v "$candidate" >/dev/null 2>&1; then geniso=$candidate; break; fi
  done
  [[ -n $geniso ]] || fail_infra ISO_TOOL_MISSING "genisoimage|mkisofs|xorrisofs"

  # Locate the verified bootable base image from the lane's cloud artifact.
  local cloud_id base_image
  cloud_id=$(jq -r '.lane.artifacts[] | select(test("cloud"))' "$run/meta/run.json" | head -1)
  [[ -n $cloud_id ]] || fail_infra CLOUD_ARTIFACT_UNLISTED ""
  base_image=$(find "$cache/$cloud_id" -maxdepth 1 -type f \( -name '*.img' -o -name '*.qcow2' \) 2>/dev/null | head -1)
  [[ -n $base_image && -f $base_image ]] || fail_infra BASE_IMAGE_MISSING "$cache/$cloud_id"

  # Required staged guest inputs.
  local ssh_key="$run/transient/ssh/id_ed25519"
  local ssh_pub="$run/meta/ssh-public-key"
  [[ -f $ssh_key ]] || fail_infra SSH_KEY_MISSING "$ssh_key"
  [[ -f $ssh_pub ]] || fail_infra SSH_PUBLIC_KEY_MISSING "$ssh_pub"
  local debs_dir="$staging/debs" workload="$staging/workload/alpine-amd64.tar"
  local compose_file="$staging/compose/compose.yaml"
  [[ -d $debs_dir ]] || fail_infra STAGED_DEBS_MISSING "$debs_dir"
  [[ -f $workload ]] || fail_infra STAGED_WORKLOAD_MISSING "$workload"
  [[ -f $compose_file ]] || fail_infra STAGED_COMPOSE_MISSING "$compose_file"

  # Build the per-run overlay and the NoCloud seed inside the writable scratch.
  local overlay="$scratch/overlay.qcow2"
  local seed="$scratch/seed.iso"
  local serial="$scratch/serial.log"
  local qmp="$scratch/q.sock"
  local known_hosts="$scratch/known_hosts"
  local user_data="$scratch/user-data"
  local meta_data="$scratch/meta-data"
  local qemu_err="$scratch/qemu.stderr.log"

  qemu-img create -f qcow2 -F qcow2 -b "$base_image" "$overlay" 20G >/dev/null 2>&1 \
    || fail_infra OVERLAY_CREATE_FAILED ""
  sed "s|__BASIL_PHASE1_SSH_PUBLIC_KEY__|$(cat "$ssh_pub")|" "$cloud_init_template" >"$user_data" \
    || fail_infra CLOUDINIT_RENDER_FAILED ""
  printf 'instance-id: %s\nlocal-hostname: basil-phase1-ubuntu2404\n' \
    "$(basename "$run")" >"$meta_data"
  "$geniso" -quiet -output "$seed" -volid CIDATA -joliet -rock "$user_data" "$meta_data" \
    >/dev/null 2>&1 || fail_infra SEED_BUILD_FAILED ""

  # Assemble the boundary-conforming unprivileged QEMU argv, fail closed if the
  # library rejects it, then boot. Acceleration rides on the lane's `machine`.
  # shellcheck source=/dev/null
  source "$driver_dir/lib/qemu-unpriv.sh" || fail_infra QEMU_LIB_MISSING ""
  local -a qemu_argv=()
  qemu_unpriv_build_argv qemu_argv \
    "$base_image" "$overlay" "$serial" "$qmp" "$SSH_PORT" "$seed" \
    "$memory_mib" "$vcpus" "$machine" \
    || fail_infra QEMU_ARGV_REJECTED ""
  qemu_unpriv_assert_boundary "${qemu_argv[@]}" || fail_infra QEMU_BOUNDARY_VIOLATION ""

  : >"$serial"
  "${qemu_argv[@]}" >/dev/null 2>"$qemu_err" &
  QEMU_PID=$!

  # Wait for cloud-init to finish (final message) and the console host keys.
  local booted=no
  for _ in $(seq 1 90); do
    if grep -qa 'Basil Compose Phase 1 Ubuntu foundation ready' "$serial" 2>/dev/null; then
      booted=yes
      break
    fi
    [[ -e /proc/$QEMU_PID/stat ]] || break
    sleep 3
  done
  [[ $booted == yes ]] || fail_infra GUEST_BOOT_TIMEOUT ""

  # Serial-established host-key pin: no TOFU, no StrictHostKeyChecking=no.
  local host_key
  host_key=$(sed -n '/BEGIN SSH HOST KEY KEYS/,/END SSH HOST KEY KEYS/p' "$serial" \
    | tr -d '\r' | awk '/^ssh-ed25519 /{print $1" "$2; exit}')
  [[ -n $host_key ]] || fail_infra GUEST_HOST_KEY_MISSING ""
  printf '[%s]:%s %s\n' "$SSH_HOST" "$SSH_PORT" "$host_key" >"$known_hosts"

  # -F /dev/null makes ssh ignore the host's system ssh_config (whose includes
  # are owned by a uid that maps to `nobody` inside the driver's user namespace).
  local -a ssh_base=(ssh -F /dev/null -i "$ssh_key" -p "$SSH_PORT"
    -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$known_hosts"
    -o IdentitiesOnly=yes -o BatchMode=yes -o PasswordAuthentication=no
    -o ConnectTimeout=10)
  local -a scp_base=(scp -F /dev/null -i "$ssh_key" -P "$SSH_PORT"
    -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$known_hosts"
    -o IdentitiesOnly=yes -o BatchMode=yes -o PasswordAuthentication=no)

  local ready=no
  for _ in $(seq 1 30); do
    if "${ssh_base[@]}" "$SSH_USER@$SSH_HOST" true 2>/dev/null; then
      ready=yes
      break
    fi
    sleep 3
  done
  [[ $ready == yes ]] || fail_infra GUEST_SSH_TIMEOUT ""

  # Stage guest inputs and the check program, then run it as root in the guest.
  "${ssh_base[@]}" "$SSH_USER@$SSH_HOST" 'mkdir -p /home/basil-ci/in/debs /home/basil-ci/in/compose' \
    2>/dev/null || fail_infra GUEST_STAGE_MKDIR_FAILED ""
  "${scp_base[@]}" "$debs_dir"/*.deb "$SSH_USER@$SSH_HOST:/home/basil-ci/in/debs/" >/dev/null 2>&1 \
    || fail_infra GUEST_DEBS_COPY_FAILED ""

  # Capacity-preflight suite (basil-ge9): only the pinned debs are needed
  # in-guest; run the readiness preflight instead of the lane-smoke checks.
  if [[ $SUITE == capacity-preflight ]]; then
    run_capacity_preflight "$fixture_root" "$scratch"
    "${ssh_base[@]}" "$SSH_USER@$SSH_HOST" 'sudo -n poweroff' 2>/dev/null || true
    write_result
    return
  fi

  # Runtime-evidence suite (basil-9tj.2): needs the pinned debs (already staged
  # above) plus the Alpine workload; run the prototype instead of lane smoke.
  if [[ $SUITE == runtime-evidence ]]; then
    run_runtime_evidence "$fixture_root" "$scratch" "$workload"
    "${ssh_base[@]}" "$SSH_USER@$SSH_HOST" 'sudo -n poweroff' 2>/dev/null || true
    write_result
    return
  fi

  "${scp_base[@]}" "$workload" "$SSH_USER@$SSH_HOST:/home/basil-ci/in/alpine-amd64.tar" >/dev/null 2>&1 \
    || fail_infra GUEST_WORKLOAD_COPY_FAILED ""
  "${scp_base[@]}" "$compose_file" "$SSH_USER@$SSH_HOST:/home/basil-ci/in/compose/compose.yaml" >/dev/null 2>&1 \
    || fail_infra GUEST_COMPOSE_COPY_FAILED ""
  guest_program | "${ssh_base[@]}" "$SSH_USER@$SSH_HOST" 'cat >/home/basil-ci/in/checks.sh' 2>/dev/null \
    || fail_infra GUEST_CHECK_COPY_FAILED ""

  local guest_out
  guest_out=$("${ssh_base[@]}" "$SSH_USER@$SSH_HOST" 'sudo -n bash /home/basil-ci/in/checks.sh' 2>&1) \
    || true
  # Retain the non-secret guest facts and verdict transcript as raw evidence.
  printf '%s\n' "$guest_out" | grep -E '^(FACT|RESULT) ' || true

  local produced=no tag test_id status reason
  while IFS=' ' read -r tag test_id status reason; do
    [[ $tag == RESULT ]] || continue
    [[ -n $test_id && -n $status && -n $reason ]] || continue
    set_verdict "$test_id" "$status" "$reason"
    produced=yes
  done < <(printf '%s\n' "$guest_out")

  [[ $produced == yes ]] || fail_infra GUEST_CHECKS_PRODUCED_NO_RESULT ""

  # Graceful guest shutdown before the trap reaps QEMU.
  "${ssh_base[@]}" "$SSH_USER@$SSH_HOST" 'sudo -n poweroff' 2>/dev/null || true

  write_result
}

main "$@"
