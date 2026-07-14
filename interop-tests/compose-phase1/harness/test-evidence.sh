#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
IFS=$'\n\t'
umask 077

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly HERE
TEST_REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
readonly TEST_REPO_ROOT
readonly RUNNER="$TEST_REPO_ROOT/scripts/compose-phase1-evidence.sh"
TEST_ROOT="$(mktemp -d /tmp/basil-compose-evidence-test.XXXXXX)"
readonly TEST_ROOT
SLEEP_PIDS=()

cleanup() {
  local pid
  for pid in "${SLEEP_PIDS[@]}"; do
    if [[ -e /proc/$pid/stat ]]; then
      kill -TERM "$pid" 2>/dev/null || true
    fi
  done
  rm -rf --one-file-system -- "$TEST_ROOT"
}
trap cleanup EXIT

# shellcheck disable=SC1090,SC1091
source "$RUNNER"

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

pass() {
  printf 'ok: %s\n' "$*"
}

expect_exit() {
  local expected=$1
  shift
  set +e
  "$@" >/dev/null 2>&1
  local actual=$?
  set -e
  [[ $actual == "$expected" ]] || fail "expected exit $expected, got $actual: $*"
}

prepare_run() {
  bash "$RUNNER" prepare --lane fedora-44-x86_64 --development \
    --evidence-root "$TEST_ROOT/runs"
}

finalize_unprovisioned() {
  local run_id=$1
  set +e
  bash "$RUNNER" run --run "$run_id" --evidence-root "$TEST_ROOT/runs" >/dev/null 2>&1
  local result=$?
  set -e
  case "$result" in
    "$EXIT_INCOMPLETE"|"$EXIT_NOT_MEASURED"|"$EXIT_INFRA_ERROR") ;;
    *) fail "unprovisioned run returned unexpected exit $result" ;;
  esac
}

# Unsafe roots: repository paths and broad roots must be rejected before creation.
expect_exit "$EXIT_INFRA_ERROR" bash "$RUNNER" prepare --lane fedora-44-x86_64 \
  --development --evidence-root "$REPO_ROOT/interop-tests/compose-phase1/evidence"
expect_exit "$EXIT_INFRA_ERROR" bash "$RUNNER" prepare --lane fedora-44-x86_64 \
  --development --evidence-root /tmp
mkdir -p "$TEST_ROOT/real-root"
ln -s "$TEST_ROOT/real-root" "$TEST_ROOT/symlink-root"
expect_exit "$EXIT_INFRA_ERROR" bash "$RUNNER" prepare --lane fedora-44-x86_64 \
  --development --evidence-root "$TEST_ROOT/symlink-root/runs"
pass "unsafe and symbolic-link evidence roots are rejected"

# A correctly finalized non-passing run must still pass integrity/schema checks
# and preserve its exact typed exit status.
valid_id=$(prepare_run)
set +e
bash "$RUNNER" run --run "$valid_id" --evidence-root "$TEST_ROOT/runs" >/dev/null 2>&1
valid_status=$?
set -e
case "$valid_status" in
  "$EXIT_INCOMPLETE"|"$EXIT_NOT_MEASURED"|"$EXIT_INFRA_ERROR") ;;
  *) fail "valid non-passing run returned unexpected exit $valid_status" ;;
esac
set +e
valid_verify_output=$(bash "$RUNNER" verify-run --run "$valid_id" \
  --evidence-root "$TEST_ROOT/runs")
valid_verify_status=$?
set -e
[[ $valid_verify_status == "$valid_status" ]] \
  || fail "verify-run returned $valid_verify_status, expected $valid_status"
valid_manifest_sha256=$(jq -er '.manifest_sha256' <<<"$valid_verify_output") \
  || fail "verify-run did not report manifest_sha256"
[[ $valid_manifest_sha256 == "$(sha256_file "$TEST_ROOT/runs/$valid_id/manifest.json")" ]] \
  || fail "verify-run reported the wrong manifest_sha256"
pass "valid finalized evidence reports its manifest hash and preserves typed status"

# Interrupted/stale RUNNING state becomes retained INCOMPLETE evidence, never PASS.
interrupted_id=$(prepare_run)
interrupted_run="$TEST_ROOT/runs/$interrupted_id"
write_json_atomic "$interrupted_run/meta/process-orchestrator.json" \
  "$(jq -n -c --argjson pid 999999999 --arg marker "$interrupted_run/transient/markers/orchestrator" \
    '{role:"orchestrator",pid:$pid,start_time:"1",executable:"/bin/false",marker:$marker,token:"missing"}')"
expect_exit "$EXIT_INCOMPLETE" bash "$RUNNER" status --run "$interrupted_id" \
  --evidence-root "$TEST_ROOT/runs"
[[ -f $interrupted_run/INCOMPLETE && ! -e $interrupted_run/RUNNING ]] \
  || fail "stale run did not atomically finalize as INCOMPLETE"
expect_exit "$EXIT_INCOMPLETE" bash "$RUNNER" verify-run --run "$interrupted_id" \
  --evidence-root "$TEST_ROOT/runs"
pass "interrupted runs retain verifiable INCOMPLETE state"

# Manifest alteration must be caught by the independent sidecar hash.
altered_id=$(prepare_run)
finalize_unprovisioned "$altered_id"
altered_run="$TEST_ROOT/runs/$altered_id"
jq -c '.reason_code="ALTERED"' "$altered_run/manifest.json" >"$altered_run/manifest.json.tmp"
mv -f -- "$altered_run/manifest.json.tmp" "$altered_run/manifest.json"
expect_exit "$EXIT_INCOMPLETE" bash "$RUNNER" verify-run --run "$altered_id" \
  --evidence-root "$TEST_ROOT/runs"
pass "altered manifests fail verification"

# Rewriting both a manifest and its sidecar cannot shrink the suite's required
# terminal set because verification re-reads the checked-in phase lock.
requirements_id=$(prepare_run)
finalize_unprovisioned "$requirements_id"
requirements_run="$TEST_ROOT/runs/$requirements_id"
jq -c '.required_tests = [.required_tests[0]]' "$requirements_run/manifest.json" \
  >"$requirements_run/manifest.json.tmp"
mv -f -- "$requirements_run/manifest.json.tmp" "$requirements_run/manifest.json"
sha256_file "$requirements_run/manifest.json" >"$requirements_run/manifest.sha256"
expect_exit "$EXIT_INCOMPLETE" bash "$RUNNER" verify-run --run "$requirements_id" \
  --evidence-root "$TEST_ROOT/runs"
pass "manifest required tests cannot diverge from the checked-in lock"

# Sequence regressions must fail even when hashes are recomputed by a party able
# to rewrite the evidence directory.
regress_id=$(prepare_run)
finalize_unprovisioned "$regress_id"
regress_run="$TEST_ROOT/runs/$regress_id"
jq -c 'if .seq == 2 then .seq = 1 else . end' "$regress_run/sanitized/events.jsonl" \
  >"$regress_run/sanitized/events.jsonl.tmp"
mv -f -- "$regress_run/sanitized/events.jsonl.tmp" "$regress_run/sanitized/events.jsonl"
collect_outputs "$regress_run"
build_manifest "$regress_run" "$(jq -r '.status' "$regress_run/manifest.json")" \
  "$(jq -r '.reason_code' "$regress_run/manifest.json")"
expect_exit "$EXIT_INCOMPLETE" bash "$RUNNER" verify-run --run "$regress_id" \
  --evidence-root "$TEST_ROOT/runs"
pass "regressing event sequences fail verification"

# Duplicate required terminals must fail independently of sequence monotonicity.
duplicate_id=$(prepare_run)
finalize_unprovisioned "$duplicate_id"
duplicate_run="$TEST_ROOT/runs/$duplicate_id"
last_seq=$(jq -s 'length' "$duplicate_run/sanitized/events.jsonl")
jq -c -s '
  . as $events
  | ($events[] | select(.event == "test.end")) as $terminal
  | ($terminal + {seq:($events[-1].seq),time:$events[-1].time}) as $duplicate
  | (($events[0:-1] + [$duplicate] + [$events[-1]])
      | to_entries | map(.value.seq = (.key + 1)) | .[])
' "$duplicate_run/sanitized/events.jsonl" >"$duplicate_run/sanitized/events.jsonl.tmp"
[[ -n $last_seq ]]
mv -f -- "$duplicate_run/sanitized/events.jsonl.tmp" "$duplicate_run/sanitized/events.jsonl"
collect_outputs "$duplicate_run"
build_manifest "$duplicate_run" "$(jq -r '.status' "$duplicate_run/manifest.json")" \
  "$(jq -r '.reason_code' "$duplicate_run/manifest.json")"
expect_exit "$EXIT_INCOMPLETE" bash "$RUNNER" verify-run --run "$duplicate_id" \
  --evidence-root "$TEST_ROOT/runs"
pass "duplicate test terminals fail verification"

# Cleanup refuses a process when its random marker is altered, and succeeds only
# after PID, start time, executable, marker path, and marker token all match.
cleanup_id=$(prepare_run)
cleanup_run="$TEST_ROOT/runs/$cleanup_id"
sleep 120 &
sleeper=$!
SLEEP_PIDS+=("$sleeper")
marker="$cleanup_run/transient/markers/qemu"
token=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
printf '%s\n' "$token" >"$marker"
chmod 0600 "$marker"
record_process "$cleanup_run" qemu "$sleeper" "$marker" "$token"
printf '%s\n' altered >"$marker"
set +e
terminate_recorded_process "$cleanup_run/meta/process-qemu.json" "$cleanup_run" >/dev/null 2>&1
cleanup_rc=$?
set -e
[[ $cleanup_rc == "$EXIT_INCOMPLETE" ]] || fail "altered cleanup marker was accepted"
[[ -e /proc/$sleeper/stat ]] || fail "marker mismatch signaled an unrelated process"
printf '%s\n' "$token" >"$marker"
terminate_recorded_process "$cleanup_run/meta/process-qemu.json" "$cleanup_run"
for _ in $(seq 1 20); do
  [[ ! -e /proc/$sleeper/stat ]] && break
  sleep 0.05
done
[[ ! -e /proc/$sleeper/stat ]] || fail "exact cleanup identity did not terminate recorded process"
pass "cleanup requires exact process identity and per-run marker"

# --- Lane-driver contract -------------------------------------------------

prepare_dev_run() {
  bash "$RUNNER" prepare --lane dev-null --suite dev-null --development \
    --evidence-root "$TEST_ROOT/runs"
}

mk_driver_result() {
  local destination=$1 results=$2
  jq -n -c --arg schema "$DRIVER_RESULT_SCHEMA" --argjson results "$results" \
    '{schema:$schema,schema_version:1,driver:"null",results:$results}' >"$destination"
}

# Driver-name resolution is allowlisted and refuses traversal or arbitrary paths.
for bad in "../../../etc/passwd" "../null" "lib/qemu-unpriv" "null.sh" \
  "/etc/passwd" "n/../null" ".." "." "NULL" "nosuch" "notadriver"; do
  set +e
  resolve_driver "$bad" >/dev/null 2>&1
  resolve_rc=$?
  set -e
  [[ $resolve_rc != 0 ]] || fail "resolve_driver accepted unsafe or unlisted name: $bad"
done
resolve_driver null >/dev/null 2>&1 || fail "allowlisted null driver failed to resolve"
pass "driver-name resolution is allowlisted and traversal-safe"

# Bounded result contract: a valid result is accepted; oversize, unlisted, and
# duplicate results are refused.
driver_scratch="$TEST_ROOT/driver-results"
mkdir -p "$driver_scratch"
dev_required=$(required_tests_json dev-null)
mk_driver_result "$driver_scratch/ok.json" \
  '[{"test_id":"dev.result-contract","status":"PASS","reason_code":"OK"},{"test_id":"dev.sandbox-readonly","status":"PASS","reason_code":"OK"}]'
validate_driver_result "$driver_scratch/ok.json" "$dev_required" \
  || fail "a valid driver result contract was rejected"
mk_driver_result "$driver_scratch/unlisted.json" \
  '[{"test_id":"dev.not-a-listed-test","status":"PASS","reason_code":"OK"}]'
if validate_driver_result "$driver_scratch/unlisted.json" "$dev_required"; then
  fail "driver result with an unlisted test id was accepted"
fi
mk_driver_result "$driver_scratch/duplicate.json" \
  '[{"test_id":"dev.result-contract","status":"PASS","reason_code":"A"},{"test_id":"dev.result-contract","status":"PASS","reason_code":"B"}]'
if validate_driver_result "$driver_scratch/duplicate.json" "$dev_required"; then
  fail "driver result with a duplicate test id was accepted"
fi
head -c $((64 * 1024 + 1)) /dev/zero | tr '\0' 'a' >"$driver_scratch/oversize.json"
if validate_driver_result "$driver_scratch/oversize.json" "$dev_required"; then
  fail "oversize driver result file was accepted"
fi
pass "driver result contract rejects oversize, unlisted, and duplicate results"

# A nonzero driver exit degrades to an infrastructure error and never a pass.
badexit_id=$(prepare_dev_run)
badexit_run="$TEST_ROOT/runs/$badexit_id"
bad_driver="$TEST_ROOT/bad-exit-driver.sh"
printf '#!/usr/bin/env bash\nexit 3\n' >"$bad_driver"
chmod +x "$bad_driver"
badexit_outcome=$(execute_driver_lane "$badexit_run" "$bad_driver")
[[ $badexit_outcome == "INFRA_ERROR DRIVER_EXECUTION_FAILED" ]] \
  || fail "nonzero driver exit was not classified as an infrastructure error: $badexit_outcome"
pass "a nonzero driver exit degrades to INFRA_ERROR without a pass"

# Qualification refuses the development-only lane before preparing a run.
set +e
bash "$RUNNER" prepare --lane dev-null --suite dev-null --qualification \
  --evidence-root "$TEST_ROOT/runs" >/dev/null 2>&1
qual_prepare_rc=$?
set -e
[[ $qual_prepare_rc == "$EXIT_UNSUPPORTED" ]] \
  || fail "prepare accepted the development-only lane under qualification (rc=$qual_prepare_rc)"

# Defense in depth: even a run whose metadata is promoted to qualification is
# refused before the driver executes.
qual_id=$(prepare_dev_run)
qual_run="$TEST_ROOT/runs/$qual_id"
jq -c '.qualification="qualification"' "$qual_run/meta/run.json" >"$qual_run/meta/run.json.tmp"
mv -f -- "$qual_run/meta/run.json.tmp" "$qual_run/meta/run.json"
set +e
bash "$RUNNER" run --run "$qual_id" --evidence-root "$TEST_ROOT/runs" >/dev/null 2>&1
qual_run_rc=$?
set -e
[[ $qual_run_rc == "$EXIT_UNSUPPORTED" ]] \
  || fail "run executed the development-only lane under qualification (rc=$qual_run_rc)"
grep -q DEVELOPMENT_LANE_REFUSED "$qual_run/sanitized/events.jsonl" \
  || fail "qualification refusal reason was not recorded"
if grep -q MOCK_CONTRACT_OK "$qual_run/sanitized/events.jsonl"; then
  fail "the driver executed despite qualification refusal"
fi
pass "qualification refuses the development-only lane before driver execution"

# End-to-end development null-driver run yields verifiable PASS evidence, and the
# driver self-reports that it ran under the read-only sandbox.
dev_id=$(prepare_dev_run)
dev_run="$TEST_ROOT/runs/$dev_id"
set +e
bash "$RUNNER" run --run "$dev_id" --evidence-root "$TEST_ROOT/runs" >/dev/null 2>&1
dev_rc=$?
set -e
[[ $dev_rc == "$EXIT_PASS" ]] || fail "null driver development run did not pass (rc=$dev_rc)"
expect_exit "$EXIT_PASS" bash "$RUNNER" verify-run --run "$dev_id" \
  --evidence-root "$TEST_ROOT/runs"
sandbox_status=$(jq -r 'select(.test_id == "dev.sandbox-readonly") | .status' \
  "$dev_run/sanitized/events.jsonl")
[[ $sandbox_status == PASS ]] \
  || fail "null driver did not run under a read-only sandbox (status=$sandbox_status)"
pass "development null-driver run yields verifiable PASS evidence under a read-only sandbox"

# Capacity-preflight v2 profiles and host-evidence anchoring are pure decision
# logic, so exercise them with a bounded fake Docker info response. The test
# creates only tiny scripts/JSON; it does not benchmark disk or write large files.
preflight="$REPO_ROOT/interop-tests/compose-phase1/guest/capacity-preflight.sh"
preflight_root="$TEST_ROOT/capacity-preflight"
fake_bin="$preflight_root/bin"
fake_runtime_root="$preflight_root/runtime-root"
mkdir -p "$fake_bin" "$fake_runtime_root"
cat >"$fake_bin/docker" <<'FAKE_DOCKER'
#!/usr/bin/env bash
set -euo pipefail
[[ ${1:-} == info ]] || exit 2
jq -cn --arg root "${FAKE_DOCKER_ROOT:?}" '{
  ServerVersion:"test", Driver:"overlay2", CgroupDriver:"systemd",
  CgroupVersion:"2", DockerRootDir:$root, NCPU:8, MemTotal:68719476736,
  Containers:0, ContainersRunning:0, ContainersPaused:0, ContainersStopped:0,
  Images:0, SecurityOptions:["name=apparmor"]
}'
FAKE_DOCKER
chmod +x "$fake_bin/docker"

run_preflight_profile() {
  local name=$1
  shift
  local out="$preflight_root/$name.jsonl" rc
  set +e
  env -u BASIL_CAPACITY_PROFILE -u BASIL_HOST_EVIDENCE_SNAPSHOT \
    -u BASIL_HOST_EVIDENCE_SNAPSHOT_ID -u BASIL_HOST_EVIDENCE_SNAPSHOT_SHA256 \
    PATH="$fake_bin:$PATH" FAKE_DOCKER_ROOT="$fake_runtime_root" \
    bash "$preflight" --runtime docker --probe /nonexistent \
      --evidence-root "$preflight_root" --run-id "$name" --lane-id test-x86_64 \
      "$@" >"$out" 2>"$preflight_root/$name.stderr"
  rc=$?
  set -e
  [[ $rc == 0 || $rc == 1 ]] || fail "capacity preflight $name exited $rc"
  jq -e -s 'length >= 4 and all(.[]; type == "object")' "$out" >/dev/null \
    || fail "capacity preflight $name did not emit bounded JSONL"
}

run_preflight_profile host-default
jq -e -s '
  ([.[] | select(.event == "start")][0]
    | .schema_version == "basil.compose.phase1.capacity-preflight/v2"
      and .data.profile == "host" and .data.execution_scope == "host")
  and ([.[] | select(.event == "end")][0].data.thresholds
    | .profile == "host" and .min_cpus == 8
      and .min_memory_bytes == 34359738368
      and .min_disk_bytes_per_checked_local_filesystem == 42949672960)
' "$preflight_root/host-default.jsonl" >/dev/null \
  || fail "default host profile thresholds changed"

run_preflight_profile guest-small --profile guest_small
jq -e -s '
  ([.[] | select(.event == "end")][0].data.thresholds
    | .profile == "guest_small" and .execution_scope == "guest"
      and .min_cpus == 2 and .min_memory_bytes == 1073741824
      and .min_disk_bytes_per_checked_local_filesystem == 10737418240
      and .min_fd_soft == 32768)
  and ([.[] | select(.event == "capacity_projection")][0]
    | .status == "NOT_MEASURED"
      and .reason_code == "HOST_EVIDENCE_ROOT_NOT_SUPPLIED"
      and .data.evidence_projection.source == "not-measured"
      and .data.evidence_projection.evaluated == false
      and .data.evidence_projection.evidence_bytes_available == null
      and .data.evidence_projection.headroom_after_ladder_bytes == null
      and .data.evidence_projection.disk_reserve_source == "profile-readiness-constant"
      and .data.evidence_projection.fits == null)
  and ([.[] | select(.event == "end")][0].data
    | any(.warnings[]; .code == "HOST_EVIDENCE_ROOT_NOT_SUPPLIED")
      and (all(.block_reasons[]; .code != "EVIDENCE_RETENTION_INSUFFICIENT")))
' "$preflight_root/guest-small.jsonl" >/dev/null \
  || fail "guest_small profile did not skip unanchored retention honestly"

host_snapshot="$preflight_root/host-evidence-snapshot.json"
jq -n -c '{source:"host-evidence-root",snapshot_id:"test-host-snapshot",path_label:"test-host-evidence-root",fs_type:"testfs",device_id:"42",bytes_available:107374182400,bytes_total:214748364800,inodes_available:1000000,inodes_total:2000000}' \
  >"$host_snapshot"
host_snapshot_sha256=$(sha256_file "$host_snapshot")
run_preflight_profile guest-medium --profile guest_medium \
  --host-evidence-snapshot "$host_snapshot" \
  --host-evidence-snapshot-id test-host-snapshot \
  --host-evidence-snapshot-sha256 "$host_snapshot_sha256"
jq -e -s '
  ([.[] | select(.event == "end")][0].data.thresholds
    | .profile == "guest_medium" and .execution_scope == "guest"
      and .min_cpus == 4 and .min_memory_bytes == 4294967296
      and .min_disk_bytes_per_checked_local_filesystem == 25769803776
      and .host_evidence_reserve_bytes == 42949672960
      and .min_fd_soft == 32768)
  and ([.[] | select(.event == "host_snapshot")][0].data
    | .retention_anchor_supplied == true
      and .evidence_filesystem.source == "host-evidence-root"
      and .evidence_filesystem.path == "test-host-evidence-root"
      and .evidence_filesystem.snapshot_id == "test-host-snapshot")
  and ([.[] | select(.event == "capacity_projection")][0].data.evidence_projection
    | .source == "host-evidence-root" and .evaluated == true
      and .snapshot_id == "test-host-snapshot"
      and .evidence_bytes_available == 107374182400
      and .disk_reserve_bytes == 42949672960 and .fits == true
      and .retention_basis == "measured filesystem counters + evidence-size estimate + profile readiness constant")
  and ([.[] | select(.event == "capacity_projection")][0].data.derived_stop_thresholds.filesystems
    | (map(.filesystem_identity) | length == (unique | length))
      and any(.[]; (.scopes | index("guest-local")) and (.scopes | index("docker")))
      and any(.[]; .filesystem_identity == "host-device:42:testfs"))
' "$preflight_root/guest-medium.jsonl" >/dev/null \
  || fail "guest_medium profile did not use the supplied host evidence anchor"
pass "capacity preflight profiles preserve host defaults and host-anchor guest retention"

# Snapshot parsing is exactly-one-object, digest-bound, dash-path-safe, and
# accepts the dynamic-inode zero pair without inventing an inode reserve.
dynamic_snapshot="$preflight_root/dynamic-inodes.json"
jq -n -c '{source:"host-evidence-root",snapshot_id:"dynamic-inodes",path_label:"dynamic",fs_type:"btrfs",device_id:"77",bytes_available:107374182400,bytes_total:214748364800,inodes_available:0,inodes_total:0}' \
  >"$dynamic_snapshot"
dynamic_sha256=$(sha256_file "$dynamic_snapshot")
run_preflight_profile dynamic-inodes --profile guest_small \
  --host-evidence-snapshot "$dynamic_snapshot" \
  --host-evidence-snapshot-id dynamic-inodes \
  --host-evidence-snapshot-sha256 "$dynamic_sha256"
jq -e -s '[.[] | select(.event == "capacity_projection")][0].data.derived_stop_thresholds.filesystems
  | any(.[]; .filesystem_identity == "host-device:77:btrfs"
      and .inodes.applicable == false and .inodes.stop_below == null)' \
  "$preflight_root/dynamic-inodes.jsonl" >/dev/null \
  || fail "dynamic inode counters were treated as a fixed inode pool"

multiple_snapshot="$preflight_root/multiple.json"
printf '%s\n%s\n' "$(<"$host_snapshot")" "$(<"$host_snapshot")" >"$multiple_snapshot"
multiple_sha256=$(sha256_file "$multiple_snapshot")
expect_exit 2 env -u BASIL_CAPACITY_PROFILE -u BASIL_HOST_EVIDENCE_SNAPSHOT \
  PATH="$fake_bin:$PATH" FAKE_DOCKER_ROOT="$fake_runtime_root" bash "$preflight" \
  --profile guest_medium --runtime docker --probe /nonexistent \
  --evidence-root "$preflight_root" --run-id hostile --lane-id test-x86_64 \
  --host-evidence-snapshot "$multiple_snapshot" \
  --host-evidence-snapshot-id test-host-snapshot \
  --host-evidence-snapshot-sha256 "$multiple_sha256"
expect_exit 2 bash "$preflight" --profile guest_small --runtime docker \
  --host-evidence-snapshot -snapshot --host-evidence-snapshot-id invalid \
  --host-evidence-snapshot-sha256 "$host_snapshot_sha256"
pass "capacity snapshot parsing rejects multiple objects and dash-prefixed paths"

run_preflight_profile unavailable-local --profile guest_small \
  --evidence-root "$preflight_root/does-not-exist"
jq -e -s '
  ([.[] | select(.event == "host_snapshot")][0]
    | .status == "INCOMPLETE" and .data.local_filesystem.available == false)
  and ([.[] | select(.event == "capacity_projection")][0].data.derived_stop_thresholds.disk_floor_bytes
    | .source == "not-measured" and .stop_below == null and .current_headroom_bytes == null)
' "$preflight_root/unavailable-local.jsonl" >/dev/null \
  || fail "unavailable filesystem claimed measured stop-threshold provenance"
pass "unavailable filesystem thresholds remain explicitly not measured"

# Effective VM resources and the host snapshot are runner-owned retained facts.
preflight_meta_id=$(bash "$RUNNER" prepare --lane fedora-44-x86_64 \
  --suite capacity-preflight --development --evidence-root "$TEST_ROOT/runs")
preflight_meta_run="$TEST_ROOT/runs/$preflight_meta_id"
capacity_meta_id=$(bash "$RUNNER" prepare --lane fedora-44-x86_64 \
  --suite capacity --development --evidence-root "$TEST_ROOT/runs")
capacity_meta_run="$TEST_ROOT/runs/$capacity_meta_id"
jq -e '
  .effective_vm == {disk_gib:32,memory_mib:8192,vcpus:4}
  and .lane.disk_gib == 20 and .lane.memory_mib == 4096 and .lane.vcpus == 4
  and (.host_evidence_snapshot.path == "raw/host-filesystem-snapshot.json")
' "$preflight_meta_run/meta/run.json" >/dev/null \
  || fail "capacity-preflight effective VM shape was not runner-owned"
jq -e --argjson preflight "$(jq -c '.effective_vm' "$preflight_meta_run/meta/run.json")" '
  .effective_vm.memory_mib >= $preflight.memory_mib
  and .effective_vm.vcpus >= $preflight.vcpus
  and .effective_vm.disk_gib >= $preflight.disk_gib
' "$capacity_meta_run/meta/run.json" >/dev/null \
  || fail "capacity VM shape is smaller than capacity-preflight"
snapshot_rel=$(jq -r '.host_evidence_snapshot.path' "$preflight_meta_run/meta/run.json")
snapshot_bytes=$(jq -r '.host_evidence_snapshot.bytes' "$preflight_meta_run/meta/run.json")
snapshot_hash=$(jq -r '.host_evidence_snapshot.sha256' "$preflight_meta_run/meta/run.json")
[[ $(stat -c '%s' -- "$preflight_meta_run/$snapshot_rel") == "$snapshot_bytes" \
  && $(sha256_file "$preflight_meta_run/$snapshot_rel") == "$snapshot_hash" ]] \
  || fail "runner host snapshot metadata does not match retained raw bytes"
pass "runner records effective VM resources and a digest-bound host snapshot"

# Capacity-preflight verification requires its raw guest JSONL inventory entry.
finish_run "$preflight_meta_run" INCOMPLETE TEST_MISSING_GUEST_EVENTS
expect_exit "$EXIT_INCOMPLETE" bash "$RUNNER" verify-run --run "$preflight_meta_id" \
  --evidence-root "$TEST_ROOT/runs"
artifact_meta_id=$(bash "$RUNNER" prepare --lane fedora-44-x86_64 \
  --suite capacity-preflight --development --evidence-root "$TEST_ROOT/runs")
artifact_meta_run="$TEST_ROOT/runs/$artifact_meta_id"
guest_scratch="$artifact_meta_run/transient/driver/scratch"
ensure_private_directory "$artifact_meta_run/transient/driver"
ensure_private_directory "$guest_scratch"
printf '{"bounded":true}\n' >"$guest_scratch/guest-events.jsonl"
retain_guest_events_artifact "$artifact_meta_run" "$guest_scratch" \
  || fail "bounded raw guest events were not retained"
[[ $(sha256_file "$guest_scratch/guest-events.jsonl") \
  == "$(sha256_file "$artifact_meta_run/raw/guest-events.jsonl")" ]] \
  || fail "retained raw guest events changed bytes"
rm -f -- "$guest_scratch/guest-events.jsonl"
if retain_guest_events_artifact "$artifact_meta_run" "$guest_scratch"; then
  fail "missing capacity guest events were accepted"
fi
pass "raw capacity guest events are retained atomically and required fail closed"

# The shared unprivileged-QEMU helper enforces the documented VM boundary and
# supplies every x86 lane with one short path inside the sandbox-private /tmp.
# shellcheck source=/dev/null
source "$REPO_ROOT/interop-tests/compose-phase1/drivers/lib/qemu-unpriv.sh"
require_tool python3 >/dev/null || fail "python3 is required for the QMP socket test"
qemu_unpriv_selfcheck || fail "unprivileged-QEMU boundary self-check failed"
qmp_socket=$(qemu_unpriv_qmp_socket_path)
[[ $qmp_socket == /tmp/* && ${#qmp_socket} -lt 108 ]] \
  || fail "QMP socket path is not short and sandbox-private: $qmp_socket"
for x86_driver in fedora-selinux-rootless.sh ubuntu-2404.sh; do
  grep -Eq '^[[:space:]]*qmp=\$\(qemu_unpriv_qmp_socket_path\)$' \
    "$REPO_ROOT/interop-tests/compose-phase1/drivers/$x86_driver" \
    || fail "$x86_driver does not use the shared private-/tmp QMP path"
done

# Prove the shared path is usable inside the actual Bubblewrap boundary. The
# probe deliberately leaves the socket pathname behind; sandbox teardown must
# discard the private /tmp mount without changing any pre-existing host entry.
# Use lstat-style metadata so a stale host socket or symlink is preserved rather
# than making host state a prerequisite for this isolation test.
qmp_host_before=$(stat -c '%d:%i:%F' -- "$qmp_socket" 2>/dev/null || printf 'absent\n')
qmp_probe_id=$(prepare_dev_run)
qmp_probe_run="$TEST_ROOT/runs/$qmp_probe_id"
qmp_probe_scratch="$qmp_probe_run/transient/qmp-probe"
ensure_private_directory "$qmp_probe_scratch"
printf '%s\n' "$qmp_socket" >"$qmp_probe_scratch/qmp-path"
qmp_probe_driver="$qmp_probe_scratch/probe.sh"
cat >"$qmp_probe_driver" <<'QMP_PROBE'
#!/usr/bin/env bash
set -euo pipefail
qmp=$(<"$BASIL_DRIVER_SCRATCH/qmp-path")
python3 - "$qmp" "$BASIL_DRIVER_SCRATCH/qmp-bound" <<'PY'
import socket
import sys
from pathlib import Path

path, marker = sys.argv[1:]
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
    listener.bind(path)
    Path(marker).write_text(path, encoding="utf-8")
PY
QMP_PROBE
chmod 0700 "$qmp_probe_driver"
invoke_driver "$qmp_probe_run" "$qmp_probe_driver" "$qmp_probe_scratch" \
  || fail "sandbox-private QMP socket probe failed"
[[ $(<"$qmp_probe_scratch/qmp-bound") == "$qmp_socket" ]] \
  || fail "QMP socket probe did not bind the shared path"
qmp_host_after=$(stat -c '%d:%i:%F' -- "$qmp_socket" 2>/dev/null || printf 'absent\n')
[[ $qmp_host_after == "$qmp_host_before" ]] \
  || fail "sandbox-private QMP socket changed the pre-existing host path"
pass "QMP socket binds inside private /tmp and is discarded with the sandbox"

# shellcheck disable=SC2054  # QEMU arguments use commas intentionally.
bridge_argv=(qemu-system-x86_64 -nodefaults -netdev bridge,id=net0 \
  -device virtio-net-pci,netdev=net0 \
  -qmp "unix:$qmp_socket,server=on,wait=off")
if qemu_unpriv_assert_boundary "${bridge_argv[@]}"; then
  fail "QEMU boundary accepted bridged networking"
fi

# shellcheck disable=SC2054  # QEMU arguments use commas intentionally.
tcp_qmp_argv=(qemu-system-x86_64 -nodefaults \
  -netdev user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:2222-:22 \
  -device virtio-net-pci,netdev=net0 -qmp tcp:127.0.0.1:4444,server=on,wait=off)
if qemu_unpriv_assert_boundary "${tcp_qmp_argv[@]}"; then
  fail "QEMU boundary accepted a TCP QMP endpoint"
fi

long_qmp_path="/tmp/$(printf '%0103d' 0)"
# shellcheck disable=SC2054  # QEMU arguments use commas intentionally.
long_qmp_argv=(qemu-system-x86_64 -nodefaults \
  -netdev user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:2222-:22 \
  -device virtio-net-pci,netdev=net0 \
  -qmp "unix:$long_qmp_path,server=on,wait=off")
if qemu_unpriv_assert_boundary "${long_qmp_argv[@]}"; then
  fail "QEMU boundary accepted an overlong QMP socket path"
fi
pass "unprivileged-QEMU helper enforces the VM boundary and short QMP path"

printf 'PASS: Compose Phase 1 evidence fault tests\n'
