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
expect_exit "$valid_status" bash "$RUNNER" verify-run --run "$valid_id" \
  --evidence-root "$TEST_ROOT/runs"
pass "valid finalized evidence preserves typed verification status"

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

printf 'PASS: Compose Phase 1 evidence fault tests\n'
