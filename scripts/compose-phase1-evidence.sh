#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
#
# SPDX-License-Identifier: Apache-2.0

# Retained-evidence runner for Compose integration 1.0 Phase 1 feasibility work.
# This is evidence infrastructure, not a production attestor or provider.

set -euo pipefail
IFS=$'\n\t'
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
readonly REPO_ROOT
readonly FIXTURE_ROOT="$REPO_ROOT/interop-tests/compose-phase1"
readonly LOCK_FILE="$FIXTURE_ROOT/phase1.lock.toml"
readonly DRIVER_ROOT="$FIXTURE_ROOT/drivers"
readonly ARTIFACT_TOOL="$SCRIPT_DIR/compose-phase1-artifacts.sh"
readonly EVENT_SCHEMA="basil.compose.phase1.event"
readonly EVENT_SCHEMA_VERSION=1
readonly MANIFEST_SCHEMA="basil.compose.phase1.manifest"
readonly MANIFEST_SCHEMA_VERSION=1
readonly DRIVER_RESULT_SCHEMA="basil.compose.phase1.driver-result"
readonly DRIVER_RESULT_SCHEMA_VERSION=1
readonly MAX_EVENT_BYTES=$((16 * 1024 * 1024))
readonly MAX_EVENTS=10000
readonly MAX_DRIVER_RESULT_BYTES=$((64 * 1024))
readonly MAX_DRIVER_RESULTS=1024
readonly MAX_GUEST_EVENTS_BYTES=$((16 * 1024 * 1024))
readonly MAX_HOST_SNAPSHOT_BYTES=$((16 * 1024))
readonly MAX_SANDBOX_STATUS_BYTES=$((16 * 1024))
readonly DEFAULT_DRIVER_TIMEOUT_SECONDS=900
readonly INVOKE_SANDBOX_UNVERIFIED=125

readonly EXIT_PASS=0
readonly EXIT_TEST_FAIL=10
readonly EXIT_INFRA_ERROR=20
readonly EXIT_UNSUPPORTED=30
readonly EXIT_INCOMPLETE=40
readonly EXIT_UNQUALIFIED_DIRTY_SOURCE=50
readonly EXIT_NOT_MEASURED=60
readonly EXIT_USAGE=64

usage() {
  cat <<'USAGE'
Usage:
  compose-phase1-evidence.sh prepare --lane LANE [--suite SUITE]
      [--evidence-root PATH] [--qualification|--development]
  compose-phase1-evidence.sh run --run RUN_ID [--evidence-root PATH]
  compose-phase1-evidence.sh collect --run RUN_ID [--evidence-root PATH]
  compose-phase1-evidence.sh verify-run --run RUN_ID [--evidence-root PATH]
  compose-phase1-evidence.sh destroy --run RUN_ID [--evidence-root PATH]
  compose-phase1-evidence.sh status [--run RUN_ID] [--evidence-root PATH]

Typed run statuses and process exit codes:
  PASS=0, TEST_FAIL=10, INFRA_ERROR=20, UNSUPPORTED=30,
  INCOMPLETE=40, UNQUALIFIED_DIRTY_SOURCE=50, NOT_MEASURED=60.
USAGE
}

log() {
  printf '%s\n' "$*" >&2
}

status_exit_code() {
  case "$1" in
    PASS) printf '%s\n' "$EXIT_PASS" ;;
    TEST_FAIL) printf '%s\n' "$EXIT_TEST_FAIL" ;;
    INFRA_ERROR) printf '%s\n' "$EXIT_INFRA_ERROR" ;;
    UNSUPPORTED) printf '%s\n' "$EXIT_UNSUPPORTED" ;;
    INCOMPLETE) printf '%s\n' "$EXIT_INCOMPLETE" ;;
    UNQUALIFIED_DIRTY_SOURCE) printf '%s\n' "$EXIT_UNQUALIFIED_DIRTY_SOURCE" ;;
    NOT_MEASURED) printf '%s\n' "$EXIT_NOT_MEASURED" ;;
    *) printf '%s\n' "$EXIT_INFRA_ERROR" ;;
  esac
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || {
    log "INFRA_ERROR: required tool '$1' is not on PATH"
    return "$EXIT_INFRA_ERROR"
  }
}

utc_now() {
  date -u '+%Y-%m-%dT%H:%M:%SZ'
}

sha256_file() {
  sha256sum -- "$1" | cut -d ' ' -f 1
}

canonical_json_file() {
  local source=$1 destination=$2 temporary
  temporary="${destination}.tmp.$$"
  jq -S -c . "$source" >"$temporary"
  printf '\n' >>"$temporary"
  chmod 0600 "$temporary"
  mv -f -- "$temporary" "$destination"
}

write_json_atomic() {
  local destination=$1 json=$2 temporary
  temporary="${destination}.tmp.$$"
  printf '%s\n' "$json" | jq -S -c . >"$temporary"
  chmod 0600 "$temporary"
  mv -f -- "$temporary" "$destination"
}

default_evidence_root() {
  printf '%s\n' "${XDG_STATE_HOME:-$HOME/.local/state}/basil/compose-qualification/runs"
}

path_has_symlink_component() {
  local candidate=$1 probe
  probe=$candidate
  while [[ $probe != / && $probe != . ]]; do
    if [[ -L $probe ]]; then
      return 0
    fi
    probe=$(dirname "$probe")
  done
  return 1
}

validate_evidence_root() {
  local requested=$1 qualification=$2 canonical repo mode mode_octal owner
  [[ -n $requested && $requested = /* ]] || {
    log "INFRA_ERROR: evidence root must be an absolute path"
    return "$EXIT_INFRA_ERROR"
  }
  path_has_symlink_component "$requested" && {
    log "INFRA_ERROR: evidence root has a symbolic-link path component"
    return "$EXIT_INFRA_ERROR"
  }
  canonical=$(realpath -m -- "$requested")
  repo=$(realpath -e -- "$REPO_ROOT")

  case "$canonical" in
    /|/bin|/boot|/dev|/etc|/home|/lib|/lib64|/nix|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/var|/var/tmp|"$HOME")
      log "INFRA_ERROR: evidence root is too broad: $canonical"
      return "$EXIT_INFRA_ERROR"
      ;;
  esac
  case "$canonical/" in
    "$repo/"*|*/target/*)
      log "INFRA_ERROR: evidence root must not be inside the repository or target tree"
      return "$EXIT_INFRA_ERROR"
      ;;
  esac
  case "$repo/" in
    "$canonical/"*)
      log "INFRA_ERROR: evidence root must not contain the repository"
      return "$EXIT_INFRA_ERROR"
      ;;
  esac

  if [[ -e $canonical ]]; then
    [[ -d $canonical && ! -L $canonical ]] || {
      log "INFRA_ERROR: evidence root is not a real directory"
      return "$EXIT_INFRA_ERROR"
    }
    owner=$(stat -c '%u' -- "$canonical")
    [[ $owner == "$EUID" ]] || {
      log "INFRA_ERROR: evidence root is not owned by the current user"
      return "$EXIT_INFRA_ERROR"
    }
    mode=$(stat -c '%a' -- "$canonical")
    mode_octal=$((8#$mode))
    if (( (mode_octal & 077) != 0 )); then
      log "INFRA_ERROR: existing evidence root must deny group/other access"
      return "$EXIT_INFRA_ERROR"
    fi
  fi

  if [[ $qualification == qualification && $canonical == /tmp/* ]]; then
    log "INFRA_ERROR: qualification evidence cannot be retained under /tmp"
    return "$EXIT_INFRA_ERROR"
  fi
  printf '%s\n' "$canonical"
}

ensure_private_directory() {
  local directory=$1
  mkdir -p -- "$directory"
  chmod 0700 -- "$directory"
}

ensure_evidence_root() {
  local requested=$1 qualification=$2 canonical
  canonical=$(validate_evidence_root "$requested" "$qualification") || return $?
  ensure_private_directory "$canonical"
  printf '%s\n' "$canonical"
}

validate_identifier() {
  [[ $1 =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]{0,95}$ ]]
}

validate_driver_name() {
  [[ $1 =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]]
}

validate_process_role() {
  [[ $1 =~ ^[a-z0-9][a-z0-9-]{0,47}$ ]]
}

lane_is_development_only() {
  local run=$1
  [[ $(run_metadata_field "$run" '.lane.development_only // false') == true ]]
}

required_test_contains() {
  local suite=$1 test_id=$2
  required_tests_json "$suite" | jq -e --arg test_id "$test_id" 'index($test_id) != null' >/dev/null
}

new_run_id() {
  local random
  random=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
  printf '%s-%s\n' "$(date -u '+%Y%m%dT%H%M%SZ')" "$random"
}

lock_python() {
  require_tool python3 >/dev/null
  [[ -f $LOCK_FILE && ! -L $LOCK_FILE ]] || {
    log "INFRA_ERROR: missing phase lock: $LOCK_FILE"
    return "$EXIT_INFRA_ERROR"
  }
  python3 - "$LOCK_FILE" "$@" <<'PY'
import json
import pathlib
import sys
import tomllib

path = pathlib.Path(sys.argv[1])
with path.open("rb") as handle:
    data = tomllib.load(handle)
node = data
for part in sys.argv[2:]:
    if not isinstance(node, dict) or part not in node:
        raise SystemExit(2)
    node = node[part]
if isinstance(node, (dict, list)):
    print(json.dumps(node, separators=(",", ":"), sort_keys=True))
elif isinstance(node, bool):
    print("true" if node else "false")
else:
    print(node)
PY
}

lock_lane_field() {
  lock_python lanes "$1" "$2"
}

required_tests_json() {
  lock_python suites "$1" required_tests
}

required_tests_lines() {
  required_tests_json "$1" | jq -r '.[]'
}

effective_vm_json() {
  local lane_json=$1 suite=$2 suite_vm effective preflight_vm
  suite_vm=$(lock_python suites "$suite" vm 2>/dev/null || printf '{}')
  effective=$(jq -e -n -c --argjson lane "$lane_json" --argjson suite_vm "$suite_vm" '
    {
      memory_mib: ($suite_vm.memory_mib // $lane.memory_mib),
      vcpus: ($suite_vm.vcpus // $lane.vcpus),
      disk_gib: ($suite_vm.disk_gib // $lane.disk_gib)
    }
    | select(
        (.memory_mib | type == "number" and floor == . and . > 0)
        and (.vcpus | type == "number" and floor == . and . > 0)
        and (.disk_gib | type == "number" and floor == . and . > 0)
      )
  ') || return "$EXIT_INFRA_ERROR"
  if [[ $suite == capacity ]]; then
    preflight_vm=$(lock_python suites capacity-preflight vm) || return "$EXIT_INFRA_ERROR"
    jq -e -n --argjson capacity "$effective" --argjson preflight "$preflight_vm" '
      $capacity.memory_mib >= $preflight.memory_mib
      and $capacity.vcpus >= $preflight.vcpus
      and $capacity.disk_gib >= $preflight.disk_gib
    ' >/dev/null || return "$EXIT_INFRA_ERROR"
  fi
  printf '%s\n' "$effective"
}

create_host_filesystem_snapshot() {
  local run=$1 run_id=$2
  local destination="$run/raw/host-filesystem-snapshot.json"
  local fs_type device_id block_size blocks_available blocks_total
  local inodes_available inodes_total inode_applicable snapshot_id bytes digest
  fs_type=$(stat -f -c '%T' -- "$run") || return "$EXIT_INFRA_ERROR"
  device_id=$(stat -c '%d' -- "$run") || return "$EXIT_INFRA_ERROR"
  block_size=$(stat -f -c '%S' -- "$run") || return "$EXIT_INFRA_ERROR"
  blocks_available=$(stat -f -c '%a' -- "$run") || return "$EXIT_INFRA_ERROR"
  blocks_total=$(stat -f -c '%b' -- "$run") || return "$EXIT_INFRA_ERROR"
  inodes_available=$(stat -f -c '%d' -- "$run") || return "$EXIT_INFRA_ERROR"
  inodes_total=$(stat -f -c '%c' -- "$run") || return "$EXIT_INFRA_ERROR"
  [[ $device_id =~ ^[0-9]+$ && $block_size =~ ^[0-9]+$ \
    && $blocks_available =~ ^[0-9]+$ && $blocks_total =~ ^[0-9]+$ \
    && $inodes_available =~ ^[0-9]+$ && $inodes_total =~ ^[0-9]+$ \
    && $blocks_available -le $blocks_total ]] || return "$EXIT_INFRA_ERROR"
  if (( inodes_total == 0 && inodes_available == 0 )); then
    inode_applicable=false
  elif (( inodes_total > 0 && inodes_available <= inodes_total )); then
    inode_applicable=true
  else
    return "$EXIT_INFRA_ERROR"
  fi
  snapshot_id="${run_id}-host-filesystem"
  write_json_atomic "$destination" "$(jq -n -c \
    --arg snapshot_id "$snapshot_id" --arg fs_type "${fs_type:0:64}" \
    --arg device_id "$device_id" \
    --argjson bytes_available "$((block_size * blocks_available))" \
    --argjson bytes_total "$((block_size * blocks_total))" \
    --argjson inodes_available "$inodes_available" \
    --argjson inodes_total "$inodes_total" \
    --argjson inode_applicable "$inode_applicable" \
    '{source:"host-evidence-root",snapshot_id:$snapshot_id,
      path_label:"runner-evidence-root",fs_type:$fs_type,device_id:$device_id,
      bytes_available:$bytes_available,bytes_total:$bytes_total,
      inodes_available:$inodes_available,inodes_total:$inodes_total,
      inode_applicable:$inode_applicable}')"
  bytes=$(stat -c '%s' -- "$destination") || return "$EXIT_INFRA_ERROR"
  (( bytes > 0 && bytes <= MAX_HOST_SNAPSHOT_BYTES )) || return "$EXIT_INFRA_ERROR"
  digest=$(sha256_file "$destination") || return "$EXIT_INFRA_ERROR"
  jq -n -c --arg path raw/host-filesystem-snapshot.json \
    --arg snapshot_id "$snapshot_id" --argjson bytes "$bytes" --arg sha256 "$digest" \
    '{path:$path,snapshot_id:$snapshot_id,bytes:$bytes,sha256:$sha256}'
}

source_snapshot_json() {
  local commit dirty=true summary
  commit=$(jj log -r @ --no-graph -T 'commit_id.short(12)' 2>/dev/null || printf 'unknown')
  summary=$(jj diff --summary 2>/dev/null || printf 'jj-status-unavailable')
  [[ -z $summary ]] && dirty=false
  jq -n -c \
    --arg commit "$commit" \
    --argjson dirty "$dirty" \
    --arg summary "$summary" \
    '{vcs:"jj",commit:$commit,dirty:$dirty,dirty_summary:$summary}'
}

run_path() {
  local root=$1 run_id=$2
  validate_identifier "$run_id" || {
    log "INFRA_ERROR: invalid run ID"
    return "$EXIT_INFRA_ERROR"
  }
  printf '%s/%s\n' "$root" "$run_id"
}

assert_run_directory() {
  local run=$1 root=$2 canonical
  [[ -d $run && ! -L $run ]] || {
    log "INFRA_ERROR: run directory does not exist: $run"
    return "$EXIT_INFRA_ERROR"
  }
  canonical=$(realpath -e -- "$run")
  [[ $canonical == "$root/"* ]] || {
    log "INFRA_ERROR: run directory escapes evidence root"
    return "$EXIT_INFRA_ERROR"
  }
  [[ -f $run/meta/run.json && ! -L $run/meta/run.json ]] || {
    log "INFRA_ERROR: run metadata is missing or unsafe"
    return "$EXIT_INFRA_ERROR"
  }
}

run_metadata_field() {
  jq -er "$2" "$1/meta/run.json"
}

emit_event() {
  local run=$1 event=$2 status=$3 reason=$4 test_id=${5:-} message=${6:-} details=${7:-'{}'}
  local run_id lane_id sequence timestamp temporary
  run_id=$(run_metadata_field "$run" '.run_id')
  lane_id=$(run_metadata_field "$run" '.lane_id')
  sequence=$(<"$run/meta/seq")
  [[ $sequence =~ ^[0-9]+$ ]] || return "$EXIT_INFRA_ERROR"
  sequence=$((sequence + 1))
  timestamp=$(utc_now)
  jq -e 'type == "object"' <<<"$details" >/dev/null
  temporary="$run/sanitized/events.jsonl.tmp.$$"
  jq -n -c \
    --arg schema "$EVENT_SCHEMA" \
    --argjson schema_version "$EVENT_SCHEMA_VERSION" \
    --arg run_id "$run_id" \
    --arg lane_id "$lane_id" \
    --argjson seq "$sequence" \
    --arg time "$timestamp" \
    --arg event "$event" \
    --arg status "$status" \
    --arg reason_code "$reason" \
    --arg test_id "$test_id" \
    --arg message "$message" \
    --argjson details "$details" \
    '{schema:$schema,schema_version:$schema_version,run_id:$run_id,lane_id:$lane_id,
      seq:$seq,time:$time,event:$event,status:$status,reason_code:$reason_code,
      details:$details}
     + (if $test_id == "" then {} else {test_id:$test_id} end)
     + (if $message == "" then {} else {message:$message} end)' >"$temporary"
  chmod 0600 "$temporary"
  cat -- "$temporary" >>"$run/sanitized/events.jsonl"
  rm -f -- "$temporary"
  printf '%s\n' "$sequence" >"$run/meta/seq.tmp"
  chmod 0600 "$run/meta/seq.tmp"
  mv -f -- "$run/meta/seq.tmp" "$run/meta/seq"
}

validate_events() {
  local events=$1 required=$2 bytes lines
  [[ -f $events && ! -L $events ]] || return 1
  bytes=$(stat -c '%s' -- "$events")
  (( bytes > 0 && bytes <= MAX_EVENT_BYTES )) || return 1
  lines=$(wc -l <"$events")
  (( lines > 0 && lines <= MAX_EVENTS )) || return 1
  jq -e -s --arg schema "$EVENT_SCHEMA" \
    --argjson version "$EVENT_SCHEMA_VERSION" \
    --argjson required "$required" '
      . as $events
      | length > 0
      and (all($events[];
        (.schema == $schema)
        and (.schema_version == $version)
        and (.run_id | type == "string" and test("^[a-zA-Z0-9._-]{1,96}$"))
        and (.lane_id | type == "string" and test("^[a-z0-9][a-z0-9._-]{0,62}$"))
        and (.seq | type == "number" and floor == . and . > 0)
        and (.time | type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))
        and (.event | type == "string" and test("^[a-z][a-z0-9.-]{0,63}$"))
        and (.status | IN("RUNNING","PASS","TEST_FAIL","INFRA_ERROR","UNSUPPORTED","INCOMPLETE","UNQUALIFIED_DIRTY_SOURCE","NOT_MEASURED"))
        and (.reason_code | type == "string" and test("^[A-Z][A-Z0-9_]{0,63}$"))
        and ((.message // "") | type == "string" and length <= 512)
        and (.details | type == "object" and (tostring | length) <= 4096)))
      and (($events | map(.run_id) | unique | length) == 1)
      and (($events | map(.lane_id) | unique | length) == 1)
      and ($events | to_entries | all(.[]; .value.seq == (.key + 1)))
      and ([$events[] | select(.event == "run.start")] | length == 1)
      and ([$events[] | select(.event == "run.end")] | length == 1)
      and ($events[0].event == "run.start" and $events[0].status == "RUNNING")
      and ($events[-1].event == "run.end" and $events[-1].status != "RUNNING")
      and (all($required[];
        . as $test
        | ([$events[] | select(.event == "test.end" and .test_id == $test)] | length) == 1))
      and (all($events[] | select(.event == "test.end");
        .test_id as $test_id
        | ($test_id | type == "string" and length > 0)
        and ($required | index($test_id)) != null
        and (.status != "RUNNING")))
      and (([$events[] | select(.event == "test.end") | .test_id] | length)
        == ([$events[] | select(.event == "test.end") | .test_id] | unique | length))
      and (if $events[-1].status == "PASS" then
        ($required | length) > 0
        and all($required[];
          . as $test
          | any($events[]; .event == "test.end" and .test_id == $test and .status == "PASS"))
        and any($events[]; .event == "test.end" and .status == "PASS")
      else true end)
    ' "$events" >/dev/null
}

test_has_terminal() {
  local events=$1 test_id=$2
  jq -e --arg test_id "$test_id" \
    'select(.event == "test.end" and .test_id == $test_id)' "$events" >/dev/null 2>&1
}

fill_missing_test_terminals() {
  local run=$1 status=$2 reason=$3 suite test_id
  suite=$(run_metadata_field "$run" '.suite')
  while IFS= read -r test_id; do
    if ! test_has_terminal "$run/sanitized/events.jsonl" "$test_id"; then
      emit_event "$run" test.end "$status" "$reason" "$test_id"
    fi
  done < <(required_tests_lines "$suite")
}

copy_retained_file() {
  local source=$1 destination=$2
  [[ -f $source && ! -L $source ]] || return 0
  install -m 0600 -- "$source" "$destination"
}

collect_outputs() {
  local run=$1
  local scratch="$run/transient/driver/scratch"
  copy_retained_file "$run/transient/serial.log" "$run/raw/serial.log"
  copy_retained_file "$run/transient/qemu.stderr.log" "$run/raw/qemu.stderr.log"
  copy_retained_file "$run/transient/guest-events.jsonl" "$run/raw/guest-events.jsonl"
  copy_retained_file "$scratch/serial.log" "$run/raw/serial.log"
  copy_retained_file "$scratch/qemu.stderr.log" "$run/raw/qemu.stderr.log"
  copy_retained_file "$scratch/driver.stdout.log" "$run/raw/driver.stdout.log"
  copy_retained_file "$scratch/driver.stderr.log" "$run/raw/driver.stderr.log"
  jq -S -c '{schema,schema_version,run_id,lane_id,seq,time,event,status,reason_code,test_id,message,details}' \
    "$run/sanitized/events.jsonl" >"$run/sanitized/events.canonical.jsonl"
  chmod 0600 "$run/sanitized/events.canonical.jsonl"
}

inventory_json() {
  local run=$1 relative file size digest privacy first=true
  printf '['
  while IFS= read -r -d '' file; do
    relative=${file#"$run/"}
    case "$relative" in
      raw/*) privacy=private-raw ;;
      sanitized/*) privacy=sanitized ;;
      meta/run.json) privacy=metadata ;;
      *) continue ;;
    esac
    size=$(stat -c '%s' -- "$file")
    digest=$(sha256_file "$file")
    if [[ $first == true ]]; then first=false; else printf ','; fi
    jq -n -c --arg path "$relative" --argjson size "$size" --arg sha256 "$digest" \
      --arg privacy "$privacy" '{path:$path,size:$size,sha256:$sha256,privacy:$privacy}'
  done < <(find "$run/raw" "$run/sanitized" "$run/meta/run.json" -xdev -type f -print0 | sort -z)
  printf ']\n'
}

build_manifest() {
  local run=$1 status=$2 reason=$3 required started ended inventory source qualification
  required=$(required_tests_json "$(run_metadata_field "$run" '.suite')")
  started=$(jq -sr '[.[] | select(.event == "run.start")][0].time' "$run/sanitized/events.jsonl")
  ended=$(jq -sr '[.[] | select(.event == "run.end")][0].time' "$run/sanitized/events.jsonl")
  inventory=$(inventory_json "$run")
  source=$(run_metadata_field "$run" '.source')
  qualification=$(run_metadata_field "$run" '.qualification')
  jq -n -S -c \
    --arg schema "$MANIFEST_SCHEMA" \
    --argjson schema_version "$MANIFEST_SCHEMA_VERSION" \
    --arg run_id "$(run_metadata_field "$run" '.run_id')" \
    --arg lane_id "$(run_metadata_field "$run" '.lane_id')" \
    --arg suite "$(run_metadata_field "$run" '.suite')" \
    --arg qualification "$qualification" \
    --arg status "$status" \
    --arg reason_code "$reason" \
    --arg started_at "$started" \
    --arg ended_at "$ended" \
    --arg event_sha256 "$(sha256_file "$run/sanitized/events.jsonl")" \
    --argjson required_tests "$required" \
    --argjson source "$source" \
    --argjson files "$inventory" \
    '{schema:$schema,schema_version:$schema_version,run_id:$run_id,lane_id:$lane_id,
      suite:$suite,qualification:$qualification,status:$status,reason_code:$reason_code,
      started_at:$started_at,ended_at:$ended_at,event_sha256:$event_sha256,
      required_tests:$required_tests,source:$source,files:$files}' >"$run/manifest.json.tmp"
  chmod 0600 "$run/manifest.json.tmp"
  mv -f -- "$run/manifest.json.tmp" "$run/manifest.json"
  sha256_file "$run/manifest.json" >"$run/manifest.sha256.tmp"
  chmod 0600 "$run/manifest.sha256.tmp"
  mv -f -- "$run/manifest.sha256.tmp" "$run/manifest.sha256"
}

finalize_state_marker() {
  local run=$1 marker=$2
  [[ -f $run/RUNNING && ! -L $run/RUNNING ]] || return "$EXIT_INFRA_ERROR"
  case "$marker" in COMPLETE|INCOMPLETE) ;; *) return "$EXIT_INFRA_ERROR" ;; esac
  mv -- "$run/RUNNING" "$run/$marker"
}

finish_run() {
  local run=$1 status=$2 reason=$3 marker=COMPLETE required
  [[ -f $run/RUNNING ]] || return 0
  [[ $status == INCOMPLETE ]] && marker=INCOMPLETE
  fill_missing_test_terminals "$run" "$status" "$reason"
  emit_event "$run" run.end "$status" "$reason"
  collect_outputs "$run"
  required=$(required_tests_json "$(run_metadata_field "$run" '.suite')")
  if ! validate_events "$run/sanitized/events.jsonl" "$required"; then
    status=INCOMPLETE
    reason=EVENT_VALIDATION_FAILED
    marker=INCOMPLETE
  fi
  build_manifest "$run" "$status" "$reason"
  finalize_state_marker "$run" "$marker"
}

process_start_time() {
  local pid=$1
  perl -ne 'if (/^\d+ \(.*\) (.*)$/) { @f=split / /,$1; print $f[19] }' "/proc/$pid/stat" 2>/dev/null
}

process_marker_is_owned() {
  local run=$1 marker=$2 token=$3 transient canonical_marker marker_value
  [[ $marker = /* && -f $marker && ! -L $marker ]] || return 1
  path_has_symlink_component "$marker" && return 1
  transient=$(realpath -e -- "$run/transient") || return 1
  canonical_marker=$(realpath -e -- "$marker") || return 1
  [[ $canonical_marker == "$transient/"* ]] || return 1
  marker_value=$(<"$marker")
  [[ $marker_value == "$token" ]]
}

record_process() {
  local run=$1 role=$2 pid=$3 marker=$4 token=$5 executable start_time record
  validate_process_role "$role" || return "$EXIT_INFRA_ERROR"
  [[ $pid =~ ^[1-9][0-9]*$ ]] || return "$EXIT_INFRA_ERROR"
  process_marker_is_owned "$run" "$marker" "$token" || return "$EXIT_INFRA_ERROR"
  executable=$(readlink -f -- "/proc/$pid/exe")
  start_time=$(process_start_time "$pid")
  [[ -n $executable && -n $start_time ]] || return "$EXIT_INFRA_ERROR"
  record="$run/meta/process-$role.json"
  [[ ! -e $record ]] || return "$EXIT_INFRA_ERROR"
  write_json_atomic "$record" "$(jq -n -c --arg role "$role" --argjson pid "$pid" \
    --arg start_time "$start_time" --arg executable "$executable" \
    --arg marker "$marker" --arg token "$token" \
    '{role:$role,pid:$pid,start_time:$start_time,executable:$executable,marker:$marker,token:$token}')"
}

process_record_matches() {
  local record=$1 run=$2 pid start_time executable marker token actual_start actual_executable
  [[ -f $record && ! -L $record ]] || return 1
  pid=$(jq -er '.pid' "$record") || return 1
  start_time=$(jq -er '.start_time' "$record") || return 1
  executable=$(jq -er '.executable' "$record") || return 1
  marker=$(jq -er '.marker' "$record") || return 1
  token=$(jq -er '.token' "$record") || return 1
  [[ $pid =~ ^[1-9][0-9]*$ && -e /proc/$pid/stat ]] || return 1
  process_marker_is_owned "$run" "$marker" "$token" || return 1
  actual_start=$(process_start_time "$pid")
  actual_executable=$(readlink -f -- "/proc/$pid/exe")
  [[ $actual_start == "$start_time" && $actual_executable == "$executable" ]]
}

terminate_recorded_process() {
  local record=$1 run=$2 pid
  [[ -e $record ]] || return 0
  if ! process_record_matches "$record" "$run"; then
    log "INCOMPLETE: refusing to signal process whose PID/start/executable/marker do not all match: $record"
    return "$EXIT_INCOMPLETE"
  fi
  pid=$(jq -er '.pid' "$record")
  kill -TERM "$pid" 2>/dev/null || true
  for _ in $(seq 1 50); do
    [[ ! -e /proc/$pid/stat ]] && break
    sleep 0.1
  done
  if [[ -e /proc/$pid/stat ]]; then
    if ! process_record_matches "$record" "$run"; then
      log "INCOMPLETE: process identity changed before escalation; refusing SIGKILL"
      return "$EXIT_INCOMPLETE"
    fi
    kill -KILL "$pid" 2>/dev/null || true
  fi
  rm -f -- "$record"
}

destroy_run_transients() {
  local run=$1 record owner process_records=false
  for record in "$run"/meta/process-*.json; do
    [[ -e $record ]] || continue
    if [[ $record == */process-orchestrator.json ]]; then
      continue
    fi
    process_records=true
    terminate_recorded_process "$record" "$run" || return $?
  done
  if [[ ! -e $run/transient ]]; then
    [[ $process_records == false ]] || return "$EXIT_INCOMPLETE"
    return 0
  fi
  owner="$run/transient/.owner"
  [[ -f $owner && ! -L $owner && $(<"$owner") == "$(run_metadata_field "$run" '.run_id')" ]] || {
    log "INCOMPLETE: refusing cleanup without the exact per-run transient marker"
    return "$EXIT_INCOMPLETE"
  }
  [[ -d $run/transient && ! -L $run/transient ]] || return "$EXIT_INCOMPLETE"
  rm -rf --one-file-system -- "$run/transient"
}

cleanup_for_finalization() {
  local run=$1
  collect_outputs "$run"
  if destroy_run_transients "$run"; then
    emit_event "$run" harness.cleanup PASS CLEANUP_COMPLETE
    return 0
  fi
  emit_event "$run" harness.cleanup INCOMPLETE CLEANUP_IDENTITY_MISMATCH
  return "$EXIT_INCOMPLETE"
}

prepare_ssh_material() {
  local run=$1 public_key
  ensure_private_directory "$run/transient/ssh"
  ensure_private_directory "$run/transient/qmp"
  ensure_private_directory "$run/transient/markers"
  if command -v ssh-keygen >/dev/null 2>&1; then
    ssh-keygen -q -t ed25519 -N '' -C "basil-compose-phase1-$(run_metadata_field "$run" '.run_id')" \
      -f "$run/transient/ssh/id_ed25519"
    chmod 0600 "$run/transient/ssh/id_ed25519" "$run/transient/ssh/id_ed25519.pub"
    public_key=$(<"$run/transient/ssh/id_ed25519.pub")
    printf '%s\n' "$public_key" >"$run/meta/ssh-public-key"
    chmod 0600 "$run/meta/ssh-public-key"
  fi
}

prepare_command() {
  local lane='' suite=lane-smoke root_requested qualification=development root run_id run source lane_json
  local effective_vm host_snapshot
  root_requested=$(default_evidence_root)
  while (( $# > 0 )); do
    case "$1" in
      --lane) lane=${2:-}; shift 2 ;;
      --suite) suite=${2:-}; shift 2 ;;
      --evidence-root) root_requested=${2:-}; shift 2 ;;
      --qualification) qualification=qualification; shift ;;
      --development) qualification=development; shift ;;
      *) log "unknown prepare argument: $1"; return "$EXIT_USAGE" ;;
    esac
  done
  validate_identifier "$lane" || { log "invalid or missing lane"; return "$EXIT_USAGE"; }
  validate_identifier "$suite" || { log "invalid suite"; return "$EXIT_USAGE"; }
  lane_json=$(lock_python lanes "$lane") || { log "unsupported lane: $lane"; return "$EXIT_UNSUPPORTED"; }
  if [[ $qualification == qualification && $(jq -r '.development_only // false' <<<"$lane_json") == true ]]; then
    log "UNSUPPORTED: development-only lane refused under qualification: $lane"
    return "$EXIT_UNSUPPORTED"
  fi
  required_tests_json "$suite" >/dev/null || { log "unsupported suite: $suite"; return "$EXIT_UNSUPPORTED"; }
  effective_vm=$(effective_vm_json "$lane_json" "$suite") \
    || { log "INFRA_ERROR: invalid effective VM sizing for lane=$lane suite=$suite"; return "$EXIT_INFRA_ERROR"; }
  root=$(ensure_evidence_root "$root_requested" "$qualification") || return $?
  run_id=$(new_run_id)
  run=$(run_path "$root" "$run_id")
  ensure_private_directory "$run"
  ensure_private_directory "$run/raw"
  ensure_private_directory "$run/sanitized"
  ensure_private_directory "$run/meta"
  ensure_private_directory "$run/transient"
  printf '%s\n' "$run_id" >"$run/transient/.owner"
  chmod 0600 "$run/transient/.owner"
  printf '0\n' >"$run/meta/seq"
  chmod 0600 "$run/meta/seq"
  : >"$run/sanitized/events.jsonl"
  chmod 0600 "$run/sanitized/events.jsonl"
  host_snapshot=$(create_host_filesystem_snapshot "$run" "$run_id") \
    || { log "INFRA_ERROR: host evidence filesystem snapshot failed"; return "$EXIT_INFRA_ERROR"; }
  source=$(source_snapshot_json)
  write_json_atomic "$run/meta/run.json" "$(jq -n -c \
    --arg run_id "$run_id" --arg lane_id "$lane" --arg suite "$suite" \
    --arg qualification "$qualification" --arg created_at "$(utc_now)" \
    --argjson source "$source" --argjson lane "$lane_json" \
    --argjson effective_vm "$effective_vm" --argjson host_snapshot "$host_snapshot" \
    '{run_id:$run_id,lane_id:$lane_id,suite:$suite,qualification:$qualification,
      created_at:$created_at,source:$source,lane:$lane,effective_vm:$effective_vm,
      host_evidence_snapshot:$host_snapshot}')"
  write_json_atomic "$run/RUNNING" "$(jq -n -c --arg run_id "$run_id" --arg started_at "$(utc_now)" \
    '{run_id:$run_id,started_at:$started_at}')"
  prepare_ssh_material "$run"
  emit_event "$run" run.start RUNNING RUN_PREPARED '' '' \
    "$(jq -n -c --arg qualification "$qualification" '{qualification:$qualification}')"

  if [[ $qualification == qualification && $(jq -r '.dirty' <<<"$source") == true ]]; then
    fill_missing_test_terminals "$run" UNQUALIFIED_DIRTY_SOURCE DIRTY_SOURCE
    cleanup_for_finalization "$run" || true
    finish_run "$run" UNQUALIFIED_DIRTY_SOURCE DIRTY_SOURCE
    printf '%s\n' "$run_id"
    return "$EXIT_UNQUALIFIED_DIRTY_SOURCE"
  fi
  printf '%s\n' "$run_id"
}

verify_lane_artifacts() {
  local run=$1 artifact
  [[ -x $ARTIFACT_TOOL && ! -L $ARTIFACT_TOOL ]] || return "$EXIT_INCOMPLETE"
  while IFS= read -r artifact; do
    "$ARTIFACT_TOOL" verify "$artifact" >/dev/null || return "$EXIT_INFRA_ERROR"
  done < <(run_metadata_field "$run" '.lane.artifacts[]')
}

# Explicit fail-closed allowlist of scenario driver names. Only names listed
# here may be resolved and executed; provisioning a real lane driver adds its
# name to this predicate and drops the script under the driver root.
driver_is_allowlisted() {
  case "$1" in
    null) return 0 ;;
    fedora-selinux-rootless) return 0 ;;
    ubuntu-2404) return 0 ;;
    ubuntu-2404-arm64) return 0 ;;
    *) return 1 ;;
  esac
}

# Resolve a driver name to an absolute, executable, non-symlink script strictly
# under the driver root. Rejects traversal, arbitrary paths, and unlisted names.
resolve_driver() {
  local name=$1 root candidate canonical
  validate_driver_name "$name" || {
    log "INFRA_ERROR: invalid driver name"
    return "$EXIT_INFRA_ERROR"
  }
  driver_is_allowlisted "$name" || {
    log "INFRA_ERROR: driver is not allowlisted: $name"
    return "$EXIT_INFRA_ERROR"
  }
  root=$(realpath -e -- "$DRIVER_ROOT" 2>/dev/null) || {
    log "INFRA_ERROR: driver root is missing"
    return "$EXIT_INFRA_ERROR"
  }
  candidate="$root/$name.sh"
  [[ -f $candidate && ! -L $candidate ]] || {
    log "INFRA_ERROR: unknown or unsafe driver: $name"
    return "$EXIT_INFRA_ERROR"
  }
  canonical=$(realpath -e -- "$candidate" 2>/dev/null) || {
    log "INFRA_ERROR: driver path did not resolve"
    return "$EXIT_INFRA_ERROR"
  }
  [[ $canonical == "$root/"* ]] || {
    log "INFRA_ERROR: driver escapes the driver root"
    return "$EXIT_INFRA_ERROR"
  }
  [[ -x $canonical ]] || {
    log "INFRA_ERROR: driver is not executable"
    return "$EXIT_INFRA_ERROR"
  }
  printf '%s\n' "$canonical"
}

namespace_inode() {
  local namespace=$1 link
  link=$(readlink -- "/proc/self/ns/$namespace") || return "$EXIT_INFRA_ERROR"
  [[ $link =~ ^[a-z]+:\[([0-9]+)\]$ ]] || return "$EXIT_INFRA_ERROR"
  printf '%s\n' "${BASH_REMATCH[1]}"
}

# Bubblewrap reports the child and exit lifecycle on a runner-owned descriptor.
# Accept exactly one start and one exit report, require distinct PID and cgroup
# namespaces, and bind the reported exit to the foreground wrapper result.
validate_sandbox_status() {
  local status_file=$1 wrapper_rc=$2 outer_pid_namespace=$3 outer_cgroup_namespace=$4 bytes
  [[ -f $status_file && ! -L $status_file ]] || return 1
  bytes=$(stat -c '%s' -- "$status_file" 2>/dev/null) || return 1
  (( bytes > 0 && bytes <= MAX_SANDBOX_STATUS_BYTES )) || return 1
  jq -e -s \
    --argjson wrapper_rc "$wrapper_rc" \
    --argjson outer_pid_namespace "$outer_pid_namespace" \
    --argjson outer_cgroup_namespace "$outer_cgroup_namespace" '
      (all(.[]; type == "object"))
      and ([.[] | select(has("child-pid"))] as $starts
        | ($starts | length) == 1
        and ($starts[0]["child-pid"] | type == "number" and . > 0)
        and ($starts[0]["pid-namespace"] | type == "number"
          and . != $outer_pid_namespace)
        and ($starts[0]["cgroup-namespace"] | type == "number"
          and . != $outer_cgroup_namespace))
      and ([.[] | select(has("exit-code"))] as $exits
        | ($exits | length) == 1
        and ($exits[0]["exit-code"] == $wrapper_rc))
    ' "$status_file" >/dev/null 2>&1
}

# Execute a resolved driver under a read-only Bubblewrap view: only the driver
# scratch directory (which holds the result file) is writable. The sandbox is
# time-bounded, owns its process tree through a PID namespace, dies with the
# runner, and starts from a cleared environment. The cgroup namespace isolates
# the view; this harness does not create or claim ownership of a cgroup subtree.
invoke_driver() {
  local run=$1 driver_path=$2 scratch=$3 run_id lane_id suite wrapper_rc
  local sandbox_status sandbox_verified outer_pid_namespace outer_cgroup_namespace
  local vm_memory_mib vm_vcpus vm_disk_gib snapshot_rel snapshot snapshot_bytes snapshot_sha256 snapshot_id
  run_id=$(run_metadata_field "$run" '.run_id') || return "$EXIT_INFRA_ERROR"
  lane_id=$(run_metadata_field "$run" '.lane_id') || return "$EXIT_INFRA_ERROR"
  suite=$(run_metadata_field "$run" '.suite') || return "$EXIT_INFRA_ERROR"
  vm_memory_mib=$(run_metadata_field "$run" '.effective_vm.memory_mib') || return "$EXIT_INFRA_ERROR"
  vm_vcpus=$(run_metadata_field "$run" '.effective_vm.vcpus') || return "$EXIT_INFRA_ERROR"
  vm_disk_gib=$(run_metadata_field "$run" '.effective_vm.disk_gib') || return "$EXIT_INFRA_ERROR"
  snapshot_rel=$(run_metadata_field "$run" '.host_evidence_snapshot.path') || return "$EXIT_INFRA_ERROR"
  snapshot="$run/$snapshot_rel"
  snapshot_bytes=$(run_metadata_field "$run" '.host_evidence_snapshot.bytes') || return "$EXIT_INFRA_ERROR"
  snapshot_sha256=$(run_metadata_field "$run" '.host_evidence_snapshot.sha256') || return "$EXIT_INFRA_ERROR"
  snapshot_id=$(run_metadata_field "$run" '.host_evidence_snapshot.snapshot_id') || return "$EXIT_INFRA_ERROR"
  [[ -f $snapshot && ! -L $snapshot ]] || return "$EXIT_INFRA_ERROR"
  require_tool bwrap >/dev/null || return "$EXIT_INFRA_ERROR"
  require_tool timeout >/dev/null || return "$EXIT_INFRA_ERROR"
  outer_pid_namespace=$(namespace_inode pid) || return "$EXIT_INFRA_ERROR"
  outer_cgroup_namespace=$(namespace_inode cgroup) || return "$EXIT_INFRA_ERROR"
  ensure_private_directory "$run/transient/driver"
  sandbox_status="$run/transient/driver/sandbox-status.jsonl"
  sandbox_verified="$run/transient/driver/sandbox-status.verified"
  rm -f -- "$sandbox_status" "$sandbox_verified"
  local -a sandbox=(
    bwrap
    --ro-bind / /
    --dev /dev
  )
  # The fresh --dev tmpfs hides host device nodes; re-expose /dev/kvm when the
  # host has it so VM lane drivers get hardware acceleration. Drivers request
  # accel=kvm:tcg and degrade to TCG where KVM is absent.
  if [[ -e /dev/kvm ]]; then
    sandbox+=(--dev-bind /dev/kvm /dev/kvm)
  fi
  sandbox+=(
    --tmpfs /tmp
    --bind "$scratch" "$scratch"
    --chdir "$scratch"
    --unshare-user --unshare-ipc --unshare-uts --unshare-cgroup --unshare-pid --unshare-net
    --json-status-fd 3
    --die-with-parent --new-session --clearenv
    --setenv PATH "$PATH"
    --setenv HOME "$scratch"
    --setenv TMPDIR /tmp
    --setenv BASIL_DRIVER_RESULT "$scratch/result.json"
    --setenv BASIL_DRIVER_SCRATCH "$scratch"
    --setenv BASIL_RUN_ID "$run_id"
    --setenv BASIL_LANE_ID "$lane_id"
    --setenv BASIL_DRIVER_SUITE "$suite"
    --setenv BASIL_VM_MEMORY_MIB "$vm_memory_mib"
    --setenv BASIL_VM_VCPUS "$vm_vcpus"
    --setenv BASIL_VM_DISK_GIB "$vm_disk_gib"
    --setenv BASIL_HOST_EVIDENCE_SNAPSHOT "$snapshot"
    --setenv BASIL_HOST_EVIDENCE_SNAPSHOT_BYTES "$snapshot_bytes"
    --setenv BASIL_HOST_EVIDENCE_SNAPSHOT_SHA256 "$snapshot_sha256"
    --setenv BASIL_HOST_EVIDENCE_SNAPSHOT_ID "$snapshot_id"
    --setenv BASIL_DRIVER_RESULT_SCHEMA "$DRIVER_RESULT_SCHEMA"
    --setenv BASIL_DRIVER_RESULT_SCHEMA_VERSION "$DRIVER_RESULT_SCHEMA_VERSION"
    --setenv BASIL_MAX_RESULT_BYTES "$MAX_DRIVER_RESULT_BYTES"
    --
    "$driver_path"
  )
  if timeout --signal=TERM --kill-after=10 "$DEFAULT_DRIVER_TIMEOUT_SECONDS" \
    "${sandbox[@]}" >"$scratch/driver.stdout.log" 2>"$scratch/driver.stderr.log" \
    3>"$sandbox_status"; then
    wrapper_rc=0
  else
    wrapper_rc=$?
  fi
  if ! validate_sandbox_status "$sandbox_status" "$wrapper_rc" \
    "$outer_pid_namespace" "$outer_cgroup_namespace"; then
    log "INCOMPLETE: sandbox PID/cgroup namespace teardown could not be verified"
    return "$INVOKE_SANDBOX_UNVERIFIED"
  fi
  printf 'verified\n' >"$sandbox_verified"
  return "$wrapper_rc"
}

retain_guest_events_artifact() {
  local run=$1 scratch=$2 suite source destination temporary bytes source_hash retained_hash
  suite=$(run_metadata_field "$run" '.suite') || return "$EXIT_INFRA_ERROR"
  source="$scratch/guest-events.jsonl"
  destination="$run/raw/guest-events.jsonl"
  if [[ ! -f $source || -L $source ]]; then
    [[ $suite != capacity-preflight ]] && return 0
    return "$EXIT_INFRA_ERROR"
  fi
  bytes=$(stat -c '%s' -- "$source") || return "$EXIT_INFRA_ERROR"
  (( bytes > 0 && bytes <= MAX_GUEST_EVENTS_BYTES )) || return "$EXIT_INFRA_ERROR"
  source_hash=$(sha256_file "$source") || return "$EXIT_INFRA_ERROR"
  temporary="${destination}.tmp.$$"
  install -m 0600 -- "$source" "$temporary" || { rm -f -- "$temporary"; return "$EXIT_INFRA_ERROR"; }
  [[ $(stat -c '%s' -- "$temporary") == "$bytes" ]] \
    || { rm -f -- "$temporary"; return "$EXIT_INFRA_ERROR"; }
  retained_hash=$(sha256_file "$temporary") || { rm -f -- "$temporary"; return "$EXIT_INFRA_ERROR"; }
  [[ $retained_hash == "$source_hash" ]] \
    || { rm -f -- "$temporary"; return "$EXIT_INFRA_ERROR"; }
  mv -f -- "$temporary" "$destination"
  [[ $(stat -c '%s' -- "$destination") == "$bytes" \
    && $(sha256_file "$destination") == "$source_hash" ]] || return "$EXIT_INFRA_ERROR"
}

# Validate the bounded driver result contract: size-capped, single object with
# the pinned schema/version, and a bounded results array whose every test_id is
# required by the suite, unique, and carries a typed status and reason code.
validate_driver_result() {
  local result=$1 required=$2 bytes
  [[ -f $result && ! -L $result ]] || return 1
  bytes=$(stat -c '%s' -- "$result" 2>/dev/null) || return 1
  (( bytes > 0 && bytes <= MAX_DRIVER_RESULT_BYTES )) || return 1
  jq -e \
    --arg schema "$DRIVER_RESULT_SCHEMA" \
    --argjson version "$DRIVER_RESULT_SCHEMA_VERSION" \
    --argjson max_results "$MAX_DRIVER_RESULTS" \
    --argjson required "$required" '
      (type == "object")
      and (.schema == $schema)
      and (.schema_version == $version)
      and (.driver | type == "string" and test("^[a-z0-9][a-z0-9-]{0,63}$"))
      and (.results | type == "array" and length > 0 and length <= $max_results)
      and (all(.results[];
        (.test_id as $test_id
          | ($test_id | type == "string")
          and (($required | index($test_id)) != null))
        and (.status | IN("PASS","TEST_FAIL","INFRA_ERROR","UNSUPPORTED","INCOMPLETE","NOT_MEASURED"))
        and (.reason_code | type == "string" and test("^[A-Z][A-Z0-9_]{0,63}$"))
        and ((.message // "") | type == "string" and length <= 512)
        and ((.details // {}) | type == "object" and (tostring | length) <= 4096)))
      and (([.results[].test_id] | length) == ([.results[].test_id] | unique | length))
    ' "$result" >/dev/null 2>&1
}

# Emit one runner-owned test.end event per driver-reported result. The runner
# alone assigns sequence numbers; the driver never writes events or manifests.
ingest_driver_result() {
  local run=$1 result=$2 count index test_id status reason message
  count=$(jq '.results | length' "$result") || return "$EXIT_INFRA_ERROR"
  for (( index = 0; index < count; index++ )); do
    test_id=$(jq -r --argjson i "$index" '.results[$i].test_id' "$result")
    status=$(jq -r --argjson i "$index" '.results[$i].status' "$result")
    reason=$(jq -r --argjson i "$index" '.results[$i].reason_code' "$result")
    message=$(jq -r --argjson i "$index" '.results[$i].message // ""' "$result")
    emit_event "$run" test.end "$status" "$reason" "$test_id" "$message"
  done
}

# Derive the overall run status/reason from a validated result. A pass requires
# every required test reported and all reported statuses PASS; any failure or
# incomplete coverage degrades honestly and never becomes a pass.
driver_run_outcome() {
  local result=$1 required=$2
  jq -r --argjson required "$required" '
    .results as $r
    | ([$r[].test_id] | unique) as $reported
    | ([$required[] | select(. as $t | ($reported | index($t)) == null)] | length == 0) as $full
    | if any($r[]; .status == "INFRA_ERROR")   then "INFRA_ERROR DRIVER_TEST_INFRA_ERROR"
      elif any($r[]; .status == "TEST_FAIL")   then "TEST_FAIL DRIVER_TEST_FAILED"
      elif any($r[]; .status == "UNSUPPORTED") then "UNSUPPORTED DRIVER_TEST_UNSUPPORTED"
      elif any($r[]; .status == "INCOMPLETE")  then "INCOMPLETE DRIVER_TEST_INCOMPLETE"
      elif ($full and all($r[]; .status == "PASS")) then "PASS DRIVER_TESTS_PASSED"
      else "INCOMPLETE DRIVER_INCOMPLETE_COVERAGE" end
  ' "$result"
}

# Run one lane driver end to end and echo the run "STATUS REASON". Drivers speak
# only through the bounded result file; the runner keeps sole event authority.
execute_driver_lane() {
  local run=$1 driver_path=$2 scratch result required rc sandbox_verified
  ensure_private_directory "$run/transient/driver"
  scratch="$run/transient/driver/scratch"
  sandbox_verified="$run/transient/driver/sandbox-status.verified"
  ensure_private_directory "$scratch"
  result="$scratch/result.json"
  rm -f -- "$result"
  set +e
  invoke_driver "$run" "$driver_path" "$scratch"
  rc=$?
  set -e
  if [[ ! -f $sandbox_verified || -L $sandbox_verified \
    || $(<"$sandbox_verified") != verified ]]; then
    printf '%s %s\n' INCOMPLETE SANDBOX_TEARDOWN_UNVERIFIED
    return 0
  fi
  if (( rc != 0 )); then
    printf '%s %s\n' INFRA_ERROR DRIVER_EXECUTION_FAILED
    return 0
  fi
  if ! retain_guest_events_artifact "$run" "$scratch"; then
    printf '%s %s\n' INFRA_ERROR GUEST_EVENTS_RETENTION_FAILED
    return 0
  fi
  required=$(required_tests_json "$(run_metadata_field "$run" '.suite')")
  # lane.artifacts is runner-owned: run_command emits its terminal after
  # verify_lane_artifacts, so the driver neither reports it nor owes coverage.
  required=$(jq -c 'map(select(. != "lane.artifacts"))' <<<"$required")
  if ! validate_driver_result "$result" "$required"; then
    printf '%s %s\n' INFRA_ERROR DRIVER_RESULT_INVALID
    return 0
  fi
  ingest_driver_result "$run" "$result"
  driver_run_outcome "$result" "$required"
}

run_command() {
  local run_id='' root_requested root run token marker driver completed=false status reason exit_code
  local suite driver_path resolve_rc outcome
  root_requested=$(default_evidence_root)
  while (( $# > 0 )); do
    case "$1" in
      --run) run_id=${2:-}; shift 2 ;;
      --evidence-root) root_requested=${2:-}; shift 2 ;;
      *) log "unknown run argument: $1"; return "$EXIT_USAGE" ;;
    esac
  done
  root=$(ensure_evidence_root "$root_requested" development) || return $?
  run=$(run_path "$root" "$run_id") || return $?
  assert_run_directory "$run" "$root" || return $?
  [[ -f $run/RUNNING ]] || { log "INFRA_ERROR: run is already finalized"; return "$EXIT_INFRA_ERROR"; }
  suite=$(run_metadata_field "$run" '.suite')
  token=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
  marker="$run/transient/markers/orchestrator"
  printf '%s\n' "$token" >"$marker"
  chmod 0600 "$marker"
  record_process "$run" orchestrator "$$" "$marker" "$token"

  on_run_exit() {
    local rc=$?
    if [[ $completed != true && -f $run/RUNNING ]]; then
      rm -f -- "$run/meta/process-orchestrator.json"
      fill_missing_test_terminals "$run" INCOMPLETE ORCHESTRATOR_INTERRUPTED || true
      cleanup_for_finalization "$run" || true
      finish_run "$run" INCOMPLETE ORCHESTRATOR_INTERRUPTED || true
    fi
    return "$rc"
  }
  trap on_run_exit EXIT INT TERM HUP

  set +e
  verify_lane_artifacts "$run"
  exit_code=$?
  set -e
  if (( exit_code != 0 )); then
    if (( exit_code == EXIT_INCOMPLETE )); then
      status=INCOMPLETE
      reason=ARTIFACT_INTERFACE_UNAVAILABLE
    else
      status=INFRA_ERROR
      reason=ARTIFACT_VERIFICATION_FAILED
    fi
    if required_test_contains "$suite" lane.artifacts; then
      emit_event "$run" test.end "$status" "$reason" lane.artifacts
    fi
    fill_missing_test_terminals "$run" NOT_MEASURED "$reason"
    rm -f -- "$run/meta/process-orchestrator.json"
    if ! cleanup_for_finalization "$run"; then
      status=INCOMPLETE
      reason=CLEANUP_IDENTITY_MISMATCH
    fi
    finish_run "$run" "$status" "$reason"
    completed=true
    trap - EXIT INT TERM HUP
    return "$(status_exit_code "$status")"
  fi

  if required_test_contains "$suite" lane.artifacts; then
    emit_event "$run" test.end PASS ARTIFACTS_VERIFIED lane.artifacts
  fi
  driver=$(run_metadata_field "$run" '.lane.driver')
  if [[ -z $driver ]]; then
    status=NOT_MEASURED
    reason=LANE_NOT_PROVISIONED
    fill_missing_test_terminals "$run" NOT_MEASURED "$reason"
  elif [[ $(run_metadata_field "$run" '.qualification') == qualification ]] && lane_is_development_only "$run"; then
    # Qualification refuses the development-only lane before any driver runs.
    status=UNSUPPORTED
    reason=DEVELOPMENT_LANE_REFUSED
    fill_missing_test_terminals "$run" UNSUPPORTED "$reason"
  else
    set +e
    driver_path=$(resolve_driver "$driver")
    resolve_rc=$?
    set -e
    if (( resolve_rc != 0 )); then
      status=INFRA_ERROR
      reason=DRIVER_UNRESOLVED
      fill_missing_test_terminals "$run" NOT_MEASURED "$reason"
    else
      outcome=$(execute_driver_lane "$run" "$driver_path")
      status=${outcome%% *}
      reason=${outcome#* }
      if [[ -z $status || $status == "$reason" ]]; then
        status=INCOMPLETE
        reason=DRIVER_OUTCOME_UNREADABLE
      fi
      fill_missing_test_terminals "$run" NOT_MEASURED DRIVER_DID_NOT_REPORT
    fi
  fi
  rm -f -- "$run/meta/process-orchestrator.json"
  if ! cleanup_for_finalization "$run"; then
    status=INCOMPLETE
    reason=CLEANUP_IDENTITY_MISMATCH
  fi
  finish_run "$run" "$status" "$reason"
  completed=true
  trap - EXIT INT TERM HUP
  return "$(status_exit_code "$status")"
}

recover_stale_run() {
  local run=$1 record
  [[ -f $run/RUNNING ]] || return 0
  record="$run/meta/process-orchestrator.json"
  if [[ -f $record ]] && process_record_matches "$record" "$run"; then
    return 1
  fi
  rm -f -- "$record"
  fill_missing_test_terminals "$run" INCOMPLETE ORCHESTRATOR_NOT_LIVE
  cleanup_for_finalization "$run" || true
  finish_run "$run" INCOMPLETE ORCHESTRATOR_NOT_LIVE
  return 0
}

collect_command() {
  local run_id='' root_requested root run status
  root_requested=$(default_evidence_root)
  while (( $# > 0 )); do
    case "$1" in
      --run) run_id=${2:-}; shift 2 ;;
      --evidence-root) root_requested=${2:-}; shift 2 ;;
      *) log "unknown collect argument: $1"; return "$EXIT_USAGE" ;;
    esac
  done
  root=$(ensure_evidence_root "$root_requested" development) || return $?
  run=$(run_path "$root" "$run_id") || return $?
  assert_run_directory "$run" "$root" || return $?
  if [[ -f $run/RUNNING ]]; then
    if ! recover_stale_run "$run"; then
      log "INCOMPLETE: run orchestrator is still live; refusing concurrent collection"
      return "$EXIT_INCOMPLETE"
    fi
  fi
  collect_outputs "$run"
  status=$(jq -er '.status' "$run/manifest.json")
  return "$(status_exit_code "$status")"
}

verify_inventory() {
  local run=$1 path expected_size expected_hash actual_size actual_hash
  while IFS=$'\t' read -r path expected_size expected_hash; do
    [[ $path != /* && $path != *'..'* ]] || return 1
    [[ -f $run/$path && ! -L $run/$path ]] || return 1
    actual_size=$(stat -c '%s' -- "$run/$path")
    [[ $actual_size == "$expected_size" ]] || return 1
    actual_hash=$(sha256_file "$run/$path")
    [[ $actual_hash == "$expected_hash" ]] || return 1
  done < <(jq -r '.files[] | [.path,.size,.sha256] | @tsv' "$run/manifest.json")
}

verify_manifest_shape() {
  local run=$1
  jq -e --arg schema "$MANIFEST_SCHEMA" --argjson version "$MANIFEST_SCHEMA_VERSION" '
    .schema == $schema
    and .schema_version == $version
    and (.run_id | type == "string")
    and (.lane_id | type == "string")
    and (.suite | type == "string")
    and (.qualification | IN("development","qualification"))
    and (.status | IN("PASS","TEST_FAIL","INFRA_ERROR","UNSUPPORTED","INCOMPLETE","UNQUALIFIED_DIRTY_SOURCE","NOT_MEASURED"))
    and (.reason_code | type == "string" and test("^[A-Z][A-Z0-9_]{0,63}$"))
    and (.started_at | type == "string")
    and (.ended_at | type == "string")
    and (.event_sha256 | test("^[0-9a-f]{64}$"))
    and (.required_tests | type == "array" and length > 0)
    and (.files | type == "array" and length > 0)
    and (all(.files[];
      (.path | type == "string" and startswith("/") | not)
      and (.size | type == "number" and . >= 0)
      and (.sha256 | test("^[0-9a-f]{64}$"))
      and (.privacy | IN("private-raw","sanitized","metadata"))))
  ' "$run/manifest.json" >/dev/null
}

verify_run_directory() {
  local run=$1 manifest_hash expected_manifest_hash required expected_required event_hash status
  local start_time end_time reason run_id lane_id suite event_run_id event_lane_id
  [[ -f $run/manifest.json && -f $run/manifest.sha256 ]] || return "$EXIT_INCOMPLETE"
  [[ ! -e $run/RUNNING ]] || return "$EXIT_INCOMPLETE"
  expected_manifest_hash=$(tr -d ' \n' <"$run/manifest.sha256")
  manifest_hash=$(sha256_file "$run/manifest.json")
  [[ $manifest_hash == "$expected_manifest_hash" ]] || return "$EXIT_INCOMPLETE"
  verify_manifest_shape "$run" || return "$EXIT_INCOMPLETE"
  verify_inventory "$run" || return "$EXIT_INCOMPLETE"
  event_hash=$(sha256_file "$run/sanitized/events.jsonl")
  [[ $event_hash == "$(jq -er '.event_sha256' "$run/manifest.json")" ]] || return "$EXIT_INCOMPLETE"

  run_id=$(jq -er '.run_id' "$run/manifest.json")
  lane_id=$(jq -er '.lane_id' "$run/manifest.json")
  suite=$(jq -er '.suite' "$run/manifest.json")
  [[ $run_id == "$(basename "$run")" ]] || return "$EXIT_INCOMPLETE"
  [[ $run_id == "$(run_metadata_field "$run" '.run_id')" ]] || return "$EXIT_INCOMPLETE"
  [[ $lane_id == "$(run_metadata_field "$run" '.lane_id')" ]] || return "$EXIT_INCOMPLETE"
  [[ $suite == "$(run_metadata_field "$run" '.suite')" ]] || return "$EXIT_INCOMPLETE"
  if [[ $suite == capacity-preflight ]]; then
    [[ -f $run/raw/guest-events.jsonl && ! -L $run/raw/guest-events.jsonl ]] \
      || return "$EXIT_INCOMPLETE"
    jq -e '[.files[] | select(.path == "raw/guest-events.jsonl")] | length == 1' \
      "$run/manifest.json" >/dev/null || return "$EXIT_INCOMPLETE"
  fi

  required=$(jq -S -c '.required_tests' "$run/manifest.json")
  expected_required=$(required_tests_json "$suite" | jq -S -c .) || return "$EXIT_INCOMPLETE"
  [[ $required == "$expected_required" ]] || return "$EXIT_INCOMPLETE"
  validate_events "$run/sanitized/events.jsonl" "$required" || return "$EXIT_INCOMPLETE"
  event_run_id=$(jq -sr '.[0].run_id' "$run/sanitized/events.jsonl")
  event_lane_id=$(jq -sr '.[0].lane_id' "$run/sanitized/events.jsonl")
  [[ $event_run_id == "$run_id" && $event_lane_id == "$lane_id" ]] || return "$EXIT_INCOMPLETE"

  start_time=$(jq -sr '[.[] | select(.event == "run.start")][0].time' "$run/sanitized/events.jsonl")
  end_time=$(jq -sr '[.[] | select(.event == "run.end")][0].time' "$run/sanitized/events.jsonl")
  [[ $start_time == "$(jq -er '.started_at' "$run/manifest.json")" ]] || return "$EXIT_INCOMPLETE"
  [[ $end_time == "$(jq -er '.ended_at' "$run/manifest.json")" ]] || return "$EXIT_INCOMPLETE"
  status=$(jq -er '.status' "$run/manifest.json")
  reason=$(jq -er '.reason_code' "$run/manifest.json")
  [[ $status == "$(jq -sr '[.[] | select(.event == "run.end")][0].status' "$run/sanitized/events.jsonl")" ]] \
    || return "$EXIT_INCOMPLETE"
  [[ $reason == "$(jq -sr '[.[] | select(.event == "run.end")][0].reason_code' "$run/sanitized/events.jsonl")" ]] \
    || return "$EXIT_INCOMPLETE"
  if [[ $status == INCOMPLETE ]]; then
    [[ -f $run/INCOMPLETE && ! -e $run/COMPLETE ]] || return "$EXIT_INCOMPLETE"
  else
    [[ -f $run/COMPLETE && ! -e $run/INCOMPLETE ]] || return "$EXIT_INCOMPLETE"
  fi
  status_exit_code "$status"
}

verify_run_command() {
  local run_id='' root_requested root run exit_code
  root_requested=$(default_evidence_root)
  while (( $# > 0 )); do
    case "$1" in
      --run) run_id=${2:-}; shift 2 ;;
      --evidence-root) root_requested=${2:-}; shift 2 ;;
      *) log "unknown verify-run argument: $1"; return "$EXIT_USAGE" ;;
    esac
  done
  root=$(ensure_evidence_root "$root_requested" development) || return $?
  run=$(run_path "$root" "$run_id") || return $?
  assert_run_directory "$run" "$root" || return $?
  if [[ -f $run/RUNNING ]]; then
    recover_stale_run "$run" || {
      log "INCOMPLETE: run is still active"
      return "$EXIT_INCOMPLETE"
    }
  fi
  set +e
  exit_code=$(verify_run_directory "$run")
  local verify_rc=$?
  set -e
  if (( verify_rc != 0 )); then
    log "INCOMPLETE: retained evidence failed integrity or schema verification"
    return "$EXIT_INCOMPLETE"
  fi
  printf '%s\n' "$(jq -c '{run_id,lane_id,status,reason_code,manifest_sha256:$manifest_sha256}' \
    --arg manifest_sha256 "$(sha256_file "$run/manifest.json")" "$run/manifest.json")"
  return "$exit_code"
}

destroy_command() {
  local run_id='' root_requested root run
  root_requested=$(default_evidence_root)
  while (( $# > 0 )); do
    case "$1" in
      --run) run_id=${2:-}; shift 2 ;;
      --evidence-root) root_requested=${2:-}; shift 2 ;;
      *) log "unknown destroy argument: $1"; return "$EXIT_USAGE" ;;
    esac
  done
  root=$(ensure_evidence_root "$root_requested" development) || return $?
  run=$(run_path "$root" "$run_id") || return $?
  assert_run_directory "$run" "$root" || return $?
  destroy_run_transients "$run"
}

status_command() {
  local run_id='' root_requested root run state status reason
  root_requested=$(default_evidence_root)
  while (( $# > 0 )); do
    case "$1" in
      --run) run_id=${2:-}; shift 2 ;;
      --evidence-root) root_requested=${2:-}; shift 2 ;;
      *) log "unknown status argument: $1"; return "$EXIT_USAGE" ;;
    esac
  done
  root=$(ensure_evidence_root "$root_requested" development) || return $?
  if [[ -n $run_id ]]; then
    run=$(run_path "$root" "$run_id") || return $?
    assert_run_directory "$run" "$root" || return $?
    if [[ -f $run/RUNNING ]]; then
      if recover_stale_run "$run"; then state=INCOMPLETE; else state=RUNNING; fi
    elif [[ -f $run/COMPLETE ]]; then state=COMPLETE
    elif [[ -f $run/INCOMPLETE ]]; then state=INCOMPLETE
    else state=INCOMPLETE
    fi
    if [[ -f $run/manifest.json ]]; then
      status=$(jq -er '.status' "$run/manifest.json")
      reason=$(jq -er '.reason_code' "$run/manifest.json")
    else
      status=$state
      reason=NOT_FINALIZED
    fi
    jq -n -c --arg run_id "$run_id" --arg state "$state" --arg status "$status" \
      --arg reason_code "$reason" '{run_id:$run_id,state:$state,status:$status,reason_code:$reason_code}'
    if [[ $status == RUNNING ]]; then
      return 0
    fi
    return "$(status_exit_code "$status")"
  fi
  for run in "$root"/*; do
    [[ -d $run && ! -L $run ]] || continue
    status_command --run "$(basename "$run")" --evidence-root "$root" || true
  done
}

main() {
  local command=${1:-}
  [[ -n $command ]] || { usage; return "$EXIT_USAGE"; }
  shift || true
  require_tool jq
  require_tool sha256sum
  require_tool realpath
  require_tool stat
  require_tool find
  require_tool perl
  case "$command" in
    prepare) prepare_command "$@" ;;
    run) run_command "$@" ;;
    collect) collect_command "$@" ;;
    verify-run) verify_run_command "$@" ;;
    destroy) destroy_command "$@" ;;
    status) status_command "$@" ;;
    -h|--help|help) usage ;;
    *) usage; return "$EXIT_USAGE" ;;
  esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  main "$@"
fi
