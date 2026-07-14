#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
# SPDX-License-Identifier: Apache-2.0

# Guest-side, non-secret Phase 1 foundation checks. This script never disables an
# LSM, changes runtime policy, reads environments, or emits raw runtime payloads.

set -euo pipefail
IFS=$'\n\t'
umask 077

readonly SCHEMA="basil.compose.phase1.event"
readonly SCHEMA_VERSION=1
readonly EXIT_TEST_FAIL=10
readonly EXIT_INFRA_ERROR=20
readonly EXIT_UNSUPPORTED=30
readonly EXIT_NOT_MEASURED=60

usage() {
  printf '%s\n' \
    'Usage: common.sh preflight --lane LANE --run-id RUN_ID --events FILE [--sequence-start N]' >&2
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'missing required guest tool: %s\n' "$1" >&2
    return "$EXIT_INFRA_ERROR"
  }
}

validate_id() {
  [[ $1 =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]{0,95}$ ]]
}

utc_now() {
  date -u '+%Y-%m-%dT%H:%M:%SZ'
}

emit_event() {
  local event=$1 status=$2 reason=$3 test_id=$4 details=${5:-'{}'} temporary
  sequence=$((sequence + 1))
  temporary="${events}.tmp.$$"
  jq -e 'type == "object"' <<<"$details" >/dev/null
  jq -n -c \
    --arg schema "$SCHEMA" --argjson schema_version "$SCHEMA_VERSION" \
    --arg run_id "$run_id" --arg lane_id "$lane" --argjson seq "$sequence" \
    --arg time "$(utc_now)" --arg event "$event" --arg status "$status" \
    --arg reason_code "$reason" --arg test_id "$test_id" --argjson details "$details" \
    '{schema:$schema,schema_version:$schema_version,run_id:$run_id,lane_id:$lane_id,
      seq:$seq,time:$time,event:$event,status:$status,reason_code:$reason_code,
      test_id:$test_id,details:$details}' >"$temporary"
  chmod 0600 "$temporary"
  cat -- "$temporary" >>"$events"
  rm -f -- "$temporary"
}

check_cgroup_v2() {
  local filesystem
  filesystem=$(stat -fc '%T' /sys/fs/cgroup 2>/dev/null || true)
  if [[ $filesystem == cgroup2fs ]]; then
    emit_event test.end PASS CGROUP_V2_PRESENT lane.cgroup-v2 \
      "$(jq -n -c --arg filesystem "$filesystem" '{filesystem:$filesystem}')"
    return 0
  fi
  emit_event test.end TEST_FAIL CGROUP_V2_ABSENT lane.cgroup-v2 \
    "$(jq -n -c --arg filesystem "$filesystem" '{filesystem:$filesystem}')"
  return "$EXIT_TEST_FAIL"
}

check_fedora() {
  local enforcement rootless selinux runtime_version failed=0
  require_tool getenforce || return $?
  require_tool podman || return $?
  enforcement=$(getenforce)
  if [[ $enforcement == Enforcing ]]; then
    emit_event test.end PASS SELINUX_ENFORCING lane.lsm-enforcing \
      "$(jq -n -c --arg mode "$enforcement" '{kind:"selinux",mode:$mode}')"
  else
    emit_event test.end TEST_FAIL SELINUX_NOT_ENFORCING lane.lsm-enforcing \
      "$(jq -n -c --arg mode "$enforcement" '{kind:"selinux",mode:$mode}')"
    failed=1
  fi
  rootless=$(podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null || true)
  selinux=$(podman info --format '{{.Host.Security.SELinuxEnabled}}' 2>/dev/null || true)
  runtime_version=$(podman version --format '{{.Client.Version}}' 2>/dev/null || true)
  if [[ $rootless == true && $selinux == true && -n $runtime_version ]]; then
    emit_event test.end PASS PODMAN_ROOTLESS_SELINUX lane.runtime-mode \
      "$(jq -n -c --arg runtime podman --arg version "$runtime_version" \
        --argjson rootless true --argjson selinux true \
        '{runtime:$runtime,version:$version,rootless:$rootless,selinux:$selinux}')"
  else
    emit_event test.end TEST_FAIL PODMAN_MODE_MISMATCH lane.runtime-mode \
      "$(jq -n -c --arg runtime podman --arg version "$runtime_version" \
        --arg rootless "$rootless" --arg selinux "$selinux" \
        '{runtime:$runtime,version:$version,rootless:$rootless,selinux:$selinux}')"
    failed=1
  fi
  (( failed == 0 ))
}

check_ubuntu() {
  local apparmor server_version security failed=0
  require_tool docker || return $?
  if [[ -r /sys/module/apparmor/parameters/enabled ]]; then
    apparmor=$(tr -d '\n' </sys/module/apparmor/parameters/enabled)
  else
    apparmor=missing
  fi
  if [[ $apparmor == Y ]]; then
    emit_event test.end PASS APPARMOR_ENABLED lane.lsm-enforcing \
      "$(jq -n -c --arg mode "$apparmor" '{kind:"apparmor",kernel_enabled:$mode}')"
  else
    emit_event test.end TEST_FAIL APPARMOR_NOT_ENABLED lane.lsm-enforcing \
      "$(jq -n -c --arg mode "$apparmor" '{kind:"apparmor",kernel_enabled:$mode}')"
    failed=1
  fi
  server_version=$(docker version --format '{{.Server.Version}}' 2>/dev/null || true)
  security=$(docker info --format '{{json .SecurityOptions}}' 2>/dev/null || printf '[]')
  if ! jq -e 'type == "array"' <<<"$security" >/dev/null 2>&1; then
    security='[]'
  fi
  if [[ -n $server_version ]] && jq -e '
      any(.[]; contains("name=apparmor"))
      and (all(.[]; contains("name=userns") | not))
    ' <<<"$security" >/dev/null; then
    emit_event test.end PASS DOCKER_ROOTFUL_APPARMOR lane.runtime-mode \
      "$(jq -n -c --arg runtime docker --arg version "$server_version" \
        '{runtime:$runtime,version:$version,userns_remap:false,apparmor:true}')"
  else
    emit_event test.end TEST_FAIL DOCKER_MODE_MISMATCH lane.runtime-mode \
      "$(jq -n -c --arg runtime docker --arg version "$server_version" \
        '{runtime:$runtime,version:$version}')"
    failed=1
  fi
  (( failed == 0 ))
}

preflight() {
  local cgroup_rc=0 lane_rc=0
  check_cgroup_v2 || cgroup_rc=$?
  case "$lane" in
    fedora-44-x86_64) check_fedora || lane_rc=$? ;;
    ubuntu-24.04-x86_64) check_ubuntu || lane_rc=$? ;;
    ubuntu-24.04-aarch64)
      emit_event test.end NOT_MEASURED FUNCTIONAL_LANE_RUNTIME_NOT_PROVISIONED lane.lsm-enforcing
      emit_event test.end NOT_MEASURED FUNCTIONAL_LANE_RUNTIME_NOT_PROVISIONED lane.runtime-mode
      lane_rc=$EXIT_NOT_MEASURED
      ;;
    *)
      emit_event test.end UNSUPPORTED UNKNOWN_LANE lane.lsm-enforcing
      emit_event test.end UNSUPPORTED UNKNOWN_LANE lane.runtime-mode
      lane_rc=$EXIT_UNSUPPORTED
      ;;
  esac
  (( cgroup_rc == 0 )) || return "$cgroup_rc"
  return "$lane_rc"
}

main() {
  local command=${1:-}
  lane=''
  run_id=''
  events=''
  sequence=0
  [[ $command == preflight ]] || { usage; return 64; }
  shift
  while (( $# > 0 )); do
    case "$1" in
      --lane) lane=${2:-}; shift 2 ;;
      --run-id) run_id=${2:-}; shift 2 ;;
      --events) events=${2:-}; shift 2 ;;
      --sequence-start) sequence=${2:-}; shift 2 ;;
      *) usage; return 64 ;;
    esac
  done
  if ! validate_id "$lane" || ! validate_id "$run_id"; then
    usage
    return 64
  fi
  [[ $events = /* && $sequence =~ ^[0-9]+$ ]] || { usage; return 64; }
  require_tool jq
  require_tool stat
  mkdir -p -- "$(dirname "$events")"
  chmod 0700 -- "$(dirname "$events")"
  touch -- "$events"
  chmod 0600 -- "$events"
  preflight
}

main "$@"
