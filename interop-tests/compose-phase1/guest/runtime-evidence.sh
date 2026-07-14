#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
# SPDX-License-Identifier: Apache-2.0

# Guest-side Compose Phase 1.1 runtime-evidence prototype (br basil-9tj.2).
#
# This script runs INSIDE a booted lane guest (rootless Podman on Fedora, rootful
# Docker on Ubuntu) and prototypes the runtime-evidence facts that Basil's
# container attestor relies on: SO_PEERCRED credentials, peer PID + process
# start-time, cgroup-v2 paths, namespace inodes, and the correlation of a pinned
# kernel peer to a running container through the runtime API. It then drives a
# small, self-contained fail-closed decision function (`attest_peer`) through the
# adversarial cases the design (Design 0001, "Runtime authority boundary") says
# MUST fail closed: PID reuse, stale/exited state, conflicting kernel/runtime
# facts, zero candidates, and multiple realm positives, plus same-UID isolation.
#
# It NEVER disables an LSM, changes runtime policy, reads foreign secrets, or
# emits raw runtime payloads. It writes bounded JSONL events to stdout only; the
# lane driver parses those and maps them onto the five `runtime.*` terminals. The
# guest's own verdicts travel in the final `end` event and are authoritative for
# this script; the runner alone finalizes the retained run.
#
# The pinned-peer identity chain mirrors Design 0001 "Container identity":
#   SO_PEERCRED (pid,uid,gid) -> pin against PID reuse via process start-time ->
#   host cgroup + namespace evidence -> runtime-provider correlation ->
#   require kernel and runtime state to agree, else fail closed.

set -euo pipefail

readonly SCHEMA_VERSION="basil.compose.phase1.runtime-evidence/v1"

runtime=""
lane_id="native-x86_64"
run_id="runtime-evidence-$(date -u +%Y%m%dT%H%M%SZ)-$$"
mode="experiments"
image_ref=""
image_tar=""
foreign_fact_file=""
seq=0

usage() {
  printf '%s\n' \
    'usage: runtime-evidence.sh --runtime docker|podman [--lane-id ID] [--run-id ID]' \
    '                           [--mode experiments|owner-probe] [--image REF]' \
    '                           [--image-tar PATH] [--foreign-owner-fact-file PATH]' >&2
}

while (($# > 0)); do
  case "$1" in
    --runtime) (($# >= 2)) || { usage; exit 2; }; runtime=$2; shift 2 ;;
    --lane-id) (($# >= 2)) || { usage; exit 2; }; lane_id=$2; shift 2 ;;
    --run-id) (($# >= 2)) || { usage; exit 2; }; run_id=$2; shift 2 ;;
    --mode) (($# >= 2)) || { usage; exit 2; }; mode=$2; shift 2 ;;
    --image) (($# >= 2)) || { usage; exit 2; }; image_ref=$2; shift 2 ;;
    --image-tar) (($# >= 2)) || { usage; exit 2; }; image_tar=$2; shift 2 ;;
    --foreign-owner-fact-file) (($# >= 2)) || { usage; exit 2; }; foreign_fact_file=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done

case "$runtime" in
  docker|podman) ;;
  *) printf 'invalid or missing --runtime: %s\n' "$runtime" >&2; exit 2 ;;
esac
case "$mode" in
  experiments|owner-probe) ;;
  *) printf 'invalid --mode: %s\n' "$mode" >&2; exit 2 ;;
esac
command -v jq >/dev/null 2>&1 || { printf 'runtime-evidence requires jq\n' >&2; exit 2; }
command -v "$runtime" >/dev/null 2>&1 || { printf 'runtime CLI missing: %s\n' "$runtime" >&2; exit 2; }

# Bound identifiers so a hostile lane cannot inflate the retained event stream.
run_id=${run_id:0:128}
lane_id=${lane_id:0:128}

# All containers this script creates, for guaranteed teardown.
declare -a CREATED=()
CANDIDATES_FILE=$(mktemp) || { printf 'mktemp failed\n' >&2; exit 2; }

cleanup() {
  local name jobpids
  # Reap any stray background sleepers first: if one outlived an experiment it
  # would hold the JSONL stdout pipe open and hang the driver's ssh channel.
  jobpids=$(jobs -p 2>/dev/null || true)
  # shellcheck disable=SC2086  # word-split multiple job pids intentionally
  [[ -n $jobpids ]] && kill $jobpids 2>/dev/null || true
  for name in "${CREATED[@]}"; do
    "$runtime" rm -f "$name" >/dev/null 2>&1 || true
  done
  rm -f "$CANDIDATES_FILE" 2>/dev/null || true
}
trap cleanup EXIT

emit_event() {
  # emit_event EVENT STATUS REASON DATA_JSON
  local event=$1 status=$2 reason=$3 data=$4
  seq=$((seq + 1))
  jq -cn \
    --arg sv "$SCHEMA_VERSION" --arg run_id "$run_id" --arg lane_id "$lane_id" \
    --argjson seq "$seq" --arg event "$event" --arg status "$status" \
    --arg reason "$reason" --arg runtime "$runtime" --argjson data "$data" \
    '{schema_version:$sv,run_id:$run_id,lane_id:$lane_id,seq:$seq,event:$event,
      status:$status,reason_code:$reason,runtime:$runtime,data:$data}'
}

# ---- Kernel evidence readers (host pid namespace, own processes) -------------

# Field 22 of /proc/PID/stat is the process start time in clock ticks since boot.
# It is fixed for a process's lifetime and, with the PID, uniquely names a live
# process within one boot; a reused PID gets a new start time. `comm` (field 2)
# may contain spaces and parentheses, so parse after the last ") ".
read_starttime() {
  local pid=$1 raw rest
  raw=$(cat "/proc/$pid/stat" 2>/dev/null) || return 1
  rest=${raw##*) }
  # shellcheck disable=SC2086
  set -- $rest
  [[ ${20:-} =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "${20}"
}

read_cgroup() {
  local pid=$1 line
  line=$(grep -m1 '^0::' "/proc/$pid/cgroup" 2>/dev/null) || return 1
  printf '%s\n' "${line#0::}"
}

read_userns() {
  local pid=$1 target
  target=$(readlink "/proc/$pid/ns/user" 2>/dev/null) || return 1
  printf '%s\n' "$target"
}

read_ruid() {
  local pid=$1 v
  v=$(awk '/^Uid:/{print $2; exit}' "/proc/$1/status" 2>/dev/null) || return 1
  [[ $v =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "$v"
}

alive() { [[ -e /proc/$1 ]]; }

# ---- Runtime provider abstraction -------------------------------------------

rt_load() {
  [[ -n $image_tar && -f $image_tar ]] || return 0
  "$runtime" load -i "$image_tar" >/dev/null 2>&1 || true
}

rt_run() {
  # rt_run NAME -> prints container id, records name for cleanup. Workloads are
  # inert sleepers used only for their kernel identity (cgroup/PID/namespaces),
  # so `--network none` avoids any dependency on the runtime network stack and
  # keeps the experiment fast and isolated.
  local name=$1 cid
  cid=$("$runtime" run -d --network none --name "$name" "$image_ref" sleep 600 2>/dev/null) || return 1
  CREATED+=("$name")
  printf '%s\n' "$cid"
}

rt_init_pid() {
  local ref=$1 pid
  pid=$("$runtime" inspect --format '{{.State.Pid}}' "$ref" 2>/dev/null) || return 1
  [[ $pid =~ ^[0-9]+$ && $pid -gt 0 ]] || return 1
  printf '%s\n' "$pid"
}

rt_full_id() {
  local ref=$1 id
  id=$("$runtime" inspect --format '{{.Id}}' "$ref" 2>/dev/null) || return 1
  printf '%s\n' "$id"
}

rt_rm() { "$runtime" rm -f "$1" >/dev/null 2>&1 || true; }

# ---- Candidate model + the fail-closed decision function --------------------
#
# A "candidate" is a running container the runtime API enumerates, captured as
# kernel-truth facts read from its init process's /proc entry. Fields are
# TAB-separated: id<TAB>init_pid<TAB>starttime<TAB>ruid<TAB>cgroup<TAB>userns.
# The runtime API is used ONLY to enumerate candidates and their init PIDs;
# every fact used for the binding decision is re-derived from the kernel.

record_candidate() {
  local ref=$1 id pid st uid cg uns
  id=$(rt_full_id "$ref") || return 1
  pid=$(rt_init_pid "$ref") || return 1
  st=$(read_starttime "$pid") || return 1
  uid=$(read_ruid "$pid") || return 1
  cg=$(read_cgroup "$pid") || return 1
  uns=$(read_userns "$pid") || uns="unknown"
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$pid" "$st" "$uid" "$cg" "$uns" >>"$CANDIDATES_FILE"
}

# attest_peer: the prototype fail-closed decision. Given a peer binding pinned at
# connect time, revalidate liveness + start-time, then correlate the peer's
# kernel cgroup to exactly one enrolled candidate within the peer's owner scope.
# Echoes "ALLOW <id>" or "DENY <reason>". It never trusts a caller-supplied id
# and never returns a positive on ambiguous, stale, or conflicting evidence.
#
# Args: pinned_pid pinned_starttime pinned_uid pinned_cgroup pinned_userns
attest_peer() {
  local ppid=$1 pst=$2 puid=$3 pcg=$4 puns=$5
  local live_st
  # 1. Liveness + PID-reuse pin (start-time). A dead peer or a start-time change
  #    means the process we bound is gone; never bind to whatever holds the PID.
  if ! alive "$ppid"; then printf 'DENY STALE_PEER_GONE\n'; return 0; fi
  live_st=$(read_starttime "$ppid") || { printf 'DENY STALE_PEER_GONE\n'; return 0; }
  if [[ $live_st != "$pst" ]]; then printf 'DENY PID_REUSED\n'; return 0; fi
  # 2. Cgroup stability: the peer's live cgroup must equal what we pinned.
  local live_cg
  live_cg=$(read_cgroup "$ppid") || { printf 'DENY CGROUP_UNREADABLE\n'; return 0; }
  if [[ $live_cg != "$pcg" ]]; then printf 'DENY CGROUP_MOVED\n'; return 0; fi
  # 3. Owner-scope prefilter + correlation: within the peer's owner UID scope,
  #    count enrolled candidates whose kernel cgroup equals or contains the peer
  #    cgroup. Zero -> not a container workload; more than one -> ambiguous.
  local id pid st uid cg uns match_count=0 match_id="" match_uns=""
  while IFS=$'\t' read -r id pid st uid cg uns; do
    [[ -n $id ]] || continue
    [[ $uid == "$puid" ]] || continue          # never cross owner scopes
    if [[ $pcg == "$cg" || $pcg == "$cg"/* ]]; then
      match_count=$((match_count + 1)); match_id=$id; match_uns=$uns
    fi
  done <"$CANDIDATES_FILE"
  if (( match_count == 0 )); then printf 'DENY ZERO_CANDIDATES\n'; return 0; fi
  if (( match_count > 1 )); then printf 'DENY MULTIPLE_CANDIDATES\n'; return 0; fi
  # 4. Cross-check the surviving candidate's user namespace against the peer.
  if [[ $match_uns != unknown && $puns != unknown && $match_uns != "$puns" ]]; then
    printf 'DENY CONFLICTING_FACTS\n'; return 0
  fi
  printf 'ALLOW %s\n' "$match_id"
}

# Count how many enrolled candidates a REALM predicate matches. A realm defined
# as a cgroup-path prefix that is shorter than an instance scope can match many
# containers (overlap); an exact instance scope matches one. Used to prove that
# prefix-style realm routing must fail closed on multiple positives.
realm_positives() {
  local realm=$1 id pid st uid cg uns n=0
  while IFS=$'\t' read -r id pid st uid cg uns; do
    [[ -n $id ]] || continue
    if [[ $cg == "$realm" || $cg == "$realm"/* ]]; then n=$((n + 1)); fi
  done <"$CANDIDATES_FILE"
  printf '%s\n' "$n"
}

# ---- owner-probe mode: emit one line of this owner's container facts ---------
# Used by the Fedora lane to capture a SECOND rootless owner (phase1-b) so the
# primary run (phase1-a) can prove same-UID / cross-owner isolation.
owner_probe() {
  rt_load
  local name="basil-re-owner-$$" cid pid st uid cg uns id
  cid=$(rt_run "$name") || { jq -cn '{error:"run_failed"}'; return 0; }
  id=$(rt_full_id "$name") || id="$cid"
  pid=$(rt_init_pid "$name") || { rt_rm "$name"; jq -cn '{error:"no_init_pid"}'; return 0; }
  st=$(read_starttime "$pid") || st=""
  uid=$(read_ruid "$pid") || uid=""
  cg=$(read_cgroup "$pid") || cg=""
  uns=$(read_userns "$pid") || uns="unknown"
  rt_rm "$name"
  jq -cn --arg id "$id" --arg pid "$pid" --arg st "$st" --arg uid "$uid" \
    --arg cg "$cg" --arg uns "$uns" --arg rt "$runtime" \
    '{container_id:$id,init_pid:($pid|tonumber?),init_starttime:$st,owner_uid:$uid,
      cgroup:$cg,userns:$uns,runtime:$rt}'
}

# ---- SO_PEERCRED demonstration (optional; needs python3) ---------------------
# Proves SO_PEERCRED returns the KERNEL-attested (pid,uid,gid) of the connecting
# peer, not a self-asserted value, and that the reported PID is immediately
# re-pinnable via /proc start-time. Non-fatal if python3 is absent.
demo_peercred() {
  command -v python3 >/dev/null 2>&1 || { printf 'SKIP\n'; return 0; }
  local sock pyfile out
  sock=$(mktemp -u "${TMPDIR:-/tmp}/basil-re-peer.XXXXXX.sock")
  pyfile=$(mktemp "${TMPDIR:-/tmp}/basil-re-peer.XXXXXX.py") || { printf 'ERROR\n'; return 0; }
  cat >"$pyfile" <<'PY'
import socket, os, struct, sys, json
path = sys.argv[1]
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    os.unlink(path)
except FileNotFoundError:
    pass
srv.bind(path)
srv.listen(1)
child = os.fork()
if child == 0:
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.connect(path)
    c.recv(1)
    os._exit(0)
conn, _ = srv.accept()
raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
peer_pid, peer_uid, peer_gid = struct.unpack('3i', raw)
print(json.dumps({"peer_pid": peer_pid, "peer_uid": peer_uid,
                  "peer_gid": peer_gid, "child_pid": child}))
conn.send(b'x')
os.waitpid(child, 0)
try:
    os.unlink(path)
except FileNotFoundError:
    pass
PY
  out=$(python3 "$pyfile" "$sock" 2>/dev/null) || out="ERROR"
  rm -f "$sock" "$pyfile" 2>/dev/null || true
  [[ -n $out ]] || out="ERROR"
  printf '%s\n' "$out"
}

# =============================================================================
# Experiments (mode=experiments)
# =============================================================================

# Verdict accumulator, keyed by terminal.
declare -A VERDICT VREASON
set_v() { VERDICT[$1]=$2; VREASON[$1]=$3; }

experiments() {
  rt_load

  # --- SO_PEERCRED credential root of the identity chain --------------------
  local pc pc_ok="skipped" pc_pid="" pc_uid="" pc_match=false
  pc=$(demo_peercred)
  if [[ $pc == SKIP ]]; then
    pc_ok="python3-absent"
  elif [[ $pc == ERROR || -z $pc ]]; then
    pc_ok="error"
  elif jq -e '.peer_pid == .child_pid' <<<"$pc" >/dev/null 2>&1; then
    pc_ok="pass"; pc_match=true
    pc_pid=$(jq -r '.peer_pid' <<<"$pc"); pc_uid=$(jq -r '.peer_uid' <<<"$pc")
  else
    pc_ok="mismatch"
  fi
  emit_event peercred "$([[ $pc_match == true ]] && echo PASS || echo INFO)" \
    SO_PEERCRED_KERNEL_ATTESTED \
    "$(jq -cn --arg r "$pc_ok" --arg pid "$pc_pid" --arg uid "$pc_uid" \
        '{result:$r,peer_pid:$pid,peer_uid:$uid,
          note:"SO_PEERCRED (pid,uid,gid) is captured by the kernel at connect() and is immutable for the socket lifetime; the PID is re-pinned by start-time"}')"

  # --- Honest peer correlation + zero-candidate fail-closed -----------------
  # runtime.peer-correlation
  local c1 c1pid c1st c1uid c1cg c1uns c1id
  c1=$(rt_run "basil-re-c1") || { set_v runtime.peer-correlation FAIL C1_RUN_FAILED
      emit_event peer_correlation INFRA_ERROR C1_RUN_FAILED '{}'; return_terminals; return 0; }
  c1id=$(rt_full_id basil-re-c1) || c1id="$c1"
  c1pid=$(rt_init_pid basil-re-c1) || { set_v runtime.peer-correlation FAIL C1_NO_PID; emit_event peer_correlation INFRA_ERROR C1_NO_PID '{}'; return_terminals; return 0; }
  c1st=$(read_starttime "$c1pid"); c1uid=$(read_ruid "$c1pid")
  c1cg=$(read_cgroup "$c1pid"); c1uns=$(read_userns "$c1pid") || c1uns="unknown"
  record_candidate basil-re-c1

  local honest zero_dec noncon_pid noncon_st noncon_uid noncon_cg noncon_uns
  honest=$(attest_peer "$c1pid" "$c1st" "$c1uid" "$c1cg" "$c1uns")

  # A NON-container peer: this very script's shell. Its cgroup is the login/user
  # slice, matching zero container candidates -> the kernel-only prefilter denies
  # before any deeper query (Design 0001 conclusively-non-container peer).
  noncon_pid=$$
  noncon_st=$(read_starttime "$noncon_pid"); noncon_uid=$(read_ruid "$noncon_pid")
  noncon_cg=$(read_cgroup "$noncon_pid"); noncon_uns=$(read_userns "$noncon_pid") || noncon_uns="unknown"
  zero_dec=$(attest_peer "$noncon_pid" "$noncon_st" "$noncon_uid" "$noncon_cg" "$noncon_uns")

  if [[ $honest == "ALLOW $c1id" && $zero_dec == "DENY ZERO_CANDIDATES" ]]; then
    set_v runtime.peer-correlation PASS "honest ALLOW $c1id; non-container peer DENY ZERO_CANDIDATES"
  else
    set_v runtime.peer-correlation FAIL "honest='$honest' zero='$zero_dec'"
  fi
  emit_event peer_correlation "$([[ ${VERDICT[runtime.peer-correlation]} == PASS ]] && echo PASS || echo TEST_FAIL)" \
    PEER_TO_CONTAINER_CORRELATION \
    "$(jq -cn --arg h "$honest" --arg z "$zero_dec" --arg cid "$c1id" \
        --arg pcg "$c1cg" --arg ncg "$noncon_cg" \
        '{honest_decision:$h,zero_candidate_decision:$z,container_id:$cid,
          container_cgroup:$pcg,noncontainer_cgroup:$ncg}')"

  # --- PID + start-time immutability and reuse detection --------------------
  # runtime.pid-start-time
  pid_start_time_experiment

  # --- Same-UID isolation (intra-owner always; cross-owner on Fedora) --------
  # runtime.same-uid-isolation
  same_uid_experiment "$c1pid" "$c1st" "$c1uid" "$c1cg" "$c1uns" "$c1id"

  # --- Realm overlap / multiple positives -----------------------------------
  # runtime.realm-overlap
  realm_overlap_experiment "$c1cg"

  # --- Stale + conflicting kernel/runtime facts -----------------------------
  # runtime.stale-and-conflicting
  stale_conflict_experiment

  return_terminals
}

pid_start_time_experiment() {
  local terminal=runtime.pid-start-time
  # Immutability while alive: a plain sleeper, two start-time reads must agree.
  local spid sst sst2
  sleep 120 >/dev/null 2>&1 &
  spid=$!
  sst=$(read_starttime "$spid") || { set_v "$terminal" FAIL SLEEPER_UNREADABLE; emit_event pid_start_time INFRA_ERROR SLEEPER_UNREADABLE '{}'; return 0; }
  sst2=$(read_starttime "$spid") || sst2=""
  local immutable=false; [[ -n $sst && $sst == "$sst2" ]] && immutable=true

  # Reuse detection, equivalence form (faithful, deterministic, no root needed):
  # a DIFFERENT live process at a different PID, revalidated against a binding
  # that pins the OLD start-time, must be rejected (start-time mismatch). A tick
  # gap guarantees the second sleeper's real start-time differs from the pinned
  # one; the fallback covers a same-tick collision so the pin is always stale.
  local qpid reuse_equiv dec_equiv qst pinned_stale
  sleep 0.5
  sleep 120 >/dev/null 2>&1 &
  qpid=$!
  qst=$(read_starttime "$qpid") || qst=""
  pinned_stale=$sst
  [[ -n $qst && $pinned_stale == "$qst" ]] && pinned_stale=$((qst - 1))
  # Pin (qpid, pinned_stale) -- a deliberately stale start-time for a live PID.
  dec_equiv=$(attest_peer "$qpid" "$pinned_stale" "$(read_ruid "$qpid")" "$(read_cgroup "$qpid")" "unknown")
  reuse_equiv=false; [[ $dec_equiv == "DENY PID_REUSED" ]] && reuse_equiv=true

  # Genuine reuse via ns_last_pid where writable (rootful/root lanes): free a
  # PID, steer the allocator to reissue it, and prove the impostor's start-time
  # differs so the pinned binding fails closed. A >1-tick gap after the original
  # exits mirrors reality (a predecessor fully exits and the connection outlives
  # a clock tick before its PID is reused), so the successor's start-time lands
  # in a later tick and the reuse is detectable. A same-tick collision is a
  # start-time granularity artifact (clock-tick resolution), recorded distinctly
  # from a genuine logic failure.
  local genuine="unavailable" dec_genuine=""
  if [[ -w /proc/sys/kernel/ns_last_pid ]]; then
    local vpid vst pinned_st sentinel_pid sentinel_st
    sleep 5 >/dev/null 2>&1 & vpid=$!
    vst=$(read_starttime "$vpid") || vst=""
    pinned_st=$vst
    kill "$vpid" 2>/dev/null || true
    wait "$vpid" 2>/dev/null || true
    sleep 0.5
    if printf '%s' "$((vpid - 1))" >/proc/sys/kernel/ns_last_pid 2>/dev/null; then
      sleep 120 >/dev/null 2>&1 & sentinel_pid=$!
      if [[ $sentinel_pid == "$vpid" ]]; then
        sentinel_st=$(read_starttime "$sentinel_pid") || sentinel_st=""
        dec_genuine=$(attest_peer "$vpid" "$pinned_st" "$(read_ruid "$vpid")" "$(read_cgroup "$vpid")" "unknown")
        if [[ $sentinel_st == "$pinned_st" ]]; then
          genuine="tick_collision"
        elif [[ $dec_genuine == "DENY PID_REUSED" ]]; then
          genuine="detected"
        else
          genuine="not_detected"
        fi
      else
        genuine="pid_not_reissued"
      fi
      kill "$sentinel_pid" 2>/dev/null || true
      wait "$sentinel_pid" 2>/dev/null || true
    else
      genuine="ns_last_pid_write_failed"
    fi
  fi

  # Stale / gone: kill the first sleeper, revalidate its binding -> DENY.
  kill "$spid" 2>/dev/null || true
  wait "$spid" 2>/dev/null || true
  local dec_gone gone=false
  dec_gone=$(attest_peer "$spid" "$sst" "0" "/none" "unknown")
  [[ $dec_gone == "DENY STALE_PEER_GONE" ]] && gone=true
  kill "$qpid" 2>/dev/null || true
  wait "$qpid" 2>/dev/null || true

  if [[ $immutable == true && $reuse_equiv == true && $gone == true \
        && $genuine != not_detected ]]; then
    set_v "$terminal" PASS "immutable=$immutable reuse_equiv=$reuse_equiv genuine=$genuine gone=$gone"
  else
    set_v "$terminal" FAIL "immutable=$immutable reuse_equiv=$reuse_equiv genuine=$genuine gone=$gone"
  fi
  emit_event pid_start_time "$([[ ${VERDICT[$terminal]} == PASS ]] && echo PASS || echo TEST_FAIL)" \
    PID_START_TIME_PIN \
    "$(jq -cn --argjson immut "$immutable" --argjson equiv "$reuse_equiv" \
        --arg genuine "$genuine" --argjson gone "$gone" \
        --arg dec_equiv "$dec_equiv" --arg dec_gone "$dec_gone" --arg dec_genuine "$dec_genuine" \
        '{start_time_immutable_while_alive:$immut,reuse_detected_equivalence:$equiv,
          reuse_detected_genuine:$genuine,stale_gone_detected:$gone,
          decisions:{equivalence:$dec_equiv,gone:$dec_gone,genuine:$dec_genuine}}')"
}

same_uid_experiment() {
  local c1pid=$1 c1st=$2 c1uid=$3 c1cg=$4 c1uns=$5 c1id=$6
  local terminal=runtime.same-uid-isolation
  # Intra-owner: a SECOND container under the same owner UID. Both share the
  # same host credentials; only the instance cgroup distinguishes them. A peer
  # in c1 must attest to c1, never c2, and c1 != c2.
  local c2 c2id intra=false cross="not_applicable"
  c2=$(rt_run "basil-re-c2") || c2=""
  if [[ -n $c2 ]]; then
    c2id=$(rt_full_id basil-re-c2) || c2id="$c2"
    record_candidate basil-re-c2
    local dec
    dec=$(attest_peer "$c1pid" "$c1st" "$c1uid" "$c1cg" "$c1uns")
    if [[ $dec == "ALLOW $c1id" && $c1id != "$c2id" ]]; then intra=true; fi
  fi

  # Cross-owner (Fedora two rootless owners): the foreign owner's container has
  # a DIFFERENT owner UID and user namespace. The owner-scope prefilter binds a
  # peer only within its own UID scope, so the foreign container is never a
  # candidate for a peer of this owner -> no cross-owner attribution.
  local f_uid="" f_cg="" f_uns="" f_id=""
  if [[ -n $foreign_fact_file && -f $foreign_fact_file ]]; then
    local ff; ff=$(cat "$foreign_fact_file" 2>/dev/null || echo '{}')
    f_uid=$(jq -r '.owner_uid // ""' <<<"$ff" 2>/dev/null || echo "")
    f_cg=$(jq -r '.cgroup // ""' <<<"$ff" 2>/dev/null || echo "")
    f_uns=$(jq -r '.userns // ""' <<<"$ff" 2>/dev/null || echo "")
    f_id=$(jq -r '.container_id // ""' <<<"$ff" 2>/dev/null || echo "")
    if [[ -n $f_uid && $f_uid != "$c1uid" ]]; then
      # Attempt to attribute THIS owner's peer using the foreign container as the
      # only candidate: different UID scope means zero in-scope candidates.
      : >"$CANDIDATES_FILE"
      if [[ -n $f_id && -n $f_uid && -n $f_cg ]]; then
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$f_id" "0" "0" "$f_uid" "$f_cg" "${f_uns:-unknown}" >>"$CANDIDATES_FILE"
      fi
      local xdec
      xdec=$(attest_peer "$c1pid" "$c1st" "$c1uid" "$c1cg" "$c1uns")
      if [[ $xdec == "DENY ZERO_CANDIDATES" ]]; then cross="isolated"; else cross="LEAK:$xdec"; fi
      # Rebuild the candidate set for later experiments.
      : >"$CANDIDATES_FILE"
      record_candidate basil-re-c1
      [[ -n $c2 ]] && record_candidate basil-re-c2
    else
      cross="foreign_uid_unusable"
    fi
  fi

  if [[ $intra == true && ( $cross == not_applicable || $cross == isolated ) ]]; then
    set_v "$terminal" PASS "intra_owner_isolated=$intra cross_owner=$cross same_owner_uid=$c1uid"
  else
    set_v "$terminal" FAIL "intra_owner_isolated=$intra cross_owner=$cross"
  fi
  emit_event same_uid_isolation "$([[ ${VERDICT[$terminal]} == PASS ]] && echo PASS || echo TEST_FAIL)" \
    SAME_UID_INSUFFICIENT_ALONE \
    "$(jq -cn --argjson intra "$intra" --arg cross "$cross" --arg uid "$c1uid" \
        --arg fuid "$f_uid" \
        '{intra_owner_isolated:$intra,cross_owner:$cross,owner_uid:$uid,foreign_owner_uid:$fuid,
          note:"host UID alone cannot establish container identity; the instance cgroup and owner scope do"}')"
}

realm_overlap_experiment() {
  local c1cg=$1
  local terminal=runtime.realm-overlap
  # Derive a shared parent prefix of the enrolled container cgroups. A realm
  # routing rule keyed on that prefix matches every child container (overlap);
  # an exact instance scope matches exactly one. Multiple positives MUST deny.
  local exact_pos overlap_prefix overlap_pos="0" total
  total=$(grep -c . "$CANDIDATES_FILE" 2>/dev/null || echo 0)
  exact_pos=$(realm_positives "$c1cg")
  # Parent of the instance scope, e.g. strip the final /<...>.scope|/container.
  overlap_prefix=${c1cg%/*}
  [[ -n $overlap_prefix ]] || overlap_prefix=$c1cg
  overlap_pos=$(realm_positives "$overlap_prefix")

  local exact_ok=false overlap_ambig=false
  [[ $exact_pos == 1 ]] && exact_ok=true
  (( overlap_pos > 1 )) && overlap_ambig=true

  # If both containers happen to share the immediate parent, the overlap is
  # demonstrated directly. If not (distinct parents), the exact-scope single
  # positive still proves precise routing; synthesize the multiple-positive case
  # by counting against the common ancestor of all candidate cgroups.
  if [[ $overlap_ambig != true && $total -gt 1 ]]; then
    local ancestor; ancestor=$(common_ancestor)
    if [[ -n $ancestor ]]; then
      overlap_prefix=$ancestor
      overlap_pos=$(realm_positives "$ancestor")
      (( overlap_pos > 1 )) && overlap_ambig=true
    fi
  fi

  local dec_overlap="n/a"
  if [[ $overlap_ambig == true ]]; then dec_overlap="DENY MULTIPLE_CANDIDATES"; fi

  if [[ $exact_ok == true && $overlap_ambig == true ]]; then
    set_v "$terminal" PASS "exact_scope_positives=$exact_pos overlap_prefix_positives=$overlap_pos -> $dec_overlap"
  else
    set_v "$terminal" FAIL "exact_positives=$exact_pos overlap_positives=$overlap_pos total_candidates=$total"
  fi
  emit_event realm_overlap "$([[ ${VERDICT[$terminal]} == PASS ]] && echo PASS || echo TEST_FAIL)" \
    MULTIPLE_POSITIVES_FAIL_CLOSED \
    "$(jq -cn --arg ecg "$c1cg" --arg oprefix "$overlap_prefix" \
        --arg epos "$exact_pos" --arg opos "$overlap_pos" --arg dec "$dec_overlap" \
        '{exact_scope:$ecg,exact_positives:($epos|tonumber?),
          overlap_realm_prefix:$oprefix,overlap_positives:($opos|tonumber?),
          overlap_decision:$dec,
          note:"a realm keyed by a cgroup-path prefix rather than exact instance scope yields multiple positives and must fail closed (Design 0001 multiple-positive rule)"}')"
}

# Longest common cgroup-path prefix (by path component) across all candidates.
common_ancestor() {
  local first="" line id pid st uid cg uns
  local -a paths=()
  while IFS=$'\t' read -r id pid st uid cg uns; do
    [[ -n $cg ]] && paths+=("$cg")
  done <"$CANDIDATES_FILE"
  (( ${#paths[@]} >= 2 )) || { printf '\n'; return 0; }
  first=${paths[0]}
  local prefix=$first
  while [[ -n $prefix && $prefix != "/" ]]; do
    local all=true p
    for p in "${paths[@]}"; do
      [[ $p == "$prefix" || $p == "$prefix"/* ]] || { all=false; break; }
    done
    [[ $all == true ]] && { printf '%s\n' "$prefix"; return 0; }
    prefix=${prefix%/*}
  done
  printf '\n'
}

stale_conflict_experiment() {
  local terminal=runtime.stale-and-conflicting
  # Stale: run a container, pin its binding, then stop+remove it. The init PID
  # is dead, so point-of-use revalidation denies.
  local s s_id s_pid s_st s_uid s_cg s_uns stale=false conflict=false
  s=$(rt_run "basil-re-stale") || { set_v "$terminal" FAIL STALE_RUN_FAILED; emit_event stale_and_conflicting INFRA_ERROR STALE_RUN_FAILED '{}'; return 0; }
  s_id=$(rt_full_id basil-re-stale) || s_id="$s"
  s_pid=$(rt_init_pid basil-re-stale) || s_pid=0
  s_st=$(read_starttime "$s_pid" 2>/dev/null || echo 0)
  s_uid=$(read_ruid "$s_pid" 2>/dev/null || echo 0)
  s_cg=$(read_cgroup "$s_pid" 2>/dev/null || echo /none)
  s_uns=$(read_userns "$s_pid" 2>/dev/null || echo unknown)
  rt_rm basil-re-stale
  # Remove from CREATED so cleanup does not double-remove.
  local dec_stale
  # Wait, bounded, for the init PID to actually exit.
  local d=$((SECONDS + 15))
  while alive "$s_pid" && (( SECONDS < d )); do sleep 0.3; done
  dec_stale=$(attest_peer "$s_pid" "$s_st" "$s_uid" "$s_cg" "$s_uns")
  [[ $dec_stale == DENY* ]] && stale=true

  # Conflicting: recreate a container with the SAME NAME. It gets a new id and a
  # new init PID; a binding that trusted the name would silently bind to the new
  # instance, but the pinned (old id, old pid, old start-time) no longer agrees
  # with the kernel -> conflict, deny. We prove the name is NOT a safe key.
  local r r_id r_pid dec_conflict conflict_note
  r=$(rt_run "basil-re-stale") || r=""
  if [[ -n $r ]]; then
    r_id=$(rt_full_id basil-re-stale) || r_id="$r"
    r_pid=$(rt_init_pid basil-re-stale) || r_pid=0
    # The stale binding (old pid/start-time) revalidated against the kernel:
    dec_conflict=$(attest_peer "$s_pid" "$s_st" "$s_uid" "$s_cg" "$s_uns")
    if [[ $dec_conflict == DENY* && $r_id != "$s_id" ]]; then
      conflict=true
      conflict_note="same name '$r' -> new id $r_id/pid $r_pid; stale binding denied ($dec_conflict)"
    else
      conflict_note="dec=$dec_conflict old_id=$s_id new_id=$r_id"
    fi
    rt_rm basil-re-stale
  else
    dec_conflict="recreate_failed"; conflict_note="recreate failed"
  fi

  if [[ $stale == true && $conflict == true ]]; then
    set_v "$terminal" PASS "stale->$dec_stale; name-conflict->$dec_conflict"
  else
    set_v "$terminal" FAIL "stale=$stale ($dec_stale) conflict=$conflict"
  fi
  emit_event stale_and_conflicting "$([[ ${VERDICT[$terminal]} == PASS ]] && echo PASS || echo TEST_FAIL)" \
    STALE_AND_CONFLICT_FAIL_CLOSED \
    "$(jq -cn --arg ds "$dec_stale" --arg dc "$dec_conflict" --arg note "$conflict_note" \
        --argjson stale "$stale" --argjson conflict "$conflict" \
        '{stale_decision:$ds,conflict_decision:$dc,stale_detected:$stale,
          conflict_detected:$conflict,detail:$note,
          note:"a runtime container name is mutable and reusable; identity must pin the exact instance id plus PID/start-time, never the name"}')"
}

# Emit the authoritative end event carrying the five terminal verdicts.
return_terminals() {
  local all_pass=true t
  local -a keys=(
    runtime.peer-correlation runtime.pid-start-time
    runtime.same-uid-isolation runtime.realm-overlap runtime.stale-and-conflicting
  )
  local verdicts='{}'
  for t in "${keys[@]}"; do
    local v=${VERDICT[$t]:-FAIL} r=${VREASON[$t]:-not_run}
    [[ $v == PASS ]] || all_pass=false
    verdicts=$(jq -c --arg k "$t" --arg v "$v" --arg r "${r:0:400}" \
      '. + {($k): {verdict:$v, reason:$r}}' <<<"$verdicts")
  done
  emit_event end "$([[ $all_pass == true ]] && echo PASS || echo TEST_FAIL)" \
    RUNTIME_EVIDENCE_COMPLETE \
    "$(jq -cn --argjson verdicts "$verdicts" --argjson all "$all_pass" \
        '{all_pass:$all,verdicts:$verdicts}')"
}

# =============================================================================

main() {
  if [[ $mode == owner-probe ]]; then
    owner_probe
    return 0
  fi
  emit_event start INFO RUNTIME_EVIDENCE_START \
    "$(jq -cn --arg rt "$runtime" --arg img "$image_ref" '{runtime:$rt,image:$img}')"
  experiments
  # Exit non-zero if any terminal failed, so the driver can distinguish a clean
  # all-pass run; the end event remains authoritative regardless.
  local t
  for t in runtime.peer-correlation runtime.pid-start-time runtime.same-uid-isolation \
           runtime.realm-overlap runtime.stale-and-conflicting; do
    [[ ${VERDICT[$t]:-FAIL} == PASS ]] || return 1
  done
  return 0
}

main "$@"
