#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
# SPDX-License-Identifier: Apache-2.0

# Guest-side Compose Phase 1.2 capacity ladder (br basil-9tj.4).
#
# Runs INSIDE a booted lane guest (rootless Podman on Fedora, rootful Docker on
# Ubuntu) and measures the ATTESTOR resource + latency ceilings of the container
# identity path at a serial scale ladder up to 1,000 managed containers, with
# adversarial container metadata present. It reuses the fail-closed `attest_peer`
# correlation from the Phase 1.1 runtime-evidence prototype (br basil-9tj.2) and
# times its two cost components, which map to the design's two attestation SLOs:
#
#   * runtime-API enumeration + candidate-inventory build (once per ladder step)
#     -> the FIRST-authorization cost (design SLO: p95 <= 250 ms, p99 <= 1 s);
#   * per-attestation correlation (kernel re-read of the pinned peer + candidate
#     resolution) -> the WARM-authorization cost (design SLO: p95 <= 10 ms).
#
# The subject under measurement is the ATTESTOR/BROKER cost per container, not
# the workload: containers are inert `--network none` sleepers from the pinned
# lane workload image. Adversarial metadata (very long look-alike names, hostile
# label values with shell/jq metacharacters, and deep cgroup nesting) is attached
# to a fraction of the containers to prove the correlation stays BOUNDED and
# FAIL-CLOSED under hostile input; correlation binds by exact kernel cgroup and
# never trusts a name/label, so hostile metadata can only add parse cost.
#
# It NEVER disables an LSM, changes runtime policy, reads foreign secrets, or
# emits raw runtime payloads. Its stdout is PURE bounded JSONL; every step event
# and the authoritative `end` event (carrying the five `capacity.*` verdicts) is
# parsed by the lane driver. The guest verdicts are "measurement collected
# completely" verdicts (mirroring capacity-preflight): a ge9 stop-condition abort
# or a wall-clock-budget stop is a FINDING carried in the data + message, never a
# false failure. The ladder is self-bounding so a runner driver run stays inside
# the 900 s driver cap: it stops at the highest step reached under the budget and
# reports that reached top as the checked lower-only bound.

set -uo pipefail  # deliberately NOT -e: wrap steps so `end` always emits.

readonly SCHEMA_VERSION="basil.compose.phase1.capacity-ladder/v1"

runtime=""
lane_id="native-x86_64"
run_id="capacity-ladder-$(date -u +%Y%m%dT%H%M%SZ)-$$"
image_ref=""
image_tar=""
ladder_csv="10,50,100,250,500,750,1000"
budget_secs=600
attest_samples=60
seq=0

usage() {
  printf '%s\n' \
    'usage: capacity-ladder.sh --runtime docker|podman [--lane-id ID] [--run-id ID]' \
    '        [--image REF] [--image-tar PATH] [--ladder 10,50,...,1000]' \
    '        [--budget-secs N] [--attest-samples N]' >&2
}

while (($# > 0)); do
  case "$1" in
    --runtime) runtime=${2:-}; shift 2 ;;
    --lane-id) lane_id=${2:-}; shift 2 ;;
    --run-id) run_id=${2:-}; shift 2 ;;
    --image) image_ref=${2:-}; shift 2 ;;
    --image-tar) image_tar=${2:-}; shift 2 ;;
    --ladder) ladder_csv=${2:-}; shift 2 ;;
    --budget-secs) budget_secs=${2:-}; shift 2 ;;
    --attest-samples) attest_samples=${2:-}; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done

case "$runtime" in
  docker|podman) ;;
  *) printf 'invalid or missing --runtime: %s\n' "$runtime" >&2; exit 2 ;;
esac
command -v jq >/dev/null 2>&1 || { printf 'capacity-ladder requires jq\n' >&2; exit 2; }
command -v "$runtime" >/dev/null 2>&1 || { printf 'runtime CLI missing: %s\n' "$runtime" >&2; exit 2; }
[[ $budget_secs =~ ^[0-9]+$ ]] || budget_secs=600
[[ $attest_samples =~ ^[0-9]+$ ]] || attest_samples=60

run_id=${run_id:0:128}
lane_id=${lane_id:0:128}

readonly NAME_PREFIX="basilcap"
CANDIDATES_FILE=$(mktemp) || { printf 'mktemp failed\n' >&2; exit 2; }
LAT_FILE=$(mktemp) || { printf 'mktemp failed\n' >&2; exit 2; }
START_EPOCH=$EPOCHSECONDS

cleanup() {
  local jobpids
  jobpids=$(jobs -p 2>/dev/null || true)
  # shellcheck disable=SC2086
  [[ -n $jobpids ]] && kill $jobpids 2>/dev/null || true
  # Remove every container this run created (by name prefix), bounded + quiet.
  local ids
  ids=$("$runtime" ps -aq --filter "name=$NAME_PREFIX" 2>/dev/null || true)
  # shellcheck disable=SC2086
  [[ -n $ids ]] && "$runtime" rm -f $ids >/dev/null 2>&1 || true
  rm -f "$CANDIDATES_FILE" "$LAT_FILE" 2>/dev/null || true
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

# ---- Kernel evidence readers (host pid namespace) : identical semantics to the
# runtime-evidence prototype (basil-9tj.2). Field 22 of /proc/PID/stat is the
# process start time in clock ticks; comm may contain spaces so parse after ") ".
# These readers are FORK-FREE (bash builtin `read`), except read_userns which
# needs one readlink. A real Rust attestor reads /proc directly with no
# subprocess; the shell prototype must avoid per-candidate `cat`/`awk`/`grep`
# forks so its per-candidate cost reflects the kernel-read work, not shell fork
# overhead (which would otherwise dominate at 1,000 candidates).
read_starttime() {
  local raw rest
  read -r raw <"/proc/$1/stat" 2>/dev/null || return 1
  rest=${raw##*) }
  # shellcheck disable=SC2086
  set -- $rest
  [[ ${20:-} =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "${20}"
}
read_cgroup() {
  # cgroup v2 exposes a single `0::/path` line; `read` grabs it fork-free.
  local line
  read -r line <"/proc/$1/cgroup" 2>/dev/null || return 1
  [[ $line == 0::* ]] || return 1
  printf '%s\n' "${line#0::}"
}
read_userns() { readlink "/proc/$1/ns/user" 2>/dev/null || return 1; }
read_ruid() {
  local k v
  while read -r k v _; do
    [[ $k == Uid: ]] || continue
    [[ $v =~ ^[0-9]+$ ]] || return 1
    printf '%s\n' "$v"; return 0
  done <"/proc/$1/status" 2>/dev/null
  return 1
}
alive() { [[ -e /proc/$1 ]]; }

# attest_peer: the fail-closed decision, identical to the runtime-evidence
# prototype. Revalidate liveness + start-time pin, cgroup stability, then
# owner-scoped correlation against the enrolled candidate set (0 -> deny, >1 ->
# deny ambiguous), then user-ns cross-check. Echoes "ALLOW <id>" / "DENY <r>".
# Args: pinned_pid pinned_starttime pinned_uid pinned_cgroup pinned_userns
attest_peer() {
  local ppid=$1 pst=$2 puid=$3 pcg=$4 puns=$5 live_st live_cg
  if ! alive "$ppid"; then printf 'DENY STALE_PEER_GONE\n'; return 0; fi
  live_st=$(read_starttime "$ppid") || { printf 'DENY STALE_PEER_GONE\n'; return 0; }
  if [[ $live_st != "$pst" ]]; then printf 'DENY PID_REUSED\n'; return 0; fi
  live_cg=$(read_cgroup "$ppid") || { printf 'DENY CGROUP_UNREADABLE\n'; return 0; }
  if [[ $live_cg != "$pcg" ]]; then printf 'DENY CGROUP_MOVED\n'; return 0; fi
  local id pid st uid cg uns match_count=0 match_id="" match_uns=""
  while IFS=$'\t' read -r id pid st uid cg uns; do
    [[ -n $id ]] || continue
    [[ $uid == "$puid" ]] || continue
    if [[ $pcg == "$cg" || $pcg == "$cg"/* ]]; then
      match_count=$((match_count + 1)); match_id=$id; match_uns=$uns
    fi
  done <"$CANDIDATES_FILE"
  if (( match_count == 0 )); then printf 'DENY ZERO_CANDIDATES\n'; return 0; fi
  if (( match_count > 1 )); then printf 'DENY MULTIPLE_CANDIDATES\n'; return 0; fi
  if [[ $match_uns != unknown && $puns != unknown && $match_uns != "$puns" ]]; then
    printf 'DENY CONFLICTING_FACTS\n'; return 0
  fi
  printf 'ALLOW %s\n' "$match_id"
}

# ---- Runtime provider abstraction -------------------------------------------
rt_load() {
  [[ -n $image_tar && -f $image_tar ]] || return 0
  "$runtime" load -i "$image_tar" >/dev/null 2>&1 || true
}

# A hostile label value: shell + jq metacharacters and a long run. Container
# LABELS accept arbitrary bytes (names do not), so this is where adversarial
# free-form metadata lives; the attestor must parse it bounded and never bind on
# it. Kept < 2 KiB so 1,000 of them do not blow the inspect JSON past sane size.
adversarial_label() {
  local pad; pad=$(printf 'A%.0s' {1..200})
  # shellcheck disable=SC2016  # literal shell/jq metacharacters are the payload
  printf '$(id);`whoami`;{"x":1}|.["y"]//0;%s;../../../etc/passwd;\\x00nul;%s' \
    '/system.slice/docker-lookalike.scope' "$pad"
}
# A very long, runtime-legal look-alike name (<=200 chars, allowed charset),
# suggestive of a realm path, to prove names are never an identity selector.
adversarial_name() {
  local i=$1 pad
  pad=$(printf 'x%.0s' {1..120})
  printf '%s_system_slice_docker_lookalike_%s_%d' "$NAME_PREFIX" "$pad" "$i"
}

# Start ONE container. Every Nth (adv_mod) container carries adversarial metadata
# (very long look-alike name + hostile label values) and shares one extra cgroup
# parent slice so the adversarial cohort creates a real cgroup-path-PREFIX overlap
# (the multiple-positive case the correlation must fail closed on); the rest are
# plain sleepers. A half-created container from a failed cgroup-parent attempt is
# removed before the fallback so the name is free (else "name already in use").
# Output silenced -- the JSONL stdout is the sole result channel.
rt_run_one() {
  local i=$1 adv_mod=$2 name
  if (( adv_mod > 0 && i % adv_mod == 0 )); then
    name=$(adversarial_name "$i")
    "$runtime" run -d --network none --name "$name" \
      --label "basilcap.adv=$(adversarial_label)" \
      --label "basilcap.hostile.$i=/user.slice/user-99999.slice/lookalike" \
      --cgroup-parent basilcapadv.slice \
      "$image_ref" sleep 3600 >/dev/null 2>&1 && return 0
    "$runtime" rm -f "$name" >/dev/null 2>&1 || true
    "$runtime" run -d --network none --name "$name" \
      --label "basilcap.adv=$(adversarial_label)" \
      --label "basilcap.hostile.$i=/user.slice/user-99999.slice/lookalike" \
      "$image_ref" sleep 3600 >/dev/null 2>&1 && return 0
    return 1
  fi
  "$runtime" run -d --network none --name "${NAME_PREFIX}-plain-$i" \
    "$image_ref" sleep 3600 >/dev/null 2>&1
}

# Start containers with ids in [lo, hi] in parallel across `par` workers.
rt_start_range() {
  local lo=$1 hi=$2 par=$3 adv_mod=$4
  # shellcheck disable=SC2016  # $1/$2 are the child bash -c positional params
  seq "$lo" "$hi" | xargs -P "$par" -I{} bash -c \
    'rt_run_one "$1" "$2" || true' _ {} "$adv_mod" 2>/dev/null
}

# Count running basilcap containers.
rt_count() { "$runtime" ps -q --filter "name=$NAME_PREFIX" 2>/dev/null | grep -c . || true; }

# ---- host resource snapshot readers -----------------------------------------
mem_available_kb() { awk '/^MemAvailable:/{print $2; exit}' /proc/meminfo 2>/dev/null || echo 0; }
mem_total_kb() { awk '/^MemTotal:/{print $2; exit}' /proc/meminfo 2>/dev/null || echo 0; }
disk_avail_bytes() { df -B1 --output=avail / 2>/dev/null | tail -1 | tr -d ' ' || echo 0; }
# shellcheck disable=SC2012  # /proc pid dirs are numeric; ls is fine and fast
proc_count() { ls -d /proc/[0-9]* 2>/dev/null | wc -l; }
pid_max() { cat /proc/sys/kernel/pid_max 2>/dev/null || echo 0; }
fd_soft() { ulimit -Sn; }
open_fds_system() { awk '{print $1}' /proc/sys/fs/file-nr 2>/dev/null || echo 0; }
# runtime daemon RSS (dockerd for docker; conmon/podman aggregate for podman).
runtime_daemon_rss_kb() {
  local total=0 p rss
  if [[ $runtime == docker ]]; then
    for p in $(pgrep -x dockerd 2>/dev/null; pgrep -x containerd 2>/dev/null); do
      rss=$(awk '/^VmRSS:/{print $2}' "/proc/$p/status" 2>/dev/null); total=$((total + ${rss:-0}))
    done
  else
    for p in $(pgrep -x conmon 2>/dev/null); do
      rss=$(awk '/^VmRSS:/{print $2}' "/proc/$p/status" 2>/dev/null); total=$((total + ${rss:-0}))
    done
  fi
  printf '%s\n' "$total"
}
self_rss_kb() { awk '/^VmRSS:/{print $2}' "/proc/$$/status" 2>/dev/null || echo 0; }
self_cpu_ms() {
  # utime+stime of this shell in ms (CLK_TCK=100 on these guests).
  local u s hz
  read -r u s < <(awk '{print $14, $15}' "/proc/$$/stat" 2>/dev/null)
  hz=$(getconf CLK_TCK 2>/dev/null || echo 100)
  printf '%s\n' "$(( (u + s) * 1000 / hz ))"
}

# percentile of a newline-separated numeric file: pctl FILE P(0..100)
pctl() {
  local f=$1 p=$2
  sort -n "$f" 2>/dev/null | awk -v p="$p" '
    {a[NR]=$1} END{ if (NR==0){print 0; exit}
      idx=int((p/100.0)*(NR-1)+0.5)+1; if(idx<1)idx=1; if(idx>NR)idx=NR; print a[idx] }'
}

# ---- ge9 stop conditions (measured floors/ceilings; abort a step cleanly if
# tripped -- that itself is a finding, not a failure). -------------------------
declare -A STOP
compute_stop_thresholds() {
  local mt; mt=$(mem_total_kb)
  # memory floor = max(4 GiB, 10% of total), in KiB.
  local ten=$(( mt / 10 )) fourg=$(( 4 * 1024 * 1024 ))
  STOP[mem_floor_kb]=$(( ten > fourg ? ten : fourg ))
  STOP[disk_floor_bytes]=$(( 2 * 1024 * 1024 * 1024 ))   # 2 GiB free floor
  STOP[fd_per_container]=16
  STOP[pids_per_container]=4
  # Per-step RUNAWAY guard (30 s): aborts a step whose inventory build blows up,
  # a genuine wall. This is deliberately far above the design's first-auth SLO
  # (p99 <= 1 s): the shell prototype's enumeration carries fork/`inspect` cost a
  # Rust attestor does not, so the enum latency is REPORTED and SLO-compared in
  # the findings, not used to stop the ladder on shell overhead alone.
  STOP[per_step_latency_ceiling_ms]=30000
}
# Returns a stop reason if any threshold trips at container count S, else empty.
stop_reason_at() {
  local s=$1 enum_ms=$2 ma da soft procs pm
  ma=$(mem_available_kb); da=$(disk_avail_bytes); soft=$(fd_soft)
  procs=$(proc_count); pm=$(pid_max)
  if (( ma < STOP[mem_floor_kb] )); then printf 'MEMORY_FLOOR mem_avail_kb=%s floor_kb=%s' "$ma" "${STOP[mem_floor_kb]}"; return; fi
  if (( da < STOP[disk_floor_bytes] )); then printf 'DISK_FLOOR avail_bytes=%s floor=%s' "$da" "${STOP[disk_floor_bytes]}"; return; fi
  if [[ $soft != unlimited ]] && (( soft < s * STOP[fd_per_container] )); then
    printf 'FD_HEADROOM soft=%s need=%s' "$soft" "$(( s * STOP[fd_per_container] ))"; return; fi
  if (( pm < s * STOP[pids_per_container] )); then printf 'PID_HEADROOM pid_max=%s need=%s' "$pm" "$(( s * STOP[pids_per_container] ))"; return; fi
  if (( enum_ms > STOP[per_step_latency_ceiling_ms] )); then
    printf 'LATENCY_CEILING enum_ms=%s ceiling=%s' "$enum_ms" "${STOP[per_step_latency_ceiling_ms]}"; return; fi
  printf ''
}

# ---- verdict accumulator ----------------------------------------------------
declare -A VERDICT VREASON
set_v() { VERDICT[$1]=$2; VREASON[$1]=$3; }

# Build the candidate inventory for all running basilcap containers: this is the
# runtime-API enumeration + kernel-fact build whose latency is the FIRST-auth
# cost. Fills CANDIDATES_FILE (id<TAB>pid<TAB>st<TAB>uid<TAB>cg<TAB>uns) and echoes
# "ENUM_MS API_MS KERNEL_MS COUNT".
build_inventory() {
  : >"$CANDIDATES_FILE"
  local t0 t1 t2 api_ms kern_ms rows id pid
  t0=$EPOCHREALTIME
  # One runtime-API call returns id+init-pid for every container (the enumeration
  # a real attestor performs). --no-trunc keeps full ids; format keeps it bounded.
  rows=$("$runtime" ps -a --filter "name=$NAME_PREFIX" --no-trunc \
      --format '{{.ID}} {{.Names}}' 2>/dev/null)
  # Batch inspect for init PIDs (single API round-trip over all ids).
  local ids
  ids=$(printf '%s\n' "$rows" | awk '{print $1}' | tr '\n' ' ')
  local pidmap
  # shellcheck disable=SC2086
  pidmap=$("$runtime" inspect --format '{{.Id}} {{.State.Pid}}' $ids 2>/dev/null)
  t1=$EPOCHREALTIME
  # Kernel-fact read per candidate (cgroup/ns/starttime/uid from /proc).
  local cid p st uid cg uns
  while read -r cid p; do
    [[ $p =~ ^[0-9]+$ && $p -gt 0 ]] || continue
    st=$(read_starttime "$p") || continue
    uid=$(read_ruid "$p") || continue
    cg=$(read_cgroup "$p") || continue
    uns=$(read_userns "$p") || uns="unknown"
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$cid" "$p" "$st" "$uid" "$cg" "$uns" >>"$CANDIDATES_FILE"
  done <<<"$pidmap"
  t2=$EPOCHREALTIME
  api_ms=$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.1f",(b-a)*1000}')
  kern_ms=$(awk -v a="$t1" -v b="$t2" 'BEGIN{printf "%.1f",(b-a)*1000}')
  local enum_ms; enum_ms=$(awk -v a="$t0" -v b="$t2" 'BEGIN{printf "%.1f",(b-a)*1000}')
  local count; count=$(grep -c . "$CANDIDATES_FILE")
  printf '%s %s %s %s\n' "$enum_ms" "$api_ms" "$kern_ms" "$count"
}

# Measure the WARM per-attestation correlation latency distribution over N sample
# peers drawn from the candidate set. Also asserts fail-closed on adversarial
# peers (stale + look-alike-realm-prefix) WITH the hostile set present. Echoes
# "P50 P95 MAX MEAN ALLOW_OK DENY_STALE_OK DENY_AMBIG_OK".
measure_warm_latency() {
  local n=$1
  : >"$LAT_FILE"
  local total_lines; total_lines=$(grep -c . "$CANDIDATES_FILE")
  (( total_lines > 0 )) || { printf '0 0 0 0 false false false\n'; return; }
  # Sample up to n candidates (stride so we cover the whole set).
  local stride=$(( total_lines / n )); (( stride < 1 )) && stride=1
  local i=0 allow_ok=0 seen=0 id pid st uid cg uns t0 t1 dec
  while IFS=$'\t' read -r id pid st uid cg uns; do
    i=$((i + 1))
    (( i % stride == 0 )) || continue
    seen=$((seen + 1)); (( seen > n )) && break
    alive "$pid" || continue
    t0=$EPOCHREALTIME
    dec=$(attest_peer "$pid" "$st" "$uid" "$cg" "$uns")
    t1=$EPOCHREALTIME
    awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.3f\n",(b-a)*1000}' >>"$LAT_FILE"
    [[ $dec == "ALLOW $id" ]] && allow_ok=$((allow_ok + 1))
  done <"$CANDIDATES_FILE"
  # Adversarial fail-closed probes (correctness under hostile metadata present):
  #  * stale pin: a live candidate PID with a deliberately wrong start-time.
  local a_stale="false" a_ambig="false"
  local fid fpid fst fuid fcg funs
  IFS=$'\t' read -r fid fpid fst fuid fcg funs < <(head -1 "$CANDIDATES_FILE")
  if [[ -n ${fpid:-} ]]; then
    local wrong_st=$(( fst - 1 ))
    dec=$(attest_peer "$fpid" "$wrong_st" "$fuid" "$fcg" "$funs")
    [[ $dec == "DENY PID_REUSED" ]] && a_stale="true"
    #  * look-alike realm prefix: pin the parent cgroup of a candidate -> if >1
    #    candidate shares it, must DENY MULTIPLE (prefix routing forbidden).
    local parent=${fcg%/*}
    local shared; shared=$(awk -F'\t' -v pfx="$parent" '$5==pfx || index($5, pfx"/")==1{c++} END{print c+0}' "$CANDIDATES_FILE")
    if (( shared > 1 )); then
      dec=$(attest_peer "$fpid" "$fst" "$fuid" "$parent" "$funs")
      [[ $dec == DENY* ]] && a_ambig="true"
    else
      a_ambig="true"   # only one under this parent -> exact scope, not a prefix overlap
    fi
  fi
  local p50 p95 mx mean
  p50=$(pctl "$LAT_FILE" 50); p95=$(pctl "$LAT_FILE" 95); mx=$(pctl "$LAT_FILE" 100)
  mean=$(awk '{s+=$1;n++} END{if(n)printf "%.3f",s/n; else print 0}' "$LAT_FILE")
  local allow_all="false"; (( seen > 0 && allow_ok == seen )) && allow_all="true"
  printf '%s %s %s %s %s %s %s\n' "$p50" "$p95" "$mx" "$mean" "$allow_all" "$a_stale" "$a_ambig"
}

# ---- the ladder -------------------------------------------------------------
declare -a STEP_JSON=()
LADDER_TOP=0
STOP_HIT=""
run_ladder() {
  rt_load
  compute_stop_thresholds
  # capacity.preflight: environment + inventory machinery ready.
  local soft0; soft0=$(fd_soft)
  local mt; mt=$(mem_total_kb)
  emit_event preflight INFO CAPACITY_PRELIGHT_READY \
    "$(jq -cn --arg rt "$runtime" --arg img "$image_ref" --arg soft "$soft0" \
        --argjson mt "$mt" --argjson budget "$budget_secs" \
        --argjson thr "$(jq -cn --argjson m "${STOP[mem_floor_kb]}" --argjson d "${STOP[disk_floor_bytes]}" \
            --argjson f "${STOP[fd_per_container]}" --argjson p "${STOP[pids_per_container]}" \
            --argjson l "${STOP[per_step_latency_ceiling_ms]}" \
            '{mem_floor_kb:$m,disk_floor_bytes:$d,fd_per_container:$f,pids_per_container:$p,per_step_latency_ceiling_ms:$l}')" \
        '{runtime:$rt,image:$img,fd_soft:$soft,mem_total_kb:$mt,budget_secs:$budget,derived_stop_thresholds:$thr}')"
  if [[ -n $image_ref ]]; then
    set_v capacity.preflight PASS "runtime=$runtime image loaded; fd_soft=$soft0; thresholds derived"
  else
    set_v capacity.preflight PASS "runtime=$runtime; fd_soft=$soft0; thresholds derived"
  fi

  local -a steps
  IFS=',' read -r -a steps <<<"$ladder_csv"
  local par; par=$(nproc 2>/dev/null || echo 4)
  local current=0 step
  for step in "${steps[@]}"; do
    [[ $step =~ ^[0-9]+$ ]] || continue
    # budget guard BEFORE starting a potentially long step.
    local elapsed=$(( EPOCHSECONDS - START_EPOCH ))
    if (( elapsed > budget_secs )); then STOP_HIT="BUDGET elapsed=${elapsed}s top=${current}"; break; fi
    # start containers up to `step` (parallel), adversarial every 5th.
    if (( step > current )); then
      rt_start_range "$((current + 1))" "$step" "$par" 5 || true
    fi
    local running; running=$(rt_count)
    # If the runtime could not reach the target, capture WHY (the density-ceiling
    # cause: rootless pids/locks, EMFILE, etc.) via one probe start with stderr.
    local start_error=""
    if (( running < step )); then
      start_error=$("$runtime" run -d --network none --name "${NAME_PREFIX}-probe-$RANDOM" \
        "$image_ref" sleep 5 2>&1 >/dev/null | tr -d '\r' | head -c 240)
      [[ -z $start_error ]] && "$runtime" rm -f "$("$runtime" ps -aq --filter "name=${NAME_PREFIX}-probe" 2>/dev/null)" >/dev/null 2>&1 || true
    fi
    # build inventory (first-auth enumeration cost).
    local enum_line; enum_line=$(build_inventory)
    local enum_ms api_ms kern_ms count
    read -r enum_ms api_ms kern_ms count <<<"$enum_line"
    # stop conditions (measured; abort cleanly if tripped).
    local sr; sr=$(stop_reason_at "$count" "${enum_ms%.*}")
    # warm per-attestation latency distribution + fail-closed under adversarial set.
    local warm_line; warm_line=$(measure_warm_latency "$attest_samples")
    local p50 p95 mx mean allow_all a_stale a_ambig
    read -r p50 p95 mx mean allow_all a_stale a_ambig <<<"$warm_line"
    # resource snapshot.
    local ma da procs dfd drss srss scpu
    ma=$(mem_available_kb); da=$(disk_avail_bytes); procs=$(proc_count)
    dfd=$(open_fds_system); drss=$(runtime_daemon_rss_kb); srss=$(self_rss_kb); scpu=$(self_cpu_ms)
    LADDER_TOP=$running
    local ev
    ev=$(jq -cn \
      --argjson target "$step" --argjson running "$running" --argjson count "$count" \
      --arg enum_ms "$enum_ms" --arg api_ms "$api_ms" --arg kern_ms "$kern_ms" \
      --arg warm_p50 "$p50" --arg warm_p95 "$p95" --arg warm_max "$mx" --arg warm_mean "$mean" \
      --arg allow_all "$allow_all" --arg adv_stale "$a_stale" --arg adv_ambig "$a_ambig" \
      --argjson mem_avail_kb "$ma" --argjson disk_avail_bytes "$da" --argjson procs "$procs" \
      --argjson sys_open_fds "$dfd" --argjson daemon_rss_kb "$drss" \
      --argjson attestor_rss_kb "$srss" --argjson attestor_cpu_ms "$scpu" \
      --arg elapsed "$(( EPOCHSECONDS - START_EPOCH ))" --arg stop "${sr:-}" \
      --arg start_error "${start_error:-}" \
      '{target:$target,running:$running,candidates:$count,start_error:$start_error,
        first_auth_enum_ms:($enum_ms|tonumber),runtime_api_ms:($api_ms|tonumber),kernel_read_ms:($kern_ms|tonumber),
        warm_attest_ms:{p50:($warm_p50|tonumber),p95:($warm_p95|tonumber),max:($warm_max|tonumber),mean:($warm_mean|tonumber)},
        fail_closed:{honest_allow_all:($allow_all=="true"),adversarial_stale_denied:($adv_stale=="true"),adversarial_prefix_denied:($adv_ambig=="true")},
        resources:{mem_avail_kb:$mem_avail_kb,disk_avail_bytes:$disk_avail_bytes,process_count:$procs,system_open_fds:$sys_open_fds,runtime_daemon_rss_kb:$daemon_rss_kb,attestor_rss_kb:$attestor_rss_kb,attestor_cpu_ms:($attestor_cpu_ms|tonumber)},
        elapsed_secs:($elapsed|tonumber),stop_reason:$stop}')
    STEP_JSON+=("$ev")
    emit_event step "$([[ -z $sr ]] && echo PASS || echo INFO)" LADDER_STEP_MEASURED "$ev"
    current=$running
    if [[ -n $sr ]]; then STOP_HIT="$sr top=$running"; break; fi
  done
}

# capacity.overload: past-ceiling behaviour. Drive a concurrent attestation storm
# against the reached candidate set and confirm the attestor stays BOUNDED and
# FAIL-CLOSED and does not crash. (The runtime API itself is the natural ceiling;
# there is no attestor-imposed admission control in Compose 1.0 yet.)
run_overload() {
  local storm=200 ok=0 dec fid fpid fst fuid fcg funs
  IFS=$'\t' read -r fid fpid fst fuid fcg funs < <(head -1 "$CANDIDATES_FILE" 2>/dev/null)
  local crashed="false" i
  if [[ -n ${fpid:-} ]] && alive "$fpid"; then
    for (( i=0; i<storm; i++ )); do
      dec=$(attest_peer "$fpid" "$fst" "$fuid" "$fcg" "$funs" 2>/dev/null) || crashed="true"
      [[ $dec == "ALLOW $fid" ]] && ok=$((ok + 1))
    done
    # an over-limit adversarial flood: attest a peer that is gone -> must DENY.
    dec=$(attest_peer 999999 "$fst" "$fuid" "$fcg" "$funs" 2>/dev/null) || crashed="true"
  fi
  local stale_ok="false"; [[ ${dec:-} == DENY* ]] && stale_ok="true"
  emit_event overload "$([[ $crashed == false ]] && echo PASS || echo TEST_FAIL)" OVERLOAD_BOUNDED_FAIL_CLOSED \
    "$(jq -cn --argjson storm "$storm" --argjson ok "$ok" --arg crashed "$crashed" --arg stale "$stale_ok" \
        '{attestation_storm:$storm,honest_allow_ok:$ok,attestor_crashed:($crashed=="true"),overlimit_gone_peer_denied:($stale=="true")}')"
  if [[ $crashed == false && $ok -gt 0 && $stale_ok == true ]]; then
    set_v capacity.overload PASS "storm=$storm honest_ok=$ok; over-limit gone-peer denied; attestor bounded + fail-closed, no crash"
  else
    set_v capacity.overload TEST_FAIL "crashed=$crashed ok=$ok stale_denied=$stale_ok"
  fi
}

# capacity.teardown: remove all containers, confirm the count returns to zero.
run_teardown() {
  local t0 t1 ids before after ms
  before=$(rt_count)
  t0=$EPOCHREALTIME
  ids=$("$runtime" ps -aq --filter "name=$NAME_PREFIX" 2>/dev/null || true)
  # shellcheck disable=SC2086
  [[ -n $ids ]] && "$runtime" rm -f $ids >/dev/null 2>&1 || true
  t1=$EPOCHREALTIME
  after=$(rt_count)
  ms=$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.0f",(b-a)*1000}')
  emit_event teardown "$([[ ${after:-1} -eq 0 ]] && echo PASS || echo TEST_FAIL)" TEARDOWN_COMPLETE \
    "$(jq -cn --argjson before "${before:-0}" --argjson after "${after:-0}" --argjson ms "$ms" \
        '{removed_from:$before,remaining:$after,teardown_ms:$ms}')"
  if [[ ${after:-1} -eq 0 ]]; then
    set_v capacity.teardown PASS "removed $before containers in ${ms}ms; 0 remain"
  else
    set_v capacity.teardown TEST_FAIL "$after containers still running after teardown"
  fi
}

# Derive the resources + latency verdicts from the collected step data.
finalize_measurement_verdicts() {
  local nsteps=${#STEP_JSON[@]}
  if (( nsteps == 0 )); then
    set_v capacity.resources TEST_FAIL "no ladder step measured"
    set_v capacity.latency TEST_FAIL "no ladder step measured"
    return
  fi
  # resources: every step carries mem/fd/pids/cpu/rss for attestor + daemon.
  set_v capacity.resources PASS "collected cpu/mem/fd/rss across $nsteps step(s); ladder top=$LADDER_TOP containers${STOP_HIT:+; stop=$STOP_HIT}"
  # latency: SLO comparison at the top step.
  local top; top=${STEP_JSON[-1]}
  local warm_p95 first_p95 fc_ok
  warm_p95=$(jq -r '.warm_attest_ms.p95' <<<"$top")
  first_p95=$(jq -r '.first_auth_enum_ms' <<<"$top")
  fc_ok=$(jq -r '.fail_closed | (.honest_allow_all and .adversarial_stale_denied and .adversarial_prefix_denied)' <<<"$top")
  local warm_verdict first_verdict
  warm_verdict=$(awk -v v="$warm_p95" 'BEGIN{print (v<=10)?"MEETS":"EXCEEDS"}')
  first_verdict=$(awk -v v="$first_p95" 'BEGIN{print (v<=250)?"MEETS":"EXCEEDS"}')
  set_v capacity.latency PASS "top=$LADDER_TOP warm_p95=${warm_p95}ms(SLO<=10:$warm_verdict) first_auth=${first_p95}ms(SLO<=250:$first_verdict) fail_closed=$fc_ok"
}

return_terminals() {
  local all_pass=true t
  local -a keys=(capacity.preflight capacity.resources capacity.latency capacity.overload capacity.teardown)
  local verdicts='{}'
  for t in "${keys[@]}"; do
    local v=${VERDICT[$t]:-TEST_FAIL} r=${VREASON[$t]:-not_run}
    [[ $v == PASS ]] || all_pass=false
    verdicts=$(jq -c --arg k "$t" --arg v "$v" --arg r "${r:0:460}" \
      '. + {($k): {verdict:$v, reason:$r}}' <<<"$verdicts")
  done
  # compact per-step summary table (bounded).
  local table='[]'
  for ev in "${STEP_JSON[@]}"; do
    table=$(jq -c --argjson e "$ev" \
      '. + [{n:$e.running,first_auth_ms:$e.first_auth_enum_ms,warm_p50:$e.warm_attest_ms.p50,warm_p95:$e.warm_attest_ms.p95,warm_max:$e.warm_attest_ms.max,daemon_rss_kb:$e.resources.runtime_daemon_rss_kb,attestor_rss_kb:$e.resources.attestor_rss_kb,mem_avail_kb:$e.resources.mem_avail_kb}]' <<<"$table")
  done
  emit_event end "$([[ $all_pass == true ]] && echo PASS || echo TEST_FAIL)" CAPACITY_LADDER_COMPLETE \
    "$(jq -cn --argjson verdicts "$verdicts" --argjson all "$all_pass" \
        --argjson top "$LADDER_TOP" --arg stop "${STOP_HIT:-none}" --argjson table "$table" \
        '{all_pass:$all,ladder_top:$top,stop_condition:$stop,verdicts:$verdicts,per_step:$table,
          slo_reference:{warm_auth_p95_ms:10,first_auth_p95_ms:250,first_auth_p99_ms:1000}}')"
}

main() {
  emit_event start INFO CAPACITY_LADDER_START \
    "$(jq -cn --arg rt "$runtime" --arg img "$image_ref" --arg ladder "$ladder_csv" \
        --argjson budget "$budget_secs" '{runtime:$rt,image:$img,ladder:$ladder,budget_secs:$budget}')"
  run_ladder || true
  finalize_measurement_verdicts || true
  run_overload || true
  run_teardown || true
  return_terminals
  local t
  for t in capacity.preflight capacity.resources capacity.latency capacity.overload capacity.teardown; do
    [[ ${VERDICT[$t]:-TEST_FAIL} == PASS ]] || return 1
  done
  return 0
}

# rt_run_one is invoked by xargs subshells; export it + deps for `bash -c`.
export -f rt_run_one adversarial_name adversarial_label
export runtime image_ref NAME_PREFIX

main "$@"
