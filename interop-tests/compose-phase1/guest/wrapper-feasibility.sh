#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
# SPDX-License-Identifier: Apache-2.0

# Guest-side Compose Phase 1.3 wrapper / raw-delivery feasibility prototype
# (br basil-9tj.6).
#
# Runs INSIDE a booted lane guest (rootless Podman on Fedora/SELinux, rootful
# Docker on Ubuntu/AppArmor). It prototypes two secret-delivery shapes that
# Basil's Compose integration (Design 0001, "Raw-value flow") depends on and
# measures how they behave across the platform matrix:
#
#   * WRAPPER (entrypoint interposition): a minimal wrapper replaces the image
#     entrypoint, delivers SYNTHETIC secret material to a tmpfs-backed path with
#     restrictive permissions, then `exec`s the original argv. Proves argv
#     preservation, PID 1 identity, signal forwarding, exit-code propagation,
#     tmpfs / no-swap / fail-before-start semantics, and the shell-free
#     (distroless) case where a shell entrypoint is impossible.
#   * RAW delivery: the orchestrator places a secret file the workload already
#     reads (e.g. postgres `POSTGRES_PASSWORD_FILE`) via a mount, exercising the
#     LSM's volume/label behaviour (:Z/:z SELinux contexts, AppArmor bind/tmpfs).
#
# It NEVER disables or loosens an LSM, reads a real secret, or emits raw payloads.
# The "secrets" are random synthetic tokens. It writes bounded JSONL events to
# stdout only; the lane driver maps the final `end` event onto the five
# wrapper.* terminals. The runner alone finalizes the retained run.
#
# The five terminals (see phase1.lock.toml [suites.wrapper-feasibility]):
#   wrapper.argv               shell vs exec argv form; argv preservation; PID 1
#   wrapper.pid1-signals-exit  SIGTERM forwarding + child exit-code propagation
#   wrapper.tmpfs-and-cleanup  tmpfs delivery, no-swap, fail-before-start, cleanup
#   wrapper.lsm                labels/mounts under the lane's LSM, confinement on
#   wrapper.platform           alpine/glibc/distroless families + postgres accept
#
# A terminal PASSes when every SUPPORTED shape works AND every UNSUPPORTED shape
# fails actionably (a specific error before the workload starts) -- an actionable
# fail-closed is a pass, never a silent degradation.

# Many container CMD strings are single-quoted ON PURPOSE: `$$`, `$#`, `$1`, and
# `$BASIL_SECRET_VALUE` must expand inside the GUEST container's shell, not here.
# shellcheck disable=SC2016
set -euo pipefail

readonly SCHEMA_VERSION="basil.compose.phase1.wrapper-feasibility/v1"

runtime=""
lane_id="native-x86_64"
run_id="wrapper-feasibility-$(date -u +%Y%m%dT%H%M%SZ)-$$"
images_dir=""
busybox=""
lsm="none"
workdir=""
arch_mode="full"
seq=0

usage() {
  printf '%s\n' \
    'usage: wrapper-feasibility.sh --runtime docker|podman --images-dir DIR [--busybox PATH]' \
    '            [--lsm selinux|apparmor|none] [--lane-id ID] [--run-id ID] [--workdir DIR]' \
    '            [--arch-mode full|functional]' >&2
}

while (($# > 0)); do
  case "$1" in
    --runtime) (($# >= 2)) || { usage; exit 2; }; runtime=$2; shift 2 ;;
    --lane-id) (($# >= 2)) || { usage; exit 2; }; lane_id=$2; shift 2 ;;
    --run-id) (($# >= 2)) || { usage; exit 2; }; run_id=$2; shift 2 ;;
    --images-dir) (($# >= 2)) || { usage; exit 2; }; images_dir=$2; shift 2 ;;
    --busybox) (($# >= 2)) || { usage; exit 2; }; busybox=$2; shift 2 ;;
    --lsm) (($# >= 2)) || { usage; exit 2; }; lsm=$2; shift 2 ;;
    --workdir) (($# >= 2)) || { usage; exit 2; }; workdir=$2; shift 2 ;;
    --arch-mode) (($# >= 2)) || { usage; exit 2; }; arch_mode=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done

case "$runtime" in docker|podman) ;; *) printf 'invalid --runtime: %s\n' "$runtime" >&2; exit 2 ;; esac
case "$lsm" in selinux|apparmor|none) ;; *) printf 'invalid --lsm: %s\n' "$lsm" >&2; exit 2 ;; esac
command -v jq >/dev/null 2>&1 || { printf 'wrapper-feasibility requires jq\n' >&2; exit 2; }
command -v "$runtime" >/dev/null 2>&1 || { printf 'runtime CLI missing: %s\n' "$runtime" >&2; exit 2; }
[[ -n $images_dir && -d $images_dir ]] || { printf 'images dir missing: %s\n' "$images_dir" >&2; exit 2; }
[[ -n $workdir ]] || workdir=$(mktemp -d)
mkdir -p "$workdir"

run_id=${run_id:0:128}
lane_id=${lane_id:0:128}

RT=$runtime
# SELinux relabel suffix for shared read-only helper mounts; only meaningful on
# SELinux hosts (Docker on a non-SELinux host rejects/ignores :z).
Z=""
[[ $lsm == selinux ]] && Z=",z"

WRAP_C=/basil/wrapper           # in-container wrapper path
BB_C=/basil/busybox             # in-container static busybox path
WRAP_H="$workdir/wrapper.sh"    # host-side wrapper source (bind-mounted ro)
SECRET="basilsecret-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"

declare -A IMG=()               # family -> loaded image ref
declare -a CREATED=()           # container names for guaranteed teardown

cleanup() {
  local jobpids name
  jobpids=$(jobs -p 2>/dev/null || true)
  # shellcheck disable=SC2086
  [[ -n $jobpids ]] && kill $jobpids 2>/dev/null || true
  for name in "${CREATED[@]:-}"; do
    [[ -n $name ]] && "$RT" rm -f "$name" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

emit_event() {
  # emit_event EVENT STATUS REASON DATA_JSON
  local event=$1 status=$2 reason=$3 data=$4
  seq=$((seq + 1))
  jq -cn \
    --arg sv "$SCHEMA_VERSION" --arg run_id "$run_id" --arg lane_id "$lane_id" \
    --argjson seq "$seq" --arg event "$event" --arg status "$status" \
    --arg reason "$reason" --arg runtime "$RT" --argjson data "$data" \
    '{schema_version:$sv,run_id:$run_id,lane_id:$lane_id,seq:$seq,event:$event,
      status:$status,reason_code:$reason,runtime:$runtime,data:$data}'
}

declare -A VERDICT VREASON
set_v() { VERDICT[$1]=$2; VREASON[$1]=${3:0:400}; }

# ---- the wrapper prototype (written to the guest, bind-mounted read-only) -----
# Dependency-light POSIX sh: builtins only, plus an optional injected busybox
# ($BASIL_BB) for chmod/chown, so it runs unchanged under busybox ash (Alpine),
# bash/dash (Debian, Postgres), and a static busybox injected into a shell-free
# image (distroless). BASIL_WRAP_MODE selects the invocation shape:
#   exec   -> `exec "$@"`               (workload becomes PID 1; the correct shape)
#   noexec -> `"$@" & wait`             (wrapper shell stays PID 1; no forwarding)
write_wrapper() {
  cat >"$WRAP_H" <<'WRAP_EOF'
#!/bin/sh
# Basil entrypoint-interposition wrapper prototype (feasibility; SYNTHETIC secret,
# never a real credential).
set -eu
fatal() { c=$1; shift; printf 'basil-wrapper: FATAL %s\n' "$*" >&2; exit "$c"; }

DEST=${BASIL_SECRET_DEST:-}
[ -n "$DEST" ] || fatal 97 "BASIL_SECRET_DEST unset; refusing to start workload"
[ -n "${BASIL_SECRET_VALUE:-}" ] || fatal 97 "no secret material (BASIL_SECRET_VALUE); refusing to start workload"

DDIR=${DEST%/*}; [ -n "$DDIR" ] || DDIR=/

# The delivery dir MUST be memory-backed (tmpfs/ramfs): a raw secret must never
# reach a disk-backed layer. Pure-shell longest-prefix match over /proc/mounts.
_fs=""; _best=-1
while read -r _dev _mp _t _rest; do
  case "$DDIR" in
    "$_mp"|"$_mp"/*) _l=${#_mp}; if [ "$_l" -gt "$_best" ]; then _best=$_l; _fs=$_t; fi ;;
  esac
done < /proc/mounts
case "$_fs" in
  tmpfs|ramfs) : ;;
  *) fatal 96 "delivery dir $DDIR is '${_fs:-unknown}', not tmpfs/ramfs; refusing (secret must be memory-backed)" ;;
esac

umask 077
printf '%s' "$BASIL_SECRET_VALUE" > "$DEST" || fatal 94 "cannot write $DEST"
if [ -n "${BASIL_BB:-}" ] && [ -x "${BASIL_BB:-}" ]; then
  "$BASIL_BB" chmod 0400 "$DEST" 2>/dev/null || true
  [ -n "${BASIL_SECRET_OWNER:-}" ] && "$BASIL_BB" chown "$BASIL_SECRET_OWNER" "$DEST" 2>/dev/null || true
else
  chmod 0400 "$DEST" 2>/dev/null || true
  [ -n "${BASIL_SECRET_OWNER:-}" ] && chown "$BASIL_SECRET_OWNER" "$DEST" 2>/dev/null || true
fi
unset BASIL_SECRET_VALUE

case "${BASIL_WRAP_MODE:-exec}" in
  exec)   exec "$@" ;;
  noexec) "$@" & _c=$!; wait "$_c"; exit $? ;;
  *) fatal 93 "unknown BASIL_WRAP_MODE ${BASIL_WRAP_MODE:-}" ;;
esac
WRAP_EOF
  # The wrapper is bind-mounted read-only as the container entrypoint, so it must
  # be executable (crun/runc refuse a non-executable entrypoint).
  chmod 0755 "$WRAP_H"
}

# ---- image loading -----------------------------------------------------------
load_images() {
  local f out ref base fam n=0
  for f in "$images_dir"/*.tar.gz "$images_dir"/*.tar; do
    [[ -f $f ]] || continue
    out=$("$RT" load -i "$f" 2>&1) || { emit_event image_load INFRA_ERROR IMAGE_LOAD_FAILED \
      "$(jq -cn --arg f "$(basename "$f")" --arg o "${out:0:200}" '{file:$f,error:$o}')"; continue; }
    ref=$(printf '%s\n' "$out" | sed -n 's/.*[Ll]oaded image[s]*: *//p' | head -1 | tr -d '\r')
    base=$(basename "$f"); base=${base%.tar.gz}; base=${base%.tar}
    fam=${base%%-*}
    [[ -n $ref ]] || ref="basil.local/wf/$fam:wf"
    IMG[$fam]=$ref
    n=$((n + 1))
    emit_event image_load INFO IMAGE_LOADED \
      "$(jq -cn --arg fam "$fam" --arg ref "$ref" '{family:$fam,ref:$ref}')"
  done
  return 0
}

# ============================================================================
# wrapper.argv : exec-form transfers PID 1 and preserves argv (incl. spaces);
#                a non-exec (shell) form leaves the wrapper shell as PID 1.
# ============================================================================
exp_argv() {
  local t=wrapper.argv img=${IMG[alpine]:-}
  [[ -n $img ]] || { set_v "$t" FAIL "alpine image not loaded"; emit_event argv INFRA_ERROR ALPINE_MISSING '{}'; return 0; }

  local exec_out noexec_out
  exec_out=$("$RT" run --rm --tmpfs /s:mode=0700 -v "$WRAP_H:$WRAP_C:ro$Z" \
    -e BASIL_SECRET_DEST=/s/x -e BASIL_SECRET_VALUE="$SECRET" -e BASIL_WRAP_MODE=exec \
    --entrypoint "$WRAP_C" "$img" \
    /bin/sh -c 'printf "SELFPID=%s ARGC=%s A1=[%s] A2=[%s]\n" "$$" "$#" "$1" "$2"' \
    basil-argv "alpha beta" gamma 2>&1) || exec_out="ERR:$exec_out"

  noexec_out=$("$RT" run --rm --tmpfs /s:mode=0700 -v "$WRAP_H:$WRAP_C:ro$Z" \
    -e BASIL_SECRET_DEST=/s/x -e BASIL_SECRET_VALUE="$SECRET" -e BASIL_WRAP_MODE=noexec \
    --entrypoint "$WRAP_C" "$img" \
    /bin/sh -c 'printf "SELFPID=%s ARGC=%s A1=[%s]\n" "$$" "$#" "$1"' \
    basil-argv "alpha beta" gamma 2>&1) || noexec_out="ERR:$noexec_out"

  local exec_pid1=no exec_preserved=no noexec_child=no
  case "$exec_out" in *"SELFPID=1 "*) exec_pid1=yes ;; esac
  case "$exec_out" in *"ARGC=2 A1=[alpha beta] A2=[gamma]"*) exec_preserved=yes ;; esac
  # non-exec: workload is a child, so its PID is not 1.
  case "$noexec_out" in *"SELFPID=1 "*) noexec_child=no ;; *"SELFPID="*) noexec_child=yes ;; esac

  if [[ $exec_pid1 == yes && $exec_preserved == yes && $noexec_child == yes ]]; then
    set_v "$t" PASS "exec-form: workload PID1 + argv preserved (incl. spaces); non-exec: wrapper shell stays PID1"
  else
    set_v "$t" FAIL "exec_pid1=$exec_pid1 exec_preserved=$exec_preserved noexec_child=$noexec_child"
  fi
  emit_event argv "$([[ ${VERDICT[$t]} == PASS ]] && echo PASS || echo TEST_FAIL)" ARGV_FORM_AND_PID1 \
    "$(jq -cn --arg e "$exec_out" --arg n "$noexec_out" \
        --arg ep "$exec_pid1" --arg epr "$exec_preserved" --arg nc "$noexec_child" \
        '{exec_form:$e,noexec_form:$n,exec_is_pid1:$ep,exec_argv_preserved:$epr,noexec_workload_is_child:$nc,
          note:"exec \"$@\" transfers PID 1 to the workload and preserves the argv vector exactly; a shell wrapper that does not exec stays PID 1 and reduces the workload to a child"}')"
}

# ============================================================================
# wrapper.pid1-signals-exit : exec-form forwards SIGTERM + propagates exit code;
#                             a non-exec shell PID 1 ignores SIGTERM (must SIGKILL).
# ============================================================================
exp_signals() {
  local t=wrapper.pid1-signals-exit img=${IMG[alpine]:-}
  [[ -n $img ]] || { set_v "$t" FAIL "alpine image not loaded"; emit_event signals INFRA_ERROR ALPINE_MISSING '{}'; return 0; }

  # (1) exec-form graceful SIGTERM: workload traps TERM, prints marker, exits 0.
  local gname=wf-sig-exec glogs gcode gdt t0
  CREATED+=("$gname"); "$RT" rm -f "$gname" >/dev/null 2>&1 || true
  "$RT" run -d --name "$gname" --tmpfs /s:mode=0700 -v "$WRAP_H:$WRAP_C:ro$Z" \
    -e BASIL_SECRET_DEST=/s/x -e BASIL_SECRET_VALUE="$SECRET" -e BASIL_WRAP_MODE=exec \
    --entrypoint "$WRAP_C" "$img" \
    /bin/sh -c 'trap "echo GOT_TERM; exit 0" TERM; echo READY; while :; do sleep 1; done' >/dev/null 2>&1 || true
  _wait_log "$gname" READY 20
  t0=$SECONDS
  "$RT" stop --time 6 "$gname" >/dev/null 2>&1 || true
  gdt=$((SECONDS - t0))
  gcode=$("$RT" inspect --format '{{.State.ExitCode}}' "$gname" 2>/dev/null || echo -1)
  glogs=$("$RT" logs "$gname" 2>&1 || true)
  "$RT" rm -f "$gname" >/dev/null 2>&1 || true
  local graceful=no
  case "$glogs" in *GOT_TERM*) [[ $gcode == 0 && $gdt -lt 6 ]] && graceful=yes ;; esac

  # (2) exit-code propagation: exec-form workload exits 42 -> container exit 42.
  local ecode
  "$RT" run --rm --tmpfs /s:mode=0700 -v "$WRAP_H:$WRAP_C:ro$Z" \
    -e BASIL_SECRET_DEST=/s/x -e BASIL_SECRET_VALUE="$SECRET" -e BASIL_WRAP_MODE=exec \
    --entrypoint "$WRAP_C" "$img" /bin/sh -c 'exit 42' >/dev/null 2>&1
  ecode=$?
  local exit_prop=no; [[ $ecode == 42 ]] && exit_prop=yes

  # (3) non-exec shell PID 1 ignores SIGTERM -> stop must SIGKILL after the grace.
  local nname=wf-sig-noexec ncode ndt n0
  CREATED+=("$nname"); "$RT" rm -f "$nname" >/dev/null 2>&1 || true
  "$RT" run -d --name "$nname" --tmpfs /s:mode=0700 -v "$WRAP_H:$WRAP_C:ro$Z" \
    -e BASIL_SECRET_DEST=/s/x -e BASIL_SECRET_VALUE="$SECRET" -e BASIL_WRAP_MODE=noexec \
    --entrypoint "$WRAP_C" "$img" \
    /bin/sh -c 'echo READY; while :; do sleep 1; done' >/dev/null 2>&1 || true
  _wait_log "$nname" READY 20
  n0=$SECONDS
  "$RT" stop --time 3 "$nname" >/dev/null 2>&1 || true
  ndt=$((SECONDS - n0))
  ncode=$("$RT" inspect --format '{{.State.ExitCode}}' "$nname" 2>/dev/null || echo -1)
  "$RT" rm -f "$nname" >/dev/null 2>&1 || true
  # SIGKILL after grace -> exit 137 and the stop consumed the full grace window.
  local noexec_ignored=no
  [[ $ncode == 137 && $ndt -ge 3 ]] && noexec_ignored=yes

  if [[ $graceful == yes && $exit_prop == yes && $noexec_ignored == yes ]]; then
    set_v "$t" PASS "exec-form forwards SIGTERM (exit 0, ${gdt}s) + propagates exit 42; non-exec shell PID1 ignores SIGTERM (exit 137 after ${ndt}s grace)"
  else
    set_v "$t" FAIL "graceful=$graceful(code=$gcode dt=${gdt}s) exit_prop=$exit_prop(code=$ecode) noexec_ignored=$noexec_ignored(code=$ncode dt=${ndt}s)"
  fi
  emit_event signals "$([[ ${VERDICT[$t]} == PASS ]] && echo PASS || echo TEST_FAIL)" PID1_SIGNAL_AND_EXIT \
    "$(jq -cn --arg gr "$graceful" --argjson gc "$gcode" --argjson gd "$gdt" \
        --arg ep "$exit_prop" --argjson ec "$ecode" \
        --arg ni "$noexec_ignored" --argjson nc "$ncode" --argjson nd "$ndt" \
        '{exec_graceful_term:$gr,exec_exit_code:$gc,exec_stop_seconds:$gd,
          exit_code_propagated:$ep,propagated_code:$ec,
          noexec_ignores_term:$ni,noexec_exit_code:$nc,noexec_stop_seconds:$nd,
          note:"only exec-form makes the workload PID 1, so only exec-form receives the runtime SIGTERM and propagates the workload exit code; a non-exec shell PID 1 ignores SIGTERM (PID 1 signal semantics) and forces a SIGKILL"}')"
}

_wait_log() { # name marker timeout_s
  local name=$1 marker=$2 d=$((SECONDS + $3))
  while (( SECONDS < d )); do
    "$RT" logs "$name" 2>&1 | grep -q "$marker" && return 0
    "$RT" inspect --format '{{.State.Running}}' "$name" 2>/dev/null | grep -q true || break
    sleep 1
  done
  return 1
}

# ============================================================================
# wrapper.tmpfs-and-cleanup : tmpfs-backed 0400 delivery + env scrub; no active
#                             swap; fail-before-start on missing secret / non-tmpfs
#                             dest; no host-side residue after teardown.
# ============================================================================
exp_tmpfs() {
  local t=wrapper.tmpfs-and-cleanup img=${IMG[alpine]:-}
  [[ -n $img ]] || { set_v "$t" FAIL "alpine image not loaded"; emit_event tmpfs INFRA_ERROR ALPINE_MISSING '{}'; return 0; }

  # (1) tmpfs delivery, 0400, content match, env scrub.
  local dout
  dout=$("$RT" run --rm --tmpfs /s:mode=0700 -v "$WRAP_H:$WRAP_C:ro$Z" \
    -e BASIL_SECRET_DEST=/s/x -e BASIL_SECRET_VALUE="$SECRET" -e BASIL_WRAP_MODE=exec \
    --entrypoint "$WRAP_C" "$img" \
    /bin/sh -c '
      ft=unknown; grep -q " /s tmpfs " /proc/mounts && ft=tmpfs
      m=$(stat -c %a /s/x 2>/dev/null)
      v=$(cat /s/x 2>/dev/null)
      env_leak=leaked; [ -z "${BASIL_SECRET_VALUE:-}" ] && env_leak=scrubbed
      printf "FT=%s MODE=%s MATCH=%s ENV=%s\n" "$ft" "$m" "$([ "$v" = "'"$SECRET"'" ] && echo yes || echo no)" "$env_leak"
    ' 2>&1) || dout="ERR:$dout"
  local deliver=no
  case "$dout" in *"FT=tmpfs MODE=400 MATCH=yes ENV=scrubbed"*) deliver=yes ;; esac

  # (2) no-swap semantics: mount the delivery tmpfs `noswap` (Linux >= 6.4) so its
  # pages are never paged out to disk EVEN WHEN the host has active swap. We also
  # record the host swap state; swap is "safe" if the delivery is noswap-backed or
  # the host has no swap at all.
  local swaplines swap=present noswap_out noswap_ok=no swap_safe=no
  swaplines=$(( $(wc -l < /proc/swaps 2>/dev/null || echo 1) - 1 ))
  [[ ${swaplines:-1} -le 0 ]] && swap=none
  noswap_out=$("$RT" run --rm --tmpfs /s:mode=0700,noswap -v "$WRAP_H:$WRAP_C:ro$Z" \
    -e BASIL_SECRET_DEST=/s/x -e BASIL_SECRET_VALUE="$SECRET" -e BASIL_WRAP_MODE=exec \
    --entrypoint "$WRAP_C" "$img" /bin/sh -c 'grep -m1 " /s " /proc/mounts' 2>&1 || true)
  case "$noswap_out" in *noswap*) noswap_ok=yes ;; esac
  { [[ $noswap_ok == yes ]] || [[ $swap == none ]]; } && swap_safe=yes

  # (3) fail-before-start: missing secret -> wrapper exits 97, workload never runs.
  local mrc mlogs mname=wf-fail-nosrc
  mlogs=$("$RT" run --name "$mname" --tmpfs /s:mode=0700 -v "$WRAP_H:$WRAP_C:ro$Z" \
    -e BASIL_SECRET_DEST=/s/x -e BASIL_WRAP_MODE=exec \
    --entrypoint "$WRAP_C" "$img" /bin/sh -c 'echo WORKLOAD_RAN' 2>&1) && mrc=0 || mrc=$?
  "$RT" rm -f "$mname" >/dev/null 2>&1 || true
  local fail_nosrc=no
  { [[ $mrc == 97 ]] && ! grep -q WORKLOAD_RAN <<<"$mlogs"; } && fail_nosrc=yes

  # (4) fail-before-start: dest on a non-tmpfs path -> wrapper exits 96.
  local trc tlogs tname=wf-fail-nontmpfs
  tlogs=$("$RT" run --name "$tname" -v "$WRAP_H:$WRAP_C:ro$Z" \
    -e BASIL_SECRET_DEST=/etc/basil-x -e BASIL_SECRET_VALUE="$SECRET" -e BASIL_WRAP_MODE=exec \
    --entrypoint "$WRAP_C" "$img" /bin/sh -c 'echo WORKLOAD_RAN' 2>&1) && trc=0 || trc=$?
  "$RT" rm -f "$tname" >/dev/null 2>&1 || true
  local fail_nontmpfs=no
  { [[ $trc == 96 ]] && ! grep -q WORKLOAD_RAN <<<"$tlogs"; } && fail_nontmpfs=yes

  # (5) cleanup: no wf-* container or secret residue remains after teardown.
  local residue=none leftover
  leftover=$("$RT" ps -a --format '{{.Names}}' 2>/dev/null | grep -c '^wf-' || true)
  [[ ${leftover:-0} -ne 0 ]] && residue="containers:$leftover"
  [[ -e $workdir/x || -e /s/x ]] && residue="host-secret-file"

  if [[ $deliver == yes && $swap_safe == yes && $fail_nosrc == yes && $fail_nontmpfs == yes && $residue == none ]]; then
    set_v "$t" PASS "tmpfs 0400 delivery + env scrub; no-swap safe (noswap=$noswap_ok host_swap=$swap); fail-before-start on missing-secret (97) and non-tmpfs (96); no residue"
  else
    set_v "$t" FAIL "deliver=$deliver swap_safe=$swap_safe(noswap=$noswap_ok host_swap=$swap) fail_nosrc=$fail_nosrc fail_nontmpfs=$fail_nontmpfs residue=$residue"
  fi
  emit_event tmpfs "$([[ ${VERDICT[$t]} == PASS ]] && echo PASS || echo TEST_FAIL)" TMPFS_NOSWAP_FAILCLOSED \
    "$(jq -cn --arg d "$dout" --arg dl "$deliver" --arg sw "$swap" --arg ns "$noswap_ok" --arg ss "$swap_safe" \
        --arg fn "$fail_nosrc" --argjson mrc "$mrc" --arg ft "$fail_nontmpfs" --argjson trc "$trc" \
        --arg res "$residue" \
        '{delivery_probe:$d,tmpfs_0400_scrub:$dl,host_swap:$sw,delivery_tmpfs_noswap:$ns,no_swap_safe:$ss,
          fail_before_start_missing_secret:{ok:$fn,wrapper_exit:$mrc},
          fail_before_start_non_tmpfs:{ok:$ft,wrapper_exit:$trc},
          residue:$res,
          note:"delivery is memory-backed (tmpfs, 0400, env-scrubbed); the delivery tmpfs is mounted noswap so pages never reach disk even under host swap; a delivery failure exits the wrapper with a specific code BEFORE the workload starts"}')"
}

# ============================================================================
# wrapper.lsm : labels/mounts work under the lane's LSM with confinement enabled
#               throughout; unlabeled shapes fail actionably (SELinux).
# ============================================================================
exp_lsm() {
  local t=wrapper.lsm img=${IMG[alpine]:-}
  [[ -n $img ]] || { set_v "$t" FAIL "alpine image not loaded"; emit_event lsm INFRA_ERROR ALPINE_MISSING '{}'; return 0; }
  printf 'RAWLABELTEST-%s' "$SECRET" >"$workdir/rawsecret"

  if [[ $lsm == selinux ]]; then
    exp_lsm_selinux "$t" "$img"
  elif [[ $lsm == apparmor ]]; then
    exp_lsm_apparmor "$t" "$img"
  else
    set_v "$t" FAIL "lane declares no LSM (lsm=none) but wrapper.lsm requires an enforcing LSM"
    emit_event lsm TEST_FAIL LSM_NOT_DECLARED '{}'
  fi
}

exp_lsm_selinux() {
  local t=$1 img=$2 enforce_before enforce_after label nolabel_out nolabel_denied=no zlabel_out z_ok=no
  enforce_before=$(getenforce 2>/dev/null || echo unknown)
  label=$("$RT" run --rm "$img" cat /proc/1/attr/current 2>/dev/null | tr -d '\000' || echo "")
  # Raw bind WITHOUT a relabel option: the container_t process cannot read the
  # host file's non-container label -> permission denied (the actionable shape).
  nolabel_out=$("$RT" run --rm -v "$workdir/rawsecret:/run/rs:ro" "$img" \
    /bin/sh -c 'cat /run/rs 2>&1' 2>&1 || true)
  case "$nolabel_out" in *"Permission denied"*|*"permission denied"*) nolabel_denied=yes ;; esac
  # Raw bind WITH :z (shared relabel): now readable.
  zlabel_out=$("$RT" run --rm -v "$workdir/rawsecret:/run/rs:ro,z" "$img" \
    /bin/sh -c 'cat /run/rs 2>&1' 2>&1 || true)
  case "$zlabel_out" in "RAWLABELTEST-$SECRET") z_ok=yes ;; esac
  enforce_after=$(getenforce 2>/dev/null || echo unknown)

  local container_t=no; case "$label" in *container_t*) container_t=yes ;; esac
  if [[ $enforce_before == Enforcing && $enforce_after == Enforcing && $container_t == yes \
        && $nolabel_denied == yes && $z_ok == yes ]]; then
    set_v "$t" PASS "SELinux Enforcing throughout; process label container_t; unlabeled bind DENIED (actionable); :z relabel bind readable"
  else
    set_v "$t" FAIL "enforce=$enforce_before/$enforce_after container_t=$container_t nolabel_denied=$nolabel_denied z_ok=$z_ok"
  fi
  emit_event lsm "$([[ ${VERDICT[$t]} == PASS ]] && echo PASS || echo TEST_FAIL)" SELINUX_LABEL_MOUNT \
    "$(jq -cn --arg eb "$enforce_before" --arg ea "$enforce_after" --arg lbl "$label" \
        --arg ct "$container_t" --arg nd "$nolabel_denied" --arg zo "$z_ok" \
        --arg no "${nolabel_out:0:160}" \
        '{kind:"selinux",enforce_before:$eb,enforce_after:$ea,process_label:$lbl,container_t:$ct,
          unlabeled_bind_denied:$nd,unlabeled_bind_error:$no,relabel_z_bind_readable:$zo,
          note:"SELinux stays Enforcing; an unrelabeled host bind is denied to container_t (fail actionable), and :z (shared) relabel makes it readable -- delivery mounts work without weakening the LSM"}')"
}

exp_lsm_apparmor() {
  local t=$1 img=$2 aa_enabled attr profile bind_out bind_ok=no tmpfs_out tmpfs_ok=no
  aa_enabled=$(tr -d '\n' </sys/module/apparmor/parameters/enabled 2>/dev/null || echo "")
  local pname=wf-aa
  CREATED+=("$pname"); "$RT" rm -f "$pname" >/dev/null 2>&1 || true
  "$RT" run -d --name "$pname" "$img" /bin/sh -c 'while :; do sleep 1; done' >/dev/null 2>&1 || true
  attr=$("$RT" exec "$pname" cat /proc/1/attr/current 2>/dev/null | tr -d '\000' || echo "")
  profile=$("$RT" inspect --format '{{.AppArmorProfile}}' "$pname" 2>/dev/null || echo "")
  "$RT" rm -f "$pname" >/dev/null 2>&1 || true
  # bind + tmpfs mounts work under docker-default (no profile change, no relabel).
  bind_out=$("$RT" run --rm -v "$workdir/rawsecret:/run/rs:ro" "$img" \
    /bin/sh -c 'cat /run/rs 2>&1' 2>&1 || true)
  case "$bind_out" in "RAWLABELTEST-$SECRET") bind_ok=yes ;; esac
  tmpfs_out=$("$RT" run --rm --tmpfs /s:mode=0700 -v "$WRAP_H:$WRAP_C:ro" \
    -e BASIL_SECRET_DEST=/s/x -e BASIL_SECRET_VALUE="$SECRET" -e BASIL_WRAP_MODE=exec \
    --entrypoint "$WRAP_C" "$img" /bin/sh -c 'cat /s/x' 2>&1 || true)
  case "$tmpfs_out" in "$SECRET") tmpfs_ok=yes ;; esac

  local enforce=no; case "$attr" in *docker-default*|*"(enforce)"*) enforce=yes ;; esac
  local prof_ok=no; [[ $profile == docker-default ]] && prof_ok=yes
  if [[ $aa_enabled == Y && $enforce == yes && $prof_ok == yes && $bind_ok == yes && $tmpfs_ok == yes ]]; then
    set_v "$t" PASS "AppArmor enabled; container confined by docker-default (enforce); bind + tmpfs delivery mounts work with no profile change"
  else
    set_v "$t" FAIL "aa=$aa_enabled enforce=$enforce profile=$profile bind_ok=$bind_ok tmpfs_ok=$tmpfs_ok"
  fi
  emit_event lsm "$([[ ${VERDICT[$t]} == PASS ]] && echo PASS || echo TEST_FAIL)" APPARMOR_PROFILE_MOUNT \
    "$(jq -cn --arg aa "$aa_enabled" --arg attr "$attr" --arg prof "$profile" \
        --arg bo "$bind_ok" --arg to "$tmpfs_ok" \
        '{kind:"apparmor",kernel_enabled:$aa,proc1_attr:$attr,inspect_profile:$prof,
          bind_mount_readable:$bo,tmpfs_delivery_readable:$to,
          note:"the container stays confined by docker-default (enforce); bind and tmpfs delivery mounts work with no profile change; :Z/:z relabeling is SELinux-specific and is a no-op under AppArmor"}')"
}

# ============================================================================
# wrapper.platform : image families (musl/glibc/shell-free) + postgres accept.
# ============================================================================
exp_platform() {
  local t=wrapper.platform
  local alpine_ok debian_ok distro_shell_refused distro_static_ok pg_verdict
  alpine_ok=$(family_delivery alpine "/bin/sh")
  debian_ok=$(family_delivery debian "/bin/sh")
  distro_probe_and_deliver   # sets DISTRO_SHELL_REFUSED, DISTRO_STATIC_OK
  distro_shell_refused=$DISTRO_SHELL_REFUSED
  distro_static_ok=$DISTRO_STATIC_OK
  postgres_acceptance        # sets PG_OK, PG_DETAIL
  pg_verdict=$PG_OK

  if [[ $alpine_ok == yes && $debian_ok == yes && $distro_shell_refused == yes \
        && $distro_static_ok == yes && $pg_verdict == yes ]]; then
    set_v "$t" PASS "alpine(musl) works; debian(glibc) works; distroless shell-wrapper refused actionably + static-injected wrapper works; postgres:18 unmodified accepts delivered credential"
  else
    set_v "$t" FAIL "alpine=$alpine_ok debian=$debian_ok distroless_shell_refused=$distro_shell_refused distroless_static=$distro_static_ok postgres=$pg_verdict ($PG_DETAIL)"
  fi
  emit_event platform "$([[ ${VERDICT[$t]} == PASS ]] && echo PASS || echo TEST_FAIL)" IMAGE_FAMILY_MATRIX \
    "$(jq -cn --arg a "$alpine_ok" --arg d "$debian_ok" \
        --arg dr "$distro_shell_refused" --arg ds "$distro_static_ok" \
        --arg pg "$pg_verdict" --arg pgd "$PG_DETAIL" --arg arch "$arch_mode" \
        '{alpine_musl:$a,debian_glibc:$d,distroless_shell_refused_actionable:$dr,
          distroless_static_wrapper:$ds,postgres_acceptance:$pg,postgres_detail:$pgd,arch_mode:$arch,
          note:"shell entrypoint interposition works on shell-bearing images (musl/glibc) and is impossible on shell-free images (distroless), where it fails actionably; the supported shell-free shapes are a static injected wrapper or raw file delivery"}')"
}

family_delivery() { # family sh -> echo yes|no
  local fam=$1 shbin=$2 img=${IMG[$1]:-} out
  [[ -n $img ]] || { echo "no"; return 0; }
  out=$("$RT" run --rm --tmpfs /s:mode=0700 -v "$WRAP_H:$WRAP_C:ro$Z" \
    -e BASIL_SECRET_DEST=/s/x -e BASIL_SECRET_VALUE="$SECRET" -e BASIL_WRAP_MODE=exec \
    --entrypoint "$WRAP_C" "$img" "$shbin" -c 'cat /s/x' 2>&1 || true)
  [[ $out == "$SECRET" ]] && echo yes || echo no
}

DISTRO_SHELL_REFUSED=no
DISTRO_STATIC_OK=no
distro_probe_and_deliver() {
  local img=${IMG[distroless]:-} probe_rc probe_out static_out
  DISTRO_SHELL_REFUSED=no; DISTRO_STATIC_OK=no
  [[ -n $img ]] || { emit_event distroless INFRA_ERROR DISTROLESS_MISSING '{}'; return 0; }

  # Actionable preflight: a shell entrypoint is impossible on a shell-free image.
  probe_out=$("$RT" run --rm --entrypoint /bin/sh "$img" -c 'true' 2>&1) && probe_rc=0 || probe_rc=$?
  [[ $probe_rc -ne 0 ]] && DISTRO_SHELL_REFUSED=yes

  # Supported shell-free shape: inject a static busybox as the entrypoint that
  # runs the wrapper, deliver to tmpfs, then exec a static workload reading it.
  if [[ -n $busybox && -f $busybox ]]; then
    static_out=$("$RT" run --rm --tmpfs /s:mode=0700 \
      -v "$WRAP_H:$WRAP_C:ro$Z" -v "$busybox:$BB_C:ro$Z" \
      -e BASIL_SECRET_DEST=/s/x -e BASIL_SECRET_VALUE="$SECRET" -e BASIL_WRAP_MODE=exec -e BASIL_BB="$BB_C" \
      --entrypoint "$BB_C" "$img" \
      sh "$WRAP_C" "$BB_C" cat /s/x 2>&1 || true)
    [[ $static_out == "$SECRET" ]] && DISTRO_STATIC_OK=yes
  else
    static_out="(no static busybox provided)"
  fi
  emit_event distroless "$([[ $DISTRO_SHELL_REFUSED == yes && $DISTRO_STATIC_OK == yes ]] && echo PASS || echo TEST_FAIL)" \
    DISTROLESS_SHELLFREE \
    "$(jq -cn --arg pr "${probe_out:0:160}" --arg sr "$DISTRO_SHELL_REFUSED" \
        --arg so "$DISTRO_STATIC_OK" \
        '{shell_entrypoint_probe:$pr,shell_wrapper_refused_actionable:$sr,static_injected_wrapper_ok:$so,
          note:"distroless/static has no /bin/sh: a shell entrypoint fails at start with a specific exec error; the supported shape injects a static wrapper (or uses raw file delivery)"}')"
}

PG_OK=no
PG_DETAIL=""
postgres_acceptance() {
  local img=${IMG[postgres]:-} name=wf-postgres pgpw ready=no uid pid1uid confined=no attr label authok=no
  PG_OK=no; PG_DETAIL=""
  [[ -n $img ]] || { PG_DETAIL="postgres image not loaded"; emit_event postgres INFRA_ERROR POSTGRES_MISSING '{}'; return 0; }
  pgpw="pg-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  CREATED+=("$name"); "$RT" rm -f "$name" >/dev/null 2>&1 || true

  # Record the image's default entrypoint uid (postgres:18 runs as the postgres
  # user by default rather than dropping from root via gosu).
  local default_uid
  default_uid=$("$RT" run --rm "$img" id -u 2>/dev/null | tr -d '\r') || default_uid=""

  # Entrypoint interposition on the UNMODIFIED official image: the wrapper delivers
  # POSTGRES_PASSWORD_FILE to a tmpfs then exec's the original docker-entrypoint.sh
  # chain. postgres:18's entrypoint runs as the non-root postgres uid (999), so the
  # delivery tmpfs is world-writable (the file stays 0400 and is owned to the
  # postgres uid so only it can read it) and PGDATA rides a writable tmpfs -- both
  # work identically under rootless Podman and rootful Docker.
  "$RT" run -d --name "$name" \
    --tmpfs /run/secrets:mode=0777 \
    --tmpfs /pgdata:mode=0777 \
    -v "$WRAP_H:$WRAP_C:ro$Z" \
    -e BASIL_SECRET_DEST=/run/secrets/pgpw -e BASIL_SECRET_VALUE="$pgpw" -e BASIL_WRAP_MODE=exec \
    -e BASIL_SECRET_OWNER=999 \
    -e POSTGRES_PASSWORD_FILE=/run/secrets/pgpw -e POSTGRES_USER=basil -e POSTGRES_DB=basil \
    -e PGDATA=/pgdata/data \
    --entrypoint "$WRAP_C" "$img" \
    docker-entrypoint.sh postgres >/dev/null 2>&1 || { PG_DETAIL="run failed"; }

  for _ in $(seq 1 120); do
    if "$RT" exec "$name" pg_isready -U basil -d basil >/dev/null 2>&1; then ready=yes; break; fi
    "$RT" inspect --format '{{.State.Running}}' "$name" 2>/dev/null | grep -q true || { PG_DETAIL="container exited early"; break; }
    sleep 2
  done

  if [[ $ready == yes ]]; then
    # The main postgres process (PID 1) dropped from root to the postgres uid.
    pid1uid=$("$RT" exec "$name" sh -c 'awk "/^Uid:/{print \$2; exit}" /proc/1/status' 2>/dev/null | tr -d '\r')
    uid=$("$RT" exec "$name" id -un 2>/dev/null | tr -d '\r')
    # The delivered credential actually authenticates a client connection.
    if "$RT" exec -e PGPASSWORD="$pgpw" "$name" psql -U basil -d basil -tAc 'select 1' 2>/dev/null | grep -q '^1$'; then authok=yes; fi
    # Confinement is still enforced on the running workload.
    if [[ $lsm == selinux ]]; then
      label=$("$RT" exec "$name" cat /proc/1/attr/current 2>/dev/null | tr -d '\000')
      case "$label" in *container_t*) confined=yes ;; esac
    elif [[ $lsm == apparmor ]]; then
      attr=$("$RT" inspect --format '{{.AppArmorProfile}}' "$name" 2>/dev/null)
      [[ $attr == docker-default ]] && confined=yes
    else
      confined=yes
    fi
    local nonroot=no; [[ -n $pid1uid && $pid1uid != 0 ]] && nonroot=yes
    if [[ $authok == yes && $nonroot == yes && $confined == yes ]]; then
      PG_OK=yes
      PG_DETAIL="ready; workload runs as non-root PID1 uid=$pid1uid; delivered credential authenticates; confinement enforced"
    else
      PG_DETAIL="ready but authok=$authok nonroot=$nonroot(uid=$pid1uid) confined=$confined"
    fi
  fi
  local logs; logs=$("$RT" logs "$name" 2>&1 | tail -c 600 || true)
  "$RT" rm -f "$name" >/dev/null 2>&1 || true

  emit_event postgres "$([[ $PG_OK == yes ]] && echo PASS || echo TEST_FAIL)" POSTGRES_UNMODIFIED_ACCEPT \
    "$(jq -cn --arg r "$ready" --arg a "$authok" --arg u "${pid1uid:-}" --arg un "${uid:-}" \
        --arg du "${default_uid:-}" --arg c "$confined" --arg d "$PG_DETAIL" --arg l "$logs" \
        '{ready_to_accept_connections:$r,delivered_credential_authenticates:$a,
          image_default_uid:$du,pid1_uid:$u,exec_user:$un,workload_runs_nonroot:($u!="0" and $u!=""),
          confinement_enforced:$c,detail:$d,tail_logs:$l,
          note:"the official postgres:18 image runs unmodified: entrypoint interposition delivers POSTGRES_PASSWORD_FILE to a tmpfs owned by the postgres uid, the docker-entrypoint.sh chain initialises the DB as the non-root postgres user, and a client authenticates with the delivered password -- all with confinement enabled"}')"
}

# ============================================================================
# End event.
# ============================================================================
return_terminals() {
  local all_pass=true t
  local -a keys=(wrapper.argv wrapper.pid1-signals-exit wrapper.tmpfs-and-cleanup wrapper.lsm wrapper.platform)
  local verdicts='{}'
  for t in "${keys[@]}"; do
    local v=${VERDICT[$t]:-FAIL} r=${VREASON[$t]:-not_run}
    [[ $v == PASS ]] || all_pass=false
    verdicts=$(jq -c --arg k "$t" --arg v "$v" --arg r "${r:0:400}" \
      '. + {($k): {verdict:$v, reason:$r}}' <<<"$verdicts")
  done
  emit_event end "$([[ $all_pass == true ]] && echo PASS || echo TEST_FAIL)" WRAPPER_FEASIBILITY_COMPLETE \
    "$(jq -cn --argjson verdicts "$verdicts" --argjson all "$all_pass" \
        '{all_pass:$all,verdicts:$verdicts}')"
}

main() {
  write_wrapper
  emit_event start INFO WRAPPER_FEASIBILITY_START \
    "$(jq -cn --arg rt "$RT" --arg lsm "$lsm" --arg am "$arch_mode" '{runtime:$rt,lsm:$lsm,arch_mode:$am}')"
  load_images
  # Each experiment is isolated in a tested context so a single failure cannot
  # abort the whole run (bash disables errexit inside a function invoked from an
  # || list); every terminal still gets an honest verdict and the end event is
  # always emitted. An un-run terminal defaults to FAIL in return_terminals.
  exp_argv || true
  exp_signals || true
  exp_tmpfs || true
  exp_lsm || true
  exp_platform || true
  return_terminals
  local t
  for t in wrapper.argv wrapper.pid1-signals-exit wrapper.tmpfs-and-cleanup wrapper.lsm wrapper.platform; do
    [[ ${VERDICT[$t]:-FAIL} == PASS ]] || return 1
  done
  return 0
}

main "$@"
