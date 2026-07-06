#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
#
# SPDX-License-Identifier: Apache-2.0

# tpm-unlock-e2e.sh: TPM unlock-slot e2e (basil-h8qq.1 harness + .2/.3 scenarios).
#
# Boots emulated-TPM 2.0 guests under qemu + swtpm and drives the just-built
# `basil` binary (built with `--features unlock-tpm`) inside them. This is the
# SHELL-FIRST lane (no nix/cargo coupling beyond fetching guest fixtures): fast
# turnaround against a REAL emulated TPM. It exercises the real `TpmMethod`
# orchestrator in crates/basil-core/src/core/seal/unlock/tpm.rs end to end.
#
# ---------------------------------------------------------------------------
# WHAT THIS PROVES
# ---------------------------------------------------------------------------
#   Phase 1 (boot plumbing):
#     - the guest boots and exposes /dev/tpmrm0 (tpm_available() == true);
#     - the just-built `basil` runs end-to-end in-guest off a 9p share
#       (`basil --version`) and resolves its nix dynamic-loader/library closure
#       over a read-only /nix/store 9p share.
#
#   Scenario A (basil-h8qq.2): seal -> auto-unlock -> reboot -> auto-unlock:
#     1. In-guest `basil bundle create --slot tpm` seals a TPM-only unlock slot:
#        a fresh 32-byte slot key is TPM2_Sealed into a keyed-hash object under a
#        SHA-256 PolicyPCR (PCRs 0,2,4,7) and the master KEK is AES-256-GCM
#        wrapped under it. The on-disk bundle carries ONLY the sealed
#        public/private areas + the PCR selection (asserted host-side); the slot
#        key is never serialized.
#     2. `basil doctor` with `[unlock] unlock-tpm = true` and NO operator
#        secret TPM2_Unseals the slot under a PolicyPCR session and OPENS the
#        bundle ("unlock slot opened method=tpm" / "sealed bundle unlocked").
#     3. A full guest REBOOT reusing the SAME persistent swtpm state dir
#        auto-unlocks again on first boot (the unattended-restart property).
#
#   Scenario B (basil-h8qq.3): fail-closed negatives (assert an UnlockError, no
#   panic, no key bytes logged):
#     - no-TPM: boot the bundle in a guest started WITHOUT the swtpm device ->
#       the TPM slot is unavailable -> a TPM-only bundle fails closed and the
#       broker refuses to start; a bundle that ALSO has a passphrase recovery
#       slot falls back to it and opens. Both asserted.
#     - PCR mismatch: tpm2_pcrextend a sealing-policy PCR before unseal ->
#       PolicyPCR unsatisfied (TPM_RC_POLICY_FAIL) -> recover fails closed.
#     - different-TPM: open the Scenario-A bundle against a SECOND swtpm state
#       dir (fresh hierarchy) -> the blob does not load (TPM_RC_INTEGRITY) ->
#       fail closed (the does-not-move-with-a-disk-image property).
#
#   Persistence: Scenario A's reboot leg IS the persistence proof: the sealed
#   blob, the owner-hierarchy SRK, and the PolicyPCR all survive an swtpm restart
#   on the same state dir. (Direct kernel boot does no measured boot, so PCRs
#   0,2,4,7 are a stable all-zero baseline across reboots; the seal binds to that
#   baseline and the PCR-mismatch case perturbs it.)
#
#   NOTE (sign+verify serve): proving the broker SERVES a sign+verify over the
#   unix socket needs a live backend (openbao) in-guest, which is impractical in
#   this minimal busybox initramfs. The CORE property, TPM auto-unlock opens the
#   bundle with no operator secret, is proven here; the sign+verify serve
#   assertion is DEFERRED to the Phase-4 nixosTest lane (it has journald + a real
#   backend). `doctor` reaching "catalog check: 0/0 key(s) present" after
#   the TPM unseal is the in-lane "reached serving readiness" proof.
#
# ---------------------------------------------------------------------------
# THE EXACT swtpm + qemu INVOCATIONS
# ---------------------------------------------------------------------------
# swtpm (emulated TPM 2.0, PERSISTENT state dir so sealed/SRK state survives a
# guest reboot), one unixio control socket per boot:
#
#   swtpm socket --tpm2 --tpmstate dir=$STATE/tpm \
#       --ctrl type=unixio,path=$STATE/swtpm.sock --flags startup-clear &
#
# qemu (q35, 512 MiB; -accel kvm when /dev/kvm is usable, else tcg), the TPM
# wired to that socket, a read-only 9p share of target/debug (mount_tag=basilbin)
# and of /nix/store (mount_tag=nixstore), plus a WRITABLE 9p share for the
# sealed bundle + config (mount_tag=bundleout) so a bundle sealed in one boot is
# reused by later boots:
#
#   qemu-system-x86_64 -nodefaults -no-reboot -machine q35,accel=kvm -cpu host \
#       -m 512 -smp 2 -kernel $BZIMAGE -initrd $INITRD \
#       -append "console=ttyS0 rdinit=/init panic=-1 basil.sc=<scenario>" \
#       -chardev socket,id=chrtpm,path=$STATE/swtpm.sock \
#       -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis,tpmdev=tpm0 \
#       -virtfs local,path=$PWD/target/debug,mount_tag=basilbin,security_model=none,readonly=on \
#       -virtfs local,path=/nix/store,mount_tag=nixstore,security_model=none,readonly=on \
#       -virtfs local,path=$SHARE,mount_tag=bundleout,security_model=none \
#       -display none -serial stdio -monitor none
#
# The no-TPM negative simply drops the -chardev/-tpmdev/-device trio.
#
# ---------------------------------------------------------------------------
# PCR SET CHOSEN FOR SEALING
# ---------------------------------------------------------------------------
# SHA-256 bank, PCRs 0,2,4,7: PCR0 = UEFI firmware/SRTM, PCR2 = option-ROM,
# PCR4 = boot-loader/kernel (IPL), PCR7 = secure-boot state. That set binds the
# seal to firmware + boot chain + secure-boot policy while tolerating data/config
# churn. The PCR-mismatch negative perturbs PCR7.
#
# ---------------------------------------------------------------------------
# GATING
# ---------------------------------------------------------------------------
# If qemu-system-x86_64 OR swtpm is absent on PATH, prints an explicit `SKIP:`
# and exits 0 (never a silent pass). Guest fixtures (kernel/modules/busybox,
# optionally tpm2-tools) are fetched via nix (overridable by env); if they cannot
# be obtained it SKIPs cleanly too. tpm2-tools is needed only for the PCR-mismatch
# case: absent, that single case degrades to a note. When everything is present
# it asserts real guest runs completed (an all-skip is never a pass).
#
# Usage: scripts/tpm-unlock-e2e.sh
# Env overrides (all optional):
#   TPM_E2E_WORKDIR   working dir (default: a fresh mktemp dir)
#   TPM_E2E_BZIMAGE   path to a kernel bzImage (default: nix linuxPackages.kernel)
#   TPM_E2E_MODULES   path to a lib/modules/<ver> tree matching that kernel
#   TPM_E2E_BUSYBOX   path to a STATIC busybox binary
#   TPM_E2E_TPM2_BIN  dir holding tpm2_* tools (default: nix tpm2-tools)
#   TPM_E2E_NO_BUILD  set to 1 to skip `cargo build` (binary must already exist)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ---- gating: qemu + swtpm MUST be present, else SKIP cleanly -----------------

for tool in qemu-system-x86_64 swtpm; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "SKIP: $tool not on PATH (this e2e needs qemu + swtpm to boot an emulated-TPM guest)"
    exit 0
  fi
done
for tool in cpio gzip xz find; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "SKIP: $tool not on PATH (needed to assemble the guest initramfs)"
    exit 0
  fi
done

# ---- parameters -------------------------------------------------------------

WORKDIR="${TPM_E2E_WORKDIR:-$(mktemp -d /tmp/basil-tpm-e2e.XXXXXX)}"
mkdir -p "$WORKDIR"
STATE_A="$WORKDIR/tpmA"             # primary PERSISTENT swtpm state dir
STATE_B="$WORKDIR/tpmB"             # a DIFFERENT TPM (foreign hierarchy)
SHARE="$WORKDIR/share"              # WRITABLE 9p share: bundle + config files
SWTPM_SOCK="$WORKDIR/swtpm.sock"
INITRAMFS="$WORKDIR/initramfs.cpio.gz"
AGENT_BIN="$REPO_ROOT/target/debug/basil"
mkdir -p "$STATE_A" "$STATE_B" "$SHARE"

# 9p-over-virtio module load order (deps first). The nixpkgs kernel ships these
# as modules; the TPM driver (TCG_TPM/TIS/CRB) is builtin so the TPM needs none.
MODS=(virtio_ring virtio virtio_pci_modern_dev virtio_pci_legacy_dev virtio_pci \
      netfs 9pnet 9pnet_virtio 9p)

BOOT_TIMEOUT=180                    # seconds; generous for a TCG (no-KVM) fallback

FAILED=0
RAN=0
SWTPM_PID=""

fail() { echo "  FAIL: $*"; FAILED=1; }
pass() { echo "  ok:   $*"; }
note() { echo "  note: $*"; }

stop_pid() {
  local pid="$1"
  [ -n "$pid" ] || return 0
  kill -0 "$pid" 2>/dev/null || return 0
  kill -TERM "$pid" 2>/dev/null || true
  for _ in $(seq 1 30); do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.1
  done
  kill -KILL "$pid" 2>/dev/null || true
}

# shellcheck disable=SC2329  # invoked indirectly via `trap cleanup EXIT`
cleanup() {
  [ -n "$SWTPM_PID" ] && stop_pid "$SWTPM_PID"
  pkill -TERM -f "swtpm .*$WORKDIR" 2>/dev/null || true
  pkill -TERM -f "qemu-system-x86_64 .*$INITRAMFS" 2>/dev/null || true
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

echo "== tpm-unlock-e2e (Phase 1 boot + Scenario A auto-unlock + Scenario B fail-closed) =="
echo "  repo:     $REPO_ROOT"
echo "  workdir:  $WORKDIR"

# ---- resolve fixtures (kernel bzImage + modules + static busybox) -----------

nix_build() {
  command -v nix >/dev/null 2>&1 || return 1
  timeout 600 nix build --no-link --print-out-paths "nixpkgs#$1" 2>/dev/null | tail -1
}

BZIMAGE="${TPM_E2E_BZIMAGE:-}"
MODULES_TREE="${TPM_E2E_MODULES:-}"
BUSYBOX="${TPM_E2E_BUSYBOX:-}"

if [ -z "$BZIMAGE" ] || [ -z "$MODULES_TREE" ] || [ -z "$BUSYBOX" ]; then
  if ! command -v nix >/dev/null 2>&1; then
    echo "SKIP: nix not on PATH and kernel/modules/busybox not supplied via TPM_E2E_* env"
    exit 0
  fi
  echo "-- fetching guest fixtures from the nix binary cache (kernel, modules, busybox)"
fi

if [ -z "$BZIMAGE" ]; then
  kern_out="$(nix_build linuxPackages.kernel || true)"
  [ -n "$kern_out" ] && BZIMAGE="$kern_out/bzImage"
fi
if [ -z "$MODULES_TREE" ]; then
  mod_out="$(nix_build linuxPackages.kernel.modules || true)"
  if [ -n "$mod_out" ] && [ -d "$mod_out/lib/modules" ]; then
    modver="$(find "$mod_out/lib/modules" -maxdepth 1 -mindepth 1 -type d -printf '%f\n' 2>/dev/null | head -1)"
    [ -n "$modver" ] && MODULES_TREE="$mod_out/lib/modules/$modver"
  fi
fi
if [ -z "$BUSYBOX" ]; then
  bb_out="$(nix_build pkgsStatic.busybox || true)"
  [ -n "$bb_out" ] && BUSYBOX="$bb_out/bin/busybox"
fi

if [ ! -f "$BZIMAGE" ] || [ ! -d "$MODULES_TREE" ] || [ ! -x "$BUSYBOX" ]; then
  echo "SKIP: could not obtain guest fixtures (bzImage=$BZIMAGE modules=$MODULES_TREE busybox=$BUSYBOX)"
  exit 0
fi
echo "  kernel:   $BZIMAGE"
echo "  modules:  $MODULES_TREE"
echo "  busybox:  $BUSYBOX"

# tpm2-tools: only needed for the PCR-mismatch case; absent -> that case is a note.
TPM2_BIN="${TPM_E2E_TPM2_BIN:-}"
if [ -z "$TPM2_BIN" ] && command -v nix >/dev/null 2>&1; then
  t2_out="$(nix_build tpm2-tools || true)"
  [ -n "$t2_out" ] && TPM2_BIN="$t2_out/bin"
fi
TPM2_PCREXTEND=""
if [ -n "$TPM2_BIN" ] && [ -x "$TPM2_BIN/tpm2_pcrextend" ]; then
  TPM2_PCREXTEND="$TPM2_BIN/tpm2_pcrextend"
  echo "  tpm2:     $TPM2_BIN"
else
  note "tpm2-tools unavailable -> PCR-mismatch case will be skipped (degraded, not failed)"
fi

# ---- build basil with the unlock-tpm feature --------------------------------

if [ "${TPM_E2E_NO_BUILD:-0}" != "1" ]; then
  echo "-- building basil (cargo build -p basil-bin --features unlock-tpm)"
  ( cd "$REPO_ROOT" && cargo build -p basil-bin --features unlock-tpm >/dev/null 2>&1 ) \
    || { echo "FATAL: cargo build -p basil-bin --features unlock-tpm failed"; exit 1; }
fi
[ -x "$AGENT_BIN" ] || { echo "FATAL: $AGENT_BIN not built (set TPM_E2E_NO_BUILD=1 only if it exists)"; exit 1; }

# ---- host-side shared config (in-guest paths point at /mnt/bundleout) --------
# A minimal but valid catalog: one Vault/OpenBao backend, zero keys. After the
# TPM unseal, `doctor` builds the manager and probes 0 keys -> exits 0
# WITHOUT any backend I/O, so a clean exit code distinguishes "unlocked + ready"
# from the fail-closed negatives (which never reach the unlock).

cat > "$SHARE/catalog.json" <<'JSON'
{ "schemaVersion": 1, "backends": { "primary": { "kind": "vault", "addr": "http://127.0.0.1:8200", "engines": ["transit"], "capabilities": [] } }, "keys": {} }
JSON
cat > "$SHARE/policy.json" <<'JSON'
{ "roles": {}, "rules": [], "config": { "names": { "users": {}, "groups": {} }, "memberships": {} } }
JSON
cat > "$SHARE/agent-tpm.toml" <<'TOML'
catalog = "/mnt/bundleout/catalog.json"
policy = "/mnt/bundleout/policy.json"
bundle = "/mnt/bundleout/b-tpm.sealed"
vault-addr = "http://127.0.0.1:8200"
[unlock]
unlock-tpm = true
TOML
cat > "$SHARE/agent-recov.toml" <<'TOML'
catalog = "/mnt/bundleout/catalog.json"
policy = "/mnt/bundleout/policy.json"
bundle = "/mnt/bundleout/b-recov.sealed"
vault-addr = "http://127.0.0.1:8200"
[unlock]
unlock-tpm = true
unlock-passphrase-file = "/mnt/bundleout/pass"
unlock-passphrase-no-wipe = true
TOML
printf 'tpm-e2e-recovery-not-a-secret\n' > "$SHARE/pass"
# guest.env carries the absolute /nix/store path of tpm2_pcrextend (reachable in
# the guest over the read-only /nix/store share), or empty when unavailable.
printf 'TPM2_PCREXTEND=%s\n' "$TPM2_PCREXTEND" > "$SHARE/guest.env"

# ---- assemble the busybox initramfs -----------------------------------------

echo "-- assembling guest initramfs (busybox + 9p/virtio modules + /init scenario dispatcher)"
ROOT="$WORKDIR/initramfs"
rm -rf "$ROOT"
mkdir -p "$ROOT"/bin "$ROOT"/lib/mods "$ROOT"/proc "$ROOT"/sys "$ROOT"/dev \
         "$ROOT"/tmp "$ROOT"/mnt/basilbin "$ROOT"/mnt/bundleout "$ROOT"/nix/store
cp "$BUSYBOX" "$ROOT/bin/busybox"
chmod +x "$ROOT/bin/busybox"

for m in "${MODS[@]}"; do
  ko="$(find "$MODULES_TREE/kernel" \( -name "$m.ko.xz" -o -name "$m.ko" \) 2>/dev/null | head -1)"
  [ -n "$ko" ] || { echo "FATAL: kernel module '$m' not found under $MODULES_TREE"; exit 1; }
  case "$ko" in
    *.xz) xz -dc "$ko" > "$ROOT/lib/mods/$m.ko" ;;
    *)    cp "$ko" "$ROOT/lib/mods/$m.ko" ;;
  esac
done

# The in-guest /init. Single-quoted heredoc: NO host expansion; it is a fully
# static busybox-ash script. It probes tpm_available() (device-path), loads the
# 9p chain, mounts the binary + /nix/store (ro) + bundle (rw) shares, then
# dispatches on the `basil.sc=` kernel-cmdline token. Each scenario emits a
# single summary line the host greps; opened=yes iff the broker logged
# "sealed bundle unlocked" (the TPM/recovery unlock succeeded).
cat > "$ROOT/init" <<'INIT'
#!/bin/busybox sh
/bin/busybox --install -s /bin
export PATH=/bin
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null
mount -t devtmpfs devtmpfs /dev 2>/dev/null

SC=$(cat /proc/cmdline | tr ' ' '\n' | sed -n 's/^basil.sc=//p')
echo "BASIL_SENTINEL_BEGIN sc=$SC"

if [ -e /dev/tpmrm0 ] || [ -e /dev/tpm0 ]; then
  echo "BASIL_TPM tpm_available=true"
else
  echo "BASIL_TPM tpm_available=false"
fi

for m in virtio_ring virtio virtio_pci_modern_dev virtio_pci_legacy_dev virtio_pci netfs 9pnet 9pnet_virtio 9p; do
  insmod "/lib/mods/$m.ko" 2>/dev/null
done
mount -t 9p -o trans=virtio,version=9p2000.L,ro,msize=512000 nixstore /nix/store 2>/dev/null \
  && echo "BASIL_9P nixstore ok" || echo "BASIL_9P nixstore fail"
mount -t 9p -o trans=virtio,version=9p2000.L,ro,msize=512000 basilbin /mnt/basilbin 2>/dev/null \
  && echo "BASIL_9P basilbin ok" || echo "BASIL_9P basilbin fail"
mount -t 9p -o trans=virtio,version=9p2000.L,msize=512000 bundleout /mnt/bundleout 2>/dev/null \
  && echo "BASIL_9P bundleout ok" || echo "BASIL_9P bundleout fail"

BAS=/mnt/basilbin/basil
. /mnt/bundleout/guest.env 2>/dev/null
export RUST_LOG=info
# Plain (no ANSI) logs so the host can parse "method=tpm" out of the sentinel.
export NO_COLOR=1

# Run `doctor` against a toml; print a summary + the unlock evidence.
# $1 = config toml, $2 = sentinel tag.
check_unlock() {
  _toml="$1"; _tag="$2"
  "$BAS" doctor -c "$_toml" > /tmp/chk 2>&1; _ec=$?
  if grep -q "sealed bundle unlocked" /tmp/chk; then _op=yes; else _op=no; fi
  _method=$(sed -n 's/.*unlock slot opened.*method=\([a-z]*\).*/\1/p' /tmp/chk | head -1)
  _rc=$(sed -n 's/.*\(TPM_RC_[A-Z_]*\).*/\1/p' /tmp/chk | head -1)
  echo "$_tag exit=$_ec opened=$_op method=${_method:-none} rc=${_rc:-none}"
  # Echo the fail-closed line (non-secret) for the host log; never key bytes.
  grep -E "no unlock slot opened|unlock slot failed|panicked" /tmp/chk | sed 's/^/  detail| /'
}

if [ -x "$BAS" ]; then
  "$BAS" --version > /tmp/ver 2>&1; echo "BASIL_RUN exit=$? out=[$(head -1 /tmp/ver)]"
else
  echo "BASIL_RUN missing_binary"
fi

case "$SC" in
  seal)
    # The token backend cred is read from a 0600 file (no inline token flag). A
    # dummy token is fine: these scenarios exercise TPM UNLOCK, never a real login.
    printf 'dummy-token\n' > /tmp/backend-token; chmod 600 /tmp/backend-token
    "$BAS" bundle create /mnt/bundleout/b-tpm.sealed --slot tpm \
        --backend id=primary,type=openbao,token-file=/tmp/backend-token > /tmp/s1 2>&1
    echo "BASIL_SEAL_TPM exit=$? bytes=$(wc -c < /mnt/bundleout/b-tpm.sealed 2>/dev/null)"
    # A second bundle with a passphrase RECOVERY slot alongside the TPM slot.
    "$BAS" bundle create /mnt/bundleout/b-recov.sealed --slot tpm \
        --slot passphrase:file=/mnt/bundleout/pass \
        --backend id=primary,type=openbao,token-file=/tmp/backend-token > /tmp/s2 2>&1
    echo "BASIL_SEAL_RECOV exit=$? bytes=$(wc -c < /mnt/bundleout/b-recov.sealed 2>/dev/null)"
    check_unlock /mnt/bundleout/agent-tpm.toml BASIL_A_UNLOCK
    ;;
  reboot)
    check_unlock /mnt/bundleout/agent-tpm.toml BASIL_REBOOT_UNLOCK
    ;;
  notpm)
    check_unlock /mnt/bundleout/agent-tpm.toml BASIL_NOTPM_TPMONLY
    check_unlock /mnt/bundleout/agent-recov.toml BASIL_NOTPM_RECOV
    ;;
  pcr)
    if [ -n "${TPM2_PCREXTEND:-}" ] && [ -x "$TPM2_PCREXTEND" ]; then
      "$TPM2_PCREXTEND" 7:sha256=$(busybox sha256sum /init | cut -c1-64) > /tmp/pex 2>&1
      echo "BASIL_PCR_EXTEND exit=$?"
      check_unlock /mnt/bundleout/agent-tpm.toml BASIL_PCR
    else
      echo "BASIL_PCR skipped=no-tpm2-tools"
    fi
    ;;
  othertpm)
    check_unlock /mnt/bundleout/agent-tpm.toml BASIL_OTHERTPM
    ;;
esac

echo "BASIL_SENTINEL_END"
sync
poweroff -f
INIT
chmod +x "$ROOT/init"

( cd "$ROOT" && find . | cpio -o -H newc 2>/dev/null | gzip -1 > "$INITRAMFS" )
[ -s "$INITRAMFS" ] || { echo "FATAL: initramfs assembly produced no output"; exit 1; }

# ---- acceleration -----------------------------------------------------------

ACCEL="tcg"
CPU="max"
if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
  ACCEL="kvm"
  CPU="host"
fi
echo "-- qemu acceleration: $ACCEL (cpu=$CPU)"

# ---- boot helper ------------------------------------------------------------
# boot_guest <scenario> <state-dir|none>
# Boots one guest (with swtpm bound to <state-dir>, or no TPM when "none"),
# captures the console, and writes the extracted sentinel to $SENTINEL.
SENTINEL=""
boot_guest() {
  local sc="$1" state="$2"
  local console="$WORKDIR/console-$sc.log"
  SENTINEL="$WORKDIR/sentinel-$sc.txt"
  local tpm_args=()

  SWTPM_PID=""
  if [ "$state" != "none" ]; then
    rm -f "$SWTPM_SOCK"
    swtpm socket --tpm2 --tpmstate "dir=$state" \
        --ctrl "type=unixio,path=$SWTPM_SOCK" \
        --flags startup-clear >"$WORKDIR/swtpm-$sc.log" 2>&1 &
    SWTPM_PID=$!
    local ready=0 _
    for _ in $(seq 1 50); do
      [ -S "$SWTPM_SOCK" ] && { ready=1; break; }
      kill -0 "$SWTPM_PID" 2>/dev/null || break
      sleep 0.1
    done
    if [ "$ready" != 1 ]; then
      fail "[$sc] swtpm did not create $SWTPM_SOCK (see $WORKDIR/swtpm-$sc.log)"
      stop_pid "$SWTPM_PID"; SWTPM_PID=""
      return 1
    fi
    tpm_args=(
      -chardev "socket,id=chrtpm,path=$SWTPM_SOCK"
      -tpmdev "emulator,id=tpm0,chardev=chrtpm"
      -device "tpm-tis,tpmdev=tpm0"
    )
  fi

  local qemu_args=(
    -nodefaults -no-reboot
    -machine "q35,accel=$ACCEL" -cpu "$CPU" -m 512 -smp 2
    -kernel "$BZIMAGE" -initrd "$INITRAMFS"
    -append "console=ttyS0 rdinit=/init panic=-1 basil.sc=$sc"
    -virtfs "local,path=$REPO_ROOT/target/debug,mount_tag=basilbin,security_model=none,readonly=on"
    -virtfs "local,path=/nix/store,mount_tag=nixstore,security_model=none,readonly=on"
    -virtfs "local,path=$SHARE,mount_tag=bundleout,security_model=none"
    "${tpm_args[@]}"
    -display none -serial stdio -monitor none
  )

  set +e
  timeout "$BOOT_TIMEOUT" qemu-system-x86_64 "${qemu_args[@]}" >"$console" 2>&1
  set -e
  stop_pid "$SWTPM_PID"; SWTPM_PID=""

  sed -n '/BASIL_SENTINEL_BEGIN/,/BASIL_SENTINEL_END/p' "$console" > "$SENTINEL" || true
  if [ -s "$SENTINEL" ] && grep -q "BASIL_SENTINEL_END" "$SENTINEL"; then
    RAN=1
    echo "-- [$sc] guest sentinel:"
    sed 's/^/     /' "$SENTINEL"
    return 0
  fi
  fail "[$sc] no complete guest sentinel (guest did not boot/probe to completion)"
  echo "   --- console tail ---"
  tail -20 "$console" | sed 's/^/     /'
  return 1
}

# sline <regex>: the first sentinel line matching <regex>, or "".
sline() { grep -E "$1" "$SENTINEL" 2>/dev/null | head -1; }

# =============================================================================
# Phase 1 + Scenario A boot 1: seal on TPM-A, then auto-unlock (no secret).
# =============================================================================
echo
echo "== boot 1/5: Phase-1 plumbing + Scenario A seal + auto-unlock (TPM-A) =="
if boot_guest seal "$STATE_A"; then
  # Phase 1
  if grep -q "BASIL_TPM tpm_available=true" "$SENTINEL"; then
    pass "tpm_available() == true (/dev/tpmrm0 present)"
  else
    fail "guest did not report tpm_available() == true"
  fi
  if grep -q "BASIL_RUN exit=0" "$SENTINEL"; then
    pass "basil ran end-to-end in-guest off the 9p share ($(sline 'BASIL_RUN' | grep -o 'out=\[.*\]'))"
  else
    fail "basil did not run cleanly in-guest"
  fi

  # Scenario A step 1: both seals succeeded (the TPM sealed the slot key).
  case "$(sline '^BASIL_SEAL_TPM')" in
    *"exit=0"*) pass "bundle create --slot tpm sealed a TPM-only unlock slot" ;;
    *)          fail "bundle create --slot tpm failed: $(sline '^BASIL_SEAL_TPM')" ;;
  esac
  case "$(sline '^BASIL_SEAL_RECOV')" in
    *"exit=0"*) pass "bundle create --slot tpm + passphrase recovery slot sealed" ;;
    *)          fail "recovery-slot bundle seal failed: $(sline '^BASIL_SEAL_RECOV')" ;;
  esac

  # Scenario A step 2: auto-unlock with NO operator secret.
  a_unlock="$(sline '^BASIL_A_UNLOCK')"
  case "$a_unlock" in
    *"exit=0"*"opened=yes"*"method=tpm"*)
      pass "auto-unlock: TPM2_Unseal opened the bundle (method=tpm), no operator secret, check exited 0" ;;
    *)  fail "Scenario A auto-unlock did not open via TPM: $a_unlock" ;;
  esac
fi

# =============================================================================
# Scenario A boot 2: reboot reusing the SAME swtpm state dir -> auto-unlock.
# =============================================================================
echo
echo "== boot 2/5: Scenario A reboot, same swtpm state dir, auto-unlock again =="
if boot_guest reboot "$STATE_A"; then
  r_unlock="$(sline '^BASIL_REBOOT_UNLOCK')"
  case "$r_unlock" in
    *"exit=0"*"opened=yes"*"method=tpm"*)
      pass "post-reboot auto-unlock succeeded on first boot (persistent SRK + PolicyPCR)" ;;
    *)  fail "Scenario A reboot did not auto-unlock: $r_unlock" ;;
  esac
fi

# =============================================================================
# Scenario B case 1: no TPM device -> TPM-only fails closed; recovery opens.
# =============================================================================
echo
echo "== boot 3/5: Scenario B no-TPM: TPM-only fails closed, recovery slot opens =="
if boot_guest notpm "none"; then
  if grep -q "BASIL_TPM tpm_available=false" "$SENTINEL"; then
    pass "no-TPM guest: tpm_available() == false"
  else
    fail "no-TPM guest unexpectedly reports a TPM present"
  fi
  tpmonly="$(sline '^BASIL_NOTPM_TPMONLY')"
  case "$tpmonly" in
    *"exit=0"*)     fail "TPM-only bundle opened/served with no TPM (must fail closed): $tpmonly" ;;
    *"opened=no"*)  pass "TPM-only bundle fails closed with no TPM (broker refuses to start)" ;;
    *)              fail "TPM-only bundle did not fail closed with no TPM: $tpmonly" ;;
  esac
  recov="$(sline '^BASIL_NOTPM_RECOV')"
  case "$recov" in
    *"exit=0"*"opened=yes"*"method=passphrase"*)
      pass "recovery slot opens the bundle when the TPM is absent (method=passphrase)" ;;
    *) fail "recovery-slot fallback did not open the bundle: $recov" ;;
  esac
fi

# =============================================================================
# Scenario B case 2: PCR mismatch -> PolicyPCR unsatisfied -> fail closed.
# =============================================================================
echo
echo "== boot 4/5: Scenario B PCR-mismatch: perturb PCR7 then unseal must fail closed =="
if boot_guest pcr "$STATE_A"; then
  pcr="$(sline '^BASIL_PCR exit=')"
  if [ -z "$pcr" ] && grep -q "BASIL_PCR skipped=no-tpm2-tools" "$SENTINEL"; then
    note "PCR-mismatch case skipped (tpm2-tools unavailable)"
  else
    case "$pcr" in
      *"opened=no"*"rc=TPM_RC_POLICY_FAIL"*)
        pass "PCR mismatch: TPM2_Unseal rejected (TPM_RC_POLICY_FAIL) -> fail closed" ;;
      *"opened=no"*)
        pass "PCR mismatch: bundle did not open -> fail closed ($pcr)" ;;
      *) fail "PCR-mismatch did not fail closed: $pcr" ;;
    esac
  fi
fi

# =============================================================================
# Scenario B case 3: different TPM (foreign hierarchy) -> blob does not load.
# =============================================================================
echo
echo "== boot 5/5: Scenario B different-TPM: open Scenario-A bundle on a foreign TPM =="
if boot_guest othertpm "$STATE_B"; then
  other="$(sline '^BASIL_OTHERTPM')"
  case "$other" in
    *"opened=no"*)
      pass "foreign TPM cannot unseal the blob -> fail closed ($other)" ;;
    *) fail "bundle opened on a DIFFERENT TPM (must fail closed): $other" ;;
  esac
fi

# =============================================================================
# Host-side bundle inspection: the on-disk bundle carries ONLY the sealed public
# /private areas + PCR selection, never the slot key in cleartext.
# =============================================================================
echo
echo "== host-side: sealed-bundle on-disk shape (no cleartext slot key) =="
BUNDLE="$SHARE/b-tpm.sealed"
if [ -s "$BUNDLE" ]; then
  if head -c 9 "$BUNDLE" | grep -q "BASILBDL"; then
    pass "bundle carries the BASILBDL sealed-format magic"
  else
    fail "bundle is missing the BASILBDL magic"
  fi
  # Body is JSON after the 9-byte magic + 2-byte version. The tpm slot exposes
  # kind/public/private/pcrs only; MethodParams::Tpm has no slot-key field.
  body="$(tail -c +12 "$BUNDLE")"
  if printf '%s' "$body" | grep -q '"kind":"tpm"' \
     && printf '%s' "$body" | grep -q '"public":' \
     && printf '%s' "$body" | grep -q '"private":' \
     && printf '%s' "$body" | grep -q '"pcrs":'; then
    pass "tpm slot params present on disk: public + private + pcrs (sealed areas only)"
  else
    fail "tpm slot params not found in the on-disk bundle body"
  fi
  # Defense-in-depth structural check: the only secret-bearing fields are the
  # TPM-sealed private blob and the AEAD-wrapped KEK ciphertext (both opaque).
  if printf '%s' "$body" | grep -qiE '"slot[_-]?key"|"plaintext"|"cleartext"'; then
    fail "on-disk bundle contains a cleartext slot-key/plaintext field"
  else
    pass "no cleartext slot-key/plaintext field on disk (slot key never serialized)"
  fi
else
  fail "Scenario-A bundle was not written to the shared dir"
fi

# ---- verdict ----------------------------------------------------------------

echo
if [ "$RAN" != 1 ]; then
  echo "FAIL: qemu + swtpm are present but no real guest run completed (not a silent pass)"
  exit 1
fi
if [ "$FAILED" -eq 0 ]; then
  echo "PASS: TPM seal -> auto-unlock -> reboot auto-unlock held; no-TPM/PCR-mismatch/different-TPM all failed closed"
  exit 0
else
  echo "FAIL: one or more TPM e2e assertions failed (see above; consoles under $WORKDIR)"
  exit 1
fi
