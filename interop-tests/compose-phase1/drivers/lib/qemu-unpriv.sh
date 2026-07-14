#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
# SPDX-License-Identifier: Apache-2.0

# Shared unprivileged-QEMU helper library for Compose Phase 1 lane drivers.
#
# This file is a library: `source` it, do not execute it. It codifies the VM
# boundary documented in interop-tests/compose-phase1/README.md so every future
# lane driver builds the same fail-closed QEMU invocation:
#
#   - unprivileged QEMU with -nodefaults and explicit machine/memory/vcpus;
#   - an immutable, verified base image used only as a read-only backing file;
#   - a per-run qcow2 overlay with an explicit format;
#   - loopback-only user-mode networking with a single forwarded SSH port;
#   - QMP and serial state kept below the run's private transient directory;
#   - no 9p/virtfs/fsdev shares, no host bridge/tap networking, no repository or
#     evidence-directory mounts, and no host runtime sockets.
#
# `qemu_unpriv_build_argv` assembles the argv; `qemu_unpriv_assert_boundary`
# re-checks an argv against the forbidden surface so a driver can fail closed
# before it boots anything. Neither function boots a guest.

# Reject a control character or empty value that has no business in argv.
_qemu_unpriv_is_plain() {
  [[ -n $1 && $1 != *[$'\n\t']* ]]
}

# qemu_unpriv_build_argv OUT_ARRAY BASE OVERLAY SERIAL QMP SSH_PORT CLOUD_INIT \
#   MEMORY_MIB VCPUS MACHINE
# Populates the named array with a boundary-conforming QEMU argv. The base image
# is attached read-only as the overlay's backing file; the overlay is the only
# writable disk. Returns non-zero on an obviously unsafe argument.
qemu_unpriv_build_argv() {
  local out_name=$1 base=$2 overlay=$3 serial=$4 qmp=$5 ssh_port=$6
  local cloud_init=$7 memory_mib=$8 vcpus=$9 machine=${10}
  local value
  for value in "$base" "$overlay" "$serial" "$qmp" "$cloud_init" "$machine"; do
    _qemu_unpriv_is_plain "$value" || return 1
  done
  [[ $ssh_port =~ ^[1-9][0-9]{3,4}$ ]] || return 1
  [[ $memory_mib =~ ^[1-9][0-9]{1,5}$ ]] || return 1
  [[ $vcpus =~ ^[1-9][0-9]{0,2}$ ]] || return 1
  local -n out=$out_name
  # shellcheck disable=SC2034  # nameref: assigns through to the caller's array.
  out=(
    qemu-system-x86_64
    -nodefaults
    -no-user-config
    -machine "$machine"
    -m "$memory_mib"
    -smp "$vcpus"
    -nographic
    -serial "file:$serial"
    -qmp "unix:$qmp,server=on,wait=off"
    -drive "if=none,id=base,file=$base,format=qcow2,readonly=on"
    -drive "if=virtio,id=overlay,file=$overlay,format=qcow2,backing.file.filename=$base"
    -netdev "user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:$ssh_port-:22"
    -device "virtio-net-pci,netdev=net0"
    -drive "if=virtio,format=raw,readonly=on,file=$cloud_init"
  )
}

# qemu_unpriv_assert_boundary ARGV...
# Fail closed unless the argv keeps the documented VM boundary: -nodefaults is
# present, networking is restricted loopback user-mode, and no filesystem-share
# or host-bridge/tap escape hatch appears. Checks each argument on its own so a
# flag and its value are never conflated.
qemu_unpriv_assert_boundary() {
  local arg
  local has_nodefaults=0 has_user_net=0 has_restrict=0 has_loopback_fwd=0
  for arg in "$@"; do
    # Forbidden escape hatches: guest/host filesystem sharing, bridged or tap
    # networking, bridge helpers, and privilege re-entry.
    case "$arg" in
      -virtfs | -fsdev | -runas) return 1 ;;
      tap | bridge | tap,* | bridge,*) return 1 ;;
      *virtio-9p* | *helper=* | *,bridge=* | bridge=*) return 1 ;;
    esac
    # Required hardening markers.
    case "$arg" in
      -nodefaults) has_nodefaults=1 ;;
    esac
    case "$arg" in
      user | user,*) has_user_net=1 ;;
    esac
    [[ $arg == *restrict=on* ]] && has_restrict=1
    [[ $arg == *hostfwd=tcp:127.0.0.1:* ]] && has_loopback_fwd=1
  done
  (( has_nodefaults == 1 )) || return 1
  (( has_user_net == 1 )) || return 1
  (( has_restrict == 1 )) || return 1
  (( has_loopback_fwd == 1 )) || return 1
  return 0
}

# qemu_unpriv_selfcheck
# Build a representative argv, assert it honours the boundary, and assert that a
# tampered argv (a 9p share bolted on) is rejected. Boots nothing. Returns 0 on
# success so the harness can validate the library without a VM.
qemu_unpriv_selfcheck() {
  local -a argv=()
  qemu_unpriv_build_argv argv \
    /run/base.qcow2 /run/overlay.qcow2 /run/serial.log /run/qmp.sock \
    2222 /run/seed.img 4096 4 q35 || return 1
  qemu_unpriv_assert_boundary "${argv[@]}" || return 1
  local -a tampered=("${argv[@]}" -fsdev "local,id=repo,path=/,security_model=none")
  if qemu_unpriv_assert_boundary "${tampered[@]}"; then
    return 1
  fi
  return 0
}
