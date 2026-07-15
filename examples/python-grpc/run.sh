#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
#
# SPDX-License-Identifier: Apache-2.0

# Boot a Basil agent on the zero-dependency db-keystore backend, then drive it
# from Python over plain gRPC (main.py). Proves the socket speaks standard
# gRPC from any language. SKIPs (exit 0) when grpcio/grpcio-tools are not
# installed, after verifying the broker boots and stops cleanly.
set -euo pipefail

trap 'st=$?; [[ $st -ne 0 ]] && echo "FAIL (exit $st)" >&2; exit $st' EXIT

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

WORKDIR="${PYTHON_GRPC_WORKDIR:-${TMPDIR:-/tmp}/basil-pygrpc}"
KEY_ID="demo.signing_key"

DB_PATH="$WORKDIR/keystore.db"
SOCKET="$WORKDIR/agent.sock"
BUNDLE="$WORKDIR/bundle.sealed"
PASS_FILE="$WORKDIR/disk-passphrase.txt"
DEK_FILE="$WORKDIR/db-keystore-dek.bin"
CATALOG="$WORKDIR/catalog.json"
POLICY="$WORKDIR/policy.json"
AGENT_CONFIG="$WORKDIR/basil-agent.toml"
AGENT_LOG="$WORKDIR/agent.log"

AGENT_PID=""

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

cleanup() {
  [[ -n "$AGENT_PID" ]] && kill "$AGENT_PID" >/dev/null 2>&1 || true
}

find_basil() {
  if [[ -n "${BASIL_BIN:-}" ]]; then
    BASIL="$BASIL_BIN"
  elif command -v basil >/dev/null 2>&1; then
    BASIL="$(command -v basil)"
  elif [[ -x "$ROOT/target/debug/basil" ]]; then
    BASIL="$ROOT/target/debug/basil"
  else
    echo "no basil binary found: export BASIL_BIN, put basil on PATH, or build the workspace" >&2
    exit 1
  fi
  echo "== using basil: $BASIL"
}

write_catalog() {
  cat >"$CATALOG" <<JSON
{
  "schemaVersion": 1,
  "backends": {
    "local-db": {
      "kind": "keystore",
      "addr": "$DB_PATH",
      "engines": ["transit"],
      "mintKeyTypes": ["ed25519"]
    }
  },
  "keys": {
    "$KEY_ID": {
      "class": "asymmetric", "keyType": "ed25519", "backend": "local-db",
      "engine": "transit", "path": "demo/signing-key",
      "writable": true, "missing": "generate",
      "description": "Ed25519 signing key exercised from Python over raw gRPC."
    }
  }
}
JSON
}

write_policy() {
  local uid user
  uid="$(id -u)"
  user="$(id -un)"
  cat >"$POLICY" <<JSON
{
  "schemaVersion": 2,
  "roles": {
    "signer": ["sign", "verify", "get_public_key"]
  },
  "subjects": {
    "local": { "domain": "host-process", "match": { "all": [ { "process.uid": $uid } ] } }
  },
  "rules": [
    { "id": "local-signs-demo-key", "subjects": ["local"], "action": ["role:signer"], "target": ["$KEY_ID"] }
  ],
  "config": {
    "names": { "users": { "$uid": "$user" }, "groups": {} },
    "memberships": { "$uid": [] }
  }
}
JSON
}

start_agent() {
  cat >"$AGENT_CONFIG" <<EOF
catalog = "$CATALOG"
policy = "$POLICY"
bundle = "$BUNDLE"
socket = "$SOCKET"
db-keystore-cipher = "aegis256"

[unlock]
unlock-passphrase-file = "$PASS_FILE"
EOF
  "$BASIL" agent --config "$AGENT_CONFIG" >"$AGENT_LOG" 2>&1 &
  AGENT_PID="$!"
  # Replaces the top-of-script EXIT trap, so it must keep the FAIL convention.
  trap 'st=$?; cleanup; [[ $st -ne 0 ]] && echo "FAIL (exit $st)" >&2; exit $st' EXIT
  for _ in $(seq 1 120); do
    [[ -S "$SOCKET" ]] && return
    if ! kill -0 "$AGENT_PID" >/dev/null 2>&1; then
      echo "basil agent exited during startup; log follows:" >&2
      cat "$AGENT_LOG" >&2
      exit 1
    fi
    sleep 0.1
  done
  echo "timed out waiting for $SOCKET; log follows:" >&2
  cat "$AGENT_LOG" >&2
  exit 1
}

main() {
  need python3
  find_basil

  rm -rf "$WORKDIR"
  mkdir -p "$WORKDIR"
  chmod 700 "$WORKDIR"

  echo "== scaffold =="
  umask 077
  printf 'python-grpc-passphrase\n' > "$PASS_FILE"
  # The bundle DEK must be exactly 32 raw bytes; `bundle create` strips one
  # trailing newline/CR from secret files, so avoid those as the last byte.
  while :; do
    head -c 32 /dev/urandom > "$DEK_FILE"
    last="$(tail -c 1 "$DEK_FILE" | od -An -tu1 | tr -d ' ')"
    [[ "$last" != 10 && "$last" != 13 ]] && break
  done
  write_catalog
  write_policy
  "$BASIL" bundle create "$BUNDLE" \
    --slot "passphrase:file=$PASS_FILE" \
    --backend "id=local-db,type=db-keystore,path=$DB_PATH,dek-file=$DEK_FILE" \
    >/dev/null

  echo "== agent =="
  start_agent

  # The broker is up; if the Python gRPC toolchain is missing this doubles as
  # a boot smoke test and SKIPs instead of failing.
  if ! python3 -c "import grpc, grpc_tools" >/dev/null 2>&1; then
    echo "SKIP: python gRPC deps not installed (pip install grpcio grpcio-tools)"
    exit 0
  fi

  echo "== python example =="
  BASIL_PYGRPC_GEN="$WORKDIR/gen" BASIL_SIGNING_KEY_ID="$KEY_ID" \
    python3 "$SCRIPT_DIR/main.py" "$SOCKET"

  echo
  echo "workdir: $WORKDIR"
  echo "PASS"
}

main "$@"
