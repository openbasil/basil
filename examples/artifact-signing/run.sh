#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
#
# SPDX-License-Identifier: Apache-2.0

# Boot an OpenBao dev server + a Basil agent, then sign & verify a release
# manifest through the broker and prove the deny path. Exit 0 only when every
# assertion in the example binary passes.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

WORKDIR="${ARTIFACT_SIGNING_WORKDIR:-/tmp/basil-artifact-signing}"
BAO_PORT="${ARTIFACT_SIGNING_BAO_PORT:-8220}"
VAULT_ADDR="${ARTIFACT_SIGNING_VAULT_ADDR:-http://127.0.0.1:$BAO_PORT}"
VAULT_TOKEN="${ARTIFACT_SIGNING_VAULT_TOKEN:-root}"

FIXTURES="$WORKDIR/fixtures"
CATALOG="$FIXTURES/catalog.json"
POLICY="$FIXTURES/policy.json"
BUNDLE="$FIXTURES/bundle.sealed"
PASS_FILE="$FIXTURES/disk-pass.txt"
APPROLE_SECRET_FILE="$FIXTURES/approle-secret-id.txt"
AGENT_CONFIG="$FIXTURES/basil-agent.toml"
SOCKET="$WORKDIR/agent.sock"
BAO_LOG="$WORKDIR/openbao.log"
AGENT_LOG="$WORKDIR/agent.log"

EXAMPLE_TARGET_DIR="$ROOT/target/artifact-signing"
EXAMPLE_BIN="$EXAMPLE_TARGET_DIR/debug/artifact-signing"

BAO_PID=""
AGENT_PID=""

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

cleanup() {
  for pid in "$AGENT_PID" "$BAO_PID"; do
    if [[ -n "$pid" ]]; then
      kill "$pid" >/dev/null 2>&1 || true
    fi
  done
}
trap 'st=$?; cleanup; [[ $st -ne 0 ]] && echo "FAIL (exit $st)" >&2; exit $st' EXIT

wait_for_file_socket() {
  local path="$1" log="$2" pid="$3"
  for _ in $(seq 1 120); do
    [[ -S "$path" ]] && return
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      echo "process exited while waiting for $path; log:" >&2
      cat "$log" >&2
      exit 1
    fi
    sleep 0.1
  done
  echo "timed out waiting for $path; log:" >&2
  cat "$log" >&2
  exit 1
}

write_catalog() {
  cat >"$CATALOG" <<JSON
{
  "schemaVersion": 1,
  "backends": {
    "bao": {
      "kind": "vault",
      "addr": "$VAULT_ADDR",
      "engines": ["transit"],
      "capabilities": ["approle-auth"],
      "mintKeyTypes": ["ed25519"]
    }
  },
  "keys": {
    "release.signing": {
      "class": "asymmetric", "keyType": "ed25519", "backend": "bao",
      "engine": "transit", "path": "release-signing",
      "writable": true, "missing": "generate",
      "description": "Transit-backed Ed25519 release-artifact signing key."
    },
    "forbidden.key": {
      "class": "asymmetric", "keyType": "ed25519", "backend": "bao",
      "engine": "transit", "path": "forbidden-key",
      "writable": true, "missing": "generate",
      "description": "A key the demo process is deliberately NOT granted sign on."
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
    "local.user": { "domain": "host-process", "match": { "all": [{ "process.uid": $uid }] } }
  },
  "rules": [
    {
      "id": "local-can-sign-release-key",
      "subjects": ["local.user"],
      "action": ["role:signer"],
      "target": ["release.signing"]
    }
  ],
  "config": {
    "names": { "users": { "$uid": "$user" }, "groups": {} },
    "memberships": { "$uid": [] }
  }
}
JSON
}

write_agent_config() {
  cat >"$AGENT_CONFIG" <<TOML
catalog = "$CATALOG"
policy = "$POLICY"
bundle = "$BUNDLE"
socket = "$SOCKET"
vault-addr = "$VAULT_ADDR"

[unlock]
unlock-passphrase-file = "$PASS_FILE"
TOML
}

main() {
  BAO="$(command -v bao || command -v vault || true)"
  [[ -n "$BAO" ]] || { echo "missing required command: bao (or vault)" >&2; exit 1; }

  rm -rf "$WORKDIR"
  mkdir -p "$FIXTURES"
  chmod 700 "$WORKDIR"

  echo "== build =="
  if [[ -n "${BASIL_BIN:-}" ]]; then
    BASIL="$BASIL_BIN"
  elif command -v basil >/dev/null 2>&1; then
    BASIL="$(command -v basil)"
  else
    cargo build --manifest-path "$ROOT/Cargo.toml" -p basil-bin --bin basil >/dev/null
    BASIL="$ROOT/target/debug/basil"
  fi
  CARGO_TARGET_DIR="$EXAMPLE_TARGET_DIR" \
    cargo build --manifest-path "$SCRIPT_DIR/Cargo.toml" >/dev/null

  echo "== openbao =="
  LISTEN="${VAULT_ADDR#http://}"
  "$BAO" server -dev -dev-root-token-id="$VAULT_TOKEN" -dev-listen-address="$LISTEN" \
    >"$BAO_LOG" 2>&1 &
  BAO_PID="$!"
  for _ in $(seq 1 80); do
    VAULT_ADDR="$VAULT_ADDR" VAULT_TOKEN="$VAULT_TOKEN" "$BAO" status >/dev/null 2>&1 && break
    sleep 0.1
  done
  VAULT_ADDR="$VAULT_ADDR" VAULT_TOKEN="$VAULT_TOKEN" "$BAO" status >/dev/null
  export VAULT_ADDR VAULT_TOKEN

  "$BAO" secrets enable transit >/dev/null 2>&1 || true

  "$BAO" policy write basil-artifact-signing - >/dev/null <<'HCL'
path "transit/*" { capabilities = ["create", "read", "update", "delete", "list"] }
HCL
  "$BAO" auth enable approle >/dev/null 2>&1 || true
  "$BAO" write auth/approle/role/basil-artifact-signing \
    token_policies=basil-artifact-signing \
    token_ttl=1h token_max_ttl=4h >/dev/null
  role_id="$("$BAO" read -field=role_id auth/approle/role/basil-artifact-signing/role-id)"
  "$BAO" write -f -field=secret_id auth/approle/role/basil-artifact-signing/secret-id \
    >"$APPROLE_SECRET_FILE"
  chmod 600 "$APPROLE_SECRET_FILE"

  printf 'artifact-signing-passphrase\n' >"$PASS_FILE"
  chmod 600 "$PASS_FILE"
  write_catalog
  write_policy
  "$BASIL" bundle create "$BUNDLE" \
    --slot "passphrase:file=$PASS_FILE" \
    --backend "id=bao,type=openbao,addr=$VAULT_ADDR,role-id=$role_id,secret-id-file=$APPROLE_SECRET_FILE" \
    >/dev/null
  write_agent_config

  echo "== agent =="
  "$BASIL" agent --config "$AGENT_CONFIG" >"$AGENT_LOG" 2>&1 &
  AGENT_PID="$!"
  wait_for_file_socket "$SOCKET" "$AGENT_LOG" "$AGENT_PID"

  echo "== example =="
  "$EXAMPLE_BIN" "$SOCKET"
  echo "workdir: $WORKDIR"
  echo "PASS"
}

main "$@"
