#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
#
# SPDX-License-Identifier: Apache-2.0

# Boot OpenBao + a Basil agent + an operator-mode nats-server, then have two
# services exchange COSE-signed telemetry over NATS using Basil-minted user
# leases and in-place NKey signing. Exit 0 only when every assertion passes.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

WORKDIR="${COSE_NATS_TELEMETRY_WORKDIR:-/tmp/basil-cose-nats-telemetry}"
BAO_PORT="${COSE_NATS_TELEMETRY_BAO_PORT:-8222}"
NATS_PORT="${COSE_NATS_TELEMETRY_NATS_PORT:-4240}"
VAULT_ADDR="${COSE_NATS_TELEMETRY_VAULT_ADDR:-http://127.0.0.1:$BAO_PORT}"
VAULT_TOKEN="${COSE_NATS_TELEMETRY_VAULT_TOKEN:-root}"
NATS_URL="${COSE_NATS_TELEMETRY_NATS_URL:-nats://127.0.0.1:$NATS_PORT}"

FIXTURES="$WORKDIR/fixtures"
CATALOG="$FIXTURES/catalog.json"
POLICY="$FIXTURES/policy.json"
BUNDLE="$FIXTURES/bundle.sealed"
PASS_FILE="$FIXTURES/disk-pass.txt"
APPROLE_SECRET_FILE="$FIXTURES/approle-secret-id.txt"
AGENT_CONFIG="$FIXTURES/basil-agent.toml"
NATS_CONF="$FIXTURES/nats-server.conf"
OPERATOR_JWT="$FIXTURES/operator.jwt"
SOCKET="$WORKDIR/agent.sock"
BAO_LOG="$WORKDIR/openbao.log"
AGENT_LOG="$WORKDIR/agent.log"
NATS_LOG="$WORKDIR/nats.log"

EXAMPLE_TARGET_DIR="$ROOT/target/cose-nats-telemetry"
EXAMPLE_BIN="$EXAMPLE_TARGET_DIR/debug/cose-nats-telemetry"

BAO_PID=""
AGENT_PID=""
NATS_PID=""

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

cleanup() {
  for pid in "$NATS_PID" "$AGENT_PID" "$BAO_PID"; do
    if [[ -n "$pid" ]]; then
      kill "$pid" >/dev/null 2>&1 || true
    fi
  done
}
trap cleanup EXIT

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

wait_for_nats() {
  for _ in $(seq 1 120); do
    if grep -q "Server is ready" "$NATS_LOG" 2>/dev/null; then
      return
    fi
    if ! kill -0 "$NATS_PID" >/dev/null 2>&1; then
      echo "nats-server exited during startup; log:" >&2
      cat "$NATS_LOG" >&2
      exit 1
    fi
    sleep 0.1
  done
  echo "timed out waiting for nats-server; log:" >&2
  cat "$NATS_LOG" >&2
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
      "mintKeyTypes": ["ed25519", "ed25519-nkey"]
    }
  },
  "keys": {
    "telemetry.sign": {
      "class": "asymmetric", "keyType": "ed25519", "backend": "bao",
      "engine": "transit", "path": "telemetry-sign",
      "writable": true, "missing": "generate",
      "description": "Transit-backed Ed25519 key that signs the COSE telemetry."
    },
    "nats.operator": {
      "class": "asymmetric", "keyType": "ed25519-nkey", "backend": "bao",
      "engine": "transit", "path": "nats-operator",
      "writable": true, "missing": "generate",
      "labels": ["nats_type=O"],
      "description": "Operator identity NKey; self-signs the operator JWT and signs the account JWT."
    },
    "nats.account": {
      "class": "asymmetric", "keyType": "ed25519-nkey", "backend": "bao",
      "engine": "transit", "path": "nats-account",
      "writable": true, "missing": "generate",
      "labels": ["nats_type=A"],
      "description": "Account identity NKey; signs the user JWTs."
    },
    "nats.pub": {
      "class": "asymmetric", "keyType": "ed25519-nkey", "backend": "bao",
      "engine": "transit", "path": "nats-pub",
      "writable": true, "missing": "generate",
      "labels": ["nats_type=U"],
      "description": "Publisher user NKey; its seed signs the NATS server nonce in place."
    },
    "nats.sub": {
      "class": "asymmetric", "keyType": "ed25519-nkey", "backend": "bao",
      "engine": "transit", "path": "nats-sub",
      "writable": true, "missing": "generate",
      "labels": ["nats_type=U"],
      "description": "Subscriber user NKey; its seed signs the NATS server nonce in place."
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
    "signer": ["sign", "verify", "get_public_key"],
    "nats_issuer": ["mint", "sign_nats_jwt", "get_public_key"],
    "nats_user": ["sign", "get_public_key"]
  },
  "subjects": {
    "local.user": { "allOf": [{ "kind": "unix", "uid": $uid }] }
  },
  "rules": [
    {
      "id": "telemetry-cose-signer",
      "subjects": ["local.user"],
      "action": ["role:signer"],
      "target": ["telemetry.sign"]
    },
    {
      "id": "nats-issuer-keys",
      "subjects": ["local.user"],
      "action": ["role:nats_issuer"],
      "target": ["nats.operator", "nats.account"]
    },
    {
      "id": "nats-user-keys",
      "subjects": ["local.user"],
      "action": ["role:nats_user"],
      "target": ["nats.pub", "nats.sub"]
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
  need bao
  need nats-server

  rm -rf "$WORKDIR"
  mkdir -p "$FIXTURES"
  chmod 700 "$WORKDIR"

  echo "== build =="
  if [[ -n "${BASIL_BIN:-}" ]]; then
    BASIL="$BASIL_BIN"
  else
    cargo build --manifest-path "$ROOT/Cargo.toml" -p basil-bin --bin basil >/dev/null
    BASIL="$ROOT/target/debug/basil"
  fi
  CARGO_TARGET_DIR="$EXAMPLE_TARGET_DIR" \
    cargo build --manifest-path "$SCRIPT_DIR/Cargo.toml" >/dev/null

  echo "== openbao =="
  LISTEN="${VAULT_ADDR#http://}"
  bao server -dev -dev-root-token-id="$VAULT_TOKEN" -dev-listen-address="$LISTEN" \
    >"$BAO_LOG" 2>&1 &
  BAO_PID="$!"
  for _ in $(seq 1 80); do
    VAULT_ADDR="$VAULT_ADDR" VAULT_TOKEN="$VAULT_TOKEN" bao status >/dev/null 2>&1 && break
    sleep 0.1
  done
  VAULT_ADDR="$VAULT_ADDR" VAULT_TOKEN="$VAULT_TOKEN" bao status >/dev/null
  export VAULT_ADDR VAULT_TOKEN

  bao secrets enable transit >/dev/null 2>&1 || true

  bao policy write basil-cose-nats-telemetry - >/dev/null <<'HCL'
path "transit/*" { capabilities = ["create", "read", "update", "delete", "list"] }
HCL
  bao auth enable approle >/dev/null 2>&1 || true
  bao write auth/approle/role/basil-cose-nats-telemetry \
    token_policies=basil-cose-nats-telemetry \
    token_ttl=1h token_max_ttl=4h >/dev/null
  role_id="$(bao read -field=role_id auth/approle/role/basil-cose-nats-telemetry/role-id)"
  bao write -f -field=secret_id auth/approle/role/basil-cose-nats-telemetry/secret-id \
    >"$APPROLE_SECRET_FILE"
  chmod 600 "$APPROLE_SECRET_FILE"

  printf 'cose-nats-telemetry-passphrase\n' >"$PASS_FILE"
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

  echo "== mint operator/account chain + nats config =="
  "$EXAMPLE_BIN" write-nats-config \
    --socket "$SOCKET" \
    --out "$NATS_CONF" \
    --operator-jwt "$OPERATOR_JWT" \
    --nats-port "$NATS_PORT"

  echo "== nats-server (operator mode) =="
  nats-server -c "$NATS_CONF" >"$NATS_LOG" 2>&1 &
  NATS_PID="$!"
  wait_for_nats

  echo "== telemetry exchange =="
  "$EXAMPLE_BIN" run --socket "$SOCKET" --nats-url "$NATS_URL"
  echo "workdir: $WORKDIR"
  echo "PASS"
}

main "$@"
