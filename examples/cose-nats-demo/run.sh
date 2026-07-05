#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

WORKDIR="${BASIL_COSE_NATS_DEMO_WORKDIR:-/tmp/basil-cose-nats-demo}"
VAULT_ADDR="${BASIL_COSE_NATS_DEMO_VAULT_ADDR:-http://127.0.0.1:8228}"
VAULT_TOKEN="${BASIL_COSE_NATS_DEMO_VAULT_TOKEN:-root}"
NATS_PORT="${BASIL_COSE_NATS_DEMO_NATS_PORT:-4229}"
NATS_URL="${BASIL_COSE_NATS_DEMO_NATS_URL:-nats://127.0.0.1:$NATS_PORT}"
BRIDGE_SUBJECT="${BASIL_COSE_NATS_DEMO_BRIDGE_SUBJECT:-basil.invoke}"

FIXTURES="$WORKDIR/fixtures"
CATALOG="$FIXTURES/catalog.json"
POLICY="$FIXTURES/policy.json"
BUNDLE="$FIXTURES/bundle.sealed"
PASS_FILE="$FIXTURES/disk-pass.txt"
APPROLE_SECRET_FILE="$FIXTURES/approle-secret-id.txt"
AGENT_CONFIG="$FIXTURES/basil-agent.toml"
BRIDGE_CONFIG="$FIXTURES/bridge.toml"
SOCKET="$WORKDIR/agent.sock"
BAO_LOG="$WORKDIR/openbao.log"
NATS_LOG="$WORKDIR/nats.log"
AGENT_LOG="$WORKDIR/agent.log"
BRIDGE_LOG="$WORKDIR/bridge.log"
DEMO_TARGET_DIR="$ROOT/target/cose-nats-demo"
DEMO_BIN="$DEMO_TARGET_DIR/debug/cose-nats-demo"

BAO_PID=""
NATS_PID=""
AGENT_PID=""
BRIDGE_PID=""

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

cleanup() {
  for pid in "$BRIDGE_PID" "$AGENT_PID" "$NATS_PID" "$BAO_PID"; do
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
  for _ in $(seq 1 100); do
    if "$DEMO_BIN" run \
      --socket "$SOCKET.missing" \
      --nats-url "$NATS_URL" \
      --bridge-subject "$BRIDGE_SUBJECT" >/dev/null 2>&1; then
      return
    fi
    if ! kill -0 "$NATS_PID" >/dev/null 2>&1; then
      echo "nats-server exited during startup; log:" >&2
      cat "$NATS_LOG" >&2
      exit 1
    fi
    if grep -q "Server is ready" "$NATS_LOG"; then
      return
    fi
    sleep 0.1
  done
  echo "timed out waiting for nats-server; log:" >&2
  cat "$NATS_LOG" >&2
  exit 1
}

write_kv_value() {
  local path="$1" value="$2" logical
  logical="${path/\/data\//\/}"
  bao kv put "$logical" "value=$value" >/dev/null
}

write_catalog() {
  cat >"$CATALOG" <<JSON
{
  "schemaVersion": 1,
  "backends": {
    "bao": {
      "kind": "vault",
      "addr": "$VAULT_ADDR",
      "engines": ["transit", "kv2"],
      "capabilities": ["approle-auth"],
      "mintKeyTypes": ["ed25519"]
    }
  },
  "keys": {
    "alice.sign": {
      "class": "asymmetric", "keyType": "ed25519", "backend": "bao",
      "engine": "transit", "path": "alice-sign",
      "writable": true, "missing": "generate",
      "description": "Alice transit-backed Ed25519 signing key for COSE peer messages."
    },
    "bob.sign": {
      "class": "asymmetric", "keyType": "ed25519", "backend": "bao",
      "engine": "transit", "path": "bob-sign",
      "writable": true, "missing": "generate",
      "description": "Bob transit-backed Ed25519 signing key for COSE peer messages."
    },
    "broker.response": {
      "class": "asymmetric", "keyType": "ed25519", "backend": "bao",
      "engine": "transit", "path": "broker-response",
      "writable": true, "missing": "generate",
      "labels": ["broker_key_use=response-signing"],
      "description": "Broker response-signing key for sealed invocation responses."
    },
    "broker.request": {
      "class": "sealing", "keyType": "x25519", "backend": "bao",
      "engine": "kv2", "path": "secret/data/demo/broker-request",
      "publicPath": "secret/data/demo/broker-request-public",
      "writable": false, "missing": "error",
      "labels": ["broker_key_use=request-encryption"],
      "description": "Broker request-encryption X25519 key for NATS bridged sealed invocations."
    },
    "alice.seal": {
      "class": "sealing", "keyType": "x25519", "backend": "bao",
      "engine": "kv2", "path": "secret/data/demo/alice-seal",
      "publicPath": "secret/data/demo/alice-seal-public",
      "writable": false, "missing": "error",
      "description": "Alice X25519 recipient key for broker-opened peer COSE messages."
    },
    "bob.seal": {
      "class": "sealing", "keyType": "x25519", "backend": "bao",
      "engine": "kv2", "path": "secret/data/demo/bob-seal",
      "publicPath": "secret/data/demo/bob-seal-public",
      "writable": false, "missing": "error",
      "description": "Bob X25519 recipient key for broker-opened peer COSE messages."
    },
    "alice.response": {
      "class": "sealing", "keyType": "x25519", "backend": "bao",
      "engine": "kv2", "path": "secret/data/demo/alice-response",
      "publicPath": "secret/data/demo/alice-response-public",
      "writable": false, "missing": "error",
      "labels": ["broker_key_use=response-encryption"],
      "description": "Alice response-encryption X25519 key for the bridged sign invocation."
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
  "roles": {
    "local_demo": ["list", "get_public_key", "sign", "verify", "decrypt"],
    "invoker": ["decrypt"],
    "alice_signer": ["sign"]
  },
  "subjects": {
    "local.user": {
      "allOf": [{ "kind": "unix", "uid": $uid }]
    },
    "svc.alice": {
      "allOf": [{ "kind": "signature-key", "algorithm": "ed25519", "public": "$ALICE_INVOKE_PUBLIC" }]
    },
    "svc.bob": {
      "allOf": [{ "kind": "signature-key", "algorithm": "ed25519", "public": "$BOB_INVOKE_PUBLIC" }]
    }
  },
  "rules": [
    {
      "id": "local-demo-can-use-demo-keys",
      "subjects": ["local.user"],
      "action": ["role:local_demo"],
      "target": ["alice.sign", "bob.sign", "broker.response", "broker.request", "alice.seal", "bob.seal", "alice.response"]
    },
    {
      "id": "alice-can-invoke-through-bridge",
      "subjects": ["svc.alice"],
      "action": ["role:invoker"],
      "target": ["broker.request"]
    },
    {
      "id": "alice-can-request-transit-signature",
      "subjects": ["svc.alice"],
      "action": ["role:alice_signer"],
      "target": ["alice.sign"]
    }
  ],
  "config": {
    "names": {
      "users": { "$uid": "$user" },
      "groups": {}
    },
    "memberships": {
      "$uid": []
    }
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

[unlock]
unlock-passphrase-file = "$PASS_FILE"

[broker-identity]
id = "basil://example/cose-nats-demo"
response-signing-key-id = "broker.response"

[invocation]
enable = true
audience = ["basil://example/cose-nats-demo"]
request-encryption-key-id = "broker.request"
max-ttl-secs = 60
clock-skew-secs = 30
replay-cache-capacity = 128
TOML
}

write_bridge_config() {
  cat >"$BRIDGE_CONFIG" <<TOML
[nats]
url = "$NATS_URL"

[basil]
socket = "$SOCKET"

[bridge]
request-subject = "$BRIDGE_SUBJECT"
max-message-bytes = 1048576
TOML
}

main() {
  need bao
  need nats-server

  rm -rf "$WORKDIR"
  mkdir -p "$FIXTURES"
  chmod 700 "$WORKDIR"

  echo "build"
  cargo build --manifest-path "$ROOT/Cargo.toml" -p basil-bin -p basil-nats-bridge --bin basil --bin basil-nats-bridge >/dev/null
  CARGO_TARGET_DIR="$DEMO_TARGET_DIR" cargo build --manifest-path "$SCRIPT_DIR/Cargo.toml" >/dev/null

  eval "$("$DEMO_BIN" print-fixtures)"

  echo "openbao"
  LISTEN="${VAULT_ADDR#http://}"
  bao server -dev -dev-root-token-id="$VAULT_TOKEN" -dev-listen-address="$LISTEN" >"$BAO_LOG" 2>&1 &
  BAO_PID="$!"
  for _ in $(seq 1 80); do
    VAULT_ADDR="$VAULT_ADDR" VAULT_TOKEN="$VAULT_TOKEN" bao status >/dev/null 2>&1 && break
    sleep 0.1
  done
  VAULT_ADDR="$VAULT_ADDR" VAULT_TOKEN="$VAULT_TOKEN" bao status >/dev/null
  export VAULT_ADDR VAULT_TOKEN

  bao secrets enable transit >/dev/null 2>&1 || true
  bao secrets enable -path=secret -version=2 kv >/dev/null 2>&1 || true
  write_kv_value "secret/data/demo/broker-request" "$BROKER_REQUEST_PRIVATE"
  write_kv_value "secret/data/demo/broker-request-public" "$BROKER_REQUEST_PUBLIC"
  write_kv_value "secret/data/demo/alice-seal" "$ALICE_SEAL_PRIVATE"
  write_kv_value "secret/data/demo/alice-seal-public" "$ALICE_SEAL_PUBLIC"
  write_kv_value "secret/data/demo/bob-seal" "$BOB_SEAL_PRIVATE"
  write_kv_value "secret/data/demo/bob-seal-public" "$BOB_SEAL_PUBLIC"
  write_kv_value "secret/data/demo/alice-response" "$ALICE_RESPONSE_PRIVATE"
  write_kv_value "secret/data/demo/alice-response-public" "$ALICE_RESPONSE_PUBLIC"

  bao policy write basil-cose-nats-demo - >/dev/null <<HCL
path "transit/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "secret/*" { capabilities = ["create", "read", "update", "delete", "list"] }
HCL
  bao auth enable approle >/dev/null 2>&1 || true
  bao write auth/approle/role/basil-cose-nats-demo \
    token_policies=basil-cose-nats-demo \
    token_ttl=1h \
    token_max_ttl=4h >/dev/null
  role_id="$(bao read -field=role_id auth/approle/role/basil-cose-nats-demo/role-id)"
  bao write -f -field=secret_id auth/approle/role/basil-cose-nats-demo/secret-id >"$APPROLE_SECRET_FILE"
  chmod 600 "$APPROLE_SECRET_FILE"

  printf 'cose-nats-demo-passphrase\n' >"$PASS_FILE"
  chmod 600 "$PASS_FILE"
  write_catalog
  write_policy
  "$ROOT/target/debug/basil" bundle create "$BUNDLE" \
    --slot passphrase:file="$PASS_FILE" \
    --backend "id=bao,type=openbao,role-id=$role_id,secret-id-file=$APPROLE_SECRET_FILE" >/dev/null
  write_agent_config

  echo "nats"
  nats-server -p "$NATS_PORT" >"$NATS_LOG" 2>&1 &
  NATS_PID="$!"
  wait_for_nats

  echo "agent"
  "$ROOT/target/debug/basil" agent --config "$AGENT_CONFIG" >"$AGENT_LOG" 2>&1 &
  AGENT_PID="$!"
  wait_for_file_socket "$SOCKET" "$AGENT_LOG" "$AGENT_PID"

  echo "bridge"
  write_bridge_config
  "$ROOT/target/debug/basil-nats-bridge" --config "$BRIDGE_CONFIG" >"$BRIDGE_LOG" 2>&1 &
  BRIDGE_PID="$!"
  sleep 0.5
  kill -0 "$BRIDGE_PID" >/dev/null 2>&1 || {
    echo "bridge exited during startup; log:" >&2
    cat "$BRIDGE_LOG" >&2
    exit 1
  }

  echo "demo"
  "$DEMO_BIN" run \
    --socket "$SOCKET" \
    --nats-url "$NATS_URL" \
    --bridge-subject "$BRIDGE_SUBJECT"
  echo "workdir: $WORKDIR"
}

main "$@"
