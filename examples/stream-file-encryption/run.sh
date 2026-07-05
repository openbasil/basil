#!/usr/bin/env bash
# Boot an OpenBao dev server + a Basil agent (pqc feature), then stream-encrypt a
# multi-MiB file two ways (AES-256-GCM and broker-custodied ML-KEM-768) and prove
# a tampered stream fails closed. Exit 0 only when every assertion passes.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

WORKDIR="${STREAM_FILE_ENCRYPTION_WORKDIR:-/tmp/basil-stream-file-encryption}"
BAO_PORT="${STREAM_FILE_ENCRYPTION_BAO_PORT:-8221}"
VAULT_ADDR="${STREAM_FILE_ENCRYPTION_VAULT_ADDR:-http://127.0.0.1:$BAO_PORT}"
VAULT_TOKEN="${STREAM_FILE_ENCRYPTION_VAULT_TOKEN:-root}"

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
STREAM_DIR="$WORKDIR/stream"

EXAMPLE_TARGET_DIR="$ROOT/target/stream-file-encryption"
EXAMPLE_BIN="$EXAMPLE_TARGET_DIR/debug/stream-file-encryption"

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
    "stream.kem": {
      "class": "sealing", "keyType": "ml-kem-768", "backend": "bao",
      "engine": "kv2", "path": "secret/data/stream/ml-kem-768",
      "publicPath": "secret/data/stream/ml-kem-768-public",
      "writable": true, "missing": "warn",
      "labels": ["crypto_provider=local-software", "crypto_provider_policy=local-software", "pqc_custody=software-encrypted", "pqc_storage_key=stream-kem-aead", "pqc_algorithm=ml-kem-768", "crypto_provider_version=1"],
      "description": "ML-KEM-768 software-custodied sealing key. Provisioned via NewKey; the seed is AEAD-sealed under transit 'stream-kem-aead'. The client wraps the stream CEK against the public encapsulation key and recovers it through UnwrapEnvelope: the decapsulation seed never leaves the vault."
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
  "rules": [
    {
      "id": "local-can-use-stream-kem",
      "subjects": ["local.user"],
      "action": ["op:new_key", "op:get_public_key", "op:decrypt", "op:use_software_custody"],
      "target": ["stream.kem"]
    }
  ],
  "subjects": {
    "local.user": { "allOf": [{ "kind": "unix", "uid": $uid }] }
  },
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

  rm -rf "$WORKDIR"
  mkdir -p "$FIXTURES" "$STREAM_DIR"
  chmod 700 "$WORKDIR"

  echo "== build =="
  if [[ -n "${BASIL_BIN:-}" ]]; then
    BASIL="$BASIL_BIN"
  else
    cargo build --manifest-path "$ROOT/Cargo.toml" -p basil-bin --features pqc --bin basil >/dev/null
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
  bao secrets enable -path=secret -version=2 kv >/dev/null 2>&1 || true
  # The transit AEAD key that seals every custodied ML-KEM seed.
  bao write -f transit/keys/stream-kem-aead type=aes256-gcm96 >/dev/null
  # A publicPath marker so the sealing-key existence probe stays non-fatal; the
  # real encapsulation key lives in the NewKey custody record and is NEVER read here.
  bao kv put secret/stream/ml-kem-768-public "value=$(printf 'unused' | base64 | tr -d '\n')" >/dev/null

  bao policy write basil-stream-file-encryption - >/dev/null <<'HCL'
path "transit/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "secret/*" { capabilities = ["create", "read", "update", "delete", "list"] }
HCL
  bao auth enable approle >/dev/null 2>&1 || true
  bao write auth/approle/role/basil-stream-file-encryption \
    token_policies=basil-stream-file-encryption \
    token_ttl=1h token_max_ttl=4h >/dev/null
  role_id="$(bao read -field=role_id auth/approle/role/basil-stream-file-encryption/role-id)"
  bao write -f -field=secret_id auth/approle/role/basil-stream-file-encryption/secret-id \
    >"$APPROLE_SECRET_FILE"
  chmod 600 "$APPROLE_SECRET_FILE"

  printf 'stream-file-encryption-passphrase\n' >"$PASS_FILE"
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
  "$EXAMPLE_BIN" "$SOCKET" "$STREAM_DIR"
  echo "workdir: $WORKDIR"
  echo "PASS"
}

main "$@"
