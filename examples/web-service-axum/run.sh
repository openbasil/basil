#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
#
# SPDX-License-Identifier: Apache-2.0

# Boot a Basil agent on the zero-dependency db-keystore backend, start the
# axum web service against its socket, and prove both halves of the story:
# POST /token returns a broker-minted JWT, and the SAME uid is denied a plain
# read of the signing key. Exit 0 only when every assertion passes.
set -euo pipefail

trap 'st=$?; [[ $st -ne 0 ]] && echo "FAIL (exit $st)" >&2; exit $st' EXIT

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

WORKDIR="${WEB_SERVICE_AXUM_WORKDIR:-${TMPDIR:-/tmp}/basil-web-axum}"
PORT="${WEB_SERVICE_AXUM_PORT:-8095}"
SIGNING_KEY="web.signing_key"

DB_PATH="$WORKDIR/keystore.db"
SOCKET="$WORKDIR/agent.sock"
BUNDLE="$WORKDIR/bundle.sealed"
PASS_FILE="$WORKDIR/disk-passphrase.txt"
DEK_FILE="$WORKDIR/db-keystore-dek.bin"
CATALOG="$WORKDIR/catalog.json"
POLICY="$WORKDIR/policy.json"
AGENT_CONFIG="$WORKDIR/basil-agent.toml"
AGENT_LOG="$WORKDIR/agent.log"
SVC_LOG="$WORKDIR/service.log"

AGENT_PID=""
SVC_PID=""

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

cleanup() {
  for pid in "$SVC_PID" "$AGENT_PID"; do
    [[ -n "$pid" ]] && kill "$pid" >/dev/null 2>&1 || true
  done
}

render_template() {
  local in_file="$1" out_file="$2"
  local escaped_db_path escaped_user_name uid
  uid="$(id -u)"
  escaped_db_path="$(printf '%s' "$DB_PATH" | sed 's/[\/&]/\\&/g')"
  escaped_user_name="$(id -un | sed 's/[\/&]/\\&/g')"
  sed \
    -e "s/__DB_PATH__/$escaped_db_path/g" \
    -e "s/__UID__/$uid/g" \
    -e "s/__USER_NAME__/$escaped_user_name/g" \
    "$in_file" > "$out_file"
}

make_secret_files() {
  umask 077
  printf 'web-service-axum-passphrase\n' > "$PASS_FILE"
  # The bundle DEK must be exactly 32 raw bytes. `bundle create` strips a
  # trailing newline/carriage-return from secret files, so regenerate until
  # the last byte is neither, keeping the DEK it reads at a full 32 bytes.
  while :; do
    head -c 32 /dev/urandom > "$DEK_FILE"
    last="$(tail -c 1 "$DEK_FILE" | od -An -tu1 | tr -d ' ')"
    [[ "$last" != 10 && "$last" != 13 ]] && break
  done
}

find_basil() {
  # Prefer a prebuilt binary when BASIL_BIN is exported, then `basil` on
  # PATH, then the repo's own debug build (default features include the
  # db-keystore backend this example runs on).
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

start_agent() {
  cat > "$AGENT_CONFIG" <<EOF
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

start_service() {
  BASIL_SOCKET="$SOCKET" BIND_ADDR="127.0.0.1:$PORT" \
    "$SCRIPT_DIR/target/debug/web-service-axum" >"$SVC_LOG" 2>&1 &
  SVC_PID="$!"
  for _ in $(seq 1 100); do
    curl -fsS "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && return
    if ! kill -0 "$SVC_PID" >/dev/null 2>&1; then
      echo "web service exited during startup; log follows:" >&2
      cat "$SVC_LOG" >&2
      exit 1
    fi
    sleep 0.1
  done
  echo "timed out waiting for the web service on port $PORT; log follows:" >&2
  cat "$SVC_LOG" >&2
  exit 1
}

main() {
  need curl
  need cargo

  rm -rf "$WORKDIR"
  mkdir -p "$WORKDIR"
  chmod 700 "$WORKDIR"

  echo "== build =="
  find_basil
  # The example crate is a detached workspace: this build stays inside the
  # example directory and never touches the repo root target/.
  cargo build --manifest-path "$SCRIPT_DIR/Cargo.toml" >/dev/null

  echo "== scaffold =="
  render_template "$SCRIPT_DIR/catalog.template.json" "$CATALOG"
  render_template "$SCRIPT_DIR/policy.template.json" "$POLICY"
  make_secret_files
  "$BASIL" bundle create "$BUNDLE" \
    --slot "passphrase:file=$PASS_FILE" \
    --backend "id=local-db,type=db-keystore,path=$DB_PATH,dek-file=$DEK_FILE" \
    >/dev/null

  echo "== agent =="
  start_agent

  echo "== service =="
  start_service

  echo "== mint: POST /token returns a broker-signed JWT =="
  token="$(curl -fsS -X POST "http://127.0.0.1:$PORT/token")"
  echo "token: $token"
  # A compact JWT is exactly three dot-separated base64url segments.
  if [[ ! "$token" =~ ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$ ]]; then
    echo "response is not a compact JWT: $token" >&2
    exit 1
  fi
  echo "token shape: OK (header.claims.signature)"

  echo
  echo "== deny: the same uid may NOT read the key it mints under =="
  set +e
  deny_out="$("$BASIL" --socket "$SOCKET" get --key-id "$SIGNING_KEY" 2>&1)"
  deny_status=$?
  set -e
  if [[ $deny_status -eq 0 ]]; then
    echo "expected 'basil get --key-id $SIGNING_KEY' to be denied, but it succeeded:" >&2
    echo "$deny_out" >&2
    exit 1
  fi
  if ! grep -qiE 'permission[ _-]?denied|unauthorized' <<<"$deny_out"; then
    echo "expected a PermissionDenied error, got:" >&2
    echo "$deny_out" >&2
    exit 1
  fi
  echo "deny observed: $deny_out"

  echo
  echo "workdir: $WORKDIR"
  echo "PASS"
}

main "$@"
