#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# shellcheck source=/dev/null
source "$SCRIPT_DIR/db-keystore.env"

mkdir -p "$BASIL_EXAMPLE_WORKDIR"
chmod 700 "$BASIL_EXAMPLE_WORKDIR"

render_template() {
  local in_file="$1"
  local out_file="$2"
  local escaped_db_path escaped_user_name uid
  uid="$(id -u)"
  escaped_db_path="$(printf '%s' "$BASIL_EXAMPLE_DB_PATH" | sed 's/[\/&]/\\&/g')"
  escaped_user_name="$(id -un | sed 's/[\/&]/\\&/g')"
  sed \
    -e "s/__DB_PATH__/$escaped_db_path/g" \
    -e "s/__UID__/$uid/g" \
    -e "s/__USER_NAME__/$escaped_user_name/g" \
    "$in_file" > "$out_file"
}

make_secret_files() {
  if [[ ! -f "$BASIL_EXAMPLE_DISK_PASSPHRASE_FILE" ]]; then
    umask 077
    printf 'db-keystore-example-passphrase\n' > "$BASIL_EXAMPLE_DISK_PASSPHRASE_FILE"
  fi
  chmod 600 "$BASIL_EXAMPLE_DISK_PASSPHRASE_FILE"

  if [[ ! -f "$BASIL_EXAMPLE_DEK_FILE" ]]; then
    umask 077
    # The bundle DEK must be exactly 32 raw bytes. `bundle create` strips a
    # trailing newline/carriage-return from secret files, so regenerate until
    # the last byte is neither, keeping the DEK it reads at a full 32 bytes.
    while :; do
      head -c 32 /dev/urandom > "$BASIL_EXAMPLE_DEK_FILE"
      last="$(tail -c 1 "$BASIL_EXAMPLE_DEK_FILE" | od -An -tu1 | tr -d ' ')"
      [[ "$last" != 10 && "$last" != 13 ]] && break
    done
  fi
  chmod 600 "$BASIL_EXAMPLE_DEK_FILE"
}

build_binary() {
  # Prefer a prebuilt binary when BASIL_BIN is exported (e.g. an all-features
  # broker); otherwise build basil-bin with the db-keystore backend feature.
  if [[ -n "${BASIL_BIN:-}" ]]; then
    BASIL="$BASIL_BIN"
    return
  fi
  cargo build \
    --manifest-path "$ROOT/Cargo.toml" \
    -p basil-bin \
    --features db-keystore \
    --bin basil
  BASIL="$ROOT/target/debug/basil"
}

init_bundle() {
  if [[ -f "$BASIL_EXAMPLE_BUNDLE" ]]; then
    return
  fi
  "$BASIL" bundle create "$BASIL_EXAMPLE_BUNDLE" \
    --slot "passphrase:file=$BASIL_EXAMPLE_DISK_PASSPHRASE_FILE" \
    --backend "id=$BASIL_EXAMPLE_BACKEND,type=db-keystore,path=$BASIL_EXAMPLE_DB_PATH,dek-file=$BASIL_EXAMPLE_DEK_FILE"
}

write_agent_config() {
  cat > "$BASIL_EXAMPLE_CONFIG" <<EOF
catalog = "$BASIL_EXAMPLE_CATALOG"
policy = "$BASIL_EXAMPLE_POLICY"
bundle = "$BASIL_EXAMPLE_BUNDLE"
socket = "$BASIL_EXAMPLE_SOCKET"
db-keystore-cipher = "aegis256"

[unlock]
unlock-passphrase-file = "$BASIL_EXAMPLE_DISK_PASSPHRASE_FILE"
EOF
}

start_agent() {
  rm -f "$BASIL_EXAMPLE_SOCKET" "$BASIL_EXAMPLE_AGENT_LOG"
  "$BASIL" agent \
    --config "$BASIL_EXAMPLE_CONFIG" \
    >"$BASIL_EXAMPLE_AGENT_LOG" 2>&1 &
  AGENT_PID="$!"
  trap 'kill "$AGENT_PID" >/dev/null 2>&1 || true' EXIT

  for _ in $(seq 1 100); do
    if [[ -S "$BASIL_EXAMPLE_SOCKET" ]]; then
      return
    fi
    if ! kill -0 "$AGENT_PID" >/dev/null 2>&1; then
      echo "basil agent exited during startup; log follows:" >&2
      cat "$BASIL_EXAMPLE_AGENT_LOG" >&2
      exit 1
    fi
    sleep 0.1
  done

  echo "timed out waiting for $BASIL_EXAMPLE_SOCKET; log follows:" >&2
  cat "$BASIL_EXAMPLE_AGENT_LOG" >&2
  exit 1
}

cli() {
  "$BASIL" --socket "$BASIL_EXAMPLE_SOCKET" "$@"
}

field() {
  awk -v name="$1" '$1 == name ":" { print $2 }'
}

hex_of() {
  printf '%s' "$1" | od -An -tx1 -v | tr -d ' \n'
}

main() {
  render_template "$SCRIPT_DIR/catalog.template.json" "$BASIL_EXAMPLE_CATALOG"
  render_template "$SCRIPT_DIR/policy.template.json" "$BASIL_EXAMPLE_POLICY"
  make_secret_files
  build_binary
  init_bundle
  write_agent_config
  start_agent

  echo "status:"
  cli status

  echo
  echo "catalog:"
  cli list

  echo
  echo "mint JWT:"
  cli mint-jwt \
    --key-id "$BASIL_EXAMPLE_SIGNING_KEY" \
    --sub db-keystore-example \
    --ttl-secs 300 \
    --claims-json '{"purpose":"db-keystore-e2e"}'

  echo
  payload="db-keystore signing payload"
  sig="$(cli sign --key-id "$BASIL_EXAMPLE_SIGNING_KEY" "$payload")"
  echo "signature: $sig"
  echo "verify:"
  cli verify --key-id "$BASIL_EXAMPLE_SIGNING_KEY" --signature "$sig" "$payload"

  echo
  plaintext="db-keystore secret payload"
  aad_hex="$(hex_of "db-keystore aad")"
  envelope="$(cli encrypt \
    --key-id "$BASIL_EXAMPLE_AEAD_KEY" \
    --algorithm aes256-gcm \
    --aad-hex "$aad_hex" \
    "$plaintext")"
  echo "$envelope"

  version="$(printf '%s\n' "$envelope" | field version)"
  nonce="$(printf '%s\n' "$envelope" | field nonce)"
  ciphertext="$(printf '%s\n' "$envelope" | field ciphertext)"
  decrypted_hex="$(cli decrypt \
    --key-id "$BASIL_EXAMPLE_AEAD_KEY" \
    --algorithm aes256-gcm \
    --version "$version" \
    --nonce "$nonce" \
    --ciphertext "$ciphertext" \
    --aad-hex "$aad_hex")"
  expected_hex="$(hex_of "$plaintext")"
  echo "decrypted_hex: $decrypted_hex"
  if [[ "$decrypted_hex" != "$expected_hex" ]]; then
    echo "decrypt mismatch: expected $expected_hex" >&2
    exit 1
  fi

  echo
  echo "db-keystore example completed"
  echo "workdir: $BASIL_EXAMPLE_WORKDIR"
  echo "config: $BASIL_EXAMPLE_CONFIG"
}

main "$@"
