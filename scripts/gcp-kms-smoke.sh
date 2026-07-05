#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage:
  scripts/gcp-kms-smoke.sh SERVICE_ACCOUNT_JSON

Environment:
  BASIL_GCP_KMS_LOCATION   GCP KMS location (default: global)
  BASIL_GCP_KMS_KEY_RING   Key ring to create/use (default: basil-smoke)
  BASIL_GCP_KMS_KEY_ID     Key id to create (default: basil-smoke-<timestamp>-<pid>)

Creates an Ed25519 Cloud KMS key, signs a message, verifies the signature
locally with OpenSSL, then schedules destruction of the created key version.
EOF
}

if [[ $# -ne 1 ]]; then
  usage
  exit 2
fi

cred_file=$1
if [[ ! -f "$cred_file" ]]; then
  echo "credential file not found: $cred_file" >&2
  exit 2
fi

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 2
  fi
}

need base64
need curl
need date
need jq
need mktemp
need openssl

tmp=$(mktemp -d)
access_token=
key_created=false
remote_cleaned=false
version_api=

cleanup_remote() {
  if [[ "$key_created" != "true" || "$remote_cleaned" == "true" || -z "${access_token:-}" ]]; then
    return 0
  fi

  local destroy_body destroy_status
  destroy_body=$tmp/destroy-on-exit.json
  set +e
  destroy_status=$(api POST "$version_api:destroy" '{}' "$destroy_body")
  set -e
  if [[ "$destroy_status" == "200" ]]; then
    echo "scheduled destruction for created key version"
    remote_cleaned=true
  else
    echo "WARN: could not destroy created key version (HTTP $destroy_status)" >&2
    jq -c '{error}' "$destroy_body" >&2 || true
  fi
}

cleanup() {
  cleanup_remote
  rm -rf "$tmp"
}
trap cleanup EXIT

private_key=$tmp/service-account.pem
pub_key=$tmp/kms-public.pem
message=$tmp/message.bin
signature=$tmp/signature.bin

jq -er '.private_key' "$cred_file" >"$private_key"
chmod 600 "$private_key"

project=$(jq -er '.project_id' "$cred_file")
client_email=$(jq -er '.client_email' "$cred_file")
location=${BASIL_GCP_KMS_LOCATION:-global}
key_ring=${BASIL_GCP_KMS_KEY_RING:-basil-smoke}
key_id=${BASIL_GCP_KMS_KEY_ID:-basil-smoke-$(date +%s)-$$}

perm=$(stat -c '%a' "$cred_file" 2>/dev/null || true)
if [[ -n "$perm" && "$perm" != "600" && "$perm" != "400" ]]; then
  echo "WARN: credential file mode is $perm; 0600/0400 is preferred for secret files" >&2
fi

b64url() {
  openssl base64 -A | tr '+/' '-_' | tr -d '='
}

iat=$(date +%s)
exp=$((iat + 3600))
header=$(jq -nc '{alg:"RS256",typ:"JWT"}' | b64url)
claims=$(
  jq -nc \
    --arg iss "$client_email" \
    --arg scope "https://www.googleapis.com/auth/cloud-platform" \
    --arg aud "https://oauth2.googleapis.com/token" \
    --argjson iat "$iat" \
    --argjson exp "$exp" \
    '{iss:$iss,scope:$scope,aud:$aud,iat:$iat,exp:$exp}' | b64url
)
unsigned_jwt="$header.$claims"
signed_jwt=$(
  printf '%s' "$unsigned_jwt" \
    | openssl dgst -sha256 -sign "$private_key" \
    | b64url
)
jwt="$unsigned_jwt.$signed_jwt"

token_body=$tmp/token.json
token_status=$(
  curl -sS -o "$token_body" -w '%{http_code}' \
    -X POST 'https://oauth2.googleapis.com/token' \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer' \
    --data-urlencode "assertion=$jwt"
)
if [[ "$token_status" != "200" ]]; then
  echo "OAuth token exchange failed with HTTP $token_status" >&2
  jq -c '{error, error_description}' "$token_body" >&2 || true
  exit 1
fi
access_token=$(jq -er '.access_token' "$token_body")

api() {
  local method=$1
  local url=$2
  local data=$3
  local out=$4

  if [[ -n "$data" ]]; then
    curl -sS -o "$out" -w '%{http_code}' \
      -X "$method" \
      -H "Authorization: Bearer $access_token" \
      -H 'Content-Type: application/json' \
      --data "$data" \
      "$url"
  else
    curl -sS -o "$out" -w '%{http_code}' \
      -X "$method" \
      -H "Authorization: Bearer $access_token" \
      "$url"
  fi
}

kms_root="https://cloudkms.googleapis.com/v1/projects/$project/locations/$location"
ring_url="$kms_root/keyRings"
ring_resource="projects/$project/locations/$location/keyRings/$key_ring"
ring_api="$kms_root/keyRings/$key_ring"
key_resource="$ring_resource/cryptoKeys/$key_id"
key_api="$ring_api/cryptoKeys/$key_id"
version_api="$key_api/cryptoKeyVersions/1"

echo "GCP KMS smoke: project=$project location=$location keyRing=$key_ring key=$key_id"

ring_body=$tmp/create-ring.json
ring_status=$(api POST "$ring_url?keyRingId=$key_ring" '{}' "$ring_body")
case "$ring_status" in
  200|201)
    echo "created key ring: $key_ring"
    ;;
  409)
    echo "using existing key ring: $key_ring"
    ;;
  *)
    echo "create key ring failed with HTTP $ring_status" >&2
    jq -c '{error}' "$ring_body" >&2 || true
    exit 1
    ;;
esac

key_body=$tmp/create-key.json
key_status=$(
  api POST "$ring_api/cryptoKeys?cryptoKeyId=$key_id" \
    '{"purpose":"ASYMMETRIC_SIGN","versionTemplate":{"algorithm":"EC_SIGN_ED25519","protectionLevel":"SOFTWARE"}}' \
    "$key_body"
)
if [[ "$key_status" != "200" && "$key_status" != "201" ]]; then
  echo "create crypto key failed with HTTP $key_status" >&2
  jq -c '{error}' "$key_body" >&2 || true
  exit 1
fi
key_created=true
echo "created Ed25519 signing key"

printf 'basil gcp kms smoke %s\n' "$key_id" >"$message"
message_b64=$(base64 -w0 <"$message")
sign_body=$tmp/sign.json
sign_status=$(
  api POST "$version_api:asymmetricSign" \
    "$(jq -nc --arg data "$message_b64" '{data:$data}')" \
    "$sign_body"
)
if [[ "$sign_status" != "200" ]]; then
  echo "asymmetric sign failed with HTTP $sign_status" >&2
  jq -c '{error}' "$sign_body" >&2 || true
  exit 1
fi
jq -er '.signature' "$sign_body" | base64 -d >"$signature"
echo "created signature with Cloud KMS"

pub_body=$tmp/public-key.json
pub_status=$(api GET "$version_api/publicKey" '' "$pub_body")
if [[ "$pub_status" != "200" ]]; then
  echo "get public key failed with HTTP $pub_status" >&2
  jq -c '{error}' "$pub_body" >&2 || true
  exit 1
fi
jq -er '.pem' "$pub_body" >"$pub_key"

openssl pkeyutl \
  -verify \
  -pubin \
  -inkey "$pub_key" \
  -rawin \
  -in "$message" \
  -sigfile "$signature" >/dev/null
echo "signature verified locally with OpenSSL"

destroy_body=$tmp/destroy.json
destroy_status=$(api POST "$version_api:destroy" '{}' "$destroy_body")
if [[ "$destroy_status" == "200" ]]; then
  echo "scheduled destruction for created key version"
  remote_cleaned=true
else
  echo "WARN: could not destroy created key version (HTTP $destroy_status)" >&2
  jq -c '{error}' "$destroy_body" >&2 || true
fi

echo "GCP KMS smoke passed"
