#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
#
# SPDX-License-Identifier: Apache-2.0

# prefill-test-store.sh: pre-fill a Vault-compatible store (OpenBao or HashiCorp
# Vault) + build a matching sealed bundle for basil broker test scenarios (vault-8d1).
#
# The --engine selects the server CLI: `openbao` -> `bao`, `vault` -> `vault`.
# Both speak the same dev-server flags and secrets/auth subcommands this script
# uses, and both honor VAULT_ADDR/VAULT_TOKEN, so only the binary name changes.
#
# Implements steps 1-5 of the runbook (docs/runbooks/prefill-openbao-for-tests.md):
#   1. start the server (dev mode, no seal) at a temp data dir / chosen addr
#   2. enable the transit + kv-v2 secrets engines
#   3. create a couple of PRE-FILLED test secrets (a transit ed25519 key + a
#      kv-v2 value) out-of-band, so the broker starts from a known store state
#   4. write a sample catalog.json + policy.json into a fixtures dir, with the
#      policy principal templated to the *running uid* (the SO_PEERCRED uid the
#      broker's PDP binds to; see the runbook §"two unlock layers" / authz)
#   5. create a test AppRole and build the broker + create the 0600 sealed
#      bundle (passphrase slot, --backend id=bao,type=openbao,role-id=...,
#      secret-id-file=... for backend 'bao') the broker uses to reach the server
#
# It does NOT start the broker. That is the e2e test's / operator's job (step 6).
# The script leaves the dev server RUNNING and prints exactly how to launch the
# broker against the pre-filled store + bundle, plus how to stop the server.
#
# Idempotent-ish: re-running re-seeds the (dev, in-memory) store and rewrites the
# fixtures. `<cli> write -f transit/keys/<name>` is itself idempotent (no-op if
# the key exists). The work dir is recreated each run.
#
# Usage:
#   scripts/prefill-test-store.sh [--engine openbao|vault] [--workdir DIR]
#                                 [--addr ADDR] [--token TOK] [--no-build]
#                                 [--no-start-server]
# Env equivalents: BASIL_TEST_ENGINE, PREFILL_WORKDIR, VAULT_ADDR, PREFILL_TOKEN.
#
# Cross-references:
#   designs/catalog-policy-schema.html §5  (export JSON shape)
#   designs/unlock-and-bundle.html         (the sealed bundle / two unlock layers)

set -euo pipefail

# ---- parameters -------------------------------------------------------------

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

WORKDIR="${PREFILL_WORKDIR:-/tmp/sv-prefill}"
ADDR="${VAULT_ADDR:-http://127.0.0.1:8210}"   # non-default port: 8200 is often busy
TOKEN="${PREFILL_TOKEN:-root}"
ENGINE="${BASIL_TEST_ENGINE:-openbao}"        # openbao -> `bao`, vault -> `vault`
DO_BUILD=1
START_SERVER=1   # the script owns a dev server unless one is already at ADDR
# --spiffe-boot provisions the SpiffeSigner broker-boot path (basil-dk5.4): an RSA
# JWT-SVID issuer key + a `jwt` auth mount (jwt_validation_pubkeys = that key's
# public half) + a role->policy, and emits the signer's private PEM + spiffe_id as
# fixtures so the e2e seals a `BackendCred::SpiffeSigner` bundle and boots the
# broker through `auth/jwt/login`. Off by default: the AppRole bundle path
# (boot_basil) is unchanged. The two paths are mutually exclusive: under
# --spiffe-boot the AppRole bundle is NOT built (the e2e seals its own bundle).
SPIFFE_BOOT=0

while [ $# -gt 0 ]; do
  case "$1" in
    --workdir) WORKDIR="$2"; shift 2 ;;
    --addr)    ADDR="$2"; shift 2 ;;
    --token)   TOKEN="$2"; shift 2 ;;
    --engine)  ENGINE="$2"; shift 2 ;;
    --no-build) DO_BUILD=0; shift ;;
    --no-start-server) START_SERVER=0; shift ;;  # reuse a server already at ADDR
    --spiffe-boot) SPIFFE_BOOT=1; shift ;;       # provision the SpiffeSigner boot path
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# The engine picks the CLI binary. `bao` (OpenBao) and `vault` (HashiCorp Vault)
# accept identical `server -dev` flags and the secrets/auth subcommands below.
case "$ENGINE" in
  openbao) CLI="bao" ;;
  vault)   CLI="vault" ;;
  *) echo "FATAL: unknown --engine '$ENGINE' (want openbao|vault)" >&2; exit 2 ;;
esac

LISTEN="${ADDR#http://}"
LISTEN="${LISTEN#https://}"   # -dev-listen-address wants host:port only

FIXTURES="$WORKDIR/fixtures"
SERVER_LOG="$WORKDIR/server.log"
SERVER_PIDFILE="$WORKDIR/server.pid"
PASS_FILE="$FIXTURES/disk-pass.txt"
APPROLE_SECRET_FILE="$FIXTURES/approle-secret-id.txt"
BUNDLE="$FIXTURES/bundle.sealed"
AGENT_CONFIG="$FIXTURES/basil-agent.toml"
CATALOG="$FIXTURES/catalog.json"
POLICY="$FIXTURES/policy.json"
SOCKET="$WORKDIR/agent.sock"

UID_NUM="$(id -u)"
AGENT_BIN="$REPO_ROOT/target/debug/basil"

# The two PRE-FILLED secrets (created in bao before the broker ever runs):
PREFILLED_TRANSIT_KEY="web-tls"                  # transit ed25519 key (bare name)
PREFILLED_KV_PATH="secret/data/app/db-password"  # kv-v2 (mount-qualified path)
# A catalog key declared missing=generate but left ABSENT: the broker's startup
# reconcile (vault-zrg) must create it. The transit path is the bare key name.
GENERATE_TRANSIT_KEY="nats-account"
# A symmetric AEAD key, also left ABSENT for reconcile=generate (encrypt/decrypt coverage).
AEAD_TRANSIT_KEY="app-aead"
# A value-store (engine=kv2) Ed25519 materialize-to-sign signing key (vault-iiz,
# basil-cy8). Its 32-byte Ed25519 seed is PRE-FILLED out-of-band into a KV-v2 path
# (the broker materializes it into Zeroizing, signs in process, zeroizes; the seed
# never leaves the vault except into the broker's own memory for one sign). The
# catalog key is class=asymmetric + engine=kv2 + keyType=ed25519. We use a FIXED
# 32-byte seed so the e2e can assert the public + signature deterministically. The
# seed is stored exactly like any other broker KV value: raw 32 bytes,
# base64-encoded, under the `value` field (kv_get_secret base64-DECODES).
KV2_SIGNER_KV_PATH="secret/data/kv2/signing-key"   # kv-v2 (mount-qualified) seed path
# The Ed25519 PUBLIC half, provisioned out of band alongside the seed (basil-o86):
# the broker reads it here for verify/get_public_key so the seed is materialized
# ONLY on sign. A non-secret KV value (raw 32 bytes, base64 under `value`).
KV2_SIGNER_PUBLIC_KV_PATH="secret/data/kv2/signing-key-public"
# A FIXED 32-byte Ed25519 seed (64 hex chars), so the e2e can assert the public
# and signature deterministically. Its public half (ed25519-dalek-derived) is
# KV2_SIGNER_PUBLIC_HEX below: the e2e anchors on that to prove the seed→public
# mapping, then asserts the broker's signature equals a deterministic in-process
# Ed25519 sign over the same seed.
KV2_SIGNER_SEED_HEX="9d61b19deff3ee2e5b3c00a4a14d2b9bf9c2c9d5fb02b5b6e4f00f7d9e2f6e8e"
# The ed25519-dalek-derived public half of KV2_SIGNER_SEED_HEX (written out of
# band to KV2_SIGNER_PUBLIC_KV_PATH; the e2e re-derives it from the seed in-test).
KV2_SIGNER_PUBLIC_HEX="b9401e836a5c59aa085c22dbbc123abb41ab80e3c49fcae3a921ee8cf662cdd6"
# BYOK import targets (basil-dk5.7): transit ed25519 keys left ABSENT at boot with
# missing="warn" so reconcile neither FATALs (missing=error) nor pre-creates them
# (missing=generate): the e2e IMPORTS them in place. The first is granted to the
# running uid via the operator role (which includes `import`); the SECOND is NOT
# granted import, to prove import-set's all-or-nothing authorization (one bad
# entry rejects the whole batch and creates NEITHER key).
BYOK_IMPORT_KEY="byok-imported"          # transit name; catalog key byok.imported
BYOK_RSA_KEY="byok-rsa"                  # transit name; catalog key byok.rsa
BYOK_ECDSA_KEY="byok-ecdsa"              # transit name; catalog key byok.ecdsa
BYOK_DENIED_KEY="byok-denied"            # transit name; catalog key byok.denied
# ECDSA P-384 / P-521 live-crypto e2e targets (basil-0jkw). Left ABSENT at boot
# (missing=warn) so the ecdsa live e2e generates them in place via the NewKey RPC,
# then does a real ES384/ES512 transit sign/verify round-trip. P-384 additionally
# mints an ES384 JWT via the generic MintJwt path (jws_alg_for_public_key -> ES384);
# P-521 has no JWT-SVID profile alg, so it is sign/verify only. The running uid is
# granted role:signer + role:minter + op:new_key over both (step 4 policy).
ECDSA_P384_KEY="ecdsa-p384"              # transit name; catalog key ecdsa.p384
ECDSA_P521_KEY="ecdsa-p521"              # transit name; catalog key ecdsa.p521
# A pki engine mount + issue role for X.509 leaf issuance (basil-dk5.3). The
# catalog key 'web.tls.cert_issuer' points at pki/issue/<role>; the broker mints
# a DNS/IP-SAN leaf signed by an internal root the engine holds in place.
PKI_MOUNT="pki"
PKI_ROLE="basil-leaf"
PKI_ROOT_CN="basil-test-root"
PKI_ALLOWED_DOMAIN="example.org"
# SPIFFE Workload API issuers (basil-dk5.11). The standard rust-spiffe client
# (the `spiffe` crate) drives Basil's Workload API over the same socket. Two
# issuers, selected by labels:
#   - X509-SVID: a SECOND pki issue role on the same $PKI_MOUNT that permits
#     SPIFFE URI SANs; the broker sends uri_sans=spiffe://<td>/<path> to it.
#   - JWT-SVID: an ed25519 transit signing key the broker signs JWT-SVIDs with.
SPIFFE_TRUST_DOMAIN="example.org"
PKI_SPIFFE_ROLE="spiffe-svid"            # pki/issue/<role> for X509-SVID leaves
# The SPIFFE JWT-SVID profile mandates RS256/ES256 (NOT EdDSA), so the JWT-SVID
# signer is an RSA-2048 transit key. The transit backend can't reconcile=generate
# an RSA key, so it's PRE-FILLED out-of-band (like web-tls) and the catalog key
# uses missing=warn.
SPIFFE_JWT_TRANSIT_KEY="spiffe-jwt"      # bare transit name (rsa-2048) for the JWT-SVID signer
APPROLE_NAME="basil-test"
APPROLE_POLICY="basil-prefill-test"
# SpiffeSigner broker-boot path (basil-dk5.4, --spiffe-boot). The broker self-mints
# a JWT-SVID with an RSA-2048 issuer key and exchanges it at auth/$JWT_AUTH_MOUNT/login
# for a short-lived backend token. The auth mount validates the token against the
# issuer key's PUBLIC half (jwt_validation_pubkeys, static-key validation, no JWKS
# URL, no bound issuer), and a role bound to the SVID's audience + subject maps to
# the same broad test policy the AppRole path uses.
JWT_AUTH_MOUNT="jwt"
JWT_ROLE="basil-spiffe"
JWT_AUDIENCE="$ENGINE"                       # written to the broker config as jwt-audience
SPIFFE_BROKER_ID="spiffe://$SPIFFE_TRUST_DOMAIN/basil"  # the broker's own SPIFFE id (SVID sub)
SPIFFE_SIGNER_KEY="$FIXTURES/spiffe-signer.key.pem"     # RSA-2048 private (PKCS#8); sealed into the bundle by the e2e
SPIFFE_SIGNER_PUB="$FIXTURES/spiffe-signer.pub.pem"     # SPKI public; registered as jwt_validation_pubkeys
SPIFFE_BROKER_ID_FILE="$FIXTURES/spiffe-signer.id.txt"  # the broker SPIFFE id, for the e2e to seal alongside the key

echo "== prefill-test-store =="
echo "  repo:     $REPO_ROOT"
echo "  workdir:  $WORKDIR"
echo "  engine:   $ENGINE  (cli: $CLI)"
echo "  addr:     $ADDR  (listen $LISTEN)"
echo "  uid:      $UID_NUM  (the SO_PEERCRED principal the policy will grant)"
echo

require() { command -v "$1" >/dev/null 2>&1 || { echo "FATAL: '$1' not on PATH" >&2; exit 1; }; }
require "$CLI"

# ---- step 5a: build the binaries (do it early so a build break fails fast) ---

if [ "$DO_BUILD" -eq 1 ]; then
  echo "-- building basil"
  ( cd "$REPO_ROOT" && cargo build -p basil-bin )
fi
[ -x "$AGENT_BIN" ] || { echo "FATAL: $AGENT_BIN not built (drop --no-build)" >&2; exit 1; }

# ---- work dir ---------------------------------------------------------------

rm -rf "$WORKDIR"
mkdir -p "$FIXTURES"

# ---- step 1: start the server (dev mode = no seal layer) --------------------

if [ "$START_SERVER" -eq 1 ]; then
  echo "-- step 1: starting $ENGINE dev server ($CLI) at $ADDR"
  # Dev mode keeps the store in memory and is auto-unsealed (no Shamir/unseal):
  # this collapses the FIRST unlock layer (the server's own seal). For a persisted
  # image use file/raft storage + init/unseal; see the runbook.
  "$CLI" server -dev \
      -dev-root-token-id="$TOKEN" \
      -dev-listen-address="$LISTEN" \
      >"$SERVER_LOG" 2>&1 &
  echo $! >"$SERVER_PIDFILE"

  # Wait for the dev server to answer health.
  for _ in $(seq 1 50); do
    if VAULT_ADDR="$ADDR" "$CLI" status >/dev/null 2>&1; then break; fi
    sleep 0.2
  done
  VAULT_ADDR="$ADDR" "$CLI" status >/dev/null 2>&1 \
    || { echo "FATAL: $ENGINE dev server did not come up; see $SERVER_LOG" >&2; cat "$SERVER_LOG" >&2; exit 1; }
  echo "   $ENGINE up (pid $(cat "$SERVER_PIDFILE"))"
else
  echo "-- step 1: skipped (--no-start-server); using a server already at $ADDR"
fi

export VAULT_ADDR="$ADDR"
export VAULT_TOKEN="$TOKEN"

# ---- step 2: enable transit + kv-v2 ----------------------------------------

echo "-- step 2: enabling transit + kv-v2 + pki engines"
# `secrets enable` errors if already enabled; treat that as success (idempotent).
"$CLI" secrets enable transit            >/dev/null 2>&1 || echo "   (transit already enabled)"
# Dev mode mounts a kv-v2 at secret/ already; enabling again is a no-op/err.
"$CLI" secrets enable -path=secret -version=2 kv >/dev/null 2>&1 || echo "   (kv-v2 'secret/' already enabled)"

# pki: mount, raise the mount max-lease TTL, generate an internal root, and create
# an issue role. bao and vault take identical commands here (same PKI engine API).
echo "-- step 2b: enabling + configuring pki ($PKI_MOUNT, role $PKI_ROLE)"
"$CLI" secrets enable -path="$PKI_MOUNT" pki >/dev/null 2>&1 || echo "   (pki '$PKI_MOUNT/' already enabled)"
"$CLI" secrets tune -max-lease-ttl=87600h "$PKI_MOUNT" >/dev/null
# Internal root: the private CA key is generated and held in the engine, never
# exported: the broker brokers issuance, the CA key stays in place.
"$CLI" write -f "$PKI_MOUNT/root/generate/internal" \
    common_name="$PKI_ROOT_CN" ttl=87600h >/dev/null
# Issue role: allow the test domain (+ subdomains) and IP SANs so a DNS+IP leaf
# is authorized; cap the leaf TTL well under the mount max.
"$CLI" write "$PKI_MOUNT/roles/$PKI_ROLE" \
    allowed_domains="$PKI_ALLOWED_DOMAIN" \
    allow_subdomains=true \
    allow_ip_sans=true \
    max_ttl=720h >/dev/null

# SPIFFE X509-SVID issue role (basil-dk5.11): a SECOND role on the same pki mount
# that permits SPIFFE URI SANs. issue_x509_svid POSTs uri_sans=spiffe://<td>/<path>
# to pki/issue/<role>, so the role MUST allow that URI SAN (the wildcard covers any
# workload path) or issuance 400s. The leaf carries the SPIFFE ID as its only URI
# SAN; rust-spiffe validates that leaf (digitalSignature key usage, CA=false, exactly
# one URI SAN). require_cn=false + allow_any_name so a SPIFFE leaf needs no DNS CN.
echo "-- step 2c: pki SPIFFE X509-SVID role ($PKI_MOUNT/roles/$PKI_SPIFFE_ROLE)"
"$CLI" write "$PKI_MOUNT/roles/$PKI_SPIFFE_ROLE" \
    allowed_uri_sans="spiffe://$SPIFFE_TRUST_DOMAIN/*" \
    allow_any_name=true \
    allow_subdomains=true \
    require_cn=false \
    enforce_hostnames=false \
    key_usage="DigitalSignature,KeyAgreement,KeyEncipherment" \
    basic_constraints_valid_for_non_ca=true \
    max_ttl=72h >/dev/null

# ---- step 3: create the PRE-FILLED secrets (out-of-band) --------------------

echo "-- step 3: creating pre-filled secrets"
echo "   transit key:  $PREFILLED_TRANSIT_KEY (ed25519)"
"$CLI" write -f "transit/keys/$PREFILLED_TRANSIT_KEY" type=ed25519 >/dev/null
echo "   kv-v2 value:  $PREFILLED_KV_PATH"
# kv put takes the logical path (without the /data/ infix); strip secret/data/ -> secret/.
# IMPORTANT: the broker stores KV values base64-encoded under a `value` field
# (transit.rs kv_put: {"data":{"value":"<b64>"}}), and kv_get base64-DECODES it.
# So a pre-filled value the broker can read MUST be written the same way: the raw
# secret bytes, base64-encoded, under `value`. A plain `bao kv put value=foo`
# would store raw text the broker then fails to base64-decode.
KV_LOGICAL="${PREFILLED_KV_PATH/\/data\//\/}"
PREFILLED_KV_SECRET="prefilled-db-pa55"
KV_VALUE_B64="$(printf '%s' "$PREFILLED_KV_SECRET" | base64 | tr -d '\n')"
"$CLI" kv put "$KV_LOGICAL" "value=$KV_VALUE_B64" >/dev/null
echo "   (left ABSENT for reconcile=generate: transit key '$GENERATE_TRANSIT_KEY')"
echo "   (left ABSENT for reconcile=generate: SPIFFE JWT-SVID signer '$SPIFFE_JWT_TRANSIT_KEY')"

# Value-store Ed25519 materialize-to-sign signing key (engine=kv2, vault-iiz,
# basil-cy8): write the 32-byte Ed25519 seed into KV exactly like any broker KV
# value: raw bytes, base64-encoded, under the `value` field (kv_get_secret
# base64-DECODES it). The seed is the FIXED RFC 8032 Test 1 secret key so the e2e
# can assert the public + signature deterministically. xxd turns the hex seed into
# the raw 32 bytes before base64.
require xxd
echo "   kv-v2 Ed25519 seed: $KV2_SIGNER_KV_PATH (catalog key kv2.signing_key; engine=kv2 materialize-to-sign seed)"
KV2_SIGNER_LOGICAL="${KV2_SIGNER_KV_PATH/\/data\//\/}"
KV2_SIGNER_SEED_B64="$(printf '%s' "$KV2_SIGNER_SEED_HEX" | xxd -r -p | base64 | tr -d '\n')"
"$CLI" kv put "$KV2_SIGNER_LOGICAL" "value=$KV2_SIGNER_SEED_B64" >/dev/null
# The PUBLIC half, provisioned out of band (basil-o86) so verify/get_public_key
# never materialize the seed. Same KV value shape (raw 32 bytes, base64).
echo "   kv-v2 Ed25519 public: $KV2_SIGNER_PUBLIC_KV_PATH (out-of-band public half; verify/get_public_key read it, never the seed)"
KV2_SIGNER_PUBLIC_LOGICAL="${KV2_SIGNER_PUBLIC_KV_PATH/\/data\//\/}"
KV2_SIGNER_PUBLIC_B64="$(printf '%s' "$KV2_SIGNER_PUBLIC_HEX" | xxd -r -p | base64 | tr -d '\n')"
"$CLI" kv put "$KV2_SIGNER_PUBLIC_LOGICAL" "value=$KV2_SIGNER_PUBLIC_B64" >/dev/null

# ---- step 3a2: PQC software-custody provisioning prerequisites (basil-yfg7) --
# The PQC software-custody keys (pqc.sign ML-DSA-65, pqc.seal ML-KEM-768) are now
# provisioned at e2e runtime through the client NewKey RPC (the basil-o5qx seam):
# the broker generates the seed, AEAD-seals it under the transit storage key
# below, writes the SoftwareCustodyKeyRecord, and returns only the public half.
# So the prefill no longer mints byte-identical custody records out of band. It
# provisions only what NewKey needs: this transit AEAD wrap key, the catalog
# entries (step 4), and the op:new_key + op:use_software_custody grants (step 4
# policy). pqc.denied/pqc.backend are deliberately NOT provisioned: their denial
# (missing op:use_software_custody / no backend-native ML-DSA) fails at provider
# selection, before any custody record is read.
PQC_STORAGE_KEY="pqc-aead"   # transit aes256-gcm96 key that wraps every seed
echo "   transit AEAD wrap key: $PQC_STORAGE_KEY (aes256-gcm96; seals PQC seeds minted via NewKey)"
"$CLI" write -f "transit/keys/$PQC_STORAGE_KEY" type=aes256-gcm96 >/dev/null

# pqc.seal is Class::Sealing, whose reconcile existence probe expects an
# out-of-band public at its publicPath. NewKey records the encapsulation key in
# the custody record (read by GetPublicKey, basil-4ybx), not the publicPath, so
# seed a marker there to keep a post-provision reconcile/reload non-fatal. The
# value is NEVER read (GetPublicKey reads the record; wrap derives from the seed).
echo "   kv-v2 PQC ML-KEM-768 publicPath marker: secret/pqc/ml-kem-768-public (sealing probe only; never read)"
"$CLI" kv put "secret/pqc/ml-kem-768-public" "value=$(printf 'unused' | base64 | tr -d '\n')" >/dev/null

# ---- step 3b: create a live AppRole for the broker bundle -------------------

echo "-- step 3b: creating AppRole credential for broker startup"
"$CLI" policy write "$APPROLE_POLICY" - >/dev/null <<HCL
path "transit/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "secret/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "pki/*" {
  capabilities = ["create", "read", "update", "list"]
}
HCL
"$CLI" auth enable approle >/dev/null 2>&1 || echo "   (approle auth already enabled)"
"$CLI" write "auth/approle/role/$APPROLE_NAME" \
    "token_policies=$APPROLE_POLICY" \
    token_ttl=1h \
    token_max_ttl=4h >/dev/null
APPROLE_ROLE_ID="$("$CLI" read -field=role_id "auth/approle/role/$APPROLE_NAME/role-id")"
APPROLE_SECRET_ID="$("$CLI" write -f -field=secret_id "auth/approle/role/$APPROLE_NAME/secret-id")"

# ---- step 3c: provision the SpiffeSigner broker-boot path (--spiffe-boot) ----
# Only under --spiffe-boot. Generates the broker's RSA-2048 JWT-SVID issuer key out
# of band (openssl, NOT a transit key; the broker holds this key itself and signs
# its SVID in process), registers its PUBLIC half with a `jwt` auth mount, and binds
# a role to the SVID's audience + subject -> the broad test policy. The private PEM +
# the broker SPIFFE id are emitted as fixtures; the e2e seals them into a
# `BackendCred::SpiffeSigner` bundle (the bundle CLI has no SpiffeSigner flag, so the
# Rust test seals via the library `seal` API). bao and vault take identical jwt-auth
# commands here (same jwt auth method API; dk5.3/dk5.10 proved cross-engine parity).
if [ "$SPIFFE_BOOT" -eq 1 ]; then
  require openssl
  echo "-- step 3c: provisioning SpiffeSigner boot path (jwt auth mount '$JWT_AUTH_MOUNT', role '$JWT_ROLE')"
  echo "   broker SVID issuer key: $SPIFFE_SIGNER_KEY (rsa-2048; RS256 SVID signer)"
  # PKCS#8 private (the SvidMinter::from_pem path accepts PKCS#8 or PKCS#1).
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$SPIFFE_SIGNER_KEY" 2>/dev/null
  # SPKI public PEM = what the jwt auth method validates the SVID signature against.
  openssl rsa -in "$SPIFFE_SIGNER_KEY" -pubout -out "$SPIFFE_SIGNER_PUB" 2>/dev/null
  chmod 600 "$SPIFFE_SIGNER_KEY"
  printf '%s\n' "$SPIFFE_BROKER_ID" >"$SPIFFE_BROKER_ID_FILE"

  "$CLI" auth enable -path="$JWT_AUTH_MOUNT" jwt >/dev/null 2>&1 \
    || echo "   (jwt auth '$JWT_AUTH_MOUNT/' already enabled)"
  # Static-key validation: jwt_validation_pubkeys carries the issuer's PUBLIC PEM, so
  # the broker's self-minted SVID needs no JWKS URL and no bound issuer (`iss`). The
  # SvidMinter stamps no `iss`; leaving bound_issuer unset accepts that.
  "$CLI" write "auth/$JWT_AUTH_MOUNT/config" \
      jwt_validation_pubkeys=@"$SPIFFE_SIGNER_PUB" >/dev/null
  # Role: user_claim=sub binds the token identity to the SPIFFE id; bound_subject +
  # bound_audiences pin exactly this broker's SVID; token_policies grants the same
  # broad test policy the AppRole path uses. role_type=jwt (NOT oidc): we present a
  # pre-minted token, not an OIDC redirect flow.
  "$CLI" write "auth/$JWT_AUTH_MOUNT/role/$JWT_ROLE" \
      role_type=jwt \
      user_claim=sub \
      bound_subject="$SPIFFE_BROKER_ID" \
      bound_audiences="$JWT_AUDIENCE" \
      "token_policies=$APPROLE_POLICY" \
      token_ttl=20m \
      token_max_ttl=1h >/dev/null
  echo "   jwt role '$JWT_ROLE' -> policy '$APPROLE_POLICY' (sub=$SPIFFE_BROKER_ID, aud=$JWT_AUDIENCE)"
fi

# ---- step 4: write catalog.json + policy.json (export JSON shape) ------------

echo "-- step 4: writing fixtures (catalog.json, policy.json) to $FIXTURES"

# Catalog: camelCase fields; transit `path` = BARE key name; kv-v2 path is the
# mount-qualified secret/data/<p>. One pre-filled signer, one pre-filled value,
# one missing=generate signer left absent (reconcile must create it).
cat >"$CATALOG" <<JSON
{
  "schemaVersion": 1,
  "backends": {
    "bao": {
      "kind": "vault", "addr": "$ADDR",
      "engines": ["transit", "kv2", "pki"],
      "capabilities": ["byok-import", "prehash-sign", "pki-crl", "jwt-auth", "approle-auth"],
      "mintKeyTypes": ["ed25519", "ed25519-nkey", "rsa-2048", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521"]
    }
  },
  "keys": {
    "web.tls.signing_key": {
      "class": "asymmetric", "keyType": "ed25519", "backend": "bao",
      "engine": "transit", "path": "$PREFILLED_TRANSIT_KEY",
      "writable": true, "missing": "error",
      "description": "pre-filled transit signing key (created out-of-band)"
    },
    "app.db_password": {
      "class": "value", "backend": "bao", "engine": "kv2",
      "path": "$PREFILLED_KV_PATH",
      "writable": true, "missing": "error",
      "description": "pre-filled kv-v2 value (created out-of-band)"
    },
    "nats.account": {
      "class": "asymmetric", "keyType": "ed25519", "backend": "bao",
      "engine": "transit", "path": "$GENERATE_TRANSIT_KEY",
      "writable": true, "missing": "generate",
      "description": "absent at boot; startup reconcile must generate it (vault-zrg)"
    },
    "app.aead": {
      "class": "symmetric", "keyType": "aes-256-gcm", "backend": "bao",
      "engine": "transit", "path": "$AEAD_TRANSIT_KEY",
      "writable": true, "missing": "generate",
      "description": "absent at boot; reconcile generates an AEAD key (encrypt/decrypt coverage)"
    },
    "kv2.signing_key": {
      "class": "asymmetric", "keyType": "ed25519", "backend": "bao",
      "engine": "kv2", "path": "$KV2_SIGNER_KV_PATH",
      "publicPath": "$KV2_SIGNER_PUBLIC_KV_PATH",
      "writable": false, "missing": "error",
      "description": "value-store Ed25519 materialize-to-sign signing key (vault-iiz, basil-cy8). Its 32-byte seed is PRE-FILLED out-of-band into 'path'; the broker materializes it into Zeroizing, signs in process, and zeroizes on the SIGN op only: the seed never leaves the vault except into the broker's own memory for one sign. Its PUBLIC half is PRE-FILLED out-of-band into 'publicPath' (basil-o86), so verify/get_public_key read the public there and NEVER materialize the seed. engine=kv2 routes sign through the KV materialize path (NOT transit); the asymmetric op surface makes get/set structurally denied. missing=error: BOTH the seed and the public are present at boot (the reconcile probe checks both), so a missing half FATALs reconcile rather than minting authority silently."
    },
    "byok.imported": {
      "class": "asymmetric", "keyType": "ed25519", "backend": "bao",
      "engine": "transit", "path": "$BYOK_IMPORT_KEY",
      "writable": true, "missing": "warn",
      "description": "BYOK import target (basil-dk5.7); absent at boot, imported in place by the e2e. missing=warn so reconcile neither fatals (error) nor pre-creates it (generate). The running uid holds the operator role here, which includes import."
    },
    "byok.rsa": {
      "class": "asymmetric", "keyType": "rsa-2048", "backend": "bao",
      "engine": "transit", "path": "$BYOK_RSA_KEY",
      "writable": true, "missing": "warn",
      "description": "BYOK RSA import target (basil-wpp.3); absent at boot and imported from caller PKCS#8 DER in the e2e."
    },
    "byok.ecdsa": {
      "class": "asymmetric", "keyType": "ecdsa-p256", "backend": "bao",
      "engine": "transit", "path": "$BYOK_ECDSA_KEY",
      "writable": true, "missing": "warn",
      "description": "BYOK ECDSA P-256 import target (basil-wpp.3); absent at boot and imported from caller PKCS#8 DER in the e2e."
    },
    "ecdsa.p384": {
      "class": "asymmetric", "keyType": "ecdsa-p384", "backend": "bao",
      "engine": "transit", "path": "$ECDSA_P384_KEY",
      "writable": true, "missing": "generate",
      "description": "ECDSA P-384 live-crypto e2e target (basil-0jkw). Absent at boot; startup reconcile LIVE-generates the transit key at this path (create_named_key type=ecdsa-p384). The ecdsa live e2e then does a real ES384 transit sign/verify round-trip and mints an ES384 JWT via the generic MintJwt path (jws_alg_for_public_key -> ES384), and separately exercises the request-time NewKey RPC for the curve. writable=true permits the reconcile generate."
    },
    "ecdsa.p521": {
      "class": "asymmetric", "keyType": "ecdsa-p521", "backend": "bao",
      "engine": "transit", "path": "$ECDSA_P521_KEY",
      "writable": true, "missing": "generate",
      "description": "ECDSA P-521 live-crypto e2e target (basil-0jkw). Absent at boot; startup reconcile LIVE-generates the transit key at this path (create_named_key type=ecdsa-p521). Exercised with a real ES512 transit sign/verify round-trip plus the request-time NewKey RPC. P-521 is not a SPIFFE JWT-SVID profile alg (ES512 excluded from the verifier stack), so it is sign/verify only, and MintJwt fails closed on it."
    },
    "byok.denied": {
      "class": "asymmetric", "keyType": "ed25519", "backend": "bao",
      "engine": "transit", "path": "$BYOK_DENIED_KEY",
      "writable": true, "missing": "warn",
      "description": "BYOK import target the running uid is NOT granted import on (basil-dk5.7). Pairs with byok.imported to prove import-set's all-or-nothing authorization: a manifest mixing an authorized + this unauthorized entry rejects the whole batch, importing NEITHER key."
    },
    "web.tls.cert_issuer": {
      "class": "asymmetric", "keyType": "ed25519", "backend": "bao",
      "engine": "pki", "path": "$PKI_MOUNT/issue/$PKI_ROLE",
      "writable": false, "missing": "warn",
      "description": "pki issue role for DNS/IP-SAN X.509 leaf issuance (basil-dk5.3). The CA key stays in the engine; the broker mints leaves in place. missing=warn: the existence probe reads transit metadata (404 -> absent) for this pki issue path, so a warn keeps the key routable without a fatal reconcile."
    },
    "spiffe.x509_issuer": {
      "class": "asymmetric", "keyType": "ed25519", "backend": "bao",
      "engine": "pki", "path": "$PKI_MOUNT/issue/$PKI_SPIFFE_ROLE",
      "writable": false, "missing": "warn",
      "labels": ["svid_kind=x509", "trust_domain=$SPIFFE_TRUST_DOMAIN"],
      "description": "SPIFFE X509-SVID issuer (basil-dk5.11). The standard rust-spiffe client fetches X.509-SVIDs over the Workload API; selection is by labels svid_kind=x509 + trust_domain. Routes to pki/issue/<role>, which sends uri_sans=spiffe://<td>/<path>. missing=warn (same as web.tls.cert_issuer): the existence probe reads transit metadata (404) for a pki issue path, so warn keeps it routable without a fatal reconcile."
    },
    "spiffe.jwt_issuer": {
      "class": "asymmetric", "keyType": "rsa-2048", "backend": "bao",
      "engine": "transit", "path": "$SPIFFE_JWT_TRANSIT_KEY",
      "writable": true, "missing": "generate",
      "labels": ["svid_kind=jwt", "trust_domain=$SPIFFE_TRUST_DOMAIN", "spiffe_id=spiffe://$SPIFFE_TRUST_DOMAIN/basil"],
      "description": "SPIFFE JWT-SVID issuer (basil-dk5.11). Selected by labels svid_kind=jwt + trust_domain; signs RS256 JWT-SVIDs in place via transit and publishes its public half as a JWKS for FetchJWTBundles/ValidateJWTSVID. RS256 (not EdDSA) because the SPIFFE JWT-SVID profile mandates RS256/ES256. Startup reconcile generates this rsa-2048 transit key from the backend's static mintKeyTypes declaration."
    },
    "spiffe.jwt_revocations": {
      "class": "value", "backend": "bao", "engine": "kv2",
      "path": "secret/data/spiffe/jwt-revocations",
      "writable": true, "missing": "warn",
      "labels": ["revocation_store=jwt-svid"],
      "description": "JWT-SVID revocation deny-list store (basil-4gcn). Labeled revocation_store=jwt-svid so the broker loads/persists the deny-list here at boot (core/revocation.rs JwtRevocationStore). Value key on kv2; absent at boot (missing=warn) so the store starts empty, and the live revocation e2e populates it via the admin Revoke RPC. writable=true permits the persist kv_put. Additive: unused by every other live test."
    },
    "pqc.sign": {
      "class": "asymmetric", "keyType": "ml-dsa-65", "backend": "bao",
      "engine": "transit", "path": "secret/data/pqc/ml-dsa-65",
      "writable": true, "missing": "warn",
      "labels": ["crypto_provider=local-software", "crypto_provider_policy=local-software", "pqc_custody=software-encrypted", "pqc_storage_key=pqc-aead", "crypto_provider_version=1"],
      "description": "ML-DSA-65 software-custodied signer (basil-wuj.11, basil-yfg7). Provisioned at e2e runtime via the NewKey RPC: the broker generates the seed, AEAD-seals it under transit 'pqc-aead', and writes the custody record at 'path'. sign materializes + signs in place; verify/get_public_key read the published verifying key from the same record. writable=true permits the NewKey provisioning write; missing=warn keeps boot reconcile non-fatal until NewKey runs."
    },
    "pqc.denied": {
      "class": "asymmetric", "keyType": "ml-dsa-65", "backend": "bao",
      "engine": "transit", "path": "secret/data/pqc/ml-dsa-65-denied",
      "writable": false, "missing": "warn",
      "labels": ["crypto_provider=local-software", "crypto_provider_policy=local-software", "pqc_custody=software-encrypted", "pqc_storage_key=pqc-aead", "crypto_provider_version=1"],
      "description": "ML-DSA-65 software-custodied key the running uid may op:sign but is NOT granted op:use_software_custody (basil-wuj.11): proves local-software custody is denied without the dedicated grant."
    },
    "pqc.backend": {
      "class": "asymmetric", "keyType": "ml-dsa-65", "backend": "bao",
      "engine": "transit", "path": "pqc-backend-mldsa",
      "writable": true, "missing": "warn",
      "description": "Backend-required ML-DSA-65 with NO software-custody labels (basil-wuj.11). No dev transit engine has native ML-DSA, so any sign returns the canonical unsupported error end-to-end. missing=warn: ML-DSA is never startup-generated."
    },
    "pqc.seal": {
      "class": "sealing", "keyType": "ml-kem-768", "backend": "bao",
      "engine": "kv2", "path": "secret/data/pqc/ml-kem-768",
      "publicPath": "secret/data/pqc/ml-kem-768-public",
      "writable": true, "missing": "warn",
      "labels": ["crypto_provider=local-software", "crypto_provider_policy=local-software", "pqc_custody=software-encrypted", "pqc_storage_key=pqc-aead", "pqc_algorithm=ml-kem-768", "crypto_provider_version=1"],
      "description": "ML-KEM-768 software-custodied sealing key (basil-wuj.11, basil-yfg7, basil-jcnr). Provisioned at e2e runtime via NewKey: the broker generates the 64-byte seed, AEAD-seals it under transit 'pqc-aead' in a custody record at 'path', and records the public encapsulation key in that record (returned by GetPublicKey, basil-4ybx). WrapEnvelope/UnwrapEnvelope derive from the seed in place; the client streaming CEK-wrap (basil-jcnr) fetches the encapsulation key via GetPublicKey and the broker recovers the CEK via UnwrapEnvelope. writable=true permits the NewKey write; missing=warn keeps boot reconcile non-fatal until NewKey runs."
    }
  }
}
JSON

# Policy: roles = snake_case op lists; rules use prefix-form principal
# user:<uid>/action role:|op:/target dotted-key; config.names + memberships carry
# the export-resolved numeric principal. We grant the RUNNING uid signer+reader
# over the test keys so basil (same uid) is authorized. operator is granted too
# so a future write/rotate is possible. The RUNNING uid is ALSO granted the
# dedicated `reload` admin op over the reserved target broker.reload (basil-mil0.5)
# (a broker-wide op NO data-plane grant implies), so the live admin reload RPC /
# `basil reload [--check]` e2e drives an authorized reload. Purely additive: it
# grants only the reload op and changes no other test's behavior.
cat >"$POLICY" <<JSON
{
  "schemaVersion": 2,
  "roles": {
    "signer":   ["sign", "verify", "get_public_key"],
    "reader":   ["get", "list", "get_public_key"],
    "operator": ["set", "rotate", "import", "new_key"],
    "crypter":  ["encrypt", "decrypt"],
    "minter":   ["mint"],
    "validator": ["validate"]
  },
  "subjects": {
    "test-runner": { "allOf": [ { "kind": "unix", "uid": $UID_NUM } ] }
  },
  "rules": [
    {
      "id": "test-signer",
      "subjects": ["test-runner"],
      "action": ["role:signer"],
      "target": ["web.tls.signing_key", "nats.account"]
    },
    {
      "id": "test-kv2-signer",
      "subjects": ["test-runner"],
      "action": ["role:signer"],
      "target": ["kv2.signing_key"]
    },
    {
      "id": "test-reader",
      "subjects": ["test-runner"],
      "action": ["role:reader"],
      "target": ["app.db_password"]
    },
    {
      "id": "test-crypter",
      "subjects": ["test-runner"],
      "action": ["role:crypter"],
      "target": ["app.aead"]
    },
    {
      "id": "test-minter",
      "subjects": ["test-runner"],
      "action": ["role:minter"],
      "target": ["web.tls.cert_issuer", "spiffe.x509_issuer", "spiffe.jwt_issuer"]
    },
    {
      "id": "test-spiffe-validator",
      "subjects": ["test-runner"],
      "action": ["role:validator"],
      "target": ["spiffe.jwt_issuer"]
    },
    {
      "id": "test-operator",
      "subjects": ["test-runner"],
      "action": ["role:operator"],
      "target": ["web.tls.signing_key", "nats.account", "app.db_password", "app.aead"]
    },
    {
      "id": "test-byok-importer",
      "subjects": ["test-runner"],
      "action": ["role:operator", "role:signer"],
      "target": ["byok.imported", "byok.rsa", "byok.ecdsa"]
    },
    {
      "id": "test-ecdsa-highcurve",
      "subjects": ["test-runner"],
      "action": ["role:signer", "role:minter", "op:new_key"],
      "target": ["ecdsa.p384", "ecdsa.p521"]
    },
    {
      "id": "test-reload",
      "subjects": ["test-runner"],
      "action": ["op:reload"],
      "target": ["broker.reload"]
    },
    {
      "id": "test-revoke",
      "subjects": ["test-runner"],
      "action": ["op:revoke"],
      "target": ["broker.revoke"]
    },
    {
      "id": "test-pqc-sign",
      "subjects": ["test-runner"],
      "action": ["op:new_key", "op:sign", "op:verify", "op:get_public_key", "op:use_software_custody"],
      "target": ["pqc.sign"]
    },
    {
      "id": "test-pqc-seal",
      "subjects": ["test-runner"],
      "action": ["op:new_key", "op:get_public_key", "op:encrypt", "op:decrypt", "op:use_software_custody"],
      "target": ["pqc.seal"]
    },
    {
      "id": "test-pqc-denied",
      "subjects": ["test-runner"],
      "action": ["op:sign", "op:verify"],
      "target": ["pqc.denied"]
    },
    {
      "id": "test-pqc-backend",
      "subjects": ["test-runner"],
      "action": ["op:sign", "op:verify"],
      "target": ["pqc.backend"]
    }
  ],
  "config": {
    "names": { "users": { "$UID_NUM": "test-runner" }, "groups": {} },
    "memberships": { "$UID_NUM": [$UID_NUM] }
  }
}
JSON

# ---- step 5: build the sealed bundle (passphrase slot) ----------------------

# Always emit the passphrase fixture (both boot paths unlock the passphrase slot).
umask 077
printf 'test-disk-passphrase-not-a-secret\n' >"$PASS_FILE"

if [ "$SPIFFE_BOOT" -eq 1 ]; then
  # SpiffeSigner boot path: the bundle CLI has no SpiffeSigner flag, so the e2e
  # seals a `BackendCred::SpiffeSigner` (the emitted RSA PEM + spiffe_id) into the
  # bundle via the library `seal` API. We DON'T build an AppRole bundle here.
  echo "-- step 5: skipped AppRole bundle build (--spiffe-boot; the e2e seals the SpiffeSigner bundle)"
else
  echo "-- step 5: building the 0600 sealed bundle (passphrase slot + AppRole cred)"
  # The passphrase slot is the unattended test unlock method; age-yubikey/bip39
  # need interaction. The bundle holds the bao AppRole under backend id 'bao'
  # (must match the catalog backend name). This is the SECOND unlock layer (the
  # broker's own bundle) and exercises the live auth/approle/login exchange when
  # the broker boots.
  printf '%s\n' "$APPROLE_SECRET_ID" >"$APPROLE_SECRET_FILE"
  # Expose the AppRole role_id alongside the secret_id so a live e2e can re-seal
  # the SAME backend cred into a differently-slotted bundle (basil-bp30: the BIP39
  # break-glass unlock e2e re-seals this AppRole under a BIP39 slot). Additive: the
  # standard passphrase boot path ignores this file.
  printf '%s\n' "$APPROLE_ROLE_ID" >"$FIXTURES/approle-role-id.txt"
  "$AGENT_BIN" bundle create "$BUNDLE" \
      --slot "passphrase:file=$PASS_FILE" \
      --backend "id=bao,type=openbao,addr=$ADDR,role-id=$APPROLE_ROLE_ID,secret-id-file=$APPROLE_SECRET_FILE" >/dev/null
  chmod 600 "$BUNDLE"
  chmod 600 "$APPROLE_SECRET_FILE"
  chmod 600 "$FIXTURES/approle-role-id.txt"
fi

cat > "$AGENT_CONFIG" <<EOF
catalog = "$CATALOG"
policy = "$POLICY"
bundle = "$BUNDLE"
vault-addr = "$ADDR"
capability-policy = "strict"
EOF
if [ "$SPIFFE_BOOT" -eq 1 ]; then
  cat >> "$AGENT_CONFIG" <<EOF
jwt-auth-mount = "$JWT_AUTH_MOUNT"
jwt-role = "$JWT_ROLE"
jwt-audience = "$JWT_AUDIENCE"
svid-ttl-secs = 300
EOF
fi
cat >> "$AGENT_CONFIG" <<EOF

[unlock]
unlock-passphrase-file = "$PASS_FILE"
EOF

echo
echo "== DONE: pre-filled store + matching sealed bundle ready =="
echo
echo "Fixtures:"
echo "  catalog:  $CATALOG"
echo "  policy:   $POLICY"
echo "  bundle:   $BUNDLE   (0600; passphrase slot; cred 'bao' -> AppRole)"
echo "  config:   $AGENT_CONFIG"
echo "  passfile: $PASS_FILE"
echo "  approle secret_id file: $APPROLE_SECRET_FILE"
echo
echo "Pre-filled in $ENGINE ($ADDR):"
echo "  transit/keys/$PREFILLED_TRANSIT_KEY   (catalog key: web.tls.signing_key)"
echo "  $PREFILLED_KV_PATH   (catalog key: app.db_password)"
echo "  $PKI_MOUNT/issue/$PKI_ROLE   (catalog key: web.tls.cert_issuer; internal root '$PKI_ROOT_CN')"
echo "  $PKI_MOUNT/issue/$PKI_SPIFFE_ROLE   (catalog key: spiffe.x509_issuer; SPIFFE URI-SAN role, trust domain $SPIFFE_TRUST_DOMAIN)"
echo "  $KV2_SIGNER_KV_PATH   (catalog key: kv2.signing_key; engine=kv2 Ed25519 materialize-to-sign seed)"
echo "  $KV2_SIGNER_PUBLIC_KV_PATH   (catalog key: kv2.signing_key publicPath; out-of-band Ed25519 public, basil-o86)"
echo "Left ABSENT (reconcile=generate -> created at broker boot):"
echo "  transit/keys/$GENERATE_TRANSIT_KEY   (catalog key: nats.account)"
echo "  transit/keys/$SPIFFE_JWT_TRANSIT_KEY   (catalog key: spiffe.jwt_issuer; rsa-2048 RS256 JWT-SVID signer)"
echo "Left ABSENT (missing=warn -> BYOK import targets, imported in place by the e2e):"
echo "  transit/keys/$BYOK_IMPORT_KEY   (catalog key: byok.imported; uid granted import)"
echo "  transit/keys/$BYOK_RSA_KEY      (catalog key: byok.rsa; uid granted import)"
echo "  transit/keys/$BYOK_ECDSA_KEY    (catalog key: byok.ecdsa; uid granted import)"
echo "  transit/keys/$BYOK_DENIED_KEY   (catalog key: byok.denied; uid NOT granted import)"
echo "Left ABSENT (missing=generate -> ECDSA P-384/P-521 live-crypto targets, reconcile-generated at boot):"
echo "  transit/keys/$ECDSA_P384_KEY    (catalog key: ecdsa.p384; ES384 sign/verify + ES384 JWT)"
echo "  transit/keys/$ECDSA_P521_KEY    (catalog key: ecdsa.p521; ES512 sign/verify only)"
echo "Live AppRole credential sealed for broker startup:"
echo "  auth/approle/role/$APPROLE_NAME (role_id + secret_id)"
if [ "$SPIFFE_BOOT" -eq 1 ]; then
  echo "SpiffeSigner boot path (--spiffe-boot):"
  echo "  jwt auth mount:   auth/$JWT_AUTH_MOUNT  (jwt_validation_pubkeys = $SPIFFE_SIGNER_PUB)"
  echo "  jwt role:         $JWT_ROLE -> policy $APPROLE_POLICY (sub=$SPIFFE_BROKER_ID, aud=$JWT_AUDIENCE)"
  echo "  signer key (priv): $SPIFFE_SIGNER_KEY  (seal as BackendCred::SpiffeSigner under backend 'bao')"
  echo "  broker spiffe id:  $SPIFFE_BROKER_ID_FILE ($SPIFFE_BROKER_ID)"
  echo "  Boot config includes jwt-auth-mount=$JWT_AUTH_MOUNT, jwt-role=$JWT_ROLE, jwt-audience=$JWT_AUDIENCE"
fi
echo
echo "Run the broker against the pre-filled store + bundle (step 6):"
echo "  $AGENT_BIN agent \\"
echo "      --config $AGENT_CONFIG \\"
echo "      --vault-addr $ADDR \\"
echo "      --socket  $SOCKET"
echo
echo "Drive it with basil (same uid -> authorized):"
echo "  $REPO_ROOT/target/debug/basil --socket $SOCKET status"
echo "  $REPO_ROOT/target/debug/basil --socket $SOCKET sign --key-id web.tls.signing_key 'hello'"
echo
if [ "$START_SERVER" -eq 1 ]; then
  echo "Stop the dev server when done (SIGINT; dev servers ignore a plain SIGTERM):"
  echo "  kill -INT \$(cat $SERVER_PIDFILE)   # or: pkill -INT -f '$CLI server -dev'"
fi
