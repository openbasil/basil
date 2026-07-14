#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
REPO_ROOT="$(cd "$(dirname "$SCRIPT_PATH")/.." && pwd)"
LOCK_FILE="${BASIL_COMPOSE_ARTIFACT_LOCK:-$REPO_ROOT/scripts/compose-phase1-artifacts.lock.tsv}"
KEY_ROOT="${BASIL_COMPOSE_ARTIFACT_KEY_ROOT:-$REPO_ROOT/interop-tests/compose-phase1/keys}"
CACHE_ROOT="${BASIL_COMPOSE_ARTIFACT_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/basil/compose-phase1}"
DOWNLOAD_TIMEOUT_SECONDS="${BASIL_COMPOSE_ARTIFACT_DOWNLOAD_TIMEOUT:-1900}"

readonly EXPECTED_HEADER=$'schema_version\tid\tstatus\tkind\tplatform\tfilename\tsize_bytes\tsha256\tsource_url\tchecksum_url\tchecksum_size_bytes\tchecksum_sha256\tsignature_url\tsignature_size_bytes\tsignature_sha256\tkey_file\tsigner_fingerprint\tnote'

usage() {
  cat <<'EOF'
Usage:
  scripts/compose-phase1-artifacts.sh list [--json]
  scripts/compose-phase1-artifacts.sh explain [ID]
  scripts/compose-phase1-artifacts.sh fetch ID
  scripts/compose-phase1-artifacts.sh fetch-all
  scripts/compose-phase1-artifacts.sh verify ID [ID ...]
  scripts/compose-phase1-artifacts.sh verify-all
  scripts/compose-phase1-artifacts.sh offline
  scripts/compose-phase1-artifacts.sh missing
  scripts/compose-phase1-artifacts.sh recovery
  scripts/compose-phase1-artifacts.sh self-test

Environment:
  BASIL_COMPOSE_ARTIFACT_CACHE  Cache root. Default:
                                ${XDG_CACHE_HOME:-$HOME/.cache}/basil/compose-phase1

Exit status:
  0  requested operation succeeded
  2  usage error or invalid inventory
  3  required artifact is missing or inventory contains unpopulated entries
  4  cached artifact or upstream signature verification failed
  5  download failed
EOF
}

fail_inventory() {
  printf 'inventory error: %s\n' "$*" >&2
  exit 2
}

need_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'error: required command not found: %s\n' "$1" >&2
    return 1
  fi
}

is_safe_id() {
  [[ "$1" =~ ^[a-z0-9][a-z0-9._-]{0,126}[a-z0-9]$ ]]
}

is_safe_platform() {
  [[ "$1" =~ ^[a-z0-9][a-z0-9._/-]{1,126}[a-z0-9]$ ]]
}

is_safe_filename() {
  [[ "$1" != "." && "$1" != ".." && "$1" != */* && "$1" != *$'\n'* && "$1" != *$'\r'* ]]
}

is_release_specific_url() {
  local url=$1
  [[ "$url" == https://* ]] || return 1
  [[ "$url" != *'/current/'* && "$url" != *'/latest/'* && "$url" != *'LATEST'* && "$url" != *'latest'* ]]
}

is_approved_file_url() {
  case "$1" in
    https://download.fedoraproject.org/* | https://cloud-images.ubuntu.com/*) return 0 ;;
    *) return 1 ;;
  esac
}

is_approved_unpopulated_source() {
  case "$1" in
    https://download.docker.com/* | https://download.fedoraproject.org/* | registry.fedoraproject.org/* | docker.io/library/* | gcr.io/distroless/*) return 0 ;;
    *) return 1 ;;
  esac
}

# Approved download hosts for package-set members and their signed-index anchors.
# Trust flows from the pinned hashes, never the hostname; the host allow-list only
# bounds where bytes may be pulled from.
is_approved_pkg_url() {
  case "$1" in
    https://download.docker.com/* | https://download.fedoraproject.org/*) return 0 ;;
    *) return 1 ;;
  esac
}

# A cache-relative location for a `staged` package-set member: never absolute,
# never traverses upward, no empty or doubled separators, no control characters.
is_safe_cache_relpath() {
  local p=$1
  [[ -n "$p" && "$p" != /* && "$p" != *//* && "$p" != *$'\n'* && "$p" != *$'\r'* ]] || return 1
  [[ "$p" == ".." || "$p" == ../* || "$p" == */.. || "$p" == */../* ]] && return 1
  return 0
}

# Canonical registry/repository allow-list for populated OCI workload rows. Each
# project's own registry is pinned; the tag is only how a digest was resolved,
# never a trust anchor (see is_safe_oci_digest / verify_oci_layout).
is_approved_oci_repo() {
  case "$1" in
    registry.fedoraproject.org/fedora \
      | docker.io/library/alpine | docker.io/library/debian \
      | docker.io/library/ubuntu | docker.io/library/postgres \
      | gcr.io/distroless/static-debian12) return 0 ;;
    *) return 1 ;;
  esac
}

# A populated OCI source is a tag-qualified reference registry/repo:tag. The
# digest is carried in the sha256 column, so a bare or digest-bearing source is
# rejected here to keep the tag and the pinned digest in separate columns.
is_approved_oci_ready_ref() {
  local ref=$1 repo tag
  [[ "$ref" != *@* ]] || return 1
  [[ "$ref" == *:* ]] || return 1
  repo=${ref%:*}
  tag=${ref##*:}
  [[ "$tag" =~ ^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$ ]] || return 1
  is_approved_oci_repo "$repo"
}

is_safe_oci_digest() {
  [[ "$1" =~ ^[0-9a-f]{64}$ ]]
}

declare -a IDS=()
declare -A STATUS=()
declare -A KIND=()
declare -A PLATFORM=()
declare -A FILENAME=()
declare -A SIZE_BYTES=()
declare -A SHA256=()
declare -A SOURCE_URL=()
declare -A CHECKSUM_URL=()
declare -A CHECKSUM_SIZE_BYTES=()
declare -A CHECKSUM_SHA256=()
declare -A SIGNATURE_URL=()
declare -A SIGNATURE_SIZE_BYTES=()
declare -A SIGNATURE_SHA256=()
declare -A KEY_FILE=()
declare -A SIGNER_FINGERPRINT=()
declare -A NOTE=()

# Transient parse buffers for the current package-set member manifest, populated
# by read_pkgset_entries and consumed by the package-set verify/fetch/report paths.
declare -a PKG_RELPATH=()
declare -a PKG_METHOD=()
declare -a PKG_SIZE=()
declare -a PKG_SHA=()
declare -a PKG_SOURCE=()
declare -a PKG_RECOVERY=()

validate_ready_row() {
  local line_no=$1 id=$2 kind=$3

  case "$kind" in
    file-openpgp-clearsigned | file-openpgp-detached) validate_ready_file_row "$@" ;;
    oci-image) validate_ready_oci_row "$@" ;;
    package-set) validate_ready_pkgset_row "$@" ;;
    *) fail_inventory "line $line_no: ready entry '$id' has unsupported kind '$kind'" ;;
  esac
}

# A populated package-set row pins its per-set member manifest (the sidecar
# compose-phase1-artifacts.<id>.packages.tsv) by sha256 in the sha256 column,
# which is the anchor over the member list; each member is in turn pinned by its
# own sha256 in that manifest. filename is the cache subdirectory name; size and
# every detached-signature column are '-'. source_url is the approved download
# scope for `url` members; checksum_url / checksum_sha256 record the signed
# repository index the member hashes were derived from; key_file /
# signer_fingerprint name the signing key (key_file may be '-' when that key is
# not checked in, as for the Docker CE key).
validate_ready_pkgset_row() {
  local line_no=$1 id=$2 kind=$3 platform=$4 filename=$5 size_bytes=$6 sha256=$7
  local source_url=$8 checksum_url=$9 checksum_size=${10} checksum_sha=${11}
  local signature_url=${12} signature_size=${13} signature_sha=${14} key_file=${15} fingerprint=${16}

  is_safe_platform "$platform" || fail_inventory "line $line_no: invalid platform for '$id'"
  is_safe_filename "$filename" || fail_inventory "line $line_no: invalid cache directory name for '$id'"
  [[ "$size_bytes" == "-" ]] \
    || fail_inventory "line $line_no: package-set entry '$id' must use '-' for size (each member is pinned in its manifest)"
  [[ "$sha256" =~ ^[0-9a-f]{64}$ ]] \
    || fail_inventory "line $line_no: invalid member-manifest sha256 for '$id'"

  local url
  for url in "$source_url" "$checksum_url"; do
    is_release_specific_url "$url" || fail_inventory "line $line_no: non-release-specific URL for '$id': $url"
    is_approved_pkg_url "$url" || fail_inventory "line $line_no: unapproved URL for '$id': $url"
  done
  [[ "$checksum_size" == "-" ]] \
    || fail_inventory "line $line_no: package-set entry '$id' must use '-' for checksum size"
  [[ "$checksum_sha" =~ ^[0-9a-f]{64}$ ]] \
    || fail_inventory "line $line_no: invalid signed-index sha256 for '$id'"
  [[ "$signature_url" == "-" && "$signature_size" == "-" && "$signature_sha" == "-" ]] \
    || fail_inventory "line $line_no: package-set entry '$id' must use '-' for detached-signature fields"
  { [[ "$key_file" == "-" ]] \
    || [[ "$key_file" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*\.gpg$ && "$key_file" != /* && "$key_file" != *'../'* ]]; } \
    || fail_inventory "line $line_no: invalid key_file for '$id'"
  { [[ "$fingerprint" =~ ^[0-9A-F]{40}$ ]] || [[ "$fingerprint" =~ ^[0-9A-F]{64}$ ]]; } \
    || fail_inventory "line $line_no: invalid signer fingerprint for '$id'"
}

# A populated OCI row pins a multi-arch manifest-list (image index) digest in the
# sha256 column as the sole trust anchor. The source column holds the
# tag-qualified reference used to resolve that digest, the filename column holds
# the on-disk OCI-layout directory name, and every file-signature column is '-'
# because the content-addressed digest — re-verified locally after acquisition —
# authenticates the layout without a detached OpenPGP signature.
validate_ready_oci_row() {
  local line_no=$1 id=$2 kind=$3 platform=$4 filename=$5 size_bytes=$6 sha256=$7
  local source_url=$8 checksum_url=$9 checksum_size=${10} checksum_sha=${11}
  local signature_url=${12} signature_size=${13} signature_sha=${14} key_file=${15} fingerprint=${16}

  is_safe_platform "$platform" || fail_inventory "line $line_no: invalid platform for '$id'"
  is_safe_filename "$filename" || fail_inventory "line $line_no: invalid OCI layout name for '$id'"
  [[ "$size_bytes" == "-" ]] \
    || fail_inventory "line $line_no: OCI entry '$id' must use '-' for size (the digest is the anchor)"
  is_safe_oci_digest "$sha256" \
    || fail_inventory "line $line_no: invalid manifest-list digest for '$id'"
  is_approved_oci_ready_ref "$source_url" \
    || fail_inventory "line $line_no: unapproved or non-tag-qualified OCI reference for '$id': $source_url"
  [[ "$checksum_url" == "-" && "$checksum_size" == "-" && "$checksum_sha" == "-" \
      && "$signature_url" == "-" && "$signature_size" == "-" && "$signature_sha" == "-" \
      && "$key_file" == "-" && "$fingerprint" == "-" ]] \
    || fail_inventory "line $line_no: OCI entry '$id' must use '-' for checksum/signature/key columns"
}

validate_ready_file_row() {
  local line_no=$1 id=$2 kind=$3 platform=$4 filename=$5 size_bytes=$6 sha256=$7
  local source_url=$8 checksum_url=$9 checksum_size=${10} checksum_sha=${11}
  local signature_url=${12} signature_size=${13} signature_sha=${14} key_file=${15} fingerprint=${16}

  is_safe_platform "$platform" || fail_inventory "line $line_no: invalid platform for '$id'"
  is_safe_filename "$filename" || fail_inventory "line $line_no: invalid filename for '$id'"
  [[ "$size_bytes" =~ ^[1-9][0-9]*$ ]] || fail_inventory "line $line_no: invalid artifact size for '$id'"
  [[ "$sha256" =~ ^[0-9a-f]{64}$ ]] || fail_inventory "line $line_no: invalid SHA-256 for '$id'"
  [[ "$checksum_size" =~ ^[1-9][0-9]*$ ]] || fail_inventory "line $line_no: invalid checksum size for '$id'"
  [[ "$checksum_sha" =~ ^[0-9a-f]{64}$ ]] || fail_inventory "line $line_no: invalid checksum SHA-256 for '$id'"

  local url
  for url in "$source_url" "$checksum_url"; do
    is_release_specific_url "$url" || fail_inventory "line $line_no: non-release-specific URL for '$id': $url"
    is_approved_file_url "$url" || fail_inventory "line $line_no: unapproved URL for '$id': $url"
  done
  if [[ "$kind" == "file-openpgp-detached" ]]; then
    is_release_specific_url "$signature_url" || fail_inventory "line $line_no: invalid signature URL for '$id'"
    is_approved_file_url "$signature_url" || fail_inventory "line $line_no: unapproved signature URL for '$id'"
    [[ "$signature_size" =~ ^[1-9][0-9]*$ ]] || fail_inventory "line $line_no: invalid signature size for '$id'"
    [[ "$signature_sha" =~ ^[0-9a-f]{64}$ ]] || fail_inventory "line $line_no: invalid signature SHA-256 for '$id'"
  elif [[ "$signature_url" != "-" || "$signature_size" != "-" || "$signature_sha" != "-" ]]; then
    fail_inventory "line $line_no: clearsigned entry '$id' must use '-' for detached-signature fields"
  fi

  [[ "$key_file" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*\.gpg$ && "$key_file" != /* && "$key_file" != *'../'* ]] \
    || fail_inventory "line $line_no: invalid key_file for '$id'"
  [[ "$fingerprint" =~ ^[0-9A-F]{40}$ || "$fingerprint" =~ ^[0-9A-F]{64}$ ]] \
    || fail_inventory "line $line_no: invalid signer fingerprint for '$id'"
}

validate_unpopulated_row() {
  local line_no=$1 id=$2 kind=$3 platform=$4 filename=$5 size_bytes=$6 sha256=$7
  local source_url=$8 checksum_url=$9 checksum_size=${10} checksum_sha=${11}
  local signature_url=${12} signature_size=${13} signature_sha=${14} key_file=${15} fingerprint=${16}

  case "$kind" in
    package-set | oci-image) ;;
    *) fail_inventory "line $line_no: unpopulated entry '$id' has unsupported kind '$kind'" ;;
  esac
  is_safe_platform "$platform" || fail_inventory "line $line_no: invalid platform for '$id'"
  [[ "$filename" == "-" && "$size_bytes" == "-" && "$sha256" == "-" && "$checksum_url" == "-" \
      && "$checksum_size" == "-" && "$checksum_sha" == "-" && "$signature_url" == "-" \
      && "$signature_size" == "-" && "$signature_sha" == "-" && "$key_file" == "-" \
      && "$fingerprint" == "-" ]] \
    || fail_inventory "line $line_no: unpopulated entry '$id' must use '-' for unavailable verification fields"
  is_approved_unpopulated_source "$source_url" \
    || fail_inventory "line $line_no: unapproved unpopulated source for '$id': $source_url"
}

load_inventory() {
  [[ -f "$LOCK_FILE" ]] || fail_inventory "lock file not found: $LOCK_FILE"

  local line line_no=0 header_seen=false
  while IFS= read -r line || [[ -n "$line" ]]; do
    line_no=$((line_no + 1))
    line=${line%$'\r'}
    if [[ "$header_seen" == "false" ]]; then
      [[ -z "$line" || "$line" == \#* ]] && continue
      [[ "$line" == "$EXPECTED_HEADER" ]] || fail_inventory "line $line_no does not match schema header"
      header_seen=true
      continue
    fi
    [[ -z "$line" || "$line" == \#* ]] && continue

    local -a fields=()
    IFS=$'\t' read -r -a fields <<<"$line"
    [[ ${#fields[@]} -eq 18 ]] || fail_inventory "line $line_no has ${#fields[@]} fields; expected 18"

    local schema_version=${fields[0]} id=${fields[1]} status=${fields[2]} kind=${fields[3]}
    local platform=${fields[4]} filename=${fields[5]} size_bytes=${fields[6]} sha256=${fields[7]}
    local source_url=${fields[8]} checksum_url=${fields[9]} checksum_size=${fields[10]}
    local checksum_sha=${fields[11]} signature_url=${fields[12]} signature_size=${fields[13]}
    local signature_sha=${fields[14]} key_file=${fields[15]} fingerprint=${fields[16]} note=${fields[17]}

    [[ "$schema_version" == "1" ]] || fail_inventory "line $line_no: unsupported schema version '$schema_version'"
    is_safe_id "$id" || fail_inventory "line $line_no: invalid id '$id'"
    [[ -z "${STATUS[$id]+x}" ]] || fail_inventory "line $line_no: duplicate id '$id'"
    [[ -n "$note" && "$note" != "-" ]] || fail_inventory "line $line_no: entry '$id' requires an explanatory note"

    case "$status" in
      ready)
        validate_ready_row "$line_no" "$id" "$kind" "$platform" "$filename" "$size_bytes" "$sha256" \
          "$source_url" "$checksum_url" "$checksum_size" "$checksum_sha" "$signature_url" \
          "$signature_size" "$signature_sha" "$key_file" "$fingerprint"
        ;;
      not-yet-populated)
        validate_unpopulated_row "$line_no" "$id" "$kind" "$platform" "$filename" "$size_bytes" "$sha256" \
          "$source_url" "$checksum_url" "$checksum_size" "$checksum_sha" "$signature_url" \
          "$signature_size" "$signature_sha" "$key_file" "$fingerprint"
        ;;
      *) fail_inventory "line $line_no: invalid status '$status' for '$id'" ;;
    esac

    IDS+=("$id")
    STATUS[$id]=$status
    KIND[$id]=$kind
    PLATFORM[$id]=$platform
    FILENAME[$id]=$filename
    SIZE_BYTES[$id]=$size_bytes
    SHA256[$id]=$sha256
    SOURCE_URL[$id]=$source_url
    CHECKSUM_URL[$id]=$checksum_url
    CHECKSUM_SIZE_BYTES[$id]=$checksum_size
    CHECKSUM_SHA256[$id]=$checksum_sha
    SIGNATURE_URL[$id]=$signature_url
    SIGNATURE_SIZE_BYTES[$id]=$signature_size
    SIGNATURE_SHA256[$id]=$signature_sha
    KEY_FILE[$id]=$key_file
    SIGNER_FINGERPRINT[$id]=$fingerprint
    NOTE[$id]=$note
  done <"$LOCK_FILE"

  [[ "$header_seen" == "true" ]] || fail_inventory "empty lock file"
  [[ ${#IDS[@]} -gt 0 ]] || fail_inventory "inventory has no entries"
}

require_id() {
  local id=$1
  [[ -n "${STATUS[$id]+x}" ]] || {
    printf 'error: unknown artifact id: %s\n' "$id" >&2
    return 2
  }
}

artifact_dir() {
  printf '%s/%s' "$CACHE_ROOT" "$1"
}

artifact_path() {
  printf '%s/%s/%s' "$CACHE_ROOT" "$1" "${FILENAME[$1]}"
}

checksum_path() {
  printf '%s/%s/upstream.checksums' "$CACHE_ROOT" "$1"
}

signature_path() {
  printf '%s/%s/upstream.checksums.sig' "$CACHE_ROOT" "$1"
}

key_path() {
  printf '%s/%s' "$KEY_ROOT" "${KEY_FILE[$1]}"
}

check_file() {
  local path=$1 expected_size=$2 expected_sha=$3 actual_size actual_sha
  [[ -f "$path" ]] || return 3
  actual_size=$(stat -c '%s' -- "$path") || return 4
  if [[ "$actual_size" != "$expected_size" ]]; then
    printf 'verification error: size mismatch for %s\n  expected: %s\n  actual:   %s\n' \
      "$path" "$expected_size" "$actual_size" >&2
    return 4
  fi
  actual_sha=$(sha256sum -- "$path") || return 4
  actual_sha=${actual_sha%% *}
  if [[ "$actual_sha" != "$expected_sha" ]]; then
    printf 'verification error: SHA-256 mismatch for %s\n  expected: %s\n  actual:   %s\n' \
      "$path" "$expected_sha" "$actual_sha" >&2
    return 4
  fi
}

manifest_has_exact_hash() {
  local manifest=$1 filename=$2 expected=$3 line found=0 candidate_name candidate_hash remainder
  while IFS= read -r line || [[ -n "$line" ]]; do
    line=${line%$'\r'}
    candidate_name=
    candidate_hash=

    if [[ "$line" == "SHA256 ($filename) = "* ]]; then
      candidate_name=$filename
      candidate_hash=${line#"SHA256 ($filename) = "}
    elif [[ ${#line} -ge 66 && "${line:64:1}" =~ [[:space:]] ]]; then
      candidate_hash=${line:0:64}
      remainder=${line:64}
      remainder=${remainder#"${remainder%%[![:space:]]*}"}
      [[ "$remainder" == \** ]] && remainder=${remainder#\*}
      candidate_name=$remainder
    fi

    if [[ "$candidate_name" == "$filename" ]]; then
      found=$((found + 1))
      [[ "$candidate_hash" =~ ^[0-9A-Fa-f]{64}$ ]] || {
        printf 'verification error: malformed checksum for %s in %s\n' "$filename" "$manifest" >&2
        return 4
      }
      if [[ "${candidate_hash,,}" != "$expected" ]]; then
        printf 'verification error: signed checksum disagrees with lock for %s\n' "$filename" >&2
        return 4
      fi
    fi
  done <"$manifest"

  if [[ $found -ne 1 ]]; then
    printf 'verification error: expected one checksum for %s in %s, found %d\n' \
      "$filename" "$manifest" "$found" >&2
    return 4
  fi
}

verify_openpgp() {
  local id=$1 manifest=$2 signature=${3:-} key status_file diagnostics_file
  key=$(key_path "$id")
  [[ -f "$key" ]] || {
    printf 'verification error: checked-in key is missing for %s: %s\n' "$id" "$key" >&2
    return 4
  }

  status_file=$(mktemp)
  diagnostics_file=$(mktemp)
  local rc=0
  if [[ -n "$signature" ]]; then
    gpgv --status-fd 3 --keyring "$key" -- "$signature" "$manifest" 3>"$status_file" 2>"$diagnostics_file" || rc=$?
  else
    gpgv --status-fd 3 --keyring "$key" -- "$manifest" 3>"$status_file" 2>"$diagnostics_file" || rc=$?
  fi
  if [[ $rc -ne 0 ]]; then
    printf 'verification error: OpenPGP verification failed for %s\n' "$id" >&2
    while IFS= read -r line; do printf '  %s\n' "$line" >&2; done <"$diagnostics_file"
    rm -f -- "$status_file" "$diagnostics_file"
    return 4
  fi

  local marker record fingerprint rest valid=false
  while IFS=' ' read -r marker record fingerprint rest; do
    if [[ "$marker" == "[GNUPG:]" && "$record" == "VALIDSIG" \
        && "$fingerprint" == "${SIGNER_FINGERPRINT[$id]}" ]]; then
      valid=true
    fi
  done <"$status_file"
  rm -f -- "$status_file" "$diagnostics_file"

  if [[ "$valid" != "true" ]]; then
    printf 'verification error: signature for %s was not made by pinned fingerprint %s\n' \
      "$id" "${SIGNER_FINGERPRINT[$id]}" >&2
    return 4
  fi
}

# Offline integrity check for an OCI-layout directory. The pinned manifest-list
# (image index) digest is the trust anchor: it must be present as a
# content-addressed blob whose bytes hash back to the digest, it must be the
# entry referenced by index.json, and every blob in the layout must self-address
# (its filename equals the SHA-256 of its bytes). No network access and no trust
# in the tag or registry hostname is involved. Returns 3 for a missing layout,
# 4 for any integrity failure.
verify_oci_layout() {
  local id=$1 dir=$2 pinned=$3 blob got f name
  [[ -d "$dir" ]] || { printf 'missing: %s\n' "$dir" >&2; return 3; }
  [[ -f "$dir/oci-layout" ]] || { printf 'missing: %s\n' "$dir/oci-layout" >&2; return 3; }
  [[ -f "$dir/index.json" ]] || { printf 'missing: %s\n' "$dir/index.json" >&2; return 3; }
  [[ -d "$dir/blobs/sha256" ]] || { printf 'missing: %s\n' "$dir/blobs/sha256" >&2; return 3; }

  blob="$dir/blobs/sha256/$pinned"
  [[ -f "$blob" ]] || { printf 'missing: %s\n' "$blob" >&2; return 3; }

  if ! jq -e --arg d "sha256:$pinned" 'any((.manifests // [])[]; .digest == $d)' \
      "$dir/index.json" >/dev/null 2>&1; then
    printf 'verification error: %s index.json does not reference pinned digest sha256:%s\n' \
      "$id" "$pinned" >&2
    return 4
  fi

  got=$(sha256sum -- "$blob") || return 4
  got=${got%% *}
  if [[ "$got" != "$pinned" ]]; then
    printf 'verification error: manifest-list digest mismatch for %s\n  expected: %s\n  actual:   %s\n' \
      "$id" "$pinned" "$got" >&2
    return 4
  fi

  while IFS= read -r f; do
    name=${f##*/}
    if [[ ! "$name" =~ ^[0-9a-f]{64}$ ]]; then
      printf 'verification error: non-digest blob name in %s layout: %s\n' "$id" "$name" >&2
      return 4
    fi
    got=$(sha256sum -- "$f") || return 4
    got=${got%% *}
    if [[ "$got" != "$name" ]]; then
      printf 'verification error: blob content does not match its digest in %s: %s\n' "$id" "$name" >&2
      return 4
    fi
  done < <(find "$dir/blobs/sha256" -type f)
}

verify_oci() {
  local id=$1
  need_command sha256sum || return 2
  need_command jq || return 2
  need_command find || return 2
  verify_oci_layout "$id" "$(artifact_path "$id")" "${SHA256[$id]}" || return $?
  printf 'verified\t%s\t%s\n' "$id" "$(artifact_path "$id")"
}

pkgset_manifest_path() {
  local dir
  dir=$(dirname -- "$LOCK_FILE")
  printf '%s/compose-phase1-artifacts.%s.packages.tsv' "$dir" "$1"
}

pkgset_cache_dir() {
  printf '%s/%s' "$CACHE_ROOT" "$1"
}

# Resolve the on-disk path of member index $2 of package-set $1. A `url` member
# lives under the row's own cache directory; a `staged` member lives at its
# cache-relative source path (where a prep script places it).
pkgset_entry_path() {
  local id=$1 i=$2
  if [[ "${PKG_METHOD[$i]}" == "url" ]]; then
    printf '%s/%s/%s' "$CACHE_ROOT" "$id" "${PKG_RELPATH[$i]}"
  else
    printf '%s/%s' "$CACHE_ROOT" "${PKG_SOURCE[$i]}"
  fi
}

# Parse and validate the per-set member manifest into the PKG_* arrays. The
# manifest's own sha256 must equal the row's pinned anchor before any member is
# trusted, so the chain is lock row -> member manifest -> member bytes. Returns 2
# for a missing tool, 4 for any manifest or anchor problem.
read_pkgset_entries() {
  local id=$1 manifest got line ln=0
  need_command sha256sum || return 2
  manifest=$(pkgset_manifest_path "$id")
  [[ -f "$manifest" ]] || {
    printf 'verification error: package manifest missing for %s: %s\n' "$id" "$manifest" >&2
    return 4
  }
  got=$(sha256sum -- "$manifest") || return 4
  got=${got%% *}
  if [[ "$got" != "${SHA256[$id]}" ]]; then
    printf 'verification error: package manifest digest mismatch for %s\n  expected: %s\n  actual:   %s\n' \
      "$id" "${SHA256[$id]}" "$got" >&2
    return 4
  fi

  PKG_RELPATH=(); PKG_METHOD=(); PKG_SIZE=(); PKG_SHA=(); PKG_SOURCE=(); PKG_RECOVERY=()
  while IFS= read -r line || [[ -n "$line" ]]; do
    ln=$((ln + 1))
    line=${line%$'\r'}
    [[ -z "$line" || "$line" == \#* ]] && continue
    local -a fields=()
    IFS=$'\t' read -r -a fields <<<"$line"
    [[ ${#fields[@]} -eq 6 ]] \
      || { printf 'verification error: %s manifest line %d has %d fields; expected 6\n' "$id" "$ln" "${#fields[@]}" >&2; return 4; }
    local relpath=${fields[0]} method=${fields[1]} size=${fields[2]}
    local sha=${fields[3]} source=${fields[4]} recovery=${fields[5]}
    is_safe_filename "$relpath" \
      || { printf 'verification error: %s manifest line %d has an unsafe member name\n' "$id" "$ln" >&2; return 4; }
    [[ "$size" =~ ^[1-9][0-9]*$ ]] \
      || { printf 'verification error: %s manifest line %d has an invalid size\n' "$id" "$ln" >&2; return 4; }
    [[ "$sha" =~ ^[0-9a-f]{64}$ ]] \
      || { printf 'verification error: %s manifest line %d has an invalid sha256\n' "$id" "$ln" >&2; return 4; }
    case "$method" in
      url)
        is_release_specific_url "$source" \
          || { printf 'verification error: %s manifest line %d URL is not release-specific\n' "$id" "$ln" >&2; return 4; }
        is_approved_pkg_url "$source" \
          || { printf 'verification error: %s manifest line %d URL is not approved\n' "$id" "$ln" >&2; return 4; }
        [[ "$source" == "${SOURCE_URL[$id]}"* ]] \
          || { printf 'verification error: %s manifest line %d URL is outside the row source scope\n' "$id" "$ln" >&2; return 4; }
        [[ "$recovery" == "-" ]] \
          || { printf 'verification error: %s manifest line %d url member must use - for recovery\n' "$id" "$ln" >&2; return 4; }
        ;;
      staged)
        is_safe_cache_relpath "$source" \
          || { printf 'verification error: %s manifest line %d has an unsafe staged path\n' "$id" "$ln" >&2; return 4; }
        { [[ -n "$recovery" && "$recovery" != "-" && "$recovery" != *$'\n'* ]]; } \
          || { printf 'verification error: %s manifest line %d staged member needs a recovery command\n' "$id" "$ln" >&2; return 4; }
        ;;
      *)
        printf 'verification error: %s manifest line %d has an unknown method %s\n' "$id" "$ln" "$method" >&2
        return 4
        ;;
    esac
    PKG_RELPATH+=("$relpath"); PKG_METHOD+=("$method"); PKG_SIZE+=("$size")
    PKG_SHA+=("$sha"); PKG_SOURCE+=("$source"); PKG_RECOVERY+=("$recovery")
  done <"$manifest"

  [[ ${#PKG_RELPATH[@]} -gt 0 ]] \
    || { printf 'verification error: %s manifest has no members\n' "$id" >&2; return 4; }
}

# Offline integrity check for a package-set: the member manifest must match the
# row anchor, and every listed member must be present and hash to its pin.
# Returns 3 for a missing member, 4 for a manifest or hash failure.
verify_pkgset() {
  local id=$1 i path
  read_pkgset_entries "$id" || return $?
  for i in "${!PKG_RELPATH[@]}"; do
    path=$(pkgset_entry_path "$id" "$i")
    [[ -f "$path" ]] || { printf 'missing: %s\n' "$path" >&2; return 3; }
    check_file "$path" "${PKG_SIZE[$i]}" "${PKG_SHA[$i]}" || return $?
  done
  printf 'verified\t%s\t%s (%d members)\n' "$id" "$(pkgset_cache_dir "$id")" "${#PKG_RELPATH[@]}"
}

verify_one() {
  local id=$1
  require_id "$id" || return $?
  if [[ "${STATUS[$id]}" != "ready" ]]; then
    printf 'blocked: %s is %s: %s\n' "$id" "${STATUS[$id]}" "${NOTE[$id]}" >&2
    return 3
  fi

  if [[ "${KIND[$id]}" == "oci-image" ]]; then
    verify_oci "$id"
    return $?
  fi

  if [[ "${KIND[$id]}" == "package-set" ]]; then
    verify_pkgset "$id"
    return $?
  fi

  need_command sha256sum || return 2
  need_command stat || return 2
  need_command gpgv || return 2
  need_command mktemp || return 2

  local artifact manifest signature=
  artifact=$(artifact_path "$id")
  manifest=$(checksum_path "$id")
  [[ -f "$artifact" ]] || {
    printf 'missing: %s\n' "$artifact" >&2
    return 3
  }
  [[ -f "$manifest" ]] || {
    printf 'missing: %s\n' "$manifest" >&2
    return 3
  }

  check_file "$artifact" "${SIZE_BYTES[$id]}" "${SHA256[$id]}" || return $?
  check_file "$manifest" "${CHECKSUM_SIZE_BYTES[$id]}" "${CHECKSUM_SHA256[$id]}" || return $?
  if [[ "${KIND[$id]}" == "file-openpgp-detached" ]]; then
    signature=$(signature_path "$id")
    [[ -f "$signature" ]] || {
      printf 'missing: %s\n' "$signature" >&2
      return 3
    }
    check_file "$signature" "${SIGNATURE_SIZE_BYTES[$id]}" "${SIGNATURE_SHA256[$id]}" || return $?
  fi
  verify_openpgp "$id" "$manifest" "$signature" || return $?
  manifest_has_exact_hash "$manifest" "${FILENAME[$id]}" "${SHA256[$id]}" || return $?
  printf 'verified\t%s\t%s\n' "$id" "$artifact"
}

download_to_temp() {
  local url=$1 directory=$2 stem=$3 max_bytes=$4 output_var=$5 tmp size
  tmp=$(mktemp "$directory/.${stem}.part.XXXXXX")
  # Fedora's official download endpoint redirects to rotating mirrors. Redirects
  # stay HTTPS-only and bounded; signed metadata plus the pinned file hash, not
  # the mirror hostname, authenticates every published artifact.
  if ! timeout "$DOWNLOAD_TIMEOUT_SECONDS" curl \
    --proto '=https' \
    --proto-redir '=https' \
    --tlsv1.2 \
    --fail \
    --location \
    --max-redirs 5 \
    --silent \
    --show-error \
    --retry 3 \
    --retry-all-errors \
    --connect-timeout 15 \
    --max-time "$((DOWNLOAD_TIMEOUT_SECONDS - 10))" \
    --max-filesize "$max_bytes" \
    --output "$tmp" \
    -- "$url"; then
    rm -f -- "$tmp"
    printf 'download error: %s\n' "$url" >&2
    return 5
  fi
  size=$(stat -c '%s' -- "$tmp") || {
    rm -f -- "$tmp"
    return 5
  }
  if (( size > max_bytes )); then
    rm -f -- "$tmp"
    printf 'download error: %s exceeded %s bytes\n' "$url" "$max_bytes" >&2
    return 5
  fi
  printf -v "$output_var" '%s' "$tmp"
}

fetch_oci() {
  local id=$1 pinned ref repo dir final
  need_command skopeo || return 2
  need_command jq || return 2
  need_command sha256sum || return 2
  need_command find || return 2
  need_command mktemp || return 2
  need_command install || return 2
  need_command timeout || return 2
  [[ "$DOWNLOAD_TIMEOUT_SECONDS" =~ ^[0-9]+$ && "$DOWNLOAD_TIMEOUT_SECONDS" -gt 30 ]] || {
    printf 'error: BASIL_COMPOSE_ARTIFACT_DOWNLOAD_TIMEOUT must be an integer greater than 30\n' >&2
    return 2
  }

  if verify_oci "$id" >/dev/null 2>&1; then
    printf 'already-verified\t%s\t%s\n' "$id" "$(artifact_path "$id")"
    return 0
  fi

  pinned=${SHA256[$id]}
  ref=${SOURCE_URL[$id]}
  repo=${ref%:*}
  dir=$(artifact_dir "$id")
  final=$(artifact_path "$id")
  install -d -m 0700 -- "$CACHE_ROOT" "$dir"

  (
    set -e
    local tmp='' policy=''
    # shellcheck disable=SC2329  # invoked indirectly by the EXIT trap
    cleanup_oci() {
      [[ -z "$tmp" ]] || rm -rf -- "$tmp"
      [[ -z "$policy" ]] || rm -f -- "$policy"
    }
    trap cleanup_oci EXIT

    tmp=$(mktemp -d "$dir/.image.part.XXXXXX")
    policy=$(mktemp "$dir/.policy.XXXXXX.json")
    # The pinned manifest-list digest is the sole trust anchor and is re-verified
    # locally below, so skopeo's own signature policy is deliberately permissive.
    # This keeps acquisition portable across hosts that ship no default policy.
    printf '{"default":[{"type":"insecureAcceptAnything"}]}\n' >"$policy"

    # Digest-pinned pull of the full multi-arch index: skopeo validates the
    # requested manifest digest during transfer, and --all retains every
    # platform manifest so the arm64 lane can select its architecture offline.
    printf 'fetching\t%s\t%s@sha256:%s\n' "$id" "$repo" "$pinned"
    timeout "$DOWNLOAD_TIMEOUT_SECONDS" skopeo copy --all --quiet \
      --policy "$policy" \
      "docker://${repo}@sha256:${pinned}" "oci:${tmp}" || exit 5
    rm -f -- "$policy"
    policy=''

    # Never publish the cache entry until the freshly pulled layout verifies
    # against the pinned digest fully offline.
    verify_oci_layout "$id" "$tmp" "$pinned" || exit 4

    rm -rf -- "$final"
    mv -T -- "$tmp" "$final"
    tmp=''
    chmod -R go-rwx -- "$final" 2>/dev/null || true
    sync -f "$final" 2>/dev/null || true
  ) || return $?

  verify_oci "$id"
}

# Acquire a package-set's members into the cache. `url` members are downloaded
# from their approved immutable source and each verified against its pinned
# sha256 before an atomic rename into place, so no unverified bytes ever land
# under a verified name. `staged` members are produced out of band by a prep
# script and only verified in place; a missing or failing staged member fails
# closed (exit 3) with its recovery command, never a download.
fetch_pkgset() {
  local id=$1 i path dir rc
  need_command sha256sum || return 2
  need_command curl || return 2
  need_command timeout || return 2
  need_command mktemp || return 2
  need_command stat || return 2
  need_command install || return 2
  [[ "$DOWNLOAD_TIMEOUT_SECONDS" =~ ^[0-9]+$ && "$DOWNLOAD_TIMEOUT_SECONDS" -gt 30 ]] || {
    printf 'error: BASIL_COMPOSE_ARTIFACT_DOWNLOAD_TIMEOUT must be an integer greater than 30\n' >&2
    return 2
  }

  if verify_pkgset "$id" >/dev/null 2>&1; then
    printf 'already-verified\t%s\t%s\n' "$id" "$(pkgset_cache_dir "$id")"
    return 0
  fi

  read_pkgset_entries "$id" || return $?
  dir=$(pkgset_cache_dir "$id")
  for i in "${!PKG_RELPATH[@]}"; do
    path=$(pkgset_entry_path "$id" "$i")
    if [[ -f "$path" ]] && check_file "$path" "${PKG_SIZE[$i]}" "${PKG_SHA[$i]}" >/dev/null 2>&1; then
      continue
    fi
    if [[ "${PKG_METHOD[$i]}" == "staged" ]]; then
      printf 'blocked: %s member %s is staged out of band and is absent or fails verification\n  expected: %s\n  recover it by running: %s\n' \
        "$id" "${PKG_RELPATH[$i]}" "$path" "${PKG_RECOVERY[$i]}" >&2
      return 3
    fi
    install -d -m 0700 -- "$CACHE_ROOT" "$dir"
    # Run the acquire+verify+place as a standalone subshell (NOT `( ... ) ||`),
    # then test its status separately: bash ignores an inner `set -e` when a
    # subshell is the left operand of `||`, which would let a hash-mismatched
    # download slip past check_file into the mv. Every step is also guarded with
    # an explicit `|| exit` so no unverified bytes can land under a verified name.
    (
      set -e
      # Not named `tmp`: download_to_temp has its own local `tmp`, and a matching
      # output-var name would make its `printf -v` target its own local instead.
      local pkg_tmp=''
      # shellcheck disable=SC2329  # invoked indirectly by the EXIT trap
      cleanup_pkg() { [[ -z "$pkg_tmp" ]] || rm -f -- "$pkg_tmp"; }
      trap cleanup_pkg EXIT
      printf 'fetching\t%s\t%s\n' "$id" "${PKG_SOURCE[$i]}"
      download_to_temp "${PKG_SOURCE[$i]}" "$dir" pkg "${PKG_SIZE[$i]}" pkg_tmp || exit $?
      check_file "$pkg_tmp" "${PKG_SIZE[$i]}" "${PKG_SHA[$i]}" || exit $?
      chmod 0600 -- "$pkg_tmp" || exit $?
      mv -f -- "$pkg_tmp" "$path" || exit $?
      pkg_tmp=''
      sync -f "$path" 2>/dev/null || true
    )
    rc=$?
    [[ $rc -eq 0 ]] || return "$rc"
  done

  verify_pkgset "$id"
}

fetch_one() {
  local id=$1
  require_id "$id" || return $?
  if [[ "${STATUS[$id]}" != "ready" ]]; then
    printf 'blocked: %s is %s: %s\n' "$id" "${STATUS[$id]}" "${NOTE[$id]}" >&2
    return 3
  fi

  if [[ "${KIND[$id]}" == "oci-image" ]]; then
    fetch_oci "$id"
    return $?
  fi

  if [[ "${KIND[$id]}" == "package-set" ]]; then
    fetch_pkgset "$id"
    return $?
  fi

  need_command curl || return 2
  need_command timeout || return 2
  need_command mktemp || return 2
  need_command stat || return 2
  need_command install || return 2
  need_command sha256sum || return 2
  need_command gpgv || return 2
  [[ "$DOWNLOAD_TIMEOUT_SECONDS" =~ ^[0-9]+$ && "$DOWNLOAD_TIMEOUT_SECONDS" -gt 30 ]] || {
    printf 'error: BASIL_COMPOSE_ARTIFACT_DOWNLOAD_TIMEOUT must be an integer greater than 30\n' >&2
    return 2
  }

  if verify_one "$id" >/dev/null 2>&1; then
    printf 'already-verified\t%s\t%s\n' "$id" "$(artifact_path "$id")"
    return 0
  fi

  local directory artifact_final manifest_final signature_final rc
  directory=$(artifact_dir "$id")
  artifact_final=$(artifact_path "$id")
  manifest_final=$(checksum_path "$id")
  signature_final=$(signature_path "$id")
  install -d -m 0700 -- "$CACHE_ROOT" "$directory"

  (
    set -e
    local artifact_tmp='' manifest_tmp='' signature_tmp=''
    # shellcheck disable=SC2329  # invoked indirectly by the EXIT trap
    cleanup_fetch() {
      [[ -z "$artifact_tmp" ]] || rm -f -- "$artifact_tmp"
      [[ -z "$manifest_tmp" ]] || rm -f -- "$manifest_tmp"
      [[ -z "$signature_tmp" ]] || rm -f -- "$signature_tmp"
    }
    trap cleanup_fetch EXIT

    printf 'fetching\t%s\t%s\n' "$id" "${CHECKSUM_URL[$id]}"
    download_to_temp "${CHECKSUM_URL[$id]}" "$directory" checksums "${CHECKSUM_SIZE_BYTES[$id]}" manifest_tmp
    check_file "$manifest_tmp" "${CHECKSUM_SIZE_BYTES[$id]}" "${CHECKSUM_SHA256[$id]}"
    if [[ "${KIND[$id]}" == "file-openpgp-detached" ]]; then
      printf 'fetching\t%s\t%s\n' "$id" "${SIGNATURE_URL[$id]}"
      download_to_temp "${SIGNATURE_URL[$id]}" "$directory" signature "${SIGNATURE_SIZE_BYTES[$id]}" signature_tmp
      check_file "$signature_tmp" "${SIGNATURE_SIZE_BYTES[$id]}" "${SIGNATURE_SHA256[$id]}"
      verify_openpgp "$id" "$manifest_tmp" "$signature_tmp"
    else
      verify_openpgp "$id" "$manifest_tmp"
    fi
    manifest_has_exact_hash "$manifest_tmp" "${FILENAME[$id]}" "${SHA256[$id]}"

    printf 'fetching\t%s\t%s\n' "$id" "${SOURCE_URL[$id]}"
    download_to_temp "${SOURCE_URL[$id]}" "$directory" artifact "${SIZE_BYTES[$id]}" artifact_tmp
    check_file "$artifact_tmp" "${SIZE_BYTES[$id]}" "${SHA256[$id]}"

    chmod 0600 -- "$artifact_tmp" "$manifest_tmp"
    mv -f -- "$artifact_tmp" "$artifact_final"
    artifact_tmp=
    mv -f -- "$manifest_tmp" "$manifest_final"
    manifest_tmp=
    if [[ -n "$signature_tmp" ]]; then
      chmod 0600 -- "$signature_tmp"
      mv -f -- "$signature_tmp" "$signature_final"
      signature_tmp=
    else
      rm -f -- "$signature_final"
    fi
    sync -f "$artifact_final" "$manifest_final" "$directory" 2>/dev/null || true
  )
  # Standalone subshell + separate status test: as a `( ... ) || return` operand
  # the inner `set -e` is ignored, which would let a size-matched but hash-wrong
  # download reach the mv. Kept standalone so set -e aborts before any placement.
  rc=$?
  [[ $rc -eq 0 ]] || return "$rc"

  verify_one "$id"
}

list_human() {
  printf 'ID\tSTATUS\tKIND\tPLATFORM\tSHA256\tSOURCE\n'
  local id
  for id in "${IDS[@]}"; do
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "${STATUS[$id]}" "${KIND[$id]}" \
      "${PLATFORM[$id]}" "${SHA256[$id]}" "${SOURCE_URL[$id]}"
  done
}

list_json() {
  need_command jq || return 2
  local id
  {
    for id in "${IDS[@]}"; do
      jq -n \
        --arg id "$id" \
        --arg status "${STATUS[$id]}" \
        --arg kind "${KIND[$id]}" \
        --arg platform "${PLATFORM[$id]}" \
        --arg filename "${FILENAME[$id]}" \
        --arg size_bytes "${SIZE_BYTES[$id]}" \
        --arg sha256 "${SHA256[$id]}" \
        --arg source_url "${SOURCE_URL[$id]}" \
        --arg checksum_url "${CHECKSUM_URL[$id]}" \
        --arg checksum_size_bytes "${CHECKSUM_SIZE_BYTES[$id]}" \
        --arg checksum_sha256 "${CHECKSUM_SHA256[$id]}" \
        --arg signature_url "${SIGNATURE_URL[$id]}" \
        --arg signature_size_bytes "${SIGNATURE_SIZE_BYTES[$id]}" \
        --arg signature_sha256 "${SIGNATURE_SHA256[$id]}" \
        --arg key_file "${KEY_FILE[$id]}" \
        --arg signer_fingerprint "${SIGNER_FINGERPRINT[$id]}" \
        --arg note "${NOTE[$id]}" \
        '{id:$id,status:$status,kind:$kind,platform:$platform,filename:$filename,size_bytes:$size_bytes,sha256:$sha256,source_url:$source_url,checksum_url:$checksum_url,checksum_size_bytes:$checksum_size_bytes,checksum_sha256:$checksum_sha256,signature_url:$signature_url,signature_size_bytes:$signature_size_bytes,signature_sha256:$signature_sha256,key_file:$key_file,signer_fingerprint:$signer_fingerprint,note:$note}'
    done
  } | jq -s '{schema_version:1,artifacts:.}'
}

explain_one() {
  local id=$1
  require_id "$id" || return $?
  printf 'id: %s\n' "$id"
  printf 'status: %s\n' "${STATUS[$id]}"
  printf 'kind: %s\n' "${KIND[$id]}"
  printf 'platform: %s\n' "${PLATFORM[$id]}"
  printf 'filename: %s\n' "${FILENAME[$id]}"
  printf 'size bytes: %s\n' "${SIZE_BYTES[$id]}"
  printf 'sha256: %s\n' "${SHA256[$id]}"
  printf 'source: %s\n' "${SOURCE_URL[$id]}"
  if [[ "${KIND[$id]}" == "oci-image" && "${STATUS[$id]}" == "ready" ]]; then
    printf 'pinned reference: %s@sha256:%s\n' "${SOURCE_URL[$id]}" "${SHA256[$id]}"
  fi
  if [[ "${KIND[$id]}" == "package-set" && "${STATUS[$id]}" == "ready" ]]; then
    printf 'member manifest: %s\n' "$(pkgset_manifest_path "$id")"
  fi
  printf 'checksums: %s\n' "${CHECKSUM_URL[$id]}"
  printf 'checksums size bytes: %s\n' "${CHECKSUM_SIZE_BYTES[$id]}"
  printf 'checksums sha256: %s\n' "${CHECKSUM_SHA256[$id]}"
  printf 'signature: %s\n' "${SIGNATURE_URL[$id]}"
  printf 'signature size bytes: %s\n' "${SIGNATURE_SIZE_BYTES[$id]}"
  printf 'signature sha256: %s\n' "${SIGNATURE_SHA256[$id]}"
  printf 'key: %s\n' "${KEY_FILE[$id]}"
  printf 'signer fingerprint: %s\n' "${SIGNER_FINGERPRINT[$id]}"
  printf 'cache path: %s\n' "$(if [[ "${STATUS[$id]}" == ready ]]; then artifact_path "$id"; else printf '%s' '-'; fi)"
  printf 'note: %s\n' "${NOTE[$id]}"
}

run_all_ready() {
  local operation=$1 id rc first_error=0
  for id in "${IDS[@]}"; do
    if [[ "${STATUS[$id]}" != "ready" ]]; then
      printf 'blocked\t%s\t%s\n' "$id" "${NOTE[$id]}" >&2
      continue
    fi
    if "$operation" "$id"; then
      continue
    else
      rc=$?
      [[ $first_error -ne 0 ]] || first_error=$rc
    fi
  done
  [[ $first_error -eq 0 ]] || return "$first_error"
}

require_populated_inventory() {
  local id blocked=0
  for id in "${IDS[@]}"; do
    [[ "${STATUS[$id]}" == "ready" ]] || blocked=$((blocked + 1))
  done
  if [[ $blocked -gt 0 ]]; then
    printf 'inventory incomplete: %d entries are not yet populated\n' "$blocked" >&2
    return 3
  fi
}

report_missing() {
  local id path missing=0
  for id in "${IDS[@]}"; do
    if [[ "${STATUS[$id]}" != "ready" ]]; then
      printf 'BLOCKED\t%s\t%s\n' "$id" "${NOTE[$id]}"
      missing=$((missing + 1))
      continue
    fi
    if [[ "${KIND[$id]}" == "oci-image" ]]; then
      local layout
      layout=$(artifact_path "$id")
      for path in "$layout/oci-layout" "$layout/index.json" "$layout/blobs/sha256/${SHA256[$id]}"; do
        if [[ ! -f "$path" ]]; then
          printf 'MISSING\t%s\t%s\n' "$id" "$path"
          missing=$((missing + 1))
        fi
      done
      continue
    fi
    if [[ "${KIND[$id]}" == "package-set" ]]; then
      if ! read_pkgset_entries "$id" 2>/dev/null; then
        printf 'MISSING\t%s\t%s\n' "$id" "$(pkgset_manifest_path "$id")"
        missing=$((missing + 1))
        continue
      fi
      local pi
      for pi in "${!PKG_RELPATH[@]}"; do
        path=$(pkgset_entry_path "$id" "$pi")
        if [[ ! -f "$path" ]]; then
          printf 'MISSING\t%s\t%s\n' "$id" "$path"
          missing=$((missing + 1))
        fi
      done
      continue
    fi
    for path in "$(artifact_path "$id")" "$(checksum_path "$id")"; do
      if [[ ! -f "$path" ]]; then
        printf 'MISSING\t%s\t%s\n' "$id" "$path"
        missing=$((missing + 1))
      fi
    done
    if [[ "${KIND[$id]}" == "file-openpgp-detached" ]]; then
      path=$(signature_path "$id")
      if [[ ! -f "$path" ]]; then
        printf 'MISSING\t%s\t%s\n' "$id" "$path"
        missing=$((missing + 1))
      fi
    fi
  done
  [[ $missing -eq 0 ]] || return 3
}

recovery() {
  printf 'Compose Phase 1 artifact recovery\n\n'
  printf 'Cache root:\n  %s\n\n' "$CACHE_ROOT"
  printf 'Prerequisites:\n'
  printf '  bash curl timeout sha256sum gpgv mktemp install mv sync\n'
  printf '  skopeo, jq, and find are additionally required for oci-image rows\n'
  printf '  jq is additionally required for list --json\n\n'
  printf 'Fresh-checkout commands (run from the repository root):\n'
  printf '  BASIL_COMPOSE_ARTIFACT_CACHE=%q ./scripts/compose-phase1-artifacts.sh fetch-all\n' "$CACHE_ROOT"
  printf '  BASIL_COMPOSE_ARTIFACT_CACHE=%q ./scripts/compose-phase1-artifacts.sh verify-all\n' "$CACHE_ROOT"
  printf '  BASIL_COMPOSE_ARTIFACT_CACHE=%q ./scripts/compose-phase1-artifacts.sh offline\n' "$CACHE_ROOT"
  printf '  Exit 3 is expected while entries below remain not-yet-populated; populated files are still fetched and verified.\n\n'

  local id
  printf 'Pinned downloadable artifacts:\n'
  for id in "${IDS[@]}"; do
    [[ "${STATUS[$id]}" == "ready" ]] || continue
    printf '\n  %s\n' "$id"
    printf '    platform: %s\n' "${PLATFORM[$id]}"
    printf '    output: %s\n' "$(artifact_path "$id")"
    if [[ "${KIND[$id]}" == "oci-image" ]]; then
      printf '    tag reference: %s\n' "${SOURCE_URL[$id]}"
      printf '    pinned reference: %s@sha256:%s\n' "${SOURCE_URL[$id]}" "${SHA256[$id]}"
      printf '    manifest-list digest: sha256:%s\n' "${SHA256[$id]}"
      printf '    acquisition: skopeo copy --all by digest into an OCI layout, re-verified offline\n'
    elif [[ "${KIND[$id]}" == "package-set" ]]; then
      printf '    member manifest: %s\n' "$(pkgset_manifest_path "$id")"
      printf '    manifest sha256: %s\n' "${SHA256[$id]}"
      printf '    signed index: %s (sha256 %s)\n' "${CHECKSUM_URL[$id]}" "${CHECKSUM_SHA256[$id]}"
      printf '    signer fingerprint: %s\n' "${SIGNER_FINGERPRINT[$id]}"
      if read_pkgset_entries "$id" 2>/dev/null; then
        local mi
        for mi in "${!PKG_RELPATH[@]}"; do
          if [[ "${PKG_METHOD[$mi]}" == "url" ]]; then
            printf '    member (url): %s\n      from: %s\n      sha256: %s\n' \
              "${PKG_RELPATH[$mi]}" "${PKG_SOURCE[$mi]}" "${PKG_SHA[$mi]}"
          else
            printf '    member (staged): %s\n      at: %s\n      sha256: %s\n      recover: %s\n' \
              "${PKG_RELPATH[$mi]}" "$(pkgset_entry_path "$id" "$mi")" "${PKG_SHA[$mi]}" "${PKG_RECOVERY[$mi]}"
          fi
        done
      fi
    else
      printf '    source: %s\n' "${SOURCE_URL[$id]}"
      printf '    expected bytes: %s\n' "${SIZE_BYTES[$id]}"
      printf '    expected sha256: %s\n' "${SHA256[$id]}"
      printf '    signed checksums: %s\n' "${CHECKSUM_URL[$id]}"
      printf '    checksums bytes: %s\n' "${CHECKSUM_SIZE_BYTES[$id]}"
      printf '    checksums sha256: %s\n' "${CHECKSUM_SHA256[$id]}"
      printf '    detached signature: %s\n' "${SIGNATURE_URL[$id]}"
      printf '    signature bytes: %s\n' "${SIGNATURE_SIZE_BYTES[$id]}"
      printf '    signature sha256: %s\n' "${SIGNATURE_SHA256[$id]}"
      printf '    checked-in key: ./interop-tests/compose-phase1/keys/%s\n' "${KEY_FILE[$id]}"
      printf '    pinned signer: %s\n' "${SIGNER_FINGERPRINT[$id]}"
    fi
    printf '    command: BASIL_COMPOSE_ARTIFACT_CACHE=%q ./scripts/compose-phase1-artifacts.sh fetch %q\n' "$CACHE_ROOT" "$id"
  done

  printf '\nNot yet populated; no download or verification is claimed:\n'
  local blocked=0
  for id in "${IDS[@]}"; do
    [[ "${STATUS[$id]}" != "ready" ]] || continue
    blocked=$((blocked + 1))
    printf '  %s [%s, %s]: %s\n    approved source scope: %s\n' \
      "$id" "${KIND[$id]}" "${PLATFORM[$id]}" "${NOTE[$id]}" "${SOURCE_URL[$id]}"
  done
  [[ $blocked -gt 0 ]] || printf '  none\n'
}

expect_failure() {
  local label=$1
  shift
  if "$@" >/dev/null 2>&1; then
    printf 'self-test failure: %s unexpectedly succeeded\n' "$label" >&2
    return 1
  fi
  printf 'ok: %s\n' "$label"
}

self_test() {
  need_command mktemp
  need_command sha256sum
  need_command timeout

  local tmp
  tmp=$(mktemp -d)
  # shellcheck disable=SC2064  # capture the temporary path before local scope ends
  trap "rm -rf -- $(printf '%q' "$tmp")" RETURN
  mkdir -p "$tmp/keys" "$tmp/cache" "$tmp/bin"
  : >"$tmp/keys/test.gpg"

  local header=$EXPECTED_HEADER blocked_row ready_row
  blocked_row=$'1\tblocked-entry\tnot-yet-populated\toci-image\tlinux/amd64\t-\t-\t-\tdocker.io/library/postgres\t-\t-\t-\t-\t-\t-\t-\t-\tDigest selection intentionally pending.'
  ready_row=$'1\ttest-ready\tready\tfile-openpgp-clearsigned\tlinux/amd64\ttest.qcow2\t8\t0000000000000000000000000000000000000000000000000000000000000000\thttps://cloud-images.ubuntu.com/releases/24.04.3/release/test.qcow2\thttps://cloud-images.ubuntu.com/releases/24.04.3/release/SHA256SUMS\t22\t0000000000000000000000000000000000000000000000000000000000000000\t-\t-\t-\ttest.gpg\t0000000000000000000000000000000000000000\tSynthetic self-test row.'

  printf '%s\n%s\textra\n' "$header" "$blocked_row" >"$tmp/malformed.tsv"
  expect_failure 'malformed row rejected' env \
    BASIL_COMPOSE_ARTIFACT_LOCK="$tmp/malformed.tsv" \
    BASIL_COMPOSE_ARTIFACT_KEY_ROOT="$tmp/keys" \
    "$SCRIPT_PATH" list

  printf '%s\n%s\n%s\n' "$header" "$blocked_row" "$blocked_row" >"$tmp/duplicate.tsv"
  expect_failure 'duplicate id rejected' env \
    BASIL_COMPOSE_ARTIFACT_LOCK="$tmp/duplicate.tsv" \
    BASIL_COMPOSE_ARTIFACT_KEY_ROOT="$tmp/keys" \
    "$SCRIPT_PATH" list

  printf '%s\n%s\n' "$header" "$ready_row" >"$tmp/ready.tsv"
  mkdir -p "$tmp/cache/test-ready"
  printf 'corrupt\n' >"$tmp/cache/test-ready/test.qcow2"
  printf 'not a signed manifest\n' >"$tmp/cache/test-ready/upstream.checksums"
  expect_failure 'corrupt cache rejected' env \
    BASIL_COMPOSE_ARTIFACT_LOCK="$tmp/ready.tsv" \
    BASIL_COMPOSE_ARTIFACT_KEY_ROOT="$tmp/keys" \
    BASIL_COMPOSE_ARTIFACT_CACHE="$tmp/cache" \
    "$SCRIPT_PATH" verify test-ready

  rm -rf -- "$tmp/cache/test-ready"
  expect_failure 'offline missing files rejected' env \
    BASIL_COMPOSE_ARTIFACT_LOCK="$tmp/ready.tsv" \
    BASIL_COMPOSE_ARTIFACT_KEY_ROOT="$tmp/keys" \
    BASIL_COMPOSE_ARTIFACT_CACHE="$tmp/cache" \
    "$SCRIPT_PATH" offline

  cat >"$tmp/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
output=
while [[ $# -gt 0 ]]; do
  if [[ "$1" == "--output" ]]; then
    output=$2
    shift 2
  else
    shift
  fi
done
printf 'partial download\n' >"$output"
exit 22
EOF
  chmod +x "$tmp/bin/curl"
  mkdir -p "$tmp/cache/test-ready"
  printf 'existing cache content\n' >"$tmp/cache/test-ready/test.qcow2"
  expect_failure 'failed fetch rejected' env \
    PATH="$tmp/bin:$PATH" \
    BASIL_COMPOSE_ARTIFACT_LOCK="$tmp/ready.tsv" \
    BASIL_COMPOSE_ARTIFACT_KEY_ROOT="$tmp/keys" \
    BASIL_COMPOSE_ARTIFACT_CACHE="$tmp/cache" \
    "$SCRIPT_PATH" fetch test-ready
  [[ "$(<"$tmp/cache/test-ready/test.qcow2")" == 'existing cache content' ]] \
    || { printf 'self-test failure: failed fetch replaced cached artifact\n' >&2; return 1; }
  if compgen -G "$tmp/cache/test-ready/.*.part.*" >/dev/null; then
    printf 'self-test failure: failed fetch left temporary files\n' >&2
    return 1
  fi
  printf 'ok: failed fetch preserves prior cache atomically\n'

  need_command jq
  need_command find
  # Build a synthetic, self-addressing OCI layout. The pinned manifest-list
  # digest is computed from the blob bytes, so the verifier's trust anchor is
  # exercised without any network access or a real container tool.
  build_test_oci_layout() {
    local d=$1 idx dg extra ex
    rm -rf -- "$d"
    mkdir -p "$d/blobs/sha256"
    printf '{"imageLayoutVersion":"1.0.0"}' >"$d/oci-layout"
    idx='{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","size":1,"platform":{"os":"linux","architecture":"amd64"}}]}'
    printf '%s' "$idx" >"$d/.ml"
    dg=$(sha256sum "$d/.ml"); dg=${dg%% *}
    mv -- "$d/.ml" "$d/blobs/sha256/$dg"
    extra='self-test-layer-bytes'
    printf '%s' "$extra" >"$d/.ex"
    ex=$(sha256sum "$d/.ex"); ex=${ex%% *}
    mv -- "$d/.ex" "$d/blobs/sha256/$ex"
    printf '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.index.v1+json","digest":"sha256:%s","size":%d}]}' \
      "$dg" "${#idx}" >"$d/index.json"
    printf '%s' "$dg"
  }

  local oci_dir oci_dg oci_row
  oci_dir="$tmp/cache/test-oci/image"
  oci_dg=$(build_test_oci_layout "$oci_dir")
  oci_row=$(printf '1\ttest-oci\tready\toci-image\tlinux/multiarch\timage\t-\t%s\tdocker.io/library/alpine:3.22\t-\t-\t-\t-\t-\t-\t-\t-\tSynthetic self-test OCI layout.' "$oci_dg")
  printf '%s\n%s\n' "$header" "$oci_row" >"$tmp/oci.tsv"

  env \
    BASIL_COMPOSE_ARTIFACT_LOCK="$tmp/oci.tsv" \
    BASIL_COMPOSE_ARTIFACT_KEY_ROOT="$tmp/keys" \
    BASIL_COMPOSE_ARTIFACT_CACHE="$tmp/cache" \
    "$SCRIPT_PATH" verify test-oci >/dev/null \
    || { printf 'self-test failure: valid oci layout did not verify\n' >&2; return 1; }
  printf 'ok: valid oci layout verifies offline\n'

  env \
    BASIL_COMPOSE_ARTIFACT_LOCK="$tmp/oci.tsv" \
    BASIL_COMPOSE_ARTIFACT_KEY_ROOT="$tmp/keys" \
    BASIL_COMPOSE_ARTIFACT_CACHE="$tmp/cache" \
    "$SCRIPT_PATH" offline >/dev/null \
    || { printf 'self-test failure: oci offline verification failed for a fully populated inventory\n' >&2; return 1; }
  printf 'ok: oci offline verification passes when every row is populated\n'

  # Negative: tampering the pinned manifest-list blob must fail (digest mismatch).
  printf 'tampered' >>"$oci_dir/blobs/sha256/$oci_dg"
  expect_failure 'oci manifest-list digest mismatch rejected' env \
    BASIL_COMPOSE_ARTIFACT_LOCK="$tmp/oci.tsv" \
    BASIL_COMPOSE_ARTIFACT_KEY_ROOT="$tmp/keys" \
    BASIL_COMPOSE_ARTIFACT_CACHE="$tmp/cache" \
    "$SCRIPT_PATH" verify test-oci

  # Negative: tampering any non-anchor blob must also fail (full-layout integrity).
  oci_dg=$(build_test_oci_layout "$oci_dir")
  local b
  for b in "$oci_dir"/blobs/sha256/*; do
    [[ "${b##*/}" == "$oci_dg" ]] && continue
    printf 'tampered' >>"$b"
  done
  expect_failure 'oci non-anchor blob tamper rejected' env \
    BASIL_COMPOSE_ARTIFACT_LOCK="$tmp/oci.tsv" \
    BASIL_COMPOSE_ARTIFACT_KEY_ROOT="$tmp/keys" \
    BASIL_COMPOSE_ARTIFACT_CACHE="$tmp/cache" \
    "$SCRIPT_PATH" verify test-oci

  # Negative: a fetch whose transport substitutes the manifest bytes must be
  # rejected by the local re-verification and must not replace the prior cache.
  cat >"$tmp/bin/skopeo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
dest= ; src=
while [[ $# -gt 0 ]]; do
  case "$1" in
    oci:*) dest=${1#oci:} ;;
    docker://*) src=$1 ;;
  esac
  shift
done
dg=${src##*@sha256:}
mkdir -p "$dest/blobs/sha256"
printf '{"imageLayoutVersion":"1.0.0"}' >"$dest/oci-layout"
printf 'attacker-substituted-manifest-bytes' >"$dest/blobs/sha256/$dg"
printf '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.index.v1+json","digest":"sha256:%s","size":1}]}' "$dg" >"$dest/index.json"
EOF
  chmod +x "$tmp/bin/skopeo"
  oci_dg=$(build_test_oci_layout "$oci_dir")
  printf 'stale' >>"$oci_dir/blobs/sha256/$oci_dg"
  local before_hash after_hash
  before_hash=$(sha256sum "$oci_dir/blobs/sha256/$oci_dg"); before_hash=${before_hash%% *}
  expect_failure 'oci fetch rejects a substituted manifest' env \
    PATH="$tmp/bin:$PATH" \
    BASIL_COMPOSE_ARTIFACT_LOCK="$tmp/oci.tsv" \
    BASIL_COMPOSE_ARTIFACT_KEY_ROOT="$tmp/keys" \
    BASIL_COMPOSE_ARTIFACT_CACHE="$tmp/cache" \
    "$SCRIPT_PATH" fetch test-oci
  after_hash=$(sha256sum "$oci_dir/blobs/sha256/$oci_dg"); after_hash=${after_hash%% *}
  [[ "$before_hash" == "$after_hash" ]] \
    || { printf 'self-test failure: rejected oci fetch mutated the cache\n' >&2; return 1; }
  if compgen -G "$tmp/cache/test-oci/.image.part.*" >/dev/null \
    || compgen -G "$tmp/cache/test-oci/.policy.*" >/dev/null; then
    printf 'self-test failure: rejected oci fetch left temporary files\n' >&2
    return 1
  fi
  printf 'ok: oci fetch rejects a substituted manifest and preserves the cache atomically\n'

  # -- package-set coverage -------------------------------------------------
  # Build a synthetic package-set with one `url` member and one `staged` member,
  # plus its checked-in-style sidecar manifest whose sha256 the row pins. Hashes
  # are computed from the bytes, so the verifier's anchor chain (lock row ->
  # member manifest -> member bytes) is exercised without any network access.
  local pkgset_id=test-pkgset
  local pkgset_sidecar="$tmp/compose-phase1-artifacts.$pkgset_id.packages.tsv"
  local pkgset_row=
  build_pkgset_fixture() {
    mkdir -p "$tmp/cache/$pkgset_id" "$tmp/cache/staged"
    printf 'aaaaaaaaaaaaaaaa' >"$tmp/cache/$pkgset_id/thing.deb"
    printf 'staged-member-bytes' >"$tmp/cache/staged/thing.bin"
    local usz uh ssz sh anchor
    usz=$(stat -c '%s' -- "$tmp/cache/$pkgset_id/thing.deb")
    uh=$(sha256sum -- "$tmp/cache/$pkgset_id/thing.deb"); uh=${uh%% *}
    ssz=$(stat -c '%s' -- "$tmp/cache/staged/thing.bin")
    sh=$(sha256sum -- "$tmp/cache/staged/thing.bin"); sh=${sh%% *}
    {
      printf '# test package-set member manifest\n'
      printf 'thing.deb\turl\t%s\t%s\thttps://download.docker.com/linux/ubuntu/dists/noble/pool/stable/amd64/thing.deb\t-\n' "$usz" "$uh"
      printf 'thing.bin\tstaged\t%s\t%s\tstaged/thing.bin\trun-the-prep\n' "$ssz" "$sh"
    } >"$pkgset_sidecar"
    anchor=$(sha256sum -- "$pkgset_sidecar"); anchor=${anchor%% *}
    pkgset_row=$(printf '1\t%s\tready\tpackage-set\tlinux/x86_64\tpackages\t-\t%s\thttps://download.docker.com/linux/ubuntu/dists/noble/pool/stable/amd64/\thttps://download.docker.com/linux/ubuntu/dists/noble/stable/binary-amd64/Packages\t-\t0000000000000000000000000000000000000000000000000000000000000000\t-\t-\t-\t-\t0000000000000000000000000000000000000000\tSynthetic self-test package set.' "$pkgset_id" "$anchor")
    printf '%s\n%s\n' "$header" "$pkgset_row" >"$tmp/pkgset.tsv"
  }
  build_pkgset_fixture

  env \
    BASIL_COMPOSE_ARTIFACT_LOCK="$tmp/pkgset.tsv" \
    BASIL_COMPOSE_ARTIFACT_KEY_ROOT="$tmp/keys" \
    BASIL_COMPOSE_ARTIFACT_CACHE="$tmp/cache" \
    "$SCRIPT_PATH" verify "$pkgset_id" >/dev/null \
    || { printf 'self-test failure: valid package-set did not verify\n' >&2; return 1; }
  printf 'ok: package-set verifies offline (url + staged members)\n'

  # A fully-populated inventory (every row ready and cached, across oci and
  # package-set kinds) must verify with exit 0 both offline and via verify-all --
  # the explicit "whole inventory verifies" assertion for the completed lock.
  oci_dg=$(build_test_oci_layout "$oci_dir")
  oci_row=$(printf '1\ttest-oci\tready\toci-image\tlinux/multiarch\timage\t-\t%s\tdocker.io/library/alpine:3.22\t-\t-\t-\t-\t-\t-\t-\t-\tSynthetic self-test OCI layout.' "$oci_dg")
  printf '%s\n%s\n%s\n' "$header" "$oci_row" "$pkgset_row" >"$tmp/full.tsv"
  env \
    BASIL_COMPOSE_ARTIFACT_LOCK="$tmp/full.tsv" \
    BASIL_COMPOSE_ARTIFACT_KEY_ROOT="$tmp/keys" \
    BASIL_COMPOSE_ARTIFACT_CACHE="$tmp/cache" \
    "$SCRIPT_PATH" offline >/dev/null \
    || { printf 'self-test failure: full inventory offline did not exit 0\n' >&2; return 1; }
  env \
    BASIL_COMPOSE_ARTIFACT_LOCK="$tmp/full.tsv" \
    BASIL_COMPOSE_ARTIFACT_KEY_ROOT="$tmp/keys" \
    BASIL_COMPOSE_ARTIFACT_CACHE="$tmp/cache" \
    "$SCRIPT_PATH" verify-all >/dev/null \
    || { printf 'self-test failure: full inventory verify-all did not exit 0\n' >&2; return 1; }
  printf 'ok: full inventory (oci + package-set) verifies offline with exit 0\n'

  # Negative: tampering a cached member must fail verification.
  printf 'x' >>"$tmp/cache/$pkgset_id/thing.deb"
  expect_failure 'package-set cached member tamper rejected' env \
    BASIL_COMPOSE_ARTIFACT_LOCK="$tmp/pkgset.tsv" \
    BASIL_COMPOSE_ARTIFACT_KEY_ROOT="$tmp/keys" \
    BASIL_COMPOSE_ARTIFACT_CACHE="$tmp/cache" \
    "$SCRIPT_PATH" verify "$pkgset_id"
  build_pkgset_fixture

  # Negative: editing the member manifest without re-pinning the row anchor fails.
  printf '# drift\n' >>"$pkgset_sidecar"
  expect_failure 'package-set manifest anchor mismatch rejected' env \
    BASIL_COMPOSE_ARTIFACT_LOCK="$tmp/pkgset.tsv" \
    BASIL_COMPOSE_ARTIFACT_KEY_ROOT="$tmp/keys" \
    BASIL_COMPOSE_ARTIFACT_CACHE="$tmp/cache" \
    "$SCRIPT_PATH" verify "$pkgset_id"
  build_pkgset_fixture

  # Negative: a missing staged member fails closed (exit 3) and never downloads.
  mv -- "$tmp/cache/staged/thing.bin" "$tmp/cache/staged/thing.bin.away"
  expect_failure 'package-set missing staged member rejected' env \
    BASIL_COMPOSE_ARTIFACT_LOCK="$tmp/pkgset.tsv" \
    BASIL_COMPOSE_ARTIFACT_KEY_ROOT="$tmp/keys" \
    BASIL_COMPOSE_ARTIFACT_CACHE="$tmp/cache" \
    "$SCRIPT_PATH" fetch "$pkgset_id"
  mv -- "$tmp/cache/staged/thing.bin.away" "$tmp/cache/staged/thing.bin"

  # Negative: a download whose bytes do not match the pinned sha256 must fail,
  # must not land in the cache, and must not leave temporaries.
  rm -f -- "$tmp/cache/$pkgset_id/thing.deb"
  cat >"$tmp/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
output=
while [[ $# -gt 0 ]]; do
  if [[ "$1" == "--output" ]]; then output=$2; shift 2; else shift; fi
done
printf 'bbbbbbbbbbbbbbbb' >"$output"
EOF
  chmod +x "$tmp/bin/curl"
  expect_failure 'package-set fetch rejects a wrong-hash download' env \
    PATH="$tmp/bin:$PATH" \
    BASIL_COMPOSE_ARTIFACT_LOCK="$tmp/pkgset.tsv" \
    BASIL_COMPOSE_ARTIFACT_KEY_ROOT="$tmp/keys" \
    BASIL_COMPOSE_ARTIFACT_CACHE="$tmp/cache" \
    "$SCRIPT_PATH" fetch "$pkgset_id"
  [[ ! -f "$tmp/cache/$pkgset_id/thing.deb" ]] \
    || { printf 'self-test failure: wrong-hash download landed in cache\n' >&2; return 1; }
  if compgen -G "$tmp/cache/$pkgset_id/.pkg.part.*" >/dev/null; then
    printf 'self-test failure: rejected package-set fetch left temporary files\n' >&2
    return 1
  fi
  printf 'ok: package-set fetch rejects a wrong-hash download and preserves the cache atomically\n'

  printf 'self-test: all checks passed\n'
}

main() {
  local command=${1:-}
  if [[ "$command" == "self-test" ]]; then
    [[ $# -eq 1 ]] || { usage >&2; exit 2; }
    self_test
    return
  fi
  if [[ "$command" == "--help" || "$command" == "-h" || -z "$command" ]]; then
    usage
    [[ -n "$command" ]] || return 2
    return
  fi

  load_inventory
  case "$command" in
    list)
      if [[ $# -eq 1 ]]; then
        list_human
      elif [[ $# -eq 2 && "$2" == "--json" ]]; then
        list_json
      else
        usage >&2
        return 2
      fi
      ;;
    explain)
      if [[ $# -eq 1 ]]; then
        local id
        for id in "${IDS[@]}"; do
          explain_one "$id"
          printf '\n'
        done
      elif [[ $# -eq 2 ]]; then
        explain_one "$2"
      else
        usage >&2
        return 2
      fi
      ;;
    fetch)
      [[ $# -eq 2 ]] || { usage >&2; return 2; }
      fetch_one "$2"
      ;;
    fetch-all)
      [[ $# -eq 1 ]] || { usage >&2; return 2; }
      run_all_ready fetch_one
      require_populated_inventory
      ;;
    verify)
      [[ $# -ge 2 ]] || { usage >&2; return 2; }
      local verify_error=0 verify_rc verify_id
      for verify_id in "${@:2}"; do
        if verify_one "$verify_id"; then
          continue
        else
          verify_rc=$?
          [[ $verify_error -ne 0 ]] || verify_error=$verify_rc
        fi
      done
      [[ $verify_error -eq 0 ]] || return "$verify_error"
      ;;
    verify-all)
      [[ $# -eq 1 ]] || { usage >&2; return 2; }
      run_all_ready verify_one
      require_populated_inventory
      ;;
    offline)
      [[ $# -eq 1 ]] || { usage >&2; return 2; }
      run_all_ready verify_one
      if ! require_populated_inventory; then
        printf 'offline verification is incomplete until every inventory entry is populated\n' >&2
        return 3
      fi
      ;;
    missing)
      [[ $# -eq 1 ]] || { usage >&2; return 2; }
      report_missing
      ;;
    recovery)
      [[ $# -eq 1 ]] || { usage >&2; return 2; }
      recovery
      ;;
    *)
      usage >&2
      return 2
      ;;
  esac
}

main "$@"
