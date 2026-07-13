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

validate_ready_row() {
  local line_no=$1 id=$2 kind=$3 platform=$4 filename=$5 size_bytes=$6 sha256=$7
  local source_url=$8 checksum_url=$9 checksum_size=${10} checksum_sha=${11}
  local signature_url=${12} signature_size=${13} signature_sha=${14} key_file=${15} fingerprint=${16}

  case "$kind" in
    file-openpgp-clearsigned | file-openpgp-detached) ;;
    *) fail_inventory "line $line_no: ready entry '$id' has unsupported kind '$kind'" ;;
  esac
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

verify_one() {
  local id=$1
  require_id "$id" || return $?
  if [[ "${STATUS[$id]}" != "ready" ]]; then
    printf 'blocked: %s is %s: %s\n' "$id" "${STATUS[$id]}" "${NOTE[$id]}" >&2
    return 3
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

fetch_one() {
  local id=$1
  require_id "$id" || return $?
  if [[ "${STATUS[$id]}" != "ready" ]]; then
    printf 'blocked: %s is %s: %s\n' "$id" "${STATUS[$id]}" "${NOTE[$id]}" >&2
    return 3
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

  local directory artifact_final manifest_final signature_final
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
  ) || return $?

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
