#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# Pin every third-party GitHub Action referenced by our workflows to a full
# commit SHA (supply-chain hardening -- a moving tag like `@v4` can be
# repointed at malicious code; a SHA cannot). Each `uses:` is rewritten to
#
#     uses: owner/repo@<40-hex-sha> # v4
#
# keeping the human-readable tag as a trailing comment so the pin stays legible
# and tools like Dependabot/Renovate can still bump it.
#
# Idempotent: lines already pinned to a 40-hex SHA are left untouched (their
# trailing `# tag` comment, if any, is preserved). Local (`./…`) and Docker
# (`docker://…`) action refs are skipped.
#
# Requires the GitHub CLI authenticated (or GH_TOKEN set) to resolve refs:
#   gh auth login        # or: export GH_TOKEN=<token>
#   scripts/pin-github-actions.sh [file ...]
#
# With no arguments it pins every top-level workflow in .github/workflows/.
# `just gen-release-workflow` calls this after regenerating release.yml so the
# dist-emitted (unpinned) actions get pinned on every regeneration.
set -euo pipefail

if ! command -v gh >/dev/null 2>&1; then
  echo "error: gh (GitHub CLI) is required to resolve action SHAs" >&2
  exit 1
fi
if ! gh auth status >/dev/null 2>&1 && [ -z "${GH_TOKEN:-}" ]; then
  echo "error: gh is not authenticated; run 'gh auth login' or set GH_TOKEN" >&2
  exit 1
fi

# Default target set: the runnable workflows (NOT partials/, which GitHub never
# executes and which are re-appended and pinned via the assembled release.yml).
if [ "$#" -gt 0 ]; then
  files=("$@")
else
  files=()
  for f in .github/workflows/*.yml .github/workflows/*.yaml; do
    [ -e "$f" ] && files+=("$f")
  done
fi

# Cache: "owner/repo@ref" -> sha, so each ref is resolved over the network once.
declare -A resolved

is_sha() { [[ "$1" =~ ^[0-9a-f]{40}$ ]]; }

resolve() {
  # $1 = owner/repo/maybe/subpath, $2 = ref -> prints the commit SHA
  local path="$1" ref="$2" owner repo key sha
  owner="${path%%/*}"
  repo="${path#*/}"
  repo="${repo%%/*}" # drop any /subpath after owner/repo
  key="${owner}/${repo}@${ref}"
  if [ -n "${resolved[$key]:-}" ]; then
    printf '%s' "${resolved[$key]}"
    return 0
  fi
  # `commits/{ref}` resolves a tag OR branch to the underlying commit SHA
  # (annotated tags are dereferenced to their commit), which is what pins want.
  if ! sha="$(gh api "repos/${owner}/${repo}/commits/${ref}" --jq '.sha' 2>/dev/null)"; then
    echo "error: could not resolve ${owner}/${repo}@${ref}" >&2
    return 1
  fi
  if ! is_sha "$sha"; then
    echo "error: unexpected SHA for ${owner}/${repo}@${ref}: '${sha}'" >&2
    return 1
  fi
  resolved[$key]="$sha"
  printf '%s' "$sha"
}

# Matches:  <indent>[- ]uses: <action>@<ref>[ # comment]
uses_re='^([[:space:]]*(-[[:space:]]+)?uses:[[:space:]]+)([^@[:space:]]+)@([^[:space:]#]+)([[:space:]]*#.*)?$'

for file in "${files[@]}"; do
  [ -f "$file" ] || { echo "skip (not a file): $file" >&2; continue; }
  tmp="$(mktemp)"
  changed=0
  while IFS= read -r line || [ -n "$line" ]; do
    if [[ "$line" =~ $uses_re ]]; then
      prefix="${BASH_REMATCH[1]}"
      action="${BASH_REMATCH[3]}"
      ref="${BASH_REMATCH[4]}"
      # Skip local and docker action references.
      if [[ "$action" == ./* || "$action" == docker://* ]]; then
        printf '%s\n' "$line" >>"$tmp"; continue
      fi
      # Already a SHA: leave as-is (keep whatever comment is there).
      if is_sha "$ref"; then
        printf '%s\n' "$line" >>"$tmp"; continue
      fi
      sha="$(resolve "$action" "$ref")"
      printf '%s%s@%s # %s\n' "$prefix" "$action" "$sha" "$ref" >>"$tmp"
      changed=1
    else
      printf '%s\n' "$line" >>"$tmp"
    fi
  done <"$file"
  if [ "$changed" -eq 1 ]; then
    mv "$tmp" "$file"
    echo "pinned actions in $file"
  else
    rm -f "$tmp"
    echo "no unpinned actions in $file"
  fi
done
