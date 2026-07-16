#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

fail() {
  printf 'unable to locate populated clients/go checkout: %s\n' "$1" >&2
  printf 'set BASIL_GO_CLIENT_DIR to an absolute populated checkout\n' >&2
  exit 1
}

candidate=${BASIL_GO_CLIENT_DIR:-}
if [[ -z $candidate && -f clients/go/go.mod ]]; then
  candidate=$PWD/clients/go
fi

if [[ -z $candidate && -f .beads/redirect ]]; then
  redirect=
  IFS= read -r redirect < .beads/redirect || true
  if [[ $redirect == /*/.beads ]]; then
    candidate=${redirect%/.beads}/clients/go
  fi
fi

[[ -n $candidate ]] || fail 'no local module or workspace redirect'
[[ $candidate == /* ]] || fail 'BASIL_GO_CLIENT_DIR must be absolute'
[[ -f $candidate/go.mod ]] || fail "$candidate/go.mod is missing"
[[ -x $candidate/scripts/interop-agent.sh ]] || fail "$candidate/scripts/interop-agent.sh is missing or not executable"

(
  cd -- "$candidate"
  pwd -P
)
