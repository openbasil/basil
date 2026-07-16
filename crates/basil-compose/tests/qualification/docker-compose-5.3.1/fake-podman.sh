#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [[ ${1-} != compose ]]; then
  printf 'expected compose subcommand\n' >&2
  exit 64
fi
shift
: "${PODMAN_COMPOSE_PROVIDER:?provider must be pinned}"
if [[ $PODMAN_COMPOSE_PROVIDER != /* ]]; then
  printf 'provider must be absolute\n' >&2
  exit 64
fi
exec "$PODMAN_COMPOSE_PROVIDER" "$@"
