#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 DEB DESTINATION" >&2
  exit 2
fi

deb="$1"
destination="$2"
listing="$(mktemp)"
trap 'rm -f "$listing"' EXIT

dpkg-deb --fsys-tarfile "$deb" | tar -tf - >"$listing"
if [ "$(grep -cFx './usr/share/man/man1/' "$listing" || true)" -ne 1 ] \
  || ! grep -qE '^\./usr/share/man/man1/[^/]+\.1\.gz$' "$listing"; then
  echo "Debian payload does not contain one man1 directory with gzipped pages: $deb" >&2
  exit 1
fi

mkdir -p "$destination"
dpkg-deb --fsys-tarfile "$deb" | tar -xf - -C "$destination" ./usr/share/man/man1
