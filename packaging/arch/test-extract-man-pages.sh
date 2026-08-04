#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT
repo="$(cd "$(dirname "$0")/../.." && pwd)"
mkdir -p "$root/pkg/DEBIAN" "$root/pkg/usr/share/man/man1" "$root/src"
printf 'Package: basil\nVersion: 1\nArchitecture: all\nMaintainer: test <test@example.invalid>\nDescription: test\n' >"$root/pkg/DEBIAN/control"
for page in basil basil-nats-bridge basil-https-courier basil-agent; do
  printf '.TH %s 1\n' "$page" | gzip -n >"$root/pkg/usr/share/man/man1/${page}.1.gz"
done
dpkg-deb --root-owner-group --build -Zxz "$root/pkg" "$root/basil.deb" >/dev/null
cp "$(dirname "$0")/extract-man-pages.sh" "$root/src/extract-man-pages.sh"
for binary in basil basil-nats-bridge basil-https-courier; do
  cat >"$root/src/$binary" <<'EOF'
#!/usr/bin/env bash
printf 'completion\n'
EOF
  chmod +x "$root/src/$binary"
done
cp "$root/basil.deb" "$root/src/basil-0.8.0-pre.1-amd64.deb"

# shellcheck disable=SC1091
source "$repo/packaging/arch/PKGBUILD"
# shellcheck disable=SC2034
srcdir="$root/src"
# shellcheck disable=SC2034
pkgdir="$root/out"
# shellcheck disable=SC2034
CARCH=x86_64
# shellcheck disable=SC2034
pkgver=0.8.0-pre.1
package

for binary in basil basil-nats-bridge basil-https-courier; do
  test -x "$pkgdir/usr/bin/$binary"
done
for page in basil basil-nats-bridge basil-https-courier basil-agent; do
  test -f "$pkgdir/usr/share/man/man1/${page}.1.gz"
done
