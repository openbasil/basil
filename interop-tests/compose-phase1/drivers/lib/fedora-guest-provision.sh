#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
# SPDX-License-Identifier: Apache-2.0

# Fedora 44 lane GUEST-side online provisioning + validation. Streamed over SSH
# stdin into the network-enabled prep VM by `fedora-44-prep.sh`; it never runs on
# the network-isolated retained lane. As the unprivileged `prep` user it:
#   1. resolves and downloads the exact package delta that Podman + the rootless
#      Compose provider (podman-compose) + jq add on top of the verified image;
#   2. installs that delta the same way the offline lane will (local RPMs, no
#      repositories) to prove the offline path works;
#   3. runs a rootless Podman container and a rootless Compose up/down online;
#   4. pulls the pinned Alpine workload image for offline `podman load`; and
#   5. assembles a single payload tarball plus a metadata record.
# It never disables SELinux or changes its mode.
#
# Provider note: Fedora's `docker-compose` package installs the full Docker/moby
# engine, which is wrong for a rootless-Podman lane; Fedora offers no
# Docker-engine-free Compose v2 binary. This lane therefore pins Fedora's native
# `podman-compose` rootless provider. See the basil-3kx DEVIATION comment.

set -euo pipefail
: "${ALPINE_DIGEST:?ALPINE_DIGEST must be set}"
: "${WORKLOAD_TAG:?WORKLOAD_TAG must be set}"

payload=/tmp/payload
rm -rf "$payload"
mkdir -p "$payload/rpms"

echo "== refreshing metadata =="
sudo dnf -y makecache >/dev/null

repomd_hash() {
  local repoid=$1 f
  f=$(sudo find /var/cache/libdnf5 /var/cache/dnf -type f \
    -path "*${repoid}*/repodata/repomd.xml" 2>/dev/null | head -1)
  if [[ -n $f ]]; then sudo sha256sum "$f" | cut -d' ' -f1; else echo unknown; fi
}
fedora_repomd=$(repomd_hash fedora)
updates_repomd=$(repomd_hash updates)

echo "== recording compose provider candidates (for the record) =="
dnf -q list --available 'podman-compose' 'docker-compose*' 'compose*' \
  >"$payload/compose-candidates.txt" 2>/dev/null || true

echo "== resolving + downloading exact delta =="
sudo dnf -y clean packages >/dev/null
sudo dnf -y install --downloadonly podman podman-compose jq
sudo find /var/cache/libdnf5 /var/cache/dnf -type f -name '*.rpm' \
  -exec cp -t "$payload/rpms/" {} +
sudo chown -R "$(id -un):$(id -gn)" "$payload"
delta_count=$(find "$payload/rpms" -name '*.rpm' | wc -l | tr -d ' ')
[[ $delta_count -gt 0 ]] || { echo "no delta RPMs downloaded" >&2; exit 3; }

echo "== installing the delta from local RPMs only (offline path rehearsal) =="
sudo dnf -y install --disablerepo='*' "$payload"/rpms/*.rpm

podman_nevra=$(rpm -q --qf '%{NAME}-%{EVR}.%{ARCH}' podman)
provider_nevra=$(rpm -q --qf '%{NAME}-%{EVR}.%{ARCH}' podman-compose)
jq_nevra=$(rpm -q --qf '%{NAME}-%{EVR}.%{ARCH}' jq)
podman_version=$(podman --version | awk '{print $3}')
provider_version=$(rpm -q --qf '%{VERSION}' podman-compose)
[[ -n $provider_version ]] || provider_version=unknown

echo "podman: $podman_nevra ; provider: $provider_nevra (podman-compose $provider_version)"

echo "== docker-compose package must NOT have dragged in the Docker engine =="
if rpm -q moby-engine >/dev/null 2>&1 || rpm -q docker-ce >/dev/null 2>&1; then
  echo "ERROR: a Docker engine is installed on a rootless-Podman lane" >&2; exit 3
fi

echo "== SELinux must still be Enforcing =="
[[ "$(getenforce)" == Enforcing ]] || { echo "SELinux not enforcing" >&2; exit 3; }

echo "== staging pinned Alpine workload image =="
podman pull "docker.io/library/alpine@sha256:${ALPINE_DIGEST}"
podman tag "docker.io/library/alpine@sha256:${ALPINE_DIGEST}" "$WORKLOAD_TAG"
podman save -o "$payload/workload-alpine.tar" "$WORKLOAD_TAG"

echo "== online rootless container smoke =="
podman run --rm "$WORKLOAD_TAG" true

echo "== online rootless Compose provider smoke =="
cat >"$payload/compose.yaml" <<YAML
version: "3"
services:
  probe:
    image: ${WORKLOAD_TAG}
    command: ["sleep", "2"]
YAML
podman-compose -f "$payload/compose.yaml" up -d
podman-compose -f "$payload/compose.yaml" down

cat >"$payload/versions.txt" <<TXT
podman=$podman_nevra
podman_compose=$provider_nevra
jq=$jq_nevra
TXT

echo "== assembling payload =="
tar --sort=name --numeric-owner --owner=0 --group=0 --mtime='2026-01-01 UTC' \
  -C "$payload" -cf /tmp/payload.tar .
payload_sha=$(sha256sum /tmp/payload.tar | cut -d' ' -f1)

jq -n \
  --arg podman "$podman_nevra" --arg provider "$provider_nevra" --arg jq "$jq_nevra" \
  --arg pv "$provider_version" --arg pdv "$podman_version" \
  --arg fr "$fedora_repomd" --arg ur "$updates_repomd" \
  --argjson n "$delta_count" --arg ps "$payload_sha" \
  '{podman:$podman,podman_compose:$provider,jq:$jq,compose_provider_version:$pv,
    podman_version:$pdv,repomd_fedora_sha256:$fr,repomd_updates_sha256:$ur,
    delta_rpm_count:$n,payload_sha256:$ps}' >/tmp/payload.meta.json

echo "PROVISION_OK payload_sha256=$payload_sha delta_rpms=$delta_count"
