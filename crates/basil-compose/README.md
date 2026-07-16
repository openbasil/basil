<!--
SPDX-FileCopyrightText: 2026 OpenBasil Contributors

SPDX-License-Identifier: Apache-2.0
-->

# basil-compose

`basil-compose` invokes a selected Compose frontend's `config` operation and
projects Docker Compose v2 normalized JSON into the small model Basil needs.
The projection retains the project name and bounded service identity, image,
platform, profile, and build-provenance fields. It discards environment values,
inline config and secret contents, labels, commands, and all other fields.

The caller supplies the exact files, profiles, environment files, project name,
and project directory used for workload launch. Docker runs directly. Rootless
Podman requires an absolute external provider path, passed through
`PODMAN_COMPOSE_PROVIDER`, so provider selection cannot depend on `PATH` order.
Both paths request normalized JSON and `--no-env-resolution`.

Frontend output is untrusted and bounded before parsing. Raw stdout and stderr
remain in best-effort-scrubbed memory and are never included in errors. This
crate does not parse source Compose files, pull or build images, or persist raw
frontend output.
