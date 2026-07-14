<!--
SPDX-FileCopyrightText: 2026 OpenBasil Contributors

SPDX-License-Identifier: Apache-2.0
-->

# Compose Phase 1 retained-evidence harness

This directory contains feasibility-evidence infrastructure for Compose
integration 1.0 under Design 0001 revision 1.1. It is not a production runtime
attestor, provider, delivery implementation, or `basil-entrypoint`.

The common runner is `scripts/compose-phase1-evidence.sh`. Its lifecycle is:

```console
scripts/compose-phase1-evidence.sh prepare --lane fedora-44-x86_64 --qualification
scripts/compose-phase1-evidence.sh run --run RUN_ID
scripts/compose-phase1-evidence.sh collect --run RUN_ID
scripts/compose-phase1-evidence.sh verify-run --run RUN_ID
scripts/compose-phase1-evidence.sh destroy --run RUN_ID
scripts/compose-phase1-evidence.sh status --run RUN_ID
```

`prepare` prints the run ID. Until scenario-specific VM lane drivers are
provisioned, `run` finalizes honestly as `INCOMPLETE` or `NOT_MEASURED`; it never
converts a missing lane, artifact, event, or test into a pass.

## Status and exit contract

| Status | Exit | Meaning |
| --- | ---: | --- |
| `PASS` | 0 | Every required test terminal is present and passed. |
| `TEST_FAIL` | 10 | The lane ran and a tested product or feasibility assertion failed. |
| `INFRA_ERROR` | 20 | A required artifact, host facility, or harness operation failed. |
| `UNSUPPORTED` | 30 | The requested lane or shape is outside the declared matrix. |
| `INCOMPLETE` | 40 | Collection or cleanup was interrupted, ambiguous, or unverifiable. |
| `UNQUALIFIED_DIRTY_SOURCE` | 50 | A formal run was refused because the `jj` source snapshot was dirty. |
| `NOT_MEASURED` | 60 | The dimension has no representative runnable prototype yet. |

These are evidence statuses, not product support claims. `COMPLETE` on disk means
only that a terminal manifest was finalized; the manifest status may still be a
failure, unsupported, or not measured.

## Retention and privacy

The default evidence root is:

```text
${XDG_STATE_HOME:-$HOME/.local/state}/basil/compose-qualification/runs
```

The runner rejects repository, `target`, symbolic-link, broad system, and unsafe
qualification paths. Directories are mode `0700`; retained files are mode
`0600`. A run contains:

- `raw/`: private serial and process output needed for investigation;
- `sanitized/`: versioned allowlisted JSONL events and canonical projections;
- `meta/`: non-secret run identity, source state, and process ownership records;
- `manifest.json` and `manifest.sha256`: canonical inventory and integrity data;
- exactly one state marker: `RUNNING`, `COMPLETE`, or `INCOMPLETE`.

Raw output is private evidence. It must not be attached to public issues without
an independent review. Never retain credentials, SSH private keys, complete
environments, registry authentication, raw Compose rendering, arbitrary runtime
inspect payloads, synthetic canary values, or guest overlays. The transient SSH
key, QMP socket, overlays, and other run-owned VM state are removed after
collection by default.

## Event schema

`sanitized/events.jsonl` uses schema `basil.compose.phase1.event`, version `1`.
Every line contains:

- one `run_id` and `lane_id` shared by the run;
- a contiguous, strictly increasing `seq` starting at 1;
- a UTC `time` in `YYYY-MM-DDTHH:MM:SSZ` form;
- typed `event`, `status`, and uppercase `reason_code` fields;
- bounded non-secret `details` and optional `message`;
- `test_id` for test terminal events.

Validation requires exactly one first `run.start`, exactly one last `run.end`,
and exactly one `test.end` for every test required by the selected suite in
`phase1.lock.toml`. A `PASS` run requires every required terminal to be `PASS`
and at least one real pass. Duplicate terminals, regressing or gapped sequences,
missing events, oversized fields, all-skip results, and trailing events fail
verification.

`verify-run` checks the event contract, manifest shape, state, manifest sidecar,
and every retained file size and SHA-256. Issue-closing evidence must cite the
run ID and independently checked manifest SHA-256.

## VM and artifact boundary

The artifact interface is fixed as `scripts/compose-phase1-artifacts.sh` with the
approved `verify ARTIFACT...` command. The runner does not boot or execute guest
content until that interface exists and verifies every lane artifact named in
`phase1.lock.toml`.

Future lane drivers must retain these boundaries:

- QEMU runs unprivileged with `-nodefaults`, explicit disk formats and resources,
  immutable verified base images, and per-run qcow2 overlays;
- networking is loopback-only user networking with a private forwarded SSH port;
- QMP and SSH material stay below the run's private transient directory;
- each run gets a fresh SSH key and serial-established host-key pin;
- password login, root SSH, agent forwarding, `StrictHostKeyChecking=no`, 9p,
  repository shares, evidence-directory mounts, and host runtime sockets are
  forbidden;
- guest code is transferred only after artifact verification and is never
  downloaded-and-executed from an unverified source.

## Lane-driver contract

Scenario drivers live under `drivers/` and are selected by a lane's `driver`
field in `phase1.lock.toml`. The runner resolves a driver only through a
fail-closed allowlist: the name must match `^[a-z0-9][a-z0-9-]{0,63}$`, be listed
in the runner's allowlist, and resolve to a non-symlink executable strictly
inside `drivers/`. Names with path separators, `..`, or that escape the driver
root are refused before anything runs; there is no arbitrary-path execution.

A driver runs under a read-only Bubblewrap view. The whole filesystem is bound
read-only except a fresh `/dev`, a private `/tmp`, and one writable scratch
directory that holds the result file. The sandbox starts from a cleared
environment, joins fresh user/IPC/UTS/cgroup/network namespaces, dies with the
runner, and is bounded by a timeout.

A driver communicates results **only** by writing the bounded result contract at
`$BASIL_DRIVER_RESULT`. That file uses schema `basil.compose.phase1.driver-result`
version `1`, is capped at 64 KiB, and lists per-test `{test_id,status,reason_code}`
records (with optional bounded `message`/`details`). The runner validates the
file before trusting it: every `test_id` must be required by the selected suite,
test ids must be unique, and statuses and reason codes must be typed. Drivers
never source guest output, never write JSONL events or manifests, and never
assign sequence numbers. The runner alone emits one event per validated result,
fills any unreported required terminal as `NOT_MEASURED`, and finalizes the
manifest. A nonzero driver exit, a missing or malformed result, or an invalid
result degrades to `INFRA_ERROR` and never becomes a pass.

`drivers/lib/qemu-unpriv.sh` is a shared library (source it; do not execute it)
that assembles the boundary-conforming unprivileged QEMU argv above and re-checks
an argv against the forbidden surface (filesystem shares, bridged or tap
networking, privilege re-entry) so a driver can fail closed before boot.

`drivers/null.sh` is a development-only mock driver that boots no guest; it
exercises the contract and confirms the read-only sandbox. It is reachable only
through the `dev-null` development lane, which the runner refuses under
`--qualification` before any driver executes.

## Fedora 44 lane (SELinux enforcing, rootless Podman)

Lane `fedora-44-x86_64` (driver `fedora-selinux-rootless`, suite `fedora-smoke`)
boots the verified, cached Fedora 44 cloud image as an immutable read-only
backing file under a per-run qcow2 overlay, provisions it non-interactively via
`cloud-init/fedora-44.yaml`, and reports seven confinement tests. The driver
requests `accel=kvm:tcg`: KVM when the runner sandbox exposes `/dev/kvm`,
degrading to **TCG emulation** when it does not (the stock sandbox's `--dev /dev`
omits `/dev/kvm`; `basil-k78`). TCG evidence is functional only and carries no
timing or capacity claim.

Provisioning never touches the network. Inside the driver's own network
namespace the guest gets loopback-only user-mode networking with `restrict=on`
and a single forwarded SSH port; the host key is pinned from the serial console.
`fedora-44-prep.sh` boots the same image once *with* network to resolve and
download the exact package delta, validate it online (offline-style install plus
a rootless container and a rootless Compose up/down), and stage a single
sha256-pinned payload plus `drivers/fedora-selinux-rootless.pins`. The driver
verifies the payload against the pin, delivers it read-only on the cloud-init
seed, and `cloud-init` installs it offline from local RPMs only. Two distinct
rootless owners (`phase1-a`, `phase1-b`) get subuid/subgid ranges and
`loginctl enable-linger`; SELinux stays `Enforcing` throughout (no `setenforce`,
no permissive domain, no unconfined workaround).

Package pins (Fedora 44 release + updates, `download.fedoraproject.org`; Podman is
already in the base image, so the offline delta adds only the provider and jq):

| package | NEVRA |
| --- | --- |
| podman (base image) | `podman-5:5.8.1-1.fc44.x86_64` |
| podman-compose (Compose provider) | `podman-compose-1.6.0-1.fc44.noarch` |
| jq | `jq-1.8.1-3.fc44.x86_64` |

Signed repository metadata: fedora `repomd.xml` sha256
`da3845427d188097f6fd71b417a039bdfb8efefc4f38ca44b5cbb94f95a18991`; updates
`repomd.xml` sha256
`c5216de7d214ed6b51526f5a872e08606c2fb4d70cf8ed8aea0e715d923c069c`. Workload
image: `docker.io/library/alpine@sha256:14358309…f695dce` (pinned index digest,
loaded offline as `localhost/basil-phase1/workload:alpine`).

**Compose provider — deviation.** Design 0001 (implementation-plan Milestone 6)
prefers a Docker Compose v2 provider through `podman compose`. On Fedora 44 the
`docker-compose` package installs the full Docker/moby engine, which is
inappropriate for a rootless-Podman lane, and Fedora ships no Docker-free Compose
v2 binary. This feasibility lane therefore pins Fedora-native `podman-compose`
(no Docker) — the appropriate rootless provider, and the design's called-for
separate podman-compose feasibility lane. It proves the provider *functions*
under rootless Podman with SELinux enforcing; it makes no Compose-v2-JSON-contract
claim (`basil-3kx`).

The `fedora-smoke` suite requires seven driver-reported tests: `lane.cgroup-v2`,
`lane.lsm-enforcing`, `lane.runtime-mode`, `lane.rootless-owner-a`,
`lane.rootless-owner-b`, `lane.compose-provider`, `lane.network-isolation`.
`lane.artifacts` is intentionally excluded — the runner already verifies the
lane's artifacts fail-closed via `verify_lane_artifacts` (`basil-kxg`). Reproduce:

```console
interop-tests/compose-phase1/fedora-44-prep.sh                                   # once, with network
scripts/compose-phase1-evidence.sh prepare --lane fedora-44-x86_64 --suite fedora-smoke
scripts/compose-phase1-evidence.sh run        --run RUN_ID
scripts/compose-phase1-evidence.sh collect    --run RUN_ID
scripts/compose-phase1-evidence.sh verify-run --run RUN_ID
```

`run` requires the runner allowlist to include `fedora-selinux-rootless` (see the
`basil-3kx` NEEDS-SHARED-CHANGE note for `driver_is_allowlisted`).

## Ubuntu 24.04 lane (AppArmor enforcing, rootful Docker)

Lane `ubuntu-24.04-x86_64` (driver `ubuntu-2404`, suite `ubuntu-2404-lane-smoke`)
boots the verified, cached Ubuntu 24.04 cloud image as an immutable read-only
backing file under a per-run qcow2 overlay, provisions it non-interactively via
`cloud-init/ubuntu-24.04.yaml`, and proves AppArmor confinement **without
selecting an unconfined profile**: no `aa-complain`/`aa-disable`, no
`--security-opt apparmor=unconfined`, no profile edits at all. The lane requests
`accel=kvm:tcg` (KVM when the runner sandbox exposes `/dev/kvm`, functional-only
TCG otherwise). The `basil-ci` user is locked-password, SSH-key-only, with
passwordless sudo so the driver can install packages and start rootful `dockerd`;
password and root SSH stay disabled.

The guest never touches the network: provisioning is fully offline from inputs
staged out of band under the artifact cache at
`~/.cache/basil/compose-phase1/ubuntu-24.04-docker-lane-staging/` — `debs/`
(the pinned Docker packages below, each sha256-verified against the signed apt
metadata before staging), `workload/alpine-amd64.tar` (the pinned
`workload-alpine` index digest exported for `docker load`),
`compose/compose.yaml` (a `pull_policy: never` Compose smoke), and `toolbox/`
(an ISO builder for the NoCloud seed). All hard `Depends` of the pinned set
(iptables, nftables, libseccomp2, libsystemd0) are already in the base cloud
image, so `dpkg -i` completes offline with no Ubuntu-archive packages.

Package pins (`download.docker.com/linux/ubuntu`, suite `noble`, component
`stable`, amd64). The repo hash anchor is the clearsigned `dists/noble/InRelease`
(Docker Release (CE deb) key, fingerprint
`9DC858229FC7DD38854AE2D88D81803C0EBFCD88`); the `stable/binary-amd64/Packages`
it pins hashed `ee23b23badda70914fb90302d4abd6c55a20dd2646ac93df65aa68e16a8c74ad`
at selection time, and each `.deb` below is pinned by its `Packages` sha256:

| package | version | deb sha256 |
| --- | --- | --- |
| `docker-ce` | `5:29.6.1-1~ubuntu.24.04~noble` | `b71c54e01bf05489384b01c97621293a2803a3c38c754a655456f6c1821a6b55` |
| `docker-ce-cli` | `5:29.6.1-1~ubuntu.24.04~noble` | `bab40fb817b8b541a2eb1c33ac3285b06439de06cf05c2cd0cb47a3f87c193c4` |
| `containerd.io` | `2.2.6-1~ubuntu.24.04~noble` | `ad9d5ed46615d5adf0fab492101996a395776f0f15fdc37ff425c59d5c4dca02` |
| `docker-compose-plugin` | `5.3.1-1~ubuntu.24.04~noble` | `19d9473c2f011f94e1e54b035dcac170dab0c19671799db6f015e29eb9f23357` |
| `docker-buildx-plugin` | `0.35.0-1~ubuntu.24.04~noble` | `ddcd67d3e9a8b4cda74326ebebe4ebdc3879210d2d0093274d19f5e1bbaf24f4` |

The `ubuntu-2404-lane-smoke` suite requires the runner-owned `lane.artifacts`
plus five driver-reported tests: `lane.cgroup-v2` (cgroup2fs),
`lane.lsm-enforcing` (kernel AppArmor `Y`, profiles in enforce mode, and
`docker-default` visible in `aa-status`), `lane.runtime-mode` (rootful Docker
reporting `name=apparmor` and **no** `name=userns`/`name=rootless` security
option), `lane.container-confinement` (a running container whose
`.AppArmorProfile` is `docker-default` and whose `/proc/1/attr/current` reads
`docker-default (enforce)` — never unconfined), and `lane.compose-plugin`
(`docker compose up` runs a container that itself reports
`docker-default (enforce)`). Reproduce:

```console
scripts/compose-phase1-evidence.sh prepare --lane ubuntu-24.04-x86_64 --suite ubuntu-2404-lane-smoke
scripts/compose-phase1-evidence.sh run        --run RUN_ID
scripts/compose-phase1-evidence.sh collect    --run RUN_ID
scripts/compose-phase1-evidence.sh verify-run --run RUN_ID
```

Development lane-smoke evidence: run `20260714T070109Z-a6eb31d62fe947df`
(status `PASS`, reason `DRIVER_TESTS_PASSED`, all six terminals `PASS`, manifest
sha256 `9573c57ffb4b48c1561959c4def90e79f8f9b5943d2940e9de7cf3c08a0e9147`),
retained under `~/.local/state/basil/ph1` (`basil-y0f`).

## Artifact inventory

`scripts/compose-phase1-artifacts.lock.tsv` is the checked-in inventory and
`scripts/compose-phase1-artifacts.sh` is the only tool that reads it. Its header
comments are the authoritative field reference; the file is tab-separated,
schema version `1`. Each row has a `status` of `ready` (fully pinned and
acquirable) or `not-yet-populated` (intentionally reserved), and one of three
kinds:

- **`file-openpgp-clearsigned` / `file-openpgp-detached`** — a downloadable file
  (the Fedora and Ubuntu cloud base images). The `sha256` column pins the file;
  an OpenPGP-signed upstream checksum manifest is verified against the checked-in
  key under `keys/`, and trust flows from the pinned signer fingerprint, never
  the mirror hostname.
- **`oci-image`** — a digest-pinned multi-arch workload container image
  (`workload-fedora`, `workload-alpine`, `workload-debian`, `workload-ubuntu`,
  `workload-postgres`, `workload-distroless`). The `sha256` column holds the
  manifest-list (OCI image index) digest, which is the **sole** trust anchor; the
  `source` column holds the tag-qualified reference used only to resolve that
  digest. `fetch` runs `skopeo copy --all` **by digest** into an OCI layout
  (retaining every platform manifest so the arm64 lane can select its
  architecture), then re-verifies offline: the pinned manifest-list blob and
  every other blob must self-address, and `index.json` must reference the pinned
  digest. Neither the tag nor the registry hostname is ever trusted. Skopeo, jq,
  and find are required for these rows.
- **`package-set`** — the in-guest runtime packages (`fedora-44-runtime-packages-x86_64`
  from `basil-3kx`, `ubuntu-24.04-docker-packages-x86_64` from `basil-y0f`). The
  `sha256` column pins a per-set **member manifest** — a sidecar TSV
  `scripts/compose-phase1-artifacts.<id>.packages.tsv` beside the lock — which
  lists each member by size and sha256; that member hash is the sole operational
  trust anchor, re-verified locally exactly as an `oci-image` digest is. Each
  member is either **`url`** (downloaded from an approved immutable source into
  `<cache>/<id>/` and atomically placed only after its hash matches) or
  **`staged`** (produced out of band by a named prep script and verified in place;
  a missing staged member fails closed with its recovery command, never a blind
  download). `checksum_url`/`checksum_sha256` and `signer_fingerprint` record the
  signed repository index the member hashes were derived from — Fedora
  `repomd.xml` (Fedora key), or the Ubuntu `Packages` index that the clearsigned
  `InRelease` authenticates (Docker CE key; `key_file` `-` because that key is not
  checked in) — as provenance, never a live hostname trust. Fedora ships one
  `staged` member (the `fedora-44-prep.sh` `payload.tar`, sha256
  `43c574240b105e5b…`); Ubuntu ships five `url` members (the noble/stable/amd64
  `docker-ce`/`-cli` 29.6.1, `containerd.io` 2.2.6, `docker-compose-plugin` 5.3.1,
  `docker-buildx-plugin` 0.35.0 `.deb`s), each pinned by sha256.

Fail-closed is the whole point: no unverified bytes ever land in the cache under
a verified name. Every row is now `ready`, so once every member is cached and
verifies, `fetch-all` → `verify-all` and `offline` exit `0`. Any genuinely
missing or corrupt artifact — an un-fetched image or package, a hash mismatch, a
missing staged payload — still finalizes fail-closed with exit `3` (or `4` on a
verification failure); per-artifact `fetch`/`verify` of any single row also still
work. `verify ARTIFACT...` is the approved interface the runner uses to gate every
lane artifact; `recovery` prints exact reacquisition instructions for an empty
cache; and `self-test` exercises the inventory parser and the file, OCI, and
package-set verification paths, including digest/hash-mismatch, substituted-manifest,
and wrong-hash-download rejection, and asserts a fully-populated inventory verifies
with exit `0`.

## Cleanup identity

Cleanup never uses process-name matching. Before signaling a recorded process it
requires all of:

1. the exact numeric PID still exists;
2. `/proc/PID/stat` start time equals the recorded start time;
3. `/proc/PID/exe` equals the recorded executable;
4. the process record names a marker below this run's private transient tree;
5. the marker contains the exact per-process random token.

A mismatch refuses the signal and reports `INCOMPLETE`. Escalation rechecks the
same identity before `SIGKILL`. Transient deletion requires the exact per-run
owner marker and never removes the retained run directory or unrelated paths.

## Guest foundations

`cloud-init/fedora-44.yaml` and `cloud-init/ubuntu-24.04.yaml` create locked test
users, install no unpinned runtime payload by themselves, disable password/root
SSH, and validate cgroup v2 plus the distribution LSM without changing its mode.
They do not disable SELinux labeling or AppArmor confinement.

`guest/common.sh` emits only bounded allowlisted facts. Fedora checks SELinux
`Enforcing` and rootless Podman with SELinux integration. Ubuntu checks kernel
AppArmor enablement and rootful Docker without a reported user-namespace remap.
It never emits environments or raw runtime responses and does not claim the
host-side QEMU network or artifact tests.

## Development versus qualification

Development smoke may run from a dirty source tree, but the source state and
qualification mode are recorded. `--qualification` refuses dirty `jj` source as
`UNQUALIFIED_DIRTY_SOURCE`. Formal issue-closing evidence also requires the
real enforcing-LSM VM lane, verified immutable artifacts, all required tests,
successful cleanup, and independent `verify-run` output.

The arm64 TCG lane is functional only. Its results must never support native
performance, capacity, or timing claims.
