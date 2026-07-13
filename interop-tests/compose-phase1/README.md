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

Scenario-specific drivers must write only their documented bounded result
contract. They must not source or evaluate guest/runtime output. The common
runner remains the only authority that assigns final sequence numbers, validates
required terminals, and finalizes the manifest.

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
