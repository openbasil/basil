<!-- SPDX-FileCopyrightText: 2026 OpenBasil Contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# LSM policy and unit confinement for attestor realms

Authored under `basil-uvsx` (split from `basil-zybp` part A). Source contract:
`docs/attestor-realm-contract/SPEC.md` revision 1.2, "Socket and release
authentication", and `docs/attestor-realm-contract/helper-protocol.md`.

This directory holds the prevention-policy source text. It defines two
confinement identities:

- `basil_measure_t` (SELinux) / `basil-measure-helper` (AppArmor): the single
  root-owned measurement helper per host. Its endpoint and domain are
  deliberately not generation-qualified; its two installed evidence stores
  are generation-versioned: the allowlist files under
  `/etc/basil/measure/policy.d` and the authority-manifest files under
  `/etc/basil/measure/manifest.d` (read on every measurement to derive
  lockdown-confinement expectations; `basil-6gmc`).
- `basil_attestor_g<N>_t` (SELinux) / `basil-attestor-g<N>` (AppArmor): one
  domain per installed `authorityGeneration`. The generation qualifier is a
  checked binding, so the domain and profile names embed the exact decimal
  generation (`_g<N>_` and `-g<N>`), and the loader, staged manifest, and live
  helper checks all reject a mismatch.

## Layout

| Path | Content |
| --- | --- |
| `selinux/basil_lsm_base.te` | Static base module: shared types, the `basil_attestor_domain` attribute, the full `basil_measure_t` domain, and the module's `neverallow` assertions. |
| `selinux/basil_measure.fc` | File contexts for the helper binary, both installed evidence stores (`policy.d` allowlists, `manifest.d` authority manifests), and the endpoint runtime directory. |
| `selinux/basil_attestor.te.in` | Per-generation attestor domain template. The installer renders `@GEN@` and loads one module per installed generation. |
| `selinux/basil_attestor.fc.in` | Per-generation file contexts (runtime directory subtree). |
| `apparmor/basil-measure-helper` | AppArmor profile for the helper (path-attached). |
| `apparmor/basil-attestor.in` | Per-generation named AppArmor profile template, applied through `AppArmorProfile=` in the unit. |
| `systemd/basil-measure-helper.service` | Confined system unit for the helper. |
| `systemd/basil-attestor.service.in` | Confined per-realm, per-generation attestor unit template. |

## Identity mapping

The configuration and allowlist identities map to these artifacts:

| Authority field | Artifact |
| --- | --- |
| `lsmPolicy = "basil-attestor-policy-g<N>"` | SELinux module `basil_attestor_policy_g<N>` rendered from `basil_attestor.te.in`, or the AppArmor profile file rendered from `basil-attestor.in`. |
| `lsmProfile = "selinux:basil_attestor_g<N>_t"` | The SELinux domain declared by that module. |
| `lsmProfile = "apparmor:basil-attestor-g<N>"` | The named AppArmor profile. |
| `measurement.serviceUnit` | A rendered `basil-attestor.service.in` installed under the exact generation-qualified unit name. |
| helper (static) | `basil_measure_t` / `basil-measure-helper`, entered by `basil-measure-helper.service`. |

`lockdownProfile` names the post-init seccomp profile. That is process-installed
(design `basil-kqc7`), and only its baseline precursor appears here as the
`SystemCallFilter=` lines in the units.

## Entry mechanisms

- Helper: classic exec transition. `init_t` executing
  `basil_measure_exec_t` transitions to `basil_measure_t`, so the domain is
  active at the exec boundary as the SPEC requires.
- Attestor: the rendered unit sets
  `SELinuxContext=system_u:system_r:basil_attestor_g<N>_t:s0`. An exec-based
  `type_transition` cannot select among per-generation domains for one
  executable, and it would also capture the broker if the broker and attestor
  ever ship as one binary. The template therefore declares no
  `type_transition`; the explicit unit context is the only way in.
- The attestor executable must be packaged at a dedicated path (the template
  file contexts use `/usr/libexec/basil/basil-attestor`) labeled
  `basil_attestor_exec_t`. A hard link to the broker binary is not acceptable
  because hard links share one inode and therefore one label. Ship a separate
  copy or a distinct binary.

## Placement (coordination with `basil-9tj.28`, Phase 7.1 packaging)

This directory is the policy source of truth; packaging consumes it and owns
distribution. Proposed split, to be confirmed on `basil-9tj.28`:

- Packaging installs the static pieces once per host: the compiled
  `basil_lsm_base` module, `basil_measure.fc` contexts,
  `basil-measure-helper.service`, and the AppArmor helper profile. The helper
  service is enabled at package install and never restarted by an authority
  change.
- The authority installation transaction (`basil-q5we` lineage) renders and
  additively loads the per-generation artifacts (`basil_attestor.te.in`,
  `basil_attestor.fc.in`, `basil-attestor.in`,
  `basil-attestor.service.in`) at stage time, performs `daemon-reload`, and
  never unloads or rewrites an older serving generation. Removal happens only
  after drain and retirement. The same transaction installs the
  generation-versioned files under `/etc/basil/measure/policy.d` and
  `/etc/basil/measure/manifest.d` (emission tracked as `basil-0dwl`); on
  SELinux hosts they must land with (or be `restorecon`d to) the
  `basil_measure_policy_t` / `basil_measure_manifest_t` labels declared in
  `basil_measure.fc`, or the enforcing helper cannot read them and every
  measurement fails closed.
- Build commands on the target host (Fedora lane):
  `checkmodule -M -m -o m.mod x.te && semodule_package -o m.pp -m m.mod -f x.fc && semodule -i m.pp`;
  AppArmor: `apparmor_parser -r <profile>`.
- The packaging ticket must not duplicate these files; it should reference
  `nix/lsm/` and template-render at enroll time.

## Host preconditions and known boundary limits

State these in packaging docs and verify them in the lane evidence:

- The SELinux domain denies `ptrace`, `process_vm_readv`/`writev`,
  `/proc/<pid>/mem`, and `pidfd_getfd` toward `basil_attestor_domain` for every
  confined domain by construction: no module here grants those permissions,
  and any confined domain that wants them needs its own allow rule against a
  type this module owns. The module's `neverallow` assertions are scoped to
  subjects this module itself declares (the attestor domains and the helper),
  because a domain-wide assertion cannot load into real host policy: Fedora
  targeted's boolean-gated `unconfined_t` ptrace allow and the authority
  installer's `file_type`-wide write allows both contradict it, aborting
  `semodule -i` wherever `expand-check=1` (for example Debian) and reducing
  it to unenforced text elsewhere. The rootful posture is safe because
  `attestorUid` is a dedicated system UID with no interactive same-UID
  processes. For the rootless-owner realm the socket-owner user has an
  `unconfined_t` shell, so proving the SPEC's Fedora SELinux rootless
  prevention boundary additionally requires at least one of:
  `setsebool deny_ptrace on`, or `kernel.yama.ptrace_scope >= 1` (denies
  same-UID non-ancestor tracing). This is the open proof obligation for
  conformance test 15 and blocks rootless support until the lane evidences
  it.
- `fs.suid_dumpable` must be 0 (kernel default) so the `User=` drop from root
  plus the process's own `PR_SET_DUMPABLE(0)` behave as designed.
- There is no `.socket` unit anywhere in this directory on purpose: the SPEC
  requires the admitted attestor process itself to create the listener so
  `SO_PEERCRED`/`SO_PEERPIDFD` name it, and the helper likewise binds its own
  endpoint.
- `ProtectHome=read-only` on the helper (not `yes`): the helper opens the
  peer's current executable through `/proc/<pid>/exe`, which resolves in the
  helper's mount namespace; a rootless workload executable under `/home` must
  stay readable for measurement.

## Validation status

`checkmodule -M -m` (checkpolicy 3.11) accepts `basil_lsm_base.te` and a
`@GEN@ = 1` rendering of `basil_attestor.te.in`; `apparmor_parser -Q`
(AppArmor 4.x) accepts both profiles. That validation is syntax-only: it
never checks `neverallow` assertions against a linked host policy, which is
why every assertion subject is restricted to this module's own domains (see
"Host preconditions"). Load-into-the-fedora-lane-image validation and
AVC-denial iteration belong to the `basil-zybp` runtime work and the lane;
expect additive `allow` refinements there, never relaxation of the
`neverallow` set without a SPEC change.
