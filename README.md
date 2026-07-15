<!--
SPDX-FileCopyrightText: 2026 OpenBasil Contributors

SPDX-License-Identifier: Apache-2.0
-->

# 🌿 Basil

[![GitHub release](https://img.shields.io/github/v/release/openbasil/basil)](https://github.com/openbasil/basil/releases/latest)

**Broker for Attestation, Secrets, Identity & Leases**

> **Basil is a host-local secrets broker: your app never touches the key.** The kernel attests who's
> calling, a default-deny policy decides, the key is used where it lives (OpenBao/Vault, KMS, or a
> sealed local store), and every operation is audited.

Basil is a small agent that gives the workloads on a host identity, secrets,
signatures, and short-lived credentials, without putting private keys in their
hands. Keys stay inside the backend (OpenBao, HashiCorp Vault, AWS KMS, GCP
KMS, or Basil's built-in encrypted keystore) and are used in place. Basil
attests every caller from the kernel, checks a default-deny policy, and
brokers the operation, not the key.

Full documentation lives at **[docs.openbasil.org](https://docs.openbasil.org)**.

## How it works

Your service connects to a local Unix socket. Basil anchors the presenter in
kernel evidence (`SO_PEERCRED`) and resolves one disjoint workload domain:
`host-process`, `systemd-unit`, or `container`. A policy subject combines typed
process, systemd, Compose, executable, runtime, OCI, and invocation-signature
evidence through bounded recursive `all` and `any` expressions. Exactly one
subject must match before any grant or public-class read is considered; missing
or unavailable evidence never grants authority. When approved by policy, Basil
performs the operation against the backend, where the key material stays put,
and writes a structured audit record recording the decision.

A service can sign a release, terminate TLS, mint a short-lived JWT, or decrypt
a backup, while the private key never appears in its memory, its environment,
or on its disk.

[![asciicast](https://asciinema.org/a/NJFB7lDcdoU9mx4Y.svg)](https://asciinema.org/a/NJFB7lDcdoU9mx4Y)

## Try it in sixty seconds

`basil demo` is a one-command guided tour with **no external backend, no
config authoring, and nothing else to install**. It scaffolds a throwaway
broker on the built-in `db-keystore` backend (one encrypted SQLite file),
starts it, and then signs, verifies, encrypts, and mints a short-lived JWT
through it. It also runs one operation the policy denies, and shows
`basil explain` producing the receipt for the denial and the audit event that
recorded it. Every step is printed as a copy-paste command.

```sh
nix run github:openbasil/basil -- demo   # zero-install path
# or, with basil installed:
basil demo
```

The demo ends with "try it yourself" commands against its still-scaffolded
workdir. From there, the
[quickstart](https://docs.openbasil.org/getting-started/quickstart/) walks the
same loop against OpenBao, `basil init` scaffolds a starter set for your own
broker, and
[make it your own](https://docs.openbasil.org/getting-started/make-it-your-own/)
covers writing your own catalog and policy.

## Install

| Method        | Command                                                                                                    |
| ------------- | ---------------------------------------------------------------------------------------------------------- |
| Nix           | `nix run github:openbasil/basil` (or `nix profile install github:openbasil/basil`)                         |
| Homebrew      | `brew install openbasil/tap/basil`                                                                         |
| Debian/Ubuntu | `.deb` from the [latest release](https://github.com/openbasil/basil/releases/latest)                       |
| Arch          | `.pkg.tar.zst` from the [latest release](https://github.com/openbasil/basil/releases/latest) (`basil-bin`) |
| Cargo         | `cargo install basil-bin`                                                                                  |
| From source   | `cargo build --release -p basil-bin` (toolchain pinned by `rust-toolchain.toml`)                           |

Release artifacts are built in CI and carry GitHub artifact attestations;
verify a download with `gh attestation verify <file> --repo openbasil/basil`.
The deb, Arch, and Nix packages ship man pages and bash/zsh/fish completions
(`basil completions <shell>` generates them anywhere else). A NixOS module is
included under `nix/`, and `nix build .#basil-oci-thin` builds a
`docker load`-ready container image.

See [installation](https://docs.openbasil.org/getting-started/installation/)
for details and backend prerequisites.

## Clients

- **CLI**: the `basil` binary is both the daemon and the client; every broker
  operation is available as a subcommand.
- **Rust**: the [`basil` crate](https://docs.openbasil.org/clients/rust/)
  (`crates/basil-client` in this repo).
- **Go**: `go get github.com/openbasil/basil-go/basil`, documented at
  [clients/go](https://docs.openbasil.org/clients/go/).
- Anything that speaks gRPC over a Unix socket can talk to Basil directly;
  the proto files are in `proto/`.

## Security

Basil is security infrastructure, and it is built like it: kernel-anchored
peer identity with no injectable token seam, a default-deny policy engine
whose three-state evidence evaluator fails closed and whose dry-run `explain`
shares one matcher with enforcement, oracle-free
errors, zeroized secret paths, and an append-only audit trail. The
[threat model](https://docs.openbasil.org/introduction/threat-model/) spells
out what Basil defends against and, just as importantly, what it does not.
Startup and reload logs also trace each configuration source by slot, resolved
path, modification time, byte size, and SHA-256 hash. Rejected reloads keep and
identify the active generation.

To report a vulnerability, please use the private channels described in
[SECURITY.md](SECURITY.md): email security@openbasil.org or GitHub private
vulnerability reporting. Please do not open public issues for suspected
vulnerabilities.

## Status

[Feature matrix and Roadmap](https://docs.openbasil.org/reference/feature-matrix/)

Basil is pre-1.0 (currently 0.7.x) and under active development.
All changes are documented in [CHANGELOG.md](CHANGELOG.md).

Basil is committed to following Rust SEMVER conventions: any breaking api change or wire
protocol change will incur at least a minor version update, e.g. 0.7.x -> 0.8.0;
patch updates and `cargo update` should always be a safe non-breaking update.
Enable github release notifications to be notified of updates and security patches.

Primary production target platforms: Linux x86_64 (intel/amd), aarch64.
MacOS (aarch64-darwin) is supported for development.
Installers for several platforms are on [Releases](https://github.com/openbasil/basil/releases)

---

Not sure Basil fits? The docs include honest
[comparisons](https://docs.openbasil.org/introduction/comparisons/) with
Vault Agent, SPIRE, sops-nix/agenix, systemd credentials, and cloud secret
managers, including when you should pick those instead.

## License

Apache-2.0. The repository is [REUSE](https://reuse.software/)-compliant.
