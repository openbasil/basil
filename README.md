<!--
SPDX-FileCopyrightText: 2026 OpenBasil Contributors

SPDX-License-Identifier: Apache-2.0
-->

# 🌿 Basil

**Broker for Attestation, Secrets, Identity & Leases**

Basil is a small agent that gives the workloads on a host identity, secrets,
signatures, and short-lived credentials, without putting private keys in their
hands. Keys stay inside the backend (OpenBao, HashiCorp Vault, AWS KMS, GCP
KMS, or Basil's built-in encrypted keystore) and are used in place. Basil
attests every caller from the kernel, checks a default-deny policy, and
brokers the operation, not the key.

Full documentation lives at **[docs.openbasil.org](https://docs.openbasil.org)**.

## How it works

Your service connects to a local Unix socket. Basil reads the caller's uid and
gid straight from the kernel (`SO_PEERCRED`), so there is no client token to
issue, store, or steal. A policy file maps that identity to a subject and says
which operations it may perform on which keys; everything else is denied. When
approved by policy, Basil performs the operation against the backend, where the
key material stays put, and writes a structured audit record recording the decision

A service can sign a release, terminate TLS, mint a short-lived JWT, or decrypt
a backup, while the private key never appears in its memory, its environment,
or on its disk.

[![asciicast](https://asciinema.org/a/Dwz9uMVw6y1IfP6U.svg)](https://asciinema.org/a/Dwz9uMVw6y1IfP6U)

## Try it in two minutes

The repository ships a self-contained example that needs no external backend.
It uses the built-in `db-keystore` backend (encrypted SQLite file using turso).

```sh
git clone https://github.com/openbasil/basil
cd basil
examples/db-keystore/run.sh
```

The script builds the binary, seals a credential bundle, starts the broker on
a throwaway socket, and then signs, verifies, encrypts, decrypts, and mints a
JWT through it. Read the script to see there is no magic: it is the same CLI
you would use in production.

From there, the [quickstart](https://docs.openbasil.org/getting-started/quickstart/)
walks through the same loop against OpenBao, and
[make it your own](https://docs.openbasil.org/getting-started/make-it-your-own/)
covers writing your own catalog and policy.

## Install

- **Nix**: `nix run github:openbasil/basil` runs the CLI directly, or
  `nix profile install github:openbasil/basil` to keep it. A NixOS module is
  included under `nix/`.
- **From source**: `cargo build --release -p basil-bin` produces
  `target/release/basil`. The toolchain is pinned by `rust-toolchain.toml`,
  so rustup picks the right compiler automatically.
- **Signed release binaries** land with the first tagged public release, along
  with deb and Arch packages. Release artifacts carry GitHub artifact
  attestations; verify a download with
  `gh attestation verify <file> --repo openbasil/basil`.

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
whose dry-run `explain` shares one matcher with enforcement, oracle-free
errors, zeroized secret paths, and an append-only audit trail. The
[threat model](https://docs.openbasil.org/introduction/threat-model/) spells
out what Basil defends against and, just as importantly, what it does not.

To report a vulnerability, please use the private channels described in
[SECURITY.md](SECURITY.md): email security@openbasil.org or GitHub private
vulnerability reporting. Please do not open public issues for suspected
vulnerabilities.

## Status

[Feature matrix and Roadmap](https://docs.openbasil.org/reference/feature-matrix/)

Basil is pre-1.0 (currently 0.6.x) and under active development. The wire
protocol and config formats can still change between minor versions; breaking
changes are called out in the [CHANGELOG](CHANGELOG.md). It runs on Linux;
the Unix-socket-plus-`SO_PEERCRED` design is load-bearing, so other platforms
are not a near-term goal.

Not sure Basil fits? The docs include honest
[comparisons](https://docs.openbasil.org/introduction/comparisons/) with
Vault Agent, SPIRE, sops-nix/agenix, systemd credentials, and cloud secret
managers, including when you should pick those instead.

## License

Apache-2.0. The repository is [REUSE](https://reuse.software/)-compliant;
every file carries its license header.
