<!--
SPDX-FileCopyrightText: 2026 OpenBasil Contributors

SPDX-License-Identifier: Apache-2.0
-->

# Security Policy

Basil is a security infrastructure component, and we take security seriously.
We want to know about any vulnerabilities and pledge that we will investigate
all credible reported security issues.

## Please report privately

**Do not open a public issue, discussion, or pull request for a suspected
vulnerability, and do not create a public repo with a reproducible test case.**
Public disclosure before a fix is available puts every user at risk.

Report privately through either channel:

1. **Email: (preferred)** security@openbasil.org

2. **GitHub private vulnerability reporting**
   Go to the repository's **Security** tab → **Report a vulnerability**. This
   opens a private advisory only you and the maintainers can see.

You can help by making the report clear, and, ideally, including a reproducible
test case demonstrating the vulnerability. If it looks like it's AI generated,
or is too long, verbose, or unclear, we may not take it seriously. If we can't
reproduce it, it will take longer to investigate, and that's not in either of our
interests.

Please include:

- the Basil version or commit (`basil --version`)
  - did you use a signed binary or custom build.
  - feature flags enabled
- the backend in use (OpenBao, HashiCorp Vault, `db-keystore`, AWS KMS, GCP KMS, 1Password),
  - and backend version
- OS platform and version
- a description of the issue and its impact,
- reproduction steps or a proof of concept,
- any suggested remediation.
- your contact information

**Redact real secrets, keys, or tokens** from anything you attach.

## What to expect

There is **no bug bounty** and no formal SLA. That said:

- We are grateful for feedback and getting a heads-up for security bugs.
- We aim to acknowledge a credible report within **2 business days**.
- We will keep you updated as we investigate and fix.
- We practice coordinated disclosure: we will agree on a disclosure timeline
  with you and, unless you prefer otherwise, credit you in the release notes and
  advisory.

## Scope

In scope: anything that undermines Basil's security guarantees, for example:

- bypassing kernel `SO_PEERCRED` caller attestation, or resolving a caller to
  the wrong policy subject;
- policy-engine flaws that grant an operation the default-deny policy should
  refuse (privilege escalation, wildcard/`breakGlass` bypass, `writable` cap
  bypass);
- private key material leaking across the socket, into logs, or onto disk when
  an in-place backend is configured;
- nonce reuse or other AEAD/crypto-envelope weaknesses;
- sealed-bundle unlock weaknesses (age/YubiKey, BIP39 break-glass, passphrase,
  TPM sealing);
- memory-safety issues (note: the codebase is `#![forbid(unsafe_code)]` with a
  strict no-panic rule in the runtime path).

Out of scope: issues in your own catalog/policy configuration, in the backend
(OpenBao/Vault) itself, or in the host OS. When in doubt, report it and let us
triage.

## Understanding the trust model first

Before reporting, it helps to know what Basil does and does **not** defend
against. Basil is a single **host-local** broker: it trusts the kernel's
`SO_PEERCRED` attestation and the integrity of the host it runs on. It is not a
sandbox and does not defend a workload against a root-level host compromise.
See the **Threat model** page in the Basil documentation (Introduction → Threat
model, at `https://docs.openbasil.org/introduction/threat-model/`) for the full
set of trust boundaries, assumptions, and out-of-scope threats.
