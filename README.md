# 🌿 Basil

**Broker for Attestation, Secrets, Identity & Leases**

A small agent providing workload identity, secrets management, signatures,
and short-lived credentials.

Key generation, storage, and signing/encryption are provided by a configurable backend.
With the default in-place backend model, your app and Basil don't need to touch
secret bytes.

The default backend model is Vault-compatible transit: keys stay inside
OpenBao/HashiCorp Vault and Basil brokers operations in place. Optional
key-store backends are also available for environments where an embedded
encrypted database or an existing personal/team secret provider is the better
deployment fit; those backends are explicit materialize-to-use custody choices
and are compiled only when their feature flags are enabled.

Capabilities:

- **Mint identities**: short-lived and backend-brokered; with in-place backends,
  the issuer key never leaves the backend
  - SPIFFE X.509-SVID leaf and SPIFFE JWT-SVID (signed RS256, ES256, or ES384)
  - NATS identities: user, account, operator, signer, server, curve
  - Generic EdDSA JWT
  - DNS/IP-SAN TLS leaf certificates from the backend PKI (the issuing CA stays in place)
  - Validate and revoke JWT-SVIDs (persistent deny-list + `REVOKED` watch events)
- **Sign / verify**: Ed25519/EdDSA over the raw message (never pre-hashed); RSA-2048/RS256, ECDSA P-256/ES256, ECDSA P-384/ES384, and backend-native ECDSA P-521/ES512 for generic signing. JWT-SVID issuance uses only algorithms the Rust validation stack can verify: RS256, ES256, and ES384.
  - Post-quantum ML-DSA-44/65/87 (FIPS 204) sign/verify over software-custodied keys. `Sign`/`Verify`/`GenerateKey` route an ML-DSA catalog key (`keyType: ml-dsa-*` + provider labels) through the local-software provider; the client contract is unchanged; `GenerateKey` provisions the sealed custody record and never returns the private; using the provider requires the explicit `op:use_software_custody` policy grant, and provider+algorithm are audited. Broker-side ML-KEM `wrap`/`unwrap` envelope dispatch is now wired the same way (see Encrypt / decrypt)
  - Backend-native migration path: a live, fail-closed backend capability probe (`Backend::supports_native_algorithm`) drives `backend-preferred`/`backend-required` routing, so when a backend gains native ML-DSA transit, new keys transparently use it while existing software-custodied keys keep working (migration is an explicit re-key, never a silent re-route). `BackendManager::describe_provider` surfaces the active provider/custody/version and whether a migration is available. See the [operations runbook](docs/runbooks/operations.html#ops-pqc-migrate)
  - Client/RPC provisioning: a `basil` client (or `basil new-key --key-type ml-dsa-65|ml-kem-768|…`) provisions a software-custodied PQC key through the standard `NewKey` RPC. The client names only the key id and type; custody and storage are operator-controlled by the catalog entry's `crypto_provider`/`pqc_custody`/`pqc_storage_key` labels. The broker generates the seed, seals it, writes the custody record, and returns only the public half (ML-KEM returns its encapsulation key). Gated by `op:new_key` + `op:use_software_custody`; no private material is ever returned. `get_public_key` returns the real ML-DSA verifying key, and, for an ML-KEM sealing key, its public encapsulation key (both read straight from the custody record; the private seed / decapsulation key is never materialized)
  - Verified end to end through the published `basil` client: deterministic known-answer vectors for ML-DSA-44/65/87, encap/decap + tamper vectors for ML-KEM-512/768/1024, and a cross-engine live e2e (`crates/basil-tests/tests/pqc_e2e.rs`) that **provisions every PQC key through the client `NewKey` RPC** (no out-of-band seeding) and then drives ML-DSA Sign/Verify, ML-KEM Wrap/Unwrap, and a client streaming ML-KEM CEK-wrap recovered by the live broker's `UnwrapEnvelope` (`basil::stream` ⇄ `BrokerCekRecovery`) over the unix socket on dev OpenBao **and** Vault, with unsupported algorithm/provider combinations returning canonical opaque errors. **Current limitation:** software custody is the only PQC custody; no shipping backend has native ML-DSA/ML-KEM transit
- **Encrypt / decrypt**: Basil owns the nonce, so callers can't reuse one by accident
  - AES-256-GCM (AEAD)
  - ChaCha20-Poly1305 (AEAD)
  - X25519 sealed-box `wrap`/`unwrap` envelope (KEM): X25519 ECDH (ephemeral) → HKDF-SHA256 (`info = label‖eph_pub‖recip_pub`) → ChaCha20-Poly1305, confidentiality only (anonymous; *not* sender authentication)
  - ML-KEM `wrap`/`unwrap` envelope for software-custodied sealing keys (`ml-kem-512`, `ml-kem-768`, `ml-kem-1024`): both route through the local-software provider, gated by `op:use_software_custody` (plus `op:encrypt` for `wrap` / `op:decrypt` for `unwrap`). `wrap` self-seals: it derives the encapsulation key from the custodied seed and encapsulates to it, so no published public half is needed; the self-describing `KemEnvelope` lets `unwrap` route the parameter set, AEAD algorithm, and key version. ML-KEM sealing keys are now provisioned through the client `NewKey` RPC (the broker generates and seals the seed, returning the encapsulation public key), and `get_public_key` reads that encapsulation key back from the custody record without materializing the decapsulation seed; BYOK import remains out of scope
  - The local-software provider implements ML-KEM encapsulate/decapsulate and envelope wrap/unwrap (HKDF-SHA256 + AES-256-GCM or ChaCha20-Poly1305, Basil-owned nonce) over software-custodied seeds; both ML-DSA signing and ML-KEM wrap/unwrap are wired through the broker services
  - Client-side **streaming / large-file encryption** (`basil::stream`, client-only): `AsyncRead`→`AsyncWrite` chunked AEAD that never buffers the whole payload, with the caller choosing `AES256GCM`, `ChaCha20Poly1305`, or `ML-KEM-512/768/1024`. The library owns every per-chunk nonce and binds version/suite/stream-id/index/final-marker/length into each chunk's AAD, so records are non-reorderable, non-truncatable, non-replayable, and non-downgradable, and fail closed. The container format is specified for cross-language interop in `docs/specs/streaming-encryption-format.md`; ML-KEM streams wrap the content key once and recover it through the broker's `UnwrapEnvelope` (the decapsulation seed stays custodied), proven end to end against a live broker on dev OpenBao **and** Vault (`pqc_e2e.rs`, basil-jcnr)
- **Generate keys & secrets**: fresh material minted in-broker
  - Crypto keys: Ed25519, Ed25519-NKey, RSA-2048, ECDSA P-256, AES-256-GCM, ChaCha20-Poly1305
  - Secrets / values: random ascii-printable, hex, base64; age (X25519) identity; self-signed TLS cert (dev/test)
- **Rotate** keys (with a grace window so in-flight ciphertexts still decrypt) and **import** keys (BYOK)
- **Unlock** the sealed credential bundle via age/YubiKey, a BIP39 break-glass phrase, or a production passphrase file
- **Sealed invocations**: opt-in `InvocationService` envelopes for bridged transports: requests
  are signed by `signature-key` subjects and encrypted to the broker request key; `Sign` responses
  are signed by the configured broker identity, encrypted to the requester-selected response key, and
  verified/decrypted by the Rust client helpers. Go helper parity is deferred.
- **NATS bridge courier**: the separate Rust `basil-nats-bridge` binary subscribes to a configured
  NATS request subject, accepts raw tagged COSE request bytes, wraps them in
  `SealedRequest { message }` for `InvocationService.Invoke` over the Basil Unix
  socket, and replies with raw tagged COSE bytes from `SealedResponse.message`.
  When Basil returns `SealedResponse.response_subject`, the bridge publishes
  there after validating it as a NATS subject; otherwise it uses the original
  reply inbox. The bridge is only a courier/presenter authorized by `op:invoke`
  on `broker.invocation`; actor authorization remains inside the sealed
  envelope and operation policy path. Bridge-level failures with no sealed Basil
  response use `Basil-Bridge-*` NATS headers.

Key types Basil understands but does **not** generate in-broker are provisioned out of band:
X25519 and ML-KEM sealing keys, plus value-store (`engine=kv2`) Ed25519 signing keys.

**Materialize-to-use custody** (opt-in, design §17.7): for the algorithms a backend can't run in
place (X25519/ML-KEM unseal and Ed25519 signing on a plain value store, `engine: kv2`), Basil
materializes the private in-process for exactly one operation, then zeroizes it. The public half is
provisioned out of band so public operations never touch the private.

## The problem

You don't want secrets on disk. Each one has a risk of being read, leaked,
or backed up by accident, and you can't log who accessed it or when.

Basil removes the risks associated with secrets on disk. With an in-place backend,
your app and Basil don't need to touch secret bytes at all.

By default, private keys live inside a Vault-compatible backend
([OpenBao](https://openbao.org) or HashiCorp Vault) and stay there. When a
service needs to sign or decrypt something, Basil asks that backend to do it:
the key is used *in place* and never leaves. When a service needs to prove who it
is, Basil mints a credential that expires in minutes, not months. And before
Basil does anything at all, it confirms the identity of the connecting process,
guaranteed by the kernel.

The result: fewer secrets that can be stolen, short-lived ones where you can't
avoid them, and a clear, auditable answer to *"who's asking for what, and are they
allowed?"*

---

## Backend choices

Basil's strongest custody story is the default one: OpenBao or HashiCorp Vault
transit/PKI performs private-key operations in place. For smaller or more local
deployments, Basil can also be built with optional key-store backends:

- **`db-keystore`** (`basil-bin` feature `db-keystore`) stores keys in an
  embedded encrypted SQLite-compatible database powered by turso. The database
  encryption key is sealed in Basil's credential bundle as `DbKeystoreDek`.
- **`onepassword`** (`basil-bin` feature `onepassword`) lets Basil store and
  fetch keys through a 1Password vault via the `op` CLI. 1Password items are
  string-valued, so this backend is string-only: storing non-UTF-8 key material
  fails closed.

Both use catalog backend kind `keystore` and live behind
`basil-keystore-backend`. Because these are key stores rather than transit
engines, Basil materializes key bytes in-process for one operation, then
zeroizes them. That code path is feature-gated with the backend itself, so
Vault/KMS-style builds do not compile the key-store materialize-to-use crypto.

For cloud custody, Basil also has **in-place transit** backends where the key
never leaves the provider, the same custody story as Vault transit:

- **`aws-kms`** (`basil-bin` feature `aws-kms`) brokers `sign`/`verify`/`encrypt`/
  `decrypt` against AWS KMS. Authentication is the ambient AWS credential chain
  (env / profile / IAM role / IMDS); the sealed cred carries only non-secret
  region/profile addressing.
- **`gcp-kms`** (`basil-bin` feature `gcp-kms`) does the same against GCP Cloud
  KMS over gRPC, authenticating with Application Default Credentials.

These use catalog backend kinds `aws-kms`/`gcp-kms` (transit engine), implement
Basil's `Backend` trait directly next to the Vault transit backend, and are
addressed by pre-provisioned key names; the KMS never exports private key
material. The first cut covers Ed25519 signing and symmetric AES-256-GCM
encrypt/decrypt; key provisioning and ECDSA (ES256) are follow-ups.

---

## What's in the name

Basil does four things, and they spell its name:

- **Attestation.** Basil knows who's calling. Requests arrive over a local
  socket, and Basil reads the caller's identity straight from the operating
  system kernel (`SO_PEERCRED`: the process's user, group, and PID). There's no
  shared password and no bearer token to steal; the OS itself vouches for who's
  on the line.
- **Secrets.** Sign, verify, encrypt, decrypt, fetch, store, rotate. With the
  default Vault-compatible backend, keys stay in the vault and are used *in
  place*; Basil brokers the **operation**, not the key. Optional key-store
  backends make a different, explicit custody tradeoff.
- **Identity.** Basil issues workload identity using the open
  [SPIFFE](https://spiffe.io) standard (X.509 and JWT *SVIDs*), so services can
  prove who they are to each other without credentials baked into images or
  config.
- **Leases.** When a raw secret won't do, Basil mints **short-lived,
  narrowly-scoped** credentials (NATS JWTs, SPIFFE tokens) that expire on their
  own. Authority you hold for exactly as long as you need it, and no longer.

---

## How it works

Basil runs as a small service connecting to a backend vault or key store.

```
┌────────────┐    local socket    ┌─────────────────────────────┐      ┌───────────┐
│  workload  │ ─────────────────▶ │            Basil            │ ───▶ │  Vault    │
└────────────┘    (gRPC)          │                             │      │  API      │
                                  │  1. attest the caller       │      │           │
                                  │       (kernel SO_PEERCRED)  │      │ keys live │
                                  │  2. check policy            │      │  here -   │
                                  │       (default-deny)        │      │ and stay  │
                                  │  3. broker the operation    │      │   here    │
                                  └──────────────┬──────────────┘      └───────────┘
                                                 │
                                                 └──▶ audit log
```

It listens on one local socket and exposes two APIs:

- a **Workload API** that issues identity documents (SPIFFE SVIDs), and
- a **broker API** for secrets and crypto: `sign` / `verify` / `encrypt` /
  `decrypt` / `get` / `set` / `rotate` / `list` / `mint`.

Workload API X.509-SVID streams reissue leaf material on the configured
`svid-ttl-secs` cadence, so standard SPIFFE clients such as `rust-spiffe` can
observe rotation without Basil-specific TLS adapters.

Every call passes through the same two gates:

1. **Who are you?** Basil attests the caller from the kernel. The caller id can't
   be impersonated. For this to work, each workload runs with a unique uid/gid
   that resolves to exactly one configured policy subject.
2. **Are you allowed?** Basil checks a declarative, default-deny policy that maps
   that subject to the exact operations it may run on the exact keys it may touch.

Only then does Basil talk to the backend on the caller's behalf, and every
decision is written to an audit log.


---

## Layered Security

- **Secure by default.** Nothing is permitted until policy grants it. Key
  material stays in the vault and is used in place for the default
  Vault-compatible backend. Optional key-store backends are explicit
  materialize-to-use deployments: Basil handles the key bytes only for the
  requested operation and zeroizes them afterward. The crypto API removes
  footguns by construction: Basil generates encryption nonces, so the caller
  can't accidentally reuse them.

- **Least privilege.** Every grant is the narrowest that works. Reading and
  writing are separate permissions; rotating or overwriting a key is never
  implied by being able to read it. Wherever possible, Basil hands out a
  short-lived lease instead of a standing secret.

- **Policy validation.** Configuration and policy are checked twice: at build
  time (when rules are converted to JSON configuration) and again at runtime, so
  a malformed or unsatisfiable policy fails closed before the broker serves.

- **Fully declarative, NixOS-native.** On NixOS, the catalog and policy are
  declarative, versioned, and immutable.

- **Auditable.** Every operation is written to an audit log with its decision.

- **Rust** - memory-safe with strict **no-panic** rule. No `unsafe` code, no `unwrap`.

- **Extensive Testing**  (WIP)

- **Build with Nix** - `flake.lock` provides byte-for-byte reproducible builds.

---

## How does it compare to ...

Basil doesn't replace your secret backend or your identity infrastructure. It
sits in front of them on a single host and changes *who holds what*. A few
points of comparison:

### Talking to Vault / a KMS directly

An app can call Vault or a cloud KMS itself. But then the app needs a credential
to authenticate to that backend: a bootstrapping secret you have to deliver,
rotate, and protect, and the backend authorizes by *that token*, not by who the
process actually is. Basil fronts the backend instead: it identifies the caller
from the kernel (no token to distribute or steal), enforces a local default-deny
policy, and brokers the operation, so the workload needs **no backend credential
at all**. It also closes crypto footguns by construction (Basil owns AEAD
nonces). The trade-off is an extra local hop: Basil augments the backend, it
doesn't remove it.

### SPIFFE / SPIRE

[SPIRE](https://github.com/spiffe/spire) is the reference SPIFFE
implementation: a server plus per-node agents, a rich set of node/workload
attestors, and full federation. Basil also serves the **standard SPIFFE Workload
API** and issues X.509/JWT SVIDs, and it's verified against the upstream
`rust-spiffe` client, but it's a single local broker (no server/agent split),
attests with `SO_PEERCRED` (uid/gid), and keeps issuer/CA keys in a
Vault-compatible backend, used in place. It also brokers general secrets and
crypto (sign / encrypt / mint NATS) that SPIRE doesn't. Use SPIRE for
fleet-wide SPIFFE infrastructure with cloud/k8s attestation and federation;
Use Basil when you want one host-local broker that *also* speaks SPIFFE.
They interoperate rather than compete.

### systemd credentials

systemd's `LoadCredential=` / `ImportCredential=` (and `systemd-creds`, optionally
TPM-sealed) deliver secrets to a unit at start. That's a solid fit for *static,
boot-time* material, but it hands the process a **value**: once loaded it lives
in the app's memory, it doesn't expire, and there's no per-operation
authorization or audit. Basil brokers the *operation* (the key is used in place,
never delivered), mints credentials that expire on their own, and authorizes and
logs every call. The two compose well: let systemd deliver Basil's unlock secret,
and let Basil hand out the short-lived rest.

---

## Getting Started

The quickest way to see Basil work end to end is the dev fixture: one script
boots a throwaway backend, writes an example catalog + policy, pre-fills a few
keys, and creates a sealed bundle, then prints the exact commands to run the
broker and drive it. Under five minutes.

### Prerequisites

- A **Vault-compatible backend CLI** on your `PATH`: OpenBao (`bao`) or
  HashiCorp Vault (`vault`).
- The Basil binary (`basil`). Build them with `cargo build`
  (Rust 1.96) or from the Nix dev shell.

### 1. Boot a dev backend + example config (one command)

```sh
# Boots a dev `bao` in -dev mode, writes an example catalog/policy, pre-fills
# keys, and seals a 0600 bundle. Prints the run + CLI commands when it finishes.
scripts/prefill-test-store.sh --engine openbao      # or: --engine vault
```

Basil treats OpenBao and HashiCorp Vault as one `vault` backend kind, so either
engine works.

### 2. Run the broker

Copy the `basil agent …` invocation the script printed. It wires the generated
TOML config, backend address, and socket. The config points at the catalog,
policy, sealed bundle, and passphrase file for the dev passphrase slot:

```sh
basil agent \
  --config <printed>/fixtures/basil-agent.toml \
  --vault-addr https://127.0.0.1:8200 \
  --socket /tmp/basil.sock
```

For shared local deployments, configure the socket in the agent TOML instead of
using a post-start `chmod` helper:

```toml
socket = "/run/basil/basil.sock"
socket-mode = "0660"
socket-group = "basil-clients"
```

The socket mode/group only controls which local users can open the transport.
Basil still authorizes each RPC from kernel peer credentials and catalog policy.

### 3. Drive it

The broker authorizes by a **policy subject** resolved from your kernel-attested
uid/gid, and the example policy grants the subject generated for the user that ran
the script. Talk to the broker over its socket with the `basil` CLI:

```sh
basil --socket /tmp/basil.sock status
# sign a message with a key whose private half never leaves the backend:
basil --socket /tmp/basil.sock sign --key-id web.tls.signing_key 'hello'
# AEAD-encrypt (Basil generates the nonce, so you can't reuse one):
basil --socket /tmp/basil.sock encrypt --key-id app.aead 'backup-bytes'
# mint a short-lived TLS leaf (the issuing CA key stays in the backend):
basil --socket /tmp/basil.sock issue-cert --key-id web.tls.cert_issuer \
  --common-name svc.example.org --dns-san svc.example.org --ttl-secs 3600
```

That's the whole loop: your shell proved who it was to the kernel, Basil resolved
that proof to a policy subject, policy said yes, and the Vault-compatible backend
did the crypto in place; no private key ever crossed the socket.

For the embedded db-keystore path, see `examples/db-keystore/`. It builds
`basil-bin` with the `db-keystore` feature, creates a small catalog and policy,
starts the agent on a Unix socket, and drives mint, sign/verify, and
encrypt/decrypt through the same `basil` CLI.

### Repository layout

- `crates/basil-proto` is the broker and SPIFFE gRPC contract.
- `crates/basil-cose` is the broker-free strict COSE profile used by sealed
  invocations and COSE unseal helpers.
- `crates/basil-client` is the published Rust client library.
- `crates/basil-core` is the broker runtime, backend manager, policy, services,
  and transport wiring.
- `crates/basil-bin` is the unified `basil` CLI and agent binary.
- `crates/basil-nats-bridge` is the raw-COSE NATS invocation courier.
- `xtask` is the workspace automation crate (man-page generation).
- `clients/go` is the Go client module.

### Drive it from Go

Beyond the Rust client (`crates/basil-client`), a Go client lives at
`clients/go` (module `github.com/openbasil/basil-go`). It dials the same
Unix socket and currently covers signing:

```go
c, _ := basil.Dial("/tmp/basil.sock")
defer c.Close()
sig, _ := c.Sign(ctx, "web.tls.signing_key", []byte("hello"))
ok, _ := c.Verify(ctx, "web.tls.signing_key", []byte("hello"), sig)
```

See `clients/go/README.md`. AEAD/KV/minting/certificates and SPIFFE helpers are
on the roadmap.

### Live Integration Tests

Default package checks run offline tests only. Integration tests that boot live
OpenBao/Vault dev servers are gated behind the `basil-tests/live-e2e` feature so
downstream package builds do not need `bao` or `vault` on `PATH`.

Run the live suite explicitly when those engine CLIs are available:

```sh
just cargo-live-e2e
```

### Man pages & packaging

Generate roff man pages for the `basil` and `basil-nats-bridge` binaries with the
`xtask` helper (a page per subcommand, e.g. `basil-agent.1`, is emitted
alongside the top-level pages):

```sh
just man-pages            # writes target/man/*.1
just man-pages dist/man   # override the output directory
cargo xtask -o dist/man   # same, via the cargo-xtask alias
```

Build a Debian package (binaries under `/usr/bin`, gzipped man pages under
`/usr/share/man/man1`) with nix-native tooling, no `fpm`/ruby. The archive is
named with the target architecture:

```sh
nix build .#basil-deb
dpkg-deb --contents result/*.deb
```

### Make it your own

`basil-example.nix` is a self-contained catalog + policy + NixOS module +
foreground runner. Copy it and edit two things:

- **`keys`**: the catalog of what exists (each key's class, algorithm, backend
  engine, and path).
- **`rules`**: who may do what to which key, keyed by **uid/gid**.

Remember: **give each app or service its own uid (and/or gid)**.
The uid *is* the workload's identity. Policy rules grant operations to
uids, and the kernel vouches for them. Two services sharing a uid share
authority.

Then run it (after creating a real sealed bundle for your backend credential with
`basil bundle create ...`):

```sh
nix run -f ./basil-example.nix run
```

---

## Deliverables

- `basil agent` is a broker over a local gRPC socket, backed by a
  Vault-compatible backend by default, with optional key-store backends for
  db-keystore and 1Password.
  - SPIFFE Workload API

- `basil` is a cli helper that
  - lints policy rules and configuration
  - calls the agent to create keys, rotate keys, import, sign, verify, encrypt, decrypt, mint/sign JWTs, issue certs, and show status.
  - As with other clients, what the cli is allowed to do is limited by the subject Basil resolves from its kernel-attested uid/gid and by the declared authorization policy.

---

## Status & roadmap

Basil is pre-release and under active development. What works today: kernel
`SO_PEERCRED` attestation, default-deny policy, the OpenBao/HashiCorp-Vault
backend (transit / KV-v2 / PKI engines), signing and AEAD encrypt/decrypt, X25519
sealed-box wrap/unwrap, optional db-keystore and 1Password key-store backends,
key generation / rotation / BYOK import, generic JWT + SPIFFE X.509/JWT-SVID
minting, NATS JWT mint/sign/validate and curve xkey boxes through `NatsService`, JWT-SVID validation
and revocation, and the sealed-bundle
unlock flow (age/YubiKey, BIP39, passphrase file). Verified against the upstream
`rust-spiffe` client.

Not yet: SPIFFE federation, KMS/HSM backends, additional signature algorithms
(ECDSA P-384/P-521, RSA-PSS), and broader attestation sources (systemd, k8s, TPM).

See [Features.md](./Features.md) for the detailed, per-feature breakdown of what's
implemented versus planned.

---

## References

- SPIFFE Workload API and SVID profiles:
  <https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md>
- SPIFFE Federation:
  <https://spiffe.io/docs/latest/spiffe-specs/spiffe_federation/>
- SPIRE federation architecture:
  <https://spiffe.io/docs/latest/architecture/federation/readme/>
- SPIRE extension model and Upstream Authority plugins:
  <https://spiffe.io/docs/latest/planning/extending/>
- HashiCorp Vault transit secrets engine:
  <https://developer.hashicorp.com/vault/docs/secrets/transit>
