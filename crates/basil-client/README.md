<!--
SPDX-FileCopyrightText: 2026 OpenBasil Contributors

SPDX-License-Identifier: Apache-2.0
-->

# basil (client)

> **Basil is a host-local secrets broker: your app never touches the key.** The kernel attests who's
> calling, a default-deny policy decides, the key is used where it lives (OpenBao/Vault, KMS, or a
> sealed local store), and every operation is audited.

The Rust client library for the [Basil broker](https://github.com/openbasil/basil). Your program connects to Basil's local Unix socket
over gRPC and asks the broker to sign, verify, encrypt, decrypt, mint, or fetch on its behalf. The
private key never enters your process: Basil attests you from the kernel (`SO_PEERCRED` uid/gid),
checks its default-deny policy, and performs the operation in place against the backend.

That is the point of using this crate instead of a crypto library: there is no client token to
issue, store, rotate, or steal, and nothing sensitive to zeroize on your side of the socket
beyond the plaintexts you already own.

```rust,ignore
let mut client = basil::Client::connect("/run/basil/basil.sock").await?;
let sig = client.sign("release.signing", b"artifact digest").await?;
```

`Client` is async (tokio). [`BlockingClient`] wraps the same surface for synchronous callers.

## What you can ask for

Availability is decided by the broker's policy for *your* identity; every method below is denied
by default until a rule grants it.

- **Keys**: `new_key`, `import` / `import_set` (BYOK, wrapped in place, all-or-nothing batches),
  `get_public_key`, `sign` / `verify` (plus `_with_algorithm` variants).
- **Encryption**: `encrypt` / `decrypt`, envelope `wrap_envelope` / `unwrap_envelope`,
  `unseal_cose` for broker-held COSE seals.
- **Streaming** (`stream` module): chunked authenticated encryption of `AsyncRead` →
  `AsyncWrite` without buffering whole payloads, with AES-256-GCM, ChaCha20-Poly1305, or ML-KEM
  post-quantum suites.
- **Secrets**: `get_secret`, `set_secret`, `rotate_secret`, `list_catalog`.
- **Minting**: `mint_jwt` (OIDC-style JWTs) and the NATS family: `mint_nats_user`,
  `mint_nats_account`, `mint_nats_operator`, `mint_nats_signer`, `mint_nats_server`,
  `mint_nats_curve`, `encrypt_nats_curve` / `decrypt_nats_curve`, `sign_nats_jwt`,
  `validate_nats_jwt`.
- **PKI**: `issue_certificate` for short-lived X.509 leaves.
- **Sealed invocations** (`sealed_invocation` module): build and open the COSE sealed request /
  response envelopes carried by Basil's invocation service, for callers that reach Basil through
  a courier (for example [`basil-nats-bridge`](../basil-nats-bridge)) instead of the local socket.
- **Operations**: `status`, permission-gated `status_with_realms`, `health`, realm-aware
  `readiness`, `reload`, `explain` (why a decision would be allowed or denied), `revoke`.

## Errors and wire types

Domain wire types are re-exported through the `proto` module so your code does not depend on
generated modules directly; errors arrive as structured, leak-safe `Error` values rather than raw
gRPC status strings.

## Where the trust boundary sits

The library performs no authorization, and key custody stays with the broker: even the
sealed-invocation helpers ship broker-backed adapters for actor signing and unsealing rather than
holding keys locally. The crate is deliberately thin: request construction, transport, and
response decoding. If you can open the socket, the broker still decides everything else. Audit
records land on the broker side, attributed to your attested identity.
