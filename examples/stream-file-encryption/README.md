<!--
SPDX-FileCopyrightText: 2026 OpenBasil Contributors

SPDX-License-Identifier: Apache-2.0
-->

# stream-file-encryption

Encrypt a large file with `basil::stream`, where **Basil owns every nonce** and
the container format is fixed by the library.

## Why

Whole-file, one-shot encryption forces you to hold the entire plaintext (and
ciphertext) in memory, and every hand-rolled chunking scheme reinvents the same
foot-guns: reused nonces, reorderable records, silent truncation, downgrade
attacks. `basil::stream` removes those by construction. It encrypts an
`AsyncRead` into an `AsyncWrite` chunk by chunk, and each chunk's
additional-authenticated-data binds the format version, suite, a per-stream id,
the chunk index, a final-chunk marker, and the lengths. The result is
non-reorderable, non-truncatable, non-replayable, and non-downgradable. The
caller never picks a nonce, so it cannot pick a *wrong* one.

The post-quantum pass goes one step further: the content-encryption key is
wrapped against a **broker-custodied** ML-KEM decapsulation key. Encryption
needs only the public encapsulation key, so it touches no secret at all;
decryption recovers the key through the broker, so the decapsulation seed never
leaves the vault. The container is byte-identical to the Go `stream`
subpackage, so a file sealed in one language opens in the other.

## What it demonstrates

1. **AES-256-GCM, generated CEK**: a fresh 256-bit CEK is minted per stream;
   encrypt → decrypt round-trips a 4 MiB (multi-chunk) file byte-for-byte. The
   CEK is established locally; Basil still owns the chunk nonces and framing.
2. **ML-KEM-768, broker CEK recovery**: the CEK is wrapped once against a
   custodied key (`stream.kem`, provisioned via `NewKey`). Encryption uses only
   the public key; decryption recovers the CEK through the broker's
   `UnwrapEnvelope` RPC (`BrokerCekRecovery`). The seed stays custodied.
3. **Fail closed**: flipping one ciphertext byte makes decryption error
   (`stream authentication failed`); nothing partial is emitted.

The normative byte layout is
[`docs/specs/streaming-encryption-format.md`](../../docs/specs/streaming-encryption-format.md).

## Basil pillars

- **Secrets**: the ML-KEM CEK recovery is brokered; the decapsulation seed is
  used in place and never released. The classical CEK is caller-established, but
  nonces are always the library's.
- **Least privilege** grants the process exactly `new_key`,
  `get_public_key`, `decrypt`, and `use_software_custody` on the one KEM key, and
  nothing else.

## Prerequisites

- [`bao`](https://openbao.org) (OpenBao) or [`vault`](https://developer.hashicorp.com/vault) on `PATH`
- `cargo` (the script builds the `basil` agent with the `pqc` feature and this
  example)

## How to run

```bash
examples/stream-file-encryption/run.sh
```

The script boots an OpenBao dev server and a `basil agent` (built with the `pqc`
feature), provisions the KEM key, then runs both passes and the tamper check
against the agent socket. It exits `0` only if every assertion passes.

Environment overrides (all optional): `STREAM_FILE_ENCRYPTION_WORKDIR` (default
`/tmp/basil-stream-file-encryption`), `STREAM_FILE_ENCRYPTION_BAO_PORT` (default
`8221`), `BASIL_BIN` (path to a prebuilt `basil` binary; note it must be built
with the `pqc` feature for the ML-KEM pass).

## Expected output

```
generated 4194304 byte input across many chunks
aead (aes-256-gcm): round-trip byte-identical
provisioned custodied stream.kem (1184 byte ML-KEM-768 encapsulation key)
ml-kem-768 (broker CEK recovery): round-trip byte-identical
tamper: decryption failed closed (stream authentication failed)
stream-file-encryption: all assertions passed
PASS
```

## See also

- [`examples/artifact-signing`](../artifact-signing): in-place signing and the
  typed deny path.
- [`examples/cose-nats-telemetry`](../cose-nats-telemetry): bare `COSE_Sign1`
  telemetry over NATS with Basil-minted credentials.
- The Go mirror of this example lives at
  `clients/go/examples/stream-file-encryption`; the container it produces is
  byte-identical.
- [`examples/cose-nats-demo`](../cose-nats-demo): the sealed-invocation COSE
  messaging demo carried by `basil-nats-bridge`.
