<!--
SPDX-FileCopyrightText: 2026 OpenBasil Contributors

SPDX-License-Identifier: Apache-2.0
-->

# basil-keystore-backend

Optional **materialize-to-use** key-store support for [Basil](https://github.com/openbasil/basil). Basil prefers in-place backends
(transit engines, cloud KMS) where a private key is never released. When you do not have one, this
crate lets Basil be backed by a key/value store instead: secret bytes come out of storage into a
[`Zeroizing`] owner, local crypto in `basil-core` uses the key for exactly one operation, and the
material is wiped.

That is a weaker custody story than in-place, and it is deliberately isolated as an optional
dependency so it can be compiled out if not needed.

## Stores

Both providers implement the crate's unified byte-oriented `SecretStore` interface (`store`
module).

- **`db-keystore`** (feature `db-keystore`): Basil's built-in encrypted keystore, an encrypted
  SQLite file (turso) accessed through the `keyring-core` credential-store interface. This is
  what the repository's self-contained example uses; it needs no external service.
- **1Password** (feature `onepassword`): secrets stored as Secure Note items through the `op`
  CLI, addressed by a `secretspec`-style item title. 1Password items are string-valued, so this
  backend is **string-only**: writing non-UTF-8 bytes fails closed with `StoreError::NonUtf8Value`.
  That is a limitation of the 1Password backend, not of `SecretStore`. Ported from
  `cachix/secretspec` (Apache-2.0) and adapted to Basil's byte interface.

## Guarantees

- Secret values are returned in [`Zeroizing`] owners; nothing in this crate logs, clones into
  plain `Vec`s, or holds material past the operation.
- Errors are reduced to stable, leak-safe summaries before they leave the crate: no secret bytes
  ride in any error.
- The db-keystore open path runs under panic containment: a database-layer panic (for example a
  turso panic on a database/DEK mismatch) is converted into a fail-closed `StoreError` carrying a
  stable summary — the untrusted panic payload is discarded, and the broker never unwinds.
- The crate holds storage adapters only. Policy, attestation, and auditing stay in `basil-core`;
  a store cannot be reached except through the broker's decision path.

## Rekey boundary (`rekey` module, feature `db-keystore`, Linux)

The `rekey` module is the adapter boundary for rotating the db-keystore DEK
offline, built on db-keystore's descriptor-relative `rekey_at`/`verify_at`
(the path-based `DbKeyStore::rekey` is forbidden in basil code). It provides:

- **Zeroizing DEK pass-through**: DEKs travel as `SensitiveDek` (a
  `Zeroizing` owner); `rekey_to_staging` consumes the old-key owner and
  drops it before returning, so no old-key-bearing state survives staging.
- **Verified staging**: the candidate is written into a fresh private `0700`
  staging directory, verified record-exact by `rekey_at`, then re-verified
  against the live source with `verify_at` before any marker exists.
- **Intent-marker fence**: `<db>.rekey-intent` (created `O_EXCL`, `0600`,
  read back through a validated descriptor) records the candidate **and**
  pre-rekey database ciphertext BLAKE3 hashes plus the bundle epoch pair.
  While it exists, `SecretStore::open` refuses, naming the marker and the
  recovery command. The marker is a fence, not the commit point — the
  bundle reseal/epoch advance (owned by `basil-core`) is.
- **Advisory lock**: `SecretStore::open` holds `<db>.rekey-lock` shared for
  the store's lifetime; a rekey run holds it exclusive (`RekeyLock`), and
  every destructive primitive requires that witness value.
- **Crash recovery primitives**: pre-epoch `roll_back` (verifies the live
  database against the recorded hash first; needs no DEK) and post-epoch
  `roll_forward` (hash-checked swap resume, or swap-completed detection).
- **Typed, fail-closed errors** (`KeystoreRekeyError`): wrong-DEK by side,
  verification, unsafe-destination, marker/staging/lock states, and
  contained database-layer panics whose payload is withheld from `Display`
  and `Debug` (audit sink only via `AuditPayload`).

The `basil keystore rekey` command remains a fail-closed stub; it is
re-enabled only after the adversarial review of this boundary.

## Using it

Enable through `basil-core`/`basil-bin` features of the same names (`db-keystore`,
`onepassword`); both are on by default in the shipped binary. Depend on this crate directly only
if you are implementing another store for Basil.
