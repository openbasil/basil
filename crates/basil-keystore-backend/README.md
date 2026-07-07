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
- The crate holds storage adapters only. Policy, attestation, and auditing stay in `basil-core`;
  a store cannot be reached except through the broker's decision path.

## Using it

Enable through `basil-core`/`basil-bin` features of the same names (`db-keystore`,
`onepassword`); both are on by default in the shipped binary. Depend on this crate directly only
if you are implementing another store for Basil.
