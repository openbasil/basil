<!--
SPDX-FileCopyrightText: 2026 OpenBasil Contributors

SPDX-License-Identifier: Apache-2.0
-->

# basil-nats

Build NATS JWTs (the `ed25519-nkey` JWS profile) **without holding the signing key**. NATS
credentials are JWTs signed by an Ed25519 NKey; normally the tool that mints them (`nsc`) holds
the operator or account seed. This crate produces the exact wire bytes a NATS server expects but
splits signing out: you build the **signing input**, hand it to whatever holds the key (an HSM, a
vault transit engine, an `nkeys::KeyPair`, or the Basil broker) for a raw 64-byte Ed25519
signature, then [`assemble`] the final token. The seed never has to enter your process, which is
the whole point of minting from a broker.

The crate is dependency-light, `no_std`-capable (`--no-default-features --features alloc`), and
generic: Basil uses it, but nothing in it depends on Basil.

## Minting flow

```text
claims → signing_input() → <external Ed25519 signer> → assemble(input, sig) → JWT
```

Builders exist for each claim shape: [`UserJwt`], [`AccountJwt`] (imports, exports, limits,
service latency), [`OperatorJwt`], and [`RoleJwt`], with typed [`Permissions`] /
[`UserPermissions`] rather than raw JSON. [`format_user_creds`] renders the final `nsc`-style
`.creds` document from a signed user JWT plus the user seed.

## Wire format

Matches `nats-io/jwt` v2 / `nsc` byte-for-byte:

- header `{"typ":"JWT","alg":"ed25519-nkey"}`;
- `jti` is base32 (no pad) of SHA-512/256 over the *standard* claims only (`aud, exp, jti="",
  iat, iss, name, nbf, sub`); the `nats` object is excluded;
- header and claims are `base64url` no-pad; the signing input is `header.claims`;
- the signature is a raw 64-byte Ed25519 signature, `base64url` no-pad, as the third part.

## Verification and NKey helpers

The crate also decodes and checks tokens it did not mint: [`decode_nats_jwt`] parses a compact
token into [`DecodedNatsJwt`], and [`NatsJwtValidation`] matches it against candidate signers
with closed, diagnostic [`NatsJwtValidationReason`] outcomes. NKey utilities cover
[`encode_public`] / [`decode_public`] / [`require_public_prefix`] for the CRC-checked base32
public encodings ([`NkeyType`]: operator, account, user, server, curve, …) and
[`verify_public_signature`].

For curve (X) keys, [`seal_nats_curve`] / [`open_nats_curve`] implement the `nkeys` xkey
sealed-box construction (X25519 + XSalsa20-Poly1305), with private scalars in `Zeroizing` owners.

## Scope

This crate builds, signs (by delegation), and validates tokens. It does not talk to NATS, manage
accounts on a server, or store anything. Resolver push, credential distribution, and custody
policy belong to the caller.
