# Cachix external-custody proposal

Status: local upstream proposal for Cachix `1.11.1`, tracked by `basil-bimd.3.5`.

This package expression applies a Cachix CLI integration for the generic `NXSG` 1.0 signer
protocol. The patch is based on upstream tag `v1.11.1`, whose recursive Nix source hash is recorded
in `default.nix`. It remains an opt-in package and does not replace the host Cachix installation.

The patched CLI accepts `--signer-socket PATH` for push, watch, and daemon workflows. It performs
`DescribeKey` once, checks that the returned `name:public-key` identity belongs to the selected
cache, and pins the provider's endpoint identifier. Each fingerprint request reuses the command's
random batch identifier, generates a new request identifier, and verifies the returned Ed25519
signature before constructing the upload metadata. `cachix import` rejects the option before S3
discovery because its concurrent per-entry setup cannot pin one identity for the whole command.

External signing fails closed. The socket option conflicts with `CACHIX_SIGNING_KEY` and configured
private signing keys. A protocol, identity, timeout, overload, or signature failure stops the push;
the CLI does not fall back to local signing. Authentication tokens remain independent because they
authorize upload and contain no cache signing material.

The patch's client conformance suite drives Cachix's narinfo fingerprint construction and final
HTTP upload through a real Unix `NXSG` exchange. It covers CLI parsing, private-key conflicts,
cache enrollment, stable and fresh correlation identifiers, signature installation, and
fail-closed protocol handling for malformed headers, bodies, diagnostics, identities, signatures,
paths, timeouts, and bounds. Same-UID enforcement remains in the exercised client path; a
different-UID peer requires a user-namespace or privileged test lane and is not simulated in the
unprivileged package test.

`default.nix` independently pins both upstream source bytes and the reviewed patch digest. The
patch SHA-256 is `9387c8b975750ca7d29a0466627f8eadc0af94cbdaf82f08624f807b18a33531`.

Build the opt-in package from this repository's locked `nixpkgs` revision:

```sh
nix build --no-link --impure --expr '
  let flake = builtins.getFlake (toString ./.);
      pkgs = flake.inputs.nixpkgs.legacyPackages.x86_64-linux;
  in pkgs.callPackage ./packaging/cachix {}
'
```

Run Basil's provider as the same dedicated cache-publisher user, then pass its owner-only socket to
Cachix:

```sh
basil nix signer serve --key-id cache.signing --listen /run/cache-publisher/basil-nxsg.sock
cachix push --signer-socket /run/cache-publisher/basil-nxsg.sock CACHE PATH
```

The provider process is the actor recorded by Basil's policy and audit pipeline. The wire batch and
request identifiers preserve correlation into `DescribeNixCacheKey` and
`SignNixCacheFingerprint`. Key rotation uses the enrolled Nix key name and public key returned by
`DescribeKey`; the cache must advertise that identity before the patched client uploads with it.
