# Patched Nix external-signer pilot

This directory contains the opt-in Nix 2.36.0 pilot for the generic `NXSG`
external signer. The default Basil package, host Nix installation, development
shells, and release artifacts do not use it.

Build the smaller command-line package or the complete Nix package explicitly:

```console
$ nix build .#nix-pilot-cli
$ nix build .#nix-pilot-full
```

The resulting `nix` accepts `nix store sign --signer-socket PATH`. Use it with
`basil nix signer serve`; use `basil nix cache sign|replace|remove` for
preview mutation of a `file://` binary cache.

## Provenance

[`pins.json`](pins.json) records three independent inputs: the reachable
official upstream revision and NAR hash, every file in the ordered patch series,
and both Basil conformance corpus digests. Flake evaluation rejects a mismatch
before a package build. The provenance check applies the hash-gated series with
zero fuzz, compares the complete reconstructed source tree with the package
source, confirms the reported Nix version, and compares the patched
`PATH_INFO_V1` corpus byte-for-byte with Basil's copy.

The source derivations actually consumed by both package lanes set
`patchFlags = [ "-p1" "--fuzz=0" ]`. Evaluation asserts those effective flags
and asserts that the CLI, utility tests, and functional tests consume the
resulting strict source. Both pilot outputs also depend on the
provenance derivation, so a package build cannot bypass reconstruction and
whole-tree comparison.

The external-signer patch adds a public header and a sodium-backed unit test but
omits both requirements from the split component package definitions. The
separately pinned `nix-components-packaging.patch` installs the header. Because
`overrideSource` deliberately ignores source-tree packaging expressions, the
pilot component scope supplies the test-only sodium dependency and points the
split unit-test runners at the patched corpus. It also supplies Python and
sodium, including its runtime library path, to the functional-test sandbox for
the patched `NXSG` helper. These packaging fixes leave the external-signer
implementation bytes unchanged.

```console
$ just check-nix-pilot-provenance
```

The tracked patch files are the canonical implementation artifacts. Their
ordered names, byte counts, line counts, and SHA-256 digests are pinned; no
external source branch or unresolvable revision is needed to reconstruct the
pilot.

The base patch intentionally does not claim compatibility with a different
upstream tree. A separate `nix-master-compat.patch` is rebased to the exact
reachable official-master revision recorded in `pins.json`; it is
compatibility-only and has no role in package selection or releases. Its check
applies that patch with zero fuzz, rebuilds the full Nix package and tests, and
compares its complete semantic delta with the canonical base series. New files
must match pinned content hashes and executable modes. Every change to an
existing operation or Meson registration must have the same exhaustive
added/deleted-line delta after line-number headers are removed. The check also
asserts that the canonical base patch does not apply to the recorded master.

```console
$ just check-nix-pilot-master-compat
```

## Platform tiers

`x86_64-linux` and `aarch64-linux` are preview pilot targets, but only the
`x86_64-linux` full package has passed a native build. Native full-build
qualification for `aarch64-linux` is pending. `aarch64-darwin` is a
development-only, evaluation-qualified target. The package passthrough and the
manifest output expose both tier and qualification status;
`just check-nix-pilot-matrix` checks those declarations without treating
foreign-platform evaluation as build evidence.
