<!--
SPDX-FileCopyrightText: 2026 OpenBasil Contributors

SPDX-License-Identifier: Apache-2.0
-->

# Nix examples

`basil-example.nix` is a self-contained catalog, policy, NixOS module fragment,
and foreground runner for `basil agent`.

Run the foreground example from this directory:

```bash
just run
```

or directly from the repository root:

```bash
nix run -f examples/nix/basil-example.nix run
```

The example follows the repository flake lock for `nixpkgs` by default. Override
the package set or `basilPackage` explicitly only when testing a different Nix
input.

Environment overrides:

- `BASIL_EXAMPLE_BUNDLE` (default `/var/lib/basil/bundle.sealed`)
- `BASIL_EXAMPLE_SOCKET` (default `/tmp/basil-example.sock`)
- `BASIL_EXAMPLE_VAULT_ADDR` (default `https://127.0.0.1:8200`)

`VAULT_TOKEN` is intentionally removed from the foreground `basil agent`
environment; the agent should use the sealed bundle credentials instead of a
caller shell token.
