<!--
SPDX-FileCopyrightText: 2026 OpenBasil Contributors

SPDX-License-Identifier: Apache-2.0
-->

# nixos-vm

> **Basil is a host-local secrets broker: your app never touches the key.** The kernel attests who's
> calling, a default-deny policy decides, the key is used where it lives (OpenBao/Vault, KMS, or a
> sealed local store), and every operation is audited.

Keep your NixOS secrets **off disk**: build the same tiny NixOS system twice:
once with a sops-nix-style on-disk secret, once with the same secret served by
Basil, and diff the two.

This is the runnable half of the tutorial
[Migrating from sops-nix to Basil](https://docs.openbasil.org/getting-started/sops-nix-to-basil/).

## Why

`sops-nix` (and agenix) decrypt secrets to files at activation time, typically
under `/run/secrets/...`. That works, but the decrypted secret is a file any
process running as (or above) the owning uid can read, rotation means editing
the encrypted source and rebuilding the host, and nothing audits who read it.

The Tier-1 migration keeps the app unchanged: it still reads a password from a
file, but the file is fetched **at service start** from Basil over a
policy-gated Unix socket into the unit's private runtime directory. The value
lives in the backend, only the granted uid can obtain it, every read is
audited, and rotation is one live broker command: no rebuild, no switch.

## What it demonstrates

1. **The before shape** (`before.nix`): a systemd service reading
   `/run/secrets/app/db_password`, installed on disk the way sops-nix would.
   (It *emulates* sops-nix with a clearly-marked oneshot unit, so the example
   needs no extra flake inputs.)
2. **The after shape** (`after.nix`): the identical workload with a
   `services.basil` catalog `value` key, a default-deny policy granting the
   app's uid `op:get`, and a `preStart` fetch via
   `basil get --key-id app.db_password --out-file ...` (raw bytes, file
   created mode 0600).
3. **Rotation without a rebuild**: `basil rotate --key-id app.db_password`
   inside the running after-VM, then restart the app. The journal shows a new
   fingerprint. In the before-VM the same change is an encrypted-file edit
   plus a full rebuild.
4. **Least privilege**: root is granted `op:rotate` only. Rotating the
   password never implies being able to read it, and a root `basil get` is
   denied while the app's own fetch succeeds.

Diff the two worlds directly:

```bash
diff -u before.nix after.nix
```

## Basil pillars

- **Attestation**: the policy subject is the app's kernel-proven uid
  (`SO_PEERCRED`), not file ownership.
- **Secrets**: the value stays in the backend until an authorized caller
  fetches it; reads and writes are separate grants (`op:get` vs `op:rotate`).
- **Secure by default**: nothing is readable until a rule grants it; the
  sealed bundle (secret zero) is created outside the Nix store, mode 0600.

## Prerequisites

- Nix with flakes enabled (`vm.nix` follows the repository flake lock, like
  `examples/nix`)
- Linux with `/dev/kvm` to **boot** the VMs (building them needs no KVM)
- [`just`](https://github.com/casey/just) (optional; the recipes are one-liners)

## How to run

From this directory:

```bash
just build          # builds ./result-before and ./result-after
just run-before     # boots the sops-nix-style VM (auto-login as root)
```

Inside the **before** VM, the secret is a plain file on disk:

```console
[root@before:~]# systemctl status app --no-pager | tail -n 2
[root@before:~]# cat /run/secrets/app/db_password     # any root-level reader wins
correct horse battery staple
```

Quit with `Ctrl-a x`, then boot the after variant:

```bash
just run-after
```

Inside the **after** VM, provision the throwaway backend and sealed bundle
once, then watch the same workload fetch its password from Basil:

```console
[root@after:~]# demo-provision
[root@after:~]# journalctl -u app --no-pager | tail -n 2
[root@after:~]# ls /run/secrets                        # no such path exists
[root@after:~]# basil --socket /run/basil/basil.sock get --key-id app.db_password
                                                       # denied: root holds rotate, not get
```

Rotate live: no rebuild, no switch:

```console
[root@after:~]# basil --socket /run/basil/basil.sock rotate --key-id app.db_password
[root@after:~]# systemctl restart app
[root@after:~]# journalctl -u app --no-pager | tail -n 1   # new fingerprint
```

## Expected output

Before VM (journal of `app.service`):

```
app: db password read from /run/secrets/app/db_password, fingerprint 96b982fd07242702
```

After VM, following `demo-provision`:

```
app: db password fetched from Basil, fingerprint <16 hex chars>
```

and after `rotate` + `systemctl restart app`, the same line with a
**different** fingerprint, while `nixos-version` confirms the system
generation never changed.

## See also

- The full tutorial narrative:
  [Migrating from sops-nix to Basil](https://docs.openbasil.org/getting-started/sops-nix-to-basil/)
- [`examples/nix`](../nix): the self-contained catalog/policy/module example
  this one builds on (Tier-2 keys: sign, encrypt, in-place custody).
- [`nix/basil-options.nix`](../../nix/basil-options.nix): every
  `services.basil` option used here, with documentation.
- [Unlock & the sealed bundle](https://docs.openbasil.org/configuration/unlock-and-bundle/):
  the secret-zero model behind `demo-provision`'s passphrase slot.
