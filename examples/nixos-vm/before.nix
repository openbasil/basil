# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
#
# SPDX-License-Identifier: Apache-2.0

# BEFORE: the sops-nix shape. The app's database password is a decrypted
# plaintext file on disk at /run/secrets/app/db_password, owned by the app
# user, and the workload reads it like any other file.
#
# HONESTY NOTE: this module does NOT import real sops-nix, so the example
# needs no extra flake inputs. The `mock-sops-install-secrets` unit below
# stands in for the secret-installation step sops-nix generates at
# activation. In real sops-nix the Nix store holds the *encrypted* sops
# file and the host's age/GPG key decrypts it; here the demo value sits
# plainly in the store. Either way the end state this tutorial cares about
# is identical: a decrypted secret file on disk that anything running as
# (or above) the owning uid can read.
#
# Companion to the tutorial:
# https://docs.openbasil.org/getting-started/sops-nix-to-basil/

{ pkgs, ... }:

let
  secretPath = "/run/secrets/app/db_password";
  # Real sops-nix: an encrypted secrets.yaml in the Nix store. Here: the demo
  # plaintext itself (world-readable in the store, deliberately the worst
  # case, so the after.nix diff has something honest to improve on).
  demoSecretSource = pkgs.writeText "app-db-password-demo" "correct horse battery staple\n";
in
{
  networking.hostName = "before";

  users.groups.app = {
    gid = 9001;
  };
  users.users.app = {
    isSystemUser = true;
    group = "app";
    uid = 9001;
  };

  # Stand-in for what sops-nix would generate from:
  #
  #   sops.secrets."app/db_password" = {
  #     owner = "app";
  #     # Decrypted to /run/secrets/app/db_password at activation.
  #   };
  #
  # sops-nix performs the equivalent install (sops-install-secrets) from a
  # NixOS activation script; a oneshot unit keeps the emulation visible and
  # self-contained.
  systemd.services.mock-sops-install-secrets = {
    description = "Stand-in for the sops-nix secret installation step";
    wantedBy = [ "multi-user.target" ];
    before = [ "app.service" ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
    };
    script = ''
      install -d -m 0751 /run/secrets /run/secrets/app
      install -m 0400 -o app -g app ${demoSecretSource} ${secretPath}
    '';
  };

  # The workload. It only ever consumes $DB_PASSWORD_FILE, so the diff of
  # this unit against after.nix is exactly the change an app owner makes in
  # the Tier-1 migration: same file handoff, different source of truth.
  systemd.services.app = {
    description = "Demo app consuming its database password from a file on disk";
    wantedBy = [ "multi-user.target" ];
    after = [ "mock-sops-install-secrets.service" ];
    requires = [ "mock-sops-install-secrets.service" ];
    environment.DB_PASSWORD_FILE = secretPath;
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      User = "app";
      Group = "app";
    };
    # Prove possession without logging the value: print a fingerprint only.
    script = ''
      test -s "$DB_PASSWORD_FILE"
      fingerprint=$(sha256sum "$DB_PASSWORD_FILE" | cut -c1-16)
      echo "app: db password read from $DB_PASSWORD_FILE, fingerprint $fingerprint"
    '';
  };

  system.stateVersion = "25.11";
}
