# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
#
# SPDX-License-Identifier: Apache-2.0

# AFTER: the same workload, but the database password is served by Basil
# (Tier 1 of the migration tutorial): it lives in the backend as a catalog
# `value` key, the app's uid is granted `op:get` by a default-deny policy,
# and the service fetches it at start over the Basil socket into its own
# private runtime directory. Nothing under /run/secrets, nothing in the Nix
# store, every read audited, and rotation is a live broker operation.
#
# `basilPackage` arrives via specialArgs from vm.nix. When importing this
# into your own configuration, set `services.basil.settings.package` to your
# basil package instead.
#
# Companion to the tutorial:
# https://docs.openbasil.org/getting-started/sops-nix-to-basil/

{
  lib,
  pkgs,
  basilPackage,
  ...
}:

let
  caps = import ../../nix/backend-capabilities.nix;
  socketPath = "/run/basil/basil.sock";
  basil = lib.getExe' basilPackage "basil";

  # In-VM, throwaway provisioning for the demo: a dev-mode OpenBao backend
  # plus the sealed bundle (secret zero). On a real host the backend already
  # exists and the bundle is created once by an operator; the agent then
  # unlocks it at every boot. Run `demo-provision` as root after first boot.
  demoProvision = pkgs.writeShellApplication {
    name = "demo-provision";
    runtimeInputs = [
      pkgs.openbao
      basilPackage
    ];
    text = ''
      export VAULT_ADDR=http://127.0.0.1:8200
      export VAULT_TOKEN=root

      if ! bao status >/dev/null 2>&1; then
        echo "demo-provision: starting dev-mode OpenBao (in-memory, root token 'root')"
        bao server -dev -dev-root-token-id=root \
          -dev-listen-address=127.0.0.1:8200 \
          </dev/null >/var/log/bao-dev.log 2>&1 &
        disown
        for _ in {1..60}; do
          bao status >/dev/null 2>&1 && break
          sleep 1
        done
        bao status >/dev/null
      fi

      echo "demo-provision: sealing the bundle (backend credential + passphrase slot)"
      install -d -m 0700 -o basil -g basil /var/lib/basil
      umask 077
      printf 'demo-unlock-passphrase' >/var/lib/basil/unlock.pass
      printf 'root' >/var/lib/basil/dev-token
      rm -f /var/lib/basil/bundle.sealed
      basil bundle create /var/lib/basil/bundle.sealed \
        --slot passphrase:file=/var/lib/basil/unlock.pass \
        --backend id=bao,type=openbao,token-file=/var/lib/basil/dev-token
      rm -f /var/lib/basil/dev-token
      chown basil:basil /var/lib/basil/bundle.sealed /var/lib/basil/unlock.pass
      chmod 0600 /var/lib/basil/bundle.sealed

      systemctl restart basil-agent.service
      systemctl restart app.service

      echo "demo-provision: done. Inspect with:"
      echo "  journalctl -u app --no-pager | tail -n 2"
      echo "  basil --socket ${socketPath} rotate --key-id app.db_password"
    '';
  };
in
{
  imports = [
    ../../nix/basil-agent.nix
  ];

  networking.hostName = "after";

  users.groups.app = {
    gid = 9001;
  };
  users.users.app = {
    isSystemUser = true;
    group = "app";
    uid = 9001;
  };

  services.basil = {
    enable = true;

    catalog = {
      backends.bao = {
        implementation = caps.OPENBAO_2_5;
        addr = "http://127.0.0.1:8200";
      };
      # The sops.secrets."app/db_password" replacement: a value key in the
      # backend's KV store. `missing = "generate"` lets the agent's startup
      # reconcile create it, so no human ever has to know the password.
      keys."app.db_password" = {
        class = "value";
        backend = "bao";
        engine = "kv2";
        path = "secret/data/app/db-password";
        writable = true;
        missing = "generate";
        generate = {
          format = "ascii-printable";
          bytes = 24;
        };
        description = "Demo app database password, generated at first reconcile.";
      };
    };

    policy = {
      # The owner/mode pair from sops-nix becomes a policy subject resolved
      # from the app user's kernel-proven uid (SO_PEERCRED).
      unixSubjects.svc-app = {
        user = "app";
      };
      unixSubjects.operator-root = {
        user = "root";
      };

      rules = [
        {
          id = "app-can-read-its-password";
          subjects = [ "svc-app" ];
          action = [ "op:get" ];
          target = [ "app.db_password" ];
          comment = "The app service may fetch only its own database password.";
        }
        {
          id = "root-can-rotate-app-password";
          subjects = [ "operator-root" ];
          action = [ "op:rotate" ];
          target = [ "app.db_password" ];
          comment = "Root may rotate the demo password live; rotating never implies reading.";
        }
      ];
    };

    # Secret zero: the sealed bundle holds the backend credential, unlocked
    # at agent start. It is created outside the Nix store (here by
    # demo-provision; on a real host by an operator with `basil bundle
    # create`) and kept mode 0600.
    bundle = "/var/lib/basil/bundle.sealed";

    settings = {
      package = basilPackage;
      socket = socketPath;
      socketMode = "0660";
      socketGroup = "basil";
      vaultAddr = "http://127.0.0.1:8200";
      auditLog = "/var/lib/basil/audit.jsonl";
      unlock = {
        # Unattended demo unlock via a protected passphrase file. Real hosts
        # can use a TPM slot, age-yubikey, or a systemd credential instead.
        diskPassphraseFile = "/var/lib/basil/unlock.pass";
        unlockPassphraseNoWipe = true;
      };
    };
  };

  # The same workload as before.nix. The only changes are the source of the
  # file (fetched from Basil at start into a private runtime dir instead of
  # installed by activation) and the socket access (SupplementaryGroups).
  systemd.services.app = {
    description = "Demo app consuming its database password via Basil";
    wantedBy = [ "multi-user.target" ];
    after = [ "basil-agent.service" ];
    wants = [ "basil-agent.service" ];
    environment.DB_PASSWORD_FILE = "/run/app/db_password";
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      User = "app";
      Group = "app";
      # Membership in the basil group is what allows connecting to the 0660
      # socket; authorization is still the policy decision on the app uid.
      SupplementaryGroups = [ "basil" ];
      RuntimeDirectory = "app";
      RuntimeDirectoryMode = "0700";
    };
    # Fetch at start. `--out-file` writes the raw bytes to a file created
    # mode 0600, inside this unit's private /run/app. No world-visible
    # /run/secrets path exists on this system.
    preStart = ''
      ${basil} --socket ${socketPath} get --key-id app.db_password \
        --out-file "$RUNTIME_DIRECTORY/db_password"
    '';
    # Prove possession without logging the value: print a fingerprint only.
    script = ''
      test -s "$DB_PASSWORD_FILE"
      fingerprint=$(sha256sum "$DB_PASSWORD_FILE" | cut -c1-16)
      echo "app: db password fetched from Basil, fingerprint $fingerprint"
    '';
  };

  environment.systemPackages = [
    basilPackage
    pkgs.openbao
    demoProvision
  ];

  system.stateVersion = "25.11";
}
