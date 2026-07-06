# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
#
# SPDX-License-Identifier: Apache-2.0

# Example Basil catalog, policy, NixOS service configuration, and foreground
# runner. This file is intentionally self-contained so it can be imported by a
# NixOS configuration or used directly with `nix run -f ./basil-example.nix run`.
#
# The foreground runner still needs a real OpenBao instance and a real sealed
# bundle. Override paths with environment variables:
#
#   BASIL_EXAMPLE_BUNDLE=/var/lib/basil/bundle.sealed \
#   BASIL_EXAMPLE_SOCKET=/tmp/basil-example.sock \
#   nix run -f ./basil-example.nix run
#
# Running as a managed systemd service is normally done by importing `module`
# into a NixOS configuration and applying it with `nixos-rebuild`, not `nix run`.

{
  pkgs ? import (builtins.getFlake "github:NixOS/nixpkgs/nixpkgs-unstable") {
    system = builtins.currentSystem;
  },
  #basilPackage ? (builtins.getFlake (toString ../../.)).packages.${builtins.currentSystem}.basil,
  basilPackage ?
    (builtins.getFlake "github:openbasil/basil").packages.${builtins.currentSystem}.basil,
  # ?ref=refs/tags/basil-v0.4.0";
}:

let
  # Backend capability presets: what a given Vault/OpenBao release provides.
  caps = import ../../nix/backend-capabilities.nix;

  catalog = {
    schemaVersion = 1;

    backends.bao = {
      # `implementation` declares what the backend PROVIDES (kind + engines +
      # capabilities + mintKeyTypes). Basil derives what the catalog requires
      # from the keys and enforces required ⊆ provided per --capability-policy
      # (default strict).
      implementation = caps.OPENBAO_2_5;
      addr = "https://127.0.0.1:8200";
    };

    keys = {
      "web.tls.signing_key" = {
        class = "asymmetric";
        keyType = "ed25519";
        backend = "bao";
        engine = "transit";
        path = "web-tls";
        writable = true;
        missing = "error";
        labels = [ "tier=example" ];
        description = "Example Ed25519 signing key for a web workload.";
      };

      "backups.aead_key" = {
        class = "symmetric";
        keyType = "aes-256-gcm";
        backend = "bao";
        engine = "transit";
        path = "backups-aead";
        writable = true;
        missing = "generate";
        labels = [ "tier=example" ];
        description = "Example AEAD key for encrypting backup payloads.";
      };

      "grafana.admin_password" = {
        class = "value";
        backend = "bao";
        engine = "kv2";
        path = "secret/data/grafana/admin";
        writable = true;
        missing = "generate";
        generate = {
          format = "ascii-printable";
          bytes = 24;
        };
        labels = [ "tier=example" ];
        description = "Example generated opaque value for Grafana admin bootstrap.";
      };

      "web.tls.ca_cert" = {
        class = "public";
        backend = "bao";
        engine = "kv2";
        path = "secret/data/web/tls/ca-cert";
        writable = false;
        missing = "warn";
        labels = [ "tier=example" ];
        description = "Example public CA certificate blob readable by workloads.";
      };
    };
  };

  policy = {
    schemaVersion = 2;

    # Named subjects: each maps a stable name to a typed principal selector, here
    # a Unix uid proven by `SO_PEERCRED`. Rules below grant to these names.
    subjects = {
      # `breakGlass` lets a subject appear on a global `*`-target rule (below).
      root = {
        breakGlass = true;
        allOf = [
          {
            kind = "unix";
            uid = 0;
          }
        ];
      };
      svc-web = {
        allOf = [
          {
            kind = "unix";
            uid = 9001;
          }
        ];
      };
      svc-backup = {
        allOf = [
          {
            kind = "unix";
            uid = 9002;
          }
        ];
      };
      svc-grafana = {
        allOf = [
          {
            kind = "unix";
            uid = 9003;
          }
        ];
      };
    };

    # Roles are named op bundles a rule references as `role:<name>`.
    roles = {
      signer = [
        "sign"
        "verify"
        "get_public_key"
      ];
      cryptor = [
        "encrypt"
        "decrypt"
      ];
      reader = [
        "get"
        "list"
        "get_public_key"
      ];
      operator = [
        "set"
        "rotate"
        "import"
        "new_key"
      ];
    };

    rules = [
      {
        id = "web-can-sign";
        subjects = [ "svc-web" ];
        action = [ "role:signer" ];
        target = [ "web.tls.signing_key" ];
        comment = "Example web service may sign using only its TLS signing key.";
      }
      {
        id = "backup-can-use-aead";
        subjects = [ "svc-backup" ];
        action = [ "role:cryptor" ];
        target = [ "backups.aead_key" ];
        comment = "Example backup service may encrypt and decrypt backup payloads.";
      }
      {
        id = "grafana-can-read-password";
        subjects = [ "svc-grafana" ];
        action = [ "op:get" ];
        target = [ "grafana.admin_password" ];
        comment = "Example Grafana service may fetch its generated admin password.";
      }
      # No rule is needed for `web.tls.ca_cert`: a `class = "public"` key is
      # world-readable for reads by construction (design §3.5).
      {
        id = "root-operator";
        subjects = [ "root" ];
        action = [ "role:operator" ];
        target = [ "*" ];
        comment = "Root may perform operator writes across the example catalog.";
      }
    ];

    config = {
      names = {
        users = {
          "0" = "root";
          "9001" = "svc-web";
          "9002" = "svc-backup";
          "9003" = "svc-grafana";
        };
        groups = { };
      };
      memberships = {
        "0" = [ ];
        "9001" = [ ];
        "9002" = [ ];
        "9003" = [ ];
      };
    };
  };

  # Each backend authors its capability preset under `implementation` (what the
  # server PROVIDES); the agent's on-disk schema is flat (kind/engines/
  # capabilities/mintKeyTypes at the backend top level, beside addr). The NixOS
  # `module` projects this via nix/basil-agent.nix; the direct `run` path
  # serializes the catalog itself, so it applies the same projection here.
  projectBackend = b: b.implementation // { inherit (b) addr; };
  projectedCatalog = catalog // {
    backends = builtins.mapAttrs (_: projectBackend) catalog.backends;
  };
  catalogJson = pkgs.writeText "basil-example-catalog.json" (builtins.toJSON projectedCatalog);
  policyJson = pkgs.writeText "basil-example-policy.json" (builtins.toJSON policy);

  # `--transit-mount` and `--strict-bundle-perms` are no longer `basil agent` CLI
  # flags; they are TOML startup-config settings. This minimal config carries
  # them; the wrapper still passes catalog/policy/bundle/socket/vault-addr as
  # flags, which override / fill in the config file at load time.
  agentRunConfig = pkgs.writeText "basil-example-agent.toml" ''
    transit-mount = "transit"

    [unlock]
    strict-bundle-perms = true
  '';

  run = pkgs.writeShellApplication {
    name = "basil-example-run";
    text = ''
      : "''${BASIL_EXAMPLE_BUNDLE:=/var/lib/basil/bundle.sealed}"
      : "''${BASIL_EXAMPLE_SOCKET:=/tmp/basil-example.sock}"
      : "''${BASIL_EXAMPLE_VAULT_ADDR:=https://127.0.0.1:8200}"

      exec ${basilPackage}/bin/basil agent \
        --config ${agentRunConfig} \
        --catalog ${catalogJson} \
        --policy ${policyJson} \
        --bundle "$BASIL_EXAMPLE_BUNDLE" \
        --socket "$BASIL_EXAMPLE_SOCKET" \
        --vault-addr "$BASIL_EXAMPLE_VAULT_ADDR"
    '';
  };

  module =
    { ... }:
    {
      imports = [
        ../../nix/basil-agent.nix
      ];

      service.basil = {
        enable = true;
        inherit catalog policy;

        # The sealed bundle is intentionally outside the Nix store. Create it
        # with `basil bundle create ...`, keep it mode 0600, and place it where
        # the service user can read it.
        bundle = "/var/lib/basil/bundle.sealed";

        settings = {
          package = basilPackage;
          socket = "/run/basil/basil.sock";
          socketMode = "0660";
          socketGroup = "basil";
          vaultAddr = "https://127.0.0.1:8200";
          transitMount = "transit";
          auditLog = "/var/lib/basil/audit.jsonl";
          maxEncryptSize = 1048576;
          maxPayloadSize = 1048576;
          graceVersions = 1;
          retentionSweepSecs = 3600;
          unlock.strictBundlePerms = true;
        };
      };
    };
in
{
  inherit
    catalog
    policy
    catalogJson
    policyJson
    module
    run
    ;
}
