# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
#
# SPDX-License-Identifier: Apache-2.0

{
  pkgs,
  basil,
  nixosSystem,
}:

let
  inherit (pkgs) lib;
  system = pkgs.stdenv.hostPlatform.system;

  fixture = {
    system.stateVersion = "25.11";

    services.basil = {
      enable = true;
      bundle = "/var/lib/basil/bundle.sealed";

      catalog = {
        backends.bao = {
          implementation = {
            kind = "vault";
            engines = [ "kv2" ];
          };
          addr = "https://127.0.0.1:8200";
        };
        keys."demo.value" = {
          class = "value";
          backend = "bao";
          engine = "kv2";
          path = "secret/data/demo/value";
          writable = false;
          missing = "warn";
          description = "Schema-3 module evaluation fixture.";
        };
      };

      policy = {
        unixSubjects.operator-root.user = "root";
        rules = [
          {
            id = "root-read-demo";
            subjects = [ "operator-root" ];
            action = [ "op:get" ];
            target = [ "demo.value" ];
          }
        ];
      };

      settings.package = basil;
    };
  };

  evaluated = nixosSystem {
    inherit system;
    modules = [
      ../basil-agent.nix
      fixture
    ];
  };
  inherit (evaluated) config;

  catalogFile = config.environment.etc."basil/catalog.json".source;
  policyFile = config.environment.etc."basil/policy.json".source;
  execStart = config.systemd.services.basil-agent.serviceConfig.ExecStart;
  configMatch = builtins.match ".* --config ([^ ]+)" execStart;
  configFile = builtins.appendContext (lib.head configMatch) (builtins.getContext execStart);

  expectedCatalog = pkgs.writeText "expected-basil-catalog.json" (
    builtins.toJSON {
      schema = "catalog";
      backends.bao = {
        kind = "vault";
        addr = "https://127.0.0.1:8200";
        engines = [ "kv2" ];
        capabilities = [ ];
        mintKeyTypes = [ ];
        requires = [ ];
      };
      keys."demo.value" = {
        class = "value";
        backend = "bao";
        engine = "kv2";
        path = "secret/data/demo/value";
        writable = false;
        missing = "warn";
        labels = [ ];
        description = "Schema-3 module evaluation fixture.";
      };
    }
  );
  expectedPolicy = pkgs.writeText "expected-basil-policy.json" (
    builtins.toJSON {
      schema = "policy";
      subjects.operator-root = {
        domain = "host-process";
        match.all = [ { "process.uid" = 0; } ];
      };
      roles = { };
      rules = [
        {
          id = "root-read-demo";
          subjects = [ "operator-root" ];
          action = [ "op:get" ];
          target = [ "demo.value" ];
        }
      ];
      config = {
        names = {
          users."0" = "root";
          groups = { };
        };
        memberships = { };
      };
    }
  );

  legacyCatalog = builtins.tryEval (
    (nixosSystem {
      inherit system;
      modules = [
        ../basil-agent.nix
        fixture
        { services.basil.catalog.schemaVersion = 1; }
      ];
    }).config.system.build.toplevel.drvPath
  );
  legacyPolicy = builtins.tryEval (
    (nixosSystem {
      inherit system;
      modules = [
        ../basil-agent.nix
        fixture
        { services.basil.policy.schemaVersion = 2; }
      ];
    }).config.system.build.toplevel.drvPath
  );
in
assert configMatch != null;
assert
  config.systemd.services.basil-agent.reloadTriggers == [
    catalogFile
    policyFile
  ];
assert config.systemd.services.basil-agent.serviceConfig.ProtectSystem == "strict";
assert config.systemd.services.basil-agent.serviceConfig.StateDirectoryMode == "0700";
assert !builtins.hasAttr "basil/bundle.sealed" config.environment.etc;
assert !legacyCatalog.success;
assert !legacyPolicy.success;
pkgs.runCommand "basil-agent-schema3-test"
  {
    nativeBuildInputs = [
      basil
      pkgs.diffutils
      pkgs.gnugrep
      pkgs.jq
    ];
  }
  ''
    cmp ${catalogFile} ${expectedCatalog}
    cmp ${policyFile} ${expectedPolicy}

    grep -Fqx 'schema = "agent"' ${configFile}
    grep -Fqx 'schemaVersion = 3' ${configFile}
    grep -Fqx '[import]' ${configFile}
    grep -Fqx 'catalog = "/etc/basil/catalog.json"' ${configFile}
    grep -Fqx 'policy = "/etc/basil/policy.json"' ${configFile}
    grep -Fqx 'bundle = "/var/lib/basil/bundle.sealed"' ${configFile}

    basil explain --config ${configFile} \
      -o import.catalog=${catalogFile} \
      -o import.policy=${policyFile} \
      --subject operator-root --effective --json >/dev/null

    jq 'del(.schema)' ${catalogFile} > catalog-without-schema.json
    if basil explain --config ${configFile} \
      -o import.catalog="$PWD/catalog-without-schema.json" \
      -o import.policy=${policyFile} \
      --subject operator-root --effective --json >/dev/null 2>&1; then
      echo "catalog without the schema discriminator was accepted" >&2
      exit 1
    fi

    jq 'del(.schema) + { schemaVersion: 2 }' ${policyFile} > policy-v2.json
    if basil explain --config ${configFile} \
      -o import.catalog=${catalogFile} \
      -o import.policy="$PWD/policy-v2.json" \
      --subject operator-root --effective --json >/dev/null 2>&1; then
      echo "policy schema version 2 was accepted" >&2
      exit 1
    fi

    touch $out
  ''
