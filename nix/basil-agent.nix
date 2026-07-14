# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
#
# SPDX-License-Identifier: Apache-2.0

{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.basil;
  settings = cfg.settings;

  cleanJson =
    value:
    if builtins.isAttrs value then
      lib.filterAttrs (_: v: v != null) (lib.mapAttrs (_: cleanJson) value)
    else if builtins.isList value then
      map cleanJson value
    else
      value;

  # Project each backend to the agent's flat JSON shape: the `implementation`
  # preset (what the backend PROVIDES) is spread into top-level kind/engines/
  # capabilities/mintKeyTypes, alongside addr and the explicit `requires` list.
  projectBackend = b: {
    inherit (b.implementation)
      kind
      engines
      capabilities
      mintKeyTypes
      ;
    inherit (b) addr requires;
  };
  projectedCatalog = cfg.catalog // {
    backends = lib.mapAttrs (_: projectBackend) cfg.catalog.backends;
  };
  normalizePrincipal =
    spec:
    if spec ? kind then
      spec
    else if spec ? unix then
      { kind = "unix"; } // spec.unix
    else if spec ? signature then
      {
        kind = "signature-key";
      }
      // spec.signature
    else
      spec;
  normalizeSubject =
    subject:
    let
      normalized =
        if subject.allOf != [ ] then { allOf = map normalizePrincipal subject.allOf; } else { };
      normalizedAny =
        if subject.anyOf != [ ] then
          normalized // { anyOf = map normalizePrincipal subject.anyOf; }
        else
          normalized;
    in
    normalizedAny // lib.optionalAttrs (subject.breakGlass or false) { breakGlass = true; };

  userSubject =
    subjectName: spec:
    let
      user = config.users.users.${spec.user};
      uid = user.uid;
    in
    {
      name = subjectName;
      value = {
        allOf = [
          {
            kind = "unix";
            inherit uid;
          }
        ];
      }
      // lib.optionalAttrs spec.breakGlass { breakGlass = true; };
    };
  groupSubject =
    subjectName: spec:
    let
      group = config.users.groups.${spec.group};
      gid = group.gid;
    in
    {
      name = subjectName;
      value = {
        allOf = [
          {
            kind = "unix";
            inherit gid;
          }
        ];
      }
      // lib.optionalAttrs spec.breakGlass { breakGlass = true; };
    };
  generatedSubjects = lib.mapAttrs (
    subjectName: spec:
    if spec.user != null then
      (userSubject subjectName spec).value
    else
      (groupSubject subjectName spec).value
  ) cfg.policy.unixSubjects;
  generatedUserNames = lib.mapAttrs' (
    _subjectName: spec:
    let
      uid = config.users.users.${spec.user}.uid;
    in
    lib.nameValuePair (toString uid) spec.user
  ) (lib.filterAttrs (_: spec: spec.user != null) cfg.policy.unixSubjects);
  generatedGroupNames = lib.mapAttrs' (
    _subjectName: spec:
    let
      gid = config.users.groups.${spec.group}.gid;
    in
    lib.nameValuePair (toString gid) spec.group
  ) (lib.filterAttrs (_: spec: spec.group != null) cfg.policy.unixSubjects);
  projectedPolicy = cfg.policy // {
    schemaVersion = 2;
    unixSubjects = null;
    subjects = (lib.mapAttrs (_: normalizeSubject) cfg.policy.subjects) // generatedSubjects;
    config = cfg.policy.config // {
      names = {
        users = generatedUserNames // cfg.policy.config.names.users;
        groups = generatedGroupNames // cfg.policy.config.names.groups;
      };
    };
  };

  catalogFile = pkgs.writeText "basil-catalog.json" (builtins.toJSON (cleanJson projectedCatalog));
  policyFile = pkgs.writeText "basil-policy.json" (builtins.toJSON (cleanJson projectedPolicy));

  tomlFormat = pkgs.formats.toml { };

  # Catalog and policy are referenced at STABLE /etc paths (not their store
  # paths) so that editing either one does not perturb this TOML's store path,
  # and therefore not ExecStart. That keeps catalog/policy edits on the reload
  # (SIGHUP) path (see reloadTriggers/ExecReload below and br basil-y3e), while
  # every other setting here still flows into ExecStart and triggers a restart.
  agentConfig = cleanJson (
    {
      catalog = "/etc/basil/catalog.json";
      policy = "/etc/basil/policy.json";
      bundle = toString cfg.bundle;
      "vault-addr" = settings.vaultAddr;
      "transit-mount" = settings.transitMount;
      "jwt-auth-mount" = settings.jwtAuthMount;
      "jwt-role" = settings.jwtRole;
      "jwt-audience" = settings.jwtAudience;
      "svid-ttl-secs" = settings.svidTtlSecs;
      "capability-policy" = settings.capabilityPolicy;
      "max-encrypt-size" = settings.maxEncryptSize;
      "max-payload-size" = settings.maxPayloadSize;
      "grace-versions" = settings.graceVersions;
      "retention-sweep-secs" = settings.retentionSweepSecs;
      "socket-mode" = settings.socketMode;
      "no-reconcile" = settings.noReconcile;
      "db-keystore-cipher" = settings.keystore.dbKeystoreCipher;
      "onepassword-provider-uri" = settings.keystore.onepasswordProviderUri;
      "onepassword-project" = settings.keystore.onepasswordProject;
      "onepassword-profile" = settings.keystore.onepasswordProfile;
      unlock = {
        "age-yubikey" = settings.unlock.ageYubikey;
        "unlock-tpm" = settings.unlock.unlockTpm;
        "bip39-phrase-file" =
          if settings.unlock.bip39PhraseFile == null then null else toString settings.unlock.bip39PhraseFile;
        # The binary's [unlock] key is `unlock-passphrase-file` (AgentConfigFile is
        # deny_unknown_fields, so the old `passphrase-file` spelling made a
        # disk-passphrase config fail to parse at startup).
        "unlock-passphrase-file" =
          if settings.unlock.diskPassphraseFile == null then
            null
          else
            toString settings.unlock.diskPassphraseFile;
        "unlock-passphrase-no-wipe" = settings.unlock.unlockPassphraseNoWipe;
        "strict-bundle-perms" = settings.unlock.strictBundlePerms;
      };
      # Opt-in sealed invocation service ([invocation]). The service is compiled
      # in and registered on the gRPC socket, but rejects requests unless this is
      # explicitly enabled.
      invocation = {
        enable = settings.invocation.enable;
        audience = settings.invocation.audience;
        "request-encryption-key-id" = settings.invocation.requestEncryptionKeyId;
        "max-ttl-secs" = settings.invocation.maxTtlSecs;
        "clock-skew-secs" = settings.invocation.clockSkewSecs;
        "replay-cache-capacity" = settings.invocation.replayCacheCapacity;
      };
      # Opt-in JWKS HTTP surface ([jwks]). enable defaults to false: no HTTP port
      # is bound unless explicitly turned on. listen is parsed at startup but only
      # bound when enable is true. issuer (when set) enables the OIDC discovery
      # document; a null issuer is stripped by cleanJson so discovery is not served.
      jwks = {
        enable = settings.jwks.enable;
        listen = settings.jwks.listen;
        issuer = settings.jwks.issuer;
        tls = {
          enable = settings.jwks.tls.enable;
          "cert-file" =
            if settings.jwks.tls.certFile == null then null else toString settings.jwks.tls.certFile;
          "key-file" = if settings.jwks.tls.keyFile == null then null else toString settings.jwks.tls.keyFile;
        };
      };
    }
    //
      lib.optionalAttrs
        (settings.brokerIdentity.id != null || settings.brokerIdentity.responseSigningKeyId != null)
        {
          "broker-identity" = {
            id = settings.brokerIdentity.id;
            "response-signing-key-id" = settings.brokerIdentity.responseSigningKeyId;
          };
        }
    // lib.optionalAttrs (settings.socket != null) { socket = settings.socket; }
    // lib.optionalAttrs (settings.socketGroup != null) { "socket-group" = settings.socketGroup; }
    // lib.optionalAttrs (settings.auditLog != null) { "audit-log" = settings.auditLog; }
    // lib.optionalAttrs (settings.retainVersions != null) {
      "retain-versions" = settings.retainVersions;
    }
  );

  configFile = tomlFormat.generate "basil-agent.toml" agentConfig;

  args = [
    "agent"
    "--config"
    configFile
  ];

  basilAgent = lib.getExe' settings.package "basil";

  keystoreBackendDirs =
    let
      isLocalKeystore = b: b.implementation.kind == "keystore" && lib.hasPrefix "/" b.addr;
    in
    map (b: dirOf b.addr) (builtins.filter isLocalKeystore (builtins.attrValues cfg.catalog.backends));
in
{
  imports = [
    ./basil-options.nix
  ];

  config = lib.mkIf cfg.enable {
    # Rootless container density is keyring-quota-bound: crun joins one
    # session keyring per container, and the kernel default
    # kernel.keys.maxkeys=200 (per non-root user) caps a rootless realm at
    # ~196 containers before "crun: join keyctl: Disk quota exceeded"
    # (measured, Compose Phase 1 capacity ladder, basil-9tj.4). maxbytes must
    # scale with maxkeys because keyring payloads charge the per-user byte
    # quota. mkDefault so operators can override either value; the
    # raiseRootlessKeyringQuotas option disables the pair entirely.
    boot.kernel.sysctl = lib.mkIf cfg.raiseRootlessKeyringQuotas {
      "kernel.keys.maxkeys" = lib.mkDefault 2000;
      "kernel.keys.maxbytes" = lib.mkDefault 2000000;
    };

    assertions = [
      {
        assertion = settings.package != null;
        message = "services.basil.settings.package must provide a package containing bin/basil.";
      }
      {
        assertion = cfg.bundle != null;
        message = "services.basil.bundle must be set to the sealed credential bundle path.";
      }
      {
        assertion = lib.all (
          spec:
          (
            spec.user == null
            || (builtins.hasAttr spec.user config.users.users && config.users.users.${spec.user}.uid != null)
          )
          && (
            spec.group == null
            || (
              builtins.hasAttr spec.group config.users.groups && config.users.groups.${spec.group}.gid != null
            )
          )
        ) (builtins.attrValues cfg.policy.unixSubjects);
        message = "services.basil.policy.unixSubjects entries must reference users/groups with numeric uid/gid.";
      }
      {
        assertion = lib.all (spec: (spec.user != null) != (spec.group != null)) (
          builtins.attrValues cfg.policy.unixSubjects
        );
        message = "each services.basil.policy.unixSubjects entry must set exactly one of user or group.";
      }
      {
        assertion =
          lib.intersectLists (builtins.attrNames cfg.policy.subjects) (builtins.attrNames generatedSubjects)
          == [ ];
        message = "services.basil.policy.subjects and generated policy.unixSubjects must not define the same subject.";
      }
      {
        assertion = !settings.invocation.enable || settings.brokerIdentity.id != null;
        message = "services.basil.settings.brokerIdentity.id is required when invocation.enable is true.";
      }
      {
        assertion = !settings.invocation.enable || settings.brokerIdentity.responseSigningKeyId != null;
        message = "services.basil.settings.brokerIdentity.responseSigningKeyId is required when invocation.enable is true.";
      }
      {
        assertion = !settings.invocation.enable || settings.invocation.requestEncryptionKeyId != null;
        message = "services.basil.settings.invocation.requestEncryptionKeyId is required when invocation.enable is true.";
      }
      {
        assertion = !settings.invocation.enable || settings.invocation.audience != [ ];
        message = "services.basil.settings.invocation.audience must not be empty when invocation.enable is true.";
      }
    ];

    users.groups = lib.mkIf settings.createUser {
      ${settings.group} = lib.optionalAttrs (settings.gid != null) {
        gid = settings.gid;
      };
    };

    users.users = lib.mkIf settings.createUser {
      ${settings.user} = {
        isSystemUser = true;
        group = settings.group;
        home = "/var/lib/${settings.stateDirectory}";
      }
      // lib.optionalAttrs (settings.uid != null) { uid = settings.uid; };
    };

    # Stable, hot-reloadable surface. The agent reads these paths at the fixed
    # /etc location; on `nixos-rebuild switch` the symlink targets are repointed
    # in place (before units are reloaded), and reloadTriggers turns a content
    # change into a SIGHUP rather than a restart, so a catalog/policy edit is
    # applied live without re-sealing the keystore. Catalog and policy are not
    # secrets (key inventory, rules, id tables); the sealed bundle is referenced
    # by its own path and is never placed here.
    environment.etc = {
      "basil/catalog.json".source = catalogFile;
      "basil/policy.json".source = policyFile;
    };

    systemd.services.basil-agent = {
      description = "Basil agent";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      environment = settings.environment;

      # Catalog/policy changes reload (SIGHUP) instead of restart. switch-to-
      # configuration restarts whenever any restart-worthy unit content changed,
      # and restart supersedes reload, so this only yields a reload when nothing
      # else moved. Anything else (binary, socket, vault-addr, unlock, bundle, …)
      # changes ExecStart/this unit and correctly forces a full restart.
      reloadTriggers = [
        catalogFile
        policyFile
      ];

      serviceConfig = {
        Type = "simple";
        ExecStart = lib.escapeShellArgs ([ basilAgent ] ++ args);
        # Canonical systemd reload-by-signal; $MAINPID is expanded by systemd.
        # The agent's SIGHUP handler validates the new generation and fails
        # closed onto the previous one (br basil-y3e).
        ExecReload = "${pkgs.coreutils}/bin/kill -HUP $MAINPID";
        User = settings.user;
        Group = settings.group;
        StateDirectory = settings.stateDirectory;
        # The state dir can hold a local keystore and other broker state; keep it
        # owner-only rather than the systemd default 0755.
        StateDirectoryMode = "0700";
        RuntimeDirectory = "basil";
        Restart = "on-failure";
        RestartSec = "5s";
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ReadWritePaths = [
          "/run/basil"
          "/var/lib/${settings.stateDirectory}"
        ]
        ++ lib.optionals (settings.auditLog != null) [ (dirOf settings.auditLog) ]
        ++ lib.optionals (cfg.bundle != null) [ (dirOf (toString cfg.bundle)) ]
        ++ keystoreBackendDirs;
      };
    };
  };
}
