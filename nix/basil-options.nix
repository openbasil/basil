# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
#
# SPDX-License-Identifier: Apache-2.0

{ lib, pkgs, ... }:

let
  inherit (lib) mkOption types;

  backendKindType = types.enum [
    "vault"
    "keystore"
  ];

  classType = types.enum [
    "asymmetric"
    "symmetric"
    "value"
    "public"
    "sealing"
  ];

  keyAlgorithmType = types.enum [
    "ed25519"
    "ed25519-nkey"
    "rsa-2048"
    "ecdsa-p256"
    "ecdsa-p384"
    "ecdsa-p521"
    "aes-256-gcm"
    "chacha20-poly1305"
    "x25519"
    "ml-kem-512"
    "ml-kem-768"
    "ml-kem-1024"
    "ml-dsa-44"
    "ml-dsa-65"
    "ml-dsa-87"
  ];

  engineType = types.enum [
    "transit"
    "kv2"
    "pki"
  ];

  missingPolicyType = types.enum [
    "error"
    "warn"
    "generate"
  ];

  generateFormatType = types.enum [
    "ascii-printable"
    "base64"
    "hex"
    "age-x25519"
    "self-signed-tls"
    "self-signed-tls-pair-of"
  ];

  policyOpType = types.enum [
    "get"
    "list"
    "get_public_key"
    "verify"
    "sign"
    "encrypt"
    "decrypt"
    "mint"
    "validate"
    "set"
    "rotate"
    "import"
    "new_key"
    # Broker-wide admin op (basil-atq): hot-reload the catalog/policy generation
    # from disk. NOT implied by any data-plane grant; grant it explicitly over the
    # reserved admin target `broker.reload`, e.g.
    #   { action = [ "op:reload" ]; target = [ "broker.reload" ]; ... }
    "reload"
    # Broker-wide admin op (basil-luw5): explain serving-generation policy
    # reachability. NOT implied by any data-plane grant; grant it explicitly over
    # the reserved admin target `broker.explain`.
    "explain"
    # Broker-wide admin op (basil-3wnn): persist and publish JWT-SVID revocation.
    # NOT implied by any data-plane grant; grant it explicitly over the reserved
    # admin target `broker.revoke`.
    "revoke"
  ];

  generateSpecType = types.submodule {
    options = {
      format = mkOption {
        type = generateFormatType;
        example = "ascii-printable";
        description = ''
          Generation recipe discriminator. Value/public material may use
          ascii-printable, base64, hex, age-x25519, self-signed-tls, or
          self-signed-tls-pair-of. Crypto keys with missing = "generate" are
          generated from keyType and do not need this block.
        '';
      };

      bytes = mkOption {
        type = types.nullOr types.ints.positive;
        default = null;
        example = 24;
        description = ''
          Number of random bytes for ascii-printable, base64, and hex generation
          recipes. Leave null for recipe formats that do not take a byte count.
        '';
      };

      commonName = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "web.internal";
        description = ''
          Certificate common name for the self-signed-tls test/dev generator.
          Leave null for non-TLS generation recipes.
        '';
      };

      validity = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "8760h";
        description = ''
          Certificate validity window for the self-signed-tls test/dev
          generator. Leave null for non-TLS generation recipes.
        '';
      };

      pairOf = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "web.tls.signing_key";
        description = ''
          Catalog key name paired with a self-signed-tls certificate by the
          self-signed-tls-pair-of test/dev generator.
        '';
      };
    };
  };

  backendEngineType = types.enum [
    "transit"
    "kv2"
    "pki"
  ];

  # Capabilities are an OPEN set: a known feature flag OR any string a newer
  # Vault/OpenBao release introduces. `types.str` (not `types.enum`) so a
  # hand-written config can name a capability this Basil release doesn't know
  # yet; enforcement compares by string, so an unknown one still works.
  capabilityType = types.str;

  # What a backend instance PROVIDES: its kind + supported engines/capabilities
  # plus native transit key types.
  # Supplied as a preset (nix/backend-capabilities.nix) or written inline.
  backendImplType = types.submodule {
    options = {
      kind = mkOption {
        type = backendKindType;
        default = "vault";
        example = "vault";
        description = "Backend provider kind (the vault-compatible kind: HashiCorp Vault or OpenBao).";
      };

      engines = mkOption {
        type = types.listOf backendEngineType;
        default = [ ];
        example = [
          "transit"
          "kv2"
          "pki"
        ];
        description = "Secrets engines this backend instance provides.";
      };

      capabilities = mkOption {
        type = types.listOf capabilityType;
        default = [ ];
        example = [
          "byok-import"
          "pki-crl"
        ];
        description = "Fine-grained features this backend instance provides (open set; see nix/backend-capabilities.nix presets).";
      };

      mintKeyTypes = mkOption {
        type = types.listOf keyAlgorithmType;
        default = [ ];
        example = [
          "ed25519"
          "ed25519-nkey"
          "rsa-2048"
          "ecdsa-p256"
          "ecdsa-p384"
          "ecdsa-p521"
        ];
        description = ''
          Native asymmetric transit key types this backend can generate/import.
          Basil uses this static preset field to dispatch mint/import paths
          without live backend probing.
        '';
      };
    };
  };

  backendRefType = types.submodule {
    options = {
      implementation = mkOption {
        type = backendImplType;
        example = lib.literalExpression "(import ./nix/backend-capabilities.nix).OPENBAO_2_5";
        description = ''
          What the backend instance provides: its kind plus the engines,
          capabilities, and mintKeyTypes it supports. Use a preset from
          nix/backend-capabilities.nix
          (OPENBAO_2_5, VAULT_2_0, VAULT_2_0_ENT, …) or write the fields inline.
          A preset is everything that version supports: it describes provides,
          never requires.
        '';
      };

      addr = mkOption {
        type = types.str;
        example = "https://127.0.0.1:8200";
        description = "Backend address, for example the Vault API URL.";
      };

      requires = mkOption {
        type = types.listOf capabilityType;
        default = [ ];
        example = [ "byok-import" ];
        description = ''
          Capabilities this deployment explicitly requires of the backend beyond
          what its keys already imply (the derived set), for non-key-derivable
          needs such as byok-import. Unioned with the derived requirements during
          enforcement (--capability-policy).
        '';
      };
    };
  };

  keyEntryType = types.submodule {
    options = {
      class = mkOption {
        type = classType;
        example = "asymmetric";
        description = ''
          Key class. asymmetric keys support sign/verify/mint/get_public_key;
          symmetric keys support encrypt/decrypt; value keys store opaque
          values; public keys expose public material; sealing keys hold
          materialize-to-use KEM private keys.
        '';
      };

      keyType = mkOption {
        type = types.nullOr keyAlgorithmType;
        default = null;
        example = "ed25519";
        description = ''
          Crypto algorithm for asymmetric and symmetric keys. Use null for value
          keys; public keys may set this only when the public material is itself
          a public key.
        '';
      };

      backend = mkOption {
        type = types.str;
        example = "bao";
        description = "Name of the catalog backend entry that serves this key.";
      };

      engine = mkOption {
        type = types.nullOr engineType;
        default = null;
        example = "transit";
        description = ''
          Backend sub-engine. transit and kv2 are inferred from class when null;
          pki is never inferred and must be set explicitly for X.509-SVID issuer
          CA keys.
        '';
      };

      path = mkOption {
        type = types.str;
        example = "web-tls";
        description = ''
          Backend-native locator. For OpenBao this is a transit key name, KV v2
          path, or PKI issue endpoint, depending on engine.
        '';
      };

      writable = mkOption {
        type = types.bool;
        example = true;
        description = ''
          Catalog-level hard cap on broker-mediated writes. False means the
          broker must not create, import, rotate, or set this key even when
          policy grants a write operation.
        '';
      };

      missing = mkOption {
        type = missingPolicyType;
        default = "error";
        example = "generate";
        description = ''
          Startup reconcile behavior when material is absent: error fails
          startup, warn logs and continues, generate creates missing material.
        '';
      };

      generate = mkOption {
        type = types.nullOr generateSpecType;
        default = null;
        example = lib.literalExpression ''
          {
            format = "ascii-printable";
            bytes = 24;
          }
        '';
        description = ''
          Generation recipe for value/public material when missing = "generate".
          Leave null for crypto keys, which generate from keyType.
        '';
      };

      labels = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [
          "nats_type=A"
          "crypto_provider_policy=backend-required"
        ];
        description = ''
          Free-form labels, each either name=value or a bare slug. Reserved
          labels include nats_type, broker_key_use, and PQC/provider metadata
          labels.
        '';
      };

      description = mkOption {
        type = types.str;
        example = "Signing key for the web TLS leaf; signs in place.";
        description = "Required non-empty human description for lint output and audit.";
      };
    };
  };

  catalogType = types.submodule {
    options = {
      schemaVersion = mkOption {
        type = types.ints.positive;
        default = 1;
        example = 1;
        description = "Catalog schema version. The current exported JSON schema is version 1.";
      };

      backends = mkOption {
        type = types.attrsOf backendRefType;
        default = { };
        example = lib.literalExpression ''
          {
            bao = {
              implementation = (import ./nix/backend-capabilities.nix).OPENBAO_2_5;
              addr = "https://127.0.0.1:8200";
            };
          }
        '';
        description = "Backend instances keyed by provider-neutral backend name.";
      };

      keys = mkOption {
        type = types.attrsOf keyEntryType;
        default = { };
        example = lib.literalExpression ''
          {
            "web.tls.signing_key" = {
              class = "asymmetric";
              keyType = "ed25519";
              backend = "bao";
              path = "web-tls";
              writable = true;
              description = "Signing key for the web TLS leaf; signs in place.";
            };
          }
        '';
        description = ''
          Catalog key inventory keyed by dotted lowercase key name. Each key
          defines its class, optional algorithm, backend routing, write cap,
          missing-material behavior, labels, and description.
        '';
      };
    };
  };

  namesType = types.submodule {
    options = {
      users = mkOption {
        type = types.attrsOf types.str;
        default = { };
        example = lib.literalExpression ''{ "9001" = "svc-web"; }'';
        description = "uid-to-name table used only for logging and audit.";
      };

      groups = mkOption {
        type = types.attrsOf types.str;
        default = { };
        example = lib.literalExpression ''{ "9001" = "svc-web"; }'';
        description = "gid-to-name table used only for logging and audit.";
      };
    };
  };

  policyConfigType = types.submodule {
    options = {
      names = mkOption {
        type = namesType;
        default = { };
        example = lib.literalExpression ''
          {
            users."9001" = "svc-web";
            groups."9001" = "svc-web";
          }
        '';
        description = "Export-resolved numeric id to symbolic name tables.";
      };

      memberships = mkOption {
        type = types.attrsOf (types.listOf types.ints.unsigned);
        default = { };
        example = lib.literalExpression ''{ "9001" = [ 9001 10 ]; }'';
        description = ''
          uid-to-full-group-set table. Each uid maps to all declared primary and
          supplementary gids used by the PDP for group principal checks.
        '';
      };
    };
  };

  principalSpecType = types.attrs;

  subjectType = types.submodule {
    options = {
      breakGlass = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Mark this subject as eligible for rules targeting the global wildcard
          target `*`. This marker is not a grant by itself.
        '';
      };

      allOf = mkOption {
        type = types.listOf principalSpecType;
        default = [ ];
        description = ''
          Principal specs that must all match. Specs may be runtime-shaped
          `{ kind = "unix"; uid = 9001; }` values or source-shaped
          `{ unix.uid = 9001; }` / `{ signature = { algorithm = "ed25519"; public = "..."; }; }`
          values.
        '';
      };

      anyOf = mkOption {
        type = types.listOf principalSpecType;
        default = [ ];
        description = ''
          Principal specs where any one may match. Leave empty when using allOf.
        '';
      };
    };
  };

  unixSubjectType = types.submodule {
    options = {
      user = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "svc-web";
        description = "System user name to resolve to a numeric uid subject.";
      };

      group = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "wheel";
        description = "System group name to resolve to a numeric gid subject.";
      };

      breakGlass = mkOption {
        type = types.bool;
        default = false;
        description = "Whether the generated Unix subject may appear on a `*` target rule.";
      };
    };
  };

  policyRuleType = types.submodule {
    options = {
      id = mkOption {
        type = types.str;
        example = "web-signer";
        description = "Stable rule id used in diagnostics, logging, and audit.";
      };

      subjects = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [
          "svc.web"
          "ops.wheel"
        ];
        description = ''
          Subject names this rule grants to. Each name must exist in
          policy.subjects or policy.unixSubjects.
        '';
      };

      action = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [
          "role:signer"
          "op:get_public_key"
        ];
        description = ''
          Action terms. Use role:<name>, op:<operation>, or * for any operation.
          Operations are the policy operation enum: get, list, get_public_key,
          verify, sign, encrypt, decrypt, mint, validate, set, rotate, import,
          and new_key.
        '';
      };

      target = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [
          "web.tls.signing_key"
          "web.tls.*"
        ];
        description = ''
          Target key names or globs. Bare dotted key names match exactly; * and
          ** are restricted to the documented last-segment glob forms.
        '';
      };

      comment = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "web service may sign its TLS challenge.";
        description = "Optional human-readable explanation for the rule.";
      };
    };
  };

  policyType = types.submodule {
    options = {
      roles = mkOption {
        type = types.attrsOf (types.listOf policyOpType);
        default = { };
        example = lib.literalExpression ''
          {
            signer = [ "sign" "verify" "get_public_key" ];
            reader = [ "get" "list" "get_public_key" ];
          }
        '';
        description = "Named roles, each expanding to a set of concrete policy operations.";
      };

      subjects = mkOption {
        type = types.attrsOf subjectType;
        default = { };
        example = lib.literalExpression ''
          {
            "svc.web".allOf = [
              { unix.uid = 9001; }
            ];
          }
        '';
        description = "Subject registry exported to policy.json.";
      };

      unixSubjects = mkOption {
        type = types.attrsOf unixSubjectType;
        default = { };
        example = lib.literalExpression ''
          {
            "svc.web".user = "svc-web";
            "ops.wheel".group = "wheel";
          }
        '';
        description = ''
          Convenience source form for generated Unix subjects. The exporter
          resolves user/group names to numeric uid/gid principals and writes
          audit name mappings into policy.config.names.
        '';
      };

      rules = mkOption {
        type = types.listOf policyRuleType;
        default = [ ];
        example = lib.literalExpression ''
          [
            {
              id = "web-signer";
              subjects = [ "svc.web" ];
              action = [ "role:signer" ];
              target = [ "web.tls.signing_key" ];
              comment = "web service may sign its TLS challenge.";
            }
          ]
        '';
        description = ''
          Authorization allow-list rules. Absence of a matching rule is
          default-deny.
        '';
      };

      config = mkOption {
        type = policyConfigType;
        default = { };
        example = lib.literalExpression ''
          {
            names.users."9001" = "svc-web";
            memberships."9001" = [ 9001 ];
          }
        '';
        description = "Export-resolved identity tables used by the PDP and logging.";
      };
    };
  };
in
{
  options.service.basil = {
    enable = mkOption {
      type = types.bool;
      default = false;
      description = "Enable the Basil agent systemd service.";
    };

    catalog = mkOption {
      type = catalogType;
      default = { };
      example = lib.literalExpression ''
        {
          schemaVersion = 1;
          backends.bao = {
            implementation = (import ./nix/backend-capabilities.nix).OPENBAO_2_5;
            addr = "https://127.0.0.1:8200";
          };
          keys."web.tls.signing_key" = {
            class = "asymmetric";
            keyType = "ed25519";
            backend = "bao";
            path = "web-tls";
            writable = true;
            description = "Signing key for the web TLS leaf; signs in place.";
          };
        }
      '';
      description = ''
        Basil catalog document, authored in Nix and projected to the exported JSON
        shape described by designs/catalog-policy-schema.html.
      '';
    };

    policy = mkOption {
      type = policyType;
      default = { };
      example = lib.literalExpression ''
        {
          roles.signer = [ "sign" "verify" "get_public_key" ];
          rules = [
            {
              id = "web-signer";
              subjects = [ "svc.web" ];
              action = [ "role:signer" ];
              target = [ "web.tls.signing_key" ];
              comment = "web service may sign its TLS challenge.";
            }
          ];
          config = {
            names.users."9001" = "svc-web";
            memberships."9001" = [ 9001 ];
          };
        }
      '';
      description = ''
        Basil policy document, authored in Nix and projected to the exported JSON
        shape described by designs/catalog-policy-schema.html.
      '';
    };

    bundle = mkOption {
      type = types.nullOr types.path;
      default = null;
      example = "/var/lib/basil/bundle.sealed";
      description = ''
        Path to the sealed credential bundle written to the generated agent TOML config.
        The bundle file itself is created by the Basil bundle tooling and is not
        embedded in the Nix store.
      '';
    };

    settings = mkOption {
      type = types.submodule {
        options = {
          package = mkOption {
            type = types.nullOr types.package;
            default = pkgs.basil or null;
            defaultText = lib.literalExpression "pkgs.basil or null";
            description = ''
              Package providing the basil binary. Set this when pkgs does
              not already provide a basil package.
            '';
          };

          user = mkOption {
            type = types.str;
            default = "basil";
            description = "User the Basil agent service runs as.";
          };

          group = mkOption {
            type = types.str;
            default = "basil";
            description = "Group the Basil agent service runs as.";
          };

          createUser = mkOption {
            type = types.bool;
            default = true;
            description = "Create the configured Basil system user and group.";
          };

          stateDirectory = mkOption {
            type = types.str;
            default = "basil";
            description = "systemd StateDirectory for Basil runtime state.";
          };

          socket = mkOption {
            type = types.nullOr types.str;
            default = null;
            example = "/run/basil/basil.sock";
            description = "Unix socket path written to the generated agent TOML config.";
          };

          socketMode = mkOption {
            type = types.strMatching "0?[0-7]{3,4}";
            default = "0600";
            example = "0660";
            description = ''
              Octal mode written as socket-mode in the generated agent TOML
              config. Authorization still uses peer credentials and policy; this
              only controls which local users can connect to the transport.
            '';
          };

          socketGroup = mkOption {
            type = types.nullOr types.str;
            default = null;
            example = "basil-clients";
            description = ''
              Optional group name or numeric gid written as socket-group in the
              generated agent TOML config.
            '';
          };

          vaultAddr = mkOption {
            type = types.str;
            default = "http://127.0.0.1:8200";
            description = "Default OpenBao/Vault address written to the generated agent TOML config.";
          };

          transitMount = mkOption {
            type = types.str;
            default = "transit";
            description = "OpenBao/Vault transit mount written to the generated agent TOML config.";
          };

          jwtAuthMount = mkOption {
            type = types.str;
            default = "jwt";
            description = "JWT auth-method mount for SpiffeSigner backend login.";
          };

          jwtRole = mkOption {
            type = types.str;
            default = "";
            description = "Vault/OpenBao JWT role required when a backend uses a SpiffeSigner credential.";
          };

          jwtAudience = mkOption {
            type = types.str;
            default = "openbao";
            description = "JWT-SVID audience used for SpiffeSigner backend login.";
          };

          svidTtlSecs = mkOption {
            type = types.ints.positive;
            default = 300;
            description = "Lifetime in seconds for self-minted JWT-SVIDs used by SpiffeSigner backend login.";
          };

          auditLog = mkOption {
            type = types.nullOr types.str;
            default = null;
            description = "Optional JSONL audit log path written to the generated agent TOML config.";
          };

          maxEncryptSize = mkOption {
            type = types.ints.positive;
            default = 1048576;
            description = "Maximum encrypt/decrypt payload size in bytes.";
          };

          maxPayloadSize = mkOption {
            type = types.ints.positive;
            default = 1048576;
            description = "Maximum set/import payload size in bytes.";
          };

          graceVersions = mkOption {
            type = types.ints.unsigned;
            default = 1;
            description = "Rotation grace window in key versions.";
          };

          retainVersions = mkOption {
            type = types.nullOr types.ints.unsigned;
            default = null;
            description = "Optional archived-version retention floor.";
          };

          retentionSweepSecs = mkOption {
            type = types.ints.unsigned;
            default = 3600;
            description = "Periodic retention sweep interval in seconds.";
          };

          noReconcile = mkOption {
            type = types.bool;
            default = false;
            description = "Skip startup catalog reconcile.";
          };

          capabilityPolicy = mkOption {
            type = types.enum [
              "strict"
              "degraded"
              "off"
            ];
            default = "strict";
            description = ''
              Capability-enforcement stance written to the generated agent TOML config:
              "strict" (any backend that can't provide what the catalog requires
              aborts startup, fail closed), "degraded" (defer to each key's
              missing policy: required-key gaps still fatal, others logged), or
              "off" (skip the check). A pure catalog check, no backend I/O.
            '';
          };

          keystore = mkOption {
            type = types.submodule {
              options = {
                dbKeystoreCipher = mkOption {
                  type = types.str;
                  default = "aegis256";
                  description = "db-keystore encryption cipher written as db-keystore-cipher.";
                };

                onepasswordProviderUri = mkOption {
                  type = types.str;
                  default = "";
                  description = "Default 1Password provider URI for OnePassword credentials with an empty provider_uri.";
                };

                onepasswordProject = mkOption {
                  type = types.str;
                  default = "";
                  description = "Default 1Password project for OnePassword credentials with an empty project.";
                };

                onepasswordProfile = mkOption {
                  type = types.str;
                  default = "";
                  description = "Default 1Password profile for OnePassword credentials with an empty profile.";
                };
              };
            };
            default = { };
            description = "Optional key-store backend defaults for enabled db-keystore or onepassword features.";
          };

          unlock = mkOption {
            type = types.submodule {
              options = {
                ageYubikey = mkOption {
                  type = types.bool;
                  default = false;
                  description = "Enable age-yubikey unlock in the generated agent TOML config.";
                };

                bip39PhraseFile = mkOption {
                  type = types.nullOr types.path;
                  default = null;
                  description = "BIP39 phrase file path written to the generated agent TOML config.";
                };

                diskPassphraseFile = mkOption {
                  type = types.nullOr types.path;
                  default = null;
                  description = "Disk passphrase file path written to the generated agent TOML config.";
                };

                insecureTestUnlock = mkOption {
                  type = types.bool;
                  default = false;
                  description = "Enable test-only disk unlock in the generated agent TOML config.";
                };

                strictBundlePerms = mkOption {
                  type = types.bool;
                  default = true;
                  description = "Refuse startup unless the sealed bundle is mode 0600.";
                };
              };
            };
            default = { };
            description = "Unlock-method settings written to the generated agent TOML config.";
          };

          brokerIdentity = mkOption {
            type = types.submodule {
              options = {
                id = mkOption {
                  type = types.nullOr types.str;
                  default = null;
                  example = "basil://prod/us-east-1/agent-a";
                  description = ''
                    Stable broker identity written as [broker-identity] id in
                    the generated agent TOML config. Required when invocation is
                    enabled.
                  '';
                };
                responseSigningKeyId = mkOption {
                  type = types.nullOr types.str;
                  default = null;
                  example = "broker.response_signing.2026q3";
                  description = ''
                    Catalog key id used to sign sealed invocation responses,
                    written as [broker-identity] response-signing-key-id.
                    Required when invocation is enabled.
                  '';
                };
              };
            };
            default = { };
            description = "Broker identity settings for sealed invocation response protection.";
          };

          invocation = mkOption {
            type = types.submodule {
              options = {
                enable = mkOption {
                  type = types.bool;
                  default = false;
                  description = ''
                    Accept sealed `InvocationService.Invoke` requests (written as
                    [invocation] enable in the generated agent TOML config).
                    Defaults to false: the service is compiled in and registered
                    on the Unix-socket gRPC server, but rejects requests unless an
                    operator explicitly enables bridged invocations.
                  '';
                };
                audience = mkOption {
                  type = types.listOf types.str;
                  default = [ ];
                  description = ''
                    Broker audiences accepted by sealed invocations. When more
                    than one audience is configured, requests must carry an
                    explicit matching audience; omitted audiences are accepted
                    only when this list has exactly one value.
                  '';
                };
                requestEncryptionKeyId = mkOption {
                  type = types.nullOr types.str;
                  default = null;
                  example = "broker.request_encryption.2026q3";
                  description = ''
                    Catalog key id whose public half receives sealed invocation
                    requests, written as [invocation]
                    request-encryption-key-id. Required when invocation is
                    enabled.
                  '';
                };
                maxTtlSecs = mkOption {
                  type = types.ints.positive;
                  default = 60;
                  description = "Maximum accepted sealed invocation TTL in seconds.";
                };
                clockSkewSecs = mkOption {
                  type = types.ints.unsigned;
                  default = 30;
                  description = "Allowed sealed invocation clock skew in seconds.";
                };
                replayCacheCapacity = mkOption {
                  type = types.ints.positive;
                  default = 4096;
                  description = "Maximum in-memory sealed invocation replay-cache entries.";
                };
              };
            };
            default = { };
            description = "Opt-in sealed invocation service settings.";
          };

          jwks = mkOption {
            type = types.submodule {
              options = {
                enable = mkOption {
                  type = types.bool;
                  default = false;
                  description = ''
                    Open the opt-in JWKS HTTP surface (written as [jwks] enable in
                    the generated agent TOML config). Defaults to false: the broker
                    is gRPC-over-unix-socket only and binds NO HTTP port unless this
                    is explicitly enabled. When enabled, the endpoint serves the
                    issuer JWK set (public keys only) so ordinary verifiers can
                    validate Basil JWT-SVIDs without SPIFFE plumbing.
                  '';
                };

                listen = mkOption {
                  type = types.str;
                  default = "127.0.0.1:8201";
                  example = "0.0.0.0:8201";
                  description = ''
                    Socket address the JWKS HTTP surface binds when enabled, written
                    as [jwks] listen in the generated agent TOML config. Only bound
                    when jwks.enable is true.
                  '';
                };

                issuer = mkOption {
                  type = types.nullOr types.str;
                  default = null;
                  example = "https://basil.example.com";
                  description = ''
                    Public base URL the JWKS HTTP surface is reachable at (no
                    trailing slash), written as [jwks] issuer in the generated agent
                    TOML config. When set, the broker serves the OIDC discovery
                    document at /.well-known/openid-configuration with a jwks_uri
                    consistent with this issuer and the JWKS path. When null (the
                    default) the discovery document is not served. Must be an
                    absolute http(s) URL.
                  '';
                };

                tls = mkOption {
                  type = types.submodule {
                    options = {
                      enable = mkOption {
                        type = types.bool;
                        default = false;
                        description = ''
                          Serve the JWKS surface over native rustls TLS. Requires
                          the Basil binary to be built with the http-tls cargo
                          feature. Defaults to false; the listener remains plain
                          HTTP unless explicitly enabled here.
                        '';
                      };

                      certFile = mkOption {
                        type = types.nullOr types.path;
                        default = null;
                        example = "/etc/basil/jwks-cert.pem";
                        description = "PEM certificate chain written as [jwks.tls] cert-file.";
                      };

                      keyFile = mkOption {
                        type = types.nullOr types.path;
                        default = null;
                        example = "/etc/basil/jwks-key.pem";
                        description = "PEM private key written as [jwks.tls] key-file.";
                      };
                    };
                  };
                  default = { };
                  description = "Optional native TLS settings for the JWKS listener.";
                };
              };
            };
            default = { };
            description = "Opt-in JWKS HTTP-surface settings written to the generated agent TOML config.";
          };

          environment = mkOption {
            type = types.attrsOf types.str;
            default = { };
            description = "Additional environment variables for the systemd service.";
          };

        };
      };
      default = { };
      description = "Additional settings needed to run the Basil agent service.";
    };
  };
}
