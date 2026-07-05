# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
#
# SPDX-License-Identifier: Apache-2.0

# Backend capability presets: what a given Vault / OpenBao *release provides*.
#
# A preset is the `implementation` of a `service.basil.catalog.backends.<name>`
# entry: the backend `kind`, the secrets `engines`, fine-grained `capabilities`,
# and native transit key types that version supports. Reference one from your
# catalog:
#
#   let caps = import ./nix/backend-capabilities.nix; in
#   service.basil.catalog.backends.bao = {
#     implementation = caps.OPENBAO_2_5;     # what the server PROVIDES
#     addr           = "https://127.0.0.1:8200";
#     # requires = [ "byok-import" ];        # optional extra app REQUIREMENT
#   };
#
# These describe PROVIDES, never requires. A preset is, by definition,
# everything that version supports. Basil derives what the catalog *requires*
# from the keys (plus the optional `requires` list) and enforces
# `required ⊆ provided` per `--capability-policy`.
#
# `capabilities` is an OPEN set: when a new release adds a feature this file
# doesn't list yet, name it inline (`capabilities = caps.OPENBAO_2_5.capabilities
# ++ [ "the-new-feature" ];`) with no Basil rebuild needed.
#
# `mintKeyTypes` is intentionally typed to Basil's known catalog algorithms: the
# broker uses it for static generate/import dispatch before it talks to the
# backend, so an unknown token must be added to Basil before it can be dispatched.
#
# NOTE: HashiCorp Vault CE 2.0 and OpenBao 2.5 expose an identical base tier (the
# wire is the same). Post-quantum transit is the Enterprise-only delta, so it
# lives only in the `*_ENT` preset.
let
  baseEngines = [
    "transit"
    "kv2"
    "pki"
  ];
  baseCapabilities = [
    "byok-import"
    "prehash-sign"
    "pki-crl"
    "jwt-auth"
    "approle-auth"
  ];
  baseMintKeyTypes = [
    "ed25519"
    "ed25519-nkey"
    "rsa-2048"
    "ecdsa-p256"
    "ecdsa-p384"
    "ecdsa-p521"
  ];
in
{
  # HashiCorp Vault Community Edition 2.0.x.
  VAULT_2_0 = {
    kind = "vault";
    engines = baseEngines;
    capabilities = baseCapabilities;
    mintKeyTypes = baseMintKeyTypes;
  };

  # HashiCorp Vault Enterprise 2.0.x, adds post-quantum transit algorithms.
  VAULT_2_0_ENT = {
    kind = "vault";
    engines = baseEngines;
    capabilities = baseCapabilities ++ [ "pqc-transit" ];
    mintKeyTypes = baseMintKeyTypes;
  };

  # OpenBao 2.5.x.
  OPENBAO_2_5 = {
    kind = "vault";
    engines = baseEngines;
    capabilities = baseCapabilities;
    mintKeyTypes = baseMintKeyTypes;
  };

  KEYSTORE = {
    kind = "keystore";
    engines = [
      "transit"
      "kv2"
    ];
    capabilities = [ ];
    mintKeyTypes = [ "ed25519" ];
  };
}
