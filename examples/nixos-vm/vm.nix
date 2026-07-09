# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
#
# SPDX-License-Identifier: Apache-2.0

# Builds the two demo VMs (`nixos-rebuild build-vm` style) for the
# sops-nix-to-Basil migration tutorial:
#
#   nix-build ./vm.nix -A before -o result-before
#   nix-build ./vm.nix -A after  -o result-after
#   ./result-before/bin/run-before-vm     # boot needs KVM; build does not
#
# Like examples/nix/basil-example.nix, this follows the repository flake lock
# for nixpkgs by default; override `nixpkgs` or `basilPackage` explicitly only
# when testing a different input.

{
  repoFlake ? builtins.getFlake (toString ../../.),
  nixpkgs ? repoFlake.inputs.nixpkgs,
  system ? builtins.currentSystem,
  basilPackage ? repoFlake.packages.${system}.basil,
}:

let
  # Demo-only conveniences shared by both variants, kept out of
  # before.nix/after.nix so those stay importable into a real configuration.
  demoVmSettings = {
    nixpkgs.hostPlatform = system;
    documentation.enable = false;
    services.getty.autologinUser = "root";
    virtualisation.vmVariant.virtualisation = {
      graphics = false;
      memorySize = 2048;
      cores = 2;
    };
  };

  mkVm =
    module:
    (nixpkgs.lib.nixosSystem {
      specialArgs = { inherit basilPackage; };
      modules = [
        demoVmSettings
        module
      ];
    }).config.system.build.vm;
in
{
  before = mkVm ./before.nix;
  after = mkVm ./after.nix;
}
