# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
#
# SPDX-License-Identifier: Apache-2.0

{
  description = "Basil, a host-local secrets broker: your app never touches the key";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    # This source exists only for the opt-in patched Nix pilot. The revision and
    # source NAR hash are repeated in nix/patched-nix/pins.json and checked at
    # evaluation time.
    nix-pilot-upstream = {
      url = "github:NixOS/nix/00c341b4f746dadd5947c3aa4673d5231226a028?narHash=sha256-lzFOjvHKYqHYBa1PigllKqXtQzoU9Lt26M5Hm7rSdpM=";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    # Compatibility evidence is independently rebased to this exact reachable
    # official-master revision. It is never selected by a package output.
    nix-pilot-master-compat = {
      url = "github:NixOS/nix/b1939e7d1abec240fb16a0ffa92fb4c28a24e4f0?narHash=sha256-jBCkvlSdCoMIMzEx6TYHlVgsEC0zZiB45t9YOg3mjA0=";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { self, ... }@inputs:
    inputs.flake-utils.lib.eachSystem
      [
        "x86_64-linux"
        "aarch64-darwin"
        "aarch64-linux"
      ]
      (
        system:
        let
          pkgs = inputs.nixpkgs.legacyPackages.${system};
          lib = pkgs.lib;
          nixPilotPkgs = import inputs.nixpkgs {
            inherit system;
            overlays = [ inputs.nix-pilot-upstream.overlays.internal ];
          };
          nixPilot = import ./nix/patched-nix {
            pkgs = nixPilotPkgs;
            upstream = inputs.nix-pilot-upstream;
            masterUpstream = inputs.nix-pilot-master-compat;
          };
          workspace_version = (fromTOML (builtins.readFile ./Cargo.toml)).workspace.package.version;

          # Debian architecture name for packages built on each Linux platform.
          # This value is forced only by the Linux-gated package output.
          debArch =
            {
              "x86_64-linux" = "amd64";
              "aarch64-linux" = "arm64";
            }
            .${system};

          toolchain = inputs.fenix.packages.${system}.fromToolchainFile {
            file = ./rust-toolchain.toml;
            # To refresh after editing rust-toolchain.toml: set sha256 = "" (or
            # lib.fakeHash), run `nix build` (or `nix develop`), and paste the
            # `got:` sha256 the hash-mismatch error prints into this field.
            sha256 = "sha256-OATSZm98Es5kIFuqaba+UvkQtFsVgJEBMmS+t6od5/U=";
          };
          toolchainNightly = inputs.fenix.packages.${system}.latest.toolchain;
          shellTools = with pkgs; [
            jq
            just
            protobuf
          ];

          # Build the unified `basil` binary. The default invocation builds the
          # whole workspace with its test suite (`doCheck = true`), exactly as
          # before. A feature-enabled variant scopes to `-p basil-bin` (the only
          # crate that re-exports the broker's optional features) so a single cargo
          # feature can be flipped on. `--features` is rejected at the root of a
          # virtual workspace, so it MUST be package-scoped.
          mkBasil =
            {
              pname,
              packageSet ? pkgs,
              rustToolchain ? toolchain,
              rustNightlyToolchain ? toolchainNightly,
              buildFeatures ? [ ],
              cargoBuildFlags ? [ ],
              doCheck ? true,
              installManPages ? false,
              nightly ? false,
              postInstall ? "",
            }:
            let
              buildProtobuf = packageSet.buildPackages.protobuf;
              manPagesPostInstall = ''
                mkdir -p $out/share/man/man1
                $out/bin/xtask -o $out/share/man/man1
                rm -f $out/bin/xtask
                gzip -9 -n $out/share/man/man1/*.1

                mkdir -p \
                  $out/share/bash-completion/completions \
                  $out/share/zsh/site-functions \
                  $out/share/fish/vendor_completions.d
                $out/bin/basil completions bash > $out/share/bash-completion/completions/basil
                $out/bin/basil completions zsh > $out/share/zsh/site-functions/_basil
                $out/bin/basil completions fish > $out/share/fish/vendor_completions.d/basil.fish
              '';
            in
            (packageSet.makeRustPlatform {
              cargo = if nightly then rustNightlyToolchain else rustToolchain;
              rustc = if nightly then rustNightlyToolchain else rustToolchain;
            }).buildRustPackage
              {
                inherit
                  pname
                  buildFeatures
                  cargoBuildFlags
                  doCheck
                  ;
                postInstall = lib.optionalString installManPages manPagesPostInstall + postInstall;
                version = workspace_version;
                cargoLock = {
                  lockFile = ./Cargo.lock;
                  outputHashes = {
                    "age-0.12.1" = "sha256-CNYGypRocOTPj454fLOr0xGA2zFj54PKPEC6opGE9f4=";
                  };
                };
                src = ./.;
                nativeBuildInputs = [ buildProtobuf ];
                PROTOC = "${buildProtobuf}/bin/protoc";
                PROTOC_INCLUDE = "${buildProtobuf}/include";
                # `reqwest`'s `rustls-no-provider` feature pulls in
                # `rustls-platform-verifier`, which loads the OS CA trust
                # store as soon as a `Client` is built, even for tests that
                # never touch the network (transit/spiffe/pki backend
                # tests). The nix build sandbox has no `/etc/ssl/certs`, so
                # point at nixpkgs' bundle explicitly for the check phase.
                SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
                meta = with packageSet.lib; {
                  description = "Host-local secrets broker: your app never touches the key";
                  homepage = "https://github.com/openbasil/basil";
                  license = licenses.asl20;
                  mainProgram = "basil";
                };
              };

          # The published package, unchanged (whole workspace, test suite on).
          basil = mkBasil {
            pname = "basil";
            installManPages = true;
          };

          # The TPM-unlock-enabled binary the hermetic VM lane bakes in. Pure-Rust
          # `tpm2-protocol` (the `unlock-tpm` feature) needs NO extra buildInputs.
          # doCheck is off: the check binary needs only a built broker; the test
          # suite runs on `basil` and via `cargo test` in the dev gates.
          basilTpm = mkBasil {
            pname = "basil-tpm";
            buildFeatures = [ "unlock-tpm" ];
            cargoBuildFlags = [
              "-p"
              "basil-bin"
            ];
            doCheck = false;
          };

          aarch64LinuxPkgs = pkgs.pkgsCross.aarch64-multiplatform;
          basilAarch64Linux = mkBasil {
            pname = "basil-aarch64-linux";
            packageSet = aarch64LinuxPkgs;
            doCheck = false;
          };
          basilTpmAarch64Linux = mkBasil {
            pname = "basil-tpm-aarch64-linux";
            packageSet = aarch64LinuxPkgs;
            buildFeatures = [ "unlock-tpm" ];
            cargoBuildFlags = [
              "-p"
              "basil-bin"
            ];
            doCheck = false;
          };

          tpm-unlock-test = import ./nix/tests/tpm-unlock-test.nix {
            inherit pkgs basilTpm;
          };
          basil-agent-schema3-test = import ./nix/tests/basil-agent-schema3-test.nix {
            inherit pkgs basil;
            nixosSystem = inputs.nixpkgs.lib.nixosSystem;
          };

          # Distribution build for the `.deb`: the three shipped binaries plus the
          # roff man pages the `xtask` crate emits (via `clap_mangen`). Scoped to
          # the three packages so no test suite runs and no example binaries leak
          # in. Pages land gzipped under `share/man/man1`, ready to drop into
          # `/usr/share/man/man1`.
          basilDist = mkBasil {
            pname = "basil-dist";
            cargoBuildFlags = [
              "-p"
              "basil-bin"
              "-p"
              "basil-https-courier"
              "-p"
              "basil-nats-bridge"
              "-p"
              "xtask"
            ];
            doCheck = false;
            installManPages = true;
          };

        in
        {
          packages = {
            default = basil;
            basil = basil;
            basil-tpm = basilTpm;
            # Explicit pilot outputs: neither replaces `packages.default` nor
            # enters a development shell or a release artifact.
            nix-pilot-cli = nixPilot.cli;
            nix-pilot-full = nixPilot.full;
            nix-pilot-manifest = nixPilot.manifest;
            # Per-architecture release target. `${system}` is already the arch
            # name CI selects on (`x86_64-linux`, `aarch64-linux`,
            # `aarch64-darwin`), so this exposes `nix build .#basil-x86_64-linux`
            # etc. as a single uniform command each build runner invokes on its
            # matching native `system`. It resolves to the plain `basil` build, so
            # the Rust toolchain is taken from rust-toolchain.toml (via fenix,
            # `mkBasil`'s `toolchain`) with no per-arch version drift. On
            # x86_64-linux the cross `basil-aarch64-linux` below is a distinct key.
            "basil-${system}" = basil;
          }
          // lib.optionalAttrs (system == "x86_64-linux") {
            basil-aarch64-linux = basilAarch64Linux;
            basil-tpm-aarch64-linux = basilTpmAarch64Linux;
          }
          // lib.optionalAttrs (lib.hasSuffix "linux" system) {
            # A Debian package assembled with `dpkg-deb` (no ruby/fpm): the three
            # binaries under `/usr/bin` and the gzipped man pages under
            # `/usr/share/man/man1`, from the single `basilDist` build. The arch
            # is carried in the filename (`basil_<version>_<arch>.deb`) since we
            # publish one package per build platform, no multi-arch. Built from
            # nix-store binaries, so the runtime linker paths point at the nix
            # store; see CHANGELOG for the portability caveat.
            #   nix build .#basil-deb
            #   dpkg-deb --contents result/*.deb
            basil-deb =
              pkgs.runCommand "basil-deb-${workspace_version}-${debArch}"
                {
                  nativeBuildInputs = [ pkgs.dpkg ];
                  meta = {
                    description = "Debian package for the Basil broker and couriers (${debArch}).";
                  };
                }
                ''
                  root="$TMPDIR/basil-deb"
                  mkdir -p "$root/DEBIAN" "$root/usr/bin" "$root/usr/share/man/man1"

                  install -Dm755 ${basilDist}/bin/basil "$root/usr/bin/basil"
                  install -Dm755 ${basilDist}/bin/basil-https-courier "$root/usr/bin/basil-https-courier"
                  install -Dm755 ${basilDist}/bin/basil-nats-bridge "$root/usr/bin/basil-nats-bridge"
                  cp ${basilDist}/share/man/man1/*.1.gz "$root/usr/share/man/man1/"

                  {
                    echo "Package: basil"
                    echo "Version: ${workspace_version}"
                    echo "Section: utils"
                    echo "Priority: optional"
                    echo "Architecture: ${debArch}"
                    echo "Maintainer: Basil maintainers <info@openbasil.org>"
                    echo "Homepage: https://github.com/openbasil/basil"
                    echo "Depends: libc6"
                    echo "Description: Basil, a host-local secrets broker: your app never touches the key"
                    echo " Basil brokers cryptographic operations, workload identity (SPIFFE),"
                    echo " and short-lived leases, with keys kept in the backend and used in"
                    echo " place. Ships the unified basil broker/CLI, the basil-nats-bridge"
                    echo " NATS courier, and the basil-https-courier HTTPS courier, plus their man pages."
                  } > "$root/DEBIAN/control"

                  mkdir -p "$out"
                  dpkg-deb --root-owner-group --build "$root" \
                    "$out/basil_${workspace_version}_${debArch}.deb"
                '';
          };
          devShells.default = pkgs.mkShell {
            nativeBuildInputs = shellTools ++ [ toolchain ];
          };
          devShells.nightly = pkgs.mkShell {
            nativeBuildInputs = shellTools ++ [ toolchainNightly ];
          };
          checks = {
            basil-agent-schema3 = basil-agent-schema3-test;
            nix-pilot-master-compatibility = nixPilot.masterCompatibility;
            nix-pilot-provenance = nixPilot.provenance;
          };
        }
        # Linux-only: nixosTest builds NixOS guest VMs, which only make sense on
        # Linux systems. Keep them outside `checks` so `nix flake check` remains
        # lightweight.
        // lib.optionalAttrs (lib.hasSuffix "linux" system) {
          tests = {
            tpm-unlock = tpm-unlock-test;
          };
        }
      );
}
