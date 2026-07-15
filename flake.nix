# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
#
# SPDX-License-Identifier: Apache-2.0

{
  description = "Basil, a host-local secrets broker: your app never touches the key";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
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
          workspace_version = (fromTOML (builtins.readFile ./Cargo.toml)).workspace.package.version;

          # Docker/OCI architecture name for the single-arch image tag. Basil
          # publishes one image per build platform (no multi-arch manifest list
          # yet), so the arch is pinned into the tag to keep `basil:<version>-amd64`
          # and `basil:<version>-arm64` from colliding on load. Drop the suffix
          # once a multi-arch manifest is published. Only forced under the
          # linux-gated image output, so darwin eval never hits the missing key.
          dockerArch =
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
            sha256 = "sha256-h+t2xTBz5yt2YIO+1VMIIGlCU7gyp2LYOFvaV1nwOXU=";
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
                cargoLock.lockFile = ./Cargo.lock;
                cargoHash = pkgs.lib.fakeSha256;
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
          rootless-keyring-quota-test = import ./nix/tests/rootless-keyring-quota-test.nix {
            inherit pkgs basil;
          };
          basil-agent-schema3-test = import ./nix/tests/basil-agent-schema3-test.nix {
            inherit pkgs basil;
            nixosSystem = inputs.nixpkgs.lib.nixosSystem;
          };

          # Distribution build for the `.deb`: the two shipped binaries plus the
          # roff man pages the `xtask` crate emits (via `clap_mangen`). Scoped to
          # the two packages so no test suite runs and no example binaries leak
          # in. Pages land gzipped under `share/man/man1`, ready to drop into
          # `/usr/share/man/man1`.
          basilDist = mkBasil {
            pname = "basil-dist";
            cargoBuildFlags = [
              "-p"
              "basil-bin"
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
            # A `docker load`- and `podman load`-ready image archive built with
            # `buildLayeredImage`. Both runtimes accept this format directly, so
            # there is no skopeo/`oci-archive` conversion step:
            #   nix build .#basil-oci-thin
            #   docker load < result        # or: podman load < result
            #   docker run --rm basil:<version>-<arch> --help   # e.g. -amd64
            # LOAD it, never `docker import`/`podman import`, which build an image
            # from a bare rootfs and discard the entrypoint/config, leaving an image
            # that runs nothing. To publish it as OCI on the wire, push the same
            # artifact with `skopeo copy docker-archive:result docker://<registry>`.
            basil-oci-thin = pkgs.dockerTools.buildLayeredImage {
              name = "basil";
              tag = "${workspace_version}-${dockerArch}";
              contents = pkgs.buildEnv {
                name = "basil-thin-root";
                paths = [ basil ];
                pathsToLink = [ "/bin" ];
              };
              config = {
                Entrypoint = [ "/bin/basil" ];
                WorkingDir = "/";
                Labels = {
                  "org.opencontainers.image.description" = "Basil broker and client CLI";
                  "org.opencontainers.image.source" = "https://github.com/openbasil/basil";
                  "org.opencontainers.image.title" = "basil";
                  "org.opencontainers.image.version" = workspace_version;
                };
              };
            };

            # The interactive trial image: `docker run -it basil-playground:<tag>`
            # runs the self-contained `basil demo` (built-in db-keystore backend,
            # no external services), restarts the demo broker, and drops into a
            # shell with BASIL_SOCKET set so the visitor can try commands
            # immediately. This is the zero-install trial path for people who
            # won't install anything; load it like basil-oci-thin above.
            #   nix build .#basil-playground-oci
            #   docker load < result
            #   docker run --rm -it basil-playground:<version>-<arch>
            basil-playground-oci =
              let
                entry = pkgs.writeShellApplication {
                  name = "basil-playground";
                  text = ''
                    basil demo --dir /tmp/basil-demo --force "$@"
                    export BASIL_SOCKET=/tmp/basil-demo/basil.sock
                    basil agent --config /tmp/basil-demo/basil-agent.toml \
                      > /tmp/basil-demo/agent.log 2>&1 &
                    for _ in $(seq 1 100); do
                      [ -S "$BASIL_SOCKET" ] && break
                      sleep 0.1
                    done
                    echo
                    echo "The demo broker is running again and BASIL_SOCKET is set."
                    echo "Try: basil status | basil list | basil sign --key-id demo.signing_key 'hi'"
                    exec bash -i
                  '';
                };
              in
              pkgs.dockerTools.buildLayeredImage {
                name = "basil-playground";
                tag = "${workspace_version}-${dockerArch}";
                contents = pkgs.buildEnv {
                  name = "basil-playground-root";
                  paths = [
                    basil
                    entry
                    pkgs.bashInteractive
                    pkgs.coreutils
                  ];
                  pathsToLink = [ "/bin" ];
                };
                config = {
                  Entrypoint = [ "/bin/basil-playground" ];
                  WorkingDir = "/";
                  Env = [ "PATH=/bin" ];
                  Labels = {
                    "org.opencontainers.image.description" =
                      "Basil guided-tour playground: basil demo plus an interactive shell";
                    "org.opencontainers.image.source" = "https://github.com/openbasil/basil";
                    "org.opencontainers.image.title" = "basil-playground";
                    "org.opencontainers.image.version" = workspace_version;
                  };
                };
              };

            # A Debian package assembled with `dpkg-deb` (no ruby/fpm): the two
            # binaries under `/usr/bin` and the gzipped man pages under
            # `/usr/share/man/man1`, from the single `basilDist` build. The arch
            # is carried in the filename (`basil_<version>_<arch>.deb`) since we
            # publish one package per build platform, no multi-arch. Built from
            # nix-store binaries, so the runtime linker paths point at the nix
            # store; see CHANGELOG for the portability caveat.
            #   nix build .#basil-deb
            #   dpkg-deb --contents result/*.deb
            basil-deb =
              pkgs.runCommand "basil-deb-${workspace_version}-${dockerArch}"
                {
                  nativeBuildInputs = [ pkgs.dpkg ];
                  meta = {
                    description = "Debian package for the Basil broker and NATS bridge (${dockerArch}).";
                  };
                }
                ''
                  root="$TMPDIR/basil-deb"
                  mkdir -p "$root/DEBIAN" "$root/usr/bin" "$root/usr/share/man/man1"

                  install -Dm755 ${basilDist}/bin/basil "$root/usr/bin/basil"
                  install -Dm755 ${basilDist}/bin/basil-nats-bridge "$root/usr/bin/basil-nats-bridge"
                  cp ${basilDist}/share/man/man1/*.1.gz "$root/usr/share/man/man1/"

                  {
                    echo "Package: basil"
                    echo "Version: ${workspace_version}"
                    echo "Section: utils"
                    echo "Priority: optional"
                    echo "Architecture: ${dockerArch}"
                    echo "Maintainer: Basil maintainers <info@openbasil.org>"
                    echo "Homepage: https://github.com/openbasil/basil"
                    echo "Depends: libc6"
                    echo "Description: Basil, a host-local secrets broker: your app never touches the key"
                    echo " Basil brokers cryptographic operations, workload identity (SPIFFE),"
                    echo " and short-lived leases, with keys kept in the backend and used in"
                    echo " place. Ships the unified basil broker/CLI and the basil-nats-bridge"
                    echo " NATS courier, plus their man pages."
                  } > "$root/DEBIAN/control"

                  mkdir -p "$out"
                  dpkg-deb --root-owner-group --build "$root" \
                    "$out/basil_${workspace_version}_${dockerArch}.deb"
                '';
          };
          devShells.default = pkgs.mkShell {
            nativeBuildInputs = shellTools ++ [ toolchain ];
          };
          devShells.nightly = pkgs.mkShell {
            nativeBuildInputs = shellTools ++ [ toolchainNightly ];
          };
          checks.basil-agent-schema3 = basil-agent-schema3-test;
        }
        # Linux-only: nixosTest builds NixOS guest VMs, which only make sense on
        # Linux systems. Keep them outside `checks` so `nix flake check` remains
        # lightweight. The rootless-keyring-quota lane is x86_64-only; build it as
        # `nix build .#tests.x86_64-linux.rootless-keyring-quota`.
        // lib.optionalAttrs (lib.hasSuffix "linux" system) {
          tests = {
            tpm-unlock = tpm-unlock-test;
          }
          // lib.optionalAttrs (system == "x86_64-linux") {
            rootless-keyring-quota = rootless-keyring-quota-test;
          };
        }
      );
}
