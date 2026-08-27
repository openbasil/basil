# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
#
# SPDX-License-Identifier: Apache-2.0

{
  pkgs,
  upstream,
  masterUpstream,
}:

let
  pins = builtins.fromJSON (builtins.readFile ./pins.json);
  patch = ./nix-external-signer.patch;
  componentsPackagingPatch = ./nix-components-packaging.patch;
  masterCompatibilityPatch = ./nix-master-compat.patch;
  externalSignerPatchPin = builtins.elemAt pins.patchSeries 0;
  componentsPackagingPatchPin = builtins.elemAt pins.patchSeries 1;
  masterCompatibilityPatchPin = pins.compatibility.patch;
  basilPathInfoCorpus = ../../crates/basil-tests/fixtures/nix-cache-signing/path-info-v1.json;
  basilNarinfoCorpus = ../../crates/basil-tests/fixtures/nix-cache-signing/narinfo-fidelity.json;
  expectedAddedPaths = [
    "src/libutil-tests/external-signer.cc"
    "src/libutil/include/nix/util/signature/external-signer.hh"
    "src/libutil/signature/external-signer.cc"
    "tests/functional/external-signing.sh"
    "tests/functional/nix-cache-signing/DIGESTS"
    "tests/functional/nix-cache-signing/external-signer.py"
    "tests/functional/nix-cache-signing/path-info-v1.json"
    "tests/functional/nix-cache-signing/validate-path-info-v1.py"
  ];
  expectedModifiedPaths = [
    "src/libutil-tests/meson.build"
    "src/libutil/include/nix/util/meson.build"
    "src/libutil/meson.build"
    "src/nix/sigs.cc"
    "tests/functional/meson.build"
  ];
  expectedSemanticPaths = expectedAddedPaths ++ expectedModifiedPaths;
  strictPatchFlags = [
    "-p1"
    "--fuzz=0"
  ];

  platformTable = {
    x86_64-linux = {
      tier = "preview";
      production = false;
      qualification = {
        mode = "native-full-build";
        status = "passed";
        testedAt = "2026-08-04";
      };
    };
    aarch64-linux = {
      tier = "preview";
      production = false;
      qualification = {
        mode = "native-full-build";
        status = "pending";
        testedAt = null;
      };
    };
    aarch64-darwin = {
      tier = "development";
      production = false;
      qualification = {
        mode = "evaluation-only";
        status = "passed";
        testedAt = "2026-08-04";
      };
    };
  };
  platform =
    platformTable.${pkgs.stdenv.hostPlatform.system}
      or (throw "the patched Nix pilot does not support ${pkgs.stdenv.hostPlatform.system}");

  checked =
    assert upstream.rev == pins.upstream.baseRev;
    assert upstream.narHash == pins.upstream.baseNarHash;
    assert builtins.length pins.patchSeries == 2;
    assert externalSignerPatchPin.order == 1;
    assert externalSignerPatchPin.path == "nix-external-signer.patch";
    assert componentsPackagingPatchPin.order == 2;
    assert componentsPackagingPatchPin.path == "nix-components-packaging.patch";
    assert builtins.hashFile "sha256" patch == externalSignerPatchPin.sha256;
    assert builtins.hashFile "sha256" componentsPackagingPatch == componentsPackagingPatchPin.sha256;
    assert builtins.hashFile "sha256" basilPathInfoCorpus == pins.corpora.pathInfoV1Sha256;
    assert builtins.hashFile "sha256" basilNarinfoCorpus == pins.corpora.narinfoFidelitySha256;
    assert (map (entry: entry.path) pins.semanticEquivalence.addedFiles) == expectedAddedPaths;
    assert pins.semanticEquivalence.modifiedFiles == expectedModifiedPaths;
    true;

  masterChecked =
    assert masterUpstream.rev == pins.compatibility.officialMasterTestedRev;
    assert masterUpstream.narHash == pins.compatibility.officialMasterTestedNarHash;
    assert masterCompatibilityPatchPin.path == "nix-master-compat.patch";
    assert builtins.hashFile "sha256" masterCompatibilityPatch == masterCompatibilityPatchPin.sha256;
    true;

  componentsWithDefaultPatchFlags =
    assert checked;
    (pkgs.nixComponents2.overrideSource upstream).appendPatches [
      patch
      componentsPackagingPatch
    ];

  enforceStrictPatchFlags =
    sourceComponents:
    sourceComponents.overrideScope (
      _final: previous: {
        patchedSrc = previous.patchedSrc.overrideAttrs (old: {
          patchFlags = strictPatchFlags;
          passthru = (old.passthru or { }) // {
            basilPatchFlags = strictPatchFlags;
          };
        });
      }
    );

  componentsWithSource = enforceStrictPatchFlags componentsWithDefaultPatchFlags;

  # overrideSource deliberately ignores packaging expressions from the source
  # tree. Supply the patched test's dependency and corpus environment in the
  # component scope.
  withTestInputs =
    sourceComponents:
    sourceComponents.overrideScope (
      _final: previous: {
        nix-functional-tests = previous.nix-functional-tests.overrideAttrs (old: {
          nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [ pkgs.python3 ];
          buildInputs = (old.buildInputs or [ ]) ++ [ pkgs.libsodium ];
          LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [ pkgs.libsodium ];
          DYLD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [ pkgs.libsodium ];
        });
        nix-util-tests = previous.nix-util-tests.overrideAttrs (old: {
          buildInputs = (old.buildInputs or [ ]) ++ [ pkgs.libsodium ];
          passthru = (old.passthru or { }) // {
            tests = pkgs.lib.mapAttrs (
              _name: test:
              test.overrideAttrs (testOld: {
                buildCommand = ''
                  export _NIX_TEST_EXTERNAL_SIGNER_CORPUS=${sourceComponents.patchedSrc}/tests/functional/nix-cache-signing/path-info-v1.json
                  ${testOld.buildCommand}
                '';
              })
            ) (old.passthru.tests or { });
          };
        });
      }
    );

  components = withTestInputs componentsWithSource;
  masterComponentsWithDefaultPatchFlags =
    assert masterChecked;
    (pkgs.nixComponents2.overrideSource masterUpstream).appendPatches [ masterCompatibilityPatch ];
  masterComponentsWithSource = enforceStrictPatchFlags masterComponentsWithDefaultPatchFlags;
  masterComponents = withTestInputs masterComponentsWithSource;

  strictSourcesChecked =
    assert components.patchedSrc.drvAttrs.patchFlags == strictPatchFlags;
    assert components.patchedSrc.passthru.basilPatchFlags == strictPatchFlags;
    assert masterComponents.patchedSrc.drvAttrs.patchFlags == strictPatchFlags;
    assert masterComponents.patchedSrc.passthru.basilPatchFlags == strictPatchFlags;
    assert components.nix-cli.drvAttrs.src.outPath == components.patchedSrc.outPath;
    assert components.nix-functional-tests.drvAttrs.src.outPath == components.patchedSrc.outPath;
    assert components.nix-util-tests.drvAttrs.src.outPath == components.patchedSrc.outPath;
    assert masterComponents.nix-cli.drvAttrs.src.outPath == masterComponents.patchedSrc.outPath;
    assert
      masterComponents.nix-functional-tests.drvAttrs.src.outPath == masterComponents.patchedSrc.outPath;
    assert masterComponents.nix-util-tests.drvAttrs.src.outPath == masterComponents.patchedSrc.outPath;
    true;

  manifestData = {
    schema = "basil-nix-pilot-v1";
    inherit (pins)
      upstream
      patchSeries
      corpora
      compatibility
      semanticEquivalence
      ;
    platform = {
      system = pkgs.stdenv.hostPlatform.system;
      inherit (platform) tier production qualification;
    };
    outputs = {
      cli = "nix-pilot-cli";
      full = "nix-pilot-full";
    };
    defaultReplacement = false;
    releaseArtifact = false;
    sourcePatchFlags = strictPatchFlags;
  };
  manifest = pkgs.writeText "basil-nix-pilot-manifest.json" (builtins.toJSON manifestData);

  mkPilot =
    pname: package:
    assert strictSourcesChecked;
    let
      pilot = package.overrideAttrs (previous: {
        inherit pname;
        nativeBuildInputs = (previous.nativeBuildInputs or [ ]) ++ [ provenance ];
        passthru = (previous.passthru or { }) // {
          basilPilot = manifestData;
          effectivePatchFlags = components.patchedSrc.drvAttrs.patchFlags;
          effectivePatchedSource = components.patchedSrc;
          provenance = provenance;
        };
        meta = (previous.meta or { }) // {
          description = "Opt-in Nix 2.36.0 external-signer pilot (${platform.tier} tier)";
          platforms = builtins.attrNames platformTable;
        };
      });
    in
    assert builtins.any (input: input.outPath == provenance.outPath) (
      pilot.drvAttrs.nativeBuildInputs or [ ]
    );
    pilot;

  assertContextHunks = ''
    assert_context_hunks() {
      awk '
        function finish_hunk() {
          if (active && !new_file && context < 3) {
            print "hunk has fewer than three context lines in " FILENAME > "/dev/stderr"
            bad = 1
          }
          active = 0
        }
        /^diff --git / {
          finish_hunk()
          new_file = 0
          next
        }
        /^new file mode / {
          new_file = 1
          next
        }
        /^@@ / {
          finish_hunk()
          active = 1
          context = 0
          next
        }
        active && /^ / { context += 1 }
        END {
          finish_hunk()
          exit bad
        }
      ' "$1"
    }
  '';

  expectedPathAssertion = canonicalPatches: compatibilityPatch: ''
    pilot_expected_paths="$TMPDIR/expected-paths"
    printf '%s\n' ${pkgs.lib.escapeShellArgs expectedSemanticPaths} | sort > "$pilot_expected_paths"
    sed -n 's|^diff --git a/\([^ ]*\) b/.*|\1|p' ${canonicalPatches} \
      | sort -u > "$TMPDIR/canonical-paths"
    cmp "$pilot_expected_paths" "$TMPDIR/canonical-paths"
    ${pkgs.lib.optionalString (compatibilityPatch != null) ''
      sed -n 's|^diff --git a/\([^ ]*\) b/.*|\1|p' ${compatibilityPatch} \
        | sort -u > "$TMPDIR/compatibility-paths"
      cmp "$pilot_expected_paths" "$TMPDIR/compatibility-paths"
    ''}
  '';

  masterFull =
    assert strictSourcesChecked;
    masterComponents.nix-everything.overrideAttrs (previous: {
      pname = "nix-pilot-master-compat-full";
      meta = (previous.meta or { }) // {
        description = "Compatibility-only build of the Basil external-signer patch on recorded Nix master";
      };
    });

  provenance =
    assert strictSourcesChecked;
    pkgs.runCommand "basil-nix-pilot-provenance"
      {
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.diffutils
          pkgs.gawk
          pkgs.gnupatch
        ];
        passthru = {
          basilPilot = manifestData;
          effectivePatchFlags = components.patchedSrc.drvAttrs.patchFlags;
          effectivePatchedSource = components.patchedSrc;
        };
      }
      ''
        ${assertContextHunks}
        assert_context_hunks ${patch}
        assert_context_hunks ${componentsPackagingPatch}
        ${expectedPathAssertion "${patch} ${componentsPackagingPatch}" null}

        test "$(wc -c < ${patch})" = "${toString externalSignerPatchPin.bytes}"
        test "$(wc -l < ${patch})" = "${toString externalSignerPatchPin.lines}"
        test "$(sha256sum ${patch} | cut -d ' ' -f 1)" = "${externalSignerPatchPin.sha256}"
        test "$(wc -c < ${componentsPackagingPatch})" = "${toString componentsPackagingPatchPin.bytes}"
        test "$(wc -l < ${componentsPackagingPatch})" = "${toString componentsPackagingPatchPin.lines}"
        test \
          "$(sha256sum ${componentsPackagingPatch} | cut -d ' ' -f 1)" \
          = "${componentsPackagingPatchPin.sha256}"

        pilot_reconstructed="$TMPDIR/pilot-reconstructed"
        mkdir -p "$pilot_reconstructed"
        cp -a ${upstream.outPath}/. "$pilot_reconstructed/"
        chmod -R u+w "$pilot_reconstructed"
        patch --fuzz=0 -d "$pilot_reconstructed" -p1 --batch -i ${patch}
        patch --fuzz=0 -d "$pilot_reconstructed" -p1 --batch -i ${componentsPackagingPatch}
        diff -qr --no-dereference "$pilot_reconstructed" ${components.patchedSrc}

        test "$(cat "$pilot_reconstructed/.version")" = "${pins.upstream.version}"
        test \
          "$(sha256sum "$pilot_reconstructed/tests/functional/nix-cache-signing/path-info-v1.json" | cut -d ' ' -f 1)" \
          = "${pins.corpora.pathInfoV1Sha256}"
        cmp \
          ${basilPathInfoCorpus} \
          "$pilot_reconstructed/tests/functional/nix-cache-signing/path-info-v1.json"
        test \
          "$(sha256sum ${basilNarinfoCorpus} | cut -d ' ' -f 1)" \
          = "${pins.corpora.narinfoFidelitySha256}"

        mkdir -p "$out"
        cp ${manifest} "$out/pins.json"
      '';

  masterCompatibility =
    assert strictSourcesChecked;
    pkgs.runCommand "basil-nix-pilot-master-compatibility"
      {
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.diffutils
          pkgs.gawk
          pkgs.gnugrep
          pkgs.gnupatch
          pkgs.gnused
        ];
        passthru = {
          basilPilot = manifestData;
          effectivePatchFlags = masterComponents.patchedSrc.drvAttrs.patchFlags;
          effectivePatchedSource = masterComponents.patchedSrc;
          testedRevision = pins.compatibility.officialMasterTestedRev;
        };
      }
      ''
        ${assertContextHunks}
        assert_context_hunks ${patch}
        assert_context_hunks ${componentsPackagingPatch}
        assert_context_hunks ${masterCompatibilityPatch}
        ${expectedPathAssertion "${patch} ${componentsPackagingPatch}" masterCompatibilityPatch}

        test "$(wc -c < ${masterCompatibilityPatch})" = "${toString masterCompatibilityPatchPin.bytes}"
        test "$(wc -l < ${masterCompatibilityPatch})" = "${toString masterCompatibilityPatchPin.lines}"
        test \
          "$(sha256sum ${masterCompatibilityPatch} | cut -d ' ' -f 1)" \
          = "${masterCompatibilityPatchPin.sha256}"

        pilot_base_reconstructed="$TMPDIR/base-reconstructed"
        pilot_master_reconstructed="$TMPDIR/master-reconstructed"
        mkdir -p "$pilot_base_reconstructed" "$pilot_master_reconstructed" "$TMPDIR/deltas"
        cp -a ${upstream.outPath}/. "$pilot_base_reconstructed/"
        cp -a ${masterUpstream.outPath}/. "$pilot_master_reconstructed/"
        chmod -R u+w "$pilot_base_reconstructed" "$pilot_master_reconstructed"
        patch --fuzz=0 -d "$pilot_base_reconstructed" -p1 --batch -i ${patch}
        patch --fuzz=0 -d "$pilot_base_reconstructed" -p1 --batch -i ${componentsPackagingPatch}
        if patch --fuzz=0 --dry-run -d ${masterUpstream.outPath} -p1 --batch -i ${patch}; then
          echo "canonical base patch unexpectedly applies to recorded master" >&2
          exit 1
        fi
        patch --fuzz=0 -d "$pilot_master_reconstructed" -p1 --batch -i ${masterCompatibilityPatch}
        diff -qr --no-dereference "$pilot_base_reconstructed" ${components.patchedSrc}
        diff -qr --no-dereference "$pilot_master_reconstructed" ${masterComponents.patchedSrc}

        ${pkgs.lib.concatMapStringsSep "\n" (entry: ''
          test \
            "$(sha256sum "$pilot_base_reconstructed/${entry.path}" | cut -d ' ' -f 1)" \
            = "${entry.sha256}"
          test \
            "$(sha256sum "$pilot_master_reconstructed/${entry.path}" | cut -d ' ' -f 1)" \
            = "${entry.sha256}"
          ${if entry.executable then "test -x" else "test ! -x"} \
            "$pilot_base_reconstructed/${entry.path}"
          ${if entry.executable then "test -x" else "test ! -x"} \
            "$pilot_master_reconstructed/${entry.path}"
        '') pins.semanticEquivalence.addedFiles}

        normalize_delta() {
          pilot_before="$1"
          pilot_after="$2"
          pilot_output="$3"
          if diff --unified=0 "$pilot_before" "$pilot_after" > "$pilot_output.raw"; then
            echo "expected a semantic delta for $pilot_before" >&2
            return 1
          else
            pilot_status=$?
            test "$pilot_status" -eq 1
          fi
          tail -n +3 "$pilot_output.raw" | sed '/^@@ /d' > "$pilot_output"
        }

        for pilot_file in ${pkgs.lib.escapeShellArgs expectedModifiedPaths}; do
          pilot_name="$(printf '%s' "$pilot_file" | tr / _)"
          normalize_delta \
            "${upstream.outPath}/$pilot_file" \
            "$pilot_base_reconstructed/$pilot_file" \
            "$TMPDIR/deltas/base-$pilot_name"
          normalize_delta \
            "${masterUpstream.outPath}/$pilot_file" \
            "$pilot_master_reconstructed/$pilot_file" \
            "$TMPDIR/deltas/master-$pilot_name"
          cmp "$TMPDIR/deltas/base-$pilot_name" "$TMPDIR/deltas/master-$pilot_name"
        done

        test -e ${provenance}/pins.json
        test -x ${masterFull}/bin/nix
        ${masterFull}/bin/nix --version > "$TMPDIR/master-version"
        ${masterFull}/bin/nix store sign --help | grep --fixed-strings -- '--signer-socket' > /dev/null

        mkdir -p "$out"
        cp "$TMPDIR/master-version" "$out/nix-version"
        cp ${manifest} "$out/pins.json"
      '';
in
{
  inherit
    components
    manifest
    masterCompatibility
    provenance
    ;
  cli = mkPilot "nix-pilot-cli" components.nix-cli;
  full = mkPilot "nix-pilot-full" components.nix-everything;
}
