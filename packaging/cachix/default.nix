# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
#
# SPDX-License-Identifier: Apache-2.0

{
  lib,
  cachix,
  fetchFromGitHub,
}:

let
  externalSignerPatch = ./cachix-1.11.1-nxsg.patch;
  externalSignerPatchSha256 = builtins.hashFile "sha256" externalSignerPatch;
  expectedPatchSha256 = "9387c8b975750ca7d29a0466627f8eadc0af94cbdaf82f08624f807b18a33531";
  upstreamSource = fetchFromGitHub {
    owner = "cachix";
    repo = "cachix";
    rev = "v1.11.1";
    hash = "sha256-TuvKVBX60mqyMT6OB5JqVEh1YIWtFMR/igLCaCdC9tw=";
  };
in

assert lib.assertMsg (
  cachix.version == "1.11.1"
) "the Basil external-signer proposal is pinned to Cachix 1.11.1";

assert lib.assertMsg (
  externalSignerPatchSha256 == expectedPatchSha256
) "the Basil external-signer patch bytes do not match the reviewed digest";

cachix.overrideAttrs (old: {
  src = "${upstreamSource}/cachix";

  patches = (old.patches or [ ]) ++ [ externalSignerPatch ];

  passthru = (old.passthru or { }) // {
    basilExternalSigner = {
      protocol = "NXSG-1.0";
      patchSha256 = externalSignerPatchSha256;
      upstreamTag = "v1.11.1";
      upstreamSourceHash = "sha256-TuvKVBX60mqyMT6OB5JqVEh1YIWtFMR/igLCaCdC9tw=";
    };
  };
})
