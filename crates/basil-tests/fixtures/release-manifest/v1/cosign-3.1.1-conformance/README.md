<!--
SPDX-FileCopyrightText: 2026 OpenBasil Contributors

SPDX-License-Identifier: Apache-2.0
-->

# Cosign 3.1.1 conformance fixture

This directory preserves an official Sigstore keyless blob bundle that the
Cosign 3.1.1 conformance workflow uses. It exercises the release-manifest
verifier's cryptographic boundary without requiring a Basil release credential,
network access, or a mutable trust download.

The payload and bundle come from `sigstore-conformance` commit
`21533cde107c734ebc153c3e3a24d75fc9811a36`. Cosign 3.1.1 pins that commit in
its conformance workflow at source commit
`7914231b348c4057891edeb321772aad3ed04fce`. The trusted root comes from the
exact `sigstore-go` 1.2.0 dependency source commit
`8ca80c47ef03d26ebf174db7c296700b075b2c16`.

The bundle uses Sigstore bundle media type 0.3, contains one Rekor entry, and
omits `timestampVerificationData`. Its certificate has the GitHub Actions OIDC
issuer and the exact conformance-beacon workflow identity recorded in
`index.json`. This identity is test evidence only; it is not authorized for
Basil production releases.

Verify the fixture with the package-equivalent executable supplied explicitly:

```console
./verify.sh /home/user/.local/bin/cosign
```

The runner checks every authoritative file hash and the executable version
before invoking `verify-blob` with the vendored trusted root and exact identity.

