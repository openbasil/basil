<!--
SPDX-FileCopyrightText: 2026 OpenBasil Contributors

SPDX-License-Identifier: Apache-2.0
-->

# Cosign 3.1.1 conformance fixture

This directory preserves an official Sigstore keyless blob bundle and a real
offline pinned-key bundle produced by Cosign 3.1.1. Together they exercise both
verification modes without a Basil release credential, network access, or a
mutable trust download.

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

The pinned-key payload is an exact Cosign Simple Signing document for the
checked-in manifest and config chain. It was signed offline with the official Linux `amd64`
Cosign 3.1.1 release asset, SHA-256
`ae1ecd212663f3693ad9edf8b1a183900c9a52d3155ba6e354237f9a0f6463fc`,
and a signing configuration with no Fulcio, OIDC, Rekor, or timestamp service.
Only the public key and bundle are retained; the generated private key was
discarded. The authoritative file hashes are recorded in `index.json`.

Verify the fixture with the package-equivalent executable supplied explicitly:

```console
./verify.sh /home/user/.local/bin/cosign
```

The runner checks the official executable hash, its version, and every fixture
hash before invoking `verify-blob` for both keyless transparency evidence and
the explicitly transparency-optional pinned-key bundle.
