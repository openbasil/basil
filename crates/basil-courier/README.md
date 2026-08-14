<!--
SPDX-FileCopyrightText: 2026 OpenBasil Contributors

SPDX-License-Identifier: Apache-2.0
-->

# basil-courier

`basil-courier` is the shared local transport used by Basil's network-facing
invocation couriers. It connects only to a Linux Unix-domain socket whose path,
owners, permissions, socket identity, and kernel-reported peer UID match an
operator-supplied policy.

The connector walks the socket path from `/` with descriptor-relative,
no-follow opens. It connects through the pinned final-directory descriptor,
checks the socket device and inode before and after connecting, and checks
`SO_PEERCRED`. Tonic runs the complete procedure again whenever its channel
reconnects. Platforms without the required Linux `/proc/self/fd` behavior fail
with `UnsupportedPlatform`.

`InvocationCourierClient` exposes only challenge issuance and sealed
invocation. It verifies the local listener's capability response at startup and
immediately before each forwarded call. A host, unknown, optional-freshness, or
wrong-version listener is rejected.

`InvocationOnlyClient` preserves local invocation-only NATS compatibility over
the same trusted connector. It accepts only a Host listener with optional
freshness and exposes only sealed invocation.
