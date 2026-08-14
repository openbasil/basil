<!--
SPDX-FileCopyrightText: 2026 OpenBasil Contributors

SPDX-License-Identifier: Apache-2.0
-->

# Basil HTTPS courier

`basil-https-courier` is the opt-in Internet-facing transport for Basil sealed
invocations. It accepts only freshness challenges and opaque sealed invocation
messages, then forwards them to a verified local `courier` listener through the
hardened Unix-socket connector in `basil-courier`.

The process has no broker, administration, reflection, or health route. Run it
under a dedicated UID with access only to the courier socket and its optional
bearer file.

## Listener modes

Direct mode terminates `rustls` TLS and derives the admission source from the
TCP peer. Trusted-proxy mode serves plaintext HTTP on a loopback bind, accepts
only the configured loopback proxy address, requires one canonical
`X-Forwarded-For` address, and requires bearer admission. The bearer reduces
anonymous traffic; it grants no Basil operation or key authority.

```toml
bind = "127.0.0.1:8443"
bearer-file = "/run/credentials/basil-https-courier/bearer"

[listener]
mode = "trusted-proxy"
proxy-address = "127.0.0.1"

[basil]
socket-path = "/run/basil/courier.sock"
service-owner-uid = 991
directory-owner-uid = 991
directory-mode = 488 # 0750
socket-owner-uid = 990
socket-mode = 432 # 0660
expected-peer-uid = 990
```

Direct TLS replaces the listener block:

```toml
[listener]
mode = "direct-tls"
certificate-file = "/run/credentials/basil-https-courier/tls.crt"
private-key-file = "/run/credentials/basil-https-courier/tls.key"
```

The private-key path must be absolute and normalized, with no repeated
separators, dot components, trailing separator, or symlink components. The key
must be a single-link regular file owned by the courier UID, readable by its
owner, and inaccessible to group and other users. Basil reads it through a
pinned descriptor and rejects replacement during startup.

All limits have finite defaults and compiled maxima. A configured value must be
nonzero and no greater than its maximum. Requests beyond connection,
admission, framing, header, body, rate, or deadline bounds fail without waiting
for broker capacity. Every HTTP response carries `Cache-Control: no-store`.
`limits.in-flight` remains the total forwarding ceiling. Challenge forwarding
can use at most `in-flight - 1` permits, which reserves one permit for an
invocation that already holds a challenge. Setting `in-flight = 1` therefore
makes the listener invocation-only and declines challenge forwarding. The
courier acquires that route permit before changing rate state. Challenge
admission also leaves one global token, one token in its source bucket, and one
retained-source slot for Invoke. A burst or `source-buckets` value of 1 is
therefore Invoke-only at that limit. Declined challenge admission does not
consume a token, advance a refill timestamp, or add a source bucket.
In trusted-proxy mode, a connection limit greater than one reserves one of
those slots for a bounded overload response; request and overload sockets
together never exceed the configured connection limit.

Start the courier with `basil-https-courier --config PATH`. Startup fails unless
the local listener reports the `COURIER`, mandatory-challenge, protocol-v1
capability tuple; that tuple is checked again before every forwarded call.

## Installation

The HTTPS courier ships as the separate `basil-https-courier` executable in
release archives and the Debian, Arch, and Nix packages. It is not part of the
`basil agent` process; install it only on an Internet-facing host configured to
use the sealed-invocation courier boundary.
