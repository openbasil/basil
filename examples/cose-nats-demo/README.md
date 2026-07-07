<!--
SPDX-FileCopyrightText: 2026 OpenBasil Contributors

SPDX-License-Identifier: Apache-2.0
-->

# COSE over NATS Demo

This example runs an Alice/Bob peer messaging flow over NATS using the current
`basil-cose` sealed-message helpers.

Run from the repository root:

```bash
examples/cose-nats-demo/run.sh
```

The script builds `basil`, `basil-nats-bridge`, and the local demo binary, then
starts:

- an OpenBao dev server with transit and KV-v2 enabled;
- `basil agent` with sealed invocation enabled;
- `nats-server`;
- `basil-nats-bridge` subscribed to `basil.invoke`.

Alice sends Bob a COSE signed-and-sealed peer message on NATS. Alice's peer
message signature is produced by a transit-backed `alice.sign` key through a
sealed invocation carried by `basil-nats-bridge`. Bob verifies Alice's COSE
signature, asks the broker to open the message with Bob's custodied X25519 key,
then replies with a transit-backed `bob.sign` COSE message sealed to Alice.
Alice verifies and opens the reply through the broker.

Runtime files are written under `/tmp/basil-cose-nats-demo` by default. Override
any of these optional settings:

- `BASIL_COSE_NATS_DEMO_WORKDIR` (default `/tmp/basil-cose-nats-demo`)
- `BASIL_COSE_NATS_DEMO_VAULT_ADDR` (default `http://127.0.0.1:8228`)
- `BASIL_COSE_NATS_DEMO_VAULT_TOKEN` (default `root`, used only for the dev
  OpenBao setup and not inherited by `basil`, the bridge, or the demo binary)
- `BASIL_COSE_NATS_DEMO_NATS_PORT` (default `4229`)
- `BASIL_COSE_NATS_DEMO_NATS_URL` (default `nats://127.0.0.1:$NATS_PORT`)
- `BASIL_COSE_NATS_DEMO_BRIDGE_SUBJECT` (default `basil.invoke`)
- `BASIL_BIN` (path to a prebuilt `basil` binary; otherwise built from the repo
  root)
- `BASIL_NATS_BRIDGE_BIN` (path to a prebuilt `basil-nats-bridge`; otherwise
  built from the repo root)

Required commands on `PATH`: `bao`, `nats-server`, and `cargo`.

## Expected output

```
== build ==
== openbao ==
== nats ==
== agent ==
== bridge ==
== demo ==
bob verified Alice message: hello Bob - signed through the NATS bridge
alice verified Bob reply: hello Alice - Bob verified your message
demo completed
workdir: /tmp/basil-cose-nats-demo
PASS
```
