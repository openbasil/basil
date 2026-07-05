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
with:

```bash
BASIL_COSE_NATS_DEMO_WORKDIR=/tmp/my-demo examples/cose-nats-demo/run.sh
```

Required commands on `PATH`: `bao`, `nats-server`, and `cargo`.
