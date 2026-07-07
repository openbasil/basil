<!--
SPDX-FileCopyrightText: 2026 OpenBasil Contributors

SPDX-License-Identifier: Apache-2.0
-->

# basil-nats-bridge

`basil-nats-bridge` is a NATS request/reply courier for Basil sealed invocation
messages. It subscribes to one NATS subject, accepts raw tagged COSE bytes,
wraps those bytes in Basil's thin [`SealedRequest` gRPC](https://docs.openbasil.org/clients/sealed-invocations/) carrier over the
configured Unix socket, and publishes raw tagged COSE response bytes.

The bridge does not decrypt request or response bodies. Actor authorization
remains inside Basil's sealed-message and operation policy path; the bridge is
authorized only as the local Basil socket presenter.

This crate ships the separate `basil-nats-bridge` binary. It is not part of the
`basil agent` process and it does not replace local Unix-socket gRPC clients.

```toml
[nats]
url = "nats://127.0.0.1:4222"
creds = "/run/basil/bridge.creds"

[basil]
socket = "/run/basil/basil.sock"

[bridge]
request-subject = "basil.invocation"
queue-group = "basil-bridge"
max-message-bytes = 1048576
```

`creds`, `queue-group`, and `max-message-bytes` may be omitted.

## Policy

The bridge process needs no policy grant of its own. There is no transport-level
`op:invoke` action in the policy language (a policy naming one fails to load);
the broker authorizes the *actor* inside the sealed message, never the process
that delivered it:

- the sealed request's actor proof (its `signature-key` subject) must verify;
- the actor needs `op:decrypt` on the request-encryption key the message is
  sealed to;
- the actor needs the operation-specific grant for the inner request (for
  example `op:sign` on the target key).

```json
{
	"subjects": {
		"content.publisher": {
			"allOf": [
				{
					"kind": "signature-key",
					"algorithm": "nats-nkey",
					"public": "UANATS_PUBLIC_NKEY"
				}
			]
		}
	},
	"rules": [
		{
			"id": "publisher-can-use-invocation-signing",
			"subjects": ["content.publisher"],
			"action": ["op:decrypt", "op:sign"],
			"target": ["broker.request_encryption.2026q3", "publisher.signing.2026q3"]
		}
	]
}
```

The bridge's own Unix identity is still recorded in the audit log as the
presenter (`presenter_*` fields) for operational context, but it carries no
data-plane authority: the bridge cannot `sign`, `get`, `import`, `mint`, or
decrypt anything, and an unsigned or tampered COSE message never authorizes.

## Message flow

1. A caller publishes raw tagged COSE request bytes to
   `bridge.request-subject` with a NATS reply subject.
2. The bridge checks only transport shape: reply subject, message size, and
   optional response-subject routing returned by Basil.
3. The bridge wraps the request bytes as `SealedRequest { message }` and
   forwards them to Basil `InvocationService.Invoke` over `basil.socket`.
4. Basil verifies the sealed actor proof, authorizes the actor, executes the
   requested operation, and returns `SealedResponse { message,
   response_subject }`.
5. The bridge publishes `SealedResponse.message` bytes unchanged to
   `SealedResponse.response_subject` when present, or otherwise to the NATS
   reply subject.

NATS request/reply inboxes are only transport correlation. Callers must still
verify and decrypt the sealed response before trusting any status or result.

Import-key request bodies and get-secret response bodies are opaque to the
bridge:

```text
NATS request payload: <tagged COSE_Sign1 request bytes>
NATS reply payload:   <tagged COSE_Sign1 response bytes>
```

The bridge does not inspect COSE protected headers, claims, plaintext body
schemas, signatures, ciphertexts, or request/response correlation claims. It is
a byte courier between NATS and Basil's local invocation gRPC service.

## Bridge errors

If Basil returns sealed response bytes, the bridge forwards them without
bridge error headers. Bridge-level failures that have no sealed Basil response
return an empty payload with these NATS headers when the request has a reply
subject:

| Header                   | Meaning                                            |
| ------------------------ | -------------------------------------------------- |
| `Basil-Bridge-Error`     | Stable bridge-level token.                         |
| `Basil-Bridge-Message`   | Operator-facing detail.                            |
| `Basil-Bridge-Retryable` | `true` when retrying the same request may succeed. |

Stable error tokens are `MALFORMED_REQUEST`, `MESSAGE_TOO_LARGE`,
`BASIL_UNAVAILABLE`, `BASIL_REJECTED`, `TIMEOUT`, and `INTERNAL`.

## Audit and boundaries

Bridged audit records keep actor and presenter separate. The actor is the sealed
invocation subject/proof; the presenter is the `basil-nats-bridge` process
attested by `SO_PEERCRED`. Audit records include the policy generation,
decision/outcome, target, transport proof summary, and presenter context.

There is no delegation, impersonation, legacy unsigned mode, or migration bridge
in this binary. Go sealed-invocation helper parity is deferred to a separate
follow-up; this binary only carries raw tagged COSE bytes on NATS.
