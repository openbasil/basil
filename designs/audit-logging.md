# Audit Logging

Basil audit events are secret-free structured events. They are emitted through
`tracing`, may be mirrored to journald/stdout, may be exported as OpenTelemetry
logs, and authorization decisions may also be appended to the JSONL audit file
configured by `audit-log`.

## Event Shape

Every auditable event uses the same top-level shape:

```json
{
  "event": {
    "kind": "basil.audit.authz",
    "version": 1
  },
  "occurred_at": "2026-06-25T03:00:00Z",
  "op": "sign",
  "actor": {
    "kind": "unix_uid",
    "id": "svc-nats(9002)"
  },
  "target": {
    "kind": "catalog_key",
    "id": "nats.account"
  },
  "outcome": "allow",
  "reason": "user"
}
```

Required fields:

- `event.kind`: stable event type token.
- `event.version`: integer schema version for that event kind.
- `occurred_at`: UTC RFC3339 timestamp, seconds precision.
- `op`: stable operation token.
- `actor.kind`: actor identifier namespace. Today this is `unix_uid`.
- `actor.id`: actor value. Authorization events render this as `name(uid)` when
  the policy config knows the name, otherwise the bare uid.
- `target.kind`: target identifier namespace. Today this is `catalog_key`.
- `target.id`: catalog key name, or a synthetic catalog target for SPIFFE
  selection denials.
- `outcome`: stable outcome token.
- `reason`: stable reason token.

Optional fields:

- `via_group`: `name(gid)` for an authorization allow granted through a group.
- `target.version`: backend/catalog key version when known.
- Provider-operation details: `algorithm`, `provider`, and `custody`.

Audit events must never include request payloads, plaintexts, private keys,
signatures, ciphertexts, encapsulated keys, shared secrets, backend tokens, or
sealed bundle material.

## Auditable Events

### `basil.audit.authz`

Emitted for every PDP-gated broker operation, whether allowed or denied.

Current operation tokens:

- `get`
- `list`
- `get_public_key`
- `verify`
- `sign`
- `encrypt`
- `decrypt`
- `mint`
- `validate`
- `set`
- `rotate`
- `import`
- `new_key`

Current authorization outcomes:

- `allow`
- `deny`

Current allow reasons:

- `user`
- `group`
- `any_principal`
- `public_class`

Current deny reasons:

- `unknown_key`
- `not_writable`
- `not_permitted`
- `no_peer_uid`
- SPIFFE selection denials such as `not authorized to mint an X.509-SVID`,
  `no X.509-SVID issuer is configured`, `not authorized to mint a JWT-SVID`, and
  `no JWT-SVID issuer matches the requested SPIFFE ID`.

Sinks:

- `tracing`: always emitted.
- JSONL audit file: emitted when top-level `audit-log` is configured.
- stdout, journald, and OpenTelemetry: according to logging configuration.

### `basil.audit.provider_operation`

Secret-free provider-operation event for software-custodied provider decisions
and outcomes. The current helper shape is standardized for future durable
emission; the event is not yet attached to the JSONL audit writer.

Current operation tokens include provider-level names such as:

- `generate_key`
- `import_key`
- `sign`
- `verify`
- `encapsulate`
- `decapsulate`
- `wrap_envelope`
- `unwrap_envelope`

Current outcomes:

- `allow`
- `deny`
- `success`
- `failure`

Provider details:

- `algorithm`: algorithm token such as `ed25519`, `rs256`, or `ml-kem-768`.
- `provider`: `vault-transit` or `local-software`.
- `custody`: `backend-native` or `software-encrypted`.

## Logging Configuration

`basil-agent` initializes tracing from the TOML config file:

```toml
[logging.stdout]
enable = true

[logging.journald]
enable = true

[logging.opentelemetry]
enable = false
endpoint = "http://localhost:4317"
protocol = "grpc"
```

Defaults:

- `logging.stdout.enable = true`
- `logging.journald.enable = true`
- `logging.opentelemetry.enable = false`
- `logging.opentelemetry.protocol = "grpc"`

OpenTelemetry logging uses OTLP logs. Supported protocols:

- `grpc`
- `http-binary`
- `http-json`

When `logging.opentelemetry.enable = true`,
`logging.opentelemetry.endpoint` is required, must be non-empty, and must be a
valid `http` or `https` URL. Basil fails closed during startup on invalid OTLP
logging configuration.
