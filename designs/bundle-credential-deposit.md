# Bundle credential deposit (public-key contribution)

Status: **implemented** (2026-07-03; br `basil-ey2u` / `basil-3p9l`). Extends
the sealed-bundle model in `designs/unlock-and-bundle.html` and the KMS work in
`designs/kms-transit-backends.md`.

Implementation notes:

- Deposit records are stored in the main bundle JSON body as a cleartext
  `deposits` section outside the payload AEAD, capped at 1024 records. The
  header, slots, payload, and deposits still travel as one bundle artifact.
- The sealed payload carries the X25519 ingest private key and contributor
  allow-list. `create --deposit-key OUT` generates and exports the public
  recipient. Exporting/creating a recipient for an existing bundle uses
  `bundle deposit-key --open ...` because only the private ingest identity is
  sealed.
- Contributor signing identities are raw 32-byte Ed25519 seed files with `0600`
  permissions. Public key tokens are base64url-nopad 32-byte keys. If no
  `--contributor-id` is supplied, the public key token is the contributor id.
- When more than one authorized current-epoch deposit targets one backend, Basil
  keeps the highest sequence and resolves ties deterministically by the later
  record. Promotion remains explicit.

## Problem

Today, adding or changing any backend credential in a sealed bundle goes through
`seal::reseal_payload` (the `bundle set-cred` flow): it **opens the bundle via an
unlock slot → recovers the symmetric master KEK → decrypts the whole payload →
swaps the cred → re-encrypts the whole payload**. So the party adding a
credential must hold an unlock secret (passphrase / bip39 / TPM / age-yubikey)
that decrypts the *entire* bundle.

That couples two capabilities that should be separate:

- **Contribute** a credential for one backend.
- **Read** every credential already in the bundle.

Concrete case: a bundle already holds an OpenBao unlock token (added by an
admin). We want a GCP admin to add a **GCP Cloud KMS service-account key**
without handing them the master unlock secret and thus read access to the
OpenBao token. The GCP credential is a structured JSON secret (see below), and
the person who holds it is not the person who administers the bundle.

An asymmetric *unlock slot* (like age-yubikey) does **not** solve this: a slot
key protects the master KEK, and recovering the KEK is all-or-nothing over the
monolithic payload. Handing out a slot's public key lets you neither read (can't
recover the KEK) nor write (can't get the KEK to re-seal). The lever we need is
**per-credential** public-key encryption, not per-slot.

## The credential shape we must carry: GCP service-account JSON

GCP KMS authenticates either via Application Default Credentials (ambient: the
current `BackendCred::GcpKms` assumes this and carries only non-secret
`project`/`location`/`key_ring`) **or** via a service-account key file, which is
a secret:

```json
{
	"type": "service_account",
	"project_id": "PROJECT",
	"private_key_id": "00000000000000000000000000000000",
	"private_key": "-----BEGIN PRIVATE KEY-----\n…1217 bytes…\n-----END PRIVATE KEY-----\n",
	"client_email": "PROJECT@PROJECT.iam.gserviceaccount.com",
	"token_uri": "https://oauth2.googleapis.com/token",
	"…": "…"
}
```

The `private_key` is a bearer RSA key: whoever has this JSON can mint GCP access
tokens. So the JSON belongs **sealed in the bundle**, not as a plaintext file on
disk, and it is exactly the kind of secret a GCP admin should be able to deposit
without reading the rest of the bundle.

### Prerequisite cred-shape change (independent of the deposit model)

`BackendCred::GcpKms` gains an **optional sealed** service-account JSON:

```rust
GcpKms {
    project: String,
    location: String,
    key_ring: String,
    /// Whole service-account JSON, sealed. `None` ⇒ Application Default
    /// Credentials (ambient GKE workload identity, metadata server, or gcloud).
    #[serde(default, skip_serializing_if = "Option::is_none", with = "secret_string_opt")]
    service_account_json: Option<SecretString>,
}
```

`GcpKmsBackend::new` uses it when present:

- present → `ClientConfig::default().with_credentials(creds).await` where `creds`
  is `google_cloud_auth::credentials::CredentialsFile` parsed from the JSON
  (verify the exact constructor: `serde_json::from_str::<CredentialsFile>` vs a
  crate `from_json`/`new_from_*` helper; the yoshidan client re-exports
  `google_cloud_auth`).
- absent → `with_auth()` (ADC), as today.

Store the **whole JSON blob** as one opaque `SecretString`: do not decompose it;
`CredentialsFile` is the parser. This change is useful on its own (ADC isn't
available in cross-cloud / CI / non-GKE deployments) and lands before the deposit
model. The deposit format below is credential-agnostic (it encrypts a serialized
`BackendCred`), so a fat GCP `service_account_json` rides through unchanged.

## Design: per-credential deposit ("drop box")

Add a second, **contribution** path alongside the existing admin-managed payload.
The monolithic payload is unchanged and remains the authoritative, KEK-protected
baseline; deposits are per-credential records that a contributor appends using
only a **public** ingest key.

### New bundle material

- **Ingest identity**: an X25519 (age) keypair.
  - Public recipient (`age1…`) is published freely (printed at `bundle init`,
    exportable any time). Encrypting to it is the only thing a contributor needs.
  - Private identity lives **inside the sealed payload** (KEK-protected, exactly
    like the admin creds). The broker recovers it after unlocking, as today.
- **Contributor allow-list** (admin-managed, also in the sealed payload):
  `contributor_key_id → { ed25519_pubkey, allowed_backend_ids: Set<String> }`.
  Only the bundle admin (with an unlock secret) edits this.
- **Deposit log**: a new bundle section, **outside** the payload AEAD (so it can
  be appended without the KEK). A `Vec<Deposit>`.

```
Deposit {
  backend_id: String,          // which backend this cred is for
  epoch: u64,                  // bundle generation this deposit targets
  seq: u64,                    // per-(contributor, backend_id) monotonic counter
  contributor_key_id: String,  // an allow-listed contributor
  sealed_cred: Vec<u8>,        // age(recipient, serialized BackendCred)
  signature: Vec<u8>,          // Ed25519 over (backend_id, epoch, seq, sealed_cred)
}
```

### Contribute (no unlock secret)

The contributor holds only: the ingest **recipient** public key + their own
Ed25519 **signing** key (whose public half the admin allow-listed).

1. Build the `BackendCred` (e.g. `GcpKms{…, service_account_json: <file>}`).
2. `sealed_cred = age.encrypt(recipient, serialize(cred))`.
3. `signature = ed25519.sign(contributor_sk, canonical(backend_id, epoch, seq, sealed_cred))`.
4. Append the `Deposit` to the bundle's deposit section.

They cannot read any other credential (no ingest private key, no KEK) and cannot
touch the payload / slots / header (no KEK).

### Startup merge (broker)

1. Unlock via a slot → recover KEK → decrypt payload → obtain admin creds, the
   **ingest private identity**, the **allow-list**, and the current **epoch**.
2. For each deposit, in order: contributor must be in the allow-list; verify the
   Ed25519 signature; `backend_id` must be in that contributor's
   `allowed_backend_ids`; `epoch` must match (reject stale generations); keep the
   highest `seq` per `(contributor, backend_id)` (anti-rollback / last-writer).
3. `age`-decrypt `sealed_cred` with the ingest identity → `BackendCred`.
4. Resolve the effective cred map. The deposit log is an **overlay of pending,
   authorized edits** on top of the sealed-payload baseline, *not* a competing
   store. For each `backend_id`, the effective cred is the newest **authorized**
   value: an allow-listed contributor's latest deposit **shadows** the baseline
   for that id. Reusing a `backend_id` is therefore a normal **replace / rotate**
   (e.g. a GCP admin rotating `gcp1`'s SA key), not a conflict.

**Authorization vs precedence** are two separate things:

- *Authorization* is the allow-list. A deposit for a `backend_id` the contributor
  is **not** allow-listed for is rejected: an authz failure, not a "conflict."
  This is also how an admin **pins** a cred as admin-only: simply don't delegate
  it (no contributor allow-listed → no deposit can touch it).
- *Precedence* (when both baseline and a deposit hold `backend_id`) is by
  **recency within the allow-listed scope**: the deposit is the live edit;
  `promote` commits it into the baseline. No "admin-payload-wins" rule is needed.
- *(Optional, niche)* a per-id `pinned` flag lets an admin **delegate but veto** a
  specific id (baseline wins even though a contributor is allow-listed). Not the
  default; omit unless a use case appears.

Invalid/unauthorized/unsigned deposits are **dropped, not fatal**: the broker
logs and continues (fail-closed for that one backend if nothing else supplies
it).

### Promote (admin, periodic): with review

`bundle promote` (needs an unlock secret): decrypt deposits, fold the reviewed
ones into the sealed payload, bump the epoch, and prune the deposit log. Promoted
creds become KEK-protected and authoritative; the epoch bump invalidates replays
of the now-consumed deposits.

**Promotion is ratification, so the admin must be able to see what they commit.**
A deposit that passed authz + signature can still be a bad *rotation* from an
allow-listed-but-compromised contributor (e.g. a `gcp1` SA key pointing at
attacker infra), which only a human eyeballing the change can catch. So:

- `promote --dry-run` (and `show --open`) print the pending set **before**
  committing: for each deposit, `backend_id`, contributor, `seq`/`epoch`, authorized?,
  signature valid?, and **new vs replace** against the current baseline.
- Each is shown with a **non-secret fingerprint**, never the secret. For a GCP
  service account that is its identity fields (`client_email`, `private_key_id`,
  `project_id`), exactly "which SA / did it change"; for opaque creds (tokens,
  DEKs) a `SHA-256` of the serialized cred.
- **Selective promote:** `promote --backend gcp1` / `--contributor alice` commits
  only the reviewed subset, not everything since last time.
- The promotion is audit-logged with provenance (who deposited each committed
  cred, at what `seq`/`epoch`).

Two visibility levels: `show` **without** unlock lists deposit *metadata* only
(plaintext records: `backend_id`, contributor, `seq`, `epoch`): it cannot check
authorization (allow-list is sealed) or read the cred (`age`-encrypted); `show
--open` / `promote --dry-run` add the authz check, signature verification, and the
fingerprints.

## Threat model / security

- **Contributor key compromise**, bounded: can deposit/replace creds only for
  its allow-listed `backend_id`s; cannot read anything. Revoke by removing it
  from the allow-list (admin op) + `promote` to re-pin.
- **Public recipient exposure**: harmless by design; encrypting to it is not a
  privilege. A deposit is only *accepted* with a valid, allow-listed signature.
- **Rollback / replay**: `seq` monotonic per `(contributor, backend_id)` +
  `epoch` binding; broker takes the highest `seq`, rejects mismatched epochs.
  Freshness against a withholding contributor is best-effort; `promote` is the
  authoritative pin. (Same freshness caveat the current bundle already has.)
- **Deposit-log spam / DoS**: appending to the bundle file requires **write
  access to the file**; that filesystem/transport ACL is the gate on *who can
  append at all*, and the crypto gates *what is accepted*. Cap the deposit-log
  size and drop unverifiable entries. Document that bundle-file write access is a
  first-class control.
- **What does not change**: the broker still needs an unlock slot to boot (to
  get the ingest private key + admin creds). We are separating *contribution*
  from *administration/read*, not removing the unlock requirement.

## CLI

Supersedes today's `basil config bundle {init,set-cred,verify-unlock}` (and the
earlier rough sketch). Design decisions from the CLI review:

- **Top-level `basil bundle` verb** (promoted out from under `config`): bundle
  management is a first-class operator task. Breaking, but pre-release.
- **Structured values, not order-dependent parsing.** `--slot`/`--backend` are
  repeatable and each carries *its own* fields as one `key=value,…` value, so
  pairing is unambiguous and it stays clap-native (declarative help, completion,
  precise errors). This matches the existing `--vault-token BACKEND=VALUE` idiom.
  Parsing repeated flag *groups* positionally (a `--passphrase-file` bound to the
  preceding `--slot`) is explicitly rejected: it fights clap and incorrectly pairs
  easily.
- **Manifest for complex / one-shot / GitOps:** `--from bundle.toml` with
  `[[slot]]` / `[[backend]]` tables, for when inline values get unwieldy.
- **Backend id ≠ type.** Every backend carries an explicit `id=` (the catalog
  backend name creds route by); `type=` selects the shape. Two vault backends
  need two ids. A fixed `--url/--key-file` pair is rejected: backend configs are
  heterogeneous (see the per-type table).
- **Two legible modes, never inferred.** Admin ops open the bundle
  (`--open <method>`) to recover the KEK and re-seal; **deposit** is a *separate
  verb* needing only the deposit recipient + a signing identity. `-r`/`-i` never
  appear on slot ops (a slot cannot be deposited: wrapping a slot needs the KEK).
- **Deposits are signed by default;** `--unsigned-deposits` is an explicit, loud
  opt-in (unsigned = anyone who can write the file can inject a cred). `--allowed`
  is editable after create via `bundle allow`.

### Verbs

```
basil bundle create  BUNDLE  [--from FILE] [--slot …]… [--backend …]…
                             [--deposit-key OUT] [--unsigned-deposits] [--allowed FILE]
basil bundle add-slot    BUNDLE --slot …            --open <method>
basil bundle set-backend BUNDLE --backend …         --open <method>   # admin → sealed payload
basil bundle deposit     BUNDLE --backend …  -r DEPOSIT_PUB  -i IDENT  # contributor, no unlock secret
basil bundle allow       BUNDLE --contributor PUB --backend ID…  --open <method>
basil bundle promote     BUNDLE  [--dry-run] [--backend ID]… [--contributor PUB]…  --open <method>
basil bundle verify      BUNDLE                     --open <method>   # dry-run unlock (never mutates/wipes)
basil bundle show        BUNDLE  [--open <method>]                    # metadata only; --open adds authz+fingerprints
```

`create` requires **at least one `--slot`**: a slotless bundle can never be
opened.

### `--slot TYPE[:field=val,…]` (repeatable)

Secrets come from files, never argv.

| Slot          | Value                               | Generate vs read                                                                                       |
| ------------- | ----------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `passphrase`  | `passphrase:file=/run/pass`         | reads the passphrase file                                                                              |
| `bip39`       | `bip39` or `bip39:file=/run/phrase` | **generates** a fresh 24-word phrase, emitted once (as `init` does today), unless `file=` supplies one |
| `age-yubikey` | `age-yubikey[:recipient=age1…]`     | hardware PIN/touch                                                                                     |
| `tpm`         | `tpm[:pcrs=0,2,4,7]`                | host TPM, no operator secret                                                                           |

### `--backend id=NAME,type=TYPE,<fields>` (repeatable)

| type                | fields                                                                                                      |
| ------------------- | ----------------------------------------------------------------------------------------------------------- |
| `openbao` / `vault` | `addr=`, and one of `token-file=` \| `role-id=,secret-id-file=` (AppRole) \| `spiffe-key-file=,spiffe-id=`  |
| `1password`         | `provider-uri=`, `project=`, `profile=`                                                                     |
| `aws-kms`           | `region=`, `profile=?` (non-secret)                                                                         |
| `gcp-kms`           | `project=`, `location=`, `key-ring=`, `key-file=?` (service-account JSON secret; omit ⇒ ADC, `basil-4s0s`) |
| `db-keystore`       | `path=`, `cipher=?`, `dek-file=`                                                                            |

### `--open <method>` (admin unlock for mutating ops)

Same grammar as a slot's secret source: `passphrase:file=P`, `bip39:file=P`,
`age-yubikey`, `tpm`. The first slot that opens wins.

### Worked examples

One-shot create (inline structured values):

```
basil bundle create creds.sealed \
  --slot passphrase:file=/run/pass \
  --slot age-yubikey \
  --backend id=vault1,type=openbao,addr=https://vault:8200,token-file=/run/tok \
  --backend id=gcp1,type=gcp-kms,project=P,location=global,key-ring=KR,key-file=sa.json \
  --deposit-key deposit.pub --allowed depositors.txt
```

Incremental admin update:

```
basil bundle set-backend creds.sealed \
  --backend id=aws1,type=aws-kms,region=us-east-1 \
  --open passphrase:file=/run/pass
```

Contributor deposit, with no unlock secret, only the public deposit key + a signing
identity (this is the GCP-admin-adds-a-key-without-read-access flow):

```
basil bundle deposit creds.sealed \
  --backend id=gcp1,type=gcp-kms,project=P,location=global,key-ring=KR,key-file=sa.json \
  -r deposit.pub -i alice.ed25519.key
```

## Alternatives considered

- **All creds per-entry public-key (no monolithic payload).** Uniform, but makes
  *every* write unprivileged and needs contribution-auth for everything, losing
  the "modification requires an unlock secret" property for admin creds. Rejected
  as the default; the hybrid (baseline payload + deposit log) keeps admin creds
  strongly protected.
- **Sidecar deposit file** instead of an in-bundle section. Simpler to append,
  but two files to keep together and no single atomic artifact. Prefer an
  in-bundle section; a sidecar is a fallback.
- **age plugin recipient (yubikey) as the ingest key.** A natural extension:
  the ingest private key could itself be hardware-held. Out of scope for v1.

## Non-goals

- Replacing unlock slots (broker still unlocks to boot).
- Hiding metadata (backend ids, contributor set are visible).
- A general secret-sharing / threshold / MPC scheme.

## Open questions

1. Baseline-vs-deposit precedence *within the same epoch* (an admin sealed
   `backend_id` X at epoch E and a contributor also deposited X at E). The
   overlay model says the deposit shadows the baseline (deposit is the live
   edit); confirm that's always right, or whether a `pinned` id should invert it.
   Cross-epoch is unambiguous (epoch mismatch retires older deposits).
2. Deposit-log encoding + placement in `format.rs` (new authenticated section vs
   trailing records) and its interaction with the header epoch AAD.
3. Exact `google_cloud_auth::CredentialsFile` construction API from a JSON string
   (verify against the pinned `google-cloud-kms 0.6` dep tree).
4. Should `promote` be automatic on a successful unlock, or an explicit admin op?
   (Leaning explicit, for auditability.)
