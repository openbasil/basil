# db-keystore Backend Example

This example runs the unified `basil` binary against the optional `db-keystore`
backend and uses the same CLI to mint a JWT, encrypt/decrypt, and sign/verify.

The static files are:

- `catalog.template.json` - small catalog with one `kind: "keystore"` backend.
- `policy.template.json` - policy template rendered for your current uid.
- `db-keystore.env` - paths and key names used by the runner.
- agent config TOML - generated under the workdir by `run.sh`.
- `run.sh` - end-to-end driver.

Run it from the repository root or this directory:

```bash
examples/db-keystore/run.sh
```

The runner builds `basil` from `basil-bin` with the `db-keystore` feature (or
uses a prebuilt binary when `BASIL_BIN` is exported), creates a sealed bundle
containing a generated `DbKeystoreDek` with `basil bundle create`, writes a TOML
agent config, starts `basil agent` on a Unix socket, waits for startup reconcile
to generate the demo signing and AEAD keys, then exercises the broker through
the CLI (`mint-jwt`, `sign`/`verify`, `encrypt`/`decrypt`).

Runtime files are written under `/tmp/basil-db-keystore-example` by default. Set
`BASIL_EXAMPLE_WORKDIR` before running to use another directory.
