
_default:
    @just --list
   
rust-docs:
    cargo doc -p basil  -p basil-nats -p basil-proto -p basil-cose --all-features --no-deps

# Generate roff man pages for the `basil` and `basil-nats-bridge` binaries into
# `target/man` (override with `just man-pages <dir>`). Pages are named
# `basil.1`, `basil-agent.1`, ... one per (nested) subcommand.
man-pages out="target/man":
    cargo xtask -o {{out}}

# Regenerate .github/workflows/release.yml from the cargo-dist config, then
# re-append the hand-written jobs (debian-packages + arch-package) that dist
# 0.32.0 cannot emit. `dist generate` OWNS release.yml and would otherwise wipe
# them. The jobs live in .github/workflows/partials/release-handwritten-jobs.yml
# under a `jobs:` indentation anchor (a subdir, so GitHub Actions ignores it).
# Run this after bumping cargo-dist-version or editing the hand-written jobs.
gen-release-workflow:
    #!/usr/bin/env bash
    set -euo pipefail
    workflow=.github/workflows/release.yml
    fragment=.github/workflows/partials/release-handwritten-jobs.yml
    # Lines to skip in the fragment: its header through the `jobs:` anchor. The
    # header exists only to keep a YAML auto-formatter from de-indenting the jobs.
    header_lines=16
    # Fail loudly if the anchor moved (someone edited the fragment header).
    if [ "$(sed -n "${header_lines}p" "$fragment")" != "jobs:" ]; then
      echo "error: line ${header_lines} of ${fragment} is not 'jobs:' -- update header_lines" >&2
      exit 1
    fi
    # Use a pinned `dist` if installed; otherwise fetch the matching version.
    if command -v dist >/dev/null 2>&1; then
      dist_cmd=(dist)
    else
      dist_cmd=(nix run nixpkgs#cargo-dist --)
    fi
    # dist-workspace.toml pins `allow-dirty = ["ci"]`, which makes `dist generate`
    # SKIP release.yml entirely. Strip that key for a single run so dist actually
    # rewrites the file, then always restore the real config.
    cfg=dist-workspace.toml
    cfg_backup="$(mktemp)"
    cp "$cfg" "$cfg_backup"
    trap 'cp "$cfg_backup" "$cfg"; rm -f "$cfg_backup"' EXIT
    grep -vF 'allow-dirty = ["ci"]' "$cfg_backup" > "$cfg"
    # Regenerate the dist-owned portion (this DROPS the hand-written jobs) ...
    "${dist_cmd[@]}" generate --mode ci
    # dist 0.32.0 hardcodes a loose tag trigger ('**[0-9]+.[0-9]+.[0-9]+*') that
    # also matches package-prefixed tags like `basil-v0.6.1`, which dist parses
    # as a package tag for a binary-less crate (empty release matrix). Tighten
    # it to the repo-wide tag convention shared with ci.yml and build.yml:
    # strict `v{semver}` tags only (prerelease suffixes still match).
    if ! grep -qF -- "- '**[0-9]+.[0-9]+.[0-9]+*'" "$workflow"; then
      echo "error: dist tag-trigger glob not found in $workflow; dist changed its template -- update gen-release-workflow" >&2
      exit 1
    fi
    sed -i "s/- '\*\*\[0-9\]+\.\[0-9\]+\.\[0-9\]+\*'/- 'v[0-9]+.[0-9]+.[0-9]+*'/" "$workflow"
    # ... then re-append the hand-written jobs, minus the anchor header.
    tail -n +"$((header_lines + 1))" "$fragment" >> "$workflow"
    # dist emits actions pinned to moving tags (`@v4`); dist 0.32 has no config
    # to SHA-pin them, so re-pin the whole assembled file (dist-emitted jobs plus
    # the re-appended hand-written ones) to commit SHAs. Needs gh auth / GH_TOKEN.
    scripts/pin-github-actions.sh "$workflow"
    echo "regenerated $workflow, re-appended hand-written jobs, and pinned actions to SHAs"

# Pin every third-party GitHub Action referenced in .github/workflows/*.yml to a
# full commit SHA (the moving tag is kept as a trailing comment). Idempotent.
# Needs the GitHub CLI authenticated (`gh auth login`) or GH_TOKEN set.
pin-actions:
    scripts/pin-github-actions.sh

check-rust:
    cargo build  --workspace --all-features
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    cargo test  --workspace
    fd -e rs -x rustfmt --edition 2024

# Go gates: lint, test, and format
# TODO: add pinned golangci-lint
# TODO: govulncheck
check-go:
    #!/usr/bin/env bash
    go_modules=(
      clients/go
      crates/basil-tests/tests/cose_go_interop
      crates/basil-tests/tests/oidc_verifier_go
      interop-tests/go-spiffe
    )
    for module in "${go_modules[@]}"; do
      echo "== Go gates: ${module}"
      (
          cd "$module"
          go mod tidy -diff
          go build ./...
          go vet ./...
          go test -count=1 ./...
      )
    done
    unformatted="$(fd -e go -E vendor -x gofmt -l)"
    if [[ -n "$unformatted" ]]; then
      echo "Go files require formatting:"
      printf '%s\n' "$unformatted"
      exit 1
    fi

check-sh:
    fd -e sh | xargs shellcheck

check: (check-rust) (check-go) (check-sh)
    typos

    
# format all go sources
format-go:
    fd -e go -E vendor -x gofmt -w
    

   
# Run all examples (every examples/*/run.sh, including web-service-axum and
# python-grpc; python-grpc SKIPs cleanly when grpcio is not installed).
# before running, either
#    set BASIL_BIN and BASIL_NATS_BRIDGE_BIN
#    or ensure `basil` and `basil-nats-bridge` are in your PATH
run-examples:
    #!/usr/bin/env bash
    set -euo pipefail

    for script in examples/*/run.sh; do
      echo "== running ${script}"
      (cd "$(dirname "${script}")" && ./run.sh)
    done

# check status here and submodule
st:
    jj status
    git -C clients/go status -s

clean:
    rm -rf target examples/*/target
    

# Run Cargo-discovered live OpenBao/Vault integration tests. These are excluded
# from default package checks; they require `bao` and/or `vault` on PATH. `http`
# opts the harness-built `basil` binary into the JWKS/OIDC HTTP surface required
# by the JWKS/OIDC live lanes.
cargo-live-e2e:
    cargo test -p basil-tests --features live-e2e,http

# Build the Rust `stream_cli` example and run the Go `//go:build interop`
# cross-language stream tests against it. These prove the Go and Rust streaming
# implementations produce and consume byte-identical containers; they are gated
# behind the `interop` build tag and need BASIL_STREAM_RUST_CLI to point at the
# built Rust binary. These are not included in either test-rust or test-go.
test-stream-interop:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build -p basil --example stream_cli
    cli="$PWD/target/debug/examples/stream_cli"
    echo "== go test -tags interop: clients/go/stream (BASIL_STREAM_RUST_CLI=$cli)"
    BASIL_STREAM_RUST_CLI="$cli" go test -C clients/go -tags interop ./stream/...

# Run the Go client against a live backend and basil agent
test-go-live-interop: 
    clients/go/scripts/interop-agent.sh
 
# Run all live and cross-language interop suites
test-interop: cargo-live-e2e test-stream-interop test-go-live-interop

# Run all local Rust, Go, and live interop suites.
test-all: check-rust check-go test-interop

# Boot an emulated-TPM guest (qemu + swtpm) and drive the real TPM unlock slot
# against it (basil-h8qq.1/.2/.3). Builds basil with --features unlock-tpm,
# then proves Scenario A (seal -> auto-unlock -> reboot -> auto-unlock, no
# operator secret) and Scenario B (no-TPM / PCR-mismatch / different-TPM all
# fail closed; a recovery slot still opens). SKIPs cleanly (exit 0) if
# qemu/swtpm are absent.
test-tpm:
    scripts/tpm-unlock-e2e.sh

# Compose Phase 1 evidence-infrastructure self-tests: artifact fetcher/verifier
# self-test, evidence-runner fault tests, and the test-only feasibility probe's
# unit tests. Does not fetch images or boot VM lanes.
test-compose-phase1-self:
    scripts/compose-phase1-artifacts.sh self-test
    interop-tests/compose-phase1/harness/test-evidence.sh
    cargo test -p basil-tests --features compose-phase1-probe --bin compose_phase1_probe

# Each engine runs on its own dev-server port; a missing engine binary SKIPs
# cleanly (not a failure); exits non-zero iff any engine's e2e FAILED.
#   just test-e2e [openbao|vault|both]   (default: both)
#
# Run the prefill acceptance e2e against OpenBao, HashiCorp Vault, or both.
test-e2e engine="both":
    #!/usr/bin/env bash
    set -uo pipefail
    case "{{engine}}" in
      openbao|vault) engines=("{{engine}}") ;;
      both)          engines=(openbao vault) ;;
      *) echo "usage: just test-e2e [openbao|vault|both]" >&2; exit 2 ;;
    esac
    declare -A result
    rc=0
    port=8211
    for e in "${engines[@]}"; do
      echo "============================================================"
      echo "== e2e: engine=$e  (addr http://127.0.0.1:$port)"
      echo "============================================================"
      out="$(scripts/test-prefill-e2e.sh --engine "$e" --addr "http://127.0.0.1:$port" 2>&1)"
      code=$?
      printf '%s\n' "$out"
      verdict="$(printf '%s\n' "$out" | grep -E '^(PASS|FAIL|SKIP)' | tail -1)"
      if [ "$code" -ne 0 ]; then
        result[$e]="FAIL: ${verdict:-exit $code}"; rc=1
      elif printf '%s' "$verdict" | grep -q '^SKIP'; then
        result[$e]="SKIP: ${verdict}"
      else
        result[$e]="PASS: ${verdict}"
      fi
      port=$((port + 1))
    done
    echo
    echo "===== e2e summary ====="
    for e in "${engines[@]}"; do printf '  %-8s %s\n' "$e" "${result[$e]}"; done
    exit "$rc"

