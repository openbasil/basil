
_default:
    @just --list

rust-docs:
    cargo doc -p basil  -p basil-nats -p basil-proto -p basil-cose --all-features --no-deps

# Generate roff man pages for the `basil`, `basil-nats-bridge`, and
# `basil-https-courier` binaries into
# `target/man` (override with `just man-pages <dir>`). Pages are named
# `basil.1`, `basil-agent.1`, ... one per (nested) subcommand.
man-pages out="target/man":
    cargo xtask -o {{ out }}

# Regenerate .github/workflows/release.yml from the cargo-dist config, then
# re-append the hand-written jobs (debian-packages + arch-package) that dist
# 0.32.0 cannot emit. The jobs live in .github/workflow-partials/release-handwritten-jobs.yml
# under a `jobs:` indentation anchor, outside GitHub's workflow discovery path.
# Run this after bumping cargo-dist-version or editing the hand-written jobs.
gen-release-workflow:
    #!/usr/bin/env bash
    set -euo pipefail
    workflow=.github/workflows/release.yml
    fragment=.github/workflow-partials/release-handwritten-jobs.yml
    # Lines to skip in the fragment: its header through the `jobs:` anchor. The
    # header exists only to keep a YAML auto-formatter from de-indenting the jobs.
    header_lines=16
    # Fail loudly if the anchor moved (someone edited the fragment header).
    if [ "$(sed -n "${header_lines}p" "$fragment")" != "jobs:" ]; then
      echo "error: line ${header_lines} of ${fragment} is not 'jobs:' -- update header_lines" >&2
      exit 1
    fi
    cfg=dist-workspace.toml
    # The selected executable must exactly match the one pinned in the dist
    # configuration. Reject duplicate or malformed pins before any mutation.
    mapfile -t dist_pins < <(grep -n '^[[:space:]]*cargo-dist-version[[:space:]]*=' "$cfg" || true)
    if [ "${#dist_pins[@]}" -ne 1 ]; then
      echo "error: expected exactly one cargo-dist-version pin in $cfg" >&2
      exit 1
    fi
    if [[ "${dist_pins[0]}" =~ ^[0-9]+:cargo-dist-version[[:space:]]*=[[:space:]]*\"([0-9]+\.[0-9]+\.[0-9]+)\"[[:space:]]*$ ]]; then
      expected_dist_version="${BASH_REMATCH[1]}"
    else
      echo "error: malformed cargo-dist-version pin in $cfg" >&2
      exit 1
    fi
    # Resolve cargo-dist from the exact nixpkgs revision in this flake lock,
    # rather than accepting PATH or a mutable registry reference.
    nixpkgs_rev="$(jq -er '
      .nodes.root.inputs.nixpkgs as $node
      | if ($node | type) != "string" then error("root nixpkgs input is not a node name") else . end
      | .nodes[$node].locked
      | select(.type == "github" and .owner == "NixOS" and .repo == "nixpkgs")
      | .rev
      | select(test("^[0-9a-f]{40}$"))
    ' flake.lock)" || {
      echo "error: flake.lock must pin root nixpkgs to a 40-character NixOS/nixpkgs Git revision" >&2
      exit 1
    }
    dist_cmd=(nix run "github:NixOS/nixpkgs/${nixpkgs_rev}#cargo-dist" --)
    actual_dist_version="$("${dist_cmd[@]}" --version)"
    if [ "$actual_dist_version" != "cargo-dist ${expected_dist_version}" ]; then
      echo "error: selected cargo-dist is '${actual_dist_version}', expected 'cargo-dist ${expected_dist_version}'" >&2
      exit 1
    fi
    # dist-workspace.toml pins `allow-dirty = ["ci"]`, which makes `dist generate`
    # SKIP release.yml entirely. Strip that key for a single run so dist actually
    # rewrites the file, then always restore the real config.
    cfg_backup="$(mktemp)"
    cp "$cfg" "$cfg_backup"
    trap 'cp "$cfg_backup" "$cfg"; rm -f "$cfg_backup"' EXIT
    grep -vF 'allow-dirty = ["ci"]' "$cfg_backup" > "$cfg"
    # Regenerate the dist-owned portion. cargo-dist 0.32.0 may preserve the
    # previous hand-written suffix, which is delimited by the canonical
    # fragment. Migrate the one pre-delimiter fragment shape once; anything
    # else is ambiguous and fails closed.
    "${dist_cmd[@]}" generate --mode ci
    fragment_begin='  # BEGIN HAND-WRITTEN RELEASE JOBS: managed by just gen-release-workflow'
    fragment_end='  # END HAND-WRITTEN RELEASE JOBS: managed by just gen-release-workflow'
    legacy_marker='  # HAND-WRITTEN JOBS (not managed by dist). Regenerate release.yml with'
    begin_count="$(grep -cFx -- "$fragment_begin" "$workflow" || true)"
    end_count="$(grep -cFx -- "$fragment_end" "$workflow" || true)"
    legacy_count="$(grep -cFx -- "$legacy_marker" "$workflow" || true)"
    case "$begin_count:$end_count:$legacy_count" in
      0:0:0) ;;
      1:1:1) sed -i "/^${fragment_begin}$/,/^${fragment_end}$/d" "$workflow" ;;
      0:0:1)
        legacy_line="$(grep -nFx -- "$legacy_marker" "$workflow" | cut -d: -f1)"
        legacy_start="$((legacy_line - 1))"
        if [ "$legacy_start" -lt 1 ] \
          || [ "$(sed -n "${legacy_start}p" "$workflow")" != '  # ===========================================================================' ]; then
          echo "error: legacy hand-written fragment has an unexpected boundary in $workflow" >&2
          exit 1
        fi
        sed -i "${legacy_start},\$d" "$workflow"
        ;;
      *)
        echo "error: unexpected hand-written fragment delimiters in $workflow; refusing to choose one" >&2
        exit 1
        ;;
    esac
    # dist 0.32.0 emits this exact loose tag block. Accept it and the two
    # established strict forms, then normalize to strict double quotes.
    raw_tag_line="      - '**[0-9]+.[0-9]+.[0-9]+*'"
    canonical_tag_line='      - "v[0-9]+.[0-9]+.[0-9]+*"'
    legacy_tag_line="      - 'v[0-9]+.[0-9]+.[0-9]+*'"
    tag_block="$(sed -n '/^    tags:$/,/^$/p' "$workflow")"
    raw_tag_block="$(printf '%s\n%s' '    tags:' "$raw_tag_line")"
    canonical_tag_block="$(printf '%s\n%s' '    tags:' "$canonical_tag_line")"
    legacy_tag_block="$(printf '%s\n%s' '    tags:' "$legacy_tag_line")"
    case "$tag_block" in
      "$raw_tag_block"|"$canonical_tag_block"|"$legacy_tag_block") ;;
      *)
        echo "error: unexpected cargo-dist 0.32.0 tag block in $workflow; update gen-release-workflow" >&2
        exit 1
        ;;
    esac
    sed -i \
      -e 's|^      - '\''\*\*\[0-9\]+\.\[0-9\]+\.\[0-9\]+\*'\''$|      - "v[0-9]+.[0-9]+.[0-9]+*"|' \
      -e 's|^      - '\''v\[0-9\]+\.\[0-9\]+\.\[0-9\]+\*'\''$|      - "v[0-9]+.[0-9]+.[0-9]+*"|' \
      "$workflow"
    # cargo-dist 0.32.0 emits shell constructs that shellcheck rejects. Keep the
    # generated portion safe and actionlint-clean without hand-editing it later.
    scripts/normalize-release-workflow.py "$workflow"
    # ... then re-append the hand-written jobs, minus the anchor header.
    tail -n +"$((header_lines + 1))" "$fragment" >> "$workflow"
    # dist emits actions pinned to moving tags (`@v4`); dist 0.32 has no config
    # to SHA-pin them, so re-pin the whole assembled file (dist-emitted jobs plus
    # the re-appended hand-written ones) to commit SHAs. Needs gh auth / GH_TOKEN.
    scripts/pin-github-actions.sh "$workflow"
    echo "regenerated $workflow, re-appended hand-written jobs, and pinned actions to SHAs"

# Verify that the version guard rejects a selected cargo-dist before either
# generator input can be rewritten. The fake `nix` exists only for this test.
test-release-generator-version-guard:
    #!/usr/bin/env bash
    set -euo pipefail
    test_root="$(mktemp -d)"
    trap 'rm -rf "$test_root"' EXIT
    cp .github/workflows/release.yml "$test_root/release.yml"
    cp dist-workspace.toml "$test_root/dist-workspace.toml"
    mkdir "$test_root/bin"
    printf '%s\n' '#!/usr/bin/env bash' "printf '%s\\n' 'cargo-dist 99.99.99'" >"$test_root/bin/nix"
    chmod +x "$test_root/bin/nix"
    if PATH="$test_root/bin:$PATH" just gen-release-workflow; then
      echo "error: wrong cargo-dist version was accepted" >&2
      exit 1
    fi
    cmp "$test_root/release.yml" .github/workflows/release.yml
    cmp "$test_root/dist-workspace.toml" dist-workspace.toml

# Pin every third-party GitHub Action referenced in .github/workflows/*.yml to a
# full commit SHA (the moving tag is kept as a trailing comment). Idempotent.
# Needs the GitHub CLI authenticated (`gh auth login`) or GH_TOKEN set.
pin-actions:
    scripts/pin-github-actions.sh

# Rust gates: build, lint, test, and format-check.
check-rust:
    cargo build  --workspace --all-features
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    cargo test   --workspace
    cargo fmt --all -- --check

# Go gates: module hygiene, build, vet, test, and format-check.
check-go:
    #!/usr/bin/env bash
    set -euo pipefail
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

# Shell gates.
check-sh:
    fd -e sh -0 | xargs -0 shellcheck

# GitHub Actions syntax and embedded-shell gates.
check-actions: test-actions
    scripts/normalize-release-workflow.py --check .github/workflows/release.yml
    actionlint

check: check-rust check-go check-sh check-actions
    typos

# Validate the pinned source, patch, corpora, version, and platform manifest
# without compiling the complete Nix package.
check-nix-pilot-provenance:
    #!/usr/bin/env bash
    set -euo pipefail
    pilot_system="$(nix eval --raw --impure --expr builtins.currentSystem)"
    nix build --no-link ".#checks.${pilot_system}.nix-pilot-provenance"

# Evaluate both opt-in pilot outputs and their declared tier on every supported
# platform. Foreign-platform packages are evaluated, not built.
check-nix-pilot-matrix:
    #!/usr/bin/env bash
    set -euo pipefail
    for pilot_system in x86_64-linux aarch64-linux aarch64-darwin; do
      nix eval --raw ".#packages.${pilot_system}.nix-pilot-cli.drvPath" >/dev/null
      nix eval --raw ".#packages.${pilot_system}.nix-pilot-full.drvPath" >/dev/null
      pilot_tier="$(nix eval --raw ".#packages.${pilot_system}.nix-pilot-cli.basilPilot.platform.tier")"
      pilot_evidence="$(nix eval --raw ".#packages.${pilot_system}.nix-pilot-cli.basilPilot.platform.qualification.mode")"
      pilot_status="$(nix eval --raw ".#packages.${pilot_system}.nix-pilot-cli.basilPilot.platform.qualification.status")"
      pilot_patch_flags="$(nix eval --json ".#packages.${pilot_system}.nix-pilot-cli.basilPilot.sourcePatchFlags")"
      test "${pilot_patch_flags}" = '["-p1","--fuzz=0"]'
      case "${pilot_system}:${pilot_tier}:${pilot_evidence}:${pilot_status}" in
        x86_64-linux:preview:native-full-build:passed) ;;
        aarch64-linux:preview:native-full-build:pending) ;;
        aarch64-darwin:development:evaluation-only:passed) ;;
        *) echo "unexpected Nix pilot evidence: ${pilot_system}:${pilot_tier}:${pilot_evidence}:${pilot_status}" >&2; exit 1 ;;
      esac
    done

# Build both explicit pilot outputs for the native platform.
build-nix-pilot:
    nix build --no-link .#nix-pilot-cli .#nix-pilot-full

# Rebuild and test the compatibility-only patch against its exact pinned
# official-master revision, including semantic equivalence with the base patch.
check-nix-pilot-master-compat:
    #!/usr/bin/env bash
    set -euo pipefail
    pilot_system="$(nix eval --raw --impure --expr builtins.currentSystem)"
    nix build --no-link ".#checks.${pilot_system}.nix-pilot-master-compatibility"

# format all go sources
format-go:
    fd -e go -E vendor -x gofmt -w

# Run all examples (every examples/*/run.sh, including web-service-axum and
# python-grpc; python-grpc SKIPs cleanly when grpcio is not installed).
# before running, either
#    set BASIL_BIN and BASIL_NATS_BRIDGE_BIN
# or ensure `basil` and `basil-nats-bridge` are in your PATH
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

# Run the full default Rust test suite.
test-rust:
    cargo test --workspace

# Run the composite action's lifecycle and provider-workflow policy tests.
test-actions:
    node --test .github/actions/basil-ci-session/*.test.mjs

# Run every checked-in Go module.
test-go:
    #!/usr/bin/env bash
    set -euo pipefail
    for module in clients/go crates/basil-tests/tests/oidc_verifier_go interop-tests/go-spiffe; do
      echo "== go test: $module"
      (cd "$module" && go test ./...)
    done

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

# Run the full Rust-driven live interop/e2e suite.
test-interop: cargo-live-e2e test-stream-interop

# Run all local Rust, Go, and live interop suites.
test-all: test-rust test-go test-interop

# Boot an emulated-TPM guest (qemu + swtpm) and drive the real TPM unlock slot
# against it (basil-h8qq.1/.2/.3). Builds basil with --features unlock-tpm,
# then proves Scenario A (seal -> auto-unlock -> reboot -> auto-unlock, no
# operator secret) and Scenario B (no-TPM / PCR-mismatch / different-TPM all
# fail closed; a recovery slot still opens). SKIPs cleanly (exit 0) if
# qemu/swtpm are absent.
test-tpm:
    scripts/tpm-unlock-e2e.sh

# Each engine runs on its own dev-server port; a missing engine binary SKIPs
# cleanly (not a failure); exits non-zero iff any engine's e2e FAILED.
#   just test-e2e [openbao|vault|both]   (default: both)
#
# Run the prefill acceptance e2e against OpenBao, HashiCorp Vault, or both.
test-e2e engine="both":
    #!/usr/bin/env bash
    set -uo pipefail
    case "{{ engine }}" in
      openbao|vault) engines=("{{ engine }}") ;;
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
