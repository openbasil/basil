#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
#
# SPDX-License-Identifier: Apache-2.0

"""Normalize shell emitted by cargo-dist in the release workflow."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


FRAGMENT_BEGIN = (
    "  # BEGIN HAND-WRITTEN RELEASE JOBS: managed by just gen-release-workflow"
)

REPLACEMENTS = (
    (
        "GitHub path output",
        '            echo "$HOME/.cargo/bin" >> $GITHUB_PATH',
        '            echo "$HOME/.cargo/bin" >> "$GITHUB_PATH"',
    ),
    (
        "local artifact output",
        """          echo "paths<<EOF" >> "$GITHUB_OUTPUT"
          dist print-upload-files-from-manifest --manifest dist-manifest.json >> "$GITHUB_OUTPUT"
          echo "EOF" >> "$GITHUB_OUTPUT""".strip("\n"),
        """          {
            echo "paths<<EOF"
            dist print-upload-files-from-manifest --manifest dist-manifest.json
            echo "EOF"
          } >> "$GITHUB_OUTPUT""".strip("\n"),
    ),
    (
        "global artifact output",
        """          echo "paths<<EOF" >> "$GITHUB_OUTPUT"
          jq --raw-output ".upload_files[]" dist-manifest.json >> "$GITHUB_OUTPUT"
          echo "EOF" >> "$GITHUB_OUTPUT""".strip("\n"),
        """          {
            echo "paths<<EOF"
            jq --raw-output ".upload_files[]" dist-manifest.json
            echo "EOF"
          } >> "$GITHUB_OUTPUT""".strip("\n"),
    ),
    (
        "release shell declaration",
        """      - name: Create GitHub Release
        env:""".strip("\n"),
        """      - name: Create GitHub Release
        shell: bash
        env:""".strip("\n"),
    ),
    (
        "release command arguments",
        """          # Write and read notes from a file to avoid quoting breaking things
          echo "$ANNOUNCEMENT_BODY" > $RUNNER_TEMP/notes.txt

          gh release create "${{ needs.plan.outputs.tag }}" --target "$RELEASE_COMMIT" $PRERELEASE_FLAG --title "$ANNOUNCEMENT_TITLE" --notes-file "$RUNNER_TEMP/notes.txt" artifacts/*""".strip(
            "\n"
        ),
        """          # Write and read notes from a file to avoid quoting breaking things.
          printf '%s\\n' "$ANNOUNCEMENT_BODY" > "$RUNNER_TEMP/notes.txt"

          release_args=()
          case "$PRERELEASE_FLAG" in
            "") ;;
            --prerelease) release_args+=("$PRERELEASE_FLAG") ;;
            *)
              printf 'error: unexpected prerelease flag: %q\\n' "$PRERELEASE_FLAG" >&2
              exit 1
              ;;
          esac

          gh release create "${{ needs.plan.outputs.tag }}" --target "$RELEASE_COMMIT" "${release_args[@]}" --title "$ANNOUNCEMENT_TITLE" --notes-file "$RUNNER_TEMP/notes.txt" artifacts/*""".strip(
            "\n"
        ),
    ),
    (
        "Homebrew formula name",
        '            name=$(echo "$filename" | sed "s/\\.rb$//")',
        '            name="${filename%.rb}"',
    ),
)


def normalize(content: str) -> str:
    """Apply each known normalization once within cargo-dist's output."""
    fragment_count = content.count(FRAGMENT_BEGIN)
    if fragment_count > 1:
        raise ValueError(f"found {fragment_count} hand-written fragment markers")
    generated_content, marker, hand_written_content = content.partition(FRAGMENT_BEGIN)

    for label, generated, normalized in REPLACEMENTS:
        generated_count = generated_content.count(generated)
        normalized_count = generated_content.count(normalized)
        if generated_count == 1 and normalized_count == 0:
            generated_content = generated_content.replace(generated, normalized, 1)
        elif generated_count == 0 and normalized_count == 1:
            continue
        else:
            raise ValueError(
                f"unexpected {label}: found {generated_count} generated and "
                f"{normalized_count} normalized copies"
            )
    return generated_content + marker + hand_written_content


def main() -> int:
    """Normalize a workflow in place or verify that it is already normalized."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("workflow", type=Path)
    args = parser.parse_args()

    original = args.workflow.read_text(encoding="utf-8")
    try:
        normalized = normalize(original)
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    if args.check:
        if normalized != original:
            print(
                f"error: {args.workflow} needs release shell normalization",
                file=sys.stderr,
            )
            return 1
    else:
        args.workflow.write_text(normalized, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
