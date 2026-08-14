// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const actionDirectory = path.dirname(fileURLToPath(import.meta.url));
const repository = path.resolve(actionDirectory, "../../..");

function workflow(relativePath) {
  return fs.readFileSync(path.join(repository, relativePath), "utf8");
}

function actionRevision(text) {
  const match = text.match(
    /openbasil\/basil\/\.github\/actions\/basil-ci-session@([0-9a-f]{40})/u,
  );
  assert.notEqual(match, null);
  return match[1];
}

function assertPinnedActionExists(revision) {
  execFileSync("git", ["cat-file", "-e", `${revision}^{commit}`], {
    cwd: repository,
    stdio: "ignore",
  });
  for (const relative of [
    "action.yml",
    "main.mjs",
    "post.mjs",
    "session.mjs",
  ]) {
    execFileSync(
      "git",
      [
        "cat-file",
        "-e",
        `${revision}:.github/actions/basil-ci-session/${relative}`,
      ],
      { cwd: repository, stdio: "ignore" },
    );
  }

  const main = execFileSync(
    "git",
    ["show", `${revision}:.github/actions/basil-ci-session/main.mjs`],
    { cwd: repository, encoding: "utf8" },
  );
  assert.match(main, /--qualification-config/u);
  assert.match(main, /\/etc\/basil\/ci-qualification-v1\.json/u);
  assert.match(main, /qualificationRequest\(adapterSocket\)/u);
  assert.match(main, /BASIL_CI_QUALIFICATION_RECEIPT_V1/u);

  const session = execFileSync(
    "git",
    ["show", `${revision}:.github/actions/basil-ci-session/session.mjs`],
    { cwd: repository, encoding: "utf8" },
  );
  assert.match(
    session,
    /\{"version":1,"operation":"artifact-sign-qualification"\}/u,
  );
  assert.match(session, /\["artifact-sign-qualification"\]/u);
  assert.match(session, /qualification evidence changed before removal/u);
}

function assertProtectedJob(text) {
  for (const forbidden of [
    /actions\/checkout/iu,
    /\brun:/iu,
    /artifact/iu,
    /\bbuild\b/iu,
    /\$\{\{\s*inputs\./u,
    /\$\{\{\s*vars\./u,
    /workflow-ref:|workflow-sha:|workflow-repository:/iu,
    /trigger-ref:|trigger-sha:/iu,
  ]) {
    assert.doesNotMatch(text, forbidden);
  }
  const uses = [...text.matchAll(/^\s*uses:\s*(\S+)\s*$/gmu)].map(
    (match) => match[1],
  );
  assert.equal(uses.length, 1);
  assert.doesNotMatch(uses[0], /@(main|master|v[0-9]|latest)$/u);
  assertPinnedActionExists(actionRevision(text));
  assert.match(text, /basil-executable: \/usr\/local\/bin\/basil/u);
  assert.match(
    text,
    /basil-executable-sha256: \$\{\{ secrets\.BASIL_CI_EXECUTABLE_SHA256 \}\}/u,
  );
  assert.match(text, /rule-max-token-age-seconds: "300"/u);
}

test("GitHub reusable workflow qualifies one protected action lifecycle", () => {
  const text = workflow(".github/workflows/basil-ci-session-protected.yml");
  assert.match(text, /^\s{2}workflow_call:\s*$/mu);
  assert.doesNotMatch(text, /^\s{4}inputs:\s*$/mu);
  assert.match(text, /^permissions: \{\}\s*$/mu);
  assert.match(text, /^\s{6}id-token: write\s*$/mu);
  assert.match(text, /^\s{6}group: basil-ci\s*$/mu);
  assert.match(text, /^\s{6}labels: self-hosted\s*$/mu);
  assert.match(text, /^\s{4}environment: basil-ci-session\s*$/mu);
  assert.match(text, /^\s{10}provider-kind: github\s*$/mu);
  assert.match(
    text,
    /^\s{10}expected-token-request-origin: https:\/\/pipelines\.actions\.githubusercontent\.com\s*$/mu,
  );
  assert.match(text, /name: Qualify protected Basil CI session/u);
  assert.doesNotMatch(text, /\boutputs:/u);
  assertProtectedJob(text);
});

test("Forgejo push workflow fixes provider authority in the triggering commit", () => {
  const text = workflow(".forgejo/workflows/basil-ci-session-protected.yml");
  assert.match(text, /^\s{2}push:\s*$/mu);
  assert.doesNotMatch(text, /workflow_call/u);
  assert.match(text, /^\s{4}enable-openid-connect: true\s*$/mu);
  assert.match(text, /^\s{4}runs-on: basil-ci\s*$/mu);
  assert.match(text, /name: Qualify protected Basil CI session/u);
  assert.doesNotMatch(text, /\boutputs:/u);
  assert.match(text, /^\s{10}provider-kind: forgejoActions\s*$/mu);
  assert.match(
    text,
    /^\s{10}expected-token-request-origin: \$\{\{ github\.server_url \}\}\s*$/mu,
  );
  assertProtectedJob(text);
});

test("provider workflows pin the same reviewed action revision", () => {
  const github = workflow(".github/workflows/basil-ci-session-protected.yml");
  const forgejo = workflow(".forgejo/workflows/basil-ci-session-protected.yml");
  assert.equal(actionRevision(github), actionRevision(forgejo));
});
