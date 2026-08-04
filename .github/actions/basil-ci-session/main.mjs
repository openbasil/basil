// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

import { spawn } from "node:child_process";

import {
  controlRequest,
  parseSessionOutputs,
  processIdentity,
  readStartupLine,
  removeStagedExecutable,
  requireLinux,
  socketIdentity,
  stageReviewedExecutable,
  stopExactProcess,
  validateInputs,
  writeCommandEntries,
} from "./session.mjs";

let staged;
let child;
let expectedProcess;

async function main() {
  requireLinux();
  const inputs = validateInputs();
  staged = stageReviewedExecutable(inputs.executable, inputs.digest);
  child = spawn(
    staged.executable,
    [
      "ci",
      "session",
      "--basil-executable",
      staged.executable,
      "--basil-executable-sha256",
      inputs.digest,
      "--rule-max-token-age-seconds",
      inputs.maxAgeText,
      "--runtime-parent",
      process.env.RUNNER_TEMP,
    ],
    {
      detached: true,
      env: process.env,
      stdio: ["ignore", "pipe", "ignore"],
    },
  );
  if (child.pid === undefined || child.stdout === null) {
    throw new Error("the Basil CI session process did not start");
  }
  expectedProcess = processIdentity(child.pid);
  if (
    expectedProcess === undefined ||
    expectedProcess.dev !== staged.executableIdentity.dev ||
    expectedProcess.ino !== staged.executableIdentity.ino
  ) {
    throw new Error(
      "the Basil CI session process identity could not be pinned",
    );
  }
  writeCommandEntries("GITHUB_STATE", {
    pid: child.pid,
    start_time: expectedProcess.startTime,
    exe_dev: expectedProcess.dev,
    exe_ino: expectedProcess.ino,
    stage_directory: staged.directory,
    stage_dev: staged.directoryIdentity.dev,
    stage_ino: staged.directoryIdentity.ino,
  });
  const line = await readStartupLine(child.stdout, child);
  const outputs = parseSessionOutputs(line);
  const control = outputs["session-control-socket"];
  const controlIdentity = socketIdentity(control);
  const status = await controlRequest(control, "status");
  if (status?.status !== "running") {
    throw new Error("the Basil CI session did not enter the running state");
  }
  writeCommandEntries("GITHUB_STATE", {
    control_socket: control,
    control_dev: controlIdentity.dev,
    control_ino: controlIdentity.ino,
  });
  writeCommandEntries("GITHUB_OUTPUT", outputs);
  child.stdout.destroy();
  child.unref();
}

try {
  await main();
} catch (error) {
  if (child?.pid !== undefined && expectedProcess !== undefined) {
    await stopExactProcess(child.pid, expectedProcess);
  }
  if (staged !== undefined) {
    removeStagedExecutable(
      staged.directory,
      staged.directoryIdentity,
      staged.executableIdentity,
    );
  }
  const message = error instanceof Error ? error.message : "unknown failure";
  console.error(`Basil CI session setup failed: ${message}`);
  process.exitCode = 1;
}
