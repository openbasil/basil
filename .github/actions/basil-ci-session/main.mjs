// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

import { spawn } from "node:child_process";
import path from "node:path";
import { pathToFileURL } from "node:url";

import {
  buildBootstrapFrame,
  clearProviderEnvironment,
  closeReviewedExecutable,
  commitBootstrap,
  controlRequest,
  controlStateIsCurrent,
  openReviewedExecutable,
  parseSessionOutputs,
  qualificationAdapterSocket,
  qualificationRequest,
  readStartupLine,
  removeQualificationEvidence,
  requireLinux,
  socketIdentity,
  validateInputs,
  waitForChildSpawn,
  waitForOwnedChildExit,
  waitForSocketDisappearance,
  writeBootstrap,
  writeCommandEntries,
  writeQualificationEvidence,
} from "./session.mjs";

const SIGNAL_EXIT_CODES = Object.freeze({ SIGINT: 130, SIGTERM: 143 });

export class ActionCancelled extends Error {
  constructor(signal) {
    super(`Basil CI session setup cancelled by ${signal}`);
    this.name = "ActionCancelled";
    this.signal = signal;
  }
}

export async function runAction(overrides = {}) {
  const environment = overrides.environment ?? process.env;
  const signalSource = overrides.signalSource ?? process;
  const spawnProcess = overrides.spawnProcess ?? spawn;
  const operations = {
    buildBootstrapFrame,
    clearProviderEnvironment,
    closeReviewedExecutable,
    commitBootstrap,
    controlRequest,
    controlStateIsCurrent,
    openReviewedExecutable,
    parseSessionOutputs,
    qualificationAdapterSocket,
    qualificationRequest,
    readStartupLine,
    removeQualificationEvidence,
    requireLinux,
    socketIdentity,
    validateInputs,
    waitForChildSpawn,
    waitForOwnedChildExit,
    waitForSocketDisappearance,
    writeBootstrap,
    writeCommandEntries,
    writeQualificationEvidence,
    log: console.log,
    ...overrides.operations,
  };

  let bootstrapFrame;
  let child;
  let controlState;
  let commitStarted = false;
  let committed = false;
  let cancelledSignal;
  let cleanupPromise;

  const cleanup = () => {
    cleanupPromise ??= (async () => {
      if (!commitStarted) {
        if (bootstrapFrame !== undefined) bootstrapFrame.fill(0);
        if (child?.stdin != null && !child.stdin.destroyed) {
          child.stdin.once?.("error", () => {});
          child.stdin.end();
        }
        if (
          child !== undefined &&
          !(await operations.waitForOwnedChildExit(child))
        ) {
          throw new Error("the unacknowledged Basil CI session did not exit");
        }
        return;
      }
      if (
        controlState !== undefined &&
        operations.controlStateIsCurrent(controlState)
      ) {
        try {
          const response = await operations.controlRequest(
            controlState.controlSocket,
            "shutdown",
          );
          if (response?.status !== "shutting-down") {
            throw new Error("the Basil CI session rejected shutdown");
          }
        } catch (error) {
          if (
            child !== undefined &&
            (await operations.waitForOwnedChildExit(child))
          ) {
            return;
          }
          throw error;
        }
        if (
          !(await operations.waitForSocketDisappearance(
            controlState.controlSocket,
            controlState.controlIdentity,
          ))
        ) {
          throw new Error(
            "the Basil CI session control socket did not disappear",
          );
        }
      }
    })();
    return cleanupPromise;
  };

  const assertActive = () => {
    if (cancelledSignal !== undefined) {
      throw new ActionCancelled(cancelledSignal);
    }
  };
  const onSignal = (signal) => {
    cancelledSignal ??= signal;
    signalSource.exitCode = SIGNAL_EXIT_CODES[signal];
    void cleanup().catch(() => {
      signalSource.exitCode = 1;
    });
  };
  const onInterrupt = () => onSignal("SIGINT");
  const onTerminate = () => onSignal("SIGTERM");
  signalSource.on("SIGINT", onInterrupt);
  signalSource.on("SIGTERM", onTerminate);

  try {
    operations.requireLinux();
    const inputs = operations.validateInputs(environment);
    bootstrapFrame = operations.buildBootstrapFrame(inputs, environment);
    operations.clearProviderEnvironment(environment);
    assertActive();

    const reviewed = operations.openReviewedExecutable(
      inputs.executable,
      inputs.digest,
    );
    try {
      child = spawnProcess(
        "/proc/self/fd/3",
        [
          "ci",
          "session",
          "--basil-executable",
          "/proc/self/exe",
          "--basil-executable-sha256",
          inputs.digest,
          "--rule-max-token-age-seconds",
          inputs.maxAgeText,
          "--runtime-parent",
          inputs.runtimeParent,
          "--qualification-config",
          "/etc/basil/ci-qualification-v1.json",
        ],
        {
          detached: true,
          env: {},
          stdio: ["pipe", "pipe", "ignore", reviewed.descriptor],
        },
      );
    } finally {
      operations.closeReviewedExecutable(reviewed);
    }
    await operations.waitForChildSpawn(child);
    assertActive();
    if (child.stdin === null || child.stdout === null) {
      throw new Error("the Basil CI session process did not start");
    }
    await operations.writeBootstrap(child.stdin, bootstrapFrame);
    bootstrapFrame = undefined;
    assertActive();

    const line = await operations.readStartupLine(child.stdout, child);
    assertActive();
    const outputs = operations.parseSessionOutputs(line);
    const controlSocket = outputs["session-control-socket"];
    const controlIdentity = operations.socketIdentity(controlSocket);
    controlState = { controlSocket, controlIdentity };
    operations.writeCommandEntries("GITHUB_STATE", {
      control_socket: controlSocket,
      control_dev: controlIdentity.dev,
      control_ino: controlIdentity.ino,
    });
    assertActive();
    commitStarted = true;
    await operations.commitBootstrap(child.stdin);
    assertActive();
    const status = await operations.controlRequest(controlSocket, "status");
    if (status?.status !== "running") {
      throw new Error("the Basil CI session did not enter the running state");
    }
    assertActive();
    const adapterSocket = operations.qualificationAdapterSocket(
      outputs["adapter-sockets"],
    );
    const qualification = await operations.qualificationRequest(adapterSocket);
    assertActive();
    if (qualification.receipt === undefined) {
      throw new Error("the Basil CI qualification was rejected");
    }
    const evidence = operations.writeQualificationEvidence(
      path.dirname(controlSocket),
      qualification.receipt,
    );
    if (!/^[0-9a-f]{64}$/u.test(evidence.digest)) {
      throw new Error("the Basil CI qualification evidence digest is invalid");
    }
    try {
      operations.log(
        `BASIL_CI_QUALIFICATION_RECEIPT_V1 ${qualification.receipt.canonical} sha256=${evidence.digest}`,
      );
    } finally {
      operations.removeQualificationEvidence(evidence);
    }
    operations.writeCommandEntries("GITHUB_OUTPUT", outputs);
    committed = true;
    child.stdout.destroy();
    child.unref();
  } catch (error) {
    try {
      await cleanup();
    } catch (cleanupError) {
      throw new AggregateError(
        [error, cleanupError],
        "Basil CI session setup and cleanup failed",
      );
    }
    if (cancelledSignal !== undefined) {
      throw new ActionCancelled(cancelledSignal);
    }
    throw error;
  } finally {
    if (bootstrapFrame !== undefined) bootstrapFrame.fill(0);
    operations.clearProviderEnvironment(environment);
    signalSource.off("SIGINT", onInterrupt);
    signalSource.off("SIGTERM", onTerminate);
  }
}

async function command() {
  try {
    await runAction();
  } catch (error) {
    if (error instanceof ActionCancelled) return;
    const message = error instanceof Error ? error.message : "unknown failure";
    console.error(`Basil CI session setup failed: ${message}`);
    process.exitCode = 1;
  }
}

if (
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  await command();
}
