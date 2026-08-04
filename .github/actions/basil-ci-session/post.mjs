// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

import {
  controlStateIsCurrent,
  parseState,
  removeStagedExecutable,
  requireLinux,
  sameProcess,
  stopExactProcess,
} from "./session.mjs";

try {
  requireLinux();
  const state = parseState();
  if (state !== undefined) {
    const wasCurrent = sameProcess(state.pid, state.process);
    const control = controlStateIsCurrent(state)
      ? state.controlSocket
      : undefined;
    const stopped = await stopExactProcess(state.pid, state.process, control);
    if (wasCurrent && !stopped) {
      throw new Error("the pinned Basil CI session process did not stop");
    }
    if (!sameProcess(state.pid, state.process)) {
      removeStagedExecutable(
        state.stageDirectory,
        state.stageDirectoryIdentity,
        state.executableIdentity,
      );
    }
  }
} catch (error) {
  const message = error instanceof Error ? error.message : "unknown failure";
  console.error(`Basil CI session cleanup failed: ${message}`);
  process.exitCode = 1;
}
