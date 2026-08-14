// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

import {
  controlRequest,
  controlStateIsCurrent,
  parseState,
  requireLinux,
  waitForSocketDisappearance,
} from "./session.mjs";

try {
  requireLinux();
  const state = parseState();
  if (state !== undefined) {
    if (!controlStateIsCurrent(state)) {
      throw new Error("the Basil CI session control socket identity changed");
    }
    await controlRequest(state.controlSocket, "shutdown");
    if (
      !(await waitForSocketDisappearance(
        state.controlSocket,
        state.controlIdentity,
      ))
    ) {
      throw new Error("the Basil CI session control socket did not disappear");
    }
  }
} catch (error) {
  const message = error instanceof Error ? error.message : "unknown failure";
  console.error(`Basil CI session cleanup failed: ${message}`);
  process.exitCode = 1;
}
