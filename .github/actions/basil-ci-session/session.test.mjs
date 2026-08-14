// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { ActionCancelled, runAction } from "./main.mjs";
import {
  buildBootstrapFrame,
  clearProviderEnvironment,
  parseSessionOutputs,
  parseState,
  qualificationAdapterSocket,
  qualificationRequest,
  removeQualificationEvidence,
  socketIdentity,
  validateExecutableMetadata,
  validateInputs,
  validateQualificationReceipt,
  writeBootstrap,
  writeCommandEntries,
  writeQualificationEvidence,
} from "./session.mjs";

const DIGEST = "a".repeat(64);
const JKT = "A".repeat(43);
const OUTPUTS = Object.freeze({
  "session-control-socket": "/runtime/control.sock",
  "adapter-sockets": JSON.stringify({
    "artifact-sign-qualification": "/runtime/qualification.sock",
  }),
  "proof-jkt": JKT,
  "proof-audience": `urn:basil:ci:jkt:${JKT}`,
});
const QUALIFICATION_RECEIPT = JSON.stringify({
  status: "ok",
  value: {
    version: 1,
    result: "signed",
    "invocation-id": JKT,
    "policy-generation": 17,
    "target-key-id": "qualification.artifact-signing",
    "config-sha256": "b".repeat(64),
    "ca-sha256": "c".repeat(64),
    "statement-sha256": "d".repeat(64),
    "signature-sha256": "e".repeat(64),
    "signature-verified": true,
    "denial-code": null,
    "denial-retryable": null,
  },
});

class FakeInput {
  constructor(child) {
    this.child = child;
    this.destroyed = false;
    this.ended = false;
    this.writes = [];
  }

  write(value, callback) {
    this.writes.push(Buffer.from(value));
    queueMicrotask(() => callback());
    return true;
  }

  end(value, callback) {
    if (value !== undefined) this.writes.push(Buffer.from(value));
    this.ended = true;
    if (value === undefined || Buffer.from(value)[0] !== 1) {
      this.child.exitCode = 1;
      queueMicrotask(() => this.child.emit("exit", 1, null));
    }
    if (callback !== undefined) queueMicrotask(() => callback());
  }
}

class FakeChild extends EventEmitter {
  constructor() {
    super();
    this.pid = 4242;
    this.stdin = new FakeInput(this);
    this.stdout = {
      destroyed: false,
      destroy() {
        this.destroyed = true;
      },
    };
    this.exitCode = null;
    this.signalCode = null;
    this.unrefCalled = false;
  }

  unref() {
    this.unrefCalled = true;
  }
}

function environment() {
  return {
    "INPUT_BASIL-EXECUTABLE": "/reviewed/basil",
    "INPUT_BASIL-EXECUTABLE-SHA256": DIGEST,
    "INPUT_PROVIDER-KIND": "github",
    "INPUT_EXPECTED-TOKEN-REQUEST-ORIGIN": "https://issuer.example",
    "INPUT_RULE-MAX-TOKEN-AGE-SECONDS": "120",
    RUNNER_TEMP: os.tmpdir(),
    ACTIONS_ID_TOKEN_REQUEST_URL: "https://issuer.example/token",
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: "provider-request-secret",
    GITHUB_TOKEN: "job-secret-that-must-not-pass",
    PATH: "/untrusted/bin",
  };
}

function harness(customize = () => {}) {
  const signalSource = new EventEmitter();
  signalSource.exitCode = undefined;
  const actionEnvironment = environment();
  const child = new FakeChild();
  const calls = {
    closedDescriptors: 0,
    commandWrites: [],
    controlRequests: [],
    qualificationRequests: [],
    evidenceWrites: [],
    evidenceRemovals: [],
    logs: [],
    waitedForExit: 0,
  };
  const operations = {
    requireLinux() {},
    validateInputs() {
      return {
        executable: "/reviewed/basil",
        digest: DIGEST,
        providerKind: "github",
        expectedOrigin: "https://issuer.example",
        maxAgeText: "120",
        runtimeParent: "/runner/temp",
      };
    },
    buildBootstrapFrame,
    clearProviderEnvironment(target) {
      delete target.ACTIONS_ID_TOKEN_REQUEST_URL;
      delete target.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
    },
    openReviewedExecutable() {
      return { descriptor: 99 };
    },
    closeReviewedExecutable() {
      calls.closedDescriptors += 1;
    },
    waitForChildSpawn(target) {
      return new Promise((resolve) => {
        target.once("spawn", resolve);
        queueMicrotask(() => target.emit("spawn"));
      });
    },
    writeBootstrap,
    readStartupLine: async () => "startup",
    parseSessionOutputs: () => ({ ...OUTPUTS }),
    socketIdentity: () => ({ dev: "15", ino: "16" }),
    writeCommandEntries(variable, entries) {
      calls.commandWrites.push({ variable, entries });
    },
    commitBootstrap(stream) {
      return new Promise((resolve) => stream.end(Buffer.from([1]), resolve));
    },
    waitForOwnedChildExit: async () => {
      calls.waitedForExit += 1;
      return true;
    },
    controlStateIsCurrent: () => true,
    controlRequest: async (_socket, operation) => {
      calls.controlRequests.push(operation);
      return { status: operation === "status" ? "running" : "shutting-down" };
    },
    qualificationRequest: async (socket) => {
      calls.qualificationRequests.push(socket);
      return {
        receipt: Object.freeze({
          canonical: QUALIFICATION_RECEIPT,
          value: Object.freeze({}),
        }),
      };
    },
    writeQualificationEvidence(directory, receipt) {
      calls.evidenceWrites.push({ directory, receipt });
      return Object.freeze({
        digest: "b".repeat(64),
        filename: "/runtime/artifact-sign-qualification-v1.json",
        identity: { dev: "15", ino: "17" },
      });
    },
    removeQualificationEvidence(evidence) {
      calls.evidenceRemovals.push(evidence);
    },
    log(line) {
      calls.logs.push(line);
    },
    waitForSocketDisappearance: async () => true,
  };
  let spawnCall;
  const spawnProcess = (executable, args, options) => {
    spawnCall = { executable, args: [...args], options };
    return child;
  };
  const context = {
    calls,
    child,
    environment: actionEnvironment,
    operations,
    signalSource,
    spawnProcess,
    spawnCall: () => spawnCall,
  };
  customize(context);
  return context;
}

function decodeBootstrap(frame) {
  assert.equal(frame.subarray(0, 8).toString("binary"), "BASILCI\0");
  assert.equal(frame[8], 1);
  const lengths = [];
  for (let index = 0; index < 4; index += 1) {
    lengths.push(frame.readUInt32BE(9 + index * 4));
  }
  let offset = 25;
  return lengths.map((length) => {
    const value = frame.subarray(offset, offset + length).toString("utf8");
    offset += length;
    return value;
  });
}

test("the child has an empty environment and receives the reviewed fd as fd 3", async () => {
  const context = harness();
  await runAction(context);
  const spawned = context.spawnCall();
  assert.equal(spawned.executable, "/proc/self/fd/3");
  assert.deepEqual(spawned.options.env, {});
  assert.deepEqual(spawned.options.stdio, ["pipe", "pipe", "ignore", 99]);
  assert.equal(spawned.args.includes("/reviewed/basil"), false);
  assert.deepEqual(spawned.args.slice(-2), [
    "--qualification-config",
    "/etc/basil/ci-qualification-v1.json",
  ]);
  assert.equal(context.calls.closedDescriptors, 1);
  assert.equal(context.environment.ACTIONS_ID_TOKEN_REQUEST_URL, undefined);
  assert.equal(context.environment.ACTIONS_ID_TOKEN_REQUEST_TOKEN, undefined);
  assert.equal(context.child.unrefCalled, true);
  assert.deepEqual(decodeBootstrap(context.child.stdin.writes[0]), [
    "github",
    "https://issuer.example",
    "https://issuer.example/token",
    "provider-request-secret",
  ]);
  assert.deepEqual(context.child.stdin.writes[1], Buffer.from([1]));
  assert.deepEqual(context.calls.controlRequests, ["status"]);
  assert.deepEqual(context.calls.qualificationRequests, [
    "/runtime/qualification.sock",
  ]);
  assert.deepEqual(context.calls.evidenceWrites, [
    {
      directory: "/runtime",
      receipt: Object.freeze({
        canonical: QUALIFICATION_RECEIPT,
        value: Object.freeze({}),
      }),
    },
  ]);
  assert.equal(context.calls.evidenceRemovals.length, 1);
  assert.deepEqual(context.calls.logs, [
    `BASIL_CI_QUALIFICATION_RECEIPT_V1 ${QUALIFICATION_RECEIPT} sha256=${"b".repeat(64)}`,
  ]);
  for (const sentinel of [
    "provider-request-secret",
    "job-secret-that-must-not-pass",
  ]) {
    assert.equal(context.calls.logs.join("\n").includes(sentinel), false);
  }
  assert.deepEqual(context.calls.commandWrites[0], {
    variable: "GITHUB_STATE",
    entries: {
      control_socket: "/runtime/control.sock",
      control_dev: "15",
      control_ino: "16",
    },
  });
  assert.deepEqual(context.calls.commandWrites[1], {
    variable: "GITHUB_OUTPUT",
    entries: OUTPUTS,
  });
});

test("bootstrap buffers are bounded and zeroed only after write completion", async () => {
  const actionEnvironment = environment();
  const inputs = validateInputs(actionEnvironment);
  const frame = buildBootstrapFrame(inputs, actionEnvironment);
  assert(frame.includes(Buffer.from("provider-request-secret")));
  let writeCallback;
  const stream = {
    write(_value, callback) {
      writeCallback = callback;
    },
  };
  const written = writeBootstrap(stream, frame);
  assert(frame.includes(Buffer.from("provider-request-secret")));
  writeCallback();
  await written;
  assert(frame.every((byte) => byte === 0));

  const oversized = environment();
  oversized.ACTIONS_ID_TOKEN_REQUEST_TOKEN = "s".repeat(32 * 1024 + 1);
  assert.throws(() => validateInputs(oversized), /absent or invalid/);
  const totalOversized = environment();
  const prefix = "https://issuer.example/";
  totalOversized.ACTIONS_ID_TOKEN_REQUEST_URL = `${prefix}${"u".repeat(32 * 1024 - prefix.length)}`;
  totalOversized.ACTIONS_ID_TOKEN_REQUEST_TOKEN = "s".repeat(32 * 1024);
  assert.throws(
    () => buildBootstrapFrame(validateInputs(totalOversized), totalOversized),
    /field length|too large/,
  );
});

test("provider kind and expected origin are closed inputs", () => {
  const invalidProvider = environment();
  invalidProvider["INPUT_PROVIDER-KIND"] = "generic";
  assert.throws(() => validateInputs(invalidProvider), /provider kind/);
  for (const origin of [
    "http://issuer.example",
    "https://issuer.example/path",
    "https://issuer.example/",
    "https://ISSUER.example",
  ]) {
    const invalidOrigin = environment();
    invalidOrigin["INPUT_EXPECTED-TOKEN-REQUEST-ORIGIN"] = origin;
    assert.throws(
      () => validateInputs(invalidOrigin),
      /expected token-request origin/,
    );
  }
});

test("executable metadata requires non-root runner and root-owned immutable bytes", () => {
  const metadata = (uid, mode, regular = true) => ({
    uid,
    mode,
    isFile: () => regular,
  });
  assert.doesNotThrow(() =>
    validateExecutableMetadata(metadata(0, 0o100555), 1000),
  );
  assert.throws(
    () => validateExecutableMetadata(metadata(0, 0o100555), 0),
    /non-root/,
  );
  assert.throws(
    () => validateExecutableMetadata(metadata(1000, 0o100555), 1000),
    /root-owned/,
  );
  assert.throws(
    () => validateExecutableMetadata(metadata(0, 0o100575), 1000),
    /root-owned/,
  );
  assert.throws(
    () => validateExecutableMetadata(metadata(0, 0o100555, false), 1000),
    /root-owned/,
  );
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  test(`${signal} before acknowledgement closes stdin and waits without signals`, async () => {
    const context = harness((value) => {
      value.operations.readStartupLine = async () => {
        value.signalSource.emit(signal);
        await new Promise((resolve) => setImmediate(resolve));
        return "startup";
      };
    });
    await assert.rejects(runAction(context), ActionCancelled);
    assert.equal(context.child.stdin.ended, true);
    assert.equal(context.calls.waitedForExit, 1);
    assert.equal(context.child.kills, undefined);
    assert.equal(
      context.signalSource.exitCode,
      signal === "SIGINT" ? 130 : 143,
    );
  });
}

test("signal while the commit callback is pending uses socket shutdown", async () => {
  const context = harness((value) => {
    value.operations.commitBootstrap = (stream) =>
      new Promise((resolve) => {
        stream.end(Buffer.from([1]), () => {
          value.signalSource.emit("SIGTERM");
          setImmediate(resolve);
        });
      });
  });
  await assert.rejects(runAction(context), ActionCancelled);
  assert.deepEqual(context.calls.controlRequests, ["shutdown"]);
  assert.equal(context.calls.waitedForExit, 0);
  assert.equal(context.child.kills, undefined);
});

test("GITHUB_STATE failure cancels the unacknowledged runtime", async () => {
  const context = harness((value) => {
    value.operations.writeCommandEntries = (variable, entries) => {
      value.calls.commandWrites.push({ variable, entries });
      if (variable === "GITHUB_STATE") {
        throw new Error("GITHUB_STATE write failed");
      }
    };
  });
  await assert.rejects(runAction(context), /write failed/);
  assert.equal(context.child.stdin.ended, true);
  assert.equal(context.calls.waitedForExit, 1);
  assert.equal(context.child.kills, undefined);
  assert.equal(context.child.unrefCalled, false);
});

test("GITHUB_OUTPUT stays unpublished until qualification succeeds", async () => {
  const context = harness((value) => {
    value.operations.qualificationRequest = async () => ({
      evidence: Buffer.from('{"status":"rejected"}', "utf8"),
      receipt: undefined,
    });
  });
  await assert.rejects(runAction(context), /qualification was rejected/);
  assert.deepEqual(
    context.calls.commandWrites.map(({ variable }) => variable),
    ["GITHUB_STATE"],
  );
  assert.deepEqual(context.calls.controlRequests, ["status", "shutdown"]);
  assert.equal(context.child.unrefCalled, false);
});

test("signal during qualification cannot retain evidence or publish outputs", async () => {
  const context = harness((value) => {
    value.operations.qualificationRequest = async () => {
      value.signalSource.emit("SIGTERM");
      await new Promise((resolve) => setImmediate(resolve));
      return {
        receipt: Object.freeze({
          canonical: QUALIFICATION_RECEIPT,
          value: Object.freeze({}),
        }),
      };
    };
  });
  await assert.rejects(runAction(context), ActionCancelled);
  assert.deepEqual(context.calls.evidenceWrites, []);
  assert.deepEqual(context.calls.evidenceRemovals, []);
  assert.deepEqual(context.calls.logs, []);
  assert.deepEqual(
    context.calls.commandWrites.map(({ variable }) => variable),
    ["GITHUB_STATE"],
  );
  assert.deepEqual(context.calls.controlRequests, ["status", "shutdown"]);
});

test("GITHUB_OUTPUT failure shuts down the acknowledged runtime", async () => {
  const context = harness((value) => {
    value.operations.writeCommandEntries = (variable, entries) => {
      value.calls.commandWrites.push({ variable, entries });
      if (variable === "GITHUB_OUTPUT") {
        throw new Error("GITHUB_OUTPUT write failed");
      }
    };
  });
  await assert.rejects(runAction(context), /write failed/);
  assert.equal(context.child.stdin.ended, true);
  assert.deepEqual(context.calls.controlRequests, ["status", "shutdown"]);
  assert.equal(context.calls.waitedForExit, 0);
  assert.equal(context.child.unrefCalled, false);
});

test("action lifecycle code contains no process or child kill calls", () => {
  for (const file of ["main.mjs", "post.mjs", "session.mjs"]) {
    const source = fs.readFileSync(new URL(file, import.meta.url), "utf8");
    assert.equal(/\bprocess\.kill\s*\(|\.kill\s*\(/u.test(source), false, file);
  }
});

test("output parsing preserves the exact closed four-field contract", () => {
  const parsed = parseSessionOutputs(
    JSON.stringify({
      "session-control-socket": OUTPUTS["session-control-socket"],
      "adapter-sockets": JSON.parse(OUTPUTS["adapter-sockets"]),
      "proof-jkt": OUTPUTS["proof-jkt"],
      "proof-audience": OUTPUTS["proof-audience"],
    }),
  );
  assert.deepEqual(parsed, OUTPUTS);
  assert.throws(
    () => parseSessionOutputs(JSON.stringify({ ...OUTPUTS, extra: "value" })),
    /closed four-field contract/,
  );
});

test("qualification exposes one closed adapter socket", () => {
  assert.equal(
    qualificationAdapterSocket(OUTPUTS["adapter-sockets"]),
    "/runtime/qualification.sock",
  );
  for (const serialized of [
    "{}",
    '{"artifact-sign-qualification":"/runtime/qualification.sock","extra":"/runtime/extra.sock"}',
    '{"artifact-sign-qualification":"relative.sock"}',
    '{"artifact-sign-qualification":"/runtime/one.sock","artifact-sign-qualification":"/runtime/two.sock"}',
  ]) {
    assert.throws(
      () => qualificationAdapterSocket(serialized),
      /qualification adapter (sockets are invalid|socket is invalid)|qualification receipt fields are invalid/,
    );
  }
});

test("qualification adapter half-closes its exact request and accepts one closed receipt", async () => {
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), "basil-qualification-test-"),
  );
  const socketPath = path.join(root, "adapter.sock");
  const server = net.createServer((socket) => {
    let received = Buffer.alloc(0);
    socket.on("data", (chunk) => {
      received = Buffer.concat([received, chunk]);
    });
    socket.on("end", () => {
      const request = Buffer.from(
        '{"version":1,"operation":"artifact-sign-qualification"}',
        "utf8",
      );
      assert.equal(received.readUInt32BE(0), request.length);
      assert.deepEqual(received.subarray(4), request);
      const evidence = Buffer.from(QUALIFICATION_RECEIPT, "utf8");
      const response = Buffer.alloc(4 + evidence.length);
      response.writeUInt32BE(evidence.length, 0);
      evidence.copy(response, 4);
      socket.end(response);
    });
  });
  try {
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(socketPath, resolve);
    });
    const result = await qualificationRequest(socketPath);
    assert.equal(result.receipt.canonical, QUALIFICATION_RECEIPT);
    assert.equal(
      result.receipt.value["target-key-id"],
      "qualification.artifact-signing",
    );
  } finally {
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("qualification receipt and retained evidence stay closed and private", () => {
  const receipt = validateQualificationReceipt(QUALIFICATION_RECEIPT);
  assert.equal(receipt.value["signature-verified"], true);
  assert.throws(
    () =>
      validateQualificationReceipt(
        QUALIFICATION_RECEIPT.replace(
          '"status":"ok"',
          '"status":"ok","extra":true',
        ),
      ),
    /fields are invalid/,
  );
  assert.equal(
    validateQualificationReceipt('{"status":"rejected"}'),
    undefined,
  );
  const denied = JSON.parse(QUALIFICATION_RECEIPT);
  denied.value.result = "sealed-denied";
  denied.value["signature-sha256"] = null;
  denied.value["signature-verified"] = false;
  denied.value["denial-code"] = 2;
  denied.value["denial-retryable"] = false;
  assert.equal(
    validateQualificationReceipt(JSON.stringify(denied)).value.result,
    "sealed-denied",
  );
  for (const targetKeyId of [
    "qualification\u2028artifact",
    "qualification\u202eartifact",
    "qualification artifact",
  ]) {
    const invalidTarget = JSON.parse(QUALIFICATION_RECEIPT);
    invalidTarget.value["target-key-id"] = targetKeyId;
    assert.throws(
      () => validateQualificationReceipt(JSON.stringify(invalidTarget)),
      /target key ID is invalid/,
    );
  }

  const root = fs.mkdtempSync(path.join(os.tmpdir(), "basil-evidence-test-"));
  try {
    fs.chmodSync(root, 0o700);
    const evidence = Buffer.from(QUALIFICATION_RECEIPT, "utf8");
    const retained = writeQualificationEvidence(root, receipt);
    assert.match(retained.digest, /^[0-9a-f]{64}$/u);
    const filename = path.join(root, "artifact-sign-qualification-v1.json");
    assert.deepEqual(fs.readFileSync(filename), evidence);
    assert.equal(fs.statSync(filename).mode & 0o777, 0o600);
    const replacement = path.join(root, "replacement");
    fs.renameSync(filename, replacement);
    fs.writeFileSync(filename, "replacement", { mode: 0o600 });
    assert.throws(
      () => removeQualificationEvidence(retained),
      /changed before removal/,
    );
    assert.equal(fs.existsSync(filename), true);
    fs.unlinkSync(filename);
    fs.renameSync(replacement, filename);
    removeQualificationEvidence(retained);
    assert.equal(fs.existsSync(filename), false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("state contains only the control socket identity", () => {
  const previous = { ...process.env };
  process.env.STATE_control_socket = "/runtime/control.sock";
  process.env.STATE_control_dev = "15";
  process.env.STATE_control_ino = "16";
  process.env.STATE_pid = "4242";
  try {
    assert.deepEqual(parseState(), {
      controlSocket: "/runtime/control.sock",
      controlIdentity: { dev: "15", ino: "16" },
    });
  } finally {
    process.env = previous;
  }
});

test("command files reject injection shapes", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "basil-command-test-"));
  const commandFile = path.join(root, "output");
  fs.writeFileSync(commandFile, "", { mode: 0o600 });
  const previous = process.env.GITHUB_OUTPUT;
  process.env.GITHUB_OUTPUT = commandFile;
  try {
    assert.throws(
      () => writeCommandEntries("GITHUB_OUTPUT", { "bad\nname": "value" }),
      /invalid GITHUB_OUTPUT entry/,
    );
    writeCommandEntries("GITHUB_OUTPUT", { value: "line1\nname=forged" });
    assert.match(
      fs.readFileSync(commandFile, "utf8"),
      /^value<<(BASIL_[0-9a-f]{32})\nline1\nname=forged\n\1\n$/,
    );
  } finally {
    if (previous === undefined) delete process.env.GITHUB_OUTPUT;
    else process.env.GITHUB_OUTPUT = previous;
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("provider secrets never enter arguments, state, outputs, or errors", async () => {
  const context = harness();
  await runAction(context);
  const observable = JSON.stringify({
    arguments: context.spawnCall().args,
    environment: context.spawnCall().options.env,
    commandWrites: context.calls.commandWrites,
    outputs: OUTPUTS,
  });
  assert.equal(observable.includes("provider-request-secret"), false);
  assert.equal(observable.includes("job-secret-that-must-not-pass"), false);
});

function sentinelEncodings(value) {
  return [
    value,
    Buffer.from(value, "utf8").toString("hex"),
    Buffer.from(value, "utf8").toString("base64url"),
    JSON.stringify(value).slice(1, -1),
    encodeURIComponent(value),
  ];
}

test("action seam retains only the closed receipt and four outputs", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "basil-secret-scan-"));
  const stateFile = path.join(root, "state");
  const outputFile = path.join(root, "output");
  const controlSocket = path.join(root, "control.sock");
  fs.chmodSync(root, 0o700);
  fs.writeFileSync(stateFile, "", { mode: 0o600 });
  fs.writeFileSync(outputFile, "", { mode: 0o600 });
  const listener = net.createServer();
  const child = new FakeChild();
  const signalSource = new EventEmitter();
  const sentinels = Object.freeze({
    bearer: "BASIL_SENTINEL_BEARER_7e0b6ca1",
    jwt: "BASIL_SENTINEL_JWT_31f2a8d9",
    jti: "BASIL_SENTINEL_JTI_44bc9e10",
    proof: "BASIL_SENTINEL_PROOF_9da4c720",
    challenge: "BASIL_SENTINEL_CHALLENGE_4af18d5c",
    sealedRequest: "BASIL_SENTINEL_SEALED_REQUEST_1d7e6a3b",
    sealedResponse: "BASIL_SENTINEL_SEALED_RESPONSE_b8c73a19",
    signature: "BASIL_SENTINEL_SIGNATURE_2ce90bf4",
    environment: "BASIL_SENTINEL_ENVIRONMENT_d5a1068e",
  });
  const actionEnvironment = {
    ...environment(),
    RUNNER_TEMP: root,
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: sentinels.bearer,
    BASIL_TEST_SENTINEL: sentinels.environment,
  };
  const outputs = {
    ...OUTPUTS,
    "session-control-socket": controlSocket,
    "adapter-sockets": JSON.stringify({
      "artifact-sign-qualification": path.join(root, "qualification.sock"),
    }),
  };
  const receipt = Object.freeze({
    canonical: QUALIFICATION_RECEIPT,
    value: Object.freeze({}),
  });
  const snapshots = [];
  const stdout = [];
  const stderr = [];
  const previousEnvironment = {
    GITHUB_OUTPUT: process.env.GITHUB_OUTPUT,
    GITHUB_STATE: process.env.GITHUB_STATE,
  };
  const previousLog = console.log;
  const previousError = console.error;
  try {
    await new Promise((resolve, reject) => {
      listener.once("error", reject);
      listener.listen(controlSocket, resolve);
    });
    process.env.GITHUB_STATE = stateFile;
    process.env.GITHUB_OUTPUT = outputFile;
    console.log = (line) => stdout.push(String(line));
    console.error = (line) => stderr.push(String(line));
    await runAction({
      environment: actionEnvironment,
      signalSource,
      spawnProcess: () => child,
      operations: {
        requireLinux() {},
        validateInputs() {
          return {
            executable: "/reviewed/basil",
            digest: DIGEST,
            providerKind: "github",
            expectedOrigin: "https://issuer.example",
            maxAgeText: "120",
            runtimeParent: root,
          };
        },
        buildBootstrapFrame,
        clearProviderEnvironment,
        openReviewedExecutable() {
          return { descriptor: 99 };
        },
        closeReviewedExecutable() {},
        waitForChildSpawn(target) {
          queueMicrotask(() => target.emit("spawn"));
          return new Promise((resolve) => target.once("spawn", resolve));
        },
        writeBootstrap,
        readStartupLine: async () =>
          JSON.stringify({
            "session-control-socket": controlSocket,
            "adapter-sockets": JSON.parse(outputs["adapter-sockets"]),
            "proof-jkt": JKT,
            "proof-audience": `urn:basil:ci:jkt:${JKT}`,
          }),
        parseSessionOutputs,
        socketIdentity,
        writeCommandEntries,
        commitBootstrap(stream) {
          return new Promise((resolve) =>
            stream.end(Buffer.from([1]), resolve),
          );
        },
        waitForOwnedChildExit: async () => true,
        controlStateIsCurrent: () => true,
        controlRequest: async (_socket, operation) => ({
          status: operation === "status" ? "running" : "shutting-down",
        }),
        qualificationAdapterSocket,
        qualificationRequest: async () => ({
          receipt,
          ignoredBoundaryBytes: Buffer.from(Object.values(sentinels).join("|")),
          providerJwt: sentinels.jwt,
          providerJti: sentinels.jti,
          proofPrivate: sentinels.proof,
          challenge: sentinels.challenge,
          sealedRequest: sentinels.sealedRequest,
          sealedResponse: sentinels.sealedResponse,
          signature: sentinels.signature,
        }),
        writeQualificationEvidence,
        removeQualificationEvidence(evidence) {
          snapshots.push(fs.readFileSync(evidence.filename));
          removeQualificationEvidence(evidence);
        },
        waitForSocketDisappearance: async () => true,
      },
    });

    const retained = [
      Buffer.from(stdout.join("\n")),
      Buffer.from(stderr.join("\n")),
      fs.readFileSync(stateFile),
      fs.readFileSync(outputFile),
      ...snapshots,
      Buffer.from(fs.readdirSync(root).sort().join("\n")),
    ].map((bytes) => bytes.toString("utf8"));
    for (const secret of Object.values(sentinels)) {
      for (const encoding of sentinelEncodings(secret)) {
        assert.equal(
          retained.some((source) => source.includes(encoding)),
          false,
          `retained action data contains a seeded secret encoding: ${encoding}`,
        );
      }
    }
    assert.deepEqual(stdout, [
      `BASIL_CI_QUALIFICATION_RECEIPT_V1 ${QUALIFICATION_RECEIPT} sha256=${createHash("sha256").update(QUALIFICATION_RECEIPT).digest("hex")}`,
    ]);
    assert.deepEqual(stderr, []);
    assert.match(fs.readFileSync(stateFile, "utf8"), /control_socket<</);
    assert.match(fs.readFileSync(outputFile, "utf8"), /proof-jkt<</);
    assert.equal(
      fs.existsSync(path.join(root, "artifact-sign-qualification-v1.json")),
      false,
    );
  } finally {
    console.log = previousLog;
    console.error = previousError;
    if (previousEnvironment.GITHUB_STATE === undefined)
      delete process.env.GITHUB_STATE;
    else process.env.GITHUB_STATE = previousEnvironment.GITHUB_STATE;
    if (previousEnvironment.GITHUB_OUTPUT === undefined)
      delete process.env.GITHUB_OUTPUT;
    else process.env.GITHUB_OUTPUT = previousEnvironment.GITHUB_OUTPUT;
    await new Promise((resolve) => listener.close(resolve));
    fs.rmSync(root, { recursive: true, force: true });
  }
});
