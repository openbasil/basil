// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";

const MAX_STARTUP_BYTES = 64 * 1024;
const MAX_COMMAND_VALUE_BYTES = 64 * 1024;
const CONTROL_REQUEST = Buffer.from('{"operation":"shutdown"}', "utf8");
const STATUS_REQUEST = Buffer.from('{"operation":"status"}', "utf8");
const CONTROL_RESPONSE_LIMIT = 1024;

export function requireLinux() {
  if (process.platform !== "linux" || !fs.existsSync("/proc/self/stat")) {
    throw new Error("the Basil CI session action requires Linux with procfs");
  }
}

export function actionInput(name) {
  const key = `INPUT_${name.toUpperCase()}`;
  const value = process.env[key];
  if (value === undefined || value === "") {
    throw new Error(`required action input ${name} is absent`);
  }
  if (value.includes("\0") || value.includes("\r") || value.includes("\n")) {
    throw new Error(`action input ${name} contains forbidden characters`);
  }
  return value;
}

export function validateInputs() {
  const executable = actionInput("basil-executable");
  const digest = actionInput("basil-executable-sha256");
  const maxAgeText = actionInput("rule-max-token-age-seconds");
  if (!path.isAbsolute(executable)) {
    throw new Error("the reviewed Basil executable path must be absolute");
  }
  if (!/^[0-9a-f]{64}$/.test(digest)) {
    throw new Error(
      "the reviewed Basil executable digest must be lowercase SHA-256",
    );
  }
  if (!/^[1-9][0-9]{0,2}$/.test(maxAgeText)) {
    throw new Error("the rule maximum token age must be an integer in 1..=900");
  }
  const maxAge = Number(maxAgeText);
  if (!Number.isSafeInteger(maxAge) || maxAge > 900) {
    throw new Error("the rule maximum token age must be an integer in 1..=900");
  }
  requireProviderMemory();
  return { executable, digest, maxAgeText };
}

function requireProviderMemory() {
  for (const name of [
    "ACTIONS_ID_TOKEN_REQUEST_URL",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
  ]) {
    const value = process.env[name];
    if (value === undefined || value.length === 0 || value.length > 32 * 1024) {
      throw new Error(`provider-injected ${name} is absent or invalid`);
    }
  }
}

function safeRuntimeParent() {
  const parent = process.env.RUNNER_TEMP;
  if (parent === undefined || !path.isAbsolute(parent)) {
    throw new Error("RUNNER_TEMP must name an absolute directory");
  }
  const metadata = fs.lstatSync(parent);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error("RUNNER_TEMP is not a directory");
  }
  return parent;
}

function openReviewedExecutable(source) {
  const flags = fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW;
  const descriptor = fs.openSync(source, flags);
  const metadata = fs.fstatSync(descriptor);
  if (
    !metadata.isFile() ||
    (metadata.mode & 0o111) === 0 ||
    (metadata.mode & 0o022) !== 0
  ) {
    fs.closeSync(descriptor);
    throw new Error(
      "the reviewed Basil path is not a non-writable regular executable",
    );
  }
  return { descriptor, metadata };
}

export function stageReviewedExecutable(source, expectedDigest) {
  const parent = safeRuntimeParent();
  const directory = fs.mkdtempSync(path.join(parent, "basil-ci-action-"));
  fs.chmodSync(directory, 0o700);
  const staged = path.join(directory, "basil");
  let sourceDescriptor;
  let stagedDescriptor;
  try {
    ({ descriptor: sourceDescriptor } = openReviewedExecutable(source));
    stagedDescriptor = fs.openSync(
      staged,
      fs.constants.O_WRONLY |
        fs.constants.O_CREAT |
        fs.constants.O_EXCL |
        fs.constants.O_NOFOLLOW,
      0o500,
    );
    const digest = crypto.createHash("sha256");
    const buffer = Buffer.alloc(64 * 1024);
    let offset = 0;
    for (;;) {
      const count = fs.readSync(
        sourceDescriptor,
        buffer,
        0,
        buffer.length,
        offset,
      );
      if (count === 0) {
        break;
      }
      digest.update(buffer.subarray(0, count));
      let written = 0;
      while (written < count) {
        written += fs.writeSync(
          stagedDescriptor,
          buffer,
          written,
          count - written,
          offset + written,
        );
      }
      offset += count;
    }
    if (digest.digest("hex") !== expectedDigest) {
      throw new Error("the reviewed Basil executable digest does not match");
    }
    fs.fsyncSync(stagedDescriptor);
    fs.fchmodSync(stagedDescriptor, 0o500);
    const stagedMetadata = fs.fstatSync(stagedDescriptor);
    if (
      !stagedMetadata.isFile() ||
      stagedMetadata.uid !== process.geteuid() ||
      (stagedMetadata.mode & 0o7777) !== 0o500
    ) {
      throw new Error("the staged Basil executable has unsafe metadata");
    }
    return {
      directory,
      directoryIdentity: identityOf(fs.lstatSync(directory)),
      executable: staged,
      executableIdentity: identityOf(stagedMetadata),
    };
  } catch (error) {
    removeStagedExecutable(directory);
    throw error;
  } finally {
    if (sourceDescriptor !== undefined) {
      fs.closeSync(sourceDescriptor);
    }
    if (stagedDescriptor !== undefined) {
      fs.closeSync(stagedDescriptor);
    }
  }
}

function identityOf(metadata) {
  return { dev: metadata.dev.toString(), ino: metadata.ino.toString() };
}

export function processIdentity(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 1) {
    return undefined;
  }
  try {
    const stat = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
    const commEnd = stat.lastIndexOf(") ");
    if (commEnd < 0) {
      return undefined;
    }
    const fields = stat
      .slice(commEnd + 2)
      .trim()
      .split(/ +/u);
    const startTime = fields[19];
    if (startTime === undefined || !/^[0-9]+$/.test(startTime)) {
      return undefined;
    }
    const executable = fs.statSync(`/proc/${pid}/exe`);
    return { startTime, ...identityOf(executable) };
  } catch (error) {
    if (error?.code === "ENOENT" || error?.code === "ESRCH") {
      return undefined;
    }
    throw error;
  }
}

export function sameProcess(pid, expected) {
  const current = processIdentity(pid);
  return (
    current !== undefined &&
    current.startTime === expected.startTime &&
    current.dev === expected.dev &&
    current.ino === expected.ino
  );
}

export function readStartupLine(stream, child, timeoutMilliseconds = 10_000) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let bytes = Buffer.alloc(0);
    const timer = setTimeout(
      () => finish(new Error("Basil CI session startup timed out")),
      timeoutMilliseconds,
    );
    const finish = (error, value) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      stream.off("data", onData);
      child.off("error", onError);
      child.off("exit", onExit);
      if (error === undefined) {
        resolve(value);
      } else {
        reject(error);
      }
    };
    const onError = () =>
      finish(new Error("the Basil CI session process could not start"));
    const onExit = () =>
      finish(new Error("the Basil CI session exited during startup"));
    const onData = (chunk) => {
      bytes = Buffer.concat([bytes, chunk]);
      if (bytes.length > MAX_STARTUP_BYTES) {
        finish(new Error("the Basil CI session startup response is too large"));
        return;
      }
      const newline = bytes.indexOf(0x0a);
      if (newline < 0) {
        return;
      }
      if (
        newline !== bytes.length - 1 ||
        bytes.subarray(0, newline).includes(0x0d)
      ) {
        finish(new Error("the Basil CI session emitted multiline output"));
        return;
      }
      const line = bytes.subarray(0, newline).toString("utf8");
      setTimeout(() => {
        if (bytes.length !== newline + 1) {
          finish(new Error("the Basil CI session emitted multiline output"));
        } else {
          finish(undefined, line);
        }
      }, 20);
    };
    stream.on("data", onData);
    child.once("error", onError);
    child.once("exit", onExit);
  });
}

class StrictJsonParser {
  constructor(text) {
    this.text = text;
    this.offset = 0;
  }

  parse() {
    const value = this.value();
    this.space();
    if (this.offset !== this.text.length) {
      throw new Error("trailing JSON data");
    }
    return value;
  }

  value() {
    this.space();
    const next = this.text[this.offset];
    if (next === "{") return this.object();
    if (next === "[") return this.array();
    if (next === '"') return this.string();
    for (const [literal, value] of [
      ["true", true],
      ["false", false],
      ["null", null],
    ]) {
      if (this.text.startsWith(literal, this.offset)) {
        this.offset += literal.length;
        return value;
      }
    }
    throw new Error("unsupported JSON value");
  }

  object() {
    const result = Object.create(null);
    const keys = new Set();
    this.expect("{");
    this.space();
    if (this.take("}")) return result;
    for (;;) {
      const key = this.string();
      if (keys.has(key)) throw new Error("duplicate JSON object member");
      keys.add(key);
      this.space();
      this.expect(":");
      result[key] = this.value();
      this.space();
      if (this.take("}")) return result;
      this.expect(",");
      this.space();
    }
  }

  array() {
    const result = [];
    this.expect("[");
    this.space();
    if (this.take("]")) return result;
    for (;;) {
      result.push(this.value());
      this.space();
      if (this.take("]")) return result;
      this.expect(",");
    }
  }

  string() {
    if (this.text[this.offset] !== '"') throw new Error("expected JSON string");
    const start = this.offset;
    this.offset += 1;
    let escaped = false;
    for (; this.offset < this.text.length; this.offset += 1) {
      const character = this.text[this.offset];
      if (!escaped && character === '"') {
        this.offset += 1;
        return JSON.parse(this.text.slice(start, this.offset));
      }
      if (!escaped && character.charCodeAt(0) < 0x20)
        throw new Error("invalid JSON string");
      if (!escaped && character === "\\") escaped = true;
      else escaped = false;
    }
    throw new Error("unterminated JSON string");
  }

  space() {
    while (/\s/u.test(this.text[this.offset] ?? "")) this.offset += 1;
  }

  expect(character) {
    if (!this.take(character)) throw new Error(`expected ${character}`);
  }

  take(character) {
    if (this.text[this.offset] !== character) return false;
    this.offset += 1;
    return true;
  }
}

export function parseSessionOutputs(line) {
  let parsed;
  try {
    parsed = new StrictJsonParser(line).parse();
  } catch {
    throw new Error("the Basil CI session emitted invalid JSON");
  }
  if (parsed === null || Array.isArray(parsed) || typeof parsed !== "object") {
    throw new Error("the Basil CI session output must be an object");
  }
  const expected = [
    "adapter-sockets",
    "proof-audience",
    "proof-jkt",
    "session-control-socket",
  ];
  const actual = Object.keys(parsed).sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    throw new Error(
      "the Basil CI session output fields are not the closed four-field contract",
    );
  }
  const control = parsed["session-control-socket"];
  const adapters = parsed["adapter-sockets"];
  const jkt = parsed["proof-jkt"];
  const audience = parsed["proof-audience"];
  validateAbsoluteValue(control, "session control socket");
  if (
    adapters === null ||
    Array.isArray(adapters) ||
    typeof adapters !== "object"
  ) {
    throw new Error("adapter sockets must be a JSON object");
  }
  for (const [name, socket] of Object.entries(adapters)) {
    if (!/^[a-z0-9][a-z0-9-]*$/.test(name)) {
      throw new Error("an adapter socket name is invalid");
    }
    validateAbsoluteValue(socket, "adapter socket");
  }
  if (typeof jkt !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(jkt)) {
    throw new Error("the proof thumbprint has an invalid shape");
  }
  if (audience !== `urn:basil:ci:jkt:${jkt}`) {
    throw new Error("the proof audience is not bound to the proof thumbprint");
  }
  return {
    "session-control-socket": control,
    "adapter-sockets": JSON.stringify(adapters),
    "proof-jkt": jkt,
    "proof-audience": audience,
  };
}

function validateAbsoluteValue(value, label) {
  if (
    typeof value !== "string" ||
    !path.isAbsolute(value) ||
    value.includes("\0") ||
    value.includes("\r") ||
    value.includes("\n") ||
    Buffer.byteLength(value) > 4096
  ) {
    throw new Error(`${label} is invalid`);
  }
}

function openCommandFile(variable) {
  const filename = process.env[variable];
  if (filename === undefined || !path.isAbsolute(filename)) {
    throw new Error(`${variable} must name an absolute command file`);
  }
  const before = fs.lstatSync(filename);
  if (
    !before.isFile() ||
    before.isSymbolicLink() ||
    before.uid !== process.geteuid() ||
    before.nlink !== 1 ||
    (before.mode & 0o022) !== 0
  ) {
    throw new Error(`${variable} is not an owner-controlled regular file`);
  }
  const descriptor = fs.openSync(
    filename,
    fs.constants.O_WRONLY | fs.constants.O_APPEND | fs.constants.O_NOFOLLOW,
  );
  const opened = fs.fstatSync(descriptor);
  if (
    opened.dev !== before.dev ||
    opened.ino !== before.ino ||
    !opened.isFile()
  ) {
    fs.closeSync(descriptor);
    throw new Error(`${variable} changed while opening`);
  }
  return descriptor;
}

export function writeCommandEntries(variable, entries) {
  const descriptor = openCommandFile(variable);
  try {
    let body = "";
    for (const [name, rawValue] of Object.entries(entries)) {
      const value = String(rawValue);
      if (
        !/^[a-z][a-z0-9_-]*$/.test(name) ||
        Buffer.byteLength(value) > MAX_COMMAND_VALUE_BYTES
      ) {
        throw new Error(`invalid ${variable} entry`);
      }
      let delimiter;
      do {
        delimiter = `BASIL_${crypto.randomBytes(16).toString("hex")}`;
      } while (value.split("\n").includes(delimiter));
      body += `${name}<<${delimiter}\n${value}\n${delimiter}\n`;
    }
    fs.writeSync(descriptor, body, null, "utf8");
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

export function socketIdentity(socketPath) {
  validateAbsoluteValue(socketPath, "session control socket");
  const metadata = fs.lstatSync(socketPath);
  if (
    !metadata.isSocket() ||
    metadata.isSymbolicLink() ||
    metadata.uid !== process.geteuid()
  ) {
    throw new Error(
      "the session control path is not an owner-controlled socket",
    );
  }
  return identityOf(metadata);
}

function framed(request) {
  const frame = Buffer.alloc(4 + request.length);
  frame.writeUInt32BE(request.length, 0);
  request.copy(frame, 4);
  return frame;
}

export function controlRequest(
  socketPath,
  operation,
  timeoutMilliseconds = 2_000,
) {
  const request = operation === "status" ? STATUS_REQUEST : CONTROL_REQUEST;
  return new Promise((resolve, reject) => {
    let settled = false;
    let response = Buffer.alloc(0);
    const socket = net.createConnection({ path: socketPath });
    const timer = setTimeout(
      () => finish(new Error("session lifecycle request timed out")),
      timeoutMilliseconds,
    );
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      if (error === undefined) resolve(value);
      else reject(error);
    };
    socket.once("connect", () => socket.write(framed(request)));
    socket.on("data", (chunk) => {
      response = Buffer.concat([response, chunk]);
      if (response.length > CONTROL_RESPONSE_LIMIT + 4) {
        finish(new Error("session lifecycle response is too large"));
        return;
      }
      if (response.length >= 4) {
        const length = response.readUInt32BE(0);
        if (length === 0 || length > CONTROL_RESPONSE_LIMIT) {
          finish(new Error("session lifecycle response length is invalid"));
        } else if (response.length === length + 4) {
          try {
            const value = JSON.parse(response.subarray(4).toString("utf8"));
            finish(undefined, value);
          } catch {
            finish(new Error("session lifecycle response is invalid"));
          }
        } else if (response.length > length + 4) {
          finish(new Error("session lifecycle response has trailing bytes"));
        }
      }
    });
    socket.once("error", () =>
      finish(new Error("session lifecycle request failed")),
    );
    socket.once("end", () => {
      if (!settled) finish(new Error("session lifecycle response ended early"));
    });
  });
}

export async function waitForExit(pid, expected, timeoutMilliseconds) {
  const deadline = Date.now() + timeoutMilliseconds;
  while (Date.now() < deadline) {
    if (!sameProcess(pid, expected)) return true;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  return !sameProcess(pid, expected);
}

export async function stopExactProcess(pid, expected, controlSocket) {
  if (!sameProcess(pid, expected)) return true;
  if (controlSocket !== undefined) {
    try {
      await controlRequest(controlSocket, "shutdown");
    } catch {
      // Continue to bounded, identity-checked signal escalation.
    }
    if (await waitForExit(pid, expected, 5_000)) return true;
  }
  if (!sameProcess(pid, expected)) return true;
  process.kill(pid, "SIGTERM");
  if (await waitForExit(pid, expected, 2_000)) return true;
  if (!sameProcess(pid, expected)) return true;
  process.kill(pid, "SIGKILL");
  return waitForExit(pid, expected, 2_000);
}

export function removeStagedExecutable(
  directory,
  expectedDirectory,
  expectedExecutable,
) {
  if (!path.isAbsolute(directory)) return;
  const staged = path.join(directory, "basil");
  try {
    const executableMetadata = fs.lstatSync(staged);
    if (
      expectedExecutable !== undefined &&
      (!executableMetadata.isFile() ||
        executableMetadata.dev.toString() !== expectedExecutable.dev ||
        executableMetadata.ino.toString() !== expectedExecutable.ino)
    ) {
      return;
    }
    fs.unlinkSync(staged);
  } catch (error) {
    if (error?.code !== "ENOENT") return;
  }
  try {
    const directoryMetadata = fs.lstatSync(directory);
    if (
      expectedDirectory !== undefined &&
      (!directoryMetadata.isDirectory() ||
        directoryMetadata.dev.toString() !== expectedDirectory.dev ||
        directoryMetadata.ino.toString() !== expectedDirectory.ino)
    ) {
      return;
    }
    fs.rmdirSync(directory);
  } catch {
    // A non-empty or replaced staging directory is deliberately left untouched.
  }
}

export function parseState() {
  const required = [
    "pid",
    "start_time",
    "exe_dev",
    "exe_ino",
    "stage_directory",
    "stage_dev",
    "stage_ino",
  ];
  const values = Object.create(null);
  for (const name of required) {
    const value = process.env[`STATE_${name}`];
    if (
      value === undefined ||
      value.includes("\r") ||
      value.includes("\n") ||
      value.includes("\0")
    ) {
      return undefined;
    }
    values[name] = value;
  }
  if (!/^[0-9]+$/.test(values.pid) || !/^[0-9]+$/.test(values.start_time))
    return undefined;
  const pid = Number(values.pid);
  if (
    !Number.isSafeInteger(pid) ||
    pid <= 1 ||
    !path.isAbsolute(values.stage_directory)
  )
    return undefined;
  return {
    pid,
    process: {
      startTime: values.start_time,
      dev: values.exe_dev,
      ino: values.exe_ino,
    },
    stageDirectory: values.stage_directory,
    stageDirectoryIdentity: { dev: values.stage_dev, ino: values.stage_ino },
    executableIdentity: { dev: values.exe_dev, ino: values.exe_ino },
    controlSocket: process.env.STATE_control_socket,
    controlIdentity: {
      dev: process.env.STATE_control_dev,
      ino: process.env.STATE_control_ino,
    },
  };
}

export function controlStateIsCurrent(state) {
  if (
    state.controlSocket === undefined ||
    state.controlIdentity.dev === undefined ||
    state.controlIdentity.ino === undefined
  )
    return false;
  try {
    const current = socketIdentity(state.controlSocket);
    return (
      current.dev === state.controlIdentity.dev &&
      current.ino === state.controlIdentity.ino
    );
  } catch {
    return false;
  }
}

export const testOnly = { StrictJsonParser, identityOf, os };
