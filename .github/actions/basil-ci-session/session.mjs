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
const MAX_BOOTSTRAP_BYTES = 64 * 1024;
const MAX_BOOTSTRAP_TOKEN_BYTES = 32 * 1024;
const MAX_BOOTSTRAP_FIELD_BYTES = 32 * 1024;
const BOOTSTRAP_MAGIC = Buffer.from("BASILCI\0", "binary");
const BOOTSTRAP_VERSION = 1;
const BOOTSTRAP_COMMIT = Buffer.from([1]);
const CONTROL_REQUEST = Buffer.from('{"operation":"shutdown"}', "utf8");
const STATUS_REQUEST = Buffer.from('{"operation":"status"}', "utf8");
const QUALIFICATION_REQUEST = Buffer.from(
  '{"version":1,"operation":"artifact-sign-qualification"}',
  "utf8",
);
const CONTROL_RESPONSE_LIMIT = 1024;
const QUALIFICATION_RESPONSE_LIMIT = 8 * 1024;
const QUALIFICATION_EVIDENCE_NAME = "artifact-sign-qualification-v1.json";
const PROVIDER_KINDS = new Set(["github", "forgejoActions"]);
const PROVIDER_ENVIRONMENT = Object.freeze([
  "ACTIONS_ID_TOKEN_REQUEST_URL",
  "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
]);

export function requireLinux() {
  if (process.platform !== "linux" || !fs.existsSync("/proc/self/stat")) {
    throw new Error("the Basil CI session action requires Linux with procfs");
  }
}

export function actionInput(name, environment = process.env) {
  const key = `INPUT_${name.toUpperCase()}`;
  const value = environment[key];
  if (value === undefined || value === "") {
    throw new Error(`required action input ${name} is absent`);
  }
  if (value.includes("\0") || value.includes("\r") || value.includes("\n")) {
    throw new Error(`action input ${name} contains forbidden characters`);
  }
  return value;
}

export function validateInputs(environment = process.env) {
  const executable = actionInput("basil-executable", environment);
  const digest = actionInput("basil-executable-sha256", environment);
  const providerKind = actionInput("provider-kind", environment);
  const expectedOrigin = actionInput(
    "expected-token-request-origin",
    environment,
  );
  const maxAgeText = actionInput("rule-max-token-age-seconds", environment);
  if (!path.isAbsolute(executable)) {
    throw new Error("the reviewed Basil executable path must be absolute");
  }
  if (!/^[0-9a-f]{64}$/.test(digest)) {
    throw new Error(
      "the reviewed Basil executable digest must be lowercase SHA-256",
    );
  }
  if (!PROVIDER_KINDS.has(providerKind)) {
    throw new Error("the provider kind is not supported");
  }
  validateExpectedOrigin(expectedOrigin);
  if (!/^[1-9][0-9]{0,2}$/.test(maxAgeText)) {
    throw new Error("the rule maximum token age must be an integer in 1..=900");
  }
  const maxAge = Number(maxAgeText);
  if (!Number.isSafeInteger(maxAge) || maxAge > 900) {
    throw new Error("the rule maximum token age must be an integer in 1..=900");
  }
  requireProviderMemory(environment);
  return {
    executable,
    digest,
    providerKind,
    expectedOrigin,
    maxAgeText,
    runtimeParent: safeRuntimeParent(environment),
  };
}

function validateExpectedOrigin(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error("the expected token-request origin is invalid");
  }
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.pathname !== "/" ||
    url.search !== "" ||
    url.hash !== "" ||
    url.origin !== value
  ) {
    throw new Error(
      "the expected token-request origin must be exact HTTPS origin",
    );
  }
}

function requireProviderMemory(environment) {
  for (const name of PROVIDER_ENVIRONMENT) {
    const value = environment[name];
    if (value === undefined || value.length === 0 || value.length > 32 * 1024) {
      throw new Error(`provider-injected ${name} is absent or invalid`);
    }
  }
}

function safeRuntimeParent(environment = process.env) {
  const parent = environment.RUNNER_TEMP;
  if (parent === undefined || !path.isAbsolute(parent)) {
    throw new Error("RUNNER_TEMP must name an absolute directory");
  }
  const metadata = fs.lstatSync(parent);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error("RUNNER_TEMP is not a directory");
  }
  return parent;
}

export function clearProviderEnvironment(environment = process.env) {
  for (const name of PROVIDER_ENVIRONMENT) delete environment[name];
}

export function validateExecutableMetadata(metadata, effectiveUid) {
  if (!Number.isSafeInteger(effectiveUid) || effectiveUid === 0) {
    throw new Error("the Basil CI session runner must be non-root");
  }
  if (
    !metadata.isFile() ||
    metadata.uid !== 0 ||
    (metadata.mode & 0o111) === 0 ||
    (metadata.mode & 0o022) !== 0
  ) {
    throw new Error(
      "the reviewed Basil path is not a root-owned non-writable regular executable",
    );
  }
}

export function openReviewedExecutable(source, expectedDigest) {
  const flags = fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW;
  const descriptor = fs.openSync(source, flags);
  try {
    const metadata = fs.fstatSync(descriptor);
    validateExecutableMetadata(metadata, process.geteuid());
    const digest = crypto.createHash("sha256");
    const buffer = Buffer.alloc(64 * 1024);
    let offset = 0;
    for (;;) {
      const count = fs.readSync(descriptor, buffer, 0, buffer.length, offset);
      if (count === 0) break;
      digest.update(buffer.subarray(0, count));
      offset += count;
    }
    buffer.fill(0);
    if (digest.digest("hex") !== expectedDigest) {
      throw new Error("the reviewed Basil executable digest does not match");
    }
    return { descriptor, metadata };
  } catch (error) {
    fs.closeSync(descriptor);
    throw error;
  }
}

export function closeReviewedExecutable(reviewed) {
  fs.closeSync(reviewed.descriptor);
}

export function buildBootstrapFrame(inputs, environment = process.env) {
  requireProviderMemory(environment);
  const values = [
    inputs.providerKind,
    inputs.expectedOrigin,
    environment.ACTIONS_ID_TOKEN_REQUEST_URL,
    environment.ACTIONS_ID_TOKEN_REQUEST_TOKEN,
  ].map((value) => Buffer.from(value, "utf8"));
  if (
    values.some(
      (value) => value.length === 0 || value.length > MAX_BOOTSTRAP_FIELD_BYTES,
    ) ||
    values[3].length > MAX_BOOTSTRAP_TOKEN_BYTES
  ) {
    for (const value of values) value.fill(0);
    throw new Error("the CI session bootstrap field length is invalid");
  }
  const length =
    BOOTSTRAP_MAGIC.length +
    1 +
    values.length * 4 +
    values.reduce((sum, value) => sum + value.length, 0);
  if (length > MAX_BOOTSTRAP_BYTES) {
    for (const value of values) value.fill(0);
    throw new Error("the CI session bootstrap frame is too large");
  }
  const frame = Buffer.alloc(length);
  let offset = 0;
  BOOTSTRAP_MAGIC.copy(frame, offset);
  offset += BOOTSTRAP_MAGIC.length;
  frame[offset] = BOOTSTRAP_VERSION;
  offset += 1;
  for (const value of values) {
    frame.writeUInt32BE(value.length, offset);
    offset += 4;
  }
  for (const value of values) {
    value.copy(frame, offset);
    offset += value.length;
    value.fill(0);
  }
  return frame;
}

function identityOf(metadata) {
  return { dev: metadata.dev.toString(), ino: metadata.ino.toString() };
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

export function waitForChildSpawn(child) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error) => {
      if (settled) return;
      settled = true;
      child.off("spawn", onSpawn);
      child.off("error", onError);
      child.off("exit", onExit);
      if (error === undefined) resolve();
      else reject(error);
    };
    const onSpawn = () => finish();
    const onError = () =>
      finish(new Error("the Basil CI session process could not start"));
    const onExit = () =>
      finish(new Error("the Basil CI session exited while starting"));
    child.once("spawn", onSpawn);
    child.once("error", onError);
    child.once("exit", onExit);
  });
}

export function writeBootstrap(stream, frame) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error) => {
      if (settled) return;
      settled = true;
      stream.off?.("error", onError);
      frame.fill(0);
      if (error === undefined || error === null) resolve();
      else reject(new Error("the Basil CI session bootstrap write failed"));
    };
    const onError = () => finish(new Error("bootstrap stream failed"));
    stream.once?.("error", onError);
    stream.write(frame, finish);
  });
}

export function commitBootstrap(stream) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error) => {
      if (settled) return;
      settled = true;
      stream.off?.("error", onError);
      if (error === undefined || error === null) resolve();
      else
        reject(new Error("the Basil CI session commit acknowledgement failed"));
    };
    const onError = () => finish(new Error("bootstrap stream failed"));
    stream.once?.("error", onError);
    stream.end(BOOTSTRAP_COMMIT, finish);
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
    if (next === "-" || (next !== undefined && /[0-9]/u.test(next))) {
      return this.number();
    }
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

  number() {
    const match = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
    match.lastIndex = this.offset;
    const result = match.exec(this.text);
    if (result === null) throw new Error("invalid JSON number");
    this.offset += result[0].length;
    return new JsonNumber(result[0]);
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

class JsonNumber {
  constructor(text) {
    this.text = text;
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

export function qualificationAdapterSocket(serialized) {
  let adapters;
  try {
    adapters = new StrictJsonParser(serialized).parse();
  } catch {
    throw new Error("qualification adapter sockets are invalid");
  }
  requireExactObjectKeys(adapters, ["artifact-sign-qualification"]);
  const socket = adapters["artifact-sign-qualification"];
  validateAbsoluteValue(socket, "qualification adapter socket");
  return socket;
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
  const encoded = Buffer.from(body, "utf8");
  const descriptor = openCommandFile(variable);
  try {
    let offset = 0;
    while (offset < encoded.length) {
      const written = fs.writeSync(
        descriptor,
        encoded,
        offset,
        encoded.length - offset,
      );
      if (written <= 0) {
        throw new Error(`${variable} command-file write made no progress`);
      }
      offset += written;
    }
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

export function qualificationRequest(socketPath, timeoutMilliseconds = 7_000) {
  validateAbsoluteValue(socketPath, "qualification adapter socket");
  return new Promise((resolve, reject) => {
    let settled = false;
    let response = Buffer.alloc(0);
    const socket = net.createConnection({ path: socketPath });
    const timer = setTimeout(
      () => finish(new Error("qualification adapter request timed out")),
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
    socket.once("connect", () => socket.end(framed(QUALIFICATION_REQUEST)));
    socket.on("data", (chunk) => {
      response = Buffer.concat([response, chunk]);
      if (response.length > QUALIFICATION_RESPONSE_LIMIT + 4) {
        finish(new Error("qualification adapter response is too large"));
        return;
      }
      if (response.length < 4) return;
      const length = response.readUInt32BE(0);
      if (length === 0 || length > QUALIFICATION_RESPONSE_LIMIT) {
        finish(new Error("qualification adapter response length is invalid"));
      } else if (response.length === length + 4) {
        const evidence = response.subarray(4);
        if (!Buffer.from(evidence.toString("utf8"), "utf8").equals(evidence)) {
          finish(new Error("qualification adapter response is not UTF-8"));
          return;
        }
        try {
          finish(undefined, {
            receipt: validateQualificationReceipt(evidence.toString("utf8")),
          });
        } catch {
          finish(new Error("qualification adapter response is invalid"));
        }
      } else if (response.length > length + 4) {
        finish(new Error("qualification adapter response has trailing bytes"));
      }
    });
    socket.once("error", () =>
      finish(new Error("qualification adapter request failed")),
    );
    socket.once("end", () => {
      if (!settled)
        finish(new Error("qualification adapter response ended early"));
    });
  });
}

export function validateQualificationReceipt(text) {
  if (Buffer.byteLength(text, "utf8") > QUALIFICATION_RESPONSE_LIMIT) {
    throw new Error("qualification receipt is too large");
  }
  const parsed = new StrictJsonParser(text).parse();
  if (parsed?.status === "rejected") {
    requireExactObjectKeys(parsed, ["status"]);
    return undefined;
  }
  requireExactObjectKeys(parsed, ["status", "value"]);
  if (parsed.status !== "ok")
    throw new Error("qualification receipt is rejected");
  const value = parsed.value;
  requireExactObjectKeys(value, [
    "ca-sha256",
    "config-sha256",
    "denial-code",
    "denial-retryable",
    "invocation-id",
    "policy-generation",
    "result",
    "signature-sha256",
    "signature-verified",
    "statement-sha256",
    "target-key-id",
    "version",
  ]);
  if (!(value.version instanceof JsonNumber) || value.version.text !== "1") {
    throw new Error("qualification receipt version is invalid");
  }
  if (
    typeof value["invocation-id"] !== "string" ||
    !/^[A-Za-z0-9_-]{43}$/u.test(value["invocation-id"])
  ) {
    throw new Error("qualification receipt invocation ID is invalid");
  }
  if (
    !(value["policy-generation"] instanceof JsonNumber) ||
    !/^(?:0|[1-9][0-9]{0,19})$/u.test(value["policy-generation"].text) ||
    BigInt(value["policy-generation"].text) > 18_446_744_073_709_551_615n
  ) {
    throw new Error("qualification receipt policy generation is invalid");
  }
  if (
    typeof value["target-key-id"] !== "string" ||
    !/^[A-Za-z0-9._:/@-]{1,256}$/u.test(value["target-key-id"])
  ) {
    throw new Error("qualification receipt target key ID is invalid");
  }
  for (const field of ["ca-sha256", "config-sha256", "statement-sha256"]) {
    if (
      typeof value[field] !== "string" ||
      !/^[0-9a-f]{64}$/u.test(value[field])
    ) {
      throw new Error(`qualification receipt ${field} is invalid`);
    }
  }
  if (value.result === "signed") {
    if (
      typeof value["signature-sha256"] !== "string" ||
      !/^[0-9a-f]{64}$/u.test(value["signature-sha256"]) ||
      value["signature-verified"] !== true ||
      value["denial-code"] !== null ||
      value["denial-retryable"] !== null
    ) {
      throw new Error("qualification receipt signed result is invalid");
    }
  } else if (
    value.result === "sealed-denied" &&
    value["signature-sha256"] === null &&
    value["signature-verified"] === false &&
    value["denial-code"] instanceof JsonNumber &&
    value["denial-code"].text === "2" &&
    value["denial-retryable"] === false
  ) {
    // The fixed denial is authenticated by the sealed response.
  } else {
    throw new Error("qualification receipt result is invalid");
  }
  return {
    canonical: canonicalQualificationReceipt(value),
    value,
  };
}

function canonicalQualificationReceipt(value) {
  return `{"status":"ok","value":{"version":1,"result":${JSON.stringify(value.result)},"invocation-id":${JSON.stringify(value["invocation-id"])},"policy-generation":${value["policy-generation"].text},"target-key-id":${JSON.stringify(value["target-key-id"])},"config-sha256":${JSON.stringify(value["config-sha256"])},"ca-sha256":${JSON.stringify(value["ca-sha256"])},"statement-sha256":${JSON.stringify(value["statement-sha256"])},"signature-sha256":${JSON.stringify(value["signature-sha256"])},"signature-verified":${value["signature-verified"]},"denial-code":${value["denial-code"] instanceof JsonNumber ? value["denial-code"].text : "null"},"denial-retryable":${value["denial-retryable"] === null ? "null" : value["denial-retryable"]}}}`;
}

function requireExactObjectKeys(value, expected) {
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    throw new Error("qualification receipt object is invalid");
  }
  const actual = Object.keys(value).sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    throw new Error("qualification receipt fields are invalid");
  }
}

export function writeQualificationEvidence(runtimeDirectory, receipt) {
  const evidence = Buffer.from(receipt.canonical, "utf8");
  if (
    !Buffer.isBuffer(evidence) ||
    evidence.length > QUALIFICATION_RESPONSE_LIMIT
  ) {
    throw new Error("qualification evidence is invalid");
  }
  const directory = fs.lstatSync(runtimeDirectory);
  if (
    !directory.isDirectory() ||
    directory.isSymbolicLink() ||
    directory.uid !== process.geteuid() ||
    (directory.mode & 0o077) !== 0
  ) {
    throw new Error("qualification evidence runtime directory is invalid");
  }
  const filename = path.join(runtimeDirectory, QUALIFICATION_EVIDENCE_NAME);
  const descriptor = fs.openSync(
    filename,
    fs.constants.O_WRONLY |
      fs.constants.O_CREAT |
      fs.constants.O_EXCL |
      fs.constants.O_NOFOLLOW,
    0o600,
  );
  try {
    const metadata = fs.fstatSync(descriptor);
    if (
      !metadata.isFile() ||
      metadata.uid !== process.geteuid() ||
      metadata.nlink !== 1 ||
      (metadata.mode & 0o077) !== 0
    ) {
      throw new Error("qualification evidence file is invalid");
    }
    let offset = 0;
    while (offset < evidence.length) {
      const written = fs.writeSync(
        descriptor,
        evidence,
        offset,
        evidence.length - offset,
      );
      if (written <= 0)
        throw new Error("qualification evidence write made no progress");
      offset += written;
    }
    fs.fsyncSync(descriptor);
    return {
      digest: crypto.createHash("sha256").update(evidence).digest("hex"),
      filename,
      identity: identityOf(metadata),
    };
  } finally {
    fs.closeSync(descriptor);
  }
}

export function removeQualificationEvidence(evidence) {
  const metadata = fs.lstatSync(evidence.filename);
  if (
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    metadata.uid !== process.geteuid() ||
    metadata.dev.toString() !== evidence.identity.dev ||
    metadata.ino.toString() !== evidence.identity.ino
  ) {
    throw new Error("qualification evidence changed before removal");
  }
  fs.unlinkSync(evidence.filename);
  const directory = fs.openSync(
    path.dirname(evidence.filename),
    fs.constants.O_RDONLY,
  );
  try {
    fs.fsyncSync(directory);
  } finally {
    fs.closeSync(directory);
  }
}

function childHasExited(child) {
  return child.exitCode !== null || child.signalCode !== null;
}

export function waitForOwnedChildExit(child, timeoutMilliseconds = 10_000) {
  if (childHasExited(child)) return Promise.resolve(true);
  return new Promise((resolve) => {
    const timer = setTimeout(() => finish(false), timeoutMilliseconds);
    const finish = (result) => {
      clearTimeout(timer);
      child.off("exit", onExit);
      resolve(result);
    };
    const onExit = () => finish(true);
    child.once("exit", onExit);
    if (childHasExited(child)) finish(true);
  });
}

function currentSocketIdentity(socketPath) {
  try {
    return socketIdentity(socketPath);
  } catch (error) {
    if (error?.code === "ENOENT") return undefined;
    throw error;
  }
}

export async function waitForSocketDisappearance(
  socketPath,
  expected,
  timeoutMilliseconds = 10_000,
) {
  const deadline = Date.now() + timeoutMilliseconds;
  while (Date.now() < deadline) {
    const current = currentSocketIdentity(socketPath);
    if (current === undefined) return true;
    if (current.dev !== expected.dev || current.ino !== expected.ino)
      return false;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  return currentSocketIdentity(socketPath) === undefined;
}

export function parseState() {
  const required = ["control_socket", "control_dev", "control_ino"];
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
  if (!path.isAbsolute(values.control_socket)) return undefined;
  return {
    controlSocket: values.control_socket,
    controlIdentity: {
      dev: values.control_dev,
      ino: values.control_ino,
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
