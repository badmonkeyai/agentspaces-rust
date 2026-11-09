// Copyright 2026 Bad Monkey, Inc.
// Author: Al Baker
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// A scripted MCP client over the official TypeScript SDK (`@modelcontextprotocol/sdk`), for the
// tests of `aspace mcp` (`crates/aspace/tests/mcp_clients.rs`) and of the `agentspaces-mcp`
// gateway (`crates/agentspaces-mcp/tests/independent_client.rs`): an MCP client that shares no
// code with rmcp or `aspace`, over standard input and output or over Streamable HTTP.
//
//   node node_client.mjs SDK_DIR stdio COMMAND [ARGS...]  spawns the server (the SDK's
//                                                         StdioClientTransport, environment
//                                                         passed through, stderr piped)
//   node node_client.mjs SDK_DIR http URL                 Streamable HTTP
//   node node_client.mjs SDK_DIR probe                    prints {"sdk": version, "node": ..}
//
// SDK_DIR is the package directory (`.../node_modules/@modelcontextprotocol/sdk`); it is only
// read. Operations are read from standard input, one JSON object per line, and each is answered
// with one JSON object per line on standard output: `{"ok": true, ...}`, or `{"ok": false,
// "error": .., "status": <HTTP status>|null, "challenge": <WWW-Authenticate>|null, "code":
// <JSON-RPC code>|null}`.
//
//   {"op":"connect","headers":{..}}        initialize (+ notifications/initialized); headers are
//                                          HTTP request headers -> serverInfo, protocolVersion,
//                                          capabilities
//   {"op":"tools"}                         tools/list (every page) -> tools
//   {"op":"call","name":..,"arguments":..,"timeoutMs":n,"progress":bool,"cancelAfterMs":n}
//                                          tools/call -> result, progress (the progress
//                                          notifications heard, when asked for), callMs; or
//                                          cancelled: true when aborted (notifications/cancelled)
//                                          with "background": true it is started and not
//                                          awaited -> started
//   {"op":"outcome"}                       the outcomes of every background call (after each
//                                          settled) -> outcomes
//   {"op":"terminate"}                     ends the HTTP session (DELETE)
//   {"op":"ping"}                          ping
//   {"op":"await","method":..,"timeoutMs":n,"after":k}
//                                          waits until more than k notifications of method arrived
//                                          -> count
//   {"op":"notifications"}                 the methods of every notification heard, in order
//   {"op":"frames"}                        how many messages the transport delivered, and every
//                                          transport error (a line on stdout that is not JSON-RPC)
//   {"op":"stderr"}                        the server's standard error lines so far (stdio)
//   {"op":"jwks","path":..}                makes an RSA key pair, writes its public JWKS (kid k1,
//                                          RS256) to path (mode 0600)
//   {"op":"jwt","claims":{..},"kid":..}    an RS256 token of claims signed by that key
//   {"op":"close"}                         closes the client (stdio: the SDK's close: stdin ended,
//                                          SIGTERM after 2 s) -> exit, signal, closeMs

import { pathToFileURL } from 'node:url';
import { createInterface } from 'node:readline';
import { generateKeyPairSync, sign } from 'node:crypto';
import { readFileSync, writeFileSync, chmodSync } from 'node:fs';
import { join } from 'node:path';

const [sdkDir, mode, target, ...rest] = process.argv.slice(2);
const load = (path) => import(pathToFileURL(join(sdkDir, 'dist/esm', path)).href);
const { Client } = await load('client/index.js');
const { StdioClientTransport } = await load('client/stdio.js');
const { StreamableHTTPClientTransport } = await load('client/streamableHttp.js');
const sdkVersion = JSON.parse(readFileSync(join(sdkDir, 'package.json'), 'utf8')).version;
if (mode === 'probe') {
  // The SDK loads: its version, and the transports this driver uses.
  process.stdout.write(JSON.stringify({ sdk: sdkVersion, node: process.version }) + '\n');
  process.exit(0);
}

let client = null;
let transport = null;
let child = null;
const notifications = [];
const waiters = [];
const transportErrors = [];
const stderrLines = [];
let delivered = 0;
let lastStatus = null;
let lastChallenge = null;
let exit = null;
let privateKey = null;
const background = [];

function out(object) {
  process.stdout.write(JSON.stringify(object) + '\n');
}

function heard(method) {
  notifications.push(method);
  for (const waiter of [...waiters]) {
    waiter();
  }
}

// fetch, recording the status and the challenge of every answer.
async function recordingFetch(url, init) {
  const response = await fetch(url, init);
  lastStatus = response.status;
  lastChallenge = response.headers.get('www-authenticate');
  return response;
}

async function connect(op) {
  if (client) {
    await client.close().catch(() => {});
  }
  client = new Client({ name: 'aspace-interop-node', version: sdkVersion }, { capabilities: {} });
  client.fallbackNotificationHandler = async (notification) => heard(notification.method);
  if (mode === 'stdio') {
    transport = new StdioClientTransport({
      command: target,
      args: rest,
      env: { ...process.env },
      stderr: 'pipe',
    });
    let partial = '';
    transport.stderr?.on('data', (chunk) => {
      partial += chunk.toString('utf8');
      const lines = partial.split('\n');
      partial = lines.pop();
      stderrLines.push(...lines);
    });
  } else {
    transport = new StreamableHTTPClientTransport(new URL(target), {
      requestInit: { headers: op.headers ?? {} },
      fetch: recordingFetch,
    });
  }
  transport.onerror = (error) => transportErrors.push(String(error?.message ?? error));
  const started = Date.now();
  await client.connect(transport);
  // Count every message the transport delivers, under the client's own handler.
  const inner = transport.onmessage;
  transport.onmessage = (message, extra) => {
    delivered += 1;
    inner?.(message, extra);
  };
  const onerror = transport.onerror;
  transport.onerror = (error) => {
    transportErrors.push(String(error?.message ?? error));
    onerror?.(error);
  };
  child = transport._process ?? null;
  child?.once('exit', (code, signal) => {
    exit = { code, signal };
  });
  return {
    serverInfo: client.getServerVersion(),
    capabilities: client.getServerCapabilities(),
    protocolVersion: transport.protocolVersion ?? null,
    pid: transport.pid ?? null,
    connectMs: Date.now() - started,
  };
}

async function tools() {
  const all = [];
  let cursor;
  do {
    const page = await client.listTools(cursor ? { cursor } : {});
    all.push(...page.tools);
    cursor = page.nextCursor;
  } while (cursor);
  return { tools: all };
}

function awaitNotification(op) {
  const count = () => notifications.filter((method) => method === op.method).length;
  const after = op.after ?? 0;
  return new Promise((resolve) => {
    const check = () => {
      if (count() > after) {
        cleanup();
        resolve({ count: count() });
        return true;
      }
      return false;
    };
    const timer = setTimeout(() => {
      cleanup();
      resolve({ count: count(), timedOut: true });
    }, op.timeoutMs ?? 30000);
    const cleanup = () => {
      clearTimeout(timer);
      const at = waiters.indexOf(check);
      if (at >= 0) waiters.splice(at, 1);
    };
    if (!check()) waiters.push(check);
  });
}

function makeJwks(op) {
  const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
  privateKey = pair.privateKey;
  const jwk = pair.publicKey.export({ format: 'jwk' });
  const set = { keys: [{ ...jwk, kid: 'k1', alg: 'RS256', use: 'sig' }] };
  writeFileSync(op.path, JSON.stringify(set));
  chmodSync(op.path, 0o600);
  return { kid: 'k1' };
}

function makeJwt(op) {
  const b64 = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const input = `${b64({ alg: 'RS256', typ: 'JWT', kid: op.kid ?? 'k1' })}.${b64(op.claims)}`;
  const signature = sign('sha256', Buffer.from(input), privateKey).toString('base64url');
  return { token: `${input}.${signature}` };
}

// tools/call; with "progress" the SDK sends a progressToken and the progress notifications
// are counted, and with "cancelAfterMs" the call is aborted then (notifications/cancelled).
async function call(op) {
  const progress = [];
  const options = { timeout: op.timeoutMs ?? 60000 };
  if (op.progress) {
    options.onprogress = (update) => progress.push(update);
  }
  let timer = null;
  if (op.cancelAfterMs !== undefined) {
    const controller = new AbortController();
    options.signal = controller.signal;
    timer = setTimeout(() => controller.abort('cancelled by the test'), op.cancelAfterMs);
  }
  const started = Date.now();
  try {
    const result = await client.callTool(
      { name: op.name, arguments: op.arguments ?? {} }, undefined, options);
    return { result, progress, callMs: Date.now() - started };
  } catch (error) {
    if (options.signal?.aborted) {
      return { cancelled: true, progress, callMs: Date.now() - started };
    }
    throw error;
  } finally {
    if (timer) clearTimeout(timer);
  }
}

async function close() {
  const started = Date.now();
  await client?.close();
  if (child && exit === null) {
    await new Promise((resolve) => {
      const timer = setTimeout(resolve, 5000);
      child.once('exit', () => {
        clearTimeout(timer);
        resolve();
      });
    });
  }
  return { exit: exit?.code ?? null, signal: exit?.signal ?? null, closeMs: Date.now() - started };
}

async function run(op) {
  switch (op.op) {
    case 'connect':
      return connect(op);
    case 'tools':
      return tools();
    case 'call':
      if (op.background) {
        // Started, not awaited: its outcome is kept for "outcome".
        background.push(call(op).then(
          (outcome) => ({ ok: true, ...outcome }),
          (error) => ({ ok: false, error: String(error?.message ?? error) })));
        return { started: true };
      }
      return call(op);
    case 'outcome':
      return { outcomes: await Promise.all(background) };
    case 'ping':
      await client.ping();
      return {};
    case 'terminate':
      await transport.terminateSession();
      return {};
    case 'await':
      return awaitNotification(op);
    case 'notifications':
      return { notifications };
    case 'frames':
      return { delivered, errors: transportErrors };
    case 'stderr':
      return { lines: stderrLines };
    case 'jwks':
      return makeJwks(op);
    case 'jwt':
      return makeJwt(op);
    case 'close':
      return close();
    default:
      throw new Error(`unknown op ${op.op}`);
  }
}

// One operation at a time, in order.
const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of lines) {
  if (!line.trim()) continue;
  let op;
  try {
    op = JSON.parse(line);
  } catch (error) {
    out({ ok: false, error: `not JSON: ${error.message}` });
    continue;
  }
  lastStatus = null;
  lastChallenge = null;
  try {
    out({ ok: true, ...(await run(op)) });
  } catch (error) {
    out({
      ok: false,
      error: String(error?.message ?? error),
      status: lastStatus ?? (Number.isInteger(error?.code) && error.code >= 100 ? error.code : null),
      challenge: lastChallenge,
      code: Number.isInteger(error?.code) ? error.code : null,
    });
  }
}
await client?.close().catch(() => {});
process.exit(0);
