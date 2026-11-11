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

// A dial-only TypeScript peer for the cross-language tests, driven by JSON lines.
//
//     AGENTSPACES_TS=<agentspaces-typescript>/build/src node peer.mjs SEED GROUP KEYSTORE
//
// SEED is tcp://host:port or tls://host:port; GROUP is aspace://<group-id> (joined by id over
// tcp, the founding fetched and verified) or a founding text. It uses the TypeScript client's
// public API only (its built index and node entry points). Once joined it prints {"ready": true,
// "peer": ..., "lang": "typescript"}, then reads one command per line on standard input and
// answers each with one line (see ../README.md): write, count, watch, race, quit. Watch events
// are printed as {"event": KIND, ...} lines whenever they fold. Every wait is bounded.

import { createInterface } from "node:readline";

const LANG = "typescript";
const SPACE = "tasks";
/** The settle window of a take (SPEC §7.4), as the client's `Space.take` claims with. */
const SETTLE_MILLIS = 600;
const root = process.env.AGENTSPACES_TS;
if (!root) {
  console.log(JSON.stringify({ error: "AGENTSPACES_TS names no built client" }));
  process.exit(1);
}
const { Peer, Space, Template, groupIdFromFounding } = await import(`${root}/index.js`);
// The node entry point registers the tcp and tls dialers; import it before any Peer exists.
const { loadOrCreateIdentity } = await import(`${root}/node/index.js`);

function say(message) {
  process.stdout.write(JSON.stringify(message) + "\n");
}

const sleep = (millis) => new Promise((resolve) => setTimeout(resolve, millis));

async function join(seed, group, keystore) {
  const identity = loadOrCreateIdentity(keystore);
  const [scheme, address] = seed.split("://");
  const at = address.lastIndexOf(":");
  const host = address.slice(0, at);
  const port = Number(address.slice(at + 1));
  let peer;
  if (group.startsWith("aspace://")) {
    if (scheme !== "tcp") {
      throw new Error("this client joins by id over tcp only");
    }
    peer = new Peer(identity, "");
    await peer.joinByGroupId(host, port, group.slice("aspace://".length), 15_000);
  } else {
    peer = new Peer(identity, groupIdFromFounding(group));
    await peer.connect(host, port, scheme);
  }
  const deadline = Date.now() + 15_000;
  while (!peer.seedPeer) {
    if (Date.now() > deadline) {
      throw new Error("the seed never answered this peer");
    }
    await sleep(50);
  }
  return peer;
}

/**
 * Takes tasks until `idle` takes in a row find none (or a minute passes); each one taken is
 * answered with a result entry, then completed.
 *
 * The client's take ends the settle window after its claim at the first fold of any entry, not
 * when the window has passed, so in a busy race it can answer before a competing claim arrives.
 * SPEC §7.4 has a taker wait the window out: the driver does, after the take answers, and keeps
 * the take only while this peer's claim still wins; a take given up that way is answered under
 * `lost` (another member holds that task), never completed.
 */
async function race(peer, space, command) {
  const tasks = new Template(command.schema);
  const holder = peer.identity.agent(LANG);
  const took = [];
  const lost = [];
  let idle = 0;
  const deadline = Date.now() + 60_000;
  while (idle < (command.idle ?? 3) && Date.now() < deadline) {
    const taken = await space.take(tasks, "1m", "1s");
    if (taken === null) {
      idle += 1;
      continue;
    }
    idle = 0;
    const value = taken.value ?? {};
    await sleep(SETTLE_MILLIS);
    peer.pullSpace(SPACE);
    await sleep(300);
    const winner = peer.claims.get(taken.entryId)?.["claim"];
    if (!winner || winner["holder"] !== holder) {
      lost.push({ id: taken.entryId, task: value.task });
      continue;
    }
    peer.writeEntry(SPACE, command.result, { task: value.task, taskId: taken.entryId, by: LANG }, LANG);
    taken.complete();
    took.push({ id: taken.entryId, task: value.task });
  }
  return { took, lost };
}

const [seed, group, keystore] = process.argv.slice(2);
let peer;
try {
  peer = await join(seed, group, keystore);
} catch (error) {
  say({ error: `join: ${error}` });
  process.exit(1);
}
const space = new Space(peer, SPACE, null, LANG);
peer.pullSpace(SPACE);
say({ ready: true, peer: peer.identity.peerId, lang: LANG });

const watches = [];
const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of lines) {
  if (!line.trim()) {
    continue;
  }
  const command = JSON.parse(line);
  const op = command.op;
  try {
    if (op === "write") {
      const id = peer.writeEntry(SPACE, command.schema, command.entry, LANG);
      say({ op, id });
    } else if (op === "count") {
      peer.pullSpace(SPACE);
      await sleep(300);
      const found = space.entries(new Template(command.schema), 1000);
      say({ op, n: found.length, entries: found.map((e) => ({ id: e.entryId, entry: e.value })) });
    } else if (op === "watch") {
      const schema = command.schema;
      watches.push(space.watch(new Template(schema), (event) => {
        say({ event: event.kind, schema, id: event.entry.entryId, entry: event.entry.value, watcher: LANG });
      }));
      say({ op, ok: true });
    } else if (op === "race") {
      const { took, lost } = await race(peer, space, command);
      say({ op, took, lost });
    } else if (op === "quit") {
      break;
    } else {
      say({ op, error: "unknown op" });
    }
  } catch (error) {
    say({ op, error: String(error) });
  }
}
for (const watch of watches) {
  watch.close();
}
peer.close();
say({ op: "quit", bye: true });
process.exit(0);
