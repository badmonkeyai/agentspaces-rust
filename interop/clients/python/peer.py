# Copyright 2026 Bad Monkey, Inc.
# Author: Al Baker
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""A dial-only Python peer for the cross-language tests, driven by JSON lines.

    AGENTSPACES_PYTHON=<agentspaces-python> python3 -I peer.py SEED GROUP KEYSTORE

SEED is tcp://host:port or tls://host:port; GROUP is aspace://<group-id> (joined by id, the
founding fetched and verified) or a founding text. It uses the Python client's public API only
(agentspaces.peer, agentspaces.space, agentspaces.identity), from the checkout
AGENTSPACES_PYTHON names (or the import path, when it is unset). Once joined it prints {"ready": true, "peer": ..., "lang": "python"}, then reads
one command per line on standard input and answers each with one line (see ../README.md):
write, count, watch, race, quit. Watch events are printed as {"event": KIND, ...} lines
whenever they fold. Every wait is bounded."""

import json
import os
import sys
import threading
import time

if os.environ.get("AGENTSPACES_PYTHON"):
    sys.path.insert(0, os.environ["AGENTSPACES_PYTHON"])

from agentspaces.identity import Identity, group_id_from_founding
from agentspaces.peer import Peer
from agentspaces.space import Space, Template

LANG = "python"
SPACE = "tasks"
OUT = threading.Lock()


def say(message: dict) -> None:
    with OUT:
        sys.stdout.write(json.dumps(message, separators=(",", ":")) + "\n")
        sys.stdout.flush()


def join(seed: str, group: str, keystore: str) -> Peer:
    identity = Identity.load_or_create(keystore)
    scheme, _, address = seed.partition("://")
    host, _, port = address.rpartition(":")
    if group.startswith("aspace://"):
        peer = Peer(identity, None)
        peer.join_by_group_id(host, int(port), group[len("aspace://"):], 15.0, scheme=scheme)
    else:
        peer = Peer(identity, group_id_from_founding(group.encode("utf-8")))
        peer.connect(seed)
    # Linked once the seed addresses this peer (its answer to the revocation pull).
    deadline = time.monotonic() + 15
    while peer.seed_peer is None:
        if time.monotonic() > deadline:
            raise TimeoutError("the seed never answered this peer")
        time.sleep(0.05)
    peer.pull_space(SPACE)
    return peer


def main() -> int:
    seed, group, keystore = sys.argv[1:4]
    try:
        peer = join(seed, group, keystore)
    except Exception as error:  # noqa: BLE001 - reported to the test, which fails on it
        say({"error": f"join: {error!r}"})
        return 1
    space = Space(peer, SPACE, agent_name=LANG)
    say({"ready": True, "peer": peer.identity.peer_id, "lang": LANG})
    watches = []
    for line in sys.stdin:
        if not line.strip():
            continue
        command = json.loads(line)
        op = command.get("op")
        try:
            if op == "write":
                entry_id = peer.write_entry(SPACE, command["schema"], command["entry"], agent_name=LANG)
                say({"op": op, "id": entry_id})
            elif op == "count":
                peer.pull_space(SPACE)
                peer.await_fold(0.3)
                found = space.entries(Template(command["schema"]), limit=1000)
                say({"op": op, "n": len(found),
                     "entries": [{"id": e.entry_id, "entry": e.value} for e in found]})
            elif op == "watch":
                schema = command["schema"]

                def deliver(event, schema=schema):
                    say({"event": event.kind, "schema": schema, "id": event.entry.entry_id,
                         "entry": event.entry.value, "watcher": LANG})

                watches.append(space.watch(Template(schema), deliver))
                say({"op": op, "ok": True})
            elif op == "race":
                say({"op": op, "took": race(peer, space, command)})
            elif op == "quit":
                break
            else:
                say({"op": op, "error": "unknown op"})
        except Exception as error:  # noqa: BLE001 - reported to the test, which fails on it
            say({"op": op, "error": repr(error)})
    for watch in watches:
        watch.close()
    peer.close()
    say({"op": "quit", "bye": True})
    return 0


def race(peer: Peer, space: Space, command: dict) -> list:
    """Takes tasks until `idle` takes in a row find none (or a minute passes); each one taken is
    answered with a result entry, then completed."""
    tasks = Template(command["schema"])
    took = []
    idle = 0
    deadline = time.monotonic() + 60
    while idle < int(command.get("idle", 3)) and time.monotonic() < deadline:
        taken = space.take(tasks, lease="1m", timeout="1s")
        if taken is None:
            idle += 1
            continue
        idle = 0
        value = taken.value or {}
        peer.write_entry(SPACE, command["result"],
                         {"task": value.get("task"), "taskId": taken.entry_id, "by": LANG},
                         agent_name=LANG)
        taken.complete()
        took.append({"id": taken.entry_id, "task": value.get("task")})
    return took


if __name__ == "__main__":
    sys.exit(main())
