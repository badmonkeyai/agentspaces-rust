# Clients around a Rust seed

Dial-only peers in Python, TypeScript, and Ruby, each written against its client's public API, for the cross-language test `crates/aspace/tests/clients_seed.rs`. The test starts `aspace seed`, joins these three and a Rust peer to it, and runs layer 3 among them: writes, a race of takes in which each task is completed exactly once, results read across languages, and watches that hear the other languages.

| Driver | Client | Runs as |
|---|---|---|
| `python/peer.py` | `agentspaces-python` | `AGENTSPACES_PYTHON=<checkout> python3 -I python/peer.py SEED GROUP KEYSTORE` |
| `typescript/peer.mjs` | `agentspaces-typescript` (its built output) | `AGENTSPACES_TS=<checkout>/build/src node typescript/peer.mjs SEED GROUP KEYSTORE` |
| `ruby/peer.rb` | `agentspaces-rb` | `ruby -I <checkout>/gems/agentspaces/lib ruby/peer.rb SEED GROUP KEYSTORE` |

`SEED` is `tcp://host:port` or `tls://host:port`. `GROUP` is `aspace://<group-id>`, joined by id (the founding fetched from the seed and verified, SPEC §5.1; the TypeScript client does this over `tcp` only), or a founding text. `KEYSTORE` is a directory for the peer's key pair.

## The protocol

Once joined, a driver prints `{"ready": true, "peer": "<PeerID>", "lang": "<language>"}` (or `{"error": "..."}` and exits 1). It then reads one JSON command per line on standard input and answers each with one line naming its `op`:

| Command | Answer |
|---|---|
| `{"op": "write", "schema": S, "entry": {...}}` | `{"op": "write", "id": "<entry id>"}` |
| `{"op": "count", "schema": S}` | `{"op": "count", "n": N, "entries": [{"id", "entry"}]}`: the live entries it holds, after a pull |
| `{"op": "watch", "schema": S}` | `{"op": "watch", "ok": true}`; from then on, `{"event": "WRITTEN" \| "TAKEN" \| "COMPLETED" \| ..., "schema", "id", "entry", "watcher"}` lines as entries fold |
| `{"op": "race", "schema": S, "result": R, "idle": 3}` | `{"op": "race", "took": [{"id", "task"}]}`: takes entries of `S` until `idle` takes in a row find none (a minute at most), answering each with an entry of `R` (`{"task", "taskId", "by"}`) and completing it. The TypeScript driver also answers `lost`: see below. |
| `{"op": "quit"}` | `{"op": "quit", "bye": true}`, and the driver exits 0 |

A command that fails is answered `{"op": ..., "error": "..."}`. Every wait in a driver is bounded.

The TypeScript client's take ends the settle window after its claim at the first fold of any entry, rather than when the window has passed (SPEC §7.4), so in a busy race it can answer a take that a competing claim, folding a moment later, wins. Without a guard, the race then completes that task twice. The TypeScript driver waits the window out after the client's take answers, and keeps the take only while its own claim still wins. A take it gives up that way is answered under `lost` and never completed. The test prints how many there were.

## Running the test

```sh
cargo test -p aspace --test clients_seed
```

It finds the clients in the checkouts beside this repository (`../agentspaces-python`, `../agentspaces-typescript`, `../agentspaces-rb`), or where `AGENTSPACES_PYTHON`, `AGENTSPACES_TS`, and `AGENTSPACES_RB` point. Python runs from `/tmp/aspace-venv4` or the checkout's `.venv` (`AGENTSPACES_PYTHON_BIN` names another), which must hold the client's one dependency, `cryptography`. Node 22 or later and Ruby 3.3 or later run the others. A client that cannot run makes the test pass with a note, unless `ASPACE_INTEROP_REQUIRED=1`.
