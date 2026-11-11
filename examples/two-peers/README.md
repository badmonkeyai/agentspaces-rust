# Two peers in bash

A fleet of your own from a shell, with nothing but the `aspace` binary: no JVM, no Node, no Python, no Ruby, no Rust code.

- **Peer 1** is `aspace seed --found demo`. It founds the group `demo` (a signed founding kept beside its keystore, so a restart keeps the group id), listens on `127.0.0.1:7700`, and prints the `aspace://` id to join by.
- **Peer 2**, with a keystore of its own, writes a note to the space `notes`, reads it back, and leaves.
- **A worker**, `aspace work -- ./handler.sh`, serves the action `shout`: it runs [`handler.sh`](handler.sh) once per task, with the task as JSON on standard input, and the script's JSON is the result. **A third peer** finds the action with `aspace cards` and calls it with `aspace call`.
- **A late visitor** joins long after peer 2 left and reads its note anyway: the seed holds what the group wrote. Its `aspace status` lists the members the seed knows.
- The worker and the seed stop (SIGTERM, as Ctrl-C does), each with exit 0.

Every peer is a separate process with its own Ed25519 identity, and every frame is signed. They run under the `dev-local` profile on loopback (plaintext `tcp`); on a network, the seed listens on `tls://` and the members dial `tls://`.

## Run it

```sh
cargo install --locked --path crates/aspace     # from the repository root, once
examples/two-peers/two-peers.sh
```

It works in a scratch directory with its own `HOME`, so no keystore or fleet file of yours is touched, and prints each command before it runs it, as you would type it there. `PORT=7711` picks another port (`PORT=0` lets the system choose), `ASPACE=/path/to/aspace` runs another binary, and `KEEP=1` keeps the scratch directory and its logs. It stops every process it started, also when a step fails or you press Ctrl-C.

[`verify.sh`](verify.sh) runs it and checks each step of the transcript, exiting non-zero on any mismatch; `cargo test -p aspace --test two_peers` runs that with the build's `aspace`, so it needs no Java or anything else.

## What it prints

A real run (`PORT=7741 ./two-peers.sh`; PeerIDs, ids, and times differ in every run):

```text
==> peer 1, the seed: it founds the group demo and listens on 127.0.0.1:7741
$ aspace --profile dev-local --keystore keys/seed seed --found demo --listen tcp://127.0.0.1:7741 >seed.json 2>seed.log &
{"event":"listening","peer":"z4kMUMVPw8bCfvrZC9Etkk9UKeULhKPWQS6rZ9FdzpSJF","group":"z4ZbWj6SUPkKZEYvYP1buLp7k8AnRZCNUohDwDjr6Uopb","join":"aspace://z4ZbWj6SUPkKZEYvYP1buLp7k8AnRZCNUohDwDjr6Uopb","listen":["tcp://127.0.0.1:7741"],"advertise":[],"membership":"OPEN"}
(the seed runs as pid 94186)

==> every other peer joins through it: the same group, a keystore of its own
$ export ASPACE_PROFILE=dev-local ASPACE_SEEDS=tcp://127.0.0.1:7741 ASPACE_JOIN=aspace://z4ZbWj6SUPkKZEYvYP1buLp7k8AnRZCNUohDwDjr6Uopb ASPACE_NO_DAEMON=1

==> peer 2 writes a note, reads it back, and leaves
$ aspace --keystore keys/peer2 write 'demo.Note#v1' --space notes --json '{"text":"hello from peer 2"}'
{"id":"94210e27-0efc-4423-b317-4423863b5151","schema":"demo.Note#v1","space":"notes"}
$ aspace --keystore keys/peer2 read 'demo.Note#v1' --space notes
{"id":"94210e27-0efc-4423-b317-4423863b5151","schema":"demo.Note#v1","space":"notes","entry":{"text":"hello from peer 2"},"tags":{},"issuer":"z8YhKdRSSJFW4ELrJnntWKyrgXrAt7pWY6kmqp8KsrVnE/rust","attestation":"PEER_ASSERTED","expiresAt":1794394088422}

==> a worker serves the action shout: aspace work runs ./handler.sh once per task
$ aspace --keystore keys/worker work --space desk --take 'demo.Shout#v1' --produces 'demo.Shouted#v1' --action shout -- ./handler.sh 2>worker.log &
working as zEaxu5armmPWYk3X7TXpbDUXLfVtVuEugiaXJCzsBrGtr/shout
(the worker runs as pid 94224)

==> a third peer finds the action and calls it
$ aspace --keystore keys/caller cards
shout  demo.Shout#v1 -> demo.Shouted#v1 in desk  (agent zEaxu5armmPWYk3X7TXpbDUXLfVtVuEugiaXJCzsBrGtr/shout)
    Runs handler.sh for each Shout (aspace work)
$ aspace --keystore keys/caller call shout --json '{"text":"hello, fleet"}' --timeout 30s
{"offering":"shout","input":"7b195369-b305-4e55-b8db-b0c876882eb6","inputSpace":"desk","id":"befb73c3-f14d-48ee-9088-624ebf2da5ea","schema":"demo.Shouted#v1","space":"desk","entry":{"text":"hello, fleet","shout":"HELLO, FLEET","by":"handler.sh"},"tags":{},"issuer":"zEaxu5armmPWYk3X7TXpbDUXLfVtVuEugiaXJCzsBrGtr/shout","attestation":"AGENT_ATTESTED","expiresAt":1794397090685}

==> a late visitor, joining long after peer 2 left, reads its note from the seed
$ aspace --keystore keys/late read 'demo.Note#v1' --space notes
{"id":"94210e27-0efc-4423-b317-4423863b5151","schema":"demo.Note#v1","space":"notes","entry":{"text":"hello from peer 2"},"tags":{},"issuer":"z8YhKdRSSJFW4ELrJnntWKyrgXrAt7pWY6kmqp8KsrVnE/rust","attestation":"PEER_ASSERTED","expiresAt":1794394088422}
$ aspace --keystore keys/late status
peer     z6LF62cXqbSifDusPo4UpEUk8h33rMAki9ek4251oZfoB
group    z4ZbWj6SUPkKZEYvYP1buLp7k8AnRZCNUohDwDjr6Uopb
link     tcp://127.0.0.1:7741
daemon   none
members  4 (1 reachable)
  z2C2BT2QYpMszcn82AATZ1XqMJsGAVPSrH2bjxQa7ADEJ
  z4kMUMVPw8bCfvrZC9Etkk9UKeULhKPWQS6rZ9FdzpSJF
  z8YhKdRSSJFW4ELrJnntWKyrgXrAt7pWY6kmqp8KsrVnE
  zEaxu5armmPWYk3X7TXpbDUXLfVtVuEugiaXJCzsBrGtr
cards    1
offers   1
  shout  demo.Shout#v1 -> demo.Shouted#v1 in desk  (agent zEaxu5armmPWYk3X7TXpbDUXLfVtVuEugiaXJCzsBrGtr/shout)
frames   malformed=0 ignored=0 stale=0 ahead=0 replayed=0 reconnects=0
mcp      no token or policy file named (ASPACE_MCP_TOKENS, ASPACE_MCP_POLICY)

==> stopping the worker and the seed (SIGTERM, as Ctrl-C)
the worker stopped with status 0
the seed stopped with status 0; what it said:
aspace: founded the group demo (open) in keys/seed/founding-demo.cbor
aspace: seed of group demo (z4ZbWj6SUPkKZEYvYP1buLp7k8AnRZCNUohDwDjr6Uopb) listening on tcp://127.0.0.1:7741; members join with --seeds tcp://127.0.0.1:7741 --join aspace://z4ZbWj6SUPkKZEYvYP1buLp7k8AnRZCNUohDwDjr6Uopb
aspace: admitted z8YhKdRSSJFW4ELrJnntWKyrgXrAt7pWY6kmqp8KsrVnE
aspace: admitted zEaxu5armmPWYk3X7TXpbDUXLfVtVuEugiaXJCzsBrGtr
aspace: admitted z2C2BT2QYpMszcn82AATZ1XqMJsGAVPSrH2bjxQa7ADEJ
aspace: admitted z6LF62cXqbSifDusPo4UpEUk8h33rMAki9ek4251oZfoB
aspace: stopping: no new links; the links send what they queued
aspace: stopped

two peers: done
```

- The seed's one JSON line on standard output names its PeerID, the group, the URI to join by, and where it listens. Everything else it says goes to standard error, one line per member it admits.
- The visitors (`write`, `read`, `cards`, `call`, `status`) each join, do one thing, and leave. `ASPACE_SEEDS` and `ASPACE_JOIN` give them the seed and the group; `--keystore` gives each its own identity.
- `call` writes the input where the `shout` agent takes its work and prints the result whose shared fields equal the input's. That is why `handler.sh` keeps `text` and adds `shout` and `by`.
- `status` lists four members: the seed, and the peers whose signed advertisements are still live (an advertisement lives ten minutes after its peer leaves).

## The commands

| Command | What it does |
|---|---|
| `aspace seed --found NAME` | Listen and serve the group `NAME`, founding it on the first run. `--listen` (repeatable), `--advertise`, `--membership open\|invite`, `--replicate SPACE`, `--require-attestation`; see `aspace seed --help` and [docs/seed.md](../../docs/seed.md). |
| `aspace write` / `read` | Write one entry; print the entries of a schema. |
| `aspace work -- PROGRAM` | Serve an action: run the program for each task taken. |
| `aspace cards` / `call` | List the fleet's actions; invoke one and print its result. |
| `aspace status` | The group, the link, the members, and the catalogue. |
