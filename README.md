# agentspaces-rust (Rust)

## Introducing AgentSpaces by Bad Monkey AI

**A peer-to-peer coordination fabric for agents, services, and the people who work with them.**

AgentSpaces is a P2P framework to quickly discover and join P2P networks, where agents, software services, and people share assets, queries, results, and coordinate. The framework helps you build fleets of agents, tie in other software, and coordinate across them with a replicated tuple space, quorum building, and more. Agents post work, claim tasks, publish results, vote on decisions, and recover from each other's failures. There is no broker, no registry, no scheduler, and no server to keep alive. Coordination is peer-to-peer, secured end to end, and replicated across the fleet.

AgentSpaces is the spiritual successor to Linda, Jini, and JXTA.

## Quick start: build your first agent in Rust

A Rust program joins a fleet as a full member. It holds its own Ed25519 identity, signs what it writes, and takes work under the same rules as a Java member. The key terms used in AgentSpaces:

- **Fleet**: the groups, peers, and agents that work together through AgentSpaces.
- **Peer**: one running AgentSpaces process. Its PeerID is the hash of its public key.
- **Group**: the peers that share spaces. A group is founded once, here from the text `shop-v1`.
- **Seed**: a peer that listens, so others can dial it to join a group. The quick start starts one first, with `aspace seed`.
- **Space**: a shared, replicated collection of entries, such as `orders`. Each member that uses it holds a copy.
- **Entry**: one typed record in a space, such as an `Order`. In Rust, a plain struct with `#[derive(Entry)]`.
- **Lease**: how long an entry, a take, or a card lasts before it lapses.
- **Take**: an exclusive hold on one entry for the length of its lease. The taker completes it with a result. If the taker dies, the lease lapses and the entry comes back for another worker.
- **Agent**: a named worker inside a peer, `<PeerID>/<name>`. In Rust, an async function that takes an entry and returns the next one.
- **Card** (AgentCard): what an agent publishes about itself, so others can find it.
- **Action**: one thing a card offers, such as `ship`. `aspace call` and MCP hosts invoke actions by name.

You need:

- Linux or macOS, and Rust through [rustup](https://rustup.rs). The repository pins its toolchain (Rust 1.99) in `rust-toolchain.toml`; rustup installs it on first use. No JDK: the seed is the `aspace` command too.
- A clone of this repository:

```sh
git clone https://github.com/badmonkeyai/agentspaces-rust
cd agentspaces-rust/quickstart
```

Every file below is in [`quickstart/`](quickstart), and every command runs there. [`quickstart/verify.sh`](quickstart/verify.sh) runs the whole quick start and checks each step.

**1. Start a seed.** In a terminal of its own:

```sh
./seed.sh
```

The seed is `aspace seed`, a listening member. It reads `fleet.yaml` (below), listens on `127.0.0.1:7700`, serves the group `shop-v1`, and keeps the space `orders`, so a worker or a desk can leave and the orders stay. It runs the `aspace` on your PATH, or builds this repository's on the first run. It prints one JSON line when it listens, then one line per member it admits. Leave it running. Press Ctrl-C to stop it.

A Java node can be the seed instead: `SEED=java ./seed.sh` runs the scripted Java seed in `interop/java-seed`, with a JDK 21 or newer and Maven.

**2. Describe the fleet.** The program reads `fleet.yaml`, the fleet file. The Spring and Micronaut starters, the Node host, and the Ruby client read files of the same shape.

<!-- quickstart/fleet.yaml -->
```yaml
agentspaces:
  groups:
    - name: shop
      founding: shop-v1                 # the group the seed founds
      seeds: [ "tcp://127.0.0.1:7700" ] # plain tcp on loopback only; use tls:// on a network
      spaces: [ orders ]
```

**3. Write the agent.** The crate is not on crates.io yet, so `Cargo.toml` points at this repository:

<!-- quickstart/Cargo.toml -->
```toml
[package]
name = "fulfiller"
version = "0.5.0"
edition = "2024"
license = "Apache-2.0"
publish = false

# A package of its own, outside the repository's workspace.
[workspace]

[dependencies]
# Until agentspaces is on crates.io, build against this repository's crate.
# Once it is published, write this line instead:  agentspaces = "0.5.0"
agentspaces = { path = "../crates/agentspaces" }
serde = { version = "1", features = ["derive"] }
tokio = { version = "1", features = ["rt-multi-thread", "macros", "time"] }
```

The program is a worker when it runs with no argument, and a desk that places one order when it runs with one:

- `#[derive(Entry)]` names each entry's wire schema. `rename_all = "camelCase"` gives the fields their wire names: `order_id` travels as `orderId`.
- `fleet.agent("fulfiller")` binds `ship` as a worker. It takes `Order` entries from `orders`, holding each for 30 seconds, and whatever `ship` returns completes the take.
- The desk writes an `Order`, then reads the `Shipment` whose `orderId` matches.

`src/main.rs`:

<!-- quickstart/src/main.rs -->
```rust
//! The Fulfiller: one agent that ships orders, and a desk that places one.
//!
//!   cargo run              a worker: ships every order until Ctrl-C
//!   cargo run -- kite      a desk: orders a kite, prints its shipment, and exits

use std::time::Duration;

use agentspaces::agent::{HandlerError, Reply, TakeContext};
use agentspaces::space::{Fleet, Lease, Template};
use agentspaces::wire::cbor::Map;
use agentspaces::{Config, Entry};
use serde::{Deserialize, Serialize};

/// How long the desk waits for its shipment.
const WAIT: Duration = Duration::from_secs(90);

/// An order. It travels as `shop.Order#v1` with the fields `orderId` and `item`.
#[derive(Debug, Serialize, Deserialize, Entry)]
#[entry(schema = "shop.Order#v1")]
#[serde(rename_all = "camelCase")]
struct Order {
    order_id: String,
    item: String,
}

/// A shipment: what the agent makes of an order.
#[derive(Debug, Serialize, Deserialize, Entry)]
#[entry(schema = "shop.Shipment#v1")]
#[serde(rename_all = "camelCase")]
struct Shipment {
    order_id: String,
    item: String,
    by: String,
}

/// The agent's one action: an Order in, a Shipment out.
async fn ship(order: Order, ctx: TakeContext) -> Result<Reply, HandlerError> {
    println!("shipping {} (attempt {})", order.order_id, ctx.attempt());
    // keepalive renews the take while the work runs, however long it takes.
    ctx.keepalive(tokio::time::sleep(ship_time())).await;
    let shipment = Shipment {
        order_id: order.order_id,
        item: order.item,
        by: ctx.agent_id().to_owned(),
    };
    Ok(shipment.into())
}

/// How long shipping takes: no time at all, unless SHIP_SECONDS says otherwise (step 5).
fn ship_time() -> Duration {
    match std::env::var("SHIP_SECONDS") {
        Ok(seconds) => Duration::from_secs(seconds.parse().unwrap_or(0)),
        Err(_) => Duration::ZERO,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fleet = Fleet::join_config(&Config::load("fleet.yaml")?).await?;

    if let Some(item) = std::env::args().nth(1) {
        // The desk: write an order, then wait for the shipment that answers it.
        let orders = fleet.space("orders");
        let order = Order {
            order_id: format!("o-{}", std::process::id()),
            item,
        };
        orders
            .write(&order, Lease::parse("10m")?, Map::new())
            .await?;
        println!("ordered {}", order.order_id);
        let answer = format!("orderId={}", order.order_id);
        let shipped = Template::of::<Shipment>().where_clause(&answer)?;
        let shipment = orders.read_typed::<Shipment>(&shipped, WAIT).await?;
        println!("{:?}", shipment.ok_or("no shipment within 90 s")?.value());
    } else {
        // The worker: take orders, holding each for 30 s at a time, until Ctrl-C.
        let worker = fleet
            .agent("fulfiller")
            .describe("Ships orders")
            .take("orders", Lease::parse("30s")?, ship)
            .action("ship")
            .produces::<Shipment>()
            .bind()
            .await?;
        let pid = std::process::id();
        println!("serving as {} (pid {pid})", worker.agent_id());
        worker.stop_on_signals().await?;
    }

    fleet.close().await?;
    Ok(())
}
```

**4. Run two workers and a desk.** Start each worker in a terminal of its own, then run the desk in a third:

```sh
cargo run -q            # worker 1
cargo run -q            # worker 2
cargo run -q -- kite    # the desk
```

Each worker prints the agent it serves as, `<PeerID>/fulfiller`, and its process id. The desk prints the order and its shipment:

```text
ordered o-79914
Shipment { order_id: "o-79914", item: "kite", by: "z7BcP43ftjA4eJo4ABn9F2YfyN6a6LS7cEk9Wfv2uj3L5/fulfiller" }
```

`by` names the worker that shipped it. Either worker can take the order, because both take `Order` entries from `orders`. PeerIDs and order numbers differ in every run.

**5. Kill one.** Stop both workers with Ctrl-C and start them again with slow shipping:

```sh
SHIP_SECONDS=10 cargo run -q
```

Run the desk again. One worker prints `shipping o-... (attempt 1)`. Kill that one with `kill -9 <pid>`, using the pid from its `serving as` line. Its take lapses within 30 seconds. Then the other worker prints `shipping o-... (attempt 2)`, and the desk prints the shipment with the survivor in `by`.

**6. The same with no Rust code.** `aspace` is a fleet member for scripts and shells, and the seed you started in step 1. Install it from this repository (it lands in `~/.cargo/bin`):

```sh
cargo install --locked --path ../crates/aspace
```

Stop the Rust workers. `aspace work` runs any program as a worker: it starts `fulfil.sh` once per order, with the order as JSON on standard input, and completes the order with the JSON the script prints.

<!-- quickstart/fulfil.sh -->
```sh
#!/bin/sh
# The Fulfiller with no Rust code: `aspace work` runs this once per order.
# The order arrives on standard input as one line of JSON: {"orderId":"o-2","item":"ball"}
# The first JSON object printed is the shipment. A non-zero exit hands the order back.
set -eu
order=$(cat)
echo "shipping $order" >&2
# The shipment is the order plus one field: drop the closing brace and add "by".
printf '%s,"by":"fulfil.sh"}\n' "${order%\}}"
```

```sh
aspace --config fleet.yaml --keystore keys/script work --space orders \
    --take 'shop.Order#v1' --produces 'shop.Shipment#v1' --name fulfiller --action ship -- ./fulfil.sh
```

The worker gets a keystore of its own, `keys/script`: the directory that holds a member's key pair (`peer.key`, `peer.pub`). One keystore is one identity, and two members running at once need two. The commands below use your default keystore, `~/.config/agentspaces/keys`, which `aspace` creates on first use. In another terminal:

```sh
aspace --config fleet.yaml cards
aspace --config fleet.yaml write 'shop.Order#v1' --space orders --json '{"orderId":"o-2","item":"ball"}'
aspace --config fleet.yaml read 'shop.Shipment#v1' --space orders --where 'orderId=o-2' --timeout 30s
aspace --config fleet.yaml call ship --json '{"orderId":"o-3","item":"yo-yo"}'
cargo run -q -- top
```

- `cards` lists what the fleet offers. The Rust workers and the script declare the same `ship` action, so `cards` shows one offering with a replica for each worker. A stopped worker stays listed until its card lapses, 15 minutes at most.
- `write` and `read` are space verbs. The shipment comes back with `"by":"fulfil.sh"`.
- `call` does both in one step: it writes the input where the `ship` agent takes its work, and prints the result that answers it.
- The Rust desk works unchanged: a Rust program and a shell script share one fleet.
- Each `aspace` command notes on standard error that no daemon answered, and joins the fleet on its own. [`aspace daemon`](#the-aspace-command) makes that faster.

`aspace read` prints one JSON line per entry:

```json
{"id":"4a5b17e0-ab25-4b84-a5d0-e485a223e2c2","schema":"shop.Shipment#v1","space":"orders","entry":{"orderId":"o-2","item":"ball","by":"fulfil.sh"},"tags":{},"issuer":"z5syUVc2Qi3bHmzjjAz2jvCZrAXNicYqWVdmRay8mH8Ma/fulfiller","attestation":"AGENT_ATTESTED","expiresAt":1794195285910}
```

## A fleet from the shell: the multiple-peer example

You can run a whole fleet from a shell with nothing but the `aspace` binary: no JVM, no Node, no Python, no Ruby, and no Rust code. [`examples/two-peers`](examples/two-peers) does it in about four seconds. Every peer below is a separate process with its own Ed25519 identity (its own `--keystore`), and every frame is signed:

- **Peer 1, the seed**, is `aspace seed --found demo`. It founds the group `demo`, keeps the signed founding beside its keystore so a restart keeps the group's id, listens on `127.0.0.1:7700`, and prints the `aspace://` id to join by.
- **Peer 2** writes a note to the space `notes`, reads it back, and leaves.
- **A worker**, `aspace work -- ./handler.sh`, serves the action `shout`. It runs the script once per task, with the task as JSON on standard input, and the script's JSON is the result.
- **A third peer** finds the action with `aspace cards` and calls it with `aspace call`.
- **A late visitor** joins after peer 2 left and still reads its note, because the seed keeps what the group wrote. Its `aspace status` lists the members the seed knows.

The commands, as you would type them (the example script runs exactly these in a scratch directory):

```sh
# Peer 1: found the group demo and listen. Its one line on standard output names the group to join.
aspace --profile dev-local --keystore keys/seed seed --found demo --listen tcp://127.0.0.1:7700 &

# Every other peer joins through the seed: the same group, a keystore of its own.
export ASPACE_PROFILE=dev-local ASPACE_SEEDS=tcp://127.0.0.1:7700 ASPACE_JOIN=aspace://<group-id from the seed>

aspace --keystore keys/peer2 write 'demo.Note#v1' --space notes --json '{"text":"hello from peer 2"}'
aspace --keystore keys/peer2 read 'demo.Note#v1' --space notes

aspace --keystore keys/worker work --space desk --take 'demo.Shout#v1' --produces 'demo.Shouted#v1' \
    --action shout -- ./handler.sh &
aspace --keystore keys/caller cards
aspace --keystore keys/caller call shout --json '{"text":"hello, fleet"}' --timeout 30s

aspace --keystore keys/late read 'demo.Note#v1' --space notes
aspace --keystore keys/late status
```

From a real run (ids and times differ in every run):

```text
{"event":"listening","peer":"z4kMUMVP…","group":"z4ZbWj6S…","join":"aspace://z4ZbWj6S…","listen":["tcp://127.0.0.1:7741"],"advertise":[],"membership":"OPEN"}
{"id":"94210e27-…","schema":"demo.Note#v1","space":"notes"}
shout  demo.Shout#v1 -> demo.Shouted#v1 in desk  (agent zEaxu5ar…/shout)
{"offering":"shout",…,"entry":{"text":"hello, fleet","shout":"HELLO, FLEET","by":"handler.sh"},…,"attestation":"AGENT_ATTESTED",…}
members  4 (1 reachable)
```

Run it, or check it:

```sh
cargo install --locked --path crates/aspace     # once, from the repository root
examples/two-peers/two-peers.sh                 # prints each command, then what it printed
cargo test -p aspace --test two_peers           # runs examples/two-peers/verify.sh; needs nothing else
```

What to know:

- **Add as many peers as you like.** Give each one its own keystore and the same `ASPACE_SEEDS` and `ASPACE_JOIN`. A second `aspace work` serving `shout` becomes a replica of the same offering, and a call reaches whichever worker takes it.
- **The seed is a full member.** It admits the others, forwards what they write, answers late joiners from what it holds, and relays between members that cannot reach each other.
- **`dev-local` is for a laptop.** It signs every frame over plain loopback `tcp` and encrypts nothing. On a network, the seed listens on `tls://` and the members dial `tls://`.
- **An invite group** admits only peers that hold its key: start the seed with `--membership invite`, print a key with `aspace invite --found demo`, and give it to joiners with `--invite`.
- [docs/seed.md](docs/seed.md) covers running a seed in full: founding, invite groups, `tls`, a second seed, and the bounds.

## About agentspaces-rust

AgentSpaces for Rust brings coding assistants, scripts, CI jobs, and Rust services into a fleet with one binary or one crate. Any of them can call what the fleet offers, and a script or a Rust program can work for it, with no JVM, Node, Python, or Ruby beside it.

| Crate | What it is |
|---|---|
| `agentspaces-wire` | The protocol core, with no I/O and no runtime: the CBOR codec that writes Java's bytes, identities and certificates, envelopes, records, the claim lattice, and the space fold. Proven byte for byte against the specification's golden vectors for every feature it has. |
| `agentspaces` | The peer, on Tokio. It dials a seed over `tcp`, or `tls` with channel certificates, then joins, verifies, and replicates; started with listeners, it is a seed other members dial. On top: `Fleet`, the space verbs, typed entries, workers with AgentCards, remote actions, the fleet catalogue, the fleet YAML, the keystore, and a blocking facade. |
| `agentspaces-derive` | `#[derive(Entry)]`, which binds a Rust type to its wire schema. |
| `aspace` | The command: every verb from a shell with JSON in and out, `aspace work` to run any program as a worker, `aspace seed` to serve a group of your own, `aspace daemon`, and `aspace mcp`. |
| `agentspaces-mcp` | `FleetMcpServer`: the fleet's catalogue as Model Context Protocol tools, over stdio and Streamable HTTP, with tokens or JWTs and scopes. |

The repository also holds:

- [`examples/two-peers`](examples/two-peers): a seed, a writer, a worker, a caller, and a late visitor from one shell script, with nothing but `aspace`.
- [`examples/rust-fleet`](examples/rust-fleet): a Rust worker and a shell-script worker serve the Java research fleet of example 02 in the [core repository](https://github.com/badmonkeyai/agentspaces), over `tcp` and over attested `tls`.
- [`interop/java-seed`](interop/java-seed): the scripted Java peer that the Java interop tests use as a seed (and the quick start, with `SEED=java`).
- [`interop/clients`](interop/clients): Python, TypeScript, and Ruby peers that the cross-language tests join to a Rust seed.
- [`docs/seed.md`](docs/seed.md): running a seed, founding a group, invite groups, `tls`, and the bounds and counters.
- [`docs/mcp.md`](docs/mcp.md) and [`docs/recipes/`](docs/recipes): the MCP gateway in full, and recipes for Codex, goose, Zed, Claude Code, GitHub Actions, and cron.

AgentSpaces has peers in other languages too: the [Java core](https://github.com/badmonkeyai/agentspaces), [Python](https://github.com/badmonkeyai/agentspaces-python), [TypeScript](https://github.com/badmonkeyai/agentspaces-typescript), and [Ruby](https://github.com/badmonkeyai/agentspaces-rb). The protocol and its golden vectors live in the [specification](https://github.com/badmonkeyai/agentspaces-spec).

### Status

Built and tested today:

- the protocol core, proven on the golden vectors of every feature it has;
- the peer over `tcp` and `tls`, with reconnects, revocations, relays, and bounds on everything a remote sends;
- the listening role: `aspace seed` founds or serves a group, admits members under its open or invite membership, and replicates what they write, so a fleet needs no other implementation;
- spaces: write, read, take, complete, watch, and notify, typed entries, and the blocking facade;
- workers and their AgentCards, remote actions, and the fleet catalogue;
- `aspace` with every command below, including `aspace daemon` and `aspace mcp`.

Next, roughly in this order:

- capabilities: votes, aggregates, semantic discovery, the connector clients, session attestation, and the `ws` transport;
- artifacts: the content swarm, with `aspace put` and `aspace get`;
- bindings: a C header, Swift and Kotlin packages, and a WASI component;
- framework adapters: rig tools and workers, an ACP supervisor, `aspace hook` for the hooks of coding assistants such as Codex and Claude Code, and MCP servers imported as fleet agents;
- release binaries and packages on crates.io.

### How it works

- **The core judges, the peer acts.** `agentspaces-wire` owns every byte rule and every judgment: a signature valid, a frame fresh, a claim winning, a card revoked. The peer owns sockets, tasks, timers, and the replicated state.
- **Joining.** The peer dials a seed, introduces its signed advertisement, answers membership probes, and folds what anti-entropy and gossip bring. A lost link is redialed, across all the seeds.
- **Taking.** A take is a race that a claim lattice decides, and every member computes the same winner. A worker that dies stops renewing its claim, the claim lapses, and the entry reappears for another worker.
- **Signing.** Everything a peer writes is signed, by the peer or by an agent's own key under a certificate the peer signs. Readers verify before they act.

## The aspace command

`aspace` is a fleet member for scripts, hooks, and shells. Most commands join, do one thing, and leave. `aspace work`, `aspace seed`, `aspace daemon`, and `aspace mcp` stay, and `aspace watch` streams until you stop it or it reaches `--count`.

| Command | What it does |
|---|---|
| `aspace id` | Create or show this machine's identity and print its PeerID. |
| `aspace status` | Join, report the group, members, links, catalogue, and counters, and leave. |
| `aspace write SCHEMA --json OBJECT` | Write one entry and print its id. |
| `aspace read SCHEMA` | Print the available entries of a schema. `--where` filters, `--timeout` waits for a first match. |
| `aspace take SCHEMA` | Take one entry exclusively and print it with its id. |
| `aspace complete ID` | Complete an entry taken earlier with the same keystore, with a result or without. |
| `aspace watch SCHEMA` | Stream the transitions of a schema's entries: written, taken, completed, expired, reappeared. |
| `aspace cards` | List the offerings of the fleet catalogue. |
| `aspace call TARGET --json OBJECT` | Invoke an offering, by name or by the schema it consumes, and print its result. |
| `aspace work --take SCHEMA --space SPACE -- PROGRAM` | Run a program for each task taken, as an agent with a card. |
| `aspace seed` | Listen and serve a group as its seed: one it founds (`--found NAME`), one founded from a text (`--group`), or another seed's (`--join`). See [docs/seed.md](docs/seed.md). |
| `aspace invite --found NAME` | Print an invite key of an invite group this keystore founded; joiners pass it with `--invite` or `ASPACE_INVITE`. |
| `aspace daemon` | Stay joined and serve the other commands over a local socket. |
| `aspace mcp` | Serve the fleet's offerings as MCP tools. |
| `aspace doctor` | Check the configuration, the keystore, the seeds, and the join. |
| `aspace completions SHELL`, `aspace man` | Print a shell completion script, or the manual page. |

Every command's `--help` ends with examples.

**JSON in and out.** Results are JSON on standard output: one object, or one object per line for streams. `status`, `cards`, and `doctor` print text for people unless you add `--json`. Diagnostics go to standard error. Where a command takes input, `--json` takes an object inline, `-` for standard input, or `@file` for a file.

**Exit codes.** Scripts can branch on them:

| Code | Meaning |
|---|---|
| 0 | Success. |
| 1 | An error: no seed accepted the connection, an I/O failure, the peer closed. |
| 2 | Refused or not found: a bad argument or configuration, nothing matched, an entry not held. |
| 3 | A timeout: the join, the dial, or a wait for an entry or a result. |
| 4 | Authentication or authorization: a revoked identity, a key file others can read, a seed that does not attest. |

**Configuration.** Flags come first, then the `ASPACE_*` variables, then the fleet file: `--config`, else `ASPACE_CONFIG`, else `~/.config/agentspaces/fleet.yaml`. The keystore defaults to `~/.config/agentspaces/keys`. When `XDG_CONFIG_HOME` is set, both defaults move under `$XDG_CONFIG_HOME/agentspaces`. `aspace seed` also reads its listeners from `--listen`, `ASPACE_LISTEN`, or the file's `bind`, and what they advertise from `--advertise`, `ASPACE_ADVERTISE`, or the file's `advertise`; no other command binds anything.

**`aspace work`.** For each task it runs the program with no shell, in a process group of its own:

- the entry arrives as JSON on standard input, with `ASPACE_ENTRY_ID`, `ASPACE_SCHEMA`, and `ASPACE_SPACE` set;
- the environment holds `PATH`, `HOME`, `LANG`, and each `--env NAME`, nothing else;
- the take is renewed at half its lease while the program runs;
- on exit 0, the first JSON object on standard output is the result;
- anything else (a non-zero exit, a signal, `--task-timeout`, output that is not an object) kills the group and lets the take lapse, so another worker gets the task.

`--parallel N` runs up to N programs at once. SIGINT or SIGTERM stops taking and gives running programs `--grace` to finish.

**The daemon.** Each command joins the fleet on its own, unless `aspace daemon` runs. While it runs, `status`, `write`, `read`, `take`, `complete`, `watch`, `cards`, and `call` go through it when they name the same group, keystore, and profile. They answer in milliseconds, with the same output and exit codes. Its socket is owner-only and serves only processes of the same user. Run it under systemd or launchd, or with `setsid`. `--no-daemon` makes a command join on its own.

**Several peers from a shell.** [A fleet from the shell](#a-fleet-from-the-shell-the-multiple-peer-example) runs a seed, a writer, a worker, a caller, and a late visitor with nothing but `aspace`.

## MCP: the fleet as tools

`aspace mcp` serves the fleet's catalogue to any MCP host: Codex CLI, Claude Code, goose, Zed, and others. Each offering becomes one tool. A tool call writes the input entry where the advertising agent takes its work, waits for the result, and returns it.

Over stdio, the host starts it. In Claude Code's `.mcp.json`:

```json
{"mcpServers": {"fleet": {"command": "aspace", "args": ["mcp"]}}}
```

In Codex CLI's `~/.codex/config.toml`:

```toml
[mcp_servers.fleet]
command = "aspace"
args = ["mcp"]
```

Over Streamable HTTP, for a team or for several sessions at once:

```sh
aspace mcp --http 127.0.0.1:8740 --tokens ~/.config/agentspaces/mcp-tokens.yaml --only 'shop.*'
```

- **Tokens.** `--http` binds loopback by default and refuses to start without a token verifier: `--tokens FILE` (owner-only, `chmod 600`), or `--jwt-issuer`, `--jwt-audience`, and `--jwks` for JWTs. `--allow-unauthenticated` serves every caller anonymously; use it only behind a proxy that authenticates every request.
- **Answers.** A request without a valid token gets 401. A call outside the token's scopes gets 403. A browser `Origin` that is not allowed gets 403.
- **Scopes.** `--policy FILE` maps each token scope to the offerings it may call.
- **Offering less.** `--only PATTERN` limits what a model sees: a glob over offering names and schemas, or `space:<glob>`.
- **Tools follow the fleet.** Clients get `notifications/tools/list_changed` when offerings come and go.
- **Card text is data.** The gateway strips control and invisible characters from what cards say, caps its length, and frames descriptions as fleet-provided data.
- **One gateway per keystore.** The gateway is a member with its keystore's identity. Give it a keystore no other running `aspace` member uses.

[`docs/mcp.md`](docs/mcp.md) covers every option, the token and policy files, and the exit codes. [`docs/recipes/`](docs/recipes) has a page each for Codex, goose, Zed, Claude Code, GitHub Actions, and cron. A Rust program with its own rmcp server can embed `FleetMcpServer` from the `agentspaces-mcp` crate.

## Using the crate

Until the crates are on crates.io, depend on this repository by path, as the quick start does, or by git:

```toml
[dependencies]
agentspaces = { git = "https://github.com/badmonkeyai/agentspaces-rust" }
serde = { version = "1", features = ["derive"] }
tokio = { version = "1", features = ["rt-multi-thread", "macros", "time"] }
```

**Join.** A `Fleet` is a running peer. Join with a fleet file you name, or with the `ASPACE_*` variables over `~/.config/agentspaces/fleet.yaml`:

```rust
use agentspaces::Config;
use agentspaces::space::Fleet;

let fleet = Fleet::join_config(&Config::load("fleet.yaml")?).await?; // or Fleet::join_from_env()
println!("{} joined {}", fleet.peer().peer_id(), fleet.peer().group_id());
// ... the space verbs and workers below ...
fleet.close().await?;
```

**Typed entries.** `#[derive(Entry)]` with serde binds a struct to its wire schema, `<Type>#v<version>`. A Java record reads the same bytes when its fields have the same wire names and types.

```rust
use agentspaces::Entry;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Entry)]
#[entry(schema = "shop.Order#v1")]
#[serde(rename_all = "camelCase")]
struct Order {
    order_id: String,
    sku: String,
    qty: i32,
}

#[derive(Debug, Serialize, Deserialize, Entry)]
#[entry(schema = "shop.Shipment#v1")]
#[serde(rename_all = "camelCase")]
struct Shipment {
    order_id: String,
    tracking: String,
}
```

**The space verbs.** `fleet.space(name)` is a cheap handle on one replicated space:

```rust
use std::time::Duration;
use agentspaces::space::{Lease, Template};
use agentspaces::wire::cbor::Map;

let orders = fleet.space("orders");
let order = Order { order_id: "o-1".into(), sku: "A-1".into(), qty: 12 };
let id = orders.write(&order, Lease::parse("10m")?, Map::new()).await?;

let big = Template::of::<Order>().where_clause("qty>=10")?;
let first = orders.read_typed::<Order>(&big, Duration::from_secs(5)).await?;
let all_now = orders.read_all_typed::<Order>(&big, 100).await?;

let wait = Duration::from_secs(5);
if let Some(taken) = orders.take_typed::<Order>(&big, Lease::parse("30s")?, wait).await? {
    let order_id = taken.value().order_id.clone();
    let shipment = Shipment { order_id, tracking: "Z9".into() };
    taken.complete_with(&shipment, Lease::parse("1h")?, Map::new()).await?;
}

let mut events = orders.watch_typed::<Order>(&Template::of::<Order>()).await?;
while let Some(event) = events.next().await {
    println!("{:?} {:?}", event.kind, event.entry.value());
}
```

- `write` answers the entry's id. The entry lives for its lease.
- `read_typed` waits up to its timeout for a match. `read_all_typed` answers what is there now.
- `take_typed` holds an entry exclusively for its lease. Complete it, or let the hold lapse and the entry reappears.
- `watch_typed` streams transitions: `Written`, `Taken`, `Completed`, `Expired`, and `Reappeared`.
- Templates take filter clauses (`qty>=10`, `region in eu, us`), the same grammar every AgentSpaces language reads.

**Workers.** `fleet.agent(name)` binds handlers as an agent with an identity of its own, and publishes its AgentCard so the fleet catalogue, `aspace call`, and MCP hosts find it:

```rust
use agentspaces::agent::{HandlerError, Reply, TakeContext};

async fn ship(order: Order, ctx: TakeContext) -> Result<Reply, HandlerError> {
    // book_courier is your own async work, a model or an API call. keepalive renews the take
    // while it runs.
    let tracking = ctx.keepalive(book_courier(&order)).await?;
    Ok(Shipment { order_id: order.order_id, tracking }.into())
}

let worker = fleet
    .agent("fulfiller")
    .describe("Ships orders")
    .take("orders", Lease::parse("30s")?, ship)
    .action("ship")
    .produces::<Shipment>()
    .parallel(4)
    .bind()
    .await?;
worker.stop_on_signals().await?; // runs until SIGINT or SIGTERM, then finishes within a grace
```

A handler returns an entry (completes the take with it), nothing, several entries, or an error (the take lapses and another worker gets the task). `ctx.keepalive(work)` renews the take while long work runs. `notify` binds a reaction to new entries instead of a take.

**Without async.** `agentspaces::blocking` mirrors the verbs over a runtime of its own, for scripts, tests, and code with no Tokio:

```rust
use std::time::Duration;
use agentspaces::blocking::Fleet;
use agentspaces::space::{Lease, Template};
use agentspaces::wire::cbor::Map;

let fleet = Fleet::join_from_env()?; // ASPACE_CONFIG=fleet.yaml, or the other ASPACE_* variables
let orders = fleet.space("orders");
let order = Order { order_id: "o-2".into(), sku: "B-7".into(), qty: 1 };
orders.write(&order, Lease::parse("10m")?, Map::new())?;
let shipped = Template::of::<Shipment>().where_clause("orderId=o-2")?;
let shipment = orders.read_typed::<Shipment>(&shipped, Duration::from_secs(30))?;
fleet.close()?;
```

**Configuration.** The fleet file is the `agentspaces:` subtree every AgentSpaces host reads. The peer ignores keys it does not use.

```yaml
agentspaces:
  keystore: ~/.config/agentspaces/keys    # peer.key and peer.pub, shared with Java, Python, Ruby
  security:
    profile: mtls                         # tls:// seeds must attest; dev-local allows plain tcp
  groups:
    - name: research-fleet
      join: aspace://zQm...               # or founding: <text>
      seeds: [ "tls://fleet.example.com:7500" ]
      spaces: [ tasks ]
```

| Variable | Meaning |
|---|---|
| `ASPACE_CONFIG` | The fleet file. |
| `ASPACE_SEEDS` | Seeds, comma-separated: `tls://host:port`, `tcp://host:port`, or `host:port` (tcp). |
| `ASPACE_GROUP` | A group of the fleet file by name, or else a founding text. |
| `ASPACE_JOIN` | A group by id: `aspace://<group-id>`. |
| `ASPACE_KEYSTORE` | The keystore directory. The crate runs with a fresh identity without one; `aspace` uses `~/.config/agentspaces/keys`. |
| `ASPACE_PROFILE` | `mtls` (the default) or `dev-local`. |
| `ASPACE_SPACES` | The spaces to pull after joining, comma-separated. |

A plain `tcp` seed is refused unless it is on loopback or the profile is `dev-local`, since `tcp` signs every frame but encrypts nothing.

## The cross-language guarantee

A Rust member is a member like any other, so the repository proves it against the reference in two ways.

**Golden vectors.** `crates/agentspaces-wire/tests/golden.json` is a copy of the vectors in the [AgentSpaces specification](https://github.com/badmonkeyai/agentspaces-spec), which the Java codec produced.

- The suite covers 174 of the 232 vectors. It reproduces their encodings and signatures byte for byte (Ed25519 signing is deterministic) and re-encodes each to its own bytes.
- It refuses all 39 hostile inputs, as Java does.
- The other 58 vectors belong to features this peer does not have, such as DTLS, WebRTC, and the content swarm.
- A coverage test fails when a vector is neither tested nor listed as skipped with its reason.

**Around a Rust seed.** `crates/aspace/tests/clients_seed.rs` starts `aspace seed` and joins the Python, TypeScript, and Ruby clients (each through its public API, the drivers in `interop/clients`) and a Rust peer to it, over `tcp` (the group joined by id) and over `tls` with required attestation:

- each writes tasks, and every peer reads all of them;
- all four race to take them, each task completed exactly once, and every result read by the peers of the other languages;
- a watch in each language hears the other languages' writes and completions.

**Against a live Java peer.** The interop tests start the scripted Java seed (`interop/java-seed`) on a free port and check what both sides see:

- membership, over `tcp` and over attested `tls` with unsigned frames on the attested channel;
- writes, takes, and completions crossing both ways, and races for one task among three Rust peers and Java, each task completed exactly once;
- a crashed Rust worker's task reappearing for a Java agent;
- Rust AgentCards admitted by Java's discovery, and Rust and Java agents calling each other's actions, with replicas collapsing across languages;
- `aspace cards`, `aspace call`, and `aspace work` against Java agents, and the `rust-fleet` example beside the Java research fleet.

## Security

AgentSpaces peers are self-certifying: a PeerID is the hash of the peer's Ed25519 key, and everything a peer or agent writes is signed. This repository adds these rules:

- **tls.** A `tls://` seed is dialed over TLS 1.3 with a channel certificate: a fresh P-256 key, endorsed by the peer's identity key. No certificate authority is involved. The peer refuses a seed whose certificate attests nobody, and resumes no sessions.
- **Verify, then act.** The peer verifies every frame, record, claim, card, and revocation before it acts on one, and bounds what a remote can make it hold.
- **`aspace work`** runs programs with no shell and a minimal environment. The entry is data on standard input, never part of a command line.
- **Owner-only files.** The keystore directory is 0700 and `peer.key` 0600. A key file its group or others can read is refused (exit 4) unless you pass `--allow-readable-key`. The daemon's socket is owner-only and serves only processes of the same user.
- **MCP.** An HTTP gateway won't start without a token verifier, unless you pass `--allow-unauthenticated`. Tokens are kept as SHA-256 digests and compared in constant time. A token file others can read, or a policy file others can write, is refused.

Report a vulnerability privately, as [SECURITY.md](SECURITY.md) describes: through [GitHub's private advisories](https://github.com/badmonkeyai/agentspaces-rust/security/advisories/new), never a public issue.

## Building and testing

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

- The suites run on loopback and in-process networks.
- The Java interop tests need a JDK 21 or newer and Maven. They build `interop/java-seed` with Maven offline, so build it once online first:

```sh
(cd interop/java-seed && mvn -q compile dependency:build-classpath -Dmdep.outputFile=target/classpath.txt)
```

- Example 32's test also needs example 02's jar, which is not on Maven Central: run `mvn install -DskipTests` once in a clone of the [core repository](https://github.com/badmonkeyai/agentspaces).
- Without Java or the jars, each interop test says why and passes. Set `ASPACE_INTEROP_REQUIRED=1` to make that a failure, as a release check should:

```sh
ASPACE_INTEROP_REQUIRED=1 cargo test --workspace
```

- With `ASPACE_INTEROP_REQUIRED=1`, the MCP client tests need Node and Ruby too, as [CONTRIBUTING.md](CONTRIBUTING.md) lists under "The cross-language suites", and the Rust-seed test needs the Python, TypeScript, and Ruby clients beside this repository ([interop/clients](interop/clients/README.md) says how it finds them).
- `cargo test -p aspace --test two_peers` runs the two-peer example with nothing but the build's `aspace`.
- Three more Java checks are opt-in: `cargo test --workspace -- --ignored java`.
- `quickstart/verify.sh` runs the quick start end to end in a scratch copy of the repository.
- On a machine with few cores, `CARGO_BUILD_JOBS=4` keeps a build from taking every one.

## Releasing

The crates share one version, `[workspace.package] version` in `Cargo.toml`, which follows the AgentSpaces core.

1. Set the version, and the `version` of each dependency between the crates, to match.
2. Move the `Unreleased` notes of `CHANGELOG.md` under the version.
3. Run the checks above with `ASPACE_INTEROP_REQUIRED=1`, and `quickstart/verify.sh`.
4. Tag the commit `v<version>` and push the tag.
5. Publish to crates.io in dependency order, each after the one before is live: `agentspaces-wire`, `agentspaces-derive`, `agentspaces`, `agentspaces-mcp`, then `aspace`.

Release binaries of `aspace` come later. Until then, `cargo install --locked --path crates/aspace` builds it.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) and the [code of conduct](CODE_OF_CONDUCT.md). Report a vulnerability privately, as [SECURITY.md](SECURITY.md) describes. Questions go to `oss [at] badmonkey.ai`.

## Licence

Apache License 2.0. Copyright 2026 Bad Monkey, Inc. Author: Al Baker. See `LICENSE` and `NOTICE`.
