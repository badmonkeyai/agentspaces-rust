# Example 32: Rust members of the research fleet

This example puts Rust members on example 02's Java research fleet.

- **`rust-worker`** (`src/main.rs`): a Rust worker built on the `agentspaces` crate. It binds the agent `rust-worker` with one `take` action, `research`. The action takes `ResearchTask` entries and completes each with a `Finding`.
- **`research.sh`**: a shell script that `aspace work` runs once per task, as the agent `script-worker`. It declares the same `research` action, using plain `sh` and `sed`.
- **`aspace call`**: invokes `research` through the fleet catalogue, by the schema it consumes, and prints the `Finding` that answers it.

Example 02's coordinator publishes the tasks and tallies the findings. The coordinator is the Java `ResearchFleet`, run from the installed `example-02-research-fleet` 0.5.0 jar.

The two workers declare the same action, so the catalogue folds them into one offering with two replicas. A call reaches whichever worker takes the task.

## The fleet

Every member joins example 02's group (founding text `research-fleet-demo-v1`, space `tasks`):

| Process | What it is | Joins through |
|---|---|---|
| seed | `interop/java-seed`: a Java node that runs discovery, founding example 02's group | (it listens) |
| rust-worker | this example's binary | the seed |
| script-worker | `aspace work ... -- ./research.sh` | the seed |
| coordinator | example 02's `ResearchFleet coordinator` | the seed |
| `aspace cards`, `aspace call` | visitors: they join, do one thing, and leave | the seed |

The seed is there for two reasons:

- Example 02's coordinator runs no discovery, so it keeps no cards. It passes each card on, when the card is published, to the members linked at that moment. The Rust members link only to their seed. A caller that joins later would see their cards only at the next refresh, 5 minutes on.
- The coordinator leaves once it has tallied. A worker stopped after that has no seed to confirm its last results with.

A Spring Boot or Micronaut host makes the same kind of seed, since their starters run discovery. Here the workspace's interop seed plays that part.

## Prerequisites

- Rust 1.99 (the workspace's `rust-toolchain.toml`).
- A JDK 21 or later (`java`, or `JAVA_HOME`, or `JAVA=...`).
- Maven, and the AgentSpaces 0.5.0 artifacts in `~/.m2`, including `ai.badmonkey.agentspaces:example-02-research-fleet:0.5.0`. Everything resolves offline (`mvn -o`).
- `python3` is optional: `run.sh` uses it to find free ports.

## Run it

```sh
cd agentspaces-rust/examples/rust-fleet
./run.sh          # over tcp, about 10 s once built
./run.sh --tls    # over tls with attestation required, about 25 s
```

`run.sh` does these steps:

1. Builds `aspace` and `rust-worker`. Set `ASPACE_BIN` and `RUST_WORKER_BIN` to skip the build.
2. Resolves example 02's classpath (`java/pom.xml`) and compiles the seed when needed.
3. Starts the seed, the Rust worker, the script worker, and then the coordinator, each on its own keystore in a scratch directory.
4. Runs `aspace cards` and `aspace call` once the coordinator has tallied and left.
5. Stops the workers with SIGTERM and the seed with `quit`, and prints what each process said, line by line, prefixed with its name.

It exits 0 only when all of these hold:

- The coordinator recorded findings from `rust-worker` and from `script-worker`.
- The call printed a `Finding` for the topic `rust`.
- Both workers stopped cleanly.
- Over `tls`, every link the seed held was `tls` and attested, and the seed sent bare frames.

Nothing outlives the script: it removes its scratch directory and stops every process it started, also when it fails or is interrupted.

## Expected output

A real run over tcp (`./run.sh`). PeerIDs, ports, and entry ids differ in every run. Which worker takes which topic, and which worker answers the call, differ too; the split is usually three and three.

```text
==> building aspace and rust-worker
==> example 32 over tcp: example 02's group through a seed on 127.0.0.1:49273
==> the Rust worker: rust-worker
==> the script worker: aspace work --space tasks --take 'ai.badmonkey.agentspaces.examples.fleet.ResearchFleet$ResearchTask#v1' --produces 'ai.badmonkey.agentspaces.examples.fleet.ResearchFleet$Finding#v1' --action research --name script-worker -- ./research.sh
==> example 02's coordinator: ResearchFleet coordinator 49274 49273 6 1
==> the coordinator tallied its findings and left
==> aspace cards
==> aspace call 'ai.badmonkey.agentspaces.examples.fleet.ResearchFleet$ResearchTask#v1' --json '{"topic":"rust","priority":1}' --timeout 30s
==> stopping the workers (SIGTERM), then the seed
[seed] {"event":"listening","port":49273,"peer":"z2pMKBhAyG15j7H4F6NbfHBB6FkT64KmNLbmdcUdqtq91","group":"zBQJtZ4UK3uLsxZe6Tz9PEnCrbtp3mDH2jf4hHavarmom","space":"tasks","tls":false}
[seed] {"links":[{"peer":"z3XVvgQyRz5GjVDTNsZtXq2VS11E1n4N5jVSev18TJDK1","scheme":"tcp","mode":"signed"},{"peer":"zFFRQ8Ze9WZ4FddNKC3zsMg6tjfdNmCoG5fWiYDahkd1r","scheme":"tcp","mode":"signed"}]}
[seed] {"signed":135,"bare":0,"session":0}
[seed] {"bye":true}
[rust-worker] rust-worker: serving as zFFRQ8Ze9WZ4FddNKC3zsMg6tjfdNmCoG5fWiYDahkd1r/rust-worker in group zBQJtZ4UK3uLsxZe6Tz9PEnCrbtp3mDH2jf4hHavarmom
[rust-worker] rust-worker: researched 'topic-2' (attempt 1)
[rust-worker] rust-worker: researched 'topic-4' (attempt 1)
[rust-worker] rust-worker: researched 'topic-6' (attempt 1)
[rust-worker] rust-worker: researched 'rust' (attempt 1)
[rust-worker] rust-worker: stopped after 4 tasks (0 failed)
[script-worker] aspace: working as z3XVvgQyRz5GjVDTNsZtXq2VS11E1n4N5jVSev18TJDK1/script-worker (action research: ai.badmonkey.agentspaces.examples.fleet.ResearchFleet$ResearchTask#v1 -> ai.badmonkey.agentspaces.examples.fleet.ResearchFleet$Finding#v1 in tasks, on its card): running /path/to/agentspaces-rust/examples/rust-fleet/research.sh for each task, 1 at once
[script-worker] aspace: took d1462220-6884-4686-8a62-261b1e1d2fd8 (ai.badmonkey.agentspaces.examples.fleet.ResearchFleet$ResearchTask#v1, attempt 1)
[script-worker] [d1462220] researching topic-1
[script-worker] aspace: completed d1462220-6884-4686-8a62-261b1e1d2fd8
[script-worker] aspace: took 0e45e195-e540-4591-ae58-17b5480797d3 (ai.badmonkey.agentspaces.examples.fleet.ResearchFleet$ResearchTask#v1, attempt 1)
[script-worker] [0e45e195] researching topic-3
[script-worker] aspace: completed 0e45e195-e540-4591-ae58-17b5480797d3
[script-worker] aspace: took ba3ddabd-2dc8-48b0-a196-e5da0fe0f226 (ai.badmonkey.agentspaces.examples.fleet.ResearchFleet$ResearchTask#v1, attempt 1)
[script-worker] [ba3ddabd] researching topic-5
[script-worker] aspace: completed ba3ddabd-2dc8-48b0-a196-e5da0fe0f226
[script-worker] aspace: stopping: no new tasks; running programs have 30s to finish (a second signal kills them)
[script-worker] aspace: stopped: 3 tasks completed, 0 failed
[coordinator] view: 0 other peers
[coordinator] members: 3 other peers in view (expected 1)
[coordinator] coordinator: 6 tasks published; waiting for findings…
[coordinator] finding: topic-3 by script-worker
[coordinator] finding: topic-2 by rust-worker
[coordinator] finding: topic-4 by rust-worker
[coordinator] finding: topic-5 by script-worker
[coordinator] finding: topic-1 by script-worker
[coordinator] finding: topic-6 by rust-worker
[coordinator] tally: {rust-worker=3, script-worker=3}
[cards] research  ai.badmonkey.agentspaces.examples.fleet.ResearchFleet$ResearchTask#v1 -> ai.badmonkey.agentspaces.examples.fleet.ResearchFleet$Finding#v1 in tasks  (agent z3XVvgQyRz5GjVDTNsZtXq2VS11E1n4N5jVSev18TJDK1/script-worker, 2 replicas)
[cards]     Researches a topic with a shell script (example 32)
[call] {"offering":"research","input":"be06c296-141a-47fa-9347-d98b9a04aea9","id":"f3cad215-3435-4138-9fc2-88254609305e","schema":"ai.badmonkey.agentspaces.examples.fleet.ResearchFleet$Finding#v1","space":"tasks","entry":{"topic":"rust","summary":"researched in rust: rust","worker":"rust-worker"},"tags":{},"issuer":"zFFRQ8Ze9WZ4FddNKC3zsMg6tjfdNmCoG5fWiYDahkd1r/rust-worker","attestation":"AGENT_ATTESTED","expiresAt":1794169942373}
==> the coordinator recorded 3 findings by rust-worker and 3 by script-worker
==> aspace cards listed research with 2 replica(s)
==> the call printed a Finding for topic rust by rust-worker
==> the workers stopped with exit status 0 (rust-worker) and 0 (script-worker)
example 32: ok (tcp)
```

How to read it:

- The coordinator's six findings come from both workers (`tally: {rust-worker=3, script-worker=3}`).
- `aspace cards` shows one offering, `research`, with two replicas: the Rust worker and the script.
- The call's `Finding` is signed by the agent that wrote it (`issuer` ends in `/rust-worker`) and reads as `AGENT_ATTESTED`.

A real run over tls (`./run.sh --tls`) differs in these lines:

```text
[seed] {"event":"listening","port":49312,"peer":"zEot9hGYq1o9jdJxjqHTFaJPjB3iASQAfdHCU2MkUCe86","group":"zBQJtZ4UK3uLsxZe6Tz9PEnCrbtp3mDH2jf4hHavarmom","space":"tasks","tls":true}
[seed] {"links":[{"peer":"z6xPD8WRGp8N1MK6f2xuXxS9MQJQjupHqq1ZF7zuTtvak","scheme":"tls","mode":"attested"},{"peer":"z9x83EiX1vMjHPA8rKGgEqkmBu9h31aT3U3Zi3vnqqVR4","scheme":"tls","mode":"attested"}]}
[seed] {"signed":13,"bare":217,"session":0}
[coordinator] transport: tls on 49313, attestation required, channel mode ATTESTED
[coordinator] view: 0 other peers
[coordinator] members: 1 other peers in view (expected 1)
[coordinator] link: zEot9hGYq1o9jdJxjqHTFaJPjB3iASQAfdHCU2MkUCe86 ? attested
[coordinator] links: 0 tls attested of 1
[coordinator] coordinator: 6 tasks published; waiting for findings…
[coordinator] tally: {rust-worker=3, script-worker=3}
[coordinator] frames: signed=2 bare=87 session=0
==> the seed held 2 links, 2 of them tls attested, and sent 217 bare frames
example 32: ok (tls)
```

Over tls, a few lines look odd but are expected:

- **Both workers' links are attested.** Their links to the seed are `tls` and `attested`, so the seed sends them bare frames.
- **The coordinator sees one member.** A Java node that requires attestation drops frames that reach it through a relay. So the coordinator does not count members that link only to the seed. It still gets their findings, because the seed forwards them as gossip on its own attested link. This is why the coordinator waits for one member, the seed.
- **The coordinator shows `? attested`.** Java's `PeerNode` records a link's scheme when it accepts a link or dials a known member, but not for the link it opens to its seed at bootstrap. So example 02's `printLinks` shows no scheme for the coordinator's one link. The coordinator waits 15 s for a link it can show as `tls attested`, and then publishes. That wait is most of the 25 s.

## Run it by hand

The same fleet, one process per terminal, from `agentspaces-rust/`:

```sh
cargo build -p aspace -p rust-fleet
(cd interop/java-seed && mvn -q -o compile && mvn -q -o dependency:build-classpath -Dmdep.outputFile=target/classpath.txt)
(cd examples/rust-fleet/java && mvn -q -o dependency:build-classpath -Dmdep.outputFile=target/classpath.txt)

# 1. The seed. It reads commands on standard input: try links, frames, cards, and quit.
java -cp "interop/java-seed/target/classes:$(cat interop/java-seed/target/classpath.txt)" \
    ai.badmonkey.agentspaces.interop.Seed 7451 --founding research-fleet-demo-v1 --space tasks

# 2 and 3. The workers. Give each its own keystore: one keystore is one PeerID, and a seed
# treats every link of one PeerID as one member.
export ASPACE_SEEDS=tcp://127.0.0.1:7451 ASPACE_GROUP=research-fleet-demo-v1 ASPACE_SPACES=tasks
ASPACE_KEYSTORE=/tmp/fleet-keys/rust target/debug/rust-worker
ASPACE_KEYSTORE=/tmp/fleet-keys/script target/debug/aspace work --space tasks \
    --take 'ai.badmonkey.agentspaces.examples.fleet.ResearchFleet$ResearchTask#v1' \
    --produces 'ai.badmonkey.agentspaces.examples.fleet.ResearchFleet$Finding#v1' \
    --action research --name script-worker -- examples/rust-fleet/research.sh

# 4. Example 02's coordinator: listen on 7452, join through 7451, publish 6 tasks once 1 other
#    member is in view.
java -cp "$(cat examples/rust-fleet/java/target/classpath.txt)" \
    ai.badmonkey.agentspaces.examples.fleet.ResearchFleet coordinator 7452 7451 6 1

# 5. A visitor (with the variables of step 2).
ASPACE_KEYSTORE=/tmp/fleet-keys/caller target/debug/aspace cards
ASPACE_KEYSTORE=/tmp/fleet-keys/caller target/debug/aspace call \
    'ai.badmonkey.agentspaces.examples.fleet.ResearchFleet$ResearchTask#v1' \
    --json '{"topic":"rust","priority":1}' --timeout 30s
```

Notes:

- **Stopping.** Stop the workers with Ctrl-C and the seed with `quit`.
- **tls.** Add `--tls --require-attestation --channel-auth ATTESTED` to the seed and `--tls` to the coordinator, and set `ASPACE_SEEDS=tls://127.0.0.1:7451`.
- **Your own fleet file.** The `ASPACE_*` variables override `~/.config/agentspaces/fleet.yaml`, but other keys there still apply. `run.sh` gives every member a scratch `HOME`, so no fleet file applies.

## The fleet test

`tests/fleet.rs` runs `run.sh` over tcp and over tls, at the same time. It checks the output line by line:

- **Coordinator:** findings from both workers covering all six topics.
- **`aspace cards`:** one `research` offering with two replicas.
- **The call:** a `Finding` for `rust`, signed by the agent named in it, `AGENT_ATTESTED`.
- **Stopping:** both workers stopped cleanly.
- **The seed's links:** every link uses the run's scheme. Over tls, every link is also attested, and the seed sent bare frames.

```sh
ASPACE_INTEROP_REQUIRED=1 CARGO_BUILD_JOBS=4 cargo test -p rust-fleet
```

The test passes the built binaries to `run.sh`. It resolves the Java classpaths and compiles the seed first, once per run, so the two runs never call Maven at the same time.

The test needs `java`, Maven's offline resolution, and the built `aspace` (`cargo test --workspace` builds it). When one is missing, the test says why and passes. Under `ASPACE_INTEROP_REQUIRED=1` it fails instead.

`run.sh` leads a process group of its own. When the test ends, also on failure, the whole group is killed.

## Files

| File | What it is |
|---|---|
| `src/main.rs` | The Rust worker: `#[derive(Entry)]` types for example 02's `ResearchTask` and `Finding` records, and `fleet.agent("rust-worker").take(...)`. |
| `research.sh` | The script worker `aspace work` runs once per task. |
| `run.sh` | The whole example: starts, checks, and stops the fleet. |
| `java/pom.xml` | Resolves example 02's classpath from `~/.m2`. Nothing is compiled there. |
| `tests/fleet.rs` | The fleet test. |
