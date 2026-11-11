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

//! The listening role with Rust peers alone: a Rust listening peer (the hub) and three Rust
//! dial-only peers run the whole layer 3 suite through it, once over the in-memory network and
//! once over `tcp`: writes read across peers, a take race in which every task completes exactly
//! once, a crashed take that reappears after its lease, completion with a result, renewal and
//! cancellation, watch events across peers, agent-attested writes, a bound worker with its card
//! and a remote call between two peers, a late joiner that catches up by anti-entropy, and a
//! large payload written by a peer that leaves at once and read by another.

mod support;

use std::sync::Arc;
use std::time::Duration;

use agentspaces::Entry;
use agentspaces::agent::{Reply, TakeContext};
use agentspaces::clock::{Clock, SharedClock, SystemClock};
use agentspaces::group::GroupSpec;
use agentspaces::peer::{ListenerSpec, Peer, PeerConfig, PeerEvent, default_dialers};
use agentspaces::remote::RemoteActions;
use agentspaces::space::{Attestation, EventKind, Fleet, Lease, Template};
use agentspaces::transport::memory::MemoryNetwork;
use agentspaces::wire::cbor::Map;
use agentspaces::wire::cbor_map;
use agentspaces::wire::identity::Identity;
use serde::{Deserialize, Serialize};
use support::{PATIENCE, eventually};

const FOUNDING: &str = "agentspaces-rust-listening";
const SPACE: &str = "tasks";
/// The settle window of the takes here.
const SETTLE: Duration = Duration::from_millis(300);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, agentspaces::Entry)]
#[entry(schema = "com.acme.Task#v1")]
struct Task {
    topic: String,
    priority: i32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, agentspaces::Entry)]
#[entry(schema = "com.acme.Report#v1")]
struct Report {
    topic: String,
    summary: String,
    worker: String,
}

fn system() -> SharedClock {
    Arc::new(SystemClock)
}

fn task(topic: &str) -> Task {
    Task {
        topic: topic.to_owned(),
        priority: 1,
    }
}

/// How the hub's members reach it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Wire {
    Memory,
    Tcp,
}

/// A listening hub and the way its members dial it.
struct Hub {
    wire: Wire,
    network: MemoryNetwork,
    hub: Peer,
    seed: String,
}

impl Hub {
    /// A hub founded from text, listening on `wire`.
    async fn start(wire: Wire, address: &str) -> Hub {
        let network = MemoryNetwork::new();
        let identity = Identity::generate().expect("identity");
        let mut config = PeerConfig::new(identity, GroupSpec::FoundingText(FOUNDING.to_owned()));
        config.clock = system();
        let listener = match wire {
            Wire::Memory => ListenerSpec::bound(Arc::new(network.listen(address))),
            Wire::Tcp => ListenerSpec::tcp("127.0.0.1:0"),
        };
        config = config.listen_on(listener);
        config.listen.anti_entropy_period = Some(Duration::from_millis(200));
        let hub = Peer::start(config).await.expect("the hub starts");
        let bound = hub.listen_addrs();
        assert_eq!(bound.len(), 1, "{bound:?}");
        let seed = match wire {
            Wire::Memory => address.to_owned(),
            Wire::Tcp => format!("tcp://{}", bound[0].address()),
        };
        Hub {
            wire,
            network,
            hub,
            seed,
        }
    }

    /// A dial-only member of the hub's group, dialing the hub.
    async fn member(&self) -> (Fleet, Identity) {
        let identity = Identity::generate().expect("identity");
        let mut config = PeerConfig::new(
            identity.clone(),
            GroupSpec::FoundingText(FOUNDING.to_owned()),
        );
        config.seeds = vec![self.seed.parse().expect("seed")];
        config.dialers = match self.wire {
            Wire::Memory => vec![Arc::new(self.network.dialer())],
            Wire::Tcp => default_dialers(),
        };
        config.clock = system();
        config.reconnect_interval = Duration::from_millis(50);
        config.dial_timeout = Duration::from_secs(2);
        let peer = Peer::start(config).await.expect("the member starts");
        let fleet = Fleet::from_peer(peer);
        let hub = self.hub.clone();
        let id = identity.peer_id().to_owned();
        eventually("the hub admits the member", || {
            let hub = hub.clone();
            let id = id.clone();
            async move { hub.linked_members().await.contains(&id) }
        })
        .await;
        (fleet, identity)
    }

    async fn close(&self) {
        let _ = self.hub.close().await;
    }
}

/// The next event of a watch (or a panic after [`PATIENCE`]).
async fn next_event(
    events: &mut agentspaces::space::SpaceEvents,
) -> agentspaces::space::SpaceEvent {
    tokio::time::timeout(PATIENCE, events.next())
        .await
        .expect("an event in time")
        .expect("the watch is open")
}

/// Waits until `space` reads a task on `topic` (or panics).
async fn wait_task(fleet: &Fleet, topic: &str) {
    let wanted = Template::of::<Task>()
        .where_clause(&format!("topic={topic}"))
        .expect("a clause");
    fleet
        .space(SPACE)
        .read_typed::<Task>(&wanted, PATIENCE)
        .await
        .expect("read")
        .unwrap_or_else(|| panic!("no task {topic} in time"));
}

/// Writes read across members, and the hub's own replica holds them.
async fn writes_cross(wire: Wire, address: &str) {
    let hub = Hub::start(wire, address).await;
    let (a, _) = hub.member().await;
    let (b, _) = hub.member().await;
    let (c, _) = hub.member().await;
    let tasks = a.space(SPACE);
    tasks
        .write(&task("one"), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    for fleet in [&b, &c] {
        wait_task(fleet, "one").await;
    }
    // The hub replicates the space it heard of.
    let hub_peer = hub.hub.clone();
    eventually("the hub's replica", || {
        let hub_peer = hub_peer.clone();
        async move { !hub_peer.space_states(SPACE).await.is_empty() }
    })
    .await;
    let counters = hub.hub.counters().await;
    assert_eq!(counters.listen.admitted, 3, "{counters:?}");
    assert!(counters.listen.rumors_forwarded >= 1, "{counters:?}");
    assert_eq!(counters.listen.spaces_replicated, 1, "{counters:?}");
    assert_eq!(counters.listen.refused.total(), 0, "{counters:?}");
    // Every member holds the others in its view, from the hub's forwarded introductions.
    let members = b.peer().members().await;
    assert!(
        members.contains(&hub.hub.peer_id().to_owned()),
        "{members:?}"
    );
    assert!(
        members.contains(&a.peer().peer_id().to_owned()),
        "{members:?}"
    );
    assert_eq!(
        b.peer().seed_peer().await.as_deref(),
        Some(hub.hub.peer_id())
    );
    for fleet in [&a, &b, &c] {
        fleet.close().await.expect("close");
    }
    hub.close().await;
}

/// Three members race to take twelve tasks through the hub: each completes exactly once.
async fn take_race(wire: Wire, address: &str) {
    let hub = Hub::start(wire, address).await;
    let (a, _) = hub.member().await;
    let (b, _) = hub.member().await;
    let (c, _) = hub.member().await;
    let topics: Vec<String> = (0..12).map(|n| format!("t{n}")).collect();
    for topic in &topics {
        a.space(SPACE)
            .write(&task(topic), Lease::DEFAULT_WRITE, Map::new())
            .await
            .expect("write");
    }
    for fleet in [&b, &c] {
        wait_task(fleet, "t11").await;
    }
    let mut racers = Vec::new();
    for (name, fleet) in [("a", a.clone()), ("b", b.clone()), ("c", c.clone())] {
        racers.push(tokio::spawn(async move {
            let space = fleet.space(SPACE).with_settle(SETTLE);
            let mut took = Vec::new();
            loop {
                let taken = space
                    .take_typed::<Task>(
                        &Template::of::<Task>(),
                        Lease::DEFAULT_TAKE,
                        Duration::from_millis(1500),
                    )
                    .await
                    .expect("take");
                let Some(taken) = taken else {
                    break;
                };
                let topic = taken.value().topic.clone();
                let report = Report {
                    topic: topic.clone(),
                    summary: format!("done by {name}"),
                    worker: name.to_owned(),
                };
                taken
                    .complete_with(&report, Lease::DEFAULT_RESULT, Map::new())
                    .await
                    .expect("complete");
                took.push(topic);
            }
            took
        }));
    }
    let mut taken: Vec<String> = Vec::new();
    for racer in racers {
        taken.extend(racer.await.expect("a racer"));
    }
    taken.sort();
    let mut expected = topics.clone();
    expected.sort();
    assert_eq!(
        taken, expected,
        "every task taken and completed exactly once"
    );
    // Every member reads one report per task, and none is left to take.
    for fleet in [&a, &b, &c] {
        let space = fleet.space(SPACE);
        let fleet = fleet.clone();
        eventually("every report", || {
            let space = space.clone();
            async move {
                space
                    .read_all_typed::<Report>(&Template::of::<Report>(), 100)
                    .await
                    .map(|reports| reports.len())
                    .unwrap_or(0)
                    == 12
            }
        })
        .await;
        let left = fleet
            .space(SPACE)
            .read_all_typed::<Task>(&Template::of::<Task>(), 100)
            .await
            .expect("read");
        assert!(left.is_empty(), "{left:?}");
    }
    for fleet in [&a, &b, &c] {
        fleet.close().await.expect("close");
    }
    hub.close().await;
}

/// A member that took a task and crashed: the task reappears for another member once the take's
/// lease lapses; renewal and cancellation of a write cross the hub too.
async fn crash_renew_cancel(wire: Wire, address: &str) {
    let hub = Hub::start(wire, address).await;
    let (a, _) = hub.member().await;
    let (b, _) = hub.member().await;
    let (c, _) = hub.member().await;
    a.space(SPACE)
        .write(&task("orphan"), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    wait_task(&b, "orphan").await;
    wait_task(&c, "orphan").await;
    let mut taken = b
        .space(SPACE)
        .with_settle(SETTLE)
        .take_typed::<Task>(
            &Template::of::<Task>(),
            Lease::from_millis(1500).expect("lease"),
            PATIENCE,
        )
        .await
        .expect("take")
        .expect("b takes it");
    // A renewal of the take crosses too: c sees the later expiry.
    let renewed = taken
        .renew(Lease::from_millis(2500).expect("lease"))
        .await
        .expect("renew");
    let id = taken.entry_id().clone();
    let c_space = c.space(SPACE);
    eventually("c sees the renewed hold", || {
        let c_space = c_space.clone();
        let id = id.clone();
        async move {
            c_space
                .get(&id)
                .await
                .ok()
                .flatten()
                .is_some_and(|view| view.holder().is_some())
        }
    })
    .await;
    taken.release();
    b.close().await.expect("b crashes");
    let again = c
        .space(SPACE)
        .with_settle(SETTLE)
        .take_typed::<Task>(&Template::of::<Task>(), Lease::DEFAULT_TAKE, PATIENCE)
        .await
        .expect("take")
        .expect("c takes the task once the hold lapsed");
    assert!(
        SystemClock.now_ms() >= renewed,
        "not before the renewed hold lapsed"
    );
    assert_eq!(again.entry_id(), &id);
    assert_eq!(again.taken().epoch(), 2);
    again
        .complete(None, Lease::DEFAULT_RESULT, Map::new())
        .await
        .expect("complete");

    // A write renewed and then cancelled: the reader sees both.
    let space = a.space(SPACE);
    let written = space
        .write(
            &task("short"),
            Lease::from_millis(3000).expect("lease"),
            Map::new(),
        )
        .await
        .expect("write");
    wait_task(&c, "short").await;
    space
        .renew_write(&written, Lease::from_millis(60_000).expect("lease"))
        .await
        .expect("renew");
    let c_space = c.space(SPACE);
    eventually("c sees the renewed write", || {
        let c_space = c_space.clone();
        let written = written.clone();
        async move {
            c_space
                .get(&written)
                .await
                .ok()
                .flatten()
                .is_some_and(|view| view.expires_at_millis() > SystemClock.now_ms() + 30_000)
        }
    })
    .await;
    space.cancel(&written).await.expect("cancel");
    eventually("c sees the cancel", || {
        let c_space = c_space.clone();
        async move {
            c_space
                .read_all_typed::<Task>(&Template::of::<Task>(), 100)
                .await
                .is_ok_and(|left| left.is_empty())
        }
    })
    .await;
    for fleet in [&a, &c] {
        fleet.close().await.expect("close");
    }
    hub.close().await;
}

/// A watch on one member hears what the others do through the hub, and an agent's writes stay
/// agent-attested across it.
async fn watches_and_agents(wire: Wire, address: &str) {
    let hub = Hub::start(wire, address).await;
    let (a, _) = hub.member().await;
    let (b, _) = hub.member().await;
    let (c, _) = hub.member().await;
    let mut events = a
        .space(SPACE)
        .watch(&Template::of::<Task>())
        .await
        .expect("watch");
    let agent = b
        .peer()
        .agent_identity("writer", "PT1H")
        .await
        .expect("an agent");
    let id = b
        .space(SPACE)
        .as_agent(agent.clone())
        .write(&task("watched"), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    let written = next_event(&mut events).await;
    assert_eq!(
        (written.kind, written.entry.entry_id()),
        (EventKind::Written, &id)
    );
    assert_eq!(written.entry.attestation(), Attestation::AgentAttested);
    assert_eq!(written.entry.issuer(), agent.agent_id());
    wait_task(&c, "watched").await;
    let taken = c
        .space(SPACE)
        .with_settle(SETTLE)
        .take(&Template::of::<Task>(), Lease::DEFAULT_TAKE, PATIENCE)
        .await
        .expect("take")
        .expect("c takes it");
    let event = next_event(&mut events).await;
    assert_eq!(
        (event.kind, event.entry.entry_id()),
        (EventKind::Taken, &id)
    );
    taken
        .complete(None, Lease::DEFAULT_RESULT, Map::new())
        .await
        .expect("complete");
    let event = next_event(&mut events).await;
    assert_eq!(
        (event.kind, event.entry.entry_id()),
        (EventKind::Completed, &id)
    );
    for fleet in [&a, &b, &c] {
        fleet.close().await.expect("close");
    }
    hub.close().await;
}

/// A worker bound on one member, its card published through the hub, called from another member
/// as a remote action.
async fn worker_and_remote_call(wire: Wire, address: &str) {
    let hub = Hub::start(wire, address).await;
    let (worker, _) = hub.member().await;
    let (caller, _) = hub.member().await;
    let (_bystander, _) = hub.member().await;
    let bound = worker
        .agent("researcher")
        .settle(SETTLE)
        .take(
            SPACE,
            Lease::DEFAULT_TAKE,
            |task: Task, ctx: TakeContext| async move {
                Ok(Reply::from(Report {
                    topic: task.topic.clone(),
                    summary: format!("researched {}", task.topic),
                    worker: ctx.agent_id().to_owned(),
                }))
            },
        )
        .action("research")
        .produces::<Report>()
        .bind()
        .await
        .expect("bind");
    let remote = RemoteActions::new(&caller);
    eventually("the worker's card reaches the caller", || async {
        !remote.consuming(Task::SCHEMA).await.is_empty()
    })
    .await;
    let action = remote
        .consuming(Task::SCHEMA)
        .await
        .into_iter()
        .next()
        .expect("an action");
    let result = remote
        .invoke(
            &action,
            cbor_map! { "topic" => "rust", "priority" => 3 },
            PATIENCE,
        )
        .await
        .expect("invoke")
        .expect("a result");
    let report: Report = result.decode().expect("a report");
    assert_eq!(report.topic, "rust");
    assert_eq!(report.worker, bound.agent_id());
    bound.stop(Duration::from_secs(5)).await;
    for fleet in [&worker, &caller, &_bystander] {
        fleet.close().await.expect("close");
    }
    hub.close().await;
}

/// A member that joins after the writes catches up by anti-entropy from the hub, and a large
/// payload written by a member that leaves at once is still read by another.
async fn late_joiner_and_large_payload(wire: Wire, address: &str) {
    let hub = Hub::start(wire, address).await;
    let (a, _) = hub.member().await;
    let (b, _) = hub.member().await;
    for n in 0..5 {
        a.space(SPACE)
            .write(
                &task(&format!("early{n}")),
                Lease::DEFAULT_WRITE,
                Map::new(),
            )
            .await
            .expect("write");
    }
    // A payload past the inline limit travels as a block its writer holds.
    let big = "x".repeat(200 * 1024);
    let mut events = hub.hub.subscribe();
    let big_id = b
        .space(SPACE)
        .write(&task(&big), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    let cid = b
        .peer()
        .own_payload_block(SPACE, big_id.as_str())
        .await
        .expect("the payload travels as a block");
    // The hub fetches it; the writer can see that it holds it and leaves.
    let held = tokio::time::timeout(PATIENCE, async {
        loop {
            match events.recv().await {
                Ok(PeerEvent::Block { cid: got }) if got == cid => return,
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(error) => panic!("events: {error}"),
            }
        }
    })
    .await;
    assert!(held.is_ok(), "the hub fetched the block");
    let mut probe = b.peer().subscribe();
    b.peer()
        .probe_block(&cid, hub.hub.peer_id())
        .await
        .expect("probe");
    let confirmed = tokio::time::timeout(PATIENCE, async {
        loop {
            if let Ok(PeerEvent::BlockHeld { cid: got, by }) = probe.recv().await
                && got == cid
            {
                return by;
            }
        }
    })
    .await
    .expect("the hub confirms it holds the block");
    assert_eq!(confirmed, hub.hub.peer_id());
    b.close().await.expect("the writer leaves");

    let (late, _) = hub.member().await;
    for n in 0..5 {
        wait_task(&late, &format!("early{n}")).await;
    }
    let read = late.space(SPACE).get_typed::<Task>(&big_id).await;
    let read = match read {
        Ok(Some(view)) => Some(view),
        _ => {
            let space = late.space(SPACE);
            let id = big_id.clone();
            let mut found = None;
            let deadline = tokio::time::Instant::now() + PATIENCE;
            while found.is_none() && tokio::time::Instant::now() < deadline {
                found = space.get_typed::<Task>(&id).await.ok().flatten();
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            found
        }
    };
    let read = read.expect("the late joiner reads the large payload");
    assert_eq!(read.value().topic.len(), big.len());
    let counters = hub.hub.counters().await;
    assert!(counters.listen.pulls_answered >= 1, "{counters:?}");
    assert!(counters.listen.blocks_fetched >= 1, "{counters:?}");
    assert!(counters.blocks_served >= 2, "{counters:?}");
    for fleet in [&a, &late] {
        fleet.close().await.expect("close");
    }
    hub.close().await;
}

macro_rules! both_wires {
    ($scenario:ident, $memory:ident, $tcp:ident, $address:literal) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn $memory() {
            $scenario(Wire::Memory, $address).await;
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn $tcp() {
            $scenario(Wire::Tcp, "").await;
        }
    };
}

both_wires!(
    writes_cross,
    writes_cross_in_memory,
    writes_cross_over_tcp,
    "127.0.0.1:7801"
);
both_wires!(
    take_race,
    a_take_race_completes_each_task_once_in_memory,
    a_take_race_completes_each_task_once_over_tcp,
    "127.0.0.1:7802"
);
both_wires!(
    crash_renew_cancel,
    a_crashed_take_reappears_and_renewals_cross_in_memory,
    a_crashed_take_reappears_and_renewals_cross_over_tcp,
    "127.0.0.1:7803"
);
both_wires!(
    watches_and_agents,
    watches_hear_other_members_and_agents_stay_attested_in_memory,
    watches_hear_other_members_and_agents_stay_attested_over_tcp,
    "127.0.0.1:7804"
);
both_wires!(
    worker_and_remote_call,
    a_worker_s_card_and_a_remote_call_cross_in_memory,
    a_worker_s_card_and_a_remote_call_cross_over_tcp,
    "127.0.0.1:7805"
);
both_wires!(
    late_joiner_and_large_payload,
    a_late_joiner_catches_up_and_reads_a_departed_writer_s_block_in_memory,
    a_late_joiner_catches_up_and_reads_a_departed_writer_s_block_over_tcp,
    "127.0.0.1:7806"
);

/// A draining hub stops accepting links, keeps the ones it holds until it has sent what they
/// queued, and then closes.
async fn drain_then_close(wire: Wire, address: &str) {
    let hub = Hub::start(wire, address).await;
    let (a, _) = hub.member().await;
    a.space("tasks")
        .write(&task("before the drain"), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("written");
    wait_task(&a, "before the drain").await;
    assert!(
        hub.hub
            .drain(Duration::from_secs(5))
            .await
            .expect("the hub drains"),
        "everything queued went out"
    );
    // The member's link stays up through the drain.
    assert!(!hub.hub.linked_members().await.is_empty());
    // A newcomer is no longer accepted: it never joins the hub.
    let identity = Identity::generate().expect("identity");
    let mut config = PeerConfig::new(identity, GroupSpec::FoundingText(FOUNDING.to_owned()));
    config.seeds = vec![hub.seed.parse().expect("seed")];
    config.dialers = match hub.wire {
        Wire::Memory => vec![Arc::new(hub.network.dialer())],
        Wire::Tcp => default_dialers(),
    };
    config.clock = system();
    config.reconnect_interval = Duration::from_millis(50);
    config.dial_timeout = Duration::from_millis(500);
    if let Ok(late) = Peer::start(config).await {
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !hub.hub
                .admitted_members()
                .await
                .contains(&late.peer_id().to_owned()),
            "a draining hub admits nobody new"
        );
        let _ = late.close().await;
    }
    assert_eq!(
        hub.hub.counters().await.listen.admitted,
        1,
        "only the first member"
    );
    a.close().await.expect("close");
    hub.close().await;
}

both_wires!(
    drain_then_close,
    a_draining_hub_admits_nobody_new_and_sends_what_it_queued_in_memory,
    a_draining_hub_admits_nobody_new_and_sends_what_it_queued_over_tcp,
    "127.0.0.1:7807"
);
