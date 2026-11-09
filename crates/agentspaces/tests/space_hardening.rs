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

//! Hardening of the Space API ([`agentspaces::space`], [`agentspaces::blocking`]) over the
//! in-memory network: Rust peers joined through one relaying fake seed
//! (`support::FakeSeed::start_relay`).
//!
//! - A write or a completion's result that every fold would refuse (a tag that is not text, a
//!   full space) fails before anything is folded or sent, and a completion keeps its take.
//! - Spaces collect their tombstones (SPEC §7.3), so a full space takes entries again once its
//!   dead ones are past their horizon, and a member refuses re-offered tombstones at the door.
//! - Takes and reads on a closed peer answer `Closed` at once; a take with a zero timeout makes
//!   one attempt; `Duration::MAX` waits with no deadline.
//! - Cancelling an entry another member completed is `Ok`.
//! - Dropped `watch` and `notify` futures leave no watch behind; a dropped take keeps its claim
//!   until its lease lapses, and a take can be found and completed by id.
//! - Watchers share one decoded payload; a take decodes a few candidates only, and judges tags
//!   before it decodes; a won take keeps the payload it found.
//! - The blocking facade's subscriptions run their handlers on a thread of their own.

mod support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentspaces::Entry;
use agentspaces::blocking;
use agentspaces::clock::{SharedClock, SystemClock};
use agentspaces::entry;
use agentspaces::group::GroupSpec;
use agentspaces::peer::{Peer, PeerConfig, PeerError};
use agentspaces::space::{
    EntryId, EntryView, EventKind, Fleet, Lease, SpaceError, SpaceEvent, SpaceEvents, Template,
};
use agentspaces::transport::memory::MemoryNetwork;
use agentspaces::wire::bodies;
use agentspaces::wire::cbor::{self, Map, Value};
use agentspaces::wire::cbor_map;
use agentspaces::wire::filters::Matcher;
use agentspaces::wire::fold::Refusal;
use agentspaces::wire::identity::Identity;
use agentspaces::wire::ids;
use serde::{Deserialize, Serialize};
use support::{FakeSeed, PATIENCE, config};
use tokio::time::Instant;

const SEED: &str = "127.0.0.1:7800";
const FOUNDING: &str = "agentspaces-rust-space-hardening";
const SPACE: &str = "tasks";
const TASK: &str = "com.acme.Task#v1";
const RESULT: &str = "com.acme.Result#v1";
const OTHER: &str = "com.acme.Other#v1";
/// The settle window of the takes here (a Java space's 200 ms).
const SETTLE: Duration = Duration::from_millis(200);
/// A payload size that travels as a block (over the 64 KiB inline limit).
const BLOCK_BYTES: usize = 80 * 1024;

fn system() -> SharedClock {
    Arc::new(SystemClock)
}

fn group() -> GroupSpec {
    GroupSpec::FoundingText(FOUNDING.to_owned())
}

fn group_id() -> String {
    ids::group_id_from_founding(FOUNDING.as_bytes())
}

fn fresh() -> Identity {
    Identity::generate().expect("identity")
}

fn task(topic: &str, priority: i64) -> Value {
    cbor_map! { "topic" => topic, "priority" => priority }
}

fn blob(fill: u8) -> Value {
    cbor_map! { "fill" => i64::from(fill), "data" => Value::Bytes(vec![fill; BLOCK_BYTES]) }
}

fn block_cid(payload: &Value) -> String {
    bodies::block_cid(&cbor::encode(payload))
}

fn lease(text: &str) -> Lease {
    Lease::parse(text).expect("a lease")
}

fn on_topic(name: &str) -> Template {
    Template::new(TASK).where_("topic", Matcher::Eq(name.into()))
}

fn non_text_tags() -> Map {
    cbor_map! { "priority" => 3 }.into_map().expect("a map")
}

/// Waits until `check` holds, checking every 20 ms; panics naming `what` after [`PATIENCE`].
async fn wait_for(what: &str, mut check: impl AsyncFnMut() -> bool) {
    let deadline = Instant::now() + PATIENCE;
    while !check().await {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The next event of a watch, within [`PATIENCE`].
async fn next_event(events: &mut SpaceEvents) -> SpaceEvent {
    tokio::time::timeout(PATIENCE, events.next())
        .await
        .expect("an event in time")
        .expect("the watch is open")
}

/// The RUMORs the seed received whose item id starts with `prefix`.
fn rumors(seed: &FakeSeed, prefix: &str) -> usize {
    seed.received()
        .iter()
        .filter(|received| {
            received
                .rumor()
                .is_some_and(|rumor| rumor.item_id.starts_with(prefix))
        })
        .count()
}

/// A relaying seed on a fresh network.
struct Net {
    network: MemoryNetwork,
    seed: FakeSeed,
}

impl Net {
    fn new() -> Net {
        let network = MemoryNetwork::new();
        let seed = FakeSeed::start_relay(&network, SEED, &group_id(), system());
        Net { network, seed }
    }

    fn config(&self, identity: Identity) -> PeerConfig {
        config(&self.network, identity, group(), &[SEED], system())
    }

    /// A member joined through the seed.
    async fn member(&self, identity: Identity) -> Fleet {
        self.member_with(self.config(identity)).await
    }

    /// A member joined through the seed with `config`.
    async fn member_with(&self, config: PeerConfig) -> Fleet {
        let peer = Peer::start(config).await.expect("the peer starts");
        Fleet::from_peer(peer)
    }
}

// ------------------------------------------------------------------------------- writes

/// A tag that is not text is refused before anything is folded or sent (every member's fold refuses
/// such a record, the writer's own too), through the Space API and the peer's own `write_entry`
/// alike.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_write_with_a_tag_that_is_not_text_fails_and_leaves_nothing() {
    let net = Net::new();
    let a = net.member(fresh()).await;
    let tasks = a.space(SPACE);

    let refused = tasks
        .write_value(
            TASK,
            task("tagged", 1),
            Lease::DEFAULT_WRITE,
            non_text_tags(),
        )
        .await;
    assert!(
        matches!(
            refused,
            Err(SpaceError::Peer(PeerError::InvalidArgument(_)))
        ),
        "{refused:?}"
    );
    let refused = a
        .peer()
        .write_entry(SPACE, TASK, task("raw", 1), 60_000, non_text_tags(), None)
        .await;
    assert!(
        matches!(refused, Err(PeerError::InvalidArgument(_))),
        "{refused:?}"
    );
    assert!(
        tasks
            .read_all(&Template::new(TASK), 10)
            .await
            .expect("read_all")
            .is_empty()
    );
    assert!(
        a.peer().space_states(SPACE).await.is_empty(),
        "nothing folded"
    );

    // A text tag still writes, and only that write was rumored.
    let text_tags: Map = [("priority", "3")].into_iter().collect();
    let id = tasks
        .write_value(TASK, task("tagged", 1), Lease::DEFAULT_WRITE, text_tags)
        .await
        .expect("a text tag writes");
    let seen = tasks.get(&id).await.expect("get").expect("held");
    assert_eq!(seen.tag("priority"), Some("3"));
    net.seed
        .wait_for("the one write's rumor", |received| {
            received.iter().any(|frame| {
                frame
                    .rumor()
                    .is_some_and(|rumor| rumor.item_id == format!("w:{id}"))
            })
        })
        .await;
    assert_eq!(
        rumors(&net.seed, "w:"),
        1,
        "the refused writes sent nothing"
    );
    a.close().await.expect("close");
}

/// A payload outside the wire encoding (every member, this one too, reads a payload only in that
/// encoding) is refused before anything is folded or sent, so its writer hears of it rather than
/// every reader dropping it without a word: a map with an integer key (Jackson writes every key as
/// text), nesting past 64 levels, and an integer no CBOR form carries. The same values within the
/// encoding write.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_payload_outside_the_wire_encoding_fails_and_leaves_nothing() {
    let net = Net::new();
    let a = net.member(fresh()).await;
    let tasks = a.space(SPACE);
    let mut deep = Value::Int(1);
    for _ in 0..65 {
        deep = Value::Array(vec![deep]);
    }
    let mut integer_key = Map::new();
    integer_key.insert(7, "seven");
    for (what, payload) in [
        ("an integer key", Value::Map(integer_key)),
        ("65 levels", deep),
        ("an integer past 2^64", Value::Int(i128::MAX)),
    ] {
        let refused = tasks
            .write_value(TASK, payload, Lease::DEFAULT_WRITE, Map::new())
            .await;
        assert!(
            matches!(
                refused,
                Err(SpaceError::Peer(PeerError::InvalidArgument(_)))
            ),
            "{what}: {refused:?}"
        );
    }
    assert!(
        a.peer().space_states(SPACE).await.is_empty(),
        "nothing folded"
    );
    assert_eq!(rumors(&net.seed, "w:"), 0, "nothing rumored");
    let mut text_key = Map::new();
    text_key.insert("7", "seven");
    text_key.insert("big", Value::Int(i128::from(u64::MAX)));
    let id = tasks
        .write_value(TASK, Value::Map(text_key), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("a payload in the wire encoding writes");
    let held = tasks.get(&id).await.expect("get").expect("held");
    assert_eq!(
        held.payload().get("big"),
        Some(&Value::Int(i128::from(u64::MAX)))
    );
}

/// A completion whose result every fold would refuse (a tag that is not text) or that its space
/// has no room for fails before the completion commits: the take is still held, the entry not
/// completed, nothing rumored; a completion that can write its result then succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_result_that_cannot_be_written_fails_the_completion_with_the_take_held() {
    let net = Net::new();
    let mut config = net.config(fresh());
    config.space_max_entries = 3;
    let a = net.member_with(config).await;
    let tasks = a.space(SPACE).with_settle(SETTLE);
    let id = tasks
        .write_value(TASK, task("work", 1), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    let taken = tasks
        .take(&Template::new(TASK), lease("1m"), PATIENCE)
        .await
        .expect("take")
        .expect("taken");
    assert_eq!(taken.entry_id(), &id);

    let refused = taken
        .complete(
            Some((RESULT, cbor_map! { "done" => true })),
            Lease::DEFAULT_RESULT,
            non_text_tags(),
        )
        .await;
    assert!(
        matches!(
            refused,
            Err(SpaceError::Peer(PeerError::InvalidArgument(_)))
        ),
        "{refused:?}"
    );
    let still = tasks.get(&id).await.expect("get").expect("held");
    assert!(!still.completed(), "the completion did not commit");
    assert_eq!(
        still.holder(),
        Some(taken.holder()),
        "the take is still held"
    );

    // Fill the space to its bound: the result has no room, so the completion fails as well.
    for n in 0..2 {
        tasks
            .write_value(OTHER, task("filler", n), Lease::DEFAULT_WRITE, Map::new())
            .await
            .expect("a filler");
    }
    let refused = taken
        .complete(
            Some((RESULT, cbor_map! { "done" => true })),
            Lease::DEFAULT_RESULT,
            Map::new(),
        )
        .await;
    assert!(
        matches!(
            refused,
            Err(SpaceError::Refused {
                refusal: Refusal::Full,
                ..
            })
        ),
        "{refused:?}"
    );
    let still = tasks.get(&id).await.expect("get").expect("held");
    assert!(!still.completed(), "the completion did not commit");
    assert_eq!(still.holder(), Some(taken.holder()));
    assert!(
        a.peer().counters().await.space_refused_inserts >= 1,
        "the refused insert is counted"
    );

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(rumors(&net.seed, "d:"), 0, "no completion was rumored");
    // Without a result the completion needs no room: the take was kept for it.
    assert_eq!(
        taken
            .complete(None, Lease::DEFAULT_RESULT, Map::new())
            .await
            .expect("complete"),
        None
    );
    assert!(
        tasks
            .get(&id)
            .await
            .expect("get")
            .is_some_and(|view| view.completed())
    );
    a.close().await.expect("close");
}

// ------------------------------------------------------------------------------- collection

/// A space at its bound refuses a write (`Refused(Full)`, counted, nothing rumored) instead of
/// answering `Ok` for an entry it never stored; once its lapsed entries are past their horizon
/// (twice the space's longest lease, here 400 ms) they are collected, and the same write succeeds
/// and reads back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_space_refuses_writes_until_its_tombstones_are_collected() {
    let net = Net::new();
    let mut config = net.config(fresh());
    config.space_max_entries = 8;
    let a = net.member_with(config).await;
    let tasks = a.space(SPACE);
    for n in 0..8 {
        tasks
            .write_value(TASK, task("short", n), lease("400ms"), Map::new())
            .await
            .expect("a write within the bound");
    }
    let full = tasks
        .write_value(TASK, task("long", 9), lease("10m"), Map::new())
        .await;
    assert!(
        matches!(
            full,
            Err(SpaceError::Refused {
                refusal: Refusal::Full,
                ..
            })
        ),
        "{full:?}"
    );
    assert_eq!(a.peer().counters().await.space_refused_inserts, 1);
    net.seed
        .wait_for("the eight writes' rumors", |received| {
            received
                .iter()
                .filter(|frame| {
                    frame
                        .rumor()
                        .is_some_and(|rumor| rumor.item_id.starts_with("w:"))
                })
                .count()
                >= 8
        })
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(rumors(&net.seed, "w:"), 8, "the refused write sent nothing");

    // Lapsed at 400 ms, collectable 800 ms after (min(2 × 400 ms, 5 min)).
    tokio::time::sleep(Duration::from_millis(1400)).await;
    let id = tasks
        .write_value(TASK, task("long", 9), lease("10m"), Map::new())
        .await
        .expect("the space collected its tombstones");
    let view = tasks.get(&id).await.expect("get").expect("held");
    assert_eq!(
        view.payload().get("topic").and_then(Value::as_str),
        Some("long")
    );
    assert_eq!(
        tasks
            .read(&on_topic("long"), Duration::ZERO)
            .await
            .expect("read")
            .map(|view| view.entry_id().clone()),
        Some(id)
    );
    let counters = a.peer().counters().await;
    assert!(counters.space_collected >= 8, "{counters:?}");
    assert_eq!(a.peer().space_states(SPACE).await.len(), 1);
    a.close().await.expect("close");
}

/// A member whose space is full refuses received entries (counted), then collects its tombstones
/// when a new entry arrives past their horizon and folds it, and refuses the collected tombstones a
/// member that never collects (the fake seed) offers again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_member_collects_and_refuses_tombstones_offered_again() {
    let net = Net::new();
    let a = net.member(fresh()).await;
    let mut config = net.config(fresh());
    config.space_max_entries = 8;
    let b = net.member_with(config).await;
    let tasks_a = a.space(SPACE);
    let tasks_b = b.space(SPACE);
    b.peer().pull_space(SPACE).await.expect("B opens the space");
    for n in 0..8 {
        tasks_a
            .write_value(TASK, task("short", n), lease("400ms"), Map::new())
            .await
            .expect("write");
    }
    wait_for("B to hold the eight entries", async || {
        b.peer().space_states(SPACE).await.len() == 8
    })
    .await;
    tasks_a
        .write_value(TASK, task("ninth", 9), lease("400ms"), Map::new())
        .await
        .expect("write");
    wait_for("B to refuse the ninth", async || {
        b.peer().counters().await.space_refused_inserts >= 1
    })
    .await;
    assert_eq!(b.peer().space_states(SPACE).await.len(), 8);

    // Past every horizon (each lapsed 400 ms after its write and is collectable 800 ms later),
    // a new entry makes the full space collect, and folds.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let reader = tokio::spawn({
        let tasks_b = tasks_b.clone();
        async move { tasks_b.read(&on_topic("tenth"), PATIENCE).await }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let tenth = tasks_a
        .write_value(TASK, task("tenth", 10), lease("400ms"), Map::new())
        .await
        .expect("write");
    let seen = reader.await.expect("the reader").expect("read");
    assert_eq!(seen.map(|view| view.entry_id().clone()), Some(tenth));
    assert!(b.peer().counters().await.space_collected >= 8);

    // The seed never collects: a pull brings the tombstones back, and B refuses them.
    tasks_b.pull().await.expect("pull");
    wait_for("B to refuse the re-offered tombstones", async || {
        b.peer().counters().await.space_reoffers_refused >= 8
    })
    .await;
    assert!(b.peer().space_states(SPACE).await.len() <= 2);
    a.close().await.expect("close");
    b.close().await.expect("close");
}

// ------------------------------------------------------------------------------- a closed peer

/// Once the peer is closed, a take or a read already waiting ends with `Closed` at once, and so do
/// new takes (with or without a match held) and reads that find no match; a read of a held match,
/// `read_all`, and `get` still answer from what is held.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn takes_and_reads_on_a_closed_peer_answer_closed_at_once() {
    let net = Net::new();
    let a = net.member(fresh()).await;
    let tasks = a.space(SPACE).with_settle(SETTLE);
    let id = tasks
        .write_value(TASK, task("held", 1), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    // A long settle window: what wakes the waiting verbs is the close, not their next pull.
    let patient = tasks.with_settle(Duration::from_secs(5));
    let waiting_take = tokio::spawn({
        let patient = patient.clone();
        async move {
            patient
                .take(
                    &on_topic("none"),
                    Lease::DEFAULT_TAKE,
                    Duration::from_secs(30),
                )
                .await
        }
    });
    let waiting_read = tokio::spawn({
        let patient = patient.clone();
        async move {
            patient
                .read(&on_topic("none"), Duration::from_secs(30))
                .await
        }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    let closed_at = Instant::now();
    a.close().await.expect("close");
    let take = tokio::time::timeout(PATIENCE, waiting_take)
        .await
        .expect("the take ends")
        .expect("the task");
    assert!(
        matches!(take, Err(SpaceError::Peer(PeerError::Closed))),
        "{take:?}"
    );
    let read = tokio::time::timeout(PATIENCE, waiting_read)
        .await
        .expect("the read ends")
        .expect("the task");
    assert!(
        matches!(read, Err(SpaceError::Peer(PeerError::Closed))),
        "{read:?}"
    );
    assert!(
        closed_at.elapsed() < Duration::from_secs(1),
        "both ended at the close, not at their timeouts or settle windows: {:?}",
        closed_at.elapsed()
    );

    for template in [Template::new(TASK), on_topic("none")] {
        let started = Instant::now();
        let take = tasks
            .take(&template, Lease::DEFAULT_TAKE, Duration::from_secs(5))
            .await;
        assert!(
            matches!(take, Err(SpaceError::Peer(PeerError::Closed))),
            "{take:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }
    let started = Instant::now();
    let read = tasks.read(&on_topic("none"), Duration::from_secs(5)).await;
    assert!(
        matches!(read, Err(SpaceError::Peer(PeerError::Closed))),
        "{read:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    let held = tasks
        .read(&Template::new(TASK), Duration::from_secs(5))
        .await
        .expect("a held match is still read");
    assert_eq!(held.map(|view| view.entry_id().clone()), Some(id.clone()));
    assert_eq!(
        tasks
            .read_all(&Template::new(TASK), 10)
            .await
            .expect("read_all")
            .len(),
        1
    );
    assert!(tasks.get(&id).await.expect("get").is_some());
}

// ------------------------------------------------------------------------------- takes

/// A take with a zero timeout makes one attempt (Java's `tryTakeOnce` before the deadline): it
/// takes an available entry, answers `None` at once when there is none, and passes over an entry
/// another member holds to take the next.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_take_with_a_zero_timeout_takes_an_available_entry() {
    let net = Net::new();
    let a = net.member(fresh()).await;
    let b = net.member(fresh()).await;
    let tasks_a = a.space(SPACE).with_settle(SETTLE);
    let tasks_b = b.space(SPACE).with_settle(SETTLE);
    let first = tasks_a
        .write_value(TASK, task("first", 1), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    let taken = tasks_a
        .take(&Template::new(TASK), Lease::DEFAULT_TAKE, Duration::ZERO)
        .await
        .expect("take")
        .expect("a zero timeout takes what is available");
    assert_eq!(taken.entry_id(), &first);
    let started = Instant::now();
    let none = tasks_a
        .take(&Template::new(TASK), Lease::DEFAULT_TAKE, Duration::ZERO)
        .await
        .expect("take");
    assert!(none.is_none());
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );

    // Two entries, the first held by B: the zero-timeout take passes over it to the second.
    let held = tasks_a
        .write_value(TASK, task("held", 2), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    let free = tasks_a
        .write_value(TASK, task("free", 3), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    wait_for("B to see both", async || {
        tasks_b
            .read_all(&Template::new(TASK), 10)
            .await
            .is_ok_and(|views| views.len() == 2)
    })
    .await;
    let by_b = tasks_b
        .take(&on_topic("held"), Lease::DEFAULT_TAKE, PATIENCE)
        .await
        .expect("take")
        .expect("B takes it");
    assert_eq!(by_b.entry_id(), &held);
    wait_for("A to see B's claim", async || {
        tasks_a
            .read_all(&Template::new(TASK), 10)
            .await
            .is_ok_and(|views| views.len() == 1)
    })
    .await;
    let second = tasks_a
        .take(&Template::new(TASK), Lease::DEFAULT_TAKE, Duration::ZERO)
        .await
        .expect("take")
        .expect("the free one");
    assert_eq!(second.entry_id(), &free);
    a.close().await.expect("close");
    b.close().await.expect("close");
}

/// A timeout too long for the clock (`Duration::MAX`, "wait forever") waits with no deadline
/// instead of panicking.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_timeout_of_duration_max_waits_without_a_deadline() {
    let net = Net::new();
    let a = net.member(fresh()).await;
    let tasks = a.space(SPACE).with_settle(SETTLE);
    let id = tasks
        .write_value(TASK, task("forever", 1), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    let read = tasks
        .read(&Template::new(TASK), Duration::MAX)
        .await
        .expect("read");
    assert_eq!(read.map(|view| view.entry_id().clone()), Some(id.clone()));
    let taken = tasks
        .take(&Template::new(TASK), Lease::DEFAULT_TAKE, Duration::MAX)
        .await
        .expect("take")
        .expect("taken");
    assert_eq!(taken.entry_id(), &id);
    // One that has nothing to find yet waits for the entry written meanwhile.
    let waiting = tokio::spawn({
        let tasks = tasks.clone();
        async move { tasks.read(&on_topic("later"), Duration::MAX).await }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    let later = tasks
        .write_value(TASK, task("later", 2), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    let read = tokio::time::timeout(PATIENCE, waiting)
        .await
        .expect("in time")
        .expect("the task")
        .expect("read");
    assert_eq!(read.map(|view| view.entry_id().clone()), Some(later));
    let held = tasks.held(&id, Duration::MAX).await.expect("held");
    assert!(held.is_some());
    a.close().await.expect("close");
}

/// Cancelling an entry another member took and completed is `Ok`, every time, and sends nothing;
/// the entry stays completed everywhere, and another writer's entry is still `NotIssuer`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_of_an_entry_another_member_completed_is_ok() {
    let net = Net::new();
    let a = net.member(fresh()).await;
    let b = net.member(fresh()).await;
    let tasks_a = a.space(SPACE).with_settle(SETTLE);
    let tasks_b = b.space(SPACE).with_settle(SETTLE);
    let id = tasks_a
        .write_value(TASK, task("raced", 1), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    let taken = tasks_b
        .take(&Template::new(TASK), Lease::DEFAULT_TAKE, PATIENCE)
        .await
        .expect("take")
        .expect("B takes it");
    taken
        .complete(None, Lease::DEFAULT_RESULT, Map::new())
        .await
        .expect("complete");
    wait_for("A to see the completion", async || {
        tasks_a
            .get(&id)
            .await
            .is_ok_and(|view| view.is_some_and(|view| view.completed()))
    })
    .await;
    tasks_a.cancel(&id).await.expect("cancel is Ok");
    tasks_a.cancel(&id).await.expect("and idempotent");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(rumors(&net.seed, "x:"), 0, "nothing was sent");
    for tasks in [&tasks_a, &tasks_b] {
        assert!(
            tasks
                .get(&id)
                .await
                .expect("get")
                .is_some_and(|view| view.completed())
        );
    }
    let not_issuer = tasks_b.cancel(&id).await;
    assert!(
        matches!(not_issuer, Err(SpaceError::NotIssuer { .. })),
        "{not_issuer:?}"
    );
    a.close().await.expect("close");
    b.close().await.expect("close");
}

/// Documented behaviour: a take cancelled from outside after its claim went out leaves the claim
/// held until its lease lapses (there is no un-claim), and the entry then reappears; a take whose
/// future was dropped can still be found by id and completed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_take_holds_its_claim_until_its_lease_lapses() {
    let net = Net::new();
    let a = net.member(fresh()).await;
    let tasks = a.space(SPACE).with_settle(Duration::from_millis(600));
    let id = tasks
        .write_value(TASK, task("cancelled", 1), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    let started = Instant::now();
    let cancelled = tokio::time::timeout(
        Duration::from_millis(200),
        tasks.take(&Template::new(TASK), lease("1500ms"), PATIENCE),
    )
    .await;
    assert!(cancelled.is_err(), "cancelled inside its settle window");
    assert!(
        tasks
            .read_all(&Template::new(TASK), 10)
            .await
            .expect("read_all")
            .is_empty(),
        "the orphaned claim holds the entry"
    );
    let back = tasks
        .read(&Template::new(TASK), PATIENCE)
        .await
        .expect("read")
        .expect("the entry reappears once the hold lapses");
    assert_eq!(back.entry_id(), &id);
    assert!(
        started.elapsed() >= Duration::from_millis(1200),
        "held until the lease: {:?}",
        started.elapsed()
    );

    // Dropped again, then found by id and completed.
    let cancelled = tokio::time::timeout(
        Duration::from_millis(200),
        tasks.take(&Template::new(TASK), lease("1m"), PATIENCE),
    )
    .await;
    assert!(cancelled.is_err());
    let found = tasks
        .held(&id, PATIENCE)
        .await
        .expect("held")
        .expect("the orphaned take is found by id");
    assert_eq!(found.entry_id(), &id);
    assert!(found.lease() <= lease("1m"));
    found
        .complete(None, Lease::DEFAULT_RESULT, Map::new())
        .await
        .expect("complete");
    assert!(
        tasks
            .get(&id)
            .await
            .expect("get")
            .is_some_and(|view| view.completed())
    );
    a.close().await.expect("close");
}

/// `aspace take` then `aspace complete <id>` in two processes on one keystore: a peer takes
/// and closes; another on the same identity finds the take by id (after pulling), completes it,
/// and a third member sees it completed. A take whose hold lapsed is not found.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_take_is_found_and_completed_by_id_from_another_process() {
    let net = Net::new();
    let writer = net.member(fresh()).await;
    let tasks_w = writer.space(SPACE).with_settle(SETTLE);
    let worked = tasks_w
        .write_value(TASK, task("worked", 1), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    let lapsing = tasks_w
        .write_value(TASK, task("lapsing", 2), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");

    let keystore = fresh();
    let first = net.member(keystore.clone()).await;
    let tasks_1 = first.space(SPACE).with_settle(SETTLE);
    let taken = tasks_1
        .take(&on_topic("worked"), lease("1m"), PATIENCE)
        .await
        .expect("take")
        .expect("taken");
    let holder = taken.holder().to_owned();
    let short = tasks_1
        .take(&on_topic("lapsing"), lease("500ms"), PATIENCE)
        .await
        .expect("take")
        .expect("taken");
    assert_eq!(short.entry_id(), &lapsing);
    wait_for("the seed to hold both claims", async || {
        net.seed.space_states(SPACE).len() == 2
    })
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    first.close().await.expect("the first process exits");
    drop(taken);
    drop(short);

    let second = net.member(keystore).await;
    let tasks_2 = second.space(SPACE).with_settle(SETTLE);
    let found = tasks_2
        .held(&worked, PATIENCE)
        .await
        .expect("held")
        .expect("found by id in the second process");
    assert_eq!(found.holder(), holder);
    found
        .complete(
            Some((RESULT, cbor_map! { "done" => true })),
            Lease::DEFAULT_RESULT,
            Map::new(),
        )
        .await
        .expect("complete")
        .expect("a result");
    wait_for("the writer to see it completed", async || {
        tasks_w
            .get(&worked)
            .await
            .is_ok_and(|view| view.is_some_and(|view| view.completed()))
    })
    .await;

    tokio::time::sleep(Duration::from_millis(800)).await;
    let lapsed = tasks_2
        .held(&lapsing, Duration::from_millis(300))
        .await
        .expect("held");
    assert!(lapsed.is_none(), "a lapsed hold is not found");
    let unknown = tasks_2
        .held(&EntryId::new("no-such-entry"), Duration::ZERO)
        .await
        .expect("held");
    assert!(unknown.is_none());
    writer.close().await.expect("close");
    second.close().await.expect("close");
}

/// A counted entry type: each decode of its payload is counted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Counted {
    n: i64,
}

static DECODES: AtomicUsize = AtomicUsize::new(0);

impl Entry for Counted {
    const SCHEMA: &'static str = "com.acme.Counted#v1";

    fn from_payload(payload: &Value) -> Result<Self, entry::EntryError> {
        DECODES.fetch_add(1, Ordering::SeqCst);
        entry::from_value(payload)
    }
}

/// A take decodes a few candidates per pass, not every available entry (each is decoded on the
/// peer's actor, and a take claims one).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_take_decodes_a_few_candidates_only() {
    let net = Net::new();
    let a = net.member(fresh()).await;
    let tasks = a.space(SPACE).with_settle(SETTLE);
    for n in 0..40 {
        tasks
            .write(&Counted { n }, Lease::DEFAULT_WRITE, Map::new())
            .await
            .expect("write");
    }
    DECODES.store(0, Ordering::SeqCst);
    let taken = tasks
        .take_typed::<Counted>(&Template::of::<Counted>(), Lease::DEFAULT_TAKE, PATIENCE)
        .await
        .expect("take")
        .expect("taken");
    assert_eq!(taken.value(), &Counted { n: 0 });
    let decodes = DECODES.load(Ordering::SeqCst);
    assert!(
        decodes <= 8,
        "{decodes} payloads decoded for one take of the first of 40"
    );
    a.close().await.expect("close");
}

/// A find judges the tags before it decodes a payload, so an entry whose tags do not match never
/// has its payload block fetched.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tags_are_judged_before_a_payload_is_fetched_or_decoded() {
    let net = Net::new();
    let a = net.member(fresh()).await;
    let b = net.member(fresh()).await;
    let tasks_a = a.space(SPACE);
    let tasks_b = b.space(SPACE);
    b.peer().pull_space(SPACE).await.expect("B opens the space");
    let lane_a: Map = [("lane", "a")].into_iter().collect();
    let lane_b: Map = [("lane", "b")].into_iter().collect();
    let mut other_cids = Vec::new();
    for fill in 1..=3u8 {
        let payload = blob(fill);
        other_cids.push(block_cid(&payload));
        tasks_a
            .write_value(TASK, payload, Lease::DEFAULT_WRITE, lane_a.clone())
            .await
            .expect("write");
    }
    let wanted = blob(9);
    let wanted_cid = block_cid(&wanted);
    tasks_a
        .write_value(TASK, wanted, Lease::DEFAULT_WRITE, lane_b)
        .await
        .expect("write");
    wait_for("B to hold the four states", async || {
        b.peer().space_states(SPACE).await.len() == 4
    })
    .await;
    let template = Template::new(TASK).tag_eq("lane", "b");
    wait_for("B to read the lane b entry", async || {
        tasks_b
            .read_all(&template, 10)
            .await
            .is_ok_and(|views| views.len() == 1)
    })
    .await;
    assert!(b.peer().block(&wanted_cid).await.is_some());
    tokio::time::sleep(Duration::from_millis(500)).await;
    for cid in &other_cids {
        assert!(
            b.peer().block(cid).await.is_none(),
            "a block of an entry whose tags do not match was fetched"
        );
    }
    a.close().await.expect("close");
    b.close().await.expect("close");
}

/// A won take keeps the payload its candidate carried, even when the payload's block is evicted
/// from the fetched cache during the settle window.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_won_take_keeps_its_payload_when_the_block_is_evicted() {
    let net = Net::new();
    let a = net.member(fresh()).await;
    let mut config = net.config(fresh());
    config.fetched_block_bytes = 2 * BLOCK_BYTES + BLOCK_BYTES / 2;
    let b = net.member_with(config).await;
    let tasks_a = a.space(SPACE);
    let wanted = blob(1);
    let wanted_cid = block_cid(&wanted);
    tasks_a
        .write_value(TASK, wanted.clone(), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    for fill in 2..=7u8 {
        tasks_a
            .write_value(OTHER, blob(fill), Lease::DEFAULT_WRITE, Map::new())
            .await
            .expect("write");
    }
    let tasks_b = b.space(SPACE).with_settle(Duration::from_secs(3));
    let seen = tasks_b
        .read(&Template::new(TASK), PATIENCE)
        .await
        .expect("read")
        .expect("B reads the task, its block fetched");
    assert_eq!(seen.payload(), &wanted);
    let take = tokio::spawn({
        let tasks_b = tasks_b.clone();
        async move {
            tasks_b
                .take(&Template::new(TASK), Lease::DEFAULT_TAKE, PATIENCE)
                .await
        }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    let window = Instant::now();
    let others = b.space(SPACE);
    wait_for("the task's block to be evicted", async || {
        let _ = others.read_all(&Template::new(OTHER), 10).await;
        b.peer().block(&wanted_cid).await.is_none()
    })
    .await;
    assert!(
        window.elapsed() < Duration::from_millis(2500),
        "evicted inside the settle window"
    );
    let taken = take
        .await
        .expect("the take")
        .expect("take")
        .expect("B wins the take");
    assert_eq!(
        taken.entry().payload(),
        &wanted,
        "the payload found is kept"
    );
    a.close().await.expect("close");
    b.close().await.expect("close");
}

// ------------------------------------------------------------------------------- watches

/// `watch` and `notify` futures dropped after their job was queued (a `select!` branch that lost, a
/// timeout) leave no watch behind: more of them than a peer's 4096 watches, and a real watch still
/// registers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropped_watch_and_notify_futures_leave_no_watch_behind() {
    let net = Net::new();
    let a = net.member(fresh()).await;
    let tasks = a.space(SPACE);
    tasks
        .read_all(&Template::new(TASK), 1)
        .await
        .expect("opens the space");
    let template = Template::new(TASK);
    // More of each kind than the peer's 4096 watches: each kind alone would use them up.
    for kind in ["watch", "notify"] {
        let mut queued = 0;
        for _ in 0..4200 {
            let ready = if kind == "watch" {
                poll_once_and_drop(tasks.watch(&template)).await
            } else {
                poll_once_and_drop(tasks.notify(&template, lease("10m"), |_| {})).await
            };
            if !ready {
                queued += 1;
            }
            // The actor runs the queued job before the next round.
            let _ = a.peer().counters().await;
        }
        assert!(
            queued > 4096,
            "{queued} {kind} futures were dropped with their job queued"
        );
        let real = tasks.watch(&template).await;
        assert!(
            real.is_ok(),
            "a real watch registers after the {kind} futures: {real:?}"
        );
    }
    let mut real = tasks
        .watch(&template)
        .await
        .expect("a real watch registers");
    let id = tasks
        .write_value(TASK, task("watched", 1), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    let event = next_event(&mut real).await;
    assert_eq!(
        (event.kind, event.entry.entry_id()),
        (EventKind::Written, &id)
    );
    a.close().await.expect("close");
}

/// Polls `future` once, then drops it; whether it was ready.
async fn poll_once_and_drop<F: Future>(future: F) -> bool {
    let mut future = Box::pin(future);
    std::future::poll_fn(|cx| std::task::Poll::Ready(future.as_mut().poll(cx).is_ready())).await
}

/// Every watch delivers the same decoded payload, shared, not a copy per watcher.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn watchers_share_one_decoded_payload() {
    let net = Net::new();
    let a = net.member(fresh()).await;
    let tasks = a.space(SPACE);
    let mut first = tasks.watch(&Template::new(TASK)).await.expect("watch");
    let mut second = tasks.watch(&Template::new(TASK)).await.expect("watch");
    tasks
        .write_value(TASK, task("shared", 1), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    let one = next_event(&mut first).await;
    let two = next_event(&mut second).await;
    assert_eq!(one, two);
    assert!(
        std::ptr::eq(one.entry.payload(), two.entry.payload()),
        "one payload, shared"
    );
    let copy: EntryView = one.entry.clone();
    assert!(std::ptr::eq(copy.payload(), two.entry.payload()));
    assert_eq!(copy.into_payload(), task("shared", 1));
    a.close().await.expect("close");
}

// ------------------------------------------------------------------------------- blocking

/// The blocking facade runs a subscription's handler on a thread of its own: the handler may call
/// the facade's verbs, two slow handlers leave the peer answering, and the subscription ends with
/// its lease and when closed. A zero-timeout take and a `Duration::MAX` read work there too.
#[test]
fn blocking_notify_handlers_run_off_the_runtime() {
    let seed_runtime = tokio::runtime::Runtime::new().expect("a runtime for the seed");
    let network = MemoryNetwork::new();
    let seed = seed_runtime
        .block_on(async { FakeSeed::start_relay(&network, SEED, &group_id(), system()) });
    let fleet = blocking::Fleet::join(config(&network, fresh(), group(), &[SEED], system()))
        .expect("joins");
    let tasks = fleet.space(SPACE).with_settle(SETTLE);

    // A handler that writes through the facade.
    let echoed: Arc<Mutex<Vec<Result<EntryId, String>>>> = Arc::default();
    let echo = tasks.notify(&Template::new(TASK), lease("1m"), {
        let tasks = tasks.clone();
        let echoed = Arc::clone(&echoed);
        move |event: SpaceEvent| {
            if event.kind == EventKind::Written {
                let written = tasks
                    .write_value(RESULT, task("echo", 1), Lease::DEFAULT_WRITE, Map::new())
                    .map_err(|error| error.to_string());
                echoed.lock().expect("lock").push(written);
            }
        }
    });
    let echo = echo.expect("notify");
    let id = tasks
        .write_value(TASK, task("ping", 1), Lease::DEFAULT_WRITE, Map::new())
        .expect("write");
    let result = tasks
        .read(&Template::new(RESULT), PATIENCE)
        .expect("read")
        .expect("the handler's write");
    let written = echoed.lock().expect("lock").clone();
    assert_eq!(written, vec![Ok(result.entry_id().clone())]);
    echo.close();
    let deadline = std::time::Instant::now() + PATIENCE;
    while echo.is_open() {
        assert!(
            std::time::Instant::now() < deadline,
            "the closed subscription ends"
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    // Two handlers that block for a while each leave the peer answering.
    let slow: Vec<_> = (0..2)
        .map(|_| {
            tasks
                .notify(&Template::new(OTHER), lease("1m"), |_| {
                    std::thread::sleep(Duration::from_millis(1500));
                })
                .expect("notify")
        })
        .collect();
    tasks
        .write_value(OTHER, task("slow", 1), Lease::DEFAULT_WRITE, Map::new())
        .expect("write");
    std::thread::sleep(Duration::from_millis(200));
    let mut worst = Duration::ZERO;
    for _ in 0..5 {
        let started = std::time::Instant::now();
        tasks.read_all(&Template::new(TASK), 10).expect("read_all");
        worst = worst.max(started.elapsed());
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        worst < Duration::from_millis(700),
        "the peer kept answering while the handlers blocked: {worst:?}"
    );
    for subscription in &slow {
        subscription.close();
    }

    // A subscription ends with its lease.
    let leased = tasks
        .notify(&Template::new(TASK), lease("300ms"), |_| {})
        .expect("notify");
    let deadline = std::time::Instant::now() + PATIENCE;
    while leased.is_open() {
        assert!(
            std::time::Instant::now() < deadline,
            "the lapsed subscription ends"
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    let read = tasks
        .read(&Template::new(TASK), Duration::MAX)
        .expect("read")
        .expect("found");
    assert_eq!(read.entry_id(), &id);
    let taken = tasks
        .take(&Template::new(TASK), Lease::DEFAULT_TAKE, Duration::ZERO)
        .expect("take")
        .expect("a zero timeout takes it");
    assert_eq!(taken.entry_id(), &id);
    let held = tasks
        .held(&id, Duration::ZERO)
        .expect("held")
        .expect("found by id");
    held.complete(None, Lease::DEFAULT_RESULT, Map::new())
        .expect("complete");

    fleet.close().expect("close");
    drop(seed);
}

// ------------------------------------------------------------------------------- closing spaces

/// A peer opens at most 1024 spaces; [`Peer::close_space`] frees a slot, so a resident that opens
/// spaces on demand (`aspace daemon`) can make room instead of refusing every new name for the rest
/// of its life. A closed space opens again on its next use, with what the group holds of it; a
/// space a watch follows is not closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_closed_space_frees_its_slot_and_opens_again_on_use() {
    let net = Net::new();
    let fleet = net.member(fresh()).await;
    let peer = fleet.peer().clone();
    let space = fleet.space("kept");
    let id = space
        .write_value(TASK, task("kept", 1), lease("5m"), Map::new())
        .await
        .expect("write");
    for n in 0..1023 {
        peer.pull_space(&format!("job-{n}")).await.expect("open");
    }
    assert_eq!(peer.open_spaces().await, 1024);
    let refused = peer.pull_space("one-too-many").await;
    assert!(
        matches!(refused, Err(PeerError::InvalidArgument(_))),
        "{refused:?}"
    );

    assert!(peer.close_space("job-0").await.expect("closed"));
    assert!(
        !peer.close_space("job-0").await.expect("answered"),
        "not open now"
    );
    assert_eq!(peer.open_spaces().await, 1023);
    peer.pull_space("one-too-many")
        .await
        .expect("room was made");
    assert_eq!(peer.open_spaces().await, 1024);

    // A space closed and opened again reads what the group holds of it.
    assert!(peer.close_space("kept").await.expect("closed"));
    assert!(peer.close_space("job-1").await.expect("closed"));
    let again = fleet.space("kept");
    let found = again
        .read(&Template::new(TASK), PATIENCE)
        .await
        .expect("read")
        .expect("the entry, pulled again from the seed");
    assert_eq!(found.entry_id(), &id);

    // A watched space stays open.
    let mut events = fleet
        .space("job-2")
        .watch(&Template::new(TASK))
        .await
        .expect("watch");
    assert!(!peer.close_space("job-2").await.expect("answered"));
    events.close();
    assert!(
        peer.close_space("job-2")
            .await
            .expect("closed once unwatched")
    );
}
