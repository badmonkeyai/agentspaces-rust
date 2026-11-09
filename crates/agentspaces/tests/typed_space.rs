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

//! The typed layer of the Space API ([`agentspaces::space::typed`], and its mirror in
//! [`agentspaces::blocking`]) over the in-memory network: `#[derive(Entry)]` types written,
//! read, taken, completed with typed results, and watched by Rust peers joined through one
//! relaying fake seed (`support::FakeSeed::start_relay`).
//!
//! A typed write is the untyped write of [`agentspaces::entry::to_value`]'s payload under the
//! type's schema; typed reads, takes, and watches pass over entries of the schema that do not
//! decode (as a Java template of the class does), reach past them for the ones that do, and never
//! claim them; a template of another schema and a value with no payload form are refused before
//! anything happens.

mod support;

use std::collections::BTreeMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentspaces::Entry;
use agentspaces::blocking;
use agentspaces::clock::{SharedClock, SystemClock};
use agentspaces::entry::{self, EntryError};
use agentspaces::group::GroupSpec;
use agentspaces::peer::Peer;
use agentspaces::space::{
    EntryId, EventKind, Fleet, Lease, SpaceError, Template, TypedEvent, TypedEvents, TypedView,
};
use agentspaces::transport::memory::MemoryNetwork;
use agentspaces::wire::cbor::{Map, Value};
use agentspaces::wire::cbor_map;
use agentspaces::wire::filters::Matcher;
use agentspaces::wire::identity::Identity;
use agentspaces::wire::ids;
use futures_core::Stream;
use serde::{Deserialize, Serialize};
use support::{FakeSeed, PATIENCE, config};
use tokio::time::Instant;

const SEED: &str = "127.0.0.1:7800";
const FOUNDING: &str = "agentspaces-rust-typed-space";
const SPACE: &str = "tasks";
/// The settle window of the takes here (a Java space's 200 ms).
const SETTLE: Duration = Duration::from_millis(200);

/// A task, as the Java `record Task(String topic, int priority)` writes it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Entry)]
#[entry(schema = "com.acme.Task#v1")]
struct Task {
    topic: String,
    priority: i32,
}

/// The result a worker completes a task with.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Entry)]
#[entry(schema = "com.acme.Report#v1")]
#[serde(rename_all = "camelCase")]
struct Report {
    topic: String,
    summary: String,
    worked_by: String,
}

/// A value of `Task`'s shape that has no payload form: a map key that is a container.
#[derive(Debug, Serialize, Deserialize, Entry)]
#[entry(schema = "com.acme.Task#v1")]
struct Unwritable {
    topic: String,
    by_route: BTreeMap<Vec<i32>, i32>,
}

/// A report with no payload form: an integer beyond the CBOR range.
#[derive(Debug, Serialize, Deserialize, Entry)]
#[entry(schema = "com.acme.Report#v1")]
struct HugeReport {
    count: u128,
}

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

fn task(topic: &str, priority: i32) -> Task {
    Task {
        topic: topic.to_owned(),
        priority,
    }
}

fn report(topic: &str) -> Report {
    Report {
        topic: topic.to_owned(),
        summary: "done by rust".to_owned(),
        worked_by: "typed".to_owned(),
    }
}

/// A payload of `Task`'s schema that does not decode as a `Task`: its priority is text.
fn malformed(topic: &str) -> Value {
    cbor_map! { "topic" => topic, "priority" => "high" }
}

fn tags(pairs: &[(&str, &str)]) -> Map {
    pairs.iter().copied().collect()
}

fn lease(text: &str) -> Lease {
    Lease::parse(text).expect("a lease")
}

fn topics(views: &[TypedView<Task>]) -> Vec<&str> {
    views
        .iter()
        .map(|view| view.value().topic.as_str())
        .collect()
}

fn on_topic(name: &str) -> Template {
    Template::of::<Task>().where_("topic", Matcher::Eq(name.into()))
}

/// Waits until `check` holds, checking every 20 ms; panics naming `what` after [`PATIENCE`].
async fn wait_for(what: &str, mut check: impl AsyncFnMut() -> bool) {
    let deadline = Instant::now() + PATIENCE;
    while !check().await {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The next event of a typed watch, within [`PATIENCE`].
async fn next_event<T: Entry>(events: &mut TypedEvents<T>) -> TypedEvent<T> {
    tokio::time::timeout(PATIENCE, events.next())
        .await
        .expect("an event in time")
        .expect("the watch is open")
}

/// Whether a refusal is the typed layer's wrong-schema refusal.
fn wrong_schema<T>(result: &Result<T, SpaceError>) -> bool {
    matches!(
        result,
        Err(SpaceError::Entry(EntryError::WrongSchema { expected, found }))
            if *expected == Task::SCHEMA && found == "com.acme.Report#v1"
    )
}

/// A relaying seed on a fresh network.
struct Net {
    network: MemoryNetwork,
    _seed: FakeSeed,
}

impl Net {
    fn new() -> Net {
        let network = MemoryNetwork::new();
        let seed = FakeSeed::start_relay(&network, SEED, &group_id(), system());
        Net {
            network,
            _seed: seed,
        }
    }

    /// A member joined through the seed.
    async fn member(&self) -> Fleet {
        let peer = Peer::start(config(&self.network, fresh(), group(), &[SEED], system()))
            .await
            .expect("the peer starts");
        Fleet::from_peer(peer)
    }
}

// ------------------------------------------------------------------------------- round trip

/// A typed write is the untyped write of its payload; another member reads it typed, through
/// conditions and tags, takes it, and completes it with a typed result the writer reads typed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typed_write_read_take_and_complete_with_a_typed_result() {
    let net = Net::new();
    let a = net.member().await;
    let b = net.member().await;
    let tasks_a = a.space(SPACE);
    let tasks_b = b.space(SPACE).with_settle(SETTLE);
    assert_eq!(Template::of::<Task>(), Template::new("com.acme.Task#v1"));

    let index = tasks_a
        .write(&task("index", 3), lease("10m"), tags(&[("region", "eu")]))
        .await
        .expect("write");
    tasks_a
        .write(&task("crawl", 5), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    tasks_a
        .write(&task("sleep", 1), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");

    // The typed write is the payload `to_value` makes, under the type's schema.
    let raw = tasks_a
        .get(&index)
        .await
        .expect("get")
        .expect("held at once");
    assert_eq!(raw.schema(), "com.acme.Task#v1");
    assert_eq!(
        raw.payload(),
        &entry::to_value(&task("index", 3)).expect("a payload")
    );
    assert_eq!(
        raw.payload(),
        &cbor_map! { "topic" => "index", "priority" => 3 }
    );
    assert_eq!(raw.decode::<Task>(), Ok(task("index", 3)));
    assert!(matches!(
        raw.decode::<Report>(),
        Err(EntryError::WrongSchema { .. })
    ));

    let all = tasks_a
        .read_all_typed::<Task>(&Template::of::<Task>(), 10)
        .await
        .expect("read_all_typed");
    assert_eq!(topics(&all), ["index", "crawl", "sleep"], "in write order");
    let urgent = Template::of::<Task>()
        .where_clause("priority>=3")
        .expect("a clause");
    let found = tasks_a
        .read_all_typed::<Task>(&urgent, 10)
        .await
        .expect("read_all_typed");
    assert_eq!(topics(&found), ["index", "crawl"]);
    let found = tasks_a
        .read_all_typed::<Task>(&urgent, 1)
        .await
        .expect("read_all_typed");
    assert_eq!(topics(&found), ["index"], "the limit");
    assert!(
        tasks_a
            .read_all_typed::<Task>(&urgent, 0)
            .await
            .expect("read_all_typed")
            .is_empty()
    );

    let seen: TypedView<Task> = tasks_b
        .read_typed(&urgent.clone().tag_eq("region", "eu"), PATIENCE)
        .await
        .expect("read_typed")
        .expect("B reads A's task through the seed");
    assert_eq!(seen.entry_id(), &index);
    assert_eq!(seen.value(), &task("index", 3));
    assert_eq!(seen.view().tag("region"), Some("eu"));
    assert_eq!(seen.view().issuer(), format!("{}/rust", a.peer().peer_id()));
    let (view, value) = seen.clone().into_parts();
    assert_eq!((view.entry_id(), &value), (&index, &task("index", 3)));
    assert_eq!(
        tasks_b.get_typed::<Task>(&index).await.expect("get_typed"),
        Some(seen.clone())
    );
    assert_eq!(
        tasks_b
            .get_typed::<Task>(&EntryId::new("no-such-entry"))
            .await
            .expect("get_typed"),
        None
    );

    let taken = tasks_b
        .take_typed::<Task>(&on_topic("crawl"), lease("30s"), PATIENCE)
        .await
        .expect("take_typed")
        .expect("B takes the crawl task");
    assert_eq!(taken.value(), &task("crawl", 5));
    assert_eq!(
        taken.entry().payload(),
        &cbor_map! { "topic" => "crawl", "priority" => 5 }
    );
    let holder = taken.taken().holder().to_owned();
    let crawl = taken.entry_id().clone();

    // A result with no payload form is refused with the take still held.
    let refused = taken
        .complete_with(
            &HugeReport { count: u128::MAX },
            Lease::DEFAULT_RESULT,
            Map::new(),
        )
        .await;
    assert!(
        matches!(refused, Err(SpaceError::Entry(EntryError::Encode { .. }))),
        "{refused:?}"
    );
    let still = tasks_b.get(&crawl).await.expect("get").expect("held");
    assert!(!still.completed(), "nothing committed");
    assert_eq!(still.holder(), Some(holder.as_str()));

    let result_id = taken
        .complete_with(
            &report("crawl"),
            lease("1h"),
            tags(&[("for", crawl.as_str())]),
        )
        .await
        .expect("complete_with");
    let written = tasks_b
        .get_typed::<Report>(&result_id)
        .await
        .expect("get_typed")
        .expect("the result");
    assert_eq!(written.value(), &report("crawl"));
    assert_eq!(
        written.view().issuer(),
        holder,
        "the taker writes the result"
    );
    assert_eq!(
        written.view().payload(),
        &cbor_map! { "topic" => "crawl", "summary" => "done by rust", "workedBy" => "typed" },
        "the serde renames reach the wire"
    );
    let wrong = tasks_b.get_typed::<Task>(&result_id).await;
    assert!(
        matches!(
            wrong,
            Err(SpaceError::Entry(EntryError::WrongSchema { .. }))
        ),
        "{wrong:?}"
    );

    let read = tasks_a
        .read_typed::<Report>(
            &Template::of::<Report>().tag_eq("for", crawl.as_str()),
            PATIENCE,
        )
        .await
        .expect("read_typed")
        .expect("A reads the typed result");
    assert_eq!(read.entry_id(), &result_id);
    assert_eq!(read.into_value(), report("crawl"));
    wait_for("A to fold the completion", async || {
        tasks_a
            .get(&crawl)
            .await
            .ok()
            .flatten()
            .is_some_and(|view| view.completed())
    })
    .await;
    let twice = taken
        .complete_with(&report("crawl"), Lease::DEFAULT_RESULT, Map::new())
        .await;
    assert!(matches!(twice, Err(SpaceError::NotHeld(_))), "{twice:?}");
    let left = tasks_a
        .read_all_typed::<Task>(&Template::of::<Task>(), 10)
        .await
        .expect("read_all_typed");
    assert_eq!(
        topics(&left),
        ["index", "sleep"],
        "the completed task is gone"
    );
    a.close().await.expect("close");
    b.close().await.expect("close");
}

// ------------------------------------------------------------------------------- refusals

/// Every typed verb refuses a template of another schema than its type's before it reads or
/// claims anything, and a typed write of a value with no payload form writes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typed_verbs_refuse_another_schema_and_unwritable_values() {
    let net = Net::new();
    let a = net.member().await;
    let tasks = a.space(SPACE);
    tasks
        .write(&task("index", 3), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    let reports = Template::of::<Report>();

    assert!(wrong_schema(
        &tasks.read_all_typed::<Task>(&reports, 10).await
    ));
    assert!(wrong_schema(
        &tasks.read_typed::<Task>(&reports, Duration::ZERO).await
    ));
    assert!(wrong_schema(
        &tasks
            .take_typed::<Task>(&reports, Lease::DEFAULT_TAKE, Duration::ZERO)
            .await
    ));
    assert!(wrong_schema(&tasks.watch_typed::<Task>(&reports).await));
    assert!(wrong_schema(
        &tasks
            .notify_typed::<Task, _>(&reports, Lease::DEFAULT_NOTIFY, |_| {})
            .await
    ));

    let unwritable = Unwritable {
        topic: "routes".to_owned(),
        by_route: BTreeMap::from([(vec![1, 2], 3)]),
    };
    let refused = tasks
        .write(&unwritable, Lease::DEFAULT_WRITE, Map::new())
        .await;
    match refused {
        Err(SpaceError::Entry(EntryError::Encode { path, .. })) => {
            assert!(path.starts_with("$.by_route"), "{path}");
        }
        other => panic!("expected an encode refusal, got {other:?}"),
    }
    let refused = tasks
        .write(
            &HugeReport { count: u128::MAX },
            Lease::DEFAULT_WRITE,
            Map::new(),
        )
        .await;
    assert!(
        matches!(refused, Err(SpaceError::Entry(EntryError::Encode { .. }))),
        "{refused:?}"
    );
    let all = tasks
        .read_all(&Template::of::<Task>(), 10)
        .await
        .expect("read_all");
    assert_eq!(all.len(), 1, "nothing more was written");
    assert!(
        tasks
            .read_all(&Template::of::<Report>(), 10)
            .await
            .expect("read_all")
            .is_empty()
    );
    a.close().await.expect("close");
}

// ------------------------------------------------------------------------------- foreign shapes

/// Entries of the schema whose payload does not decode as the type are invisible to the typed
/// reads and takes (the untyped verbs still see them): `read_all_typed` and `read_typed` reach
/// past them for the ones that do decode, a typed take never claims them, and `get_typed` says
/// why one does not decode.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typed_reads_and_takes_pass_over_entries_that_do_not_decode() {
    let net = Net::new();
    let a = net.member().await;
    let b = net.member().await;
    let tasks_a = a.space(SPACE);
    let tasks_b = b.space(SPACE).with_settle(SETTLE);
    let schema = Task::SCHEMA;

    let mut foreign = Vec::new();
    for i in 0..5 {
        let id = tasks_a
            .write_value(
                schema,
                malformed(&format!("bad{i}")),
                Lease::DEFAULT_WRITE,
                Map::new(),
            )
            .await
            .expect("write a foreign shape");
        foreign.push(id);
    }
    let good_one = tasks_a
        .write(&task("good-one", 1), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    let good_two = tasks_a
        .write(&task("good-two", 2), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");

    let untyped = tasks_a
        .read_all(&Template::of::<Task>(), 100)
        .await
        .expect("read_all");
    assert_eq!(untyped.len(), 7, "the untyped read sees every entry");
    // Five foreign entries come first in fold order: a limit of two reaches past them.
    let typed = tasks_a
        .read_all_typed::<Task>(&Template::of::<Task>(), 2)
        .await
        .expect("read_all_typed");
    assert_eq!(topics(&typed), ["good-one", "good-two"]);
    let typed = tasks_a
        .read_all_typed::<Task>(&Template::of::<Task>(), 100)
        .await
        .expect("read_all_typed");
    assert_eq!(topics(&typed), ["good-one", "good-two"]);
    let first = tasks_a
        .read_typed::<Task>(&Template::of::<Task>(), Duration::ZERO)
        .await
        .expect("read_typed")
        .expect("found at once");
    assert_eq!(first.entry_id(), &good_one);
    let why = tasks_a.get_typed::<Task>(&foreign[0]).await;
    match why {
        Err(SpaceError::Entry(EntryError::Decode { path, .. })) => {
            assert_eq!(path, "$.priority");
        }
        other => panic!("expected a decode refusal, got {other:?}"),
    }

    // B takes both good tasks typed, never claiming a foreign one.
    tasks_b
        .read(&on_topic("good-two"), PATIENCE)
        .await
        .expect("read")
        .expect("B holds the entries");
    wait_for("B to hold all seven", async || {
        tasks_b
            .read_all(&Template::of::<Task>(), 100)
            .await
            .is_ok_and(|all| all.len() == 7)
    })
    .await;
    let mut took = Vec::new();
    for _ in 0..2 {
        let taken = tasks_b
            .take_typed::<Task>(&Template::of::<Task>(), lease("30s"), PATIENCE)
            .await
            .expect("take_typed")
            .expect("B takes a good task");
        took.push(taken.entry_id().clone());
        taken
            .complete(None, Lease::DEFAULT_RESULT, Map::new())
            .await
            .expect("complete");
    }
    took.sort();
    let mut good = vec![good_one, good_two];
    good.sort();
    assert_eq!(
        took, good,
        "both good tasks, in whatever order B folded them"
    );
    let none = tasks_b
        .take_typed::<Task>(
            &Template::of::<Task>(),
            lease("30s"),
            Duration::from_millis(300),
        )
        .await
        .expect("take_typed");
    assert!(none.is_none(), "only foreign shapes are left");
    for id in &foreign {
        let view = tasks_b.get(id).await.expect("get").expect("held");
        assert_eq!(view.holder(), None, "a foreign shape is never claimed");
        assert!(!view.completed());
    }
    a.close().await.expect("close");
    b.close().await.expect("close");
}

// ------------------------------------------------------------------------------- watches

/// A typed watch hears the transitions of the entries that decode, decoded, and counts the
/// events it passes over; it is also a `Stream`. A typed subscription hears the same.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typed_watches_and_subscriptions_decode_their_events() {
    let net = Net::new();
    let a = net.member().await;
    let b = net.member().await;
    let tasks_a = a.space(SPACE);
    let tasks_b = b.space(SPACE).with_settle(SETTLE);
    let schema = Task::SCHEMA;

    let mut events = tasks_a
        .watch_typed::<Task>(&Template::of::<Task>())
        .await
        .expect("watch_typed");
    let heard: Arc<Mutex<Vec<(EventKind, Task)>>> = Arc::default();
    let sink = Arc::clone(&heard);
    let subscription = tasks_a
        .notify_typed(
            &Template::of::<Task>(),
            Lease::DEFAULT_NOTIFY,
            move |event: TypedEvent<Task>| {
                if let Ok(mut heard) = sink.lock() {
                    heard.push((event.kind, event.entry.into_value()));
                }
            },
        )
        .await
        .expect("notify_typed");

    tasks_a
        .write_value(schema, malformed("bad"), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write a foreign shape");
    let id = tasks_a
        .write(&task("watched", 4), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    let written = next_event(&mut events).await;
    assert_eq!(written.kind, EventKind::Written);
    assert_eq!(written.entry.entry_id(), &id);
    assert_eq!(written.entry.value(), &task("watched", 4));
    assert_eq!(events.skipped(), 1, "the foreign shape was passed over");
    assert_eq!(events.dropped(), 0);

    let taken = tasks_b
        .take_typed::<Task>(&on_topic("watched"), lease("30s"), PATIENCE)
        .await
        .expect("take_typed")
        .expect("B takes it");
    taken
        .complete_with(&report("watched"), Lease::DEFAULT_RESULT, Map::new())
        .await
        .expect("complete_with");

    // The rest through the `Stream` implementation.
    let mut kinds = Vec::new();
    for _ in 0..2 {
        let event = tokio::time::timeout(
            PATIENCE,
            std::future::poll_fn(|cx| Pin::new(&mut events).poll_next(cx)),
        )
        .await
        .expect("an event in time")
        .expect("the watch is open");
        assert_eq!(event.entry.value(), &task("watched", 4));
        kinds.push(event.kind);
    }
    assert_eq!(kinds, [EventKind::Taken, EventKind::Completed]);
    assert!(events.try_next().is_none());

    wait_for("the subscription to hear all three", async || {
        heard.lock().map(|heard| heard.len()).unwrap_or_default() >= 3
    })
    .await;
    assert_eq!(
        heard.lock().map(|heard| heard.clone()).unwrap_or_default(),
        [
            (EventKind::Written, task("watched", 4)),
            (EventKind::Taken, task("watched", 4)),
            (EventKind::Completed, task("watched", 4)),
        ]
    );
    subscription.close();
    events.close();
    assert!(!events.is_open());
    assert_eq!(
        tokio::time::timeout(PATIENCE, events.next()).await.ok(),
        Some(None)
    );
    a.close().await.expect("close");
    b.close().await.expect("close");
}

// ------------------------------------------------------------------------------- blocking

/// The typed verbs of the blocking facade: a typed watch, a typed write, a typed read on another
/// member, a typed take renewed and completed with a typed result, all from plain threads.
#[test]
fn blocking_typed_round_trip() {
    let seed_runtime = tokio::runtime::Runtime::new().expect("a runtime for the seed");
    let network = MemoryNetwork::new();
    let seed = seed_runtime
        .block_on(async { FakeSeed::start_relay(&network, SEED, &group_id(), system()) });
    let a = blocking::Fleet::join(config(&network, fresh(), group(), &[SEED], system()))
        .expect("A joins");
    let b = blocking::Fleet::join(config(&network, fresh(), group(), &[SEED], system()))
        .expect("B joins");
    let tasks_a = a.space(SPACE);
    let tasks_b = b.space(SPACE).with_settle(SETTLE);

    let mut events = tasks_a
        .watch_typed::<Task>(&Template::of::<Task>())
        .expect("watch_typed");
    let id = tasks_a
        .write(&task("blocking", 2), Lease::DEFAULT_WRITE, Map::new())
        .expect("write");
    let written = events
        .recv_timeout(PATIENCE)
        .expect("recv")
        .expect("an event");
    assert_eq!(
        (
            written.kind,
            written.entry.entry_id(),
            written.entry.value()
        ),
        (EventKind::Written, &id, &task("blocking", 2))
    );
    assert_eq!(
        tasks_a
            .read_all_typed::<Task>(&Template::of::<Task>(), 10)
            .expect("read_all_typed")
            .len(),
        1
    );

    let seen = tasks_b
        .read_typed::<Task>(&on_topic("blocking"), PATIENCE)
        .expect("read_typed")
        .expect("B reads it");
    assert_eq!(seen.value(), &task("blocking", 2));
    assert_eq!(
        tasks_b
            .get_typed::<Task>(&id)
            .expect("get_typed")
            .map(TypedView::into_value),
        Some(task("blocking", 2))
    );
    assert!(wrong_schema(
        &tasks_b.read_typed::<Task>(&Template::of::<Report>(), Duration::ZERO)
    ));
    let mut taken = tasks_b
        .take_typed::<Task>(&on_topic("blocking"), lease("2s"), PATIENCE)
        .expect("take_typed")
        .expect("B takes it");
    assert_eq!(taken.value(), &task("blocking", 2));
    let first_expiry = taken.taken().expires_at_millis();
    let renewed = taken.renew(lease("30s")).expect("renew");
    assert!(renewed > first_expiry);
    let result = taken
        .complete_with(&report("blocking"), Lease::DEFAULT_RESULT, Map::new())
        .expect("complete_with");
    let kinds: Vec<EventKind> = (0..2)
        .map(|_| {
            events
                .recv_timeout(PATIENCE)
                .expect("recv")
                .expect("an event")
                .kind
        })
        .collect();
    assert_eq!(kinds, [EventKind::Taken, EventKind::Completed]);
    let read = tasks_a
        .read_typed::<Report>(&Template::of::<Report>(), PATIENCE)
        .expect("read_typed")
        .expect("A reads the result");
    assert_eq!(read.entry_id(), &result);
    assert_eq!(read.value(), &report("blocking"));
    assert_eq!(events.skipped(), 0);

    a.close().expect("close");
    b.close().expect("close");
    assert!(
        events.recv_timeout(PATIENCE).expect("recv").is_none(),
        "the watch ends"
    );
    drop(seed);
}
