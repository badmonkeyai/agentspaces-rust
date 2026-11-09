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

//! The Space API ([`agentspaces::space`], [`agentspaces::blocking`]) over the in-memory network:
//! two or three Rust peers joined through one relaying fake seed (`support::FakeSeed::
//! start_relay`), which forwards every rumor to the other members and answers their pulls.
//!
//! Writes, reads, and templates; the LEASE_RACE take among racing peers (one winner per entry,
//! no double completion), its lapse and renewal, the completion with a same-space result and its
//! atomicity; the writer's renewal and cancellation; the watch transitions in order and a slow
//! watcher; agent-signed entries, claims, and completions and the two-key rule; the live
//! re-check of a take's stale candidates; and the blocking facade.

mod support;

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentspaces::blocking;
use agentspaces::clock::{Clock, SharedClock, SystemClock};
use agentspaces::group::GroupSpec;
use agentspaces::peer::{Peer, PeerError, PeerEvent};
use agentspaces::space::{
    Attestation, CloseReason, EntryId, EntryView, EventKind, Fleet, Lease, Space, SpaceError,
    SpaceEvent, SpaceEvents, Template,
};
use agentspaces::transport::memory::MemoryNetwork;
use agentspaces::wire::bodies::{self, KIND_DIGEST, KIND_RUMOR, RUMOR_HOPS};
use agentspaces::wire::cbor::{Map, Value};
use agentspaces::wire::cbor_map;
use agentspaces::wire::filters::Matcher;
use agentspaces::wire::fold::{FoldOutcome, Refusal};
use agentspaces::wire::identity::Identity;
use agentspaces::wire::ids;
use agentspaces::wire::records;
use support::{FakeSeed, PATIENCE, Received, config};
use tokio::time::Instant;

const SEED: &str = "127.0.0.1:7800";
const FOUNDING: &str = "agentspaces-rust-space-verbs";
const SPACE: &str = "tasks";
const TASK: &str = "com.acme.Task#v1";
const RESULT: &str = "com.acme.Result#v1";
/// The settle window of the racing takes here (a Java space's 200 ms).
const SETTLE: Duration = Duration::from_millis(200);

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

fn tags(pairs: &[(&str, &str)]) -> Map {
    pairs.iter().copied().collect()
}

fn lease(text: &str) -> Lease {
    Lease::parse(text).expect("a lease")
}

fn topic(view: &EntryView) -> &str {
    view.payload()
        .get("topic")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

fn topics(views: &[EntryView]) -> Vec<&str> {
    views.iter().map(topic).collect()
}

fn on_topic(name: &str) -> Template {
    Template::new(TASK).where_("topic", Matcher::Eq(name.into()))
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

/// The kind and entry id of the next event.
async fn next_kind(events: &mut SpaceEvents) -> (EventKind, EntryId) {
    let event = next_event(events).await;
    (event.kind, event.entry.entry_id().clone())
}

/// Whether a received frame is a RUMOR whose item id starts with `prefix`.
fn rumor_item_starts(received: &Received, prefix: &str) -> bool {
    received
        .rumor()
        .is_some_and(|rumor| rumor.item_id.starts_with(prefix))
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

    /// A member joined through the seed; the n-th member to join is the seed's link n.
    async fn member(&self, identity: Identity) -> Fleet {
        let peer = Peer::start(config(&self.network, identity, group(), &[SEED], system()))
            .await
            .expect("the peer starts");
        Fleet::from_peer(peer)
    }
}

// ------------------------------------------------------------------------------- reads

/// A write reads back at once on its writer and, through the seed, on another member, with the
/// field matchers, the filter grammar, tags, and limits narrowing `read_all`; a read that finds
/// nothing waits its timeout pulling at most once per settle window, and wakes on a fold.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn write_then_read_and_read_all_with_filters_and_tags() {
    let net = Net::new();
    let a = net.member(fresh()).await;
    let b = net.member(fresh()).await;
    let tasks_a = a.space(SPACE);
    let tasks_b = b.space(SPACE);

    let index = tasks_a
        .write_value(
            TASK,
            task("index", 3),
            lease("10m"),
            tags(&[("region", "eu")]),
        )
        .await
        .expect("write");
    tasks_a
        .write_value(
            TASK,
            task("crawl", 5),
            Lease::DEFAULT_WRITE,
            tags(&[("region", "us")]),
        )
        .await
        .expect("write");
    tasks_a
        .write_value(
            TASK,
            task("sleep", 1),
            Lease::DEFAULT_WRITE,
            tags(&[("region", "eu")]),
        )
        .await
        .expect("write");
    tasks_a
        .write_value(
            RESULT,
            cbor_map! { "topic" => "index" },
            Lease::DEFAULT_WRITE,
            Map::new(),
        )
        .await
        .expect("write a result");

    let all = tasks_a
        .read_all(&Template::new(TASK), 10)
        .await
        .expect("read_all");
    assert_eq!(topics(&all), ["index", "crawl", "sleep"], "in write order");
    let urgent = Template::new(TASK)
        .where_clause("priority>=3")
        .expect("a clause");
    let found = tasks_a.read_all(&urgent, 10).await.expect("read_all");
    assert_eq!(topics(&found), ["index", "crawl"]);
    let eu_urgent = urgent.clone().tag_eq("region", "eu");
    let found = tasks_a.read_all(&eu_urgent, 10).await.expect("read_all");
    assert_eq!(topics(&found), ["index"]);
    let chosen =
        Template::new(TASK).where_("topic", Matcher::In(vec!["sleep".into(), "crawl".into()]));
    let found = tasks_a.read_all(&chosen, 10).await.expect("read_all");
    assert_eq!(topics(&found), ["crawl", "sleep"]);
    let found = tasks_a
        .read_all(&Template::new(TASK), 2)
        .await
        .expect("read_all");
    assert_eq!(found.len(), 2, "the limit");
    let found = tasks_a
        .read_all(&Template::new(RESULT), 10)
        .await
        .expect("read_all");
    assert_eq!(topics(&found), ["index"], "the schema selects");

    let view = tasks_a
        .read(&eu_urgent, Duration::ZERO)
        .await
        .expect("read")
        .expect("found at once");
    assert_eq!(view.entry_id(), &index);
    assert_eq!(view.schema(), TASK);
    assert_eq!(view.issuer(), format!("{}/rust", a.peer().peer_id()));
    assert_eq!(view.attestation(), Attestation::PeerAsserted);
    assert_eq!(view.tag("region"), Some("eu"));
    assert_eq!(
        view.payload().get("priority").and_then(Value::as_i64),
        Some(3)
    );
    assert!(!view.completed());
    assert_eq!(view.holder(), None);
    let now = SystemClock.now_ms();
    assert!(view.expires_at_millis() > now + 590_000 && view.expires_at_millis() <= now + 600_000);

    let seen = tasks_b
        .read(&eu_urgent, PATIENCE)
        .await
        .expect("read")
        .expect("B reads A's task through the seed");
    assert_eq!(seen.entry_id(), &index);
    assert_eq!(seen.issuer(), view.issuer());
    assert_eq!(seen.payload(), view.payload());
    assert_eq!(b.space(SPACE).get(&index).await.expect("get"), Some(seen));

    // A read that finds nothing waits out its timeout without polling: B pulls the space at
    // most once per settle window (600 ms by default) while it waits.
    let digests = |seed: &FakeSeed| {
        seed.received()
            .iter()
            .filter(|frame| frame.link == 1 && frame.kind() == KIND_DIGEST)
            .filter(|frame| {
                bodies::parse_digest(frame.body())
                    .is_some_and(|digests| digests.contains_key("space:tasks"))
            })
            .count()
    };
    let before = digests(&net.seed);
    let start = Instant::now();
    let nothing = Template::new(TASK)
        .where_clause("priority>9")
        .expect("a clause");
    let none = tasks_b
        .read(&nothing, Duration::from_millis(1500))
        .await
        .expect("read");
    assert!(none.is_none());
    assert!(start.elapsed() >= Duration::from_millis(1500));
    let pulls = digests(&net.seed) - before;
    assert!(
        pulls <= 3,
        "{pulls} pulls in 1.5 s with a 600 ms settle window"
    );

    // A waiting read wakes on the fold of a matching write.
    let waiting = tokio::spawn({
        let tasks_b = tasks_b.clone();
        async move { tasks_b.read(&on_topic("late"), PATIENCE).await }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let start = Instant::now();
    let late = tasks_a
        .write_value(TASK, task("late", 2), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    let woke = waiting.await.expect("the reader").expect("read");
    assert_eq!(woke.map(|view| view.entry_id().clone()), Some(late));
    assert!(
        start.elapsed() < Duration::from_millis(500),
        "{:?}",
        start.elapsed()
    );
    a.close().await.expect("close");
    b.close().await.expect("close");
}

// ------------------------------------------------------------------------------- takes

/// Three peers race to take and complete N entries through one seed: every entry is taken and
/// completed exactly once, and every peer folds every completion.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn take_wins_once_among_three_racing_peers() {
    const N: usize = 12;
    let net = Net::new();
    let mut fleets = Vec::new();
    for _ in 0..3 {
        fleets.push(net.member(fresh()).await);
    }
    let spaces: Vec<Space> = fleets
        .iter()
        .map(|fleet| fleet.space(SPACE).with_settle(SETTLE))
        .collect();
    for space in &spaces {
        space.pull().await.expect("pull");
    }
    let mut written = BTreeSet::new();
    for i in 0..N {
        let id = spaces[0]
            .write_value(
                TASK,
                task(&format!("t{i}"), 1),
                Lease::DEFAULT_WRITE,
                Map::new(),
            )
            .await
            .expect("write");
        written.insert(id);
    }
    for space in &spaces {
        wait_for("every racer to hold every entry", async || {
            space
                .read_all(&Template::new(TASK), 100)
                .await
                .is_ok_and(|all| all.len() == N)
        })
        .await;
    }

    let mut racers = Vec::new();
    for space in spaces.clone() {
        racers.push(tokio::spawn(async move {
            let mut done = Vec::new();
            while let Some(taken) = space
                .take(&Template::new(TASK), lease("30s"), Duration::from_secs(2))
                .await?
            {
                taken
                    .complete(None, Lease::DEFAULT_RESULT, Map::new())
                    .await?;
                done.push(taken.entry_id().clone());
            }
            Ok::<_, SpaceError>(done)
        }));
    }
    let mut completed = Vec::new();
    let mut per_racer = Vec::new();
    for racer in racers {
        let done = racer.await.expect("the racer").expect("its takes");
        per_racer.push(done.len());
        completed.extend(done);
    }
    assert_eq!(
        completed.len(),
        N,
        "each entry completed once: {completed:?}"
    );
    let unique: BTreeSet<EntryId> = completed.into_iter().collect();
    assert_eq!(unique, written);
    // They raced: more claims were published than entries taken (the losers' claims).
    let claims = net
        .seed
        .received()
        .iter()
        .filter(|frame| rumor_item_starts(frame, "c:"))
        .count();
    assert!(
        claims > N,
        "{claims} claims for {N} entries ({per_racer:?} per racer)"
    );

    for space in &spaces {
        wait_for("every completion folded everywhere", async || {
            let mut all = true;
            for id in &written {
                let done = space.get(id).await.ok().flatten();
                all &= done.is_some_and(|view| view.completed() && view.holder().is_some());
            }
            all
        })
        .await;
    }
    for fleet in &fleets {
        fleet.close().await.expect("close");
    }
}

/// A taker that never completes lets its entry reappear once the hold lapses: another member
/// cannot take it while held and takes it (at the next epoch) after.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_taker_that_never_completes_lets_the_entry_reappear() {
    let net = Net::new();
    let a = net.member(fresh()).await;
    let b = net.member(fresh()).await;
    let tasks_a = a.space(SPACE).with_settle(SETTLE);
    let tasks_b = b.space(SPACE).with_settle(SETTLE);
    let id = tasks_a
        .write_value(TASK, task("orphan", 1), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    tasks_b
        .read(&Template::new(TASK), PATIENCE)
        .await
        .expect("read")
        .expect("B holds the entry");

    let taken = tasks_b
        .take(&Template::new(TASK), lease("1500ms"), PATIENCE)
        .await
        .expect("take")
        .expect("B takes it");
    assert_eq!(taken.entry_id(), &id);
    assert_eq!(taken.epoch(), 1);
    let lapses_at = taken.expires_at_millis();
    taken.release();

    wait_for("A to see B's hold", async || {
        tasks_a
            .get(&id)
            .await
            .ok()
            .flatten()
            .is_some_and(|view| view.holder().is_some())
    })
    .await;
    let held = tasks_a
        .take(
            &Template::new(TASK),
            lease("30s"),
            Duration::from_millis(100),
        )
        .await
        .expect("take");
    assert!(held.is_none(), "a held entry is not takeable");

    let again = tasks_a
        .take(&Template::new(TASK), lease("30s"), PATIENCE)
        .await
        .expect("take")
        .expect("A takes it once the hold lapsed");
    assert!(SystemClock.now_ms() >= lapses_at, "not before the lapse");
    assert_eq!(again.entry_id(), &id);
    assert_eq!(again.epoch(), 2, "the next epoch");
    assert_eq!(again.holder(), format!("{}/rust", a.peer().peer_id()));
    again
        .complete(None, Lease::DEFAULT_RESULT, Map::new())
        .await
        .expect("complete");
    a.close().await.expect("close");
    b.close().await.expect("close");
}

/// A renewed take keeps its epoch and stamp with a later expiry, which every member's lattice
/// prefers, so it stays held past its first lease; a lapsed take cannot be renewed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_renewed_take_stays_held() {
    let net = Net::new();
    let a = net.member(fresh()).await;
    let b = net.member(fresh()).await;
    let tasks_a = a.space(SPACE).with_settle(SETTLE);
    let tasks_b = b.space(SPACE).with_settle(SETTLE);
    let id = tasks_a
        .write_value(TASK, task("long", 1), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    tasks_b
        .read(&Template::new(TASK), PATIENCE)
        .await
        .expect("read")
        .expect("B holds the entry");
    let mut taken = tasks_b
        .take(&Template::new(TASK), lease("1500ms"), PATIENCE)
        .await
        .expect("take")
        .expect("B takes it");
    let first = taken.expires_at_millis();

    let claim_at_a = async || {
        a.peer()
            .space_claims(SPACE)
            .await
            .into_iter()
            .find(|(entry, _)| entry == id.as_str())
            .and_then(|(_, signed)| signed.get("claim").and_then(Value::as_map).cloned())
    };
    wait_for("A to fold B's claim", async || claim_at_a().await.is_some()).await;
    let original = claim_at_a().await.expect("the claim");

    let renewed = taken.renew(lease("5s")).await.expect("renew");
    assert!(renewed > first);
    assert_eq!(taken.expires_at_millis(), renewed);
    wait_for("A to fold the renewal", async || {
        claim_at_a().await.is_some_and(|claim| {
            claim.get("expiresAtMillis").and_then(Value::as_i64) == Some(renewed)
        })
    })
    .await;
    let current = claim_at_a().await.expect("the claim");
    for field in ["epoch", "stamp", "holder", "bid"] {
        assert_eq!(current.get(field), original.get(field), "{field} is kept");
    }

    tokio::time::sleep(Duration::from_millis(1700)).await;
    let held = tasks_a
        .take(
            &Template::new(TASK),
            lease("30s"),
            Duration::from_millis(100),
        )
        .await
        .expect("take");
    assert!(held.is_none(), "still held past the first lease");
    taken
        .complete(None, Lease::DEFAULT_RESULT, Map::new())
        .await
        .expect("still held, so it completes");
    let lapsed = taken.renew(lease("5s")).await;
    assert!(matches!(lapsed, Err(SpaceError::NotHeld(_))), "{lapsed:?}");
    a.close().await.expect("close");
    b.close().await.expect("close");
}

/// A completion with a result writes the result into the same space with the completion; a
/// result that cannot be written fails the completion before anything commits, and the take is
/// still held; a second completion is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn complete_with_a_same_space_result() {
    let net = Net::new();
    let a = net.member(fresh()).await;
    let b = net.member(fresh()).await;
    let tasks_a = a.space(SPACE);
    let tasks_b = b.space(SPACE).with_settle(SETTLE);
    let id = tasks_a
        .write_value(TASK, task("summarize", 2), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    tasks_b
        .read(&Template::new(TASK), PATIENCE)
        .await
        .expect("read")
        .expect("B holds the entry");
    let taken = tasks_b
        .take(&Template::new(TASK), lease("30s"), PATIENCE)
        .await
        .expect("take")
        .expect("B takes it");
    assert_eq!(taken.entry().payload(), &task("summarize", 2));
    let holder = taken.holder().to_owned();

    // A result no frame can carry: refused before the completion commits.
    let huge = Value::Bytes(vec![7; 9 * 1024 * 1024]);
    let refused = taken
        .complete(Some((RESULT, huge)), Lease::DEFAULT_RESULT, Map::new())
        .await;
    assert!(
        matches!(
            refused,
            Err(SpaceError::Peer(PeerError::InvalidArgument(_)))
        ),
        "{refused:?}"
    );
    let still = tasks_b.get(&id).await.expect("get").expect("held");
    assert!(!still.completed(), "nothing committed");
    assert_eq!(still.holder(), Some(holder.as_str()));

    let result = cbor_map! { "topic" => "summarize", "summary" => "done by rust" };
    let result_id = taken
        .complete(
            Some((RESULT, result.clone())),
            lease("1h"),
            tags(&[("for", id.as_str())]),
        )
        .await
        .expect("complete")
        .expect("a result id");
    let done = tasks_b.get(&id).await.expect("get").expect("held");
    assert!(done.completed());
    let written = tasks_b
        .get(&result_id)
        .await
        .expect("get")
        .expect("the result");
    assert_eq!(written.payload(), &result);
    assert_eq!(written.issuer(), holder, "the taker writes the result");

    wait_for("A to fold the completion", async || {
        tasks_a
            .get(&id)
            .await
            .ok()
            .flatten()
            .is_some_and(|view| view.completed())
    })
    .await;
    let at_a = tasks_a.get(&id).await.expect("get").expect("held");
    assert_eq!(at_a.holder(), Some(holder.as_str()), "the completer");
    let read = tasks_a
        .read(&Template::new(RESULT).tag_eq("for", id.as_str()), PATIENCE)
        .await
        .expect("read")
        .expect("A reads the result");
    assert_eq!(read.entry_id(), &result_id);
    assert_eq!(read.payload(), &result);

    let twice = taken
        .complete(None, Lease::DEFAULT_RESULT, Map::new())
        .await;
    assert!(matches!(twice, Err(SpaceError::NotHeld(_))), "{twice:?}");
    let gone = tasks_a
        .take(
            &Template::new(TASK),
            lease("30s"),
            Duration::from_millis(100),
        )
        .await
        .expect("take");
    assert!(gone.is_none(), "a completed entry is not takeable");
    a.close().await.expect("close");
    b.close().await.expect("close");
}

// ------------------------------------------------------------------------------- the writer's

/// The writer renews and cancels its own entries, and only its own: a renewal outlives the first
/// lease on every member, a cancellation removes the entry everywhere, and a lapsed or cancelled
/// entry cannot be renewed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn renew_and_cancel_of_own_writes() {
    let net = Net::new();
    let a = net.member(fresh()).await;
    let b = net.member(fresh()).await;
    let tasks_a = a.space(SPACE);
    let tasks_b = b.space(SPACE);
    let id = tasks_a
        .write_value(TASK, task("renewed", 1), lease("1500ms"), Map::new())
        .await
        .expect("write");
    tasks_b
        .read(&Template::new(TASK), PATIENCE)
        .await
        .expect("read")
        .expect("B holds the entry");

    tasks_a.renew_write(&id, lease("10m")).await.expect("renew");
    wait_for("B to fold the renewal", async || {
        tasks_b
            .get(&id)
            .await
            .ok()
            .flatten()
            .is_some_and(|view| view.expires_at_millis() > SystemClock.now_ms() + 60_000)
    })
    .await;
    tokio::time::sleep(Duration::from_millis(1700)).await;
    for space in [&tasks_a, &tasks_b] {
        let live = space
            .read_all(&Template::new(TASK), 10)
            .await
            .expect("read_all");
        assert_eq!(topics(&live), ["renewed"], "alive past its first lease");
    }

    let foreign = tasks_b.renew_write(&id, lease("10m")).await;
    assert!(
        matches!(foreign, Err(SpaceError::NotIssuer { .. })),
        "{foreign:?}"
    );
    let foreign = tasks_b.cancel(&id).await;
    assert!(
        matches!(foreign, Err(SpaceError::NotIssuer { .. })),
        "{foreign:?}"
    );
    let unknown = tasks_a
        .renew_write(&EntryId::new("nope"), lease("1m"))
        .await;
    assert!(
        matches!(unknown, Err(SpaceError::UnknownEntry(_))),
        "{unknown:?}"
    );

    tasks_a.cancel(&id).await.expect("cancel");
    assert!(
        tasks_a
            .read_all(&Template::new(TASK), 10)
            .await
            .expect("read_all")
            .is_empty()
    );
    wait_for("B to fold the cancellation", async || {
        tasks_b
            .read_all(&Template::new(TASK), 10)
            .await
            .is_ok_and(|all| all.is_empty())
    })
    .await;
    tasks_a
        .cancel(&id)
        .await
        .expect("a cancellation is idempotent");
    let after = tasks_a.renew_write(&id, lease("1m")).await;
    assert!(
        matches!(after, Err(SpaceError::LeaseLapsed(_))),
        "{after:?}"
    );

    let short = tasks_a
        .write_value(TASK, task("short", 1), lease("300ms"), Map::new())
        .await
        .expect("write");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        tasks_a
            .read_all(&Template::new(TASK), 10)
            .await
            .expect("read_all")
            .is_empty()
    );
    let lapsed = tasks_a.renew_write(&short, lease("1m")).await;
    assert!(
        matches!(lapsed, Err(SpaceError::LeaseLapsed(_))),
        "{lapsed:?}"
    );
    a.close().await.expect("close");
    b.close().await.expect("close");
}

/// A cancelled entry is not takeable, here or on another member.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_entry_is_not_takeable() {
    let net = Net::new();
    let a = net.member(fresh()).await;
    let b = net.member(fresh()).await;
    let tasks_a = a.space(SPACE).with_settle(SETTLE);
    let tasks_b = b.space(SPACE).with_settle(SETTLE);
    let id = tasks_a
        .write_value(TASK, task("withdrawn", 1), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    tasks_b
        .read(&Template::new(TASK), PATIENCE)
        .await
        .expect("read")
        .expect("B holds the entry");
    tasks_a.cancel(&id).await.expect("cancel");
    wait_for("B to fold the cancellation", async || {
        tasks_b
            .read_all(&Template::new(TASK), 10)
            .await
            .is_ok_and(|all| all.is_empty())
    })
    .await;
    for space in [&tasks_a, &tasks_b] {
        let taken = space
            .take(
                &Template::new(TASK),
                lease("30s"),
                Duration::from_millis(500),
            )
            .await
            .expect("take");
        assert!(taken.is_none(), "a cancelled entry is not takeable");
    }
    let view = tasks_b
        .get(&id)
        .await
        .expect("get")
        .expect("still held, withdrawn");
    assert!(!view.completed());
    assert_eq!(view.holder(), None);
    let claims = net
        .seed
        .received()
        .iter()
        .filter(|frame| rumor_item_starts(frame, "c:"))
        .count();
    assert_eq!(claims, 0, "no member claimed it");
    a.close().await.expect("close");
    b.close().await.expect("close");
}

// ------------------------------------------------------------------------------- watches

/// A scripted sequence: each step's transition arrives before the next step starts, in order,
/// with the holder of a take named; a watch of another template hears only its entries.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn watch_yields_written_taken_completed_expired_reappeared_in_order() {
    let net = Net::new();
    let a = net.member(fresh()).await;
    let b = net.member(fresh()).await;
    let tasks_a = a.space(SPACE);
    let tasks_b = b.space(SPACE).with_settle(SETTLE);
    tasks_b.pull().await.expect("pull");
    let mut events = tasks_a.watch(&Template::new(TASK)).await.expect("watch");
    let mut only_two = tasks_a.watch(&on_topic("two")).await.expect("watch");

    // Written, Taken, Completed.
    let one = tasks_a
        .write_value(TASK, task("one", 1), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    assert_eq!(
        next_kind(&mut events).await,
        (EventKind::Written, one.clone())
    );
    tasks_b
        .read(&on_topic("one"), PATIENCE)
        .await
        .expect("read")
        .expect("B holds it");
    let taken = tasks_b
        .take(&on_topic("one"), lease("30s"), PATIENCE)
        .await
        .expect("take")
        .expect("B takes it");
    let event = next_event(&mut events).await;
    assert_eq!(
        (event.kind, event.entry.entry_id()),
        (EventKind::Taken, &one)
    );
    assert_eq!(event.entry.holder(), Some(taken.holder()));
    taken
        .complete(None, Lease::DEFAULT_RESULT, Map::new())
        .await
        .expect("complete");
    let event = next_event(&mut events).await;
    assert_eq!(
        (event.kind, event.entry.entry_id()),
        (EventKind::Completed, &one)
    );
    assert!(event.entry.completed());
    assert_eq!(event.entry.holder(), Some(taken.holder()));

    // Expired.
    let two = tasks_a
        .write_value(TASK, task("two", 2), lease("600ms"), Map::new())
        .await
        .expect("write");
    assert_eq!(
        next_kind(&mut events).await,
        (EventKind::Written, two.clone())
    );
    assert_eq!(
        next_kind(&mut events).await,
        (EventKind::Expired, two.clone())
    );

    // Reappeared.
    let three = tasks_a
        .write_value(TASK, task("three", 3), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    assert_eq!(
        next_kind(&mut events).await,
        (EventKind::Written, three.clone())
    );
    tasks_b
        .read(&on_topic("three"), PATIENCE)
        .await
        .expect("read")
        .expect("B holds it");
    let held = tasks_b
        .take(&on_topic("three"), lease("600ms"), PATIENCE)
        .await
        .expect("take")
        .expect("B takes it");
    held.release();
    assert_eq!(
        next_kind(&mut events).await,
        (EventKind::Taken, three.clone())
    );
    let event = next_event(&mut events).await;
    assert_eq!(
        (event.kind, event.entry.entry_id()),
        (EventKind::Reappeared, &three)
    );
    assert_eq!(event.entry.holder(), None, "nobody holds it any more");

    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(events.try_next(), None, "nothing more");
    assert_eq!(events.dropped(), 0);
    assert_eq!(
        next_kind(&mut only_two).await,
        (EventKind::Written, two.clone())
    );
    assert_eq!(next_kind(&mut only_two).await, (EventKind::Expired, two));
    assert_eq!(only_two.try_next(), None);

    a.close().await.expect("close");
    assert_eq!(
        tokio::time::timeout(PATIENCE, events.next())
            .await
            .expect("ends"),
        None,
        "the watch ends with the peer"
    );
    assert_eq!(events.close_reason(), Some(CloseReason::PeerClosed));
    b.close().await.expect("close");
}

/// A watcher that never takes its events does not slow the peer or another watcher: its queue
/// keeps the newest events up to its capacity and counts what it dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slow_watcher_does_not_stall_the_peer() {
    const WRITES: usize = 200;
    let net = Net::new();
    let a = net.member(fresh()).await;
    let tasks = a.space(SPACE);
    let mut slow = tasks
        .with_watch_capacity(8)
        .watch(&Template::new(TASK))
        .await
        .expect("watch");
    let mut fast = tasks.watch(&Template::new(TASK)).await.expect("watch");

    let start = Instant::now();
    let mut ids = Vec::new();
    for i in 0..WRITES {
        let id = tasks
            .write_value(
                TASK,
                task(&format!("w{i}"), 1),
                Lease::DEFAULT_WRITE,
                Map::new(),
            )
            .await
            .expect("write");
        ids.push(id);
    }
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "{:?}",
        start.elapsed()
    );
    let all = tasks
        .read_all(&Template::new(TASK), 1000)
        .await
        .expect("read_all");
    assert_eq!(all.len(), WRITES, "the peer kept folding");

    for id in &ids {
        assert_eq!(next_kind(&mut fast).await, (EventKind::Written, id.clone()));
    }
    assert_eq!(fast.dropped(), 0);

    assert_eq!(slow.dropped(), (WRITES - 8) as u64);
    let mut kept = Vec::new();
    while let Some(event) = slow.try_next() {
        kept.push(event.entry.entry_id().clone());
    }
    assert_eq!(kept, ids[WRITES - 8..], "the newest events are kept");
    assert!(slow.is_open());
    a.close().await.expect("close");
}

/// A payload over the inline limit travels as a block: another member's watch hears `Written`
/// once the block has arrived (the transition waits for it), with the whole payload.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_block_payload_is_told_once_its_block_arrives() {
    let net = Net::new();
    let a = net.member(fresh()).await;
    let b = net.member(fresh()).await;
    let tasks_a = a.space(SPACE);
    let tasks_b = b.space(SPACE);
    let mut events = tasks_b.watch(&Template::new(TASK)).await.expect("watch");
    tasks_a.pull().await.expect("pull");
    // Both learn the seed from its answer to their pulls, so their block traffic goes through it.
    wait_for("both members to learn the seed", async || {
        a.peer().seed_peer().await.is_some() && b.peer().seed_peer().await.is_some()
    })
    .await;

    let text = "x".repeat(100 * 1024);
    let payload = cbor_map! { "topic" => "large", "body" => text.as_str() };
    let id = tasks_a
        .write_value(TASK, payload.clone(), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    let event = next_event(&mut events).await;
    assert_eq!(
        (event.kind, event.entry.entry_id()),
        (EventKind::Written, &id)
    );
    assert_eq!(event.entry.payload(), &payload, "told with its block");
    let read = tasks_b
        .read(&on_topic("large"), PATIENCE)
        .await
        .expect("read")
        .expect("B reads it");
    assert_eq!(read.payload(), &payload);
    let reference = b
        .peer()
        .space_states(SPACE)
        .await
        .iter()
        .find_map(|state| {
            state
                .get("record")
                .and_then(|record| record.get("payloadRef"))
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .expect("a payload reference");
    assert!(reference.starts_with('z'), "a block: {reference}");
    assert_eq!(b.peer().counters().await.deferred_events_dropped, 0);
    a.close().await.expect("close");
    b.close().await.expect("close");
}

/// The leased push subscription: the handler hears the transitions until the lease lapses;
/// renewing a lapsed subscription is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn notify_delivers_until_its_lease_lapses() {
    let net = Net::new();
    let a = net.member(fresh()).await;
    let tasks = a.space(SPACE);
    let heard: Arc<Mutex<Vec<(EventKind, EntryId)>>> = Arc::default();
    let sink = Arc::clone(&heard);
    let subscription = tasks
        .notify(&Template::new(TASK), lease("800ms"), move |event| {
            if let Ok(mut heard) = sink.lock() {
                heard.push((event.kind, event.entry.entry_id().clone()));
            }
        })
        .await
        .expect("notify");
    let heard_len = || heard.lock().map(|heard| heard.len()).unwrap_or_default();

    let first = tasks
        .write_value(TASK, task("first", 1), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    wait_for("the handler to hear the write", async || heard_len() == 1).await;
    assert_eq!(
        heard.lock().map(|heard| heard.clone()).unwrap_or_default(),
        [(EventKind::Written, first)]
    );
    subscription
        .renew(lease("800ms"))
        .expect("renew while open");

    wait_for("the lease to lapse", async || {
        subscription.close_reason() == Some(CloseReason::Lapsed)
    })
    .await;
    let late = subscription.renew(lease("1m"));
    assert!(
        matches!(late, Err(SpaceError::SubscriptionClosed)),
        "{late:?}"
    );
    tasks
        .write_value(TASK, task("second", 1), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(heard_len(), 1, "nothing after the lapse");
    wait_for("the handler task to end", async || !subscription.is_open()).await;
    a.close().await.expect("close");
}

// ------------------------------------------------------------------------------- agents

/// An agent's write, claim, and completion are signed by the agent's key and fold AGENT_ATTESTED
/// on another member; a completion of the agent's take signed by its peer's key is refused (the
/// two-key rule), and the peer cannot renew or cancel its agent's entries.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_signed_writes_claims_and_completions_fold_as_agent_attested() {
    let net = Net::new();
    let a_identity = fresh();
    let b_identity = fresh();
    let a = net.member(a_identity.clone()).await;
    let b = net.member(b_identity.clone()).await;
    let now = SystemClock.now_ms();
    let alice = a_identity
        .renewing_subordinate("alice", "PT24H", None, now)
        .expect("alice");
    let bob = b_identity
        .renewing_subordinate("bob", "PT24H", None, now)
        .expect("bob");
    let tasks_a = a.space(SPACE).as_agent(alice.clone());
    let tasks_b = b.space(SPACE).with_settle(SETTLE).as_agent(bob.clone());
    assert_eq!(
        tasks_a.agent().map(|agent| agent.agent_id()),
        Some(alice.agent_id())
    );

    let attested = tasks_a
        .write_value(TASK, task("attested", 1), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write as alice");
    let seen = tasks_b
        .read(&on_topic("attested"), PATIENCE)
        .await
        .expect("read")
        .expect("B reads alice's entry");
    assert_eq!(seen.issuer(), alice.agent_id());
    assert_eq!(seen.attestation(), Attestation::AgentAttested);

    let taken = tasks_b
        .take(&on_topic("attested"), lease("30s"), PATIENCE)
        .await
        .expect("take")
        .expect("bob takes it");
    assert_eq!(taken.holder(), bob.agent_id());
    taken
        .complete(None, Lease::DEFAULT_RESULT, Map::new())
        .await
        .expect("bob completes it");
    wait_for("A to fold bob's completion", async || {
        tasks_a
            .get(&attested)
            .await
            .ok()
            .flatten()
            .is_some_and(|view| view.completed())
    })
    .await;
    let done = tasks_a.get(&attested).await.expect("get").expect("held");
    assert_eq!(done.holder(), Some(bob.agent_id()));
    assert_eq!(done.attestation(), Attestation::AgentAttested);
    let claim = a
        .peer()
        .space_claims(SPACE)
        .await
        .into_iter()
        .find(|(entry, _)| entry == attested.as_str())
        .map(|(_, signed)| signed)
        .expect("bob's claim at A");
    assert!(
        claim
            .get("holderCertificate")
            .is_some_and(|cert| !cert.is_null()),
        "an agent-signed claim carries its certificate"
    );
    let entry = attested.as_str().to_owned();
    let signer = a
        .peer()
        .with_space(SPACE, move |store| {
            store
                .signed_state(&entry)
                .and_then(|state| state.get("signer"))
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .await
        .flatten();
    assert_eq!(
        signer.as_deref(),
        Some(bob.agent_id()),
        "bob signed the completion"
    );

    // The two-key rule: bob holds the take, so only bob's key completes it.
    let guarded = tasks_a
        .write_value(TASK, task("guarded", 2), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write as alice");
    tasks_b
        .read(&on_topic("guarded"), PATIENCE)
        .await
        .expect("read")
        .expect("B reads it");
    let held = tasks_b
        .take(&on_topic("guarded"), lease("30s"), PATIENCE)
        .await
        .expect("take")
        .expect("bob takes it");
    let entry = guarded.as_str().to_owned();
    let (state, proof) = b
        .peer()
        .with_space(SPACE, move |store| {
            (
                store.state(&entry).cloned(),
                store.claim_proof(&entry).cloned(),
            )
        })
        .await
        .expect("the space at B");
    let mut dto = state.expect("the state at B");
    let proof = proof.expect("bob's claim at B");
    dto.insert("completed", true);
    let forged = records::sign_state(&dto, &b_identity, None).expect("peer-signed");
    let body = bodies::rumor_body(
        &format!("space:{SPACE}"),
        &format!("d:{guarded}:peer"),
        RUMOR_HOPS,
        &records::delta(Some(&forged), Some((guarded.as_str(), &proof))),
    );
    let mut folds = a.peer().subscribe();
    net.seed.send(0, KIND_RUMOR, &body, None).await;
    let refusal = tokio::time::timeout(PATIENCE, async {
        loop {
            match folds.recv().await {
                Ok(PeerEvent::StateFolded {
                    entry_id, outcome, ..
                }) if entry_id == guarded.as_str() && outcome.is_refused() => return outcome,
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(error) => panic!("the event stream: {error}"),
            }
        }
    })
    .await
    .expect("A judges the forged completion");
    assert_eq!(refusal, FoldOutcome::Refused(Refusal::UnverifiedState));
    let open = tasks_a.get(&guarded).await.expect("get").expect("held");
    assert!(!open.completed(), "the peer-signed completion did not land");

    // Nor may alice's peer act on alice's entry in her name.
    let peer_only = a.space(SPACE);
    let renewal = peer_only.renew_write(&guarded, lease("10m")).await;
    assert!(
        matches!(renewal, Err(SpaceError::NotIssuer { .. })),
        "{renewal:?}"
    );
    let cancel = peer_only.cancel(&guarded).await;
    assert!(
        matches!(cancel, Err(SpaceError::NotIssuer { .. })),
        "{cancel:?}"
    );
    tasks_a
        .renew_write(&guarded, lease("10m"))
        .await
        .expect("alice renews her own");

    held.complete(None, Lease::DEFAULT_RESULT, Map::new())
        .await
        .expect("bob completes it");
    wait_for("A to fold bob's completion", async || {
        tasks_a
            .get(&guarded)
            .await
            .ok()
            .flatten()
            .is_some_and(|view| view.completed())
    })
    .await;
    a.close().await.expect("close");
    b.close().await.expect("close");
}

/// The peer renews an agent's certificate at half-life before it signs, and keeps the renewed
/// identity: a write after the first certificate expired still verifies everywhere, and the next
/// write, before the renewal's own half-life, carries the same renewed certificate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agent_certificate_is_renewed_at_half_life_and_kept() {
    let net = Net::new();
    let identity = fresh();
    let a = net.member(identity.clone()).await;
    let b = net.member(fresh()).await;
    let alice = identity
        .renewing_subordinate("alice", "PT2S", None, SystemClock.now_ms())
        .expect("alice");
    let tasks_a = a.space(SPACE).as_agent(alice.clone());
    let tasks_b = b.space(SPACE);
    tasks_b.pull().await.expect("pull");
    let certificate_of = async |id: &EntryId| {
        let entry = id.as_str().to_owned();
        a.peer()
            .with_space(SPACE, move |store| {
                store
                    .state(&entry)
                    .and_then(|state| state.get("agentCertificate"))
                    .cloned()
            })
            .await
            .flatten()
            .expect("a certificate")
    };
    let first = tasks_a
        .write_value(TASK, task("first", 1), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");

    tokio::time::sleep(Duration::from_millis(2500)).await;
    let second = tasks_a
        .write_value(TASK, task("second", 1), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("a write after the first certificate expired");
    let renewed = certificate_of(&second).await;
    assert_ne!(
        renewed,
        certificate_of(&first).await,
        "a renewed certificate"
    );
    let seen = tasks_b
        .read(&on_topic("second"), PATIENCE)
        .await
        .expect("read")
        .expect("B verifies the renewed certificate");
    assert_eq!(seen.attestation(), Attestation::AgentAttested);

    let third = tasks_a
        .write_value(TASK, task("third", 1), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    assert_eq!(
        certificate_of(&third).await,
        renewed,
        "the peer kept the renewed identity"
    );
    a.close().await.expect("close");
    b.close().await.expect("close");
}

// ------------------------------------------------------------------------------- the re-check

/// A take judges each candidate again before claiming it: with 15 of its candidates claimed by
/// another member while it settled its first claim (which it lost), it skips them without a
/// claim or a settle window each and takes the free one, within one more settle window.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_live_recheck_skips_stale_candidates() {
    let net = Net::new();
    let a = net.member(fresh()).await;
    let settle = Duration::from_millis(400);
    let tasks = a.space(SPACE).with_settle(settle);
    let mut ids = Vec::new();
    for i in 0..17 {
        let id = tasks
            .write_value(
                TASK,
                task(&format!("e{i}"), 1),
                Lease::DEFAULT_WRITE,
                Map::new(),
            )
            .await
            .expect("write");
        ids.push(id);
    }
    let other = fresh();
    let holder = other.agent("worker");
    let space_id = ids::space_id_local(&format!("{}/{SPACE}", group_id()));

    let start = Instant::now();
    let racing = tokio::spawn({
        let tasks = tasks.clone();
        async move {
            tasks
                .take(&Template::new(TASK), lease("30s"), PATIENCE)
                .await
        }
    });
    let first = format!("c:{}:", ids[0]);
    net.seed
        .wait_for("A's claim on the first candidate", |received| {
            received
                .iter()
                .any(|frame| rumor_item_starts(frame, &first))
        })
        .await;
    let claimed_at = Instant::now();
    // The other member's claims: the first entry at epoch 2 (it beats A's), and the next 15.
    let now = SystemClock.now_ms();
    for (i, entry) in ids[..16].iter().enumerate() {
        let epoch = if i == 0 { 2 } else { 1 };
        let stamp = format!("{now}:{i}:{holder}");
        let claim = records::take_claim(
            entry.as_str(),
            &space_id,
            epoch,
            &stamp,
            &holder,
            0.0,
            now + 30_000,
        );
        let signed = records::signed_claim(&claim, &other, None).expect("a claim");
        let body = bodies::rumor_body(
            &format!("space:{SPACE}"),
            &format!("c:{entry}:{stamp}"),
            RUMOR_HOPS,
            &records::claim_delta(entry.as_str(), &signed),
        );
        net.seed.send(0, KIND_RUMOR, &body, None).await;
    }
    // The 15 stale candidates cost no claim and no settle window: A's next claim, on the free
    // entry, follows its lost one by that claim's settle window (and the pull after it) alone.
    let free = format!("c:{}:", ids[16]);
    net.seed
        .wait_for("A's claim on the free entry", |received| {
            received.iter().any(|frame| rumor_item_starts(frame, &free))
        })
        .await;
    let next_claim_at = Instant::now();
    let taken = racing
        .await
        .expect("the take")
        .expect("take")
        .expect("A takes the free entry");
    assert_eq!(taken.entry_id(), &ids[16]);
    let claims = net
        .seed
        .received()
        .iter()
        .filter(|frame| frame.link == 0 && rumor_item_starts(frame, "c:"))
        .count();
    assert_eq!(
        claims, 2,
        "the lost first candidate and the free one; no stale one"
    );
    let fold_wait = Duration::from_millis(300);
    let slack = Duration::from_millis(400);
    let between = next_claim_at.duration_since(claimed_at);
    assert!(
        between < settle + fold_wait + slack,
        "{between:?} from the lost claim to the next (15 stale candidates would cost 15 × {settle:?})"
    );
    let returned = next_claim_at.elapsed();
    assert!(
        returned < settle + fold_wait + slack,
        "the take returned {returned:?} after its last claim: one settle window plus slack"
    );
    assert!(start.elapsed() < (settle + fold_wait + slack) * 2);
    a.close().await.expect("close");
}

// ------------------------------------------------------------------------------- blocking

/// The blocking facade over a runtime of its own: a watch, a write, a read on another member,
/// a take, and a completion with a result, all from a plain thread.
#[test]
fn blocking_facade_round_trip() {
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
    assert_eq!(tasks_a.name(), SPACE);

    let mut events = tasks_a.watch(&Template::new(TASK)).expect("watch");
    let id = tasks_a
        .write_value(TASK, task("blocking", 1), Lease::DEFAULT_WRITE, Map::new())
        .expect("write");
    let written = events
        .recv_timeout(PATIENCE)
        .expect("recv")
        .expect("an event");
    assert_eq!(
        (written.kind, written.entry.entry_id()),
        (EventKind::Written, &id)
    );

    let seen = tasks_b
        .read(&Template::new(TASK), PATIENCE)
        .expect("read")
        .expect("B reads it");
    assert_eq!(seen.entry_id(), &id);
    let taken = tasks_b
        .take(&Template::new(TASK), lease("30s"), PATIENCE)
        .expect("take")
        .expect("B takes it");
    let result = taken
        .complete(
            Some((RESULT, cbor_map! { "topic" => "blocking" })),
            Lease::DEFAULT_RESULT,
            Map::new(),
        )
        .expect("complete")
        .expect("a result id");
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
        .read(&Template::new(RESULT), PATIENCE)
        .expect("read")
        .expect("A reads the result");
    assert_eq!(read.entry_id(), &result);
    assert!(
        tasks_a
            .get(&id)
            .expect("get")
            .is_some_and(|view| view.completed())
    );

    a.close().expect("close");
    b.close().expect("close");
    assert_eq!(
        events.recv_timeout(PATIENCE).expect("recv"),
        None,
        "the watch ends"
    );
    drop(seed);
}

/// Calling the blocking facade from inside a Tokio runtime (an async task, or a thread such as
/// `spawn_blocking`'s that entered one) answers an error instead of panicking; the same facade
/// works from a plain thread, and dropping it inside a runtime does not panic either.
#[test]
fn blocking_calls_from_inside_a_runtime_are_refused() {
    let runtime = tokio::runtime::Runtime::new().expect("a runtime");
    let network = MemoryNetwork::new();
    let seed =
        runtime.block_on(async { FakeSeed::start_relay(&network, SEED, &group_id(), system()) });
    let inside = runtime.block_on(async {
        blocking::Fleet::join(config(&network, fresh(), group(), &[SEED], system()))
    });
    assert!(
        matches!(inside, Err(SpaceError::InsideRuntime)),
        "{inside:?}"
    );

    let fleet = blocking::Fleet::join(config(&network, fresh(), group(), &[SEED], system()))
        .expect("joins from a plain thread");
    let tasks = fleet.space(SPACE);
    let refused = runtime.block_on(async { tasks.read_all(&Template::new(TASK), 10) });
    assert!(
        matches!(refused, Err(SpaceError::InsideRuntime)),
        "{refused:?}"
    );
    let refused = runtime.block_on(async {
        tasks.write_value(TASK, task("x", 1), Lease::DEFAULT_WRITE, Map::new())
    });
    assert!(
        matches!(refused, Err(SpaceError::InsideRuntime)),
        "{refused:?}"
    );
    let in_pool = runtime.block_on({
        let tasks = tasks.clone();
        async move {
            tokio::task::spawn_blocking(move || tasks.read_all(&Template::new(TASK), 10)).await
        }
    });
    assert!(
        matches!(in_pool, Ok(Err(SpaceError::InsideRuntime))),
        "{in_pool:?}"
    );
    let refused = runtime.block_on(async { fleet.close() });
    assert!(
        matches!(refused, Err(SpaceError::InsideRuntime)),
        "{refused:?}"
    );

    let id = tasks
        .write_value(TASK, task("outside", 1), Lease::DEFAULT_WRITE, Map::new())
        .expect("works from a plain thread");
    let all = tasks.read_all(&Template::new(TASK), 10).expect("read_all");
    assert_eq!(
        all.iter().map(|view| view.entry_id()).collect::<Vec<_>>(),
        [&id]
    );

    fleet.close().expect("close");
    runtime.block_on(async move {
        drop(tasks);
        drop(fleet);
    });
    drop(seed);
}
