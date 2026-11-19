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

//! The replication rules of SPEC §5.2, §7.2, and §7.3 (v0.1.35) between Rust peers over the
//! in-memory transport:
//!
//! - a renewal of a write, a take, or a subscription never shortens its lease, and a take's
//!   renewal keeps its claim's epoch, stamp, and bid;
//! - a take whose lease cannot outlast its settle window is refused at once, naming both values;
//! - an entry first learned already completed raises `Completed` alone, and only when its value
//!   is held (an inline payload), never for a block not held;
//! - a horizon round is one gossip period of the founding, on a dial-only peer too, and a faster
//!   `anti_entropy_period` of a peer's own never shortens it;
//! - the per-entry horizon engages after three fully hinted rounds, comes into force one longest
//!   lease plus five minutes later, collects a withdrawal ten minutes past its lease when the
//!   writer is vouched for and keeps a newcomer's to the legacy horizon, and disengages at once
//!   when a member without `wire.horizon=1` joins; a member without the hint keeps the legacy rule
//!   for everyone;
//! - the door refuses a withdrawal re-offered after its collection and acknowledges it;
//! - an `ACK` answers probe hashes with this peer's own, per stream and split by the prober's
//!   kind, refuses a malformed piggyback with its reason, and a differing hash starts a targeted
//!   round while the rounds have backed off.

mod support;

use std::sync::Arc;
use std::time::Duration;

use agentspaces::clock::{ManualClock, SharedClock, SystemClock};
use agentspaces::group::{self, Charter, GroupSpec, MembershipPolicy};
use agentspaces::peer::{ListenerSpec, Peer, PeerConfig};
use agentspaces::space::{EventKind, Fleet, Lease, SpaceError, Template};
use agentspaces::transport::memory::MemoryNetwork;
use agentspaces::wire::bodies::{self, KIND_ACK, KIND_DIGEST, KIND_PING, ProbeHashes};
use agentspaces::wire::cbor::{self, Map, Value};
use agentspaces::wire::horizon::{self, Mode, Rule};
use agentspaces::wire::identity::Identity;
use agentspaces::wire::{ids, serving};
use support::{PATIENCE, RawPeer, eventually};

const FOUNDING: &str = "agentspaces-rust-replication-rules";
const SPACE: &str = "tasks";
const TYPE: &str = "com.acme.Task#v1";
const MIN: i64 = 60_000;

fn system() -> SharedClock {
    Arc::new(SystemClock)
}

fn task(topic: &str) -> Value {
    let mut payload = Map::new();
    payload.insert("topic", topic);
    payload.insert("priority", 1);
    Value::Map(payload)
}

fn config(
    network: &MemoryNetwork,
    clock: SharedClock,
    listen: Option<&str>,
    seed: Option<&str>,
    horizon: bool,
) -> PeerConfig {
    let identity = Identity::generate().expect("identity");
    let mut config = PeerConfig::new(identity, GroupSpec::FoundingText(FOUNDING.to_owned()));
    config.clock = clock;
    config.horizon = horizon;
    config.peer_ad_interval = Duration::from_millis(100);
    if let Some(address) = listen {
        config = config.listen_on(ListenerSpec::bound(Arc::new(network.listen(address))));
        config.listen.anti_entropy_period = Some(Duration::from_millis(100));
    }
    if let Some(seed) = seed {
        config.seeds = vec![seed.parse().expect("seed")];
        config.dialers = vec![Arc::new(network.dialer())];
        config.reconnect_interval = Duration::from_millis(50);
        config.dial_timeout = Duration::from_secs(2);
    }
    config
}

async fn start(config: PeerConfig) -> Peer {
    Peer::start(config).await.expect("the peer starts")
}

async fn within<F, Fut>(what: &str, check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    eventually(what, check).await;
}

async fn hinted_member(of: &Peer, member: &str) -> bool {
    of.member_ad(member)
        .await
        .is_some_and(|ad| horizon::hints_horizon(ad.get("resourceHints")))
}

// ------------------------------------------------------------------------------- renewals (§7.2)

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn renewals_never_shorten_a_write_a_take_or_a_subscription() {
    let network = MemoryNetwork::new();
    let peer = start(config(
        &network,
        system(),
        Some("127.0.0.1:7951"),
        None,
        true,
    ))
    .await;
    let fleet = Fleet::from_peer(peer.clone());
    let tasks = fleet.space(SPACE).with_settle(Duration::from_millis(100));

    // A write: a renewal for less than the lease has left keeps the lease and sends nothing.
    let id = tasks
        .write_value(
            TYPE,
            task("renewed"),
            Lease::from_millis(10 * MIN).unwrap(),
            Map::new(),
        )
        .await
        .expect("write");
    let first = tasks.get(&id).await.unwrap().unwrap().expires_at_millis();
    let stamp = |states: &[Map]| -> Option<String> {
        states
            .first()
            .and_then(|state| state.get("leaseStamp"))
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let stamp_before = stamp(&peer.space_states(SPACE).await);
    tasks
        .renew_write(&id, Lease::from_millis(1_000).unwrap())
        .await
        .expect("a shorter renewal succeeds");
    assert_eq!(
        tasks.get(&id).await.unwrap().unwrap().expires_at_millis(),
        first
    );
    assert_eq!(
        stamp(&peer.space_states(SPACE).await),
        stamp_before,
        "nothing changed"
    );
    assert_eq!(peer.counters().await.renew_shortenings, 1);
    tasks
        .renew_write(&id, Lease::from_millis(30 * MIN).unwrap())
        .await
        .expect("a longer renewal");
    let renewed = tasks.get(&id).await.unwrap().unwrap().expires_at_millis();
    assert!(renewed >= first + 19 * MIN, "{renewed} after {first}");
    assert_ne!(stamp(&peer.space_states(SPACE).await), stamp_before);

    // A take: a shorter renewal keeps the hold; a longer one keeps the epoch, stamp, and bid.
    let claim_of = |claims: Vec<(String, Map)>, id: &str| -> Map {
        claims
            .into_iter()
            .find(|(entry, _)| entry == id)
            .and_then(|(_, signed)| signed.get("claim").and_then(Value::as_map).cloned())
            .expect("a claim")
    };
    let other = tasks
        .write_value(TYPE, task("taken"), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    let mut taken = tasks
        .take(
            &Template::new(TYPE)
                .where_clause("topic = taken")
                .expect("a clause"),
            Lease::from_millis(10 * MIN).unwrap(),
            PATIENCE,
        )
        .await
        .expect("take")
        .expect("taken");
    assert_eq!(taken.entry_id(), &other);
    let held = taken.expires_at_millis();
    let before = claim_of(peer.space_claims(SPACE).await, other.as_str());
    assert_eq!(
        taken
            .renew(Lease::from_millis(1_000).unwrap())
            .await
            .expect("renew"),
        held
    );
    assert_eq!(
        claim_of(peer.space_claims(SPACE).await, other.as_str()),
        before
    );
    let longer = taken
        .renew(Lease::from_millis(30 * MIN).unwrap())
        .await
        .expect("renew");
    assert!(longer > held);
    let after = claim_of(peer.space_claims(SPACE).await, other.as_str());
    for field in ["epoch", "stamp", "bid", "holder"] {
        assert_eq!(after.get(field), before.get(field), "{field} kept");
    }
    assert_eq!(
        after.get("expiresAtMillis").and_then(Value::as_i64),
        Some(longer)
    );
    assert_eq!(peer.counters().await.renew_shortenings, 2);

    // A subscription.
    let subscription = tasks
        .notify(
            &Template::new(TYPE),
            Lease::from_millis(10 * MIN).unwrap(),
            |_| {},
        )
        .await
        .expect("notify");
    let lapse = subscription.expires_at_millis();
    subscription
        .renew(Lease::from_millis(1_000).unwrap())
        .expect("renew");
    assert_eq!(subscription.expires_at_millis(), lapse);
    subscription
        .renew(Lease::from_millis(30 * MIN).unwrap())
        .expect("renew");
    assert!(subscription.expires_at_millis() > lapse);
    subscription.close();
    peer.close().await.expect("close");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_take_whose_lease_cannot_outlast_its_window_is_refused_at_once() {
    let network = MemoryNetwork::new();
    let peer = start(config(
        &network,
        system(),
        Some("127.0.0.1:7952"),
        None,
        true,
    ))
    .await;
    let fleet = Fleet::from_peer(peer.clone());
    let tasks = fleet.space(SPACE).with_settle(Duration::from_millis(200));
    assert_eq!(tasks.take_window(), Duration::from_millis(400));
    assert_eq!(
        fleet.space(SPACE).take_window(),
        Duration::from_millis(900),
        "600 ms and a 300 ms follow-up"
    );
    tasks
        .write_value(TYPE, task("short"), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    let started = std::time::Instant::now();
    let refused = tasks
        .take(
            &Template::new(TYPE),
            Lease::from_millis(400).unwrap(),
            Duration::from_secs(10),
        )
        .await;
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "refused at once"
    );
    match refused {
        Err(error @ SpaceError::TakeLeaseWithinSettle { .. }) => {
            let text = error.to_string();
            assert!(text.contains("400 ms") && text.contains("400 ms"), "{text}");
            assert!(matches!(
                error,
                SpaceError::TakeLeaseWithinSettle {
                    lease_millis: 400,
                    window_millis: 400
                }
            ));
        }
        other => panic!("not refused: {other:?}"),
    }
    assert!(
        peer.space_claims(SPACE).await.is_empty(),
        "no claim went out"
    );
    let taken = tasks
        .take(
            &Template::new(TYPE),
            Lease::from_millis(5_000).unwrap(),
            PATIENCE,
        )
        .await
        .expect("a lease past the window takes");
    assert!(taken.is_some());
    peer.close().await.expect("close");
}

// ------------------------------------------------------------------------------- completed on arrival

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_entry_first_learned_completed_raises_completed_alone_when_its_value_is_held() {
    let network = MemoryNetwork::new();
    let address = "127.0.0.1:7953";
    let hub = start(config(&network, system(), Some(address), None, true)).await;
    let tasks = Fleet::from_peer(hub.clone())
        .space(SPACE)
        .with_settle(Duration::from_millis(100));
    // One inline entry and one whose payload travels as a block, both taken and completed.
    tasks
        .write_value(TYPE, task("inline"), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    let big = "x".repeat(70 * 1024);
    tasks
        .write_value(TYPE, task(&big), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write a block");
    for _ in 0..2 {
        let taken = tasks
            .take(
                &Template::new(TYPE),
                Lease::from_millis(MIN).unwrap(),
                PATIENCE,
            )
            .await
            .expect("take")
            .expect("taken");
        taken
            .complete(None, Lease::DEFAULT_WRITE, Map::new())
            .await
            .expect("complete");
    }

    // A late joiner watches, then pulls: both entries arrive completed.
    let late = start(config(&network, system(), None, Some(address), true)).await;
    let space = Fleet::from_peer(late.clone()).space(SPACE);
    let mut events = space.watch(&Template::new(TYPE)).await.expect("watch");
    space.pull().await.expect("pull");
    within("the late joiner holds both completed entries", || async {
        late.space_states(SPACE)
            .await
            .iter()
            .filter(|state| state.get("completed").and_then(Value::as_bool) == Some(true))
            .count()
            == 2
    })
    .await;
    let event = tokio::time::timeout(PATIENCE, events.next())
        .await
        .expect("an event")
        .expect("open");
    assert_eq!(event.kind, EventKind::Completed);
    assert_eq!(
        event.entry.payload().get("topic").and_then(Value::as_str),
        Some("inline")
    );
    // Nothing else: no WRITTEN or TAKEN for either, no COMPLETED for the block not held.
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(events.try_next().is_none(), "one event only");
    late.close().await.expect("close");
    hub.close().await.expect("close");
}

/// A late joiner that only watches (no pull of its own) hears every entry the opening pull brings.
/// The peer opens the space and registers the watch in one step of its actor, which reads no
/// inbound frame in between, so the opening pull's answer always folds after the watch exists.
/// (The watch used to open the space as a separate step; an answer folding between the two steps
/// raised no event. That window is too narrow for this test to hit on the memory transport, so the
/// test guards the behaviour and the single step is what closes the window.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_watch_hears_every_entry_its_opening_pull_brings() {
    let network = MemoryNetwork::new();
    let address = "127.0.0.1:7961";
    let hub = start(config(&network, system(), Some(address), None, true)).await;
    let tasks = Fleet::from_peer(hub.clone()).space(SPACE);
    const ENTRIES: usize = 24;
    for i in 0..ENTRIES {
        tasks
            .write_value(
                TYPE,
                task(&format!("t{i}")),
                Lease::DEFAULT_WRITE,
                Map::new(),
            )
            .await
            .expect("write");
    }
    for round in 0..12 {
        let late = start(config(&network, system(), None, Some(address), true)).await;
        let space = Fleet::from_peer(late.clone()).space(SPACE);
        let mut events = space.watch(&Template::new(TYPE)).await.expect("watch");
        let mut heard = 0;
        while heard < ENTRIES {
            match tokio::time::timeout(PATIENCE, events.next()).await {
                Ok(Some(event)) if event.kind == EventKind::Written => heard += 1,
                Ok(Some(_)) => {}
                _ => panic!("round {round}: the watch heard {heard} of {ENTRIES} entries"),
            }
        }
        late.close().await.expect("close");
    }
    hub.close().await.expect("close");
}

// ------------------------------------------------------------------------------- horizons (§7.3)

/// Advances the shared clock in steps of a minute, letting the peers re-lease and gossip, until
/// it has moved `millis`.
async fn advance(clock: &ManualClock, millis: i64) {
    let mut left = millis;
    while left > 0 {
        let step = left.min(MIN);
        clock.advance(step);
        left -= step;
        tokio::time::sleep(Duration::from_millis(120)).await;
    }
}

/// Judges `peer`'s space a round apart until it reaches `mode`.
async fn reach(peer: &Peer, clock: &ManualClock, mode: Mode) {
    for _ in 0..200 {
        let status = peer.space_horizon(SPACE).await.expect("the space is open");
        if status.mode == mode {
            return;
        }
        clock.advance(150);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("never reached {mode:?}");
}

async fn write_and_cancel(peer: &Peer, topic: &str) -> String {
    let space = Fleet::from_peer(peer.clone()).space(SPACE);
    let id = space
        .write_value(
            TYPE,
            task(topic),
            Lease::from_millis(2_000).unwrap(),
            Map::new(),
        )
        .await
        .expect("write");
    space.cancel(&id).await.expect("cancel");
    id.as_str().to_owned()
}

fn holds(states: &[Map], id: &str) -> bool {
    states.iter().any(|state| {
        state
            .get("record")
            .and_then(|record| record.get("entryId"))
            .and_then(Value::as_str)
            == Some(id)
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_per_entry_horizon_engages_settles_vouches_for_writers_and_disengages() {
    let network = MemoryNetwork::new();
    let manual = ManualClock::new(1_800_000_000_000);
    let clock: SharedClock = Arc::new(manual.clone());
    let a_address = "127.0.0.1:7954";
    let a = start(config(&network, clock.clone(), Some(a_address), None, true)).await;
    let b = start(config(
        &network,
        clock.clone(),
        Some("127.0.0.1:7955"),
        Some(a_address),
        true,
    ))
    .await;
    for peer in [&a, &b] {
        peer.pull_space(SPACE).await.expect("open the space");
    }
    within("a holds b's hinted card", || async {
        hinted_member(&a, b.peer_id()).await
    })
    .await;
    // A 30-minute lease makes the legacy horizon of a withdrawal an hour.
    Fleet::from_peer(a.clone())
        .space(SPACE)
        .write_value(
            TYPE,
            task("long"),
            Lease::from_millis(30 * MIN).unwrap(),
            Map::new(),
        )
        .await
        .expect("write");

    // The view's half: three fully hinted rounds engage it, the settle brings it into force.
    let status = a.space_horizon(SPACE).await.expect("open");
    assert_eq!(status.rule, Rule::Legacy);
    reach(&a, &manual, Mode::Settling).await;
    let status = a.space_horizon(SPACE).await.expect("open");
    assert_eq!(status.engagements, 1);
    assert_eq!(status.rule, Rule::Legacy, "not in force while settling");
    assert_eq!(status.max_lease_millis, 30 * MIN);
    advance(&manual, 35 * MIN).await;
    let status = a.space_horizon(SPACE).await.expect("open");
    assert_eq!(status.mode, Mode::PerEntry, "{status:?}");
    assert_eq!(status.settlements, 1);

    // A newcomer, hinted, joins: the view stays hinted, but its stay is short.
    let c = start(config(
        &network,
        clock.clone(),
        Some("127.0.0.1:7956"),
        Some(a_address),
        true,
    ))
    .await;
    c.pull_space(SPACE).await.expect("open");
    within("a holds c's hinted card", || async {
        hinted_member(&a, c.peer_id()).await
    })
    .await;
    assert_eq!(
        a.space_horizon(SPACE).await.expect("open").mode,
        Mode::PerEntry
    );

    // Withdrawals by a, by b (in view 35 minutes), and by the newcomer c.
    let own = write_and_cancel(&a, "own").await;
    let vouched = write_and_cancel(&b, "vouched").await;
    let newcomer = write_and_cancel(&c, "newcomer").await;
    within("a holds the three withdrawals", || async {
        let states = a.space_states(SPACE).await;
        [&own, &vouched, &newcomer]
            .iter()
            .all(|id| holds(&states, id))
    })
    .await;
    // Past ten minutes after their leases: the vouched withdrawals go, the newcomer's stays.
    advance(&manual, 10 * MIN + 5_000).await;
    a.collect_now().await;
    let states = a.space_states(SPACE).await;
    assert!(!holds(&states, &own), "a's own withdrawal is collected");
    assert!(!holds(&states, &vouched), "b's withdrawal is collected");
    assert!(
        holds(&states, &newcomer),
        "c's withdrawal keeps the legacy horizon"
    );

    // b and c still hold the withdrawals a collected and re-offer them; a's door refuses them.
    within(
        "a's door refuses a re-offered withdrawal and acknowledges it",
        || async {
            let counters = a.counters().await;
            counters.space_reoffers_refused >= 1 && counters.reoffers_acknowledged >= 1
        },
    )
    .await;
    let acknowledged = a
        .with_space(SPACE, |store| {
            store
                .acknowledged()
                .map(str::to_owned)
                .collect::<Vec<String>>()
        })
        .await
        .expect("open");
    assert!(
        acknowledged
            .iter()
            .any(|line| line.starts_with(&format!("e:{own}="))
                || line.starts_with(&format!("e:{vouched}="))),
        "{acknowledged:?}"
    );
    assert!(
        !holds(&a.space_states(SPACE).await, &own),
        "never taken back"
    );

    // A member without the hint joins: the rule disengages at once, for everyone's entries.
    let legacy = start(config(
        &network,
        clock.clone(),
        None,
        Some(a_address),
        false,
    ))
    .await;
    within("a holds the unhinted card", || async {
        a.member_ad(legacy.peer_id())
            .await
            .is_some_and(|ad| !ad.is_empty())
    })
    .await;
    let status = a.space_horizon(SPACE).await.expect("open");
    assert_eq!(status.mode, Mode::Legacy);
    assert_eq!(status.rule, Rule::Legacy);
    assert_eq!(status.disengagements, 1);
    for peer in [&legacy, &c, &b, &a] {
        peer.close().await.expect("close");
    }
}

/// The gate counts a round by the founding's gossip period (SPEC §7.3, as the reference
/// implementation counts it), on a dial-only peer too: with a five-second period three fully
/// hinted rounds take fifteen seconds of the space's clock, not three.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_horizon_round_is_one_gossip_period_of_the_founding() {
    let network = MemoryNetwork::new();
    let manual = ManualClock::new(1_800_000_000_000);
    let clock: SharedClock = Arc::new(manual.clone());
    let founder = Identity::generate().expect("identity");
    let mut charter = Charter::new("slow-gossip", MembershipPolicy::Open);
    charter.period = "PT5S".to_owned();
    let document = group::found(&founder, &charter, clock.now_ms()).expect("found");
    let hub_address = "127.0.0.1:7963";
    let mut hub_config = config(&network, clock.clone(), Some(hub_address), None, true);
    hub_config.group = GroupSpec::FoundingDocument(document.clone());
    hub_config.identity = founder;
    let hub = start(hub_config).await;
    let mut member_config = config(&network, clock.clone(), None, Some(hub_address), true);
    member_config.group = GroupSpec::FoundingDocument(document);
    let member = start(member_config).await;
    member.pull_space(SPACE).await.expect("open the space");
    within("the member holds the hub's hinted card", || async {
        hinted_member(&member, hub.peer_id()).await
    })
    .await;

    // Judged every 150 ms of the clock for eleven seconds: two rounds of five seconds, not three.
    for _ in 0..74 {
        let status = member.space_horizon(SPACE).await.expect("open");
        assert_eq!(
            status.mode,
            Mode::Waiting,
            "engaged before three gossip periods of five seconds"
        );
        manual.advance(150);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    reach(&member, &manual, Mode::Settling).await;
    let _ = member.close().await;
    let _ = hub.close().await;
}

/// A peer whose own rounds run faster than the founding's period (`anti_entropy_period`) still
/// counts a horizon round as at least one gossip period of the founding: the override paces its
/// own rounds and never brings the per-entry horizon closer than the group's other members, or
/// the reference implementation, would bring it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_faster_anti_entropy_period_never_shortens_a_horizon_round() {
    let network = MemoryNetwork::new();
    let manual = ManualClock::new(1_800_000_000_000);
    let clock: SharedClock = Arc::new(manual.clone());
    let founder = Identity::generate().expect("identity");
    let mut charter = Charter::new("slow-gossip-fast-peer", MembershipPolicy::Open);
    charter.period = "PT5S".to_owned();
    let document = group::found(&founder, &charter, clock.now_ms()).expect("found");
    let hub_address = "127.0.0.1:7964";
    // The hub's rounds run every 100 ms of its own setting, fifty times the founding's pace.
    let mut hub_config = config(&network, clock.clone(), Some(hub_address), None, true);
    hub_config.group = GroupSpec::FoundingDocument(document.clone());
    hub_config.identity = founder;
    let hub = start(hub_config).await;
    let mut member_config = config(&network, clock.clone(), None, Some(hub_address), true);
    member_config.group = GroupSpec::FoundingDocument(document);
    member_config.listen.anti_entropy_period = Some(Duration::from_millis(100));
    let member = start(member_config).await;
    member.pull_space(SPACE).await.expect("open the space");
    hub.pull_space(SPACE).await.expect("open the space");
    within("the member holds the hub's hinted card", || async {
        hinted_member(&member, hub.peer_id()).await
    })
    .await;
    within("the hub holds the member's hinted card", || async {
        hinted_member(&hub, member.peer_id()).await
    })
    .await;

    // Judged every 150 ms of the clock for eleven seconds: two founding rounds, not a hundred
    // of the peers' own.
    for _ in 0..74 {
        for peer in [&member, &hub] {
            let status = peer.space_horizon(SPACE).await.expect("open");
            assert_eq!(
                status.mode,
                Mode::Waiting,
                "engaged before three gossip periods of the founding"
            );
        }
        manual.advance(150);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    reach(&member, &manual, Mode::Settling).await;
    reach(&hub, &manual, Mode::Settling).await;
    let _ = member.close().await;
    let _ = hub.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_without_the_hint_keeps_the_legacy_horizon_for_everyone() {
    let network = MemoryNetwork::new();
    let manual = ManualClock::new(1_800_000_000_000);
    let clock: SharedClock = Arc::new(manual.clone());
    let address = "127.0.0.1:7957";
    let a = start(config(&network, clock.clone(), Some(address), None, true)).await;
    let old = start(config(
        &network,
        clock.clone(),
        Some("127.0.0.1:7958"),
        Some(address),
        false,
    ))
    .await;
    for peer in [&a, &old] {
        peer.pull_space(SPACE).await.expect("open");
    }
    within("each holds the other's card", || async {
        a.member_ad(old.peer_id())
            .await
            .is_some_and(|ad| !ad.is_empty())
            && old
                .member_ad(a.peer_id())
                .await
                .is_some_and(|ad| !ad.is_empty())
    })
    .await;
    assert!(!hinted_member(&a, old.peer_id()).await);
    assert!(
        hinted_member(&old, a.peer_id()).await,
        "a advertises the hint"
    );
    let withdrawn = write_and_cancel(&a, "withdrawn").await;
    for _ in 0..20 {
        manual.advance(500);
        for peer in [&a, &old] {
            let status = peer.space_horizon(SPACE).await.expect("open");
            assert_eq!(status.mode, Mode::Legacy);
            assert_eq!(status.engagements, 0);
        }
    }
    // Ten minutes past the lease is the legacy horizon here too (the drift floor), and a
    // second short of it nothing goes.
    advance(&manual, 10 * MIN - 15_000).await;
    a.collect_now().await;
    assert!(holds(&a.space_states(SPACE).await, &withdrawn));
    advance(&manual, 20_000).await;
    a.collect_now().await;
    assert!(!holds(&a.space_states(SPACE).await, &withdrawn));
    for peer in [&old, &a] {
        peer.close().await.expect("close");
    }
}

// ------------------------------------------------------------------------------- probe hashes (§5.2)

fn ack_hashes(env: &Map) -> Option<ProbeHashes> {
    let body = env.get("body")?.as_bytes()?;
    let decoded = bodies::decode_body(KIND_ACK, body)?;
    bodies::probe_hashes(&decoded).ok()
}

fn nonce_of(env: &Map) -> Option<i64> {
    bodies::parse_ack(env.get("body")?.as_bytes()?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ack_answers_probe_hashes_with_its_own_split_by_the_probers_kind() {
    let network = MemoryNetwork::new();
    let address = "127.0.0.1:7959";
    let hub = start(config(&network, system(), Some(address), None, true)).await;
    Fleet::from_peer(hub.clone())
        .space(SPACE)
        .write_value(TYPE, task("held"), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    let group = ids::group_id_from_founding(FOUNDING.as_bytes());
    let stream = format!("space:{SPACE}");
    let text_hash = |digest: &[u8]| agentspaces::wire::crypto::port().sha256(digest);
    let space_text = hub
        .with_space(SPACE, |store| {
            serving::space_digest_acked(store.states(), store.claims(), store.acknowledged())
        })
        .await
        .expect("open");

    for (audits, nonce) in [(false, 41), (true, 42)] {
        let raw = RawPeer::dial(
            &network,
            address,
            Identity::generate().expect("id"),
            &group,
            system(),
        )
        .await;
        let mut hints = Map::new();
        if audits {
            hints.insert("wire.ae", "2");
        }
        raw.introduce(&hints).await;
        within("the hub admits the prober", || async {
            hub.admitted_members()
                .await
                .contains(&raw.peer_id().to_owned())
        })
        .await;
        // A bare probe: a bare acknowledgement.
        raw.send(KIND_PING, &bodies::ping_body(nonce), Some(hub.peer_id()))
            .await;
        // A probe with hashes: an acknowledgement with this peer's own.
        let mut theirs = std::collections::BTreeMap::new();
        theirs.insert(stream.clone(), [9u8; 32]);
        let probe = ProbeHashes {
            root: None,
            hashes: Some(theirs),
        };
        raw.send(
            KIND_PING,
            &bodies::ping_body_with(nonce + 100, &probe),
            Some(hub.peer_id()),
        )
        .await;
        raw.wait_for("both acknowledgements", |frames| {
            frames
                .iter()
                .filter(|env| env.get("kind").and_then(Value::as_str) == Some(KIND_ACK))
                .count()
                >= 2
        })
        .await;
        let acks = raw.of_kind(KIND_ACK);
        let bare = acks
            .iter()
            .find(|env| nonce_of(env) == Some(nonce))
            .expect("bare");
        assert!(ack_hashes(bare).is_some_and(|probe| probe.is_empty()));
        let answered = acks
            .iter()
            .find(|env| nonce_of(env) == Some(nonce + 100))
            .expect("answered");
        let own = ack_hashes(answered).expect("well formed");
        let hashes = own.hashes.expect("per stream under the bound");
        assert_eq!(own.root, None);
        assert!(hashes.contains_key("view") && hashes.contains_key("ads"));
        let space_hash = hashes.get(&stream).expect("the space");
        if audits {
            assert_ne!(
                space_hash,
                &text_hash(&space_text),
                "the trie's stream hash"
            );
        } else {
            assert_eq!(
                space_hash,
                &text_hash(&space_text),
                "the text digest's hash"
            );
        }
    }

    // A malformed piggyback: refused by name, and the probe still answered.
    let raw = RawPeer::dial(
        &network,
        address,
        Identity::generate().expect("id"),
        &group,
        system(),
    )
    .await;
    raw.introduce(&Map::new()).await;
    let mut bad = Map::new();
    bad.insert("nonce", 7);
    bad.insert("root", vec![1u8; 31]);
    raw.send(
        KIND_PING,
        &cbor::encode(&Value::Map(bad)),
        Some(hub.peer_id()),
    )
    .await;
    raw.wait_for("the acknowledgement", |frames| {
        frames
            .iter()
            .any(|env| env.get("kind").and_then(Value::as_str) == Some(KIND_ACK))
    })
    .await;
    let refused = hub.counters().await.listen.probe_hashes_refused;
    assert_eq!(refused.get("probe-root-length"), Some(&1), "{refused:?}");
    hub.close().await.expect("close");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_differing_probe_hash_starts_a_round_while_the_rounds_have_backed_off() {
    let network = MemoryNetwork::new();
    let address = "127.0.0.1:7960";
    let mut hub_config = config(&network, system(), Some(address), None, true);
    hub_config.listen.anti_entropy_period = Some(Duration::from_millis(50));
    let hub = start(hub_config).await;
    hub.pull_space(SPACE).await.expect("open");
    let group = ids::group_id_from_founding(FOUNDING.as_bytes());
    let raw = RawPeer::dial(
        &network,
        address,
        Identity::generate().expect("id"),
        &group,
        system(),
    )
    .await;
    raw.introduce(&Map::new()).await;
    within("the hub admits the prober", || async {
        hub.admitted_members()
            .await
            .contains(&raw.peer_id().to_owned())
    })
    .await;
    // A DIGEST naming the view makes the prober a partner of the hub's rounds.
    let mut digests = Map::new();
    digests.insert("view", Vec::<u8>::new());
    raw.send(
        KIND_DIGEST,
        &bodies::digest_body(&digests),
        Some(hub.peer_id()),
    )
    .await;
    // Idle rounds stretch the period; then a probe whose space hash differs starts a round.
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    let digests_before = raw.of_kind(KIND_DIGEST).len();
    let mut theirs = std::collections::BTreeMap::new();
    theirs.insert(format!("space:{SPACE}"), [9u8; 32]);
    let probe = ProbeHashes {
        root: None,
        hashes: Some(theirs.clone()),
    };
    raw.send(
        KIND_PING,
        &bodies::ping_body_with(1, &probe),
        Some(hub.peer_id()),
    )
    .await;
    within("the probe starts a round", || async {
        hub.counters().await.listen.probe_rounds == 1
    })
    .await;
    raw.wait_for("the round's DIGEST", |frames| {
        frames
            .iter()
            .filter(|env| env.get("kind").and_then(Value::as_str) == Some(KIND_DIGEST))
            .count()
            > digests_before
    })
    .await;
    // At most once per gossip period per member; an absent field starts nothing.
    raw.send(
        KIND_PING,
        &bodies::ping_body_with(2, &probe),
        Some(hub.peer_id()),
    )
    .await;
    raw.send(KIND_PING, &bodies::ping_body(3), Some(hub.peer_id()))
        .await;
    raw.wait_for("three acknowledgements", |frames| {
        frames
            .iter()
            .filter(|env| env.get("kind").and_then(Value::as_str) == Some(KIND_ACK))
            .count()
            >= 3
    })
    .await;
    assert_eq!(hub.counters().await.listen.probe_rounds, 1);
    hub.close().await.expect("close");
}

// ------------------------------------------------------------------------------- control ids (I.6)

/// Under `wire.ae=2` a state whose entry id holds a control character is dropped, uncounted and
/// unacknowledged; a peer that does not audit folds it as before.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_entry_id_holding_a_control_character_is_dropped_under_the_audit() {
    use agentspaces::clock::Clock;
    use agentspaces::wire::records::{self, EntryWrite};
    let network = MemoryNetwork::new();
    for (audit, address) in [(true, "127.0.0.1:7961"), (false, "127.0.0.1:7962")] {
        let mut hub_config = config(&network, system(), Some(address), None, true);
        hub_config.audit = audit;
        let hub = start(hub_config).await;
        hub.pull_space(SPACE).await.expect("open");
        let group = ids::group_id_from_founding(FOUNDING.as_bytes());
        let identity = Identity::generate().expect("id");
        let raw = RawPeer::dial(&network, address, identity.clone(), &group, system()).await;
        raw.introduce(&Map::new()).await;
        within("the hub admits the writer", || async {
            hub.admitted_members()
                .await
                .contains(&raw.peer_id().to_owned())
        })
        .await;
        let space_id = ids::space_id_local(&format!("{group}/{SPACE}"));
        let now = SystemClock.now_ms();
        let issued = format!("{now}:0:{}", identity.peer_id());
        let payload = cbor::encode(&task("payload"));
        for id in ["bad\u{7}id", "good-id"] {
            let write = EntryWrite {
                entry_id: id,
                space_id: &space_id,
                type_name: TYPE,
                payload: Some(&payload),
                payload_ref: None,
                tags: None,
                key_epoch: None,
                issued: &issued,
                expires_at_millis: now + 10 * MIN,
                counter: 1,
            };
            let delta = records::entry_delta(&write, &identity, "raw", None).expect("signed");
            raw.rumor(&format!("space:{SPACE}"), &format!("w:{id}"), &delta)
                .await;
        }
        within("the good entry folds", || async {
            holds(&hub.space_states(SPACE).await, "good-id")
        })
        .await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        let states = hub.space_states(SPACE).await;
        assert_eq!(holds(&states, "bad\u{7}id"), !audit, "audit {audit}");
        let status = hub.space_horizon(SPACE).await.expect("open");
        assert_eq!(status.acknowledged_lines, 0, "never acknowledged");
        hub.close().await.expect("close");
    }
}
