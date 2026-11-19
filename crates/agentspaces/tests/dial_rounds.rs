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

//! The periodic rounds of a dial-only peer (SPEC §5.3, the idle floor), over the in-memory
//! transport:
//!
//! - a rumor the link lost reaches the peer by its next rounds, with no reconnect and no read;
//! - an idle peer's period doubles to exactly 32 times the base and its rounds keep running,
//!   advertisement and `peers` refreshes leave it stretched, and activity brings it back;
//! - with 50 pulled spaces a round is one `DIGEST` naming every stream, and a Rust seed answers
//!   20 rounds without a pace refusal;
//! - the pulls on link-ready are packed the same way: 50 spaces cost at most two `DIGEST`s on a
//!   reconnect, each an empty digest per stream (send everything), and a Rust seed paces none;
//! - the pulls on link-ready and the paced pulls of a waiting read still go out.

mod support;

use std::sync::Arc;
use std::time::Duration;

use agentspaces::clock::{SharedClock, SystemClock};
use agentspaces::group::GroupSpec;
use agentspaces::peer::{ListenerSpec, Peer, PeerConfig};
use agentspaces::space::{Fleet, Template};
use agentspaces::transport::Dialer;
use agentspaces::transport::memory::MemoryNetwork;
use agentspaces::wire::ads;
use agentspaces::wire::bodies::{self, KIND_DIGEST, STREAM_SPACE_PREFIX};
use agentspaces::wire::cbor::{Map, Value};
use agentspaces::wire::identity::Identity;
use agentspaces::wire::{ids, time};
use support::{FakeSeed, HoldingDialer, LossyDialer, Received};
use tokio::time::Instant;

const FOUNDING: &str = "agentspaces-rust-dial-rounds";
const SPACE: &str = "tasks";
const TYPE: &str = "com.acme.Task#v1";
const LEASE_MILLIS: i64 = 600_000;

fn system() -> SharedClock {
    Arc::new(SystemClock)
}

fn task(topic: &str) -> Value {
    let mut payload = Map::new();
    payload.insert("topic", topic);
    payload.insert("priority", 1);
    Value::Map(payload)
}

/// A listening Rust seed at `address`.
async fn seed(network: &MemoryNetwork, address: &str) -> Peer {
    let identity = Identity::generate().expect("identity");
    let mut config = PeerConfig::new(identity, GroupSpec::FoundingText(FOUNDING.to_owned()))
        .listen_on(ListenerSpec::bound(Arc::new(network.listen(address))));
    config.clock = system();
    config.peer_ad_interval = Duration::from_millis(100);
    config.listen.anti_entropy_period = Some(Duration::from_millis(100));
    Peer::start(config).await.expect("the seed starts")
}

/// A dial-only peer of `identity` dialing `address` with `dialer`, its rounds every `period`.
fn client_config(
    identity: Identity,
    address: &str,
    dialer: Arc<dyn Dialer>,
    period: Duration,
) -> PeerConfig {
    let mut config = PeerConfig::new(identity, GroupSpec::FoundingText(FOUNDING.to_owned()));
    config.clock = system();
    config.seeds = vec![address.parse().expect("seed")];
    config.dialers = vec![dialer];
    config.reconnect_interval = Duration::from_millis(50);
    config.dial_timeout = Duration::from_secs(2);
    config.peer_ad_interval = Duration::from_millis(100);
    config.listen.anti_entropy_period = Some(period);
    config
}

async fn client(address: &str, dialer: Arc<dyn Dialer>, period: Duration) -> Peer {
    let identity = Identity::generate().expect("identity");
    Peer::start(client_config(identity, address, dialer, period))
        .await
        .expect("the client starts")
}

async fn write(peer: &Peer, space: &str, topic: &str) -> String {
    peer.write_entry(space, TYPE, task(topic), LEASE_MILLIS, Map::new(), None)
        .await
        .expect("write")
}

async fn holds(peer: &Peer, space: &str, count: usize) -> bool {
    peer.space_states(space).await.len() >= count
}

/// Waits up to `limit` for `check`; panics naming `what`.
async fn within<F, Fut>(limit: Duration, what: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + limit;
    while !check().await {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// The streams a DIGEST names.
fn digest_streams(frame: &Received) -> Vec<String> {
    bodies::parse_digest(frame.body())
        .map(|digests| {
            digests
                .keys()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

// ------------------------------------------------------------------------------- a lost rumor

/// The link drops the seed's rumor of a write; the dial-only peer, which neither reconnects nor
/// reads, still comes to hold the entry within a few periods, by its own rounds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rumor_the_link_lost_arrives_by_the_next_rounds() {
    let network = MemoryNetwork::new();
    let address = "127.0.0.1:7801";
    let hub = seed(&network, address).await;
    write(&hub, SPACE, "before").await;
    let lossy = LossyDialer::new(
        Arc::new(network.dialer()),
        &format!("{STREAM_SPACE_PREFIX}{SPACE}"),
    );
    let period = Duration::from_millis(100);
    let peer = client(address, Arc::new(lossy.clone()), period).await;
    peer.pull_space(SPACE).await.expect("pull");
    within(Duration::from_secs(5), "the pull on link-ready", || {
        holds(&peer, SPACE, 1)
    })
    .await;

    // Every round from here on may bring it; none before could.
    let rounds = peer.counters().await.dial_rounds;
    lossy.set_dropping(true);
    write(&hub, SPACE, "missed").await;
    within(
        Duration::from_secs(5),
        "the seed's rumor to be lost",
        || async { lossy.dropped() >= 1 },
    )
    .await;
    lossy.set_dropping(false);

    // An idle peer's period is at most 32 times the base: a few such periods suffice.
    within(period * 32 * 3, "the missed entry by the rounds", || {
        holds(&peer, SPACE, 2)
    })
    .await;
    let counters = peer.counters().await;
    assert_eq!(counters.reconnects, 0, "no reconnect brought it");
    assert!(
        counters.dial_rounds > rounds,
        "a round brought it: {counters:?}"
    );
    let _ = peer.close().await;
    let _ = hub.close().await;
}

// ------------------------------------------------------------------------------- the idle floor

/// Idle, the period doubles to exactly 32 times the base and stays there with the rounds still
/// running, though another member keeps refreshing its card and every member its `peers`
/// advertisement; writes on a pulled space bring it back to the base.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_period_stretches_to_32_times_never_stops_and_returns_on_activity() {
    let network = MemoryNetwork::new();
    let address = "127.0.0.1:7802";
    let hub = seed(&network, address).await;
    write(&hub, SPACE, "held").await;
    let base = Duration::from_millis(20);
    let ceiling = u64::try_from((base * 32).as_millis()).expect("millis");
    let peer = client(address, Arc::new(network.dialer()), base).await;
    peer.pull_space(SPACE).await.expect("pull");
    peer.pull_ads().await.expect("pull ads");

    // Another member refreshes its card every 50 ms: advertisements are never activity.
    let publisher_identity = Identity::generate().expect("identity");
    let publisher = Peer::start(client_config(
        publisher_identity.clone(),
        address,
        Arc::new(network.dialer()),
        Duration::from_secs(1),
    ))
    .await
    .expect("the publisher starts");
    let group = publisher.group_id().to_owned();
    let refresher = {
        let publisher = publisher.clone();
        tokio::spawn(async move {
            loop {
                let issued = time::instant_iso(
                    i64::try_from(
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .expect("time")
                            .as_millis(),
                    )
                    .expect("millis"),
                );
                let card = ads::agent_card(
                    &group,
                    &publisher_identity,
                    "refresher",
                    &issued,
                    "PT15M",
                    "refreshes its card",
                    &[],
                    &[],
                    &[],
                    &Map::new(),
                    &Map::new(),
                    None,
                    &[],
                    None,
                    None,
                )
                .expect("card");
                let _ = publisher.publish_ad(ads::AD_TYPE_AGENT_CARD, card).await;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
    };
    within(Duration::from_secs(5), "the refreshed card", || async {
        !peer.cards().await.is_empty()
    })
    .await;

    within(
        Duration::from_secs(10),
        "the period at 32 times the base",
        || async { peer.counters().await.dial_round_period_millis == ceiling },
    )
    .await;
    let before = peer.counters().await;
    tokio::time::sleep(base * 32 * 4).await;
    let after = peer.counters().await;
    assert_eq!(
        after.dial_round_period_millis, ceiling,
        "card and peers refreshes leave it stretched, and it never passes 32 times"
    );
    assert!(
        after.dial_rounds >= before.dial_rounds + 2,
        "the rounds keep running at the ceiling: {} then {}",
        before.dial_rounds,
        after.dial_rounds
    );

    // Writes the peer folds count: the period comes back to the base.
    let writer = {
        let hub = hub.clone();
        tokio::spawn(async move {
            for n in 0..=u32::MAX {
                write(&hub, SPACE, &format!("busy-{n}")).await;
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
    };
    let floor = u64::try_from(base.as_millis()).expect("millis");
    within(
        Duration::from_secs(5),
        "the period back at the base",
        || async { peer.counters().await.dial_round_period_millis == floor },
    )
    .await;
    writer.abort();
    refresher.abort();
    let _ = publisher.close().await;
    let _ = peer.close().await;
    let _ = hub.close().await;
}

// ------------------------------------------------------------------------------- the seed's pace

/// With 50 pulled spaces each round is one DIGEST that names both revocation streams and every
/// space, so a round never costs the seed more than one of its paced answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fifty_spaces_go_in_one_digest_per_round() {
    let network = MemoryNetwork::new();
    let address = "127.0.0.1:7803";
    let fake = FakeSeed::start(&network, address, &ids_of(FOUNDING), system());
    let peer = client(
        address,
        Arc::new(network.dialer()),
        Duration::from_millis(30),
    )
    .await;
    for n in 0..50 {
        peer.pull_space(&format!("s{n}")).await.expect("pull");
    }
    let streams = 2 + 50;
    let rounds_of = |received: &[Received]| -> Vec<Vec<String>> {
        received
            .iter()
            .filter(|frame| frame.kind() == KIND_DIGEST)
            .map(digest_streams)
            .filter(|named| named.len() > 3) // a pull names one space and the revocations
            .collect()
    };
    let received = fake
        .wait_for("ten rounds", |received| rounds_of(received).len() >= 10)
        .await;
    for named in rounds_of(&received) {
        assert_eq!(named.len(), streams, "one round, one DIGEST: {named:?}");
    }
    let rounds = peer.counters().await.dial_rounds;
    let digests = fake
        .received()
        .iter()
        .filter(|frame| frame.kind() == KIND_DIGEST)
        .count();
    // 50 pulls on opening, one DIGEST per round (and the round in flight).
    assert!(
        digests <= 50 + usize::try_from(rounds).expect("rounds") + 1,
        "{digests} DIGESTs for {rounds} rounds"
    );
    let _ = peer.close().await;
    fake.stop();
}

/// A Rust seed answers a dial-only peer of 50 spaces round after round at the base period
/// without refusing one for its per-member pace.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rust_seed_answers_twenty_rounds_of_fifty_spaces_without_pacing() {
    let network = MemoryNetwork::new();
    let address = "127.0.0.1:7804";
    let hub = seed(&network, address).await;
    let period = Duration::from_millis(300);
    let peer = client(address, Arc::new(network.dialer()), period).await;
    for n in 0..50 {
        peer.pull_space(&format!("s{n}")).await.expect("pull");
    }
    // The 50 pulls on opening outrun the seed's burst; let its pace fill again.
    tokio::time::sleep(Duration::from_secs(5)).await;
    let paced = hub.counters().await.listen.pulls_paced;
    let start = peer.counters().await.dial_rounds;
    // The peer's own writes count as activity: its rounds stay at the base period.
    let mut n = 0;
    while peer.counters().await.dial_rounds < start + 20 {
        write(&peer, "s0", &format!("own-{n}")).await;
        n += 1;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(n < 400, "twenty rounds in 40 s");
    }
    let counters = peer.counters().await;
    assert_eq!(
        counters.dial_round_period_millis,
        u64::try_from(period.as_millis()).expect("millis"),
        "active rounds run at the base period"
    );
    assert_eq!(
        hub.counters().await.listen.pulls_paced,
        paced,
        "no round of the 20 was refused for the pace"
    );
    let _ = peer.close().await;
    let _ = hub.close().await;
}

// ------------------------------------------------------------------------------- link-ready

/// On a reconnect, a peer that pulled 50 spaces pulls them again in at most two `DIGEST`s, each
/// stream with an empty digest (send everything), the revocations with them: the pulls are packed
/// as a round packs its streams, not sent one frame per space.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fifty_spaces_cost_at_most_two_digests_on_reconnect() {
    let network = MemoryNetwork::new();
    let address = "127.0.0.1:7806";
    let fake = FakeSeed::start(&network, address, &ids_of(FOUNDING), system());
    // Rounds an hour apart: every DIGEST here is a pull.
    let peer = client(
        address,
        Arc::new(network.dialer()),
        Duration::from_secs(3600),
    )
    .await;
    for n in 0..50 {
        peer.pull_space(&format!("s{n}")).await.expect("pull");
    }
    fake.wait_for("the opening pulls", |received| {
        received
            .iter()
            .filter(|frame| frame.kind() == KIND_DIGEST)
            .count()
            >= 50
    })
    .await;
    fake.close_link(0);
    let on_reconnect = |received: &[Received]| -> Vec<Vec<String>> {
        received
            .iter()
            .filter(|frame| frame.link == 1 && frame.kind() == KIND_DIGEST)
            .map(digest_streams)
            .collect()
    };
    let wanted: Vec<String> = (0..50)
        .map(|n| format!("{STREAM_SPACE_PREFIX}s{n}"))
        .collect();
    let received = fake
        .wait_for("every space pulled again", |received| {
            let named: Vec<String> = on_reconnect(received).concat();
            wanted.iter().all(|stream| named.contains(stream))
        })
        .await;
    // Let anything still on its way arrive.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let frames = on_reconnect(&fake.received());
    assert!(
        frames.len() <= 2,
        "{} DIGESTs on link-ready for 50 spaces",
        frames.len()
    );
    let named: Vec<String> = frames.concat();
    for stream in agentspaces::wire::revocation::STREAMS {
        assert!(named.iter().any(|named| named == stream), "{stream} pulled");
    }
    // Each stream with an empty digest: the seed sends everything.
    for frame in received
        .iter()
        .filter(|frame| frame.link == 1 && frame.kind() == KIND_DIGEST)
    {
        let digests = bodies::parse_digest(frame.body()).expect("a digest");
        for (stream, digest) in digests.iter() {
            assert_eq!(
                digest.as_bytes().map(<[u8]>::len),
                Some(0),
                "{stream:?} carries an empty digest"
            );
        }
    }
    assert_eq!(peer.counters().await.dial_rounds, 0, "no round ran");
    let _ = peer.close().await;
    fake.stop();
}

/// A Rust seed answers the link-ready pulls of a peer of 50 spaces without refusing one for its
/// per-member pace.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rust_seed_paces_none_of_fifty_spaces_pulled_on_reconnect() {
    let network = MemoryNetwork::new();
    let address = "127.0.0.1:7807";
    let hub = seed(&network, address).await;
    let link = HoldingDialer::new(Arc::new(network.dialer()));
    let peer = client(address, Arc::new(link.clone()), Duration::from_secs(3600)).await;
    for n in 0..50 {
        peer.pull_space(&format!("s{n}")).await.expect("pull");
        write(&peer, &format!("s{n}"), "held").await;
    }
    // The opening pulls outrun the seed's burst; let its pace fill again.
    tokio::time::sleep(Duration::from_secs(5)).await;
    let paced = hub.counters().await.listen.pulls_paced;
    let reconnects = peer.counters().await.reconnects;
    link.close();
    within(Duration::from_secs(10), "the reconnect", || async {
        peer.counters().await.reconnects > reconnects
    })
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        hub.counters().await.listen.pulls_paced,
        paced,
        "no link-ready pull was refused for the pace"
    );
    let _ = peer.close().await;
    let _ = hub.close().await;
}

// ------------------------------------------------------------------------------- what stays

/// The pulls on link-ready and a waiting read's paced pulls still go out beside the rounds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn link_ready_pulls_and_paced_read_pulls_stay() {
    let network = MemoryNetwork::new();
    let address = "127.0.0.1:7805";
    let fake = FakeSeed::start(&network, address, &ids_of(FOUNDING), system());
    // Rounds an hour apart: every DIGEST here is a pull.
    let peer = client(
        address,
        Arc::new(network.dialer()),
        Duration::from_secs(3600),
    )
    .await;
    let pulls_of = |received: &[Received]| -> usize {
        received
            .iter()
            .filter(|frame| frame.kind() == KIND_DIGEST)
            .filter(|frame| {
                digest_streams(frame).contains(&format!("{STREAM_SPACE_PREFIX}{SPACE}"))
            })
            .count()
    };
    peer.pull_space(SPACE).await.expect("pull");
    fake.wait_for("the first pull", |received| pulls_of(received) >= 1)
        .await;
    fake.close_link(0);
    fake.wait_for("the pull on link-ready", |received| {
        received
            .iter()
            .any(|frame| frame.link == 1 && frame.kind() == KIND_DIGEST)
            && pulls_of(received) >= 2
    })
    .await;
    let before = pulls_of(&fake.received());
    let fleet = Fleet::from_peer(peer.clone());
    let tasks = fleet.space(SPACE).with_settle(Duration::from_millis(100));
    let read = tokio::spawn(async move {
        tasks
            .read(&Template::new(TYPE), Duration::from_secs(3))
            .await
    });
    fake.wait_for("a waiting read's paced pull", |received| {
        pulls_of(received) > before
    })
    .await;
    read.abort();
    assert_eq!(
        peer.counters().await.dial_rounds,
        0,
        "no round ran within the hour"
    );
    let _ = peer.close().await;
    fake.stop();
}

/// The GroupID of a group founded from `text`.
fn ids_of(text: &str) -> String {
    ids::group_id_from_founding(text.as_bytes())
}
