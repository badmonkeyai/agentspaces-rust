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

//! The dial-only peer against a scripted in-memory seed: frame robustness from the client's side
//! (the Python `test_robustness.py`), the join by GroupID (`test_founding.py`'s join path, on the
//! golden vectors), the seed failover of `connect_any` (`test_bootstrap.py`), and the peer's own
//! verbs: writes, probes, the relay hint, CHANNEL_HELLO, pipes, pulls, advertisements, and the
//! send-overflow path.

mod support;

use std::sync::Arc;
use std::time::Duration;

use agentspaces::clock::{Clock, ManualClock, SharedClock, SystemClock};
use agentspaces::group::GroupSpec;
use agentspaces::peer::{Peer, PeerError, PeerEvent};
use agentspaces::transport::Listener;
use agentspaces::transport::memory::MemoryNetwork;
use agentspaces::wire::ads::{self, AD_TYPE_AGENT_CARD};
use agentspaces::wire::bodies::{
    self, KIND_ACK, KIND_CHANNEL_HELLO, KIND_DIGEST, KIND_GROUP_AD, KIND_GROUP_AD_WANT, KIND_PING,
    KIND_PIPE_DATA, KIND_PULL_RESP, KIND_RELAY_FRAME, KIND_RUMOR, STREAM_ADS, STREAM_PEERS,
};
use agentspaces::wire::cbor::{self, Map, Value};
use agentspaces::wire::envelope::{self, Auth};
use agentspaces::wire::fold::FoldOutcome;
use agentspaces::wire::founding;
use agentspaces::wire::identity::Identity;
use agentspaces::wire::ids;
use agentspaces::wire::limits::{MAX_FRAME_AGE_MILLIS, MAX_HLC_SKEW_MILLIS};
use agentspaces::wire::records::{self, EntryWrite};
use agentspaces::wire::revocation;
use agentspaces::wire::time;
use agentspaces::wire::{cbor_array, cbor_map};
use support::{FakeSeed, PATIENCE, config, eventually, golden_identity, golden_ms, hex, s};
use tokio::sync::broadcast;

const SEED: &str = "127.0.0.1:7600";
const FOUNDING_TEXT: &str = "agentspaces-rust-peer-tests";
const TASK_TYPE: &str = "com.acme.Task#v1";

fn system() -> SharedClock {
    Arc::new(SystemClock)
}

fn text_group() -> GroupSpec {
    GroupSpec::FoundingText(FOUNDING_TEXT.to_owned())
}

fn text_group_id() -> String {
    ids::group_id_from_founding(FOUNDING_TEXT.as_bytes())
}

fn fresh() -> Identity {
    Identity::generate().expect("identity")
}

/// A seed on a fresh network and a peer joined to it by founding text, after the peer's first
/// two frames (its introduction and its revocation pull) arrived.
async fn joined() -> (MemoryNetwork, FakeSeed, Peer) {
    let network = MemoryNetwork::new();
    let seed = FakeSeed::start(&network, SEED, &text_group_id(), system());
    let peer = Peer::start(config(&network, fresh(), text_group(), &[SEED], system()))
        .await
        .expect("the peer starts");
    assert_eq!(seed.wait_kinds(0, 2).await, [KIND_RUMOR, KIND_DIGEST]);
    (network, seed, peer)
}

/// The nonces of the ACKs on `link`.
fn ack_nonces(seed: &FakeSeed, link: usize) -> Vec<i64> {
    seed.of_kind(link, KIND_ACK)
        .iter()
        .map(|ack| bodies::parse_ping(ack.body()).expect("an ACK body"))
        .collect()
}

/// Waits for the ACK of `nonce` on `link`.
async fn wait_ack(seed: &FakeSeed, link: usize, nonce: i64) {
    seed.wait_for(&format!("the ACK of {nonce}"), |received| {
        received.iter().any(|frame| {
            frame.link == link
                && frame.kind() == KIND_ACK
                && bodies::parse_ping(frame.body()) == Some(nonce)
        })
    })
    .await;
}

/// The next event matching `wanted`, within [`PATIENCE`].
async fn next_event(
    events: &mut broadcast::Receiver<PeerEvent>,
    what: &str,
    wanted: impl Fn(&PeerEvent) -> bool,
) -> PeerEvent {
    let deadline = tokio::time::Instant::now() + PATIENCE;
    loop {
        let event = tokio::time::timeout_at(deadline, events.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
            .expect("the event stream");
        if wanted(&event) {
            return event;
        }
    }
}

/// The peer advertisement a `peers` rumor carries.
fn peer_ad_of(rumor_payload: &[u8]) -> Map {
    ads::verify_signed_peer_ad(rumor_payload)
        .expect("a verified peer advertisement")
        .0
}

/// The `relay.via` hint of a peer advertisement.
fn relay_via(ad: &Map) -> Option<String> {
    ad.get("resourceHints")
        .and_then(|hints| hints.get("relay.via"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// The stream names a DIGEST asks for.
fn digest_streams(body: &[u8]) -> Vec<String> {
    bodies::parse_digest(body)
        .expect("a DIGEST body")
        .keys()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

// ------------------------------------------------------------------------------- the filter

#[tokio::test]
async fn a_replayed_frame_is_dropped_and_counted() {
    let (_network, seed, peer) = joined().await;
    let ping = seed.frame(KIND_PING, &bodies::ping_body(7), Some(peer.peer_id()));
    for _ in 0..3 {
        seed.send_raw(0, ping.clone()).await;
    }
    // A fresh stamp from the same sender is a new frame.
    seed.ping(0, 8, Some(peer.peer_id())).await;
    wait_ack(&seed, 0, 8).await;
    assert_eq!(
        ack_nonces(&seed, 0),
        [7, 8],
        "a replayed probe earns no second ACK"
    );
    assert_eq!(peer.counters().await.filter.replayed, 2);
}

#[tokio::test]
async fn stale_and_far_ahead_frames_are_dropped_quietly() {
    let (_network, seed, peer) = joined().await;
    let now = SystemClock.now_ms();
    let to = Some(peer.peer_id());
    let at = |ms: i64, nonce: i64| {
        seed.frame_stamped(
            KIND_PING,
            &bodies::ping_body(nonce),
            to,
            &seed.stamp_at(ms, 0),
        )
    };
    seed.send_raw(0, at(now - MAX_FRAME_AGE_MILLIS - 1000, 1))
        .await;
    seed.send_raw(0, at(now + MAX_HLC_SKEW_MILLIS + 60_000, 2))
        .await;
    // Within the bounds either way, answered.
    seed.send_raw(0, at(now - MAX_FRAME_AGE_MILLIS / 2, 3))
        .await;
    seed.send_raw(0, at(now + MAX_HLC_SKEW_MILLIS / 2, 4)).await;
    wait_ack(&seed, 0, 4).await;
    assert_eq!(ack_nonces(&seed, 0), [3, 4]);
    let counters = peer.counters().await;
    assert_eq!((counters.filter.stale, counters.filter.ahead), (1, 1));
    assert_eq!(counters.filter.replayed, 0);
}

#[tokio::test]
async fn kinds_this_peer_does_not_speak_are_ignored_and_counted() {
    let (_network, seed, peer) = joined().await;
    let kinds = [
        "HAVE",
        "GRAFT",
        "PRUNE",
        "BATCH",
        "SESSION_HELLO",
        "DIGEST",
        "CHANNEL_HELLO",
        "QUERY",
        "NOT_A_KIND",
    ];
    for (i, kind) in kinds.iter().enumerate() {
        let body = cbor::encode(&cbor_map! { "anything" => i });
        seed.send(0, kind, &body, Some(peer.peer_id())).await;
    }
    seed.ping(0, 9, Some(peer.peer_id())).await;
    wait_ack(&seed, 0, 9).await;
    let counters = peer.counters().await;
    assert_eq!(counters.ignored_total(), 9);
    for kind in kinds {
        assert_eq!(counters.ignored_kinds.get(kind), Some(&1), "{kind}");
    }
    assert_eq!(counters.malformed, 0);
    assert!(
        seed.kinds(0)
            .iter()
            .all(|kind| [KIND_RUMOR, KIND_DIGEST, KIND_ACK].contains(&kind.as_str())),
        "nothing answered but the probe: {:?}",
        seed.kinds(0)
    );
}

#[tokio::test]
async fn a_malformed_body_under_a_good_signature_never_stops_the_reader() {
    let (_network, seed, peer) = joined().await;
    let to = Some(peer.peer_id());
    for kind in [
        KIND_RUMOR,
        KIND_PULL_RESP,
        KIND_PING,
        KIND_PIPE_DATA,
        KIND_RELAY_FRAME,
        bodies::KIND_BLOCK_WANT,
    ] {
        seed.send(0, kind, b"\xff\x01\x02", to).await;
    }
    seed.send_raw(0, vec![1, 2, 3]).await; // not a frame at all
    seed.send_raw(0, hex("adv_frame_bad_signature")).await; // a signature that fails
    seed.ping(0, 5, to).await;
    wait_ack(&seed, 0, 5).await;
    assert_eq!(peer.counters().await.malformed, 8);
    assert!(peer.space_states("tasks").await.is_empty());
    assert!(peer.is_connected());
}

// ------------------------------------------------------------------------------- links

#[tokio::test]
async fn a_lost_link_is_redialed_and_the_peer_reintroduces_and_repulls() {
    let (_network, seed, peer) = joined().await;
    peer.pull_space("work").await.expect("pull");
    peer.pull_ads().await.expect("pull ads");
    let first = seed.wait_kinds(0, 4).await;
    assert_eq!(first, [KIND_RUMOR, KIND_DIGEST, KIND_DIGEST, KIND_DIGEST]);
    let mut events = peer.subscribe();
    // The seed drops the link: a network hiccup from the peer's point of view.
    seed.close_link(0);
    next_event(&mut events, "the loss", |e| *e == PeerEvent::Disconnected).await;
    let second = seed.wait_kinds(1, 4).await;
    assert_eq!(
        second[..4],
        [KIND_RUMOR, KIND_DIGEST, KIND_DIGEST, KIND_DIGEST],
        "re-introduced, revocations, ads, and the space pulled again"
    );
    let digests: Vec<Vec<String>> = seed
        .of_kind(1, KIND_DIGEST)
        .iter()
        .map(|digest| digest_streams(digest.body()))
        .collect();
    assert_eq!(digests[0], revocation::STREAMS);
    assert_eq!(digests[1], [STREAM_ADS]);
    assert!(digests[2].contains(&"space:work".to_owned()));
    let reconnected = next_event(&mut events, "the reconnect", |e| {
        matches!(e, PeerEvent::Reconnected { .. })
    })
    .await;
    assert_eq!(reconnected, PeerEvent::Reconnected { reconnects: 1 });
    assert_eq!(peer.counters().await.reconnects, 1);
    assert!(peer.is_connected());
    peer.close().await.expect("close");
    assert!(!peer.is_connected());
}

#[tokio::test]
async fn close_by_the_owner_is_final() {
    let (_network, seed, peer) = joined().await;
    seed.ping(0, 1, Some(peer.peer_id())).await;
    wait_ack(&seed, 0, 1).await;
    peer.close().await.expect("close");
    peer.close().await.expect("close is idempotent");
    eventually("the link to close", || async { seed.link_closed(0) }).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(seed.links(), 1, "no redial after the owner's close");
    assert_eq!(peer.counters().await.reconnects, 0);
    assert!(!peer.is_connected());
    assert!(matches!(
        peer.pull_space("work").await,
        Err(PeerError::Closed)
    ));
    assert!(matches!(
        peer.write_entry("work", TASK_TYPE, Value::Null, 1000, Map::new(), None)
            .await,
        Err(PeerError::Closed)
    ));
    assert_eq!(
        peer.members().await,
        [seed.peer_id().to_owned()],
        "reads still answer"
    );
}

#[tokio::test]
async fn a_seed_that_is_down_is_retried_until_it_listens_again() {
    let (network, seed, peer) = joined().await;
    seed.stop();
    tokio::time::sleep(Duration::from_millis(300)).await; // several refused dials
    assert_eq!(peer.counters().await.reconnects, 0);
    assert!(!peer.is_connected());
    let again = FakeSeed::start(&network, SEED, &text_group_id(), system());
    assert_eq!(
        again.wait_kinds(0, 2).await[..2],
        [KIND_RUMOR, KIND_DIGEST],
        "the peer found the seed again"
    );
    eventually("the reconnect count", || async {
        peer.counters().await.reconnects == 1
    })
    .await;
    assert!(peer.is_connected());
}

/// A seed that accepts every link and drops it at once (a `tls` seed dialed over `tcp`, as the
/// Java interop test found): each dial succeeds, so the peer must still pace its rounds by
/// `reconnect_interval` rather than redial in a loop, and a link that never carried a frame does
/// not restart the reconnect window, so the peer gives up when it runs out.
#[tokio::test]
async fn a_seed_that_drops_every_link_at_once_is_redialed_once_per_interval_then_given_up() {
    let network = MemoryNetwork::new();
    let listener = network.listen(SEED);
    let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = Arc::clone(&accepted);
    let acceptor = tokio::spawn(async move {
        while let Some(Ok(channel)) = listener.accept().await {
            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            channel.closer.close();
        }
    });
    let mut config = config(&network, fresh(), text_group(), &[SEED], system());
    config.reconnect_interval = Duration::from_millis(100);
    config.reconnect_window = Duration::from_millis(1000);
    let started = tokio::time::Instant::now();
    let peer = Peer::start(config).await.expect("each dial succeeds");
    let mut events = peer.subscribe();

    tokio::time::sleep(Duration::from_millis(500)).await;
    let early = accepted.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        (2..=7).contains(&early),
        "{early} links in 500 ms: about one per 100 ms interval, not one per round trip"
    );

    next_event(&mut events, "giving up", |e| *e == PeerEvent::GaveUp).await;
    let took = started.elapsed();
    let links = accepted.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        took >= Duration::from_millis(900),
        "gave up after {took:?}, before the 1 s window"
    );
    assert!(
        (5..=13).contains(&links),
        "{links} links over a 1 s window at a 100 ms interval"
    );
    assert!(!peer.is_connected());
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        accepted.load(std::sync::atomic::Ordering::SeqCst),
        links,
        "no dial after giving up"
    );
    peer.close().await.expect("close");
    acceptor.abort();
}

#[tokio::test]
async fn start_dials_in_order_and_fails_over_to_the_next_seed() {
    let network = MemoryNetwork::new();
    let group = text_group_id();
    let first = FakeSeed::start(&network, "127.0.0.1:7602", &group, system());
    let second = FakeSeed::start(&network, "127.0.0.1:7603", &group, system());
    let seeds = ["127.0.0.1:7601", "127.0.0.1:7602", "127.0.0.1:7603"];
    let peer = Peer::start(config(&network, fresh(), text_group(), &seeds, system()))
        .await
        .expect("the second seed accepts");
    assert_eq!(
        peer.link().map(|link| link.remote).as_deref(),
        Some(seeds[1])
    );
    assert_eq!(first.wait_kinds(0, 2).await, [KIND_RUMOR, KIND_DIGEST]);
    assert_eq!(second.links(), 0);
    // The first seed drops the link: the peer fails over to the next, not back to the first.
    first.close_link(0);
    assert_eq!(
        second.wait_kinds(0, 2).await[..2],
        [KIND_RUMOR, KIND_DIGEST],
        "re-introduced at the next seed"
    );
    eventually("the reconnect", || async {
        peer.counters().await.reconnects == 1
    })
    .await;
    assert_eq!(
        peer.link().map(|link| link.remote).as_deref(),
        Some(seeds[2])
    );
    assert_eq!(first.links(), 1);
}

#[tokio::test]
async fn start_fails_when_no_seed_accepts_and_tries_each_once() {
    let network = MemoryNetwork::new();
    let seeds = ["127.0.0.1:7601", "127.0.0.1:7602", "127.0.0.1:7601"];
    let refused = Peer::start(config(&network, fresh(), text_group(), &seeds, system())).await;
    let Err(PeerError::NoSeedAccepted(failures)) = refused else {
        panic!("no seed accepts: {refused:?}");
    };
    assert_eq!(
        failures.matches("tcp://127.0.0.1:7601").count(),
        1,
        "{failures}"
    );
    assert_eq!(
        failures.matches("tcp://127.0.0.1:7602").count(),
        1,
        "{failures}"
    );
    let none = Peer::start(config(&network, fresh(), text_group(), &[], system())).await;
    assert!(matches!(none, Err(PeerError::NoSeeds)));
    let unserved = Peer::start(config(
        &network,
        fresh(),
        text_group(),
        &["quic://127.0.0.1:7601"],
        system(),
    ))
    .await;
    assert!(
        matches!(unserved, Err(PeerError::NoSeeds)),
        "no dialer serves quic"
    );
}

#[tokio::test]
async fn a_stalled_link_overflows_and_closes_instead_of_blocking() {
    let network = MemoryNetwork::new();
    let listener = network.listen(SEED);
    let mut config = config(&network, fresh(), text_group(), &[SEED], system());
    config.send_queue_bytes = 8 * 1024;
    config.send_stall_timeout = Duration::from_millis(300);
    let peer = Peer::start(config).await.expect("start");
    // The far end accepts and never reads.
    let stalled = listener.accept().await.expect("a link").expect("a channel");
    let mut events = peer.subscribe();
    let to = fresh().peer_id().to_owned();
    let mut refused = None;
    for i in 0..4096 {
        let sent =
            tokio::time::timeout(PATIENCE, peer.send_pipe(&to, "aspace:cap/test", &[0; 512]))
                .await
                .expect("a send never waits on the link");
        if let Err(error) = sent {
            refused = Some((i, error));
            break;
        }
    }
    let (sends, error) = refused.expect("the queue overflows");
    assert!(matches!(error, PeerError::SendOverflow), "{error:?}");
    assert!(sends < 600, "overflowed after {sends} sends");
    // The pump finds no taker for the send stall timeout: the far end stopped reading.
    next_event(&mut events, "the loss", |e| *e == PeerEvent::Disconnected).await;
    assert!(stalled.closer.is_closed(), "the stalled link is closed");
    let counters = peer.counters().await;
    assert_eq!(counters.send_overflows, 1);
    assert!(counters.send_refused >= 1);
    assert!(
        counters.send_dropped >= 1,
        "what the stalled link held is counted"
    );
    network.unlisten(SEED);
    drop(listener);
    // The actor still answers.
    assert!(peer.members().await.is_empty());
}

// ------------------------------------------------------------------------------- the join by id

/// A joiner holding only the golden founding GroupID, on the golden identity (the golden frames
/// are addressed to it), its clock one second past the golden stamp.
fn joiner(network: &MemoryNetwork, timeout: Duration) -> (FakeSeed, agentspaces::peer::PeerConfig) {
    let clock = ManualClock::new(golden_ms() + 1000);
    let shared: SharedClock = Arc::new(clock);
    let group = s("founding_group_id");
    let seed = FakeSeed::start(network, SEED, group, Arc::clone(&shared));
    let mut config = config(
        network,
        golden_identity(),
        GroupSpec::Join(format!("aspace://{group}")),
        &[SEED],
        shared,
    );
    config.join_timeout = timeout;
    (seed, config)
}

/// Waits for the joiner's GROUP_AD_WANT and checks it: unaddressed, for the wanted group, empty.
async fn the_want(seed: &FakeSeed) {
    let received = seed
        .wait_for("the GROUP_AD_WANT", |received| {
            received.iter().any(|r| r.kind() == KIND_GROUP_AD_WANT)
        })
        .await;
    let want = received
        .iter()
        .find(|r| r.kind() == KIND_GROUP_AD_WANT)
        .expect("the want");
    assert_eq!(want.to(), None, "the want is unaddressed");
    assert_eq!(want.text("group"), Some(s("founding_group_id")));
    assert!(want.body().is_empty());
    assert_eq!(want.auth, Auth::Signed);
    assert!(
        received.iter().all(|r| r.kind() != KIND_RUMOR),
        "nothing is introduced before the founding verifies"
    );
}

#[tokio::test]
async fn the_golden_group_ad_completes_a_join_by_id() {
    let network = MemoryNetwork::new();
    let (seed, config) = joiner(&network, Duration::from_secs(5));
    let start = tokio::spawn(Peer::start(config));
    the_want(&seed).await;
    seed.send_raw(0, hex("group_ad_frame_cbor")).await;
    let peer = start.await.expect("the join task").expect("joined");
    assert_eq!(peer.group_id(), s("founding_group_id"));
    let expected = cbor::decode(&hex("signed_group_ad_cbor"))
        .ok()
        .and_then(Value::into_map);
    assert_eq!(peer.founding().await, expected);
    let received = seed
        .wait_for("the introduction", |received| {
            received
                .iter()
                .any(|r| r.stream().as_deref() == Some(STREAM_PEERS))
        })
        .await;
    let kinds: Vec<&str> = received.iter().map(|r| r.kind()).collect();
    let rumor = kinds
        .iter()
        .position(|k| *k == KIND_RUMOR)
        .expect("a rumor");
    assert!(kinds[..rumor].iter().all(|k| *k == KIND_GROUP_AD_WANT));
    seed.wait_kinds(0, rumor + 2).await;
    assert_eq!(
        seed.kinds(0)[rumor + 1],
        KIND_DIGEST,
        "then the revocations"
    );
}

#[tokio::test]
async fn hostile_group_ads_are_ignored_and_the_genuine_one_still_completes_the_join() {
    let network = MemoryNetwork::new();
    let (seed, config) = joiner(&network, Duration::from_secs(5));
    let start = tokio::spawn(Peer::start(config));
    the_want(&seed).await;
    let golden = golden_identity();
    for (logical, name) in [
        "adv_group_ad_wrong_id_cbor",
        "adv_group_ad_forged_signature_cbor",
    ]
    .into_iter()
    .enumerate()
    {
        // Stamped before the genuine answer: a sender never reuses a stamp.
        let stamp = format!("{}:{logical}:{}", golden_ms(), s("peer_id"));
        let env = envelope::envelope(
            s("founding_group_id"),
            KIND_GROUP_AD,
            s("peer_id"),
            &stamp,
            &hex(name),
            Some(s("peer_id")),
        );
        seed.send_raw(0, envelope::encode_frame(&env, &golden))
            .await;
    }
    // A probe behind them proves they were handled.
    seed.ping(0, 1, Some(s("peer_id"))).await;
    wait_ack(&seed, 0, 1).await;
    assert!(!start.is_finished(), "a hostile answer completes nothing");
    assert!(seed.received().iter().all(|r| r.kind() != KIND_RUMOR));
    seed.send_raw(0, hex("group_ad_frame_cbor")).await;
    let peer = start.await.expect("the join task").expect("joined");
    assert!(peer.founding().await.is_some());
    // The seed addressed the joiner before it joined: the introduction carries the relay hint.
    let received = seed
        .wait_for("the introduction", |received| {
            received
                .iter()
                .any(|r| r.stream().as_deref() == Some(STREAM_PEERS))
        })
        .await;
    let intro = received
        .iter()
        .find_map(|r| r.rumor().filter(|rumor| rumor.stream_id == STREAM_PEERS))
        .expect("the introduction");
    assert_eq!(
        relay_via(&peer_ad_of(&intro.payload)).as_deref(),
        Some(seed.peer_id())
    );
}

#[tokio::test]
async fn a_genuine_document_for_another_group_does_not_complete_the_join() {
    let network = MemoryNetwork::new();
    let (seed, config) = joiner(&network, Duration::from_millis(600));
    let other = founding::found_group(
        &golden_identity(),
        "other-fleet",
        "OPEN",
        "LEASE_RACE",
        3,
        "PT1S",
        "2026-01-01T00:00:00Z",
        "PT24H",
    )
    .expect("founded");
    let other_id = founding::verify_signed_group_ad(&Value::Map(other.clone()));
    assert!(other_id.is_some() && other_id.as_deref() != Some(s("founding_group_id")));
    let start = tokio::spawn(Peer::start(config));
    the_want(&seed).await;
    let body = bodies::group_ad_body(&other).expect("a body");
    seed.send(0, KIND_GROUP_AD, &body, Some(s("peer_id"))).await;
    let outcome = start.await.expect("the join task");
    assert!(
        matches!(outcome, Err(PeerError::JoinTimeout { ref group, .. }) if group == s("founding_group_id")),
        "{outcome:?}"
    );
    assert!(seed.received().iter().all(|r| r.kind() != KIND_RUMOR));
}

#[tokio::test]
async fn a_join_by_id_times_out_without_a_verified_answer_and_closes_its_link() {
    let network = MemoryNetwork::new();
    let (seed, config) = joiner(&network, Duration::from_millis(300));
    let outcome = Peer::start(config).await;
    assert!(
        matches!(outcome, Err(PeerError::JoinTimeout { .. })),
        "{outcome:?}"
    );
    the_want(&seed).await;
    eventually("the link to close", || async { seed.link_closed(0) }).await;
}

#[tokio::test]
async fn a_founding_document_is_verified_locally_and_joined_without_asking() {
    let network = MemoryNetwork::new();
    let seed = FakeSeed::start(&network, SEED, s("founding_group_id"), system());
    let document = GroupSpec::FoundingDocument(hex("signed_group_ad_cbor"));
    let peer = Peer::start(config(&network, fresh(), document, &[SEED], system()))
        .await
        .expect("joined");
    assert_eq!(peer.group_id(), s("founding_group_id"));
    assert_eq!(seed.wait_kinds(0, 2).await, [KIND_RUMOR, KIND_DIGEST]);
    assert!(peer.founding().await.is_some());
    let forged = GroupSpec::FoundingDocument(hex("adv_group_ad_forged_signature_cbor"));
    let refused = Peer::start(config(&network, fresh(), forged, &[SEED], system())).await;
    assert!(matches!(refused, Err(PeerError::InvalidFounding)));
    let empty = GroupSpec::Join("aspace://".to_owned());
    let refused = Peer::start(config(&network, fresh(), empty, &[SEED], system())).await;
    assert!(matches!(refused, Err(PeerError::InvalidGroup(_))));
}

// ------------------------------------------------------------------------------- verbs

#[tokio::test]
async fn a_write_is_folded_locally_and_rumored_with_the_wire_builders_bytes() {
    let network = MemoryNetwork::new();
    let identity = fresh();
    let seed = FakeSeed::start(&network, SEED, &text_group_id(), system());
    let peer = Peer::start(config(
        &network,
        identity.clone(),
        text_group(),
        &[SEED],
        system(),
    ))
    .await
    .expect("start");
    let mut events = peer.subscribe();
    let payload = cbor_map! { "topic" => "golden vectors", "priority" => 3 };
    let tags: Map = [("lane", "a")].into_iter().collect();
    let entry_id = peer
        .write_entry(
            "tasks",
            TASK_TYPE,
            payload.clone(),
            60_000,
            tags.clone(),
            None,
        )
        .await
        .expect("write");
    let folded = next_event(&mut events, "the local fold", |e| {
        matches!(e, PeerEvent::StateFolded { .. })
    })
    .await;
    assert_eq!(
        folded,
        PeerEvent::StateFolded {
            space: "tasks".to_owned(),
            entry_id: entry_id.clone(),
            outcome: FoldOutcome::Applied,
        }
    );
    let received = seed
        .wait_for("the write's rumor", |received| {
            received
                .iter()
                .any(|r| r.stream().as_deref() == Some("space:tasks"))
        })
        .await;
    let rumor = received
        .iter()
        .find_map(|r| r.rumor().filter(|rumor| rumor.stream_id == "space:tasks"))
        .expect("the rumor");
    assert_eq!(rumor.item_id, format!("w:{entry_id}"));
    assert_eq!(rumor.hops_remaining, 6);
    // Rebuild the write from what the state says it is: the wire builders give the same bytes.
    let delta = cbor::decode(&rumor.payload).expect("a delta");
    let state = delta.get("state").and_then(Value::as_map).expect("a state");
    let record = state
        .get("record")
        .and_then(Value::as_map)
        .expect("a record");
    let issued = record
        .get("issued")
        .and_then(Value::as_str)
        .expect("issued");
    let expires = record
        .get("lease")
        .and_then(|lease| lease.get("expiresAtMillis"))
        .and_then(Value::as_i64)
        .expect("a lease");
    let space_id = ids::space_id_local(&format!("{}/tasks", text_group_id()));
    let encoded = cbor::encode(&payload);
    let write = EntryWrite {
        entry_id: &entry_id,
        space_id: &space_id,
        type_name: TASK_TYPE,
        payload: Some(&encoded),
        payload_ref: None,
        tags: Some(&tags),
        key_epoch: None,
        issued,
        expires_at_millis: expires,
        counter: 1,
    };
    let expected = records::entry_delta(&write, &identity, "rust", None).expect("a delta");
    assert_eq!(rumor.payload, expected);
    assert_eq!(
        record.get("issuer").and_then(Value::as_str),
        Some(identity.agent("rust").as_str())
    );
    let states = peer.space_states("tasks").await;
    assert_eq!(states.len(), 1);
    assert_eq!(
        states[0]
            .get("record")
            .and_then(|r| r.get("entryId"))
            .and_then(Value::as_str),
        Some(entry_id.as_str())
    );
    assert_eq!(
        peer.payload_of("tasks", &entry_id).await,
        Some(encoded),
        "the payload reads back"
    );
}

#[tokio::test]
async fn an_agent_write_is_agent_signed_and_folds() {
    let network = MemoryNetwork::new();
    let identity = fresh();
    let seed = FakeSeed::start(&network, SEED, &text_group_id(), system());
    let peer = Peer::start(config(
        &network,
        identity.clone(),
        text_group(),
        &[SEED],
        system(),
    ))
    .await
    .expect("start");
    let issued = time::instant_iso(SystemClock.now_ms() - 60_000);
    let agent = identity
        .subordinate("worker", &issued, "PT24H", None)
        .expect("an agent");
    let entry_id = peer
        .write_entry(
            "tasks",
            TASK_TYPE,
            cbor_map! { "topic" => "agent" },
            60_000,
            Map::new(),
            Some(&agent),
        )
        .await
        .expect("write");
    let states = peer.space_states("tasks").await;
    assert_eq!(states.len(), 1, "the agent-signed state folded");
    assert_eq!(
        states[0].get("signer").and_then(Value::as_str),
        Some(agent.agent_id())
    );
    let received = seed
        .wait_for("the write's rumor", |received| {
            received
                .iter()
                .any(|r| r.stream().as_deref() == Some("space:tasks"))
        })
        .await;
    let rumor = received
        .iter()
        .find_map(|r| r.rumor().filter(|rumor| rumor.stream_id == "space:tasks"))
        .expect("the rumor");
    assert_eq!(rumor.item_id, format!("w:{entry_id}"));
    // A foreign agent is refused before anything is signed.
    let stranger = fresh()
        .subordinate("worker", &issued, "PT24H", None)
        .expect("an agent");
    let refused = peer
        .write_entry(
            "tasks",
            TASK_TYPE,
            Value::Null,
            60_000,
            Map::new(),
            Some(&stranger),
        )
        .await;
    assert!(
        matches!(refused, Err(PeerError::ForeignAgent(_))),
        "{refused:?}"
    );
    let refused = peer
        .write_entry("tasks", TASK_TYPE, Value::Null, 0, Map::new(), None)
        .await;
    assert!(matches!(refused, Err(PeerError::InvalidArgument(_))));
}

#[tokio::test]
async fn a_ping_gets_an_ack_with_its_nonce() {
    let (_network, seed, peer) = joined().await;
    seed.ping(0, 42, Some(peer.peer_id())).await;
    wait_ack(&seed, 0, 42).await;
    let ack = seed.of_kind(0, KIND_ACK).remove(0);
    let body = cbor::decode(ack.body()).expect("an ACK body");
    assert_eq!(body.get("nonce").and_then(Value::as_i64), Some(42));
    assert_eq!(body.get("onBehalf"), Some(&Value::Null));
    // Addressed to the prober, as Java answers `send(group, from, ACK)`.
    assert_eq!(ack.to(), Some(seed.peer_id()));
    assert_eq!(ack.auth, Auth::Signed);
    assert_eq!(peer.reachable().await, [seed.peer_id().to_owned()]);
    assert_eq!(peer.members().await, [seed.peer_id().to_owned()]);
}

#[tokio::test]
async fn relay_via_appears_in_the_reintroduction_once_the_seed_is_learned() {
    let (_network, seed, peer) = joined().await;
    assert_eq!(peer.seed_peer().await, None);
    // An unaddressed frame does not name the seed.
    seed.ping(0, 1, None).await;
    wait_ack(&seed, 0, 1).await;
    assert_eq!(peer.seed_peer().await, None);
    seed.ping(0, 2, Some(peer.peer_id())).await;
    wait_ack(&seed, 0, 2).await;
    assert_eq!(peer.seed_peer().await.as_deref(), Some(seed.peer_id()));
    let intros: Vec<Map> = seed
        .of_kind(0, KIND_RUMOR)
        .iter()
        .filter_map(|r| r.rumor())
        .filter(|rumor| rumor.stream_id == STREAM_PEERS)
        .map(|rumor| peer_ad_of(&rumor.payload))
        .collect();
    assert_eq!(intros.len(), 2, "introduced, then again with the hint");
    assert_eq!(relay_via(&intros[0]), None);
    assert_eq!(relay_via(&intros[1]).as_deref(), Some(seed.peer_id()));
    // A third probe from the same seed changes nothing.
    seed.ping(0, 3, Some(peer.peer_id())).await;
    wait_ack(&seed, 0, 3).await;
    assert_eq!(
        seed.of_kind(0, KIND_RUMOR).len(),
        2,
        "the seed is learned once"
    );
}

#[tokio::test]
async fn channel_hello_goes_once_on_an_attested_link_and_bare_frames_are_accepted() {
    let network = MemoryNetwork::new();
    let identity = fresh();
    let seed = FakeSeed::start(&network, SEED, &text_group_id(), system());
    let mut config = config(&network, identity.clone(), text_group(), &[SEED], system());
    let mut dialer = network.dialer();
    dialer.attest_as = Some((seed.peer_id().to_owned(), identity.peer_id().to_owned()));
    config.dialers = vec![Arc::new(dialer)];
    let peer = Peer::start(config).await.expect("start");
    assert_eq!(
        peer.link().and_then(|link| link.attested).as_deref(),
        Some(seed.peer_id())
    );
    assert_eq!(
        seed.wait_kinds(0, 3).await,
        [KIND_RUMOR, KIND_CHANNEL_HELLO, KIND_DIGEST]
    );
    let hello = seed.of_kind(0, KIND_CHANNEL_HELLO).remove(0);
    assert_eq!(hello.to(), Some(seed.peer_id()));
    assert_eq!(hello.auth, Auth::Signed);
    let body = bodies::parse_channel_hello(hello.body()).expect("a hello body");
    assert!(body.accepts_bare);
    assert_eq!(body.attested_remote, seed.peer_id());
    // A bare frame from the attested seed is accepted (and the re-introduction it causes sends
    // no second hello).
    let stamp = seed.stamp();
    let bare = envelope::encode_bare_frame(&seed.envelope(
        KIND_PING,
        &bodies::ping_body(11),
        Some(peer.peer_id()),
        &stamp,
    ));
    seed.send_raw(0, bare).await;
    wait_ack(&seed, 0, 11).await;
    // A bare frame claiming another sender is refused.
    let impostor = fresh();
    let env = envelope::envelope(
        &text_group_id(),
        KIND_PING,
        impostor.peer_id(),
        &format!("{}:0:{}", SystemClock.now_ms(), impostor.peer_id()),
        &bodies::ping_body(12),
        Some(peer.peer_id()),
    );
    seed.send_raw(0, envelope::encode_bare_frame(&env)).await;
    seed.ping(0, 13, Some(peer.peer_id())).await;
    wait_ack(&seed, 0, 13).await;
    assert_eq!(ack_nonces(&seed, 0), [11, 13]);
    let counters = peer.counters().await;
    assert_eq!(counters.attested_frames, 1);
    assert_eq!(counters.malformed, 1);
    assert_eq!(
        seed.of_kind(0, KIND_CHANNEL_HELLO).len(),
        1,
        "once per link"
    );
    assert!(
        seed.received().iter().all(|r| r.auth == Auth::Signed),
        "the peer keeps signing"
    );
}

#[tokio::test]
async fn pipes_reach_subscribers_and_go_through_the_seed_to_other_members() {
    let (_network, seed, peer) = joined().await;
    let mut events = peer.subscribe();
    let to = Some(peer.peer_id());
    seed.send(
        0,
        KIND_PIPE_DATA,
        &bodies::pipe_data_body("aspace:cap/echo", b"hi"),
        to,
    )
    .await;
    let pipe = next_event(&mut events, "the pipe", |e| {
        matches!(e, PeerEvent::Pipe { .. })
    })
    .await;
    assert_eq!(
        pipe,
        PeerEvent::Pipe {
            from: seed.peer_id().to_owned(),
            capability: "aspace:cap/echo".to_owned(),
            payload: b"hi".to_vec(),
        }
    );
    // A member behind the seed reaches this peer inside a RELAY_FRAME.
    let third = fresh();
    let inner = envelope::encode_frame(
        &envelope::envelope(
            &text_group_id(),
            KIND_PIPE_DATA,
            third.peer_id(),
            &format!("{}:0:{}", SystemClock.now_ms(), third.peer_id()),
            &bodies::pipe_data_body("aspace:cap/echo", b"via"),
            to,
        ),
        &third,
    );
    let relay = bodies::relay_frame_body(peer.peer_id(), &inner, None, None);
    seed.send(0, KIND_RELAY_FRAME, &relay, to).await;
    let pipe = next_event(&mut events, "the relayed pipe", |e| {
        matches!(e, PeerEvent::Pipe { .. })
    })
    .await;
    assert!(matches!(pipe, PeerEvent::Pipe { ref from, .. } if from == third.peer_id()));
    assert_eq!(peer.counters().await.relayed_in, 1);
    assert!(peer.members().await.contains(&third.peer_id().to_owned()));
    assert_eq!(
        peer.reachable().await,
        [seed.peer_id().to_owned()],
        "a relayed frame says nothing about reaching its origin"
    );
    // This peer's frame to that member goes through the seed; one to the seed goes direct.
    peer.send_pipe(third.peer_id(), "aspace:cap/echo", b"back")
        .await
        .expect("send");
    peer.send_pipe(seed.peer_id(), "aspace:cap/echo", b"direct")
        .await
        .expect("send");
    seed.wait_for("the pipes", |received| {
        received.iter().any(|r| r.kind() == KIND_RELAY_FRAME)
            && received.iter().any(|r| r.kind() == KIND_PIPE_DATA)
    })
    .await;
    let carried = seed.of_kind(0, KIND_RELAY_FRAME).remove(0);
    assert_eq!(carried.to(), Some(seed.peer_id()));
    let relay = bodies::parse_relay_frame(carried.body()).expect("a relay body");
    assert_eq!(relay.target, third.peer_id());
    let inner = envelope::decode_frame(&relay.frame).expect("a signed inner frame");
    assert_eq!(
        inner.get("to").and_then(Value::as_str),
        Some(third.peer_id())
    );
    assert_eq!(
        inner.get("from").and_then(Value::as_str),
        Some(peer.peer_id())
    );
    let direct = seed.of_kind(0, KIND_PIPE_DATA).remove(0);
    assert_eq!(direct.to(), Some(seed.peer_id()));
    assert_eq!(peer.counters().await.relayed_out, 1);
    // A relay signal is kept, not delivered.
    let signal = bodies::relay_signal_body(third.peer_id(), seed.peer_id(), "unreachable");
    seed.send(0, KIND_PIPE_DATA, &signal, to).await;
    eventually("the relay signal", || async {
        peer.relay_signals().await.len() == 1
    })
    .await;
}

#[tokio::test]
async fn a_pull_response_folds_golden_claims_before_states() {
    let network = MemoryNetwork::new();
    let clock: SharedClock = Arc::new(ManualClock::new(golden_ms()));
    let golden_group = s("group_id");
    let seed = FakeSeed::start(&network, SEED, golden_group, Arc::clone(&clock));
    let group = GroupSpec::FoundingText("research-fleet-demo-v1".to_owned());
    let peer = Peer::start(config(&network, fresh(), group, &[SEED], clock))
        .await
        .expect("start");
    assert_eq!(peer.group_id(), golden_group);
    peer.pull_space("tasks").await.expect("pull");
    seed.wait_kinds(0, 3).await;
    let mut events = peer.subscribe();
    // The completion folds only after its claim: the claims of a sync go first.
    let complete = cbor::decode(&hex("delta_agent_complete_cbor"))
        .ok()
        .and_then(Value::into_map)
        .expect("a delta");
    let entry = complete
        .get("claimEntry")
        .and_then(Value::as_str)
        .expect("an entry")
        .to_owned();
    let claim = complete.get("claim").cloned().expect("a claim");
    let state = complete.get("state").cloned().expect("a state");
    let mut claims = Map::new();
    claims.insert(entry.as_str(), claim);
    let sync = cbor::encode(&cbor_map! { "states" => cbor_array![state], "claims" => claims });
    let mut deltas = Map::new();
    deltas.insert("space:tasks", sync);
    seed.send(
        0,
        KIND_PULL_RESP,
        &bodies::pull_resp_body(&deltas),
        Some(peer.peer_id()),
    )
    .await;
    let claimed = next_event(&mut events, "the claim", |e| {
        matches!(e, PeerEvent::ClaimFolded { .. })
    })
    .await;
    assert_eq!(
        claimed,
        PeerEvent::ClaimFolded {
            space: "tasks".to_owned(),
            entry_id: entry.clone(),
        }
    );
    let folded = next_event(&mut events, "the state", |e| {
        matches!(e, PeerEvent::StateFolded { .. })
    })
    .await;
    assert_eq!(
        folded,
        PeerEvent::StateFolded {
            space: "tasks".to_owned(),
            entry_id: entry.clone(),
            outcome: FoldOutcome::Applied,
        }
    );
    let states = peer.space_states("tasks").await;
    assert_eq!(states.len(), 1);
    assert_eq!(states[0].get("completed"), Some(&Value::Bool(true)));
    let claims = peer.space_claims("tasks").await;
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].0, entry);
    // The golden write of another space's id is refused by the space binding (in a space this
    // peer opened: data for one it never opened is not folded at all).
    peer.pull_space("other").await.expect("pull");
    let write = cbor::decode(&hex("delta_cbor")).expect("a delta");
    let mut deltas = Map::new();
    deltas.insert(
        "space:other",
        cbor::encode(&cbor_map! { "states" => cbor_array![write.get("state").cloned()] }),
    );
    seed.send(
        0,
        KIND_PULL_RESP,
        &bodies::pull_resp_body(&deltas),
        Some(peer.peer_id()),
    )
    .await;
    let refused = next_event(&mut events, "the refusal", |e| {
        matches!(e, PeerEvent::StateFolded { .. })
    })
    .await;
    assert!(
        matches!(refused, PeerEvent::StateFolded { ref space, outcome: FoldOutcome::Refused(_), .. } if space == "other"),
        "{refused:?}"
    );
    assert!(peer.space_states("other").await.is_empty());
}

#[tokio::test]
async fn cards_are_live_verified_and_unrevoked() {
    let network = MemoryNetwork::new();
    let now = time::parse_instant_millis("2026-06-01T00:00:00Z").expect("an instant");
    let clock: SharedClock = Arc::new(ManualClock::new(now));
    let golden_group = s("group_id");
    let seed = FakeSeed::start(&network, SEED, golden_group, Arc::clone(&clock));
    let group = GroupSpec::FoundingText("research-fleet-demo-v1".to_owned());
    let identity = fresh();
    let peer = Peer::start(config(&network, identity.clone(), group, &[SEED], clock))
        .await
        .expect("start");
    seed.wait_kinds(0, 2).await;
    let mut events = peer.subscribe();
    let golden = golden_identity();
    let card = |identity: &Identity, name: &str| {
        ads::agent_card(
            golden_group,
            identity,
            name,
            "2026-06-01T00:00:00Z",
            "PT10M",
            name,
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
        .expect("a card")
    };
    // This peer's own card, published on the ads stream.
    let own = card(&identity, "scout");
    peer.publish_ad(AD_TYPE_AGENT_CARD, own.clone())
        .await
        .expect("publish");
    let received = seed
        .wait_for("the ad rumor", |received| {
            received
                .iter()
                .any(|r| r.stream().as_deref() == Some(STREAM_ADS))
        })
        .await;
    let rumor = received
        .iter()
        .find_map(|r| r.rumor().filter(|rumor| rumor.stream_id == STREAM_ADS))
        .expect("the rumor");
    let id = own.get("id").and_then(Value::as_str).expect("an id");
    assert_eq!(rumor.item_id, format!("{id}:{now}"));
    let stored = cbor::decode(&rumor.payload).expect("a stored ad");
    assert!(ads::verify_stored_ad(&stored, now).is_some());
    // Two golden cards pulled with the golden revocation of the golden peer's `python`.
    let stored: Vec<Value> = ["python", "worker"]
        .iter()
        .map(|name| {
            Value::Map(ads::stored_ad(
                AD_TYPE_AGENT_CARD,
                &card(&golden, name),
                &golden,
            ))
        })
        .collect();
    let revocations = cbor::encode(&cbor_array![
        cbor::decode(&hex("signed_credential_revocation_agent_cbor")).expect("a revocation")
    ]);
    let mut deltas = Map::new();
    deltas.insert(STREAM_ADS, cbor::encode(&cbor_map! { "ads" => stored }));
    deltas.insert(revocation::CREDENTIAL_STREAM, revocations);
    seed.send(
        0,
        KIND_PULL_RESP,
        &bodies::pull_resp_body(&deltas),
        Some(peer.peer_id()),
    )
    .await;
    for _ in 0..2 {
        next_event(&mut events, "the pulled cards", |e| {
            matches!(e, PeerEvent::AdAccepted { .. })
        })
        .await;
    }
    eventually("the revocation", || async {
        peer.is_revoked(&golden.agent("python")).await
    })
    .await;
    let mut agents: Vec<String> = peer
        .cards()
        .await
        .iter()
        .filter_map(|card| card.get("agent").and_then(Value::as_str).map(str::to_owned))
        .collect();
    agents.sort();
    let mut expected = vec![golden.agent("worker"), identity.agent("scout")];
    expected.sort();
    assert_eq!(agents, expected, "the revoked agent's card is dropped");
    assert_eq!(peer.ads(AD_TYPE_AGENT_CARD).await.len(), 2);
}

#[tokio::test]
async fn the_self_advertisement_is_re_leased_on_its_interval() {
    let network = MemoryNetwork::new();
    let seed = FakeSeed::start(&network, SEED, &text_group_id(), system());
    let mut config = config(&network, fresh(), text_group(), &[SEED], system());
    config.peer_ad_interval = Duration::from_millis(100);
    let _peer = Peer::start(config).await.expect("start");
    let received = seed
        .wait_for("three introductions", |received| {
            received
                .iter()
                .filter(|r| r.stream().as_deref() == Some(STREAM_PEERS))
                .count()
                >= 3
        })
        .await;
    let items: Vec<String> = received
        .iter()
        .filter_map(|r| r.rumor())
        .filter(|rumor| rumor.stream_id == STREAM_PEERS)
        .map(|rumor| rumor.item_id)
        .collect();
    let mut distinct = items.clone();
    distinct.dedup();
    assert_eq!(distinct, items, "each re-lease is a new item");
    assert!(items.iter().all(|item| item.starts_with("peer:")));
}

#[tokio::test]
async fn a_peer_gives_up_when_the_reconnect_window_runs_out() {
    let network = MemoryNetwork::new();
    let seed = FakeSeed::start(&network, SEED, &text_group_id(), system());
    let mut config = config(&network, fresh(), text_group(), &[SEED], system());
    config.reconnect_window = Duration::from_millis(200);
    let peer = Peer::start(config).await.expect("start");
    seed.wait_kinds(0, 2).await;
    let mut events = peer.subscribe();
    seed.stop();
    next_event(&mut events, "giving up", |e| *e == PeerEvent::GaveUp).await;
    assert!(!peer.is_connected());
    assert_eq!(peer.counters().await.reconnects, 0);
    // A pull without a link is not an error; a pipe is.
    peer.pull_space("work")
        .await
        .expect("a pull waits for a link");
    let to = seed.peer_id().to_owned();
    assert!(matches!(
        peer.send_pipe(&to, "aspace:cap/test", b"x").await,
        Err(PeerError::NotConnected)
    ));
}

#[tokio::test]
async fn writes_without_a_link_wait_and_go_out_after_the_reintroduction() {
    let (network, seed, peer) = joined().await;
    seed.stop();
    eventually("the loss", || async { !peer.is_connected() }).await;
    let entry_id = peer
        .write_entry(
            "tasks",
            TASK_TYPE,
            cbor_map! { "topic" => "held" },
            60_000,
            Map::new(),
            None,
        )
        .await
        .expect("a write without a link is held");
    assert_eq!(peer.space_states("tasks").await.len(), 1, "folded at once");
    let again = FakeSeed::start(&network, SEED, &text_group_id(), system());
    let received = again
        .wait_for("the held write", |received| {
            received
                .iter()
                .any(|r| r.stream().as_deref() == Some("space:tasks"))
        })
        .await;
    let kinds: Vec<&str> = received.iter().map(|r| r.kind()).collect();
    assert_eq!(kinds[..2], [KIND_RUMOR, KIND_DIGEST], "introduced first");
    let rumor = received
        .iter()
        .find_map(|r| r.rumor().filter(|rumor| rumor.stream_id == "space:tasks"))
        .expect("the rumor");
    assert_eq!(rumor.item_id, format!("w:{entry_id}"));
    assert_eq!(peer.counters().await.outbox_dropped, 0);
}

#[tokio::test]
async fn a_large_payload_travels_as_a_block_and_is_fetched_on_demand() {
    let (network, seed, writer) = joined().await;
    let big = Value::Bytes(vec![7; 70 * 1024]);
    let encoded = cbor::encode(&big);
    let cid = bodies::block_cid(&encoded);
    let entry_id = writer
        .write_entry("files", "com.acme.Blob#v1", big, 60_000, Map::new(), None)
        .await
        .expect("write");
    assert_eq!(
        writer.payload_of("files", &entry_id).await,
        Some(encoded.clone())
    );
    assert_eq!(writer.block(&cid).await, Some(encoded.clone()));
    // The rumor carries the reference, not the bytes.
    let received = seed
        .wait_for("the write's rumor", |received| {
            received
                .iter()
                .any(|r| r.stream().as_deref() == Some("space:files"))
        })
        .await;
    let rumor = received
        .iter()
        .find_map(|r| r.rumor().filter(|rumor| rumor.stream_id == "space:files"))
        .expect("the rumor");
    let delta = cbor::decode(&rumor.payload).expect("a delta");
    let record = delta
        .get("state")
        .and_then(|state| state.get("record"))
        .expect("a record");
    assert_eq!(
        record.get("payloadRef").and_then(Value::as_str),
        Some(cid.as_str())
    );
    assert_eq!(record.get("payload"), Some(&Value::Null));
    // The writer serves the block to a member that asks.
    seed.send(
        0,
        bodies::KIND_BLOCK_WANT,
        &bodies::block_want_body(&cid),
        Some(writer.peer_id()),
    )
    .await;
    let received = seed
        .wait_for("the block", |received| {
            received.iter().any(|r| r.kind() == bodies::KIND_BLOCK)
        })
        .await;
    let served = received
        .iter()
        .find(|r| r.kind() == bodies::KIND_BLOCK)
        .and_then(|r| bodies::parse_block(r.body()))
        .expect("a block body");
    assert!(served.verifies() && served.cid == cid);
    // Another peer folds the entry and fetches the block when it reads the payload.
    let other_seed = FakeSeed::start(&network, "127.0.0.1:7604", &text_group_id(), system());
    let reader = Peer::start(config(
        &network,
        fresh(),
        text_group(),
        &["127.0.0.1:7604"],
        system(),
    ))
    .await
    .expect("start");
    reader.pull_space("files").await.expect("pull");
    other_seed.wait_kinds(0, 3).await;
    let mut events = reader.subscribe();
    let body = bodies::rumor_body("space:files", &rumor.item_id, 6, &rumor.payload);
    other_seed.send(0, KIND_RUMOR, &body, None).await;
    let folded = next_event(&mut events, "the fold", |e| {
        matches!(e, PeerEvent::StateFolded { .. })
    })
    .await;
    assert!(matches!(
        folded,
        PeerEvent::StateFolded {
            outcome: FoldOutcome::Applied,
            ..
        }
    ));
    // An unrequested block is ignored.
    let stray = vec![1, 2, 3];
    other_seed
        .send(
            0,
            bodies::KIND_BLOCK,
            &bodies::block_body(&bodies::block_cid(&stray), &stray),
            Some(reader.peer_id()),
        )
        .await;
    // A probe behind it: the stray block was handled, and the reader has learned its seed.
    other_seed.ping(0, 1, Some(reader.peer_id())).await;
    wait_ack(&other_seed, 0, 1).await;
    assert_eq!(
        reader.payload_of("files", &entry_id).await,
        None,
        "asked for"
    );
    // Asked of the issuing peer (through the seed) and of the seed itself.
    let received = other_seed
        .wait_for("the wants", |received| {
            received.iter().any(|r| r.kind() == bodies::KIND_BLOCK_WANT)
                && received.iter().any(|r| r.kind() == KIND_RELAY_FRAME)
        })
        .await;
    let direct = received
        .iter()
        .find(|r| r.kind() == bodies::KIND_BLOCK_WANT)
        .expect("a want");
    assert_eq!(direct.to(), Some(other_seed.peer_id()));
    assert_eq!(
        bodies::parse_block_want(direct.body()).as_deref(),
        Some(cid.as_str())
    );
    let relayed = received
        .iter()
        .find(|r| r.kind() == KIND_RELAY_FRAME)
        .and_then(|r| bodies::parse_relay_frame(r.body()))
        .expect("a relay body");
    assert_eq!(
        relayed.target,
        writer.peer_id(),
        "asked of the issuing peer"
    );
    let inner = envelope::decode_frame(&relayed.frame).expect("a signed inner frame");
    assert_eq!(
        inner.get("kind").and_then(Value::as_str),
        Some(bodies::KIND_BLOCK_WANT)
    );
    // Asked at most once a second: a second read sends nothing more.
    assert_eq!(reader.payload_of("files", &entry_id).await, None);
    other_seed
        .send(
            0,
            bodies::KIND_BLOCK,
            &bodies::block_body(&cid, &encoded),
            Some(reader.peer_id()),
        )
        .await;
    let arrived = next_event(&mut events, "the block", |e| {
        matches!(e, PeerEvent::Block { .. })
    })
    .await;
    assert_eq!(arrived, PeerEvent::Block { cid: cid.clone() });
    assert_eq!(reader.payload_of("files", &entry_id).await, Some(encoded));
    assert_eq!(reader.block(&bodies::block_cid(&stray)).await, None);
}
