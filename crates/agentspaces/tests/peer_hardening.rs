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

//! Regression tests of the dial-only peer (parity with the Java node, concurrency, and
//! security): each drives the peer against the scripted in-memory seed of `support`.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;

use agentspaces::clock::{Clock, SharedClock, SystemClock};
use agentspaces::group::GroupSpec;
use agentspaces::peer::{Peer, PeerConfig, PeerError, PeerEvent};
use agentspaces::transport::memory::{MemoryDialer, MemoryNetwork};
use agentspaces::transport::{BoxFuture, Channel, Dialer, TransportError};
use agentspaces::wire::ads;
use agentspaces::wire::bodies::{
    self, KIND_ACK, KIND_BLOCK, KIND_BLOCK_WANT, KIND_DIGEST, KIND_PING, KIND_PING_REQ,
    KIND_PIPE_DATA, KIND_PULL_RESP, KIND_RELAY_FRAME, KIND_RUMOR, STREAM_PEERS,
};
use agentspaces::wire::cbor::{self, Map, Value};
use agentspaces::wire::cbor_map;
use agentspaces::wire::envelope;
use agentspaces::wire::identity::Identity;
use agentspaces::wire::ids;
use agentspaces::wire::records::{self, EntryWrite};
use agentspaces::wire::revocation;
use agentspaces::wire::seed::Seed;
use agentspaces::wire::time;
use support::{FakeSeed, PATIENCE, Received, config, eventually};
use tokio::sync::broadcast;

const SEED: &str = "127.0.0.1:7700";
const FOUNDING_TEXT: &str = "agentspaces-rust-hardening-tests";
const TASK_TYPE: &str = "com.acme.Task#v1";
const CAPABILITY: &str = "aspace:cap/echo";

fn system() -> SharedClock {
    Arc::new(SystemClock)
}

fn now() -> i64 {
    SystemClock.now_ms()
}

fn text_group() -> GroupSpec {
    GroupSpec::FoundingText(FOUNDING_TEXT.to_owned())
}

fn group_id() -> String {
    ids::group_id_from_founding(FOUNDING_TEXT.as_bytes())
}

fn fresh() -> Identity {
    Identity::generate().expect("identity")
}

/// A peer on `network` joined to a seed at `SEED` by founding text, with `adjust` applied to its
/// configuration, after its introduction and revocation pull arrived.
async fn joined_with(adjust: impl FnOnce(&mut PeerConfig)) -> (MemoryNetwork, FakeSeed, Peer) {
    let network = MemoryNetwork::new();
    let seed = FakeSeed::start(&network, SEED, &group_id(), system());
    let mut config = config(&network, fresh(), text_group(), &[SEED], system());
    adjust(&mut config);
    let peer = Peer::start(config).await.expect("the peer starts");
    assert_eq!(seed.wait_kinds(0, 2).await, [KIND_RUMOR, KIND_DIGEST]);
    (network, seed, peer)
}

async fn joined() -> (MemoryNetwork, FakeSeed, Peer) {
    joined_with(|_| {}).await
}

/// Waits for the ACK of `nonce` on `link`; returns it.
async fn wait_ack(seed: &FakeSeed, link: usize, nonce: i64) -> Received {
    let received = seed
        .wait_for(&format!("the ACK of {nonce}"), |received| {
            received.iter().any(|frame| is_ack(frame, link, nonce))
        })
        .await;
    received
        .into_iter()
        .find(|frame| is_ack(frame, link, nonce))
        .expect("the ACK")
}

fn is_ack(frame: &Received, link: usize, nonce: i64) -> bool {
    frame.link == link && frame.kind() == KIND_ACK && bodies::parse_ack(frame.body()) == Some(nonce)
}

/// A probe that the peer has handled everything the seed sent before it.
async fn fence(seed: &FakeSeed, link: usize, peer: &Peer, nonce: i64) -> Received {
    seed.ping(link, nonce, Some(peer.peer_id())).await;
    wait_ack(seed, link, nonce).await
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

/// The events already delivered to `events`.
fn drain(events: &mut broadcast::Receiver<PeerEvent>) -> Vec<PeerEvent> {
    let mut seen = Vec::new();
    while let Ok(event) = events.try_recv() {
        seen.push(event);
    }
    seen
}

/// A fresh logical counter, so frames one identity signs in the same millisecond differ.
fn logical() -> i32 {
    static NEXT: AtomicI32 = AtomicI32::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// A frame signed by `from` (a member behind the seed), addressed to `to`.
fn member_frame(from: &Identity, kind: &str, body: &[u8], to: &str) -> Vec<u8> {
    let stamp = format!("{}:{}:{}", now(), logical(), from.peer_id());
    envelope::encode_frame(
        &envelope::envelope(&group_id(), kind, from.peer_id(), &stamp, body, Some(to)),
        from,
    )
}

/// Sends `inner` to `peer` inside a RELAY_FRAME from the seed.
async fn relay_to(seed: &FakeSeed, link: usize, peer: &Peer, inner: &[u8]) {
    let relay = bodies::relay_frame_body(peer.peer_id(), inner, None, None);
    seed.send(link, KIND_RELAY_FRAME, &relay, Some(peer.peer_id()))
        .await;
}

/// The self-advertisements (`peers` rumors) received on `link`.
fn introductions(seed: &FakeSeed, link: usize) -> Vec<Map> {
    seed.of_kind(link, KIND_RUMOR)
        .iter()
        .filter_map(Received::rumor)
        .filter(|rumor| rumor.stream_id == STREAM_PEERS)
        .map(|rumor| {
            ads::verify_signed_peer_ad(&rumor.payload)
                .expect("a verified peer advertisement")
                .0
        })
        .collect()
}

/// A resource hint of a peer advertisement.
fn hint(ad: &Map, name: &str) -> Option<String> {
    ad.get("resourceHints")
        .and_then(|hints| hints.get(name))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// The founder's signed revocation of peer `revoked` (the `revocations` stream).
fn peer_revocation(founder: &Identity, revoked: &str) -> Value {
    let ad = agentspaces_wire::revocation::peer_revocation(
        founder.peer_id(),
        &group_id(),
        &time::instant_iso(now() - 1000),
        "PT1H",
        revoked,
        agentspaces_wire::revocation::KEY_COMPROMISE,
        None,
    );
    Value::Map(agentspaces_wire::revocation::sign_revocation(&ad, founder))
}

/// The key-compromise revocation of `agent` by its own peer `issuer`.
fn agent_revocation(issuer: &Identity, agent: &str) -> Value {
    let ad = revocation::credential_revocation(
        issuer.peer_id(),
        &group_id(),
        &time::instant_iso(now() - 1000),
        "PT720H",
        &revocation::agent_target(agent),
        revocation::KEY_COMPROMISE,
        None,
    )
    .expect("a credential revocation");
    Value::Map(revocation::sign_revocation(&ad, issuer))
}

/// A signed write of `peer`'s agent `agent_name` into `space`, as `records` builds it.
fn state_by(peer: &Identity, agent_name: &str, space: &str, entry_id: &str) -> Map {
    let issued = format!("{}:0:{}", now() - 1000, peer.agent(agent_name));
    state_issued(peer, agent_name, space, entry_id, &issued)
}

fn state_issued(
    peer: &Identity,
    agent_name: &str,
    space: &str,
    entry_id: &str,
    issued: &str,
) -> Map {
    let space_id = ids::space_id_local(&format!("{}/{space}", group_id()));
    let payload = cbor::encode(&cbor_map! { "topic" => entry_id });
    let write = EntryWrite {
        entry_id,
        space_id: &space_id,
        type_name: TASK_TYPE,
        payload: Some(&payload),
        payload_ref: None,
        tags: None,
        key_epoch: None,
        issued,
        expires_at_millis: now() + 600_000,
        counter: 1,
    };
    records::entry_state(&write, peer, agent_name, None).expect("a signed state")
}

/// The PULL_RESP body of `space`'s states with `extra` streams, in the canonical (Java wire v3)
/// order `bodies::pull_resp_body` writes.
fn pull_resp(space: &str, states: Vec<Map>, extra: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let states: Vec<Value> = states.into_iter().map(Value::Map).collect();
    let mut deltas = Map::new();
    deltas.insert(
        format!("space:{space}"),
        // Both fields of a SyncDelta are always written (SPEC §9.1 P1).
        cbor::encode(&cbor_map! { "states" => states, "claims" => cbor_map! {} }),
    );
    for (stream, delta) in extra {
        deltas.insert(*stream, delta.clone());
    }
    bodies::pull_resp_body(&deltas)
}

/// The entry ids of a space's states.
async fn entry_ids(peer: &Peer, space: &str) -> Vec<String> {
    peer.space_states(space)
        .await
        .iter()
        .filter_map(|state| {
            state
                .get("record")
                .and_then(|record| record.get("entryId"))
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect()
}

// ------------------------------------------------------------------------------- pull responses

/// Java writes a PULL_RESP's streams in canonical order, shorter ids first, so `space:tasks` comes
/// before `credential-revocations` (and `space:jobs` before `revocations`). Folded in wire order, a
/// state of an agent the same response revokes would be kept for good.
#[tokio::test]
async fn a_pull_response_applies_its_revocations_before_the_states_they_revoke() {
    let founder = fresh();
    let founder_id = founder.peer_id().to_owned();
    let (_network, seed, peer) = joined_with(|config| config.founder = Some(founder_id)).await;
    peer.pull_space("tasks").await.expect("pull");
    peer.pull_space("jobs").await.expect("pull");
    seed.wait_kinds(0, 4).await;

    // An agent revoked by its own peer, in the same response as its state.
    let member = fresh();
    let worker = member.agent("worker");
    let revoked = cbor::encode(&Value::Array(vec![agent_revocation(&member, &worker)]));
    let body = pull_resp(
        "tasks",
        vec![
            state_by(&member, "worker", "tasks", "by-the-revoked-agent"),
            state_by(&member, "scout", "tasks", "by-another-agent"),
        ],
        &[(revocation::CREDENTIAL_STREAM, revoked)],
    );
    let order: Vec<String> = bodies::parse_pull_resp(&body)
        .expect("a PULL_RESP")
        .keys()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    assert_eq!(
        order,
        ["space:tasks", "credential-revocations"],
        "wire order"
    );
    seed.send(0, KIND_PULL_RESP, &body, Some(peer.peer_id()))
        .await;
    fence(&seed, 0, &peer, 1).await;
    assert!(peer.is_revoked(&worker).await);
    assert_eq!(entry_ids(&peer, "tasks").await, ["by-another-agent"]);

    // A peer revoked by the founder, on `revocations`, behind a space of four characters.
    let other = fresh();
    let revoked = cbor::encode(&Value::Array(vec![peer_revocation(
        &founder,
        other.peer_id(),
    )]));
    let body = pull_resp(
        "jobs",
        vec![
            state_by(&other, "rust", "jobs", "by-the-revoked-peer"),
            state_by(&member, "scout", "jobs", "by-a-member"),
        ],
        &[(revocation::PEER_STREAM, revoked)],
    );
    let first = bodies::parse_pull_resp(&body)
        .expect("a PULL_RESP")
        .keys()
        .next()
        .and_then(Value::as_str)
        .map(str::to_owned);
    assert_eq!(first.as_deref(), Some("space:jobs"), "wire order");
    seed.send(0, KIND_PULL_RESP, &body, Some(peer.peer_id()))
        .await;
    fence(&seed, 0, &peer, 2).await;
    assert!(peer.is_revoked(other.peer_id()).await);
    assert_eq!(entry_ids(&peer, "jobs").await, ["by-a-member"]);
}

// ------------------------------------------------------------------------------- relayed pings

/// A PING that came inside a RELAY_FRAME is answered back through the relay, addressed to the
/// prober; a direct PING is answered directly, addressed to the seed.
#[tokio::test]
async fn a_relayed_ping_is_answered_back_through_the_relay() {
    let (_network, seed, peer) = joined().await;
    let direct = fence(&seed, 0, &peer, 1).await;
    assert_eq!(
        direct.to(),
        Some(seed.peer_id()),
        "a direct ACK is addressed"
    );
    assert!(
        seed.of_kind(0, KIND_RELAY_FRAME).is_empty(),
        "and not wrapped"
    );

    let prober = fresh();
    let ping = member_frame(&prober, KIND_PING, &bodies::ping_body(4242), peer.peer_id());
    relay_to(&seed, 0, &peer, &ping).await;
    let received = seed
        .wait_for("the relayed ACK", |received| {
            received.iter().any(|r| r.kind() == KIND_RELAY_FRAME)
        })
        .await;
    let carried = received
        .iter()
        .find(|r| r.kind() == KIND_RELAY_FRAME)
        .expect("a RELAY_FRAME");
    assert_eq!(carried.to(), Some(seed.peer_id()));
    let relay = bodies::parse_relay_frame(carried.body()).expect("a relay body");
    assert_eq!(relay.target, prober.peer_id());
    let inner = envelope::decode_frame(&relay.frame).expect("a signed inner frame");
    assert_eq!(inner.get("kind").and_then(Value::as_str), Some(KIND_ACK));
    assert_eq!(
        inner.get("from").and_then(Value::as_str),
        Some(peer.peer_id())
    );
    assert_eq!(
        inner.get("to").and_then(Value::as_str),
        Some(prober.peer_id())
    );
    let body = inner.get("body").and_then(Value::as_bytes).expect("a body");
    assert_eq!(bodies::parse_ack(body), Some(4242));
    assert!(
        seed.of_kind(0, KIND_ACK)
            .iter()
            .all(|ack| bodies::parse_ack(ack.body()) != Some(4242)),
        "no unaddressed ACK reaches the seed"
    );
    assert_eq!(peer.counters().await.relayed_out, 1);
}

// ------------------------------------------------------------------------------- revocations

/// Once the founder revokes the seed, its frames get nothing (no ACK, no pipe, no block), it leaves
/// the member and reachable sets, it stops being the relay, and the link to it is cut; the
/// re-introduction names no relay.
#[tokio::test]
async fn a_revoked_seed_gets_nothing_and_the_peer_leaves_it() {
    let founder = fresh();
    let founder_id = founder.peer_id().to_owned();
    let (_network, seed, peer) = joined_with(|config| config.founder = Some(founder_id)).await;
    let cid = peer.put_block(vec![9; 100]).await.expect("a block");
    fence(&seed, 0, &peer, 1).await;
    assert_eq!(peer.seed_peer().await.as_deref(), Some(seed.peer_id()));
    let mut events = peer.subscribe();

    let revocation = cbor::encode(&peer_revocation(&founder, seed.peer_id()));
    let body = bodies::rumor_body(revocation::PEER_STREAM, "r:1", 6, &revocation);
    seed.send(0, KIND_RUMOR, &body, None).await;
    next_event(&mut events, "leaving the revoked seed", |e| {
        *e == PeerEvent::Disconnected
    })
    .await;
    assert!(peer.is_revoked(seed.peer_id()).await);
    // Its only seed: the peer redials it, and introduces itself naming no relay.
    seed.wait_kinds(1, 2).await;
    let intro = introductions(&seed, 1).remove(0);
    assert_eq!(hint(&intro, "relay.via"), None);
    assert_eq!(peer.seed_peer().await, None);
    assert!(!peer.members().await.contains(&seed.peer_id().to_owned()));
    assert!(!peer.reachable().await.contains(&seed.peer_id().to_owned()));

    let to = Some(peer.peer_id());
    seed.ping(1, 2, to).await;
    seed.send(
        1,
        KIND_PIPE_DATA,
        &bodies::pipe_data_body(CAPABILITY, b"x"),
        to,
    )
    .await;
    seed.send(1, KIND_BLOCK_WANT, &bodies::block_want_body(&cid), to)
        .await;
    eventually("the revoked seed's frames dropped", || async {
        peer.counters().await.revoked_frames >= 3
    })
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(seed.of_kind(1, KIND_ACK).is_empty(), "no ACK");
    assert!(seed.of_kind(1, KIND_BLOCK).is_empty(), "no block");
    assert!(
        !drain(&mut events)
            .iter()
            .any(|e| matches!(e, PeerEvent::Pipe { .. })),
        "no pipe"
    );
    assert_eq!(peer.seed_peer().await, None, "never the relay again");
}

/// A revoked member behind the seed leaves the member view, its relayed frames are dropped, and its
/// self-advertisement is never held again.
#[tokio::test]
async fn a_revoked_member_is_evicted_and_its_frames_and_ads_refused() {
    let founder = fresh();
    let founder_id = founder.peer_id().to_owned();
    let (_network, seed, peer) = joined_with(|config| config.founder = Some(founder_id)).await;
    let mut events = peer.subscribe();
    let member = fresh();
    let advertise = |n: i64| {
        let ad = ads::peer_advertisement(&group_id(), &member, &time::instant_iso(now()), None);
        bodies::rumor_body(
            STREAM_PEERS,
            &format!("peer:{}:{n}", member.peer_id()),
            6,
            &ads::signed_peer_ad(&ad, &member),
        )
    };
    seed.send(0, KIND_RUMOR, &advertise(1), None).await;
    let pipe = member_frame(
        &member,
        KIND_PIPE_DATA,
        &bodies::pipe_data_body(CAPABILITY, b"before"),
        peer.peer_id(),
    );
    relay_to(&seed, 0, &peer, &pipe).await;
    next_event(&mut events, "the member's pipe", |e| {
        matches!(e, PeerEvent::Pipe { .. })
    })
    .await;
    assert!(peer.member_ad(member.peer_id()).await.is_some());

    let revocation = cbor::encode(&peer_revocation(&founder, member.peer_id()));
    let body = bodies::rumor_body(revocation::PEER_STREAM, "r:1", 6, &revocation);
    seed.send(0, KIND_RUMOR, &body, None).await;
    fence(&seed, 0, &peer, 1).await;
    assert!(peer.is_revoked(member.peer_id()).await);
    assert!(!peer.members().await.contains(&member.peer_id().to_owned()));
    assert_eq!(peer.member_ad(member.peer_id()).await, None);

    let pipe = member_frame(
        &member,
        KIND_PIPE_DATA,
        &bodies::pipe_data_body(CAPABILITY, b"after"),
        peer.peer_id(),
    );
    relay_to(&seed, 0, &peer, &pipe).await;
    seed.send(0, KIND_RUMOR, &advertise(2), None).await;
    fence(&seed, 0, &peer, 2).await;
    assert!(
        !drain(&mut events)
            .iter()
            .any(|e| matches!(e, PeerEvent::Pipe { from, .. } if from == member.peer_id())),
        "the revoked member's pipe is dropped"
    );
    assert!(!peer.members().await.contains(&member.peer_id().to_owned()));
    assert_eq!(peer.member_ad(member.peer_id()).await, None);
    assert!(peer.counters().await.revoked_frames >= 1);
    assert!(
        peer.is_connected(),
        "a member's revocation leaves the seed's link up"
    );
}

// ------------------------------------------------------------------------------- failover

/// A dialer serving only some schemes, over a memory network.
#[derive(Debug)]
struct Schemes {
    schemes: &'static [&'static str],
    inner: MemoryDialer,
}

impl Dialer for Schemes {
    fn schemes(&self) -> &[&'static str] {
        self.schemes
    }

    fn dial<'a>(
        &'a self,
        seed: &'a Seed,
        identity: &'a Identity,
        timeout: Duration,
    ) -> BoxFuture<'a, Result<Channel, TransportError>> {
        self.inner.dial(seed, identity, timeout)
    }
}

/// After a failover the old seed no longer carries this peer, so it must stop naming it
/// (`relay.via`) and stop wrapping frames to it: a pipe to the new seed goes direct.
#[tokio::test]
async fn a_failover_forgets_the_old_seed_as_relay() {
    let network = MemoryNetwork::new();
    let (first, second) = ("127.0.0.1:7710", "127.0.0.1:7711");
    let a = FakeSeed::start(&network, first, &group_id(), system());
    let b = FakeSeed::start(&network, second, &group_id(), system());
    let peer = Peer::start(config(
        &network,
        fresh(),
        text_group(),
        &[first, second],
        system(),
    ))
    .await
    .expect("start");
    a.wait_kinds(0, 2).await;
    fence(&a, 0, &peer, 1).await;
    assert_eq!(peer.seed_peer().await.as_deref(), Some(a.peer_id()));
    a.stop();
    b.wait_kinds(0, 2).await;
    let intro = introductions(&b, 0).remove(0);
    assert_eq!(hint(&intro, "relay.via"), None, "the old seed is not named");
    assert_eq!(peer.seed_peer().await, None);
    peer.send_pipe(b.peer_id(), CAPABILITY, b"direct")
        .await
        .expect("send");
    let received = b
        .wait_for("the pipe", |received| {
            received
                .iter()
                .any(|r| [KIND_PIPE_DATA, KIND_RELAY_FRAME].contains(&r.kind()))
        })
        .await;
    let pipe = received
        .iter()
        .find(|r| [KIND_PIPE_DATA, KIND_RELAY_FRAME].contains(&r.kind()))
        .expect("the pipe");
    assert_eq!(
        pipe.kind(),
        KIND_PIPE_DATA,
        "direct, not wrapped for the old seed"
    );
    assert_eq!(pipe.to(), Some(b.peer_id()));
    // The new seed names itself by addressing this peer.
    fence(&b, 0, &peer, 2).await;
    assert_eq!(peer.seed_peer().await.as_deref(), Some(b.peer_id()));
}

/// A failover to an attested seed takes the seed the transport proved as the relay at once, before
/// it says anything.
#[tokio::test]
async fn an_attested_failover_takes_the_new_seed_as_relay_at_once() {
    let network = MemoryNetwork::new();
    let (first, second) = ("127.0.0.1:7712", "127.0.0.1:7713");
    let a = FakeSeed::start(&network, first, &group_id(), system());
    let b = FakeSeed::start(&network, second, &group_id(), system());
    let identity = fresh();
    let mut attested = network.dialer();
    attested.attest_as = Some((b.peer_id().to_owned(), identity.peer_id().to_owned()));
    let seeds = [format!("tcp://{first}"), format!("tls://{second}")];
    let seeds: Vec<&str> = seeds.iter().map(String::as_str).collect();
    let mut config = config(&network, identity, text_group(), &seeds, system());
    config.dialers = vec![
        Arc::new(Schemes {
            schemes: &["tcp"],
            inner: network.dialer(),
        }),
        Arc::new(Schemes {
            schemes: &["tls"],
            inner: attested,
        }),
    ];
    let peer = Peer::start(config).await.expect("start");
    a.wait_kinds(0, 2).await;
    fence(&a, 0, &peer, 1).await;
    assert_eq!(peer.seed_peer().await.as_deref(), Some(a.peer_id()));
    a.stop();
    b.wait_kinds(0, 2).await;
    assert_eq!(peer.seed_peer().await.as_deref(), Some(b.peer_id()));
    let intro = introductions(&b, 0).remove(0);
    assert_eq!(hint(&intro, "relay.via").as_deref(), Some(b.peer_id()));
}

// ------------------------------------------------------------------------------- re-lease cadence

/// The re-lease is the peer's keepalive with a Java seed (member TTL 30 s). In a group of
/// eight or more members (`(8 + 1) × 4 s ≥ 30 s`) it runs every 15 s, not the configured 30 s.
#[tokio::test(start_paused = true)]
async fn a_grown_group_re_leases_at_half_the_member_ttl() {
    let (_network, seed, peer) = joined().await;
    let intros = || introductions(&seed, 0).len();
    let before = intros();
    tokio::time::sleep(Duration::from_secs(20)).await;
    assert_eq!(intros(), before, "a small group keeps the 30 s interval");
    for n in 0..7 {
        let member = fresh();
        let pipe = member_frame(
            &member,
            KIND_PIPE_DATA,
            &bodies::pipe_data_body(CAPABILITY, &[n]),
            peer.peer_id(),
        );
        relay_to(&seed, 0, &peer, &pipe).await;
    }
    eventually("eight members", || async {
        peer.members().await.len() == 8
    })
    .await;
    // Due at once (more than 15 s since the last), then every 15 s.
    eventually("the overdue re-lease", || async { intros() > before }).await;
    let after = intros();
    tokio::time::sleep(Duration::from_secs(14)).await;
    assert_eq!(intros(), after, "not before 15 s");
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(intros(), after + 1, "re-leased within 16 s");
}

// ------------------------------------------------------------------------------- the block cap

/// A payload no frame can carry as one block is refused when written (nothing held or rumored), as
/// Java's `BlockExchange.put` refuses it; 7 MiB still travels as one block.
#[tokio::test]
async fn a_payload_over_the_block_cap_is_refused_and_seven_mebibytes_still_travel() {
    let (_network, seed, peer) = joined().await;
    let nine = Value::Bytes(vec![7; 9 * 1024 * 1024]);
    let cid = bodies::block_cid(&cbor::encode(&nine));
    let refused = peer
        .write_entry("files", TASK_TYPE, nine, 60_000, Map::new(), None)
        .await;
    assert!(
        matches!(&refused, Err(PeerError::InvalidArgument(why)) if why.contains("content swarm")),
        "{refused:?}"
    );
    assert!(peer.space_states("files").await.is_empty());
    assert_eq!(peer.block(&cid).await, None);
    let refused = peer.put_block(vec![1; 9 * 1024 * 1024]).await;
    assert!(
        matches!(refused, Err(PeerError::InvalidArgument(_))),
        "{refused:?}"
    );

    let seven = Value::Bytes(vec![3; 7 * 1024 * 1024]);
    let encoded = cbor::encode(&seven);
    let cid = bodies::block_cid(&encoded);
    peer.write_entry("files", TASK_TYPE, seven, 60_000, Map::new(), None)
        .await
        .expect("seven mebibytes are written");
    fence(&seed, 0, &peer, 1).await;
    assert!(
        seed.received()
            .iter()
            .filter(|r| r.stream().as_deref() == Some("space:files"))
            .count()
            == 1,
        "only the 7 MiB write was rumored"
    );
    seed.send(
        0,
        KIND_BLOCK_WANT,
        &bodies::block_want_body(&cid),
        Some(peer.peer_id()),
    )
    .await;
    let received = seed
        .wait_for("the block", |received| {
            received.iter().any(|r| r.kind() == KIND_BLOCK)
        })
        .await;
    let block = received
        .iter()
        .find(|r| r.kind() == KIND_BLOCK)
        .and_then(|r| bodies::parse_block(r.body()))
        .expect("a block body");
    assert!(block.verifies() && block.cid == cid && block.bytes == encoded);
    let counters = peer.counters().await;
    assert_eq!((counters.blocks_served, counters.blocks_unsendable), (1, 0));
}

// ------------------------------------------------------------------------------- indirect probes

/// A PING_REQ is carried to its target under a fresh nonce, and only the target's own ACK makes
/// this peer vouch for it, once, back to whoever asked.
#[tokio::test]
async fn a_ping_req_is_carried_to_its_target_and_vouched_for_once() {
    let (_network, seed, peer) = joined().await;
    let target = fresh();
    let request =
        |nonce: i64| cbor::encode(&cbor_map! { "target" => target.peer_id(), "nonce" => nonce });
    seed.send(0, KIND_PING_REQ, &request(77), Some(peer.peer_id()))
        .await;
    let probe = |received: &[Received], nth: usize| {
        received
            .iter()
            .filter(|r| r.kind() == KIND_RELAY_FRAME)
            .filter_map(|r| bodies::parse_relay_frame(r.body()))
            .filter(|relay| relay.target == target.peer_id())
            .nth(nth)
    };
    let received = seed
        .wait_for("the probe", |received| probe(received, 0).is_some())
        .await;
    let relay = probe(&received, 0).expect("the probe");
    let inner = envelope::decode_frame(&relay.frame).expect("a signed probe");
    assert_eq!(inner.get("kind").and_then(Value::as_str), Some(KIND_PING));
    assert_eq!(
        inner.get("to").and_then(Value::as_str),
        Some(target.peer_id())
    );
    let nonce = inner
        .get("body")
        .and_then(Value::as_bytes)
        .and_then(bodies::parse_ping)
        .expect("a nonce");
    assert_ne!(nonce, 77, "a fresh nonce, not the asker's");

    // An ACK from anyone but the target vouches for nothing.
    let forger = fresh();
    let forged = member_frame(&forger, KIND_ACK, &bodies::ack_body(nonce), peer.peer_id());
    relay_to(&seed, 0, &peer, &forged).await;
    let answer = member_frame(&target, KIND_ACK, &bodies::ack_body(nonce), peer.peer_id());
    relay_to(&seed, 0, &peer, &answer).await;
    let vouch = wait_ack(&seed, 0, 77).await;
    assert_eq!(vouch.to(), Some(seed.peer_id()));
    let body = cbor::decode(vouch.body()).expect("an ACK body");
    assert_eq!(
        body.get("onBehalf").and_then(Value::as_str),
        Some(target.peer_id())
    );
    // The relay is consumed: the target answering again vouches no more.
    let again = member_frame(&target, KIND_ACK, &bodies::ack_body(nonce), peer.peer_id());
    relay_to(&seed, 0, &peer, &again).await;
    fence(&seed, 0, &peer, 1).await;
    let vouches = seed
        .of_kind(0, KIND_ACK)
        .iter()
        .filter(|ack| bodies::parse_ack(ack.body()) == Some(77))
        .count();
    assert_eq!(vouches, 1);

    // A member behind the seed asks: the vouch goes back to it through the seed.
    let origin = fresh();
    let asked = member_frame(&origin, KIND_PING_REQ, &request(88), peer.peer_id());
    relay_to(&seed, 0, &peer, &asked).await;
    let received = seed
        .wait_for("the second probe", |received| probe(received, 1).is_some())
        .await;
    let relay = probe(&received, 1).expect("the second probe");
    let nonce = envelope::decode_frame(&relay.frame)
        .and_then(|inner| {
            inner
                .get("body")
                .and_then(Value::as_bytes)
                .and_then(bodies::parse_ping)
        })
        .expect("a nonce");
    let answer = member_frame(&target, KIND_ACK, &bodies::ack_body(nonce), peer.peer_id());
    relay_to(&seed, 0, &peer, &answer).await;
    let back = |received: &[Received]| {
        received
            .iter()
            .filter(|r| r.kind() == KIND_RELAY_FRAME)
            .filter_map(|r| bodies::parse_relay_frame(r.body()))
            .find(|relay| relay.target == origin.peer_id())
    };
    let received = seed
        .wait_for("the vouch for the member", |received| {
            back(received).is_some()
        })
        .await;
    let inner = back(&received)
        .and_then(|relay| envelope::decode_frame(&relay.frame))
        .expect("the vouch");
    let body = inner
        .get("body")
        .and_then(Value::as_bytes)
        .and_then(|body| cbor::decode(body).ok())
        .expect("an ACK body");
    assert_eq!(body.get("nonce").and_then(Value::as_i64), Some(88));
    assert_eq!(
        body.get("onBehalf").and_then(Value::as_str),
        Some(target.peer_id())
    );
    assert_eq!(peer.counters().await.pings_relayed, 2);
}

// ------------------------------------------------------------------------------- send pacing

/// Writes held through an outage go out in slices as the pump drains, not as one burst that trips
/// the queue bound on a healthy link and loses what was queued.
#[tokio::test]
async fn held_writes_go_out_in_slices_without_closing_a_fast_link() {
    let (network, seed, peer) = joined_with(|config| config.send_queue_bytes = 1024 * 1024).await;
    seed.stop();
    eventually("the loss", || async { !peer.is_connected() }).await;
    const WRITES: usize = 400;
    for n in 0..WRITES {
        let payload = Value::Bytes(vec![u8::try_from(n % 251).expect("small"); 20 * 1024]);
        peer.write_entry("tasks", TASK_TYPE, payload, 600_000, Map::new(), None)
            .await
            .expect("a held write");
    }
    let again = FakeSeed::start(&network, SEED, &group_id(), system());
    let written = |received: &[Received]| {
        received
            .iter()
            .filter(|r| r.stream().as_deref() == Some("space:tasks"))
            .count()
    };
    again
        .wait_for("every held write", |received| written(received) >= WRITES)
        .await;
    fence(&again, 0, &peer, 1).await;
    assert_eq!(written(&again.received()), WRITES);
    assert_eq!(again.links(), 1, "the link was never closed");
    let counters = peer.counters().await;
    assert_eq!(counters.send_overflows, 0);
    assert_eq!(counters.send_refused, 0);
    assert_eq!(counters.outbox_dropped, 0);
    assert_eq!(counters.send_dropped, 0);
}

/// Three back-to-back asks for a 7 MiB block never close a healthy link: one is answered, the
/// rest are skipped, and the link stays up.
#[tokio::test]
async fn a_burst_of_block_wants_never_closes_a_healthy_link() {
    let (_network, seed, peer) = joined().await;
    let cid = peer
        .put_block(vec![5; 7 * 1024 * 1024])
        .await
        .expect("a block");
    let mut events = peer.subscribe();
    for _ in 0..3 {
        seed.send(
            0,
            KIND_BLOCK_WANT,
            &bodies::block_want_body(&cid),
            Some(peer.peer_id()),
        )
        .await;
    }
    seed.wait_for("a block", |received| {
        received.iter().any(|r| r.kind() == KIND_BLOCK)
    })
    .await;
    fence(&seed, 0, &peer, 1).await;
    assert!(peer.is_connected());
    assert_eq!(seed.links(), 1);
    assert!(
        !drain(&mut events).contains(&PeerEvent::Disconnected),
        "the link stayed up"
    );
    let counters = peer.counters().await;
    assert_eq!(counters.send_overflows, 0);
    assert_eq!(counters.blocks_served, 1);
    assert_eq!(counters.replies_skipped, 2);
}

// ------------------------------------------------------------------------------- stalled links

/// Block answers to a far end that stopped reading stay within half the queue (the transport's own
/// queue holds two frames, not 256), and the stall closes the link.
#[tokio::test]
async fn block_answers_to_a_stalled_link_stay_within_half_its_queue() {
    let network = MemoryNetwork::new();
    let seed = FakeSeed::start_as(&network, SEED, &group_id(), system(), fresh(), false);
    let mut config = config(&network, fresh(), text_group(), &[SEED], system());
    config.send_queue_bytes = 4 * 1024 * 1024;
    config.send_stall_timeout = Duration::from_millis(500);
    let peer = Peer::start(config).await.expect("start");
    seed.wait_links(1).await;
    let mut cids = Vec::new();
    for n in 0..6u8 {
        cids.push(peer.put_block(vec![n; 1_000_000]).await.expect("a block"));
    }
    let mut events = peer.subscribe();
    for cid in &cids {
        seed.send(
            0,
            KIND_BLOCK_WANT,
            &bodies::block_want_body(cid),
            Some(peer.peer_id()),
        )
        .await;
    }
    eventually("every ask handled", || async {
        let counters = peer.counters().await;
        counters.blocks_served + counters.replies_skipped == 6
    })
    .await;
    let counters = peer.counters().await;
    assert!(
        counters.blocks_served <= 3,
        "{} answers of 1 MB queued against a 4 MiB queue",
        counters.blocks_served
    );
    next_event(&mut events, "the stall", |e| *e == PeerEvent::Disconnected).await;
    assert_eq!(peer.counters().await.send_overflows, 1);
}

// ------------------------------------------------------------------------------- unopened spaces

/// Rumors for spaces this peer never opened are not folded and open nothing, so a member cannot use
/// up the space slots and lock the peer out of its own spaces.
#[tokio::test]
async fn junk_space_rumors_never_lock_the_peer_out_of_its_own_spaces() {
    let (_network, seed, peer) = joined().await;
    // Junk that is no space delta does not decode (SPEC §9.1): dropped and counted.
    let junk = cbor::encode(&cbor_map! { "state" => cbor_map! { "x" => 1 } });
    for n in 0..1100 {
        let body = bodies::rumor_body(&format!("space:junk-{n}"), "w:x", 6, &junk);
        seed.send(0, KIND_RUMOR, &body, None).await;
    }
    // A well-formed delta for spaces this peer never opened is not folded and opens nothing.
    let delta = support::hex("delta_cbor");
    for n in 0..1100 {
        let body = bodies::rumor_body(&format!("space:junk-{n}"), "w:y", 6, &delta);
        seed.send(0, KIND_RUMOR, &body, None).await;
    }
    fence(&seed, 0, &peer, 1).await;
    assert_eq!(peer.counters().await.deltas_undecodable, 1100);
    peer.pull_space("mine").await.expect("its own space opens");
    peer.write_entry("mine2", TASK_TYPE, Value::Null, 60_000, Map::new(), None)
        .await
        .expect("and so does a written one");
    assert!(peer.space_states("junk-0").await.is_empty());
    assert_eq!(
        peer.with_space("junk-0", |_| ()).await,
        None,
        "never opened"
    );
    assert_eq!(peer.counters().await.unopened_space_items, 1100);
}

// ------------------------------------------------------------------------------- closure panics

/// A panic in a `with_space` closure unwinds in the caller; the peer carries on.
#[tokio::test]
async fn a_panicking_space_closure_unwinds_in_the_caller_and_the_peer_carries_on() {
    let (_network, seed, peer) = joined().await;
    peer.pull_space("work").await.expect("pull");
    let caller = peer.clone();
    let outcome = tokio::spawn(async move {
        caller
            .with_space("work", |_| -> usize {
                panic!("a bug in the caller's closure")
            })
            .await
    })
    .await;
    assert!(
        outcome.is_err_and(|error| error.is_panic()),
        "re-raised in the caller"
    );
    assert!(peer.is_connected());
    assert_eq!(peer.with_space("work", |store| store.len()).await, Some(0));
    peer.write_entry("work", TASK_TYPE, Value::Null, 60_000, Map::new(), None)
        .await
        .expect("the peer still writes");
    seed.wait_for("the write", |received| {
        received
            .iter()
            .any(|r| r.stream().as_deref() == Some("space:work"))
    })
    .await;
    fence(&seed, 0, &peer, 1).await;
}

// ------------------------------------------------------------------------------- reconnect events

/// `Reconnected` is told only for a link that is up after the re-introduction.
#[tokio::test]
async fn reconnected_is_only_told_for_a_link_that_is_up() {
    let (network, seed, peer) = joined_with(|config| config.send_queue_bytes = 64 * 1024).await;
    let mut events = peer.subscribe();
    seed.stop();
    eventually("the loss", || async { !peer.is_connected() }).await;
    for n in 0..200 {
        let payload = Value::Bytes(vec![u8::try_from(n % 251).expect("small"); 600]);
        peer.write_entry("tasks", TASK_TYPE, payload, 600_000, Map::new(), None)
            .await
            .expect("a held write");
    }
    let again = FakeSeed::start(&network, SEED, &group_id(), system());
    again
        .wait_for("the held writes", |received| {
            received
                .iter()
                .filter(|r| r.stream().as_deref() == Some("space:tasks"))
                .count()
                >= 200
        })
        .await;
    next_event(&mut events, "the reconnect", |e| {
        matches!(e, PeerEvent::Reconnected { .. })
    })
    .await;
    assert!(peer.is_connected());
    let mut up = false;
    let mut told = 0;
    for event in drain(&mut events) {
        match event {
            PeerEvent::Connected(_) => up = true,
            PeerEvent::Disconnected => up = false,
            PeerEvent::Reconnected { .. } => {
                assert!(up, "Reconnected told while no link is up");
                told += 1;
            }
            _ => {}
        }
    }
    assert_eq!(told, 0, "no further reconnect");
    assert_eq!(peer.counters().await.send_overflows, 0);
}

// ------------------------------------------------------------------------------- pinned stamps

/// The stamps of the ACKs on `link` whose nonce is in `nonces`.
fn ack_stamps(seed: &FakeSeed, link: usize, nonces: std::ops::Range<i64>) -> Vec<String> {
    seed.of_kind(link, KIND_ACK)
        .iter()
        .filter(|ack| bodies::parse_ack(ack.body()).is_some_and(|n| nonces.contains(&n)))
        .filter_map(|ack| ack.text("stamp").map(str::to_owned))
        .collect()
}

fn all_distinct(stamps: &[String]) -> bool {
    let mut sorted = stamps.to_vec();
    sorted.sort();
    sorted.dedup();
    sorted.len() == stamps.len()
}

/// One frame (or one folded state) stamped near the HLC ceiling with the logical counter at
/// `i32::MAX` would pin every stamp this peer issues, so receivers would drop its frames as
/// replays. Since v0.1.30 (SPEC §9, §7.3) such a stamp is not acceptable: the frame is dropped
/// and counted (`framesLogicalRefused`) and never answered, the state is refused after its
/// signatures verify and counted once (`stampsLogicalRefused`), and neither reaches the clock.
/// A stamp at the limit itself is acceptable and merges, and the clock carries past it.
#[tokio::test]
async fn a_pinned_stamp_never_freezes_this_peers_clock() {
    let (_network, seed, peer) = joined().await;
    peer.pull_space("tasks").await.expect("pull");
    let ahead = now() + 9 * 60_000;
    let pinned = seed.frame_stamped(
        KIND_PING,
        &bodies::ping_body(1),
        Some(peer.peer_id()),
        &seed.stamp_at(ahead, i32::MAX),
    );
    seed.send_raw(0, pinned).await;
    for nonce in 2..6 {
        fence(&seed, 0, &peer, nonce).await;
    }
    assert!(
        ack_stamps(&seed, 0, 1..2).is_empty(),
        "the pinned PING is not answered"
    );
    assert_eq!(peer.counters().await.filter.logical_refused, 1);
    let stamps = ack_stamps(&seed, 0, 2..6);
    assert_eq!(stamps.len(), 4);
    assert!(all_distinct(&stamps), "frame path: {stamps:?}");

    // A validly signed write whose `issued` (and lease stamp) is pinned: refused, counted once.
    let issued = format!("{ahead}:{}:{}", i32::MAX, seed.identity.agent("rust"));
    let state = state_issued(&seed.identity, "rust", "tasks", "pinned", &issued);
    let body = bodies::rumor_body(
        "space:tasks",
        "w:pinned",
        6,
        &records::delta(Some(&state), None),
    );
    for _ in 0..3 {
        seed.send(0, KIND_RUMOR, &body, None).await;
    }
    for nonce in 10..14 {
        fence(&seed, 0, &peer, nonce).await;
    }
    assert!(peer.space_states("tasks").await.is_empty());
    assert_eq!(peer.counters().await.stamps_logical_refused, 1);
    // A write stamped at the limit itself merges, and the clock carries past it.
    let at_limit = format!("{}:65536:{}", now() + 1000, seed.identity.agent("rust"));
    let state = state_issued(&seed.identity, "rust", "tasks", "at-limit", &at_limit);
    let body = bodies::rumor_body(
        "space:tasks",
        "w:at-limit",
        6,
        &records::delta(Some(&state), None),
    );
    seed.send(0, KIND_RUMOR, &body, None).await;
    eventually("the write at the limit to fold", || async {
        peer.space_states("tasks").await.len() == 1
    })
    .await;
    for nonce in 20..24 {
        fence(&seed, 0, &peer, nonce).await;
    }
    let stamps = ack_stamps(&seed, 0, 20..24);
    assert!(all_distinct(&stamps), "state path: {stamps:?}");
    for _ in 0..2 {
        peer.write_entry("tasks", TASK_TYPE, Value::Null, 60_000, Map::new(), None)
            .await
            .expect("a write");
    }
    let rumors = seed
        .wait_for("two writes", |received| {
            received
                .iter()
                .filter(|r| r.link == 0 && r.stream().as_deref() == Some("space:tasks"))
                .count()
                >= 2
        })
        .await;
    let stamps: Vec<String> = rumors
        .iter()
        .filter(|r| r.stream().as_deref() == Some("space:tasks"))
        .filter_map(|r| r.text("stamp").map(str::to_owned))
        .collect();
    assert!(all_distinct(&stamps), "writes: {stamps:?}");
    for stamp in &stamps {
        let parsed = agentspaces_wire::hlc::Stamp::parse(stamp).expect("a stamp");
        assert!(parsed.is_acceptable(), "{stamp}");
    }
}

// ------------------------------------------------------------------------------- peer ads

/// A member's self-advertisement is kept as Java keeps it: only for this group, only while it lives
/// and was not issued far ahead, and never rolled back to an older one.
#[tokio::test]
async fn peer_ads_are_judged_as_java_judges_them() {
    let (_network, seed, peer) = joined().await;
    let member = fresh();
    let item = std::sync::atomic::AtomicUsize::new(0);
    let send_ad = |who: &Identity, group: &str, issued_ms: i64, marker: &str| {
        let mut hints = Map::new();
        hints.insert("marker", marker);
        let ad = ads::peer_advertisement(group, who, &time::instant_iso(issued_ms), Some(&hints));
        let n = item.fetch_add(1, Ordering::Relaxed);
        let body = bodies::rumor_body(
            STREAM_PEERS,
            &format!("peer:{}:{n}", who.peer_id()),
            6,
            &ads::signed_peer_ad(&ad, who),
        );
        let seed = &seed;
        async move { seed.send(0, KIND_RUMOR, &body, None).await }
    };
    let marker = |ad: Option<Map>| ad.as_ref().and_then(|ad| hint(ad, "marker"));
    let t = now();
    send_ad(&member, &group_id(), t - 1000, "fresh").await;
    // Older but still live, expired, issued far ahead: none replaces the fresh one.
    send_ad(&member, &group_id(), t - 5 * 60_000, "older").await;
    send_ad(&member, &group_id(), t - 11 * 60_000, "expired").await;
    send_ad(&member, &group_id(), t + 11 * 60_000, "ahead").await;
    fence(&seed, 0, &peer, 1).await;
    assert_eq!(
        marker(peer.member_ad(member.peer_id()).await).as_deref(),
        Some("fresh")
    );
    // A newer one does.
    send_ad(&member, &group_id(), t + 1000, "newer").await;
    fence(&seed, 0, &peer, 2).await;
    assert_eq!(
        marker(peer.member_ad(member.peer_id()).await).as_deref(),
        Some("newer")
    );
    // Another group's advertisement, and an expired one, admit nobody.
    let stranger = fresh();
    send_ad(&stranger, "zSomeOtherGroup", t, "foreign").await;
    let late = fresh();
    send_ad(&late, &group_id(), t - 30 * 60_000, "expired").await;
    fence(&seed, 0, &peer, 3).await;
    let members = peer.members().await;
    for who in [&stranger, &late] {
        assert!(!members.contains(&who.peer_id().to_owned()));
        assert_eq!(peer.member_ad(who.peer_id()).await, None);
    }
}

// ------------------------------------------------------------------------------- chunked stamps

/// `bytes` with the stamp `text` that follows the key `key` (both in Jackson's definite form)
/// sent instead as an indefinite-length text of one chunk or two, which is not a stamp item
/// (SPEC §9), here for the carrier's own stamp.
fn stamp_in_chunks(bytes: &[u8], key: &str, text: &str, chunks: usize) -> Vec<u8> {
    let key_item = cbor::encode(&Value::from(key));
    let from = [key_item.clone(), cbor::encode(&Value::from(text))].concat();
    let split = if chunks == 1 {
        text.len()
    } else {
        text.len() / 2
    };
    let mut to = key_item;
    to.push(0x7F);
    for piece in [&text[..split], &text[split..]] {
        if !piece.is_empty() {
            to.extend_from_slice(&cbor::encode(&Value::from(piece)));
        }
    }
    to.push(0xFF);
    let at = bytes
        .windows(from.len())
        .position(|window| window == from)
        .unwrap_or_else(|| panic!("the carrier holds {key}: {text}"));
    [&bytes[..at], &to, &bytes[at + from.len()..]].concat()
}

/// A stamp that arrives as chunked text is undecodable where a stamp belongs (SPEC §9), at this
/// peer as in Java, Python, TypeScript, and Ruby. A frame whose envelope stamp is chunked is
/// counted malformed and never answered; a space delta whose record `issued` or whose claim
/// `stamp` is chunked is counted as an undecodable delta (`deltasUndecodable`) and folds nothing.
/// The same carriers with the stamp in its one form fold.
#[tokio::test]
async fn a_stamp_in_chunks_is_refused_in_a_frame_a_record_and_a_claim() {
    let (_network, seed, peer) = joined().await;
    peer.pull_space("work").await.expect("pull");
    seed.wait_kinds(0, 3).await;
    let before = peer.counters().await.malformed;

    // An envelope's stamp: a PING from the seed in each form gets no ACK.
    for (nonce, chunks) in [(101, 1), (102, 2)] {
        let stamp = seed.stamp();
        let frame = seed.frame_stamped(
            KIND_PING,
            &bodies::ping_body(nonce),
            Some(peer.peer_id()),
            &stamp,
        );
        seed.send_raw(0, stamp_in_chunks(&frame, "stamp", &stamp, chunks))
            .await;
    }
    fence(&seed, 0, &peer, 103).await;
    let acked: Vec<i64> = seed
        .of_kind(0, KIND_ACK)
        .iter()
        .filter_map(|frame| bodies::parse_ack(frame.body()))
        .collect();
    assert!(!acked.contains(&101) && !acked.contains(&102), "{acked:?}");
    assert_eq!(peer.counters().await.malformed, before + 2);

    // A record's issued: a member's write.
    let member = fresh();
    let worker = member.agent("worker");
    let issued = format!("{}:0:{worker}", now() - 1000);
    let state = state_issued(&member, "worker", "work", "chunked", &issued);
    let honest = records::delta(Some(&state), None);
    for chunks in [1, 2] {
        let hostile = stamp_in_chunks(&honest, "issued", &issued, chunks);
        let item = format!("w:chunked-{chunks}");
        let body = bodies::rumor_body("space:work", &item, 6, &hostile);
        seed.send(0, KIND_RUMOR, &body, None).await;
    }
    fence(&seed, 0, &peer, 104).await;
    assert!(entry_ids(&peer, "work").await.is_empty());
    assert_eq!(peer.counters().await.malformed, before + 2);
    assert_eq!(peer.counters().await.deltas_undecodable, 2);
    let body = bodies::rumor_body("space:work", "w:chunked", 6, &honest);
    seed.send(0, KIND_RUMOR, &body, None).await;
    fence(&seed, 0, &peer, 105).await;
    assert_eq!(entry_ids(&peer, "work").await, ["chunked"]);

    // A claim's stamp: the member's claim on that entry.
    let space_id = ids::space_id_local(&format!("{}/work", group_id()));
    let stamp = format!("{}:1:{worker}", now());
    let claim = records::take_claim(
        "chunked",
        &space_id,
        1,
        &stamp,
        &worker,
        0.0,
        now() + 30_000,
    );
    let signed = records::signed_claim(&claim, &member, None).expect("a claim");
    let honest = records::claim_delta("chunked", &signed);
    for chunks in [1, 2] {
        let hostile = stamp_in_chunks(&honest, "stamp", &stamp, chunks);
        let item = format!("c:chunked:{chunks}");
        let body = bodies::rumor_body("space:work", &item, 6, &hostile);
        seed.send(0, KIND_RUMOR, &body, None).await;
    }
    fence(&seed, 0, &peer, 106).await;
    assert!(peer.space_claims("work").await.is_empty());
    assert_eq!(peer.counters().await.deltas_undecodable, 4);
    let body = bodies::rumor_body("space:work", &format!("c:chunked:{stamp}"), 6, &honest);
    seed.send(0, KIND_RUMOR, &body, None).await;
    fence(&seed, 0, &peer, 107).await;
    let claims = peer.space_claims("work").await;
    assert_eq!(claims.len(), 1, "{claims:?}");
    assert_eq!(peer.counters().await.malformed, before + 2);
    assert_eq!(peer.counters().await.deltas_undecodable, 4);
}
