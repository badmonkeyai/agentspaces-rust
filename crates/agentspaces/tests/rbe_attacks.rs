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

//! Attacks on a Rust listening peer's replication by entry (SPEC §5.2, §7.2, §7.3, annex I.6),
//! each a regression test of a hole that was closed:
//!
//! - one store change derives one audited slot again, not the whole space, so a member that
//!   folds one state between two bodies cannot make every body cost a pass over the space;
//! - a member's probes that carry hashes draw this peer's own hashes at a bounded pace, since
//!   each answer reads every stream this peer serves;
//! - a budgeted pull of a space's text digest costs what any digest answer costs, and spends the
//!   same per-member pace; only the continuation an earlier answer's remainder invited is
//!   exempt;
//! - request nodes spend the per-member pace of the audit's answers like the fetches do;
//! - a member that drops `wire.ae=2` from its card receives no audit field afterwards, as the
//!   partner of a descent nor as its asker;
//! - a `remainder` this peer never asked for (its body carried no budget) draws no continuation,
//!   so a partner cannot make it rebuild and resend its digests over and over;
//! - a writer that leaves the view and comes back starts a new stay, so its withdrawals keep
//!   the legacy horizon until it has stayed one longest lease plus five minutes again;
//! - a peer whose configured hints carry `wire.horizon` with another value than `1` does not
//!   apply the per-entry horizon it does not advertise.

mod support;

use std::sync::Arc;
use std::time::Duration;

use agentspaces::clock::{ManualClock, SharedClock, SystemClock};
use agentspaces::group::GroupSpec;
use agentspaces::peer::{ListenerSpec, Peer, PeerConfig};
use agentspaces::space::{Fleet, Lease};
use agentspaces::transport::memory::MemoryNetwork;
use agentspaces::wire::audit::{self, DigestBody, TreeNode};
use agentspaces::wire::bodies::{self, KIND_ACK, KIND_DIGEST, KIND_PING, KIND_PULL_RESP};
use agentspaces::wire::cbor::{Map, Value};
use agentspaces::wire::horizon::{self, Mode, Rule};
use agentspaces::wire::identity::Identity;
use agentspaces::wire::ids;
use agentspaces::wire::trie::{AuditTrie, Path};
use support::{RawPeer, eventually};

const FOUNDING: &str = "agentspaces-rust-rbe-attacks";
const SPACE: &str = "tasks";
const STREAM: &str = "space:tasks";
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
    identity: Identity,
) -> PeerConfig {
    let mut config = PeerConfig::new(identity, GroupSpec::FoundingText(FOUNDING.to_owned()));
    config.clock = clock;
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

async fn hub_at(network: &MemoryNetwork, address: &str) -> Peer {
    let identity = Identity::generate().expect("identity");
    Peer::start(config(network, system(), Some(address), None, identity))
        .await
        .expect("the hub starts")
}

async fn write(hub: &Peer, count: usize) {
    let space = Fleet::from_peer(hub.clone()).space(SPACE);
    for i in 0..count {
        space
            .write_value(
                TYPE,
                task(&format!("t{i}")),
                Lease::DEFAULT_WRITE,
                Map::new(),
            )
            .await
            .expect("write");
    }
}

/// A raw member of the hub's group, introduced with `hints` and admitted.
async fn member(network: &MemoryNetwork, address: &str, hub: &Peer, hints: &Map) -> RawPeer {
    let group = ids::group_id_from_founding(FOUNDING.as_bytes());
    let raw = RawPeer::dial(
        network,
        address,
        Identity::generate().expect("id"),
        &group,
        system(),
    )
    .await;
    assert!(raw.introduce(hints).await);
    let peer = raw.peer_id().to_owned();
    eventually("the hub admits the member", || {
        let hub = hub.clone();
        let peer = peer.clone();
        async move { hub.admitted_members().await.contains(&peer) }
    })
    .await;
    raw
}

fn ae2() -> Map {
    let mut hints = Map::new();
    hints.insert(audit::HINT_AE, audit::AE_LEVEL);
    hints
}

fn opening() -> Vec<u8> {
    DigestBody {
        hashes: Some(vec![(STREAM.to_owned(), vec![0u8; 32])]),
        ..DigestBody::default()
    }
    .encode()
}

fn body_of(env: &Map) -> &[u8] {
    env.get("body")
        .and_then(Value::as_bytes)
        .unwrap_or_default()
}

fn carries_audit(env: &Map) -> bool {
    audit::parse_digest(body_of(env)).is_ok_and(|digest| digest.carries_audit())
}

// ------------------------------------------------------------------------------- resync cost

/// The hub keeps its space's trie in step with its store: after one more write, the next
/// opening derives that one entry's slot again, not all six hundred.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_store_change_derives_one_slot_again() {
    let network = MemoryNetwork::new();
    let address = "127.0.0.1:7991";
    let hub = hub_at(&network, address).await;
    write(&hub, 600).await;
    let raw = member(&network, address, &hub, &ae2()).await;
    raw.send(KIND_DIGEST, &opening(), Some(hub.peer_id())).await;
    eventually("the first opening is answered", || async {
        hub.counters().await.audit.openings_answered >= 1
    })
    .await;
    let before = hub.counters().await.audit.slots_derived;
    assert!(
        before >= 600,
        "the first audit derives every slot: {before}"
    );
    write(&hub, 1).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    raw.send(KIND_DIGEST, &opening(), Some(hub.peer_id())).await;
    eventually("the second opening is answered", || async {
        hub.counters().await.audit.openings_answered >= 2
    })
    .await;
    let derived = hub.counters().await.audit.slots_derived - before;
    assert!(
        derived <= 4,
        "one change derived {derived} slots again (a pass over the space per change)"
    );
    hub.close().await.expect("close");
}

// ------------------------------------------------------------------------------- probe hashes

/// Each probe that carries hashes makes the hub read every stream it serves to answer with its
/// own; a member flooding such probes gets every probe acknowledged, but its own hashes only at
/// a bounded pace.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hashed_probes_draw_hashes_at_a_bounded_pace() {
    let network = MemoryNetwork::new();
    let address = "127.0.0.1:7992";
    let hub = hub_at(&network, address).await;
    write(&hub, 50).await;
    let raw = member(&network, address, &hub, &Map::new()).await;
    let mut theirs = std::collections::BTreeMap::new();
    theirs.insert(STREAM.to_owned(), [9u8; 32]);
    let probe = bodies::ProbeHashes {
        root: None,
        hashes: Some(theirs),
    };
    for nonce in 0..60 {
        raw.send(
            KIND_PING,
            &bodies::ping_body_with(nonce, &probe),
            Some(hub.peer_id()),
        )
        .await;
    }
    raw.wait_for("every probe acknowledged", |frames| {
        frames
            .iter()
            .filter(|env| env.get("kind").and_then(Value::as_str) == Some(KIND_ACK))
            .count()
            >= 60
    })
    .await;
    let hashed = raw
        .of_kind(KIND_ACK)
        .iter()
        .filter(|env| {
            bodies::decode_body(KIND_ACK, body_of(env))
                .and_then(|body| bodies::probe_hashes(&body).ok())
                .is_some_and(|probe| !probe.is_empty())
        })
        .count();
    assert!(hashed >= 1, "a probe with hashes is answered with hashes");
    assert!(
        hashed <= 12,
        "{hashed} of 60 flooded probes drew a pass over every stream"
    );
    hub.close().await.expect("close");
}

// ------------------------------------------------------------------------------- answer pace

/// A budgeted pull of the space's text digest is a digest answer like any other (a pass over the
/// space), so it spends the member's digest pace: adding `budget` to a pull must not buy a
/// member eight times the answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_budget_does_not_buy_more_digest_answers() {
    let network = MemoryNetwork::new();
    let address = "127.0.0.1:7993";
    let hub = hub_at(&network, address).await;
    write(&hub, 5).await;
    let raw = member(&network, address, &hub, &ae2()).await;
    let pull = DigestBody {
        digests: Some(vec![(STREAM.to_owned(), Vec::new())]),
        budget: Some(1 << 20),
        ..DigestBody::default()
    }
    .encode();
    for _ in 0..60 {
        raw.send(KIND_DIGEST, &pull, Some(hub.peer_id())).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let answered = raw.of_kind(KIND_PULL_RESP).len();
    assert!(answered >= 1, "a budgeted pull is answered");
    assert!(
        answered <= 24,
        "{answered} of 60 budgeted pulls answered: the budget bypassed the digest pace"
    );
    hub.close().await.expect("close");
}

/// A 33-slot root (inner) for a tree answer.
fn inner_root() -> TreeNode {
    let mut trie = AuditTrie::new();
    for i in 0..40 {
        let id = format!("other-{i}");
        trie.put(&id, vec![format!("e:{id}=1")]);
    }
    audit::answer_root(&mut trie)
}

/// Request nodes spend the member's pace for the audit's answers, which its fetches spent: a
/// session of 64 exchanges is no licence to draw 63 more answers at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn request_nodes_spend_the_audit_pace() {
    let network = MemoryNetwork::new();
    let address = "127.0.0.1:7994";
    let hub = hub_at(&network, address).await;
    write(&hub, 80).await;
    let raw = member(&network, address, &hub, &ae2()).await;
    // The opening opens a session (the hub's root is inner).
    raw.send(KIND_DIGEST, &opening(), Some(hub.peer_id())).await;
    raw.wait_for("the root", |frames| {
        frames.iter().any(|env| {
            env.get("kind").and_then(Value::as_str) == Some(KIND_DIGEST) && carries_audit(env)
        })
    })
    .await;
    // Fetches spend the pace...
    let fetch = DigestBody {
        ids: Some(vec![(STREAM.to_owned(), vec!["nothing".to_owned()])]),
        budget: Some(1 << 20),
        ..DigestBody::default()
    }
    .encode();
    for _ in 0..64 {
        raw.send(KIND_DIGEST, &fetch, Some(hub.peer_id())).await;
    }
    // ...and requests within the session spend it too.
    let children: Vec<TreeNode> = (0..16u8)
        .map(|c| TreeNode::request(&Path::ROOT.child(c).expect("a child"), 0))
        .collect();
    let request = DigestBody {
        tree: Some(vec![(STREAM.to_owned(), children)]),
        budget: Some(1 << 20),
        ..DigestBody::default()
    }
    .encode();
    for _ in 0..40 {
        raw.send(KIND_DIGEST, &request, Some(hub.peer_id())).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let answered = hub.counters().await.audit.requests_answered;
    assert!(
        answered <= 24,
        "{answered} of 40 request bodies answered past a spent pace"
    );
    hub.close().await.expect("close");
}

// ------------------------------------------------------------------------------- the card

/// A member that drops `wire.ae=2` from its card mid-session receives no audit field from then
/// on: its later root answer draws no request nodes and no fetch, and its later request nodes
/// draw no tree answer (SPEC annex I.6: the form is chosen per partner from its current card).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_card_without_the_hint_receives_no_audit_field() {
    let network = MemoryNetwork::new();
    let address = "127.0.0.1:7995";
    let hub = hub_at(&network, address).await;
    write(&hub, 80).await;
    let raw = member(&network, address, &hub, &ae2()).await;
    // A DIGEST naming the view makes the member a partner of the hub's rounds, which open with
    // hashes toward its card on wire.ae=2; its own opening opens a session at the hub.
    let mut digests = Map::new();
    digests.insert("view", Vec::<u8>::new());
    raw.send(
        KIND_DIGEST,
        &bodies::digest_body(&digests),
        Some(hub.peer_id()),
    )
    .await;
    raw.send(KIND_DIGEST, &opening(), Some(hub.peer_id())).await;
    raw.wait_for("the hub's hashed opening and its root", |frames| {
        let digests: Vec<&Map> = frames
            .iter()
            .filter(|env| env.get("kind").and_then(Value::as_str) == Some(KIND_DIGEST))
            .collect();
        digests.iter().any(|env| carries_audit(env))
            && digests.iter().any(|env| {
                audit::parse_digest(body_of(env)).is_ok_and(|digest| digest.hashes.is_some())
            })
    })
    .await;
    // The member's card drops the hint (a later issue, a second on).
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    raw.introduce(&Map::new()).await;
    let peer = raw.peer_id().to_owned();
    eventually("the hub reads the new card", || {
        let hub = hub.clone();
        let peer = peer.clone();
        async move {
            hub.member_ad(&peer)
                .await
                .is_some_and(|ad| !ad.is_empty() && !audit::hints_audit(ad.get("resourceHints")))
        }
    })
    .await;
    let seen = raw.received().len();
    // A root answer for the hub's last opening, and request nodes in the member's session.
    let answer = DigestBody {
        tree: Some(vec![(STREAM.to_owned(), vec![inner_root()])]),
        ..DigestBody::default()
    }
    .encode();
    raw.send(KIND_DIGEST, &answer, Some(hub.peer_id())).await;
    let request = DigestBody {
        tree: Some(vec![(
            STREAM.to_owned(),
            vec![TreeNode::request(&Path::ROOT.child(3).expect("a child"), 0)],
        )]),
        budget: Some(1 << 20),
        ..DigestBody::default()
    }
    .encode();
    raw.send(KIND_DIGEST, &request, Some(hub.peer_id())).await;
    tokio::time::sleep(Duration::from_millis(600)).await;
    let late: Vec<Map> = raw.received().into_iter().skip(seen).collect();
    let audited: Vec<&Map> = late
        .iter()
        .filter(|env| env.get("kind").and_then(Value::as_str) == Some(KIND_DIGEST))
        .filter(|env| carries_audit(env))
        .collect();
    assert!(
        audited.is_empty(),
        "{} DIGEST frames with audit fields went to a card without wire.ae=2",
        audited.len()
    );
    hub.close().await.expect("close");
}

// ------------------------------------------------------------------------------- remainders

/// The hub opens rounds with a member on wire.ae=2 by hashes, which carry no budget; the member
/// answers each with a `PULL_RESP` claiming states left out for a budget. Nothing was budgeted,
/// so nothing continues.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_remainder_nobody_asked_for_draws_no_continuation() {
    let network = MemoryNetwork::new();
    let address = "127.0.0.1:7990";
    let hub = hub_at(&network, address).await;
    write(&hub, 5).await;
    let raw = member(&network, address, &hub, &ae2()).await;
    let mut digests = Map::new();
    digests.insert("view", Vec::<u8>::new());
    raw.send(
        KIND_DIGEST,
        &bodies::digest_body(&digests),
        Some(hub.peer_id()),
    )
    .await;
    let resp = audit::PullRespBody {
        deltas: Vec::new(),
        remainder: Some(vec![(STREAM.to_owned(), 5)]),
    }
    .encode();
    for _ in 0..10 {
        raw.wait_for("a round from the hub", |frames| {
            frames.iter().any(|env| {
                env.get("kind").and_then(Value::as_str) == Some(KIND_DIGEST)
                    && audit::parse_digest(body_of(env)).is_ok_and(|d| d.hashes.is_some())
            })
        })
        .await;
        raw.send(KIND_PULL_RESP, &resp, Some(hub.peer_id())).await;
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let counters = hub.counters().await;
    assert_eq!(
        counters.audit.pulls_continued, 0,
        "an unasked remainder continued a pull"
    );
    hub.close().await.expect("close");
}

// ------------------------------------------------------------------------------- the writer's stay

async fn advance(clock: &ManualClock, millis: i64) {
    let mut left = millis;
    while left > 0 {
        let step = left.min(MIN);
        clock.advance(step);
        left -= step;
        tokio::time::sleep(Duration::from_millis(120)).await;
    }
}

async fn reach(peer: &Peer, clock: &ManualClock, mode: Mode) {
    for _ in 0..200 {
        if peer.space_horizon(SPACE).await.expect("open").mode == mode {
            return;
        }
        clock.advance(150);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("never reached {mode:?}");
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

async fn hinted(of: &Peer, member: &str) -> bool {
    of.member_ad(member)
        .await
        .is_some_and(|ad| horizon::hints_horizon(ad.get("resourceHints")))
}

/// A writer that was vouched for leaves the view (its card lapses) and comes back with a fresh
/// card before the hub happens to judge its view in between. Its stay is a new one: its
/// withdrawal keeps the legacy horizon until it has stayed a longest lease plus five minutes
/// again, whatever the hub knew of its earlier stay.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_writer_that_leaves_and_returns_starts_a_new_stay() {
    let network = MemoryNetwork::new();
    let manual = ManualClock::new(1_800_000_000_000);
    let clock: SharedClock = Arc::new(manual.clone());
    let a_address = "127.0.0.1:7996";
    let a = Peer::start(config(
        &network,
        clock.clone(),
        Some(a_address),
        None,
        Identity::generate().expect("id"),
    ))
    .await
    .expect("a starts");
    let b_identity = Identity::generate().expect("id");
    let b = Peer::start(config(
        &network,
        clock.clone(),
        Some("127.0.0.1:7997"),
        Some(a_address),
        b_identity.clone(),
    ))
    .await
    .expect("b starts");
    for peer in [&a, &b] {
        peer.pull_space(SPACE).await.expect("open");
    }
    eventually("a holds b's hinted card", || async {
        hinted(&a, b.peer_id()).await
    })
    .await;
    // A 30-minute lease: the legacy horizon of a withdrawal is an hour, the per-entry one ten
    // minutes, and a writer is vouched for after 35 minutes in view.
    let thirty = Lease::from_millis(30 * MIN).unwrap();
    Fleet::from_peer(a.clone())
        .space(SPACE)
        .write_value(TYPE, task("long"), thirty, Map::new())
        .await
        .expect("write");
    reach(&a, &manual, Mode::Settling).await;
    advance(&manual, 36 * MIN).await;
    assert_eq!(
        a.space_horizon(SPACE).await.expect("open").mode,
        Mode::PerEntry
    );
    // b, vouched for now, writes and withdraws an entry.
    let space = Fleet::from_peer(b.clone()).space(SPACE);
    let id = space
        .write_value(TYPE, task("b's"), thirty, Map::new())
        .await
        .expect("write");
    space.cancel(&id).await.expect("cancel");
    let id = id.as_str().to_owned();
    eventually("a holds b's withdrawal", || async {
        a.space_states(SPACE).await.iter().any(|state| {
            holds(std::slice::from_ref(state), &id)
                && horizon::Standing::of(state) == horizon::Standing::Withdrawn
        })
    })
    .await;
    // b leaves: its card lapses on a's clock at once, and b comes back as soon as it can.
    b.close().await.expect("close b");
    manual.advance(11 * MIN);
    let back = Peer::start(config(
        &network,
        clock.clone(),
        Some("127.0.0.1:7998"),
        Some(a_address),
        b_identity,
    ))
    .await
    .expect("b comes back");
    back.pull_space(SPACE).await.expect("open");
    eventually("a holds b's new card", || async {
        hinted(&a, back.peer_id()).await
    })
    .await;
    // Ten minutes past the withdrawal's lease (and a new stay of under 35 minutes): kept.
    advance(&manual, 29 * MIN + 5_000).await;
    assert_eq!(
        a.space_horizon(SPACE).await.expect("open").rule,
        Rule::PerEntry
    );
    a.collect_now().await;
    assert!(
        holds(&a.space_states(SPACE).await, &id),
        "a writer back in view for under a lease and the grace was vouched for by its old stay"
    );
    for peer in [&back, &a] {
        peer.close().await.expect("close");
    }
}

// ------------------------------------------------------------------------------- the hint

/// The per-entry horizon is a promise the card makes; a peer configured with `wire.horizon` set
/// to anything but `1` does not make it, so it keeps the legacy horizon.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_that_does_not_advertise_the_hint_keeps_the_legacy_rule() {
    let network = MemoryNetwork::new();
    let manual = ManualClock::new(1_800_000_000_000);
    let mut config = config(
        &network,
        Arc::new(manual.clone()),
        Some("127.0.0.1:7999"),
        None,
        Identity::generate().expect("id"),
    );
    config.resource_hints.insert(horizon::HINT_HORIZON, "0");
    let lone = Peer::start(config).await.expect("starts");
    lone.pull_space(SPACE).await.expect("open");
    for _ in 0..40 {
        manual.advance(30 * MIN);
        let status = lone.space_horizon(SPACE).await.expect("open");
        assert_eq!(status.mode, Mode::Legacy, "{status:?}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    lone.close().await.expect("close");
}
