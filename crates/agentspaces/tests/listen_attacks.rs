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

//! Attacks on a Rust listening peer's admission and routing (SPEC §5.1, §5.2, §5.4, §6.1), each
//! a regression test of a hole that was closed:
//!
//! - a hub that joins an `INVITE` group by GroupID admits nobody before the founding verifies
//!   (an unverified group has no policy to admit under);
//! - a member evicted for a revoked credential hears nothing more on any link it holds, not only
//!   on the one its addressed frames took;
//! - a delegated credential re-encoded in another CBOR shape (another hash, the same signatures)
//!   is refused, as Java's wire decoding refuses it, so the revocation of its hash holds;
//! - a delegated credential with a leading control character is judged with its delegation, so
//!   the delegation's revocation evicts its holder and refuses the next one;
//! - a stranger that floods PINGs, reconnecting whenever it is cut off, does not starve the
//!   admission of an honest newcomer;
//! - a member with two links stays reachable on the older one when the newer one closes.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use agentspaces::clock::{Clock, SharedClock, SystemClock};
use agentspaces::group::{self, Charter, GroupSpec, MembershipPolicy};
use agentspaces::peer::{ListenerSpec, Peer, PeerConfig};
use agentspaces::transport::memory::MemoryNetwork;
use agentspaces::wire::bodies::{
    self, KIND_ACK, KIND_GROUP_AD, KIND_GROUP_AD_WANT, KIND_PING, KIND_RELAY_FRAME, KIND_RUMOR,
};
use agentspaces::wire::cbor::{self, Map, Value};
use agentspaces::wire::identity::Identity;
use agentspaces::wire::{ids, revocation, social, time};
use support::{FakeSeed, PATIENCE, RawPeer, eventually};

fn system() -> SharedClock {
    Arc::new(SystemClock)
}

fn now() -> i64 {
    SystemClock.now_ms()
}

/// A listening peer on `network` at `address` for `group`.
async fn listener(
    network: &MemoryNetwork,
    address: &str,
    identity: Identity,
    group: GroupSpec,
) -> Peer {
    let mut config = PeerConfig::new(identity, group)
        .listen_on(ListenerSpec::bound(Arc::new(network.listen(address))));
    config.clock = system();
    config.listen.anti_entropy_period = Some(Duration::from_millis(200));
    Peer::start(config).await.expect("the listener starts")
}

fn hints(credential: &str) -> Map {
    let mut hints = Map::new();
    hints.insert(social::HINT_KEY, credential);
    hints
}

/// An `INVITE` group founded by `founder`: its document and GroupID.
fn invite_group(founder: &Identity) -> (Vec<u8>, String) {
    let document = group::found(
        founder,
        &Charter::new("crew", MembershipPolicy::Invite),
        now(),
    )
    .expect("found");
    let group_id = group::founding_group_id(&document).expect("it verifies");
    (document, group_id)
}

/// The CBOR rumor payload of a founder-signed revocation of a join credential (or delegation)
/// hash.
fn revoke_join(founder: &Identity, group: &str, hash: &[u8; 32]) -> Vec<u8> {
    let ad = revocation::credential_revocation(
        founder.peer_id(),
        group,
        &time::instant_iso(now() - 1000),
        "PT720H",
        &revocation::join_credential_target(hash),
        revocation::UNSPECIFIED,
        None,
    )
    .expect("a credential revocation");
    cbor::encode(&Value::Map(revocation::sign_revocation(&ad, founder)))
}

/// Waits until `hub` lists `peer` among its admitted members.
async fn admitted(hub: &Peer, peer: &str) {
    let hub = hub.clone();
    let peer = peer.to_owned();
    eventually("the admission", || {
        let hub = hub.clone();
        let peer = peer.clone();
        async move { hub.admitted_members().await.contains(&peer) }
    })
    .await;
}

/// Waits until `hub` no longer lists `peer` among its admitted members.
async fn evicted(hub: &Peer, peer: &str) {
    let hub = hub.clone();
    let peer = peer.to_owned();
    eventually("the eviction", || {
        let hub = hub.clone();
        let peer = peer.clone();
        async move { !hub.admitted_members().await.contains(&peer) }
    })
    .await;
}

/// Holds for a second that `hub` has not admitted `peer`.
async fn stays_out(hub: &Peer, peer: &str) {
    for _ in 0..20 {
        assert!(
            !hub.admitted_members().await.contains(&peer.to_owned()),
            "{peer} was admitted"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Whether `frames` hold a RUMOR on `stream` whose item is `item`.
fn heard_rumor(frames: &[Map], stream: &str, item: &str) -> bool {
    frames.iter().any(|env| {
        env.get("kind").and_then(Value::as_str) == Some(KIND_RUMOR)
            && env
                .get("body")
                .and_then(Value::as_bytes)
                .and_then(bodies::parse_rumor)
                .is_some_and(|rumor| rumor.stream_id == stream && rumor.item_id == item)
    })
}

/// A raw member of `group` on `address` as `identity`, introduced with `hints` and admitted.
async fn raw_member(
    network: &MemoryNetwork,
    address: &str,
    hub: &Peer,
    identity: Identity,
    group: &str,
    hints: &Map,
) -> RawPeer {
    let raw = RawPeer::dial(network, address, identity, group, system()).await;
    assert!(raw.introduce(hints).await);
    admitted(hub, raw.peer_id()).await;
    raw
}

// ------------------------------------------------------------------------------- the founding

/// A hub joining an INVITE group by GroupID holds no verified founding until its seed answers;
/// a stranger that introduces itself meanwhile, with no credential, must not be admitted under
/// a policy nobody verified (and stay admitted once the founding says INVITE).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hub_joining_by_id_admits_nobody_before_its_founding_verifies() {
    let network = MemoryNetwork::new();
    let founder = Identity::generate().expect("identity");
    let (document, group_id) = invite_group(&founder);
    let founding = cbor::decode(&document)
        .ok()
        .and_then(Value::into_map)
        .expect("a founding map");
    let seed = FakeSeed::start(&network, "127.0.0.1:7911", &group_id, system());

    // The hub joins by id through the seed, which holds back the founding for now.
    let hub_address = "127.0.0.1:7912";
    let mut config = support::config(
        &network,
        Identity::generate().expect("identity"),
        GroupSpec::Join(format!("{}{group_id}", ids::URI_PREFIX)),
        &["127.0.0.1:7911"],
        system(),
    )
    .listen_on(ListenerSpec::bound(Arc::new(network.listen(hub_address))));
    config.join_timeout = Duration::from_secs(8);
    let starting = tokio::spawn(Peer::start(config));
    seed.wait_for("the hub's GROUP_AD_WANT", |frames| {
        frames
            .iter()
            .any(|frame| frame.kind() == KIND_GROUP_AD_WANT)
    })
    .await;

    // A stranger with no credential introduces itself to the joining hub.
    let stranger = RawPeer::dial(
        &network,
        hub_address,
        Identity::generate().expect("identity"),
        &group_id,
        system(),
    )
    .await;
    assert!(stranger.introduce(&Map::new()).await);
    tokio::time::sleep(Duration::from_millis(500)).await;

    // The seed answers; the hub's join completes under the verified INVITE founding.
    let body = bodies::group_ad_body(&founding).expect("a GROUP_AD body");
    seed.send(0, KIND_GROUP_AD, &body, None).await;
    let hub = tokio::time::timeout(PATIENCE, starting)
        .await
        .expect("the join completes")
        .expect("the start task")
        .expect("the hub joins");
    assert_eq!(hub.group_id(), group_id);
    stays_out(&hub, stranger.peer_id()).await;
    assert!(
        stranger
            .of_kind(KIND_RUMOR)
            .iter()
            .all(|env| env.get("from").and_then(Value::as_str) != Some(hub.peer_id())),
        "the hub introduced itself to a stranger it never verified a policy for"
    );
    let _ = hub.close().await;
}

// ------------------------------------------------------------------------------- eviction

/// A member that holds two links to the hub (it spoke on a second one) and is then evicted for
/// a revoked credential hears nothing more on either: every link it owns is closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_evicted_member_hears_nothing_more_on_any_of_its_links() {
    let network = MemoryNetwork::new();
    let address = "127.0.0.1:7921";
    let founder = Identity::generate().expect("identity");
    let (document, group_id) = invite_group(&founder);
    let hub = listener(
        &network,
        address,
        founder.clone(),
        GroupSpec::FoundingDocument(document),
    )
    .await;
    let invited = |identity: &Identity| {
        hints(&social::issue_credential(
            &founder,
            &group_id,
            identity.peer_id(),
        ))
    };

    let carrier_id = Identity::generate().expect("identity");
    let carrier = raw_member(
        &network,
        address,
        &hub,
        carrier_id.clone(),
        &group_id,
        &invited(&carrier_id),
    )
    .await;
    let watcher_id = Identity::generate().expect("identity");
    let watcher = raw_member(
        &network,
        address,
        &hub,
        watcher_id.clone(),
        &group_id,
        &invited(&watcher_id),
    )
    .await;

    // The member to be revoked, on its first link, then speaking on a second one.
    let member_id = Identity::generate().expect("identity");
    let credential = social::issue_credential(&founder, &group_id, member_id.peer_id());
    let first = raw_member(
        &network,
        address,
        &hub,
        member_id.clone(),
        &group_id,
        &hints(&credential),
    )
    .await;
    let second = RawPeer::dial(&network, address, member_id.clone(), &group_id, system()).await;
    assert!(
        second
            .send(KIND_PING, &bodies::ping_body(7), Some(hub.peer_id()))
            .await
    );
    second
        .wait_for("the ACK on the second link", |frames| {
            frames
                .iter()
                .any(|env| env.get("kind").and_then(Value::as_str) == Some(KIND_ACK))
        })
        .await;

    // The founder revokes the member's credential; the hub evicts it.
    let hash = social::credential_hash(&credential).expect("a hash");
    assert!(
        carrier
            .rumor(
                revocation::CREDENTIAL_STREAM,
                "revoke:member",
                &revoke_join(&founder, &group_id, &hash)
            )
            .await
    );
    evicted(&hub, member_id.peer_id()).await;

    // A member's rumor after the eviction reaches the watcher, and neither of the evicted
    // member's links.
    assert!(carrier.rumor("junk", "after-eviction", b"secret").await);
    watcher
        .wait_for("the forwarded rumor", |frames| {
            heard_rumor(frames, "junk", "after-eviction")
        })
        .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    for (name, link) in [("first", &first), ("second", &second)] {
        assert!(
            !heard_rumor(&link.received(), "junk", "after-eviction"),
            "the evicted member heard a rumor after its eviction on its {name} link"
        );
    }
    eventually("the evicted member's links closed", || async {
        first.is_closed() && second.is_closed()
    })
    .await;
    let _ = hub.close().await;
}

// ------------------------------------------------------------------------------- credentials

/// The `d1:` credential string of `credential`'s CBOR with its two fields swapped: the same
/// delegation and signature, so every signature still verifies, in bytes whose hash differs.
fn reshaped(credential: &str) -> String {
    let encoded = credential
        .trim()
        .strip_prefix(social::DELEGATED_PREFIX)
        .expect("a delegated credential");
    let bytes = social::base64_decode(encoded).expect("base64");
    let map = cbor::decode(&bytes)
        .ok()
        .and_then(Value::into_map)
        .expect("a map");
    let mut swapped = Map::new();
    for key in ["signature", "delegation"] {
        swapped.insert(key, map.get(key).expect("the field").clone());
    }
    let reshaped = cbor::encode(&Value::Map(swapped));
    assert_ne!(reshaped, bytes);
    format!(
        "{}{}",
        social::DELEGATED_PREFIX,
        social::base64_encode(&reshaped)
    )
}

/// A member evicted because the founder revoked its delegated credential cannot come back with
/// the same credential re-encoded: the reshaped bytes hash differently, and Java's wire decoding
/// refuses them, so this hub refuses them too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_re_encoded_delegated_credential_stays_revoked() {
    let network = MemoryNetwork::new();
    let address = "127.0.0.1:7931";
    let founder = Identity::generate().expect("identity");
    let (document, group_id) = invite_group(&founder);
    let hub = listener(
        &network,
        address,
        founder.clone(),
        GroupSpec::FoundingDocument(document),
    )
    .await;
    let carrier_id = Identity::generate().expect("identity");
    let carrier_credential = social::issue_credential(&founder, &group_id, carrier_id.peer_id());
    let carrier = raw_member(
        &network,
        address,
        &hub,
        carrier_id,
        &group_id,
        &hints(&carrier_credential),
    )
    .await;

    let invite = Identity::generate().expect("invite key");
    let delegation = social::delegate(
        &founder,
        &group_id,
        invite.public_raw(),
        now() + 3_600_000,
        Some("crew invite"),
    );
    let member_id = Identity::generate().expect("identity");
    let credential = social::issue_delegated(&delegation, &invite, member_id.peer_id())
        .expect("a delegated credential");
    let member = raw_member(
        &network,
        address,
        &hub,
        member_id.clone(),
        &group_id,
        &hints(&credential),
    )
    .await;

    let hash = social::credential_hash(&credential).expect("a hash");
    assert!(
        carrier
            .rumor(
                revocation::CREDENTIAL_STREAM,
                "revoke:member",
                &revoke_join(&founder, &group_id, &hash)
            )
            .await
    );
    evicted(&hub, member_id.peer_id()).await;
    drop(member);

    // The same credential, reshaped: a new hash, the same signatures.
    let again = reshaped(&credential);
    assert_ne!(
        social::credential_hash(&again).expect("a hash"),
        hash,
        "the reshaped credential hashes differently"
    );
    let returning = RawPeer::dial(&network, address, member_id.clone(), &group_id, system()).await;
    assert!(returning.introduce(&hints(&again)).await);
    stays_out(&hub, member_id.peer_id()).await;
    let _ = hub.close().await;
}

/// A delegated credential behind a leading control character still dies with its delegation:
/// the member admitted under it is evicted when the founder revokes the delegation, and the
/// next one presenting another credential under it is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_padded_delegated_credential_dies_with_its_delegation() {
    let network = MemoryNetwork::new();
    let address = "127.0.0.1:7941";
    let founder = Identity::generate().expect("identity");
    let (document, group_id) = invite_group(&founder);
    let hub = listener(
        &network,
        address,
        founder.clone(),
        GroupSpec::FoundingDocument(document),
    )
    .await;
    let carrier_id = Identity::generate().expect("identity");
    let carrier_credential = social::issue_credential(&founder, &group_id, carrier_id.peer_id());
    let carrier = raw_member(
        &network,
        address,
        &hub,
        carrier_id,
        &group_id,
        &hints(&carrier_credential),
    )
    .await;

    let invite = Identity::generate().expect("invite key");
    let delegation = social::delegate(
        &founder,
        &group_id,
        invite.public_raw(),
        now() + 3_600_000,
        Some("crew invite"),
    );
    let padded = |identity: &Identity| {
        let credential = social::issue_delegated(&delegation, &invite, identity.peer_id())
            .expect("a delegated credential");
        format!("\u{1}{credential}")
    };
    let first_id = Identity::generate().expect("identity");
    let first = raw_member(
        &network,
        address,
        &hub,
        first_id.clone(),
        &group_id,
        &hints(&padded(&first_id)),
    )
    .await;

    // The founder revokes the whole delegation.
    let delegation_hash = social::delegation_hash(&delegation).expect("a hash");
    assert!(
        carrier
            .rumor(
                revocation::CREDENTIAL_STREAM,
                "revoke:delegation",
                &revoke_join(&founder, &group_id, &delegation_hash)
            )
            .await
    );
    evicted(&hub, first_id.peer_id()).await;
    drop(first);

    let next_id = Identity::generate().expect("identity");
    let next = RawPeer::dial(&network, address, next_id.clone(), &group_id, system()).await;
    assert!(next.introduce(&hints(&padded(&next_id))).await);
    stays_out(&hub, next_id.peer_id()).await;
    let _ = hub.close().await;
}

// ------------------------------------------------------------------------------- floods

/// A stranger that floods PINGs, and dials again whenever its link is cut, does not starve the
/// admission of an honest newcomer that introduces itself meanwhile.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stranger_s_ping_flood_does_not_starve_admissions() {
    let network = MemoryNetwork::new();
    let address = "127.0.0.1:7951";
    let founding = "agentspaces-rust-ping-flood";
    let group = ids::group_id_from_founding(founding.as_bytes());
    let hub = listener(
        &network,
        address,
        Identity::generate().expect("identity"),
        GroupSpec::FoundingText(founding.to_owned()),
    )
    .await;

    let flooding = Arc::new(AtomicBool::new(true));
    let flood = {
        let network = network.clone();
        let group = group.clone();
        let flooding = Arc::clone(&flooding);
        tokio::spawn(async move {
            let mut sent = 0u64;
            while flooding.load(Ordering::SeqCst) {
                let pest = RawPeer::dial(
                    &network,
                    address,
                    Identity::generate().expect("identity"),
                    &group,
                    system(),
                )
                .await;
                let mut nonce = 0i64;
                while flooding.load(Ordering::SeqCst) && !pest.is_closed() {
                    nonce += 1;
                    if !pest.send(KIND_PING, &bodies::ping_body(nonce), None).await {
                        break;
                    }
                    sent += 1;
                    if nonce % 64 == 0 {
                        tokio::task::yield_now().await;
                    }
                }
            }
            sent
        })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;

    // An honest newcomer introduces itself, as a member re-leasing would, a few times.
    let honest = RawPeer::dial(
        &network,
        address,
        Identity::generate().expect("identity"),
        &group,
        system(),
    )
    .await;
    let mut admitted_now = false;
    for _ in 0..8 {
        assert!(honest.introduce(&Map::new()).await);
        tokio::time::sleep(Duration::from_millis(250)).await;
        if hub
            .admitted_members()
            .await
            .contains(&honest.peer_id().to_owned())
        {
            admitted_now = true;
            break;
        }
    }
    flooding.store(false, Ordering::SeqCst);
    let sent = flood.await.expect("the flood task");
    let counters = hub.counters().await.listen;
    assert!(sent > 1000, "the flood sent only {sent} PINGs");
    assert!(
        admitted_now,
        "the honest newcomer was starved by {sent} PINGs: {counters:?}"
    );
    let _ = hub.close().await;
}

// ------------------------------------------------------------------------------- routes

/// A member with two links stays reachable when the newer one, which its addressed frames took,
/// closes: they take its older link, which still carries it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_stays_reachable_on_its_older_link_when_the_newer_one_closes() {
    let network = MemoryNetwork::new();
    let address = "127.0.0.1:7961";
    let founding = "agentspaces-rust-two-links";
    let group = ids::group_id_from_founding(founding.as_bytes());
    let hub = listener(
        &network,
        address,
        Identity::generate().expect("identity"),
        GroupSpec::FoundingText(founding.to_owned()),
    )
    .await;
    let member_id = Identity::generate().expect("identity");
    let older = raw_member(
        &network,
        address,
        &hub,
        member_id.clone(),
        &group,
        &Map::new(),
    )
    .await;
    let newer = RawPeer::dial(&network, address, member_id.clone(), &group, system()).await;
    assert!(
        newer
            .send(KIND_PING, &bodies::ping_body(1), Some(hub.peer_id()))
            .await
    );
    newer
        .wait_for("the ACK on the newer link", |frames| {
            frames
                .iter()
                .any(|env| env.get("kind").and_then(Value::as_str) == Some(KIND_ACK))
        })
        .await;
    newer.close();
    drop(newer);
    let hub_peer = hub.clone();
    eventually("the newer link's close", || {
        let hub_peer = hub_peer.clone();
        async move { hub_peer.counters().await.listen.links_closed >= 1 }
    })
    .await;
    assert!(
        hub.linked_members()
            .await
            .contains(&member_id.peer_id().to_owned()),
        "the member's older link no longer reaches it"
    );

    // Another member relays a PING to it through the hub: it arrives on the older link.
    let sender = raw_member(
        &network,
        address,
        &hub,
        Identity::generate().expect("identity"),
        &group,
        &Map::new(),
    )
    .await;
    let inner = sender.frame(KIND_PING, &bodies::ping_body(5), Some(member_id.peer_id()));
    let relay = bodies::relay_frame_body(member_id.peer_id(), &inner, None, None);
    assert!(
        sender
            .send(KIND_RELAY_FRAME, &relay, Some(hub.peer_id()))
            .await
    );
    older
        .wait_for("the relayed frame on the older link", |frames| {
            frames
                .iter()
                .any(|env| env.get("kind").and_then(Value::as_str) == Some(KIND_RELAY_FRAME))
        })
        .await;
    let _ = hub.close().await;
}

// ------------------------------------------------------------------------------- slowloris

/// A stranger that fills the hub's bound of links with links that never introduce anyone (and
/// replaces each one the introduction timeout closes) does not lock newcomers out: a newcomer's
/// link takes the place of the oldest such link.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idle_links_at_the_link_bound_do_not_lock_newcomers_out() {
    let network = MemoryNetwork::new();
    let address = "127.0.0.1:7971";
    let founding = "agentspaces-rust-slowloris";
    let group = ids::group_id_from_founding(founding.as_bytes());
    let mut config = PeerConfig::new(
        Identity::generate().expect("identity"),
        GroupSpec::FoundingText(founding.to_owned()),
    )
    .listen_on(ListenerSpec::bound(Arc::new(network.listen(address))));
    config.clock = system();
    config.listen.max_links = 8;
    let hub = Peer::start(config).await.expect("the listener starts");

    let mut idle = Vec::new();
    for _ in 0..8 {
        idle.push(
            RawPeer::dial(
                &network,
                address,
                Identity::generate().expect("identity"),
                &group,
                system(),
            )
            .await,
        );
    }
    let hub_peer = hub.clone();
    eventually("the idle links held", || {
        let hub_peer = hub_peer.clone();
        async move { hub_peer.counters().await.listen.links_accepted >= 8 }
    })
    .await;

    let honest = RawPeer::dial(
        &network,
        address,
        Identity::generate().expect("identity"),
        &group,
        system(),
    )
    .await;
    assert!(honest.introduce(&Map::new()).await);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while !hub
        .admitted_members()
        .await
        .contains(&honest.peer_id().to_owned())
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the newcomer was locked out by idle links: {:?}",
            hub.counters().await.listen
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        idle.iter().any(RawPeer::is_closed),
        "an idle link made room"
    );
    let _ = hub.close().await;
}

// ------------------------------------------------------------------------------- many links

/// Opens another link to `address` as `identity` and binds it to the member with a PING the hub
/// answers on it.
async fn extra_link(
    network: &MemoryNetwork,
    address: &str,
    hub: &Peer,
    identity: &Identity,
    group: &str,
    nonce: i64,
) -> RawPeer {
    let raw = RawPeer::dial(network, address, identity.clone(), group, system()).await;
    assert!(
        raw.send(KIND_PING, &bodies::ping_body(nonce), Some(hub.peer_id()))
            .await
    );
    raw.wait_for("the ACK on the extra link", |frames| {
        frames
            .iter()
            .any(|env| env.get("kind").and_then(Value::as_str) == Some(KIND_ACK))
    })
    .await;
    raw
}

/// A member that opens many links to the hub hears each rumor once, as a Java seed sends to one
/// connection per member, not once per link: its links multiply nothing the hub sends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_with_many_links_hears_each_rumor_once() {
    let network = MemoryNetwork::new();
    let address = "127.0.0.1:7981";
    let founding = "agentspaces-rust-many-links";
    let group = ids::group_id_from_founding(founding.as_bytes());
    let hub = listener(
        &network,
        address,
        Identity::generate().expect("identity"),
        GroupSpec::FoundingText(founding.to_owned()),
    )
    .await;
    let many_id = Identity::generate().expect("identity");
    let mut links = vec![
        raw_member(
            &network,
            address,
            &hub,
            many_id.clone(),
            &group,
            &Map::new(),
        )
        .await,
    ];
    for nonce in 0..3 {
        links.push(extra_link(&network, address, &hub, &many_id, &group, nonce).await);
    }
    let writer = raw_member(
        &network,
        address,
        &hub,
        Identity::generate().expect("identity"),
        &group,
        &Map::new(),
    )
    .await;
    let watcher = raw_member(
        &network,
        address,
        &hub,
        Identity::generate().expect("identity"),
        &group,
        &Map::new(),
    )
    .await;
    assert!(writer.rumor("junk", "once", b"payload").await);
    watcher
        .wait_for("the forwarded rumor", |frames| {
            heard_rumor(frames, "junk", "once")
        })
        .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let copies = links
        .iter()
        .filter(|link| heard_rumor(&link.received(), "junk", "once"))
        .count();
    assert_eq!(
        copies,
        1,
        "the member with {} links heard {copies} copies",
        links.len()
    );
    let _ = hub.close().await;
}

/// One member cannot hold every link the hub allows by opening link after link: it keeps a few,
/// the oldest of its others closing, and a newcomer still gets in.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_member_cannot_hold_every_link() {
    let network = MemoryNetwork::new();
    let address = "127.0.0.1:7991";
    let founding = "agentspaces-rust-link-hog";
    let group = ids::group_id_from_founding(founding.as_bytes());
    let mut config = PeerConfig::new(
        Identity::generate().expect("identity"),
        GroupSpec::FoundingText(founding.to_owned()),
    )
    .listen_on(ListenerSpec::bound(Arc::new(network.listen(address))));
    config.clock = system();
    config.listen.max_links = 8;
    let hub = Peer::start(config).await.expect("the listener starts");
    let hog_id = Identity::generate().expect("identity");
    let mut links =
        vec![raw_member(&network, address, &hub, hog_id.clone(), &group, &Map::new()).await];
    for nonce in 0..7 {
        links.push(extra_link(&network, address, &hub, &hog_id, &group, nonce).await);
    }

    let honest = RawPeer::dial(
        &network,
        address,
        Identity::generate().expect("identity"),
        &group,
        system(),
    )
    .await;
    let _ = honest.introduce(&Map::new()).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while !hub
        .admitted_members()
        .await
        .contains(&honest.peer_id().to_owned())
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "one member's links locked the newcomer out: {:?}",
            hub.counters().await.listen
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let _ = hub.close().await;
}

// ------------------------------------------------------------------------------- attestation

/// Whether `frames` hold an ACK of `nonce`.
fn acked(frames: &[Map], nonce: i64) -> bool {
    frames.iter().any(|env| {
        env.get("kind").and_then(Value::as_str) == Some(KIND_ACK)
            && env
                .get("body")
                .and_then(Value::as_bytes)
                .and_then(bodies::parse_ack)
                == Some(nonce)
    })
}

/// Under SPEC §5.6's required attestation: a frame of one member inside another's RELAY_FRAME
/// is dropped, a member's frame on a link attested for someone else is dropped and evicts
/// nobody, a stranger on an unattested link is never admitted, and a member's frame on a link
/// that attests nobody evicts it from every link it holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn required_attestation_holds_against_relays_impersonation_and_bare_links() {
    let network = MemoryNetwork::new();
    let address = "127.0.0.1:7995";
    let founding = "agentspaces-rust-attested-hub";
    let group = ids::group_id_from_founding(founding.as_bytes());
    let mut config = PeerConfig::new(
        Identity::generate().expect("identity"),
        GroupSpec::FoundingText(founding.to_owned()),
    )
    .listen_on(ListenerSpec::bound(Arc::new(network.listen(address))));
    config.clock = system();
    config.listen.require_attestation = true;
    let hub = Peer::start(config).await.expect("the listener starts");
    let attested = |identity: &Identity| {
        let network = network.clone();
        let identity = identity.clone();
        let group = group.clone();
        let hub_id = hub.peer_id().to_owned();
        async move {
            let peer_id = identity.peer_id().to_owned();
            RawPeer::dial_attested(
                &network,
                address,
                identity,
                &group,
                system(),
                &hub_id,
                &peer_id,
            )
            .await
        }
    };
    let a_id = Identity::generate().expect("identity");
    let b_id = Identity::generate().expect("identity");
    let a = attested(&a_id).await;
    assert!(a.introduce(&Map::new()).await);
    admitted(&hub, a.peer_id()).await;
    let b = attested(&b_id).await;
    assert!(b.introduce(&Map::new()).await);
    admitted(&hub, b.peer_id()).await;

    // b's PING inside a's RELAY_FRAME to the hub: dropped, never answered.
    let inner = b.frame(KIND_PING, &bodies::ping_body(77), Some(hub.peer_id()));
    let relay = bodies::relay_frame_body(hub.peer_id(), &inner, None, None);
    assert!(a.send(KIND_RELAY_FRAME, &relay, Some(hub.peer_id())).await);
    // b's signed PING on a's link (attested as a): dropped, and b stays a member.
    let foreign = b.frame(KIND_PING, &bodies::ping_body(88), Some(hub.peer_id()));
    assert!(a.send_raw(foreign).await);
    // An attested control: a's own PING is answered.
    assert!(
        a.send(KIND_PING, &bodies::ping_body(99), Some(hub.peer_id()))
            .await
    );
    a.wait_for("the control ACK", |frames| acked(frames, 99))
        .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !acked(&b.received(), 77),
        "a relayed inner frame was answered"
    );
    assert!(
        !acked(&b.received(), 88),
        "an impersonating frame was answered"
    );
    assert!(!acked(&a.received(), 77) && !acked(&a.received(), 88));
    assert!(
        hub.admitted_members()
            .await
            .contains(&b_id.peer_id().to_owned()),
        "a frame attested for someone else evicted its signer"
    );

    // A stranger on a link that attests nobody is never admitted.
    let stranger = RawPeer::dial(
        &network,
        address,
        Identity::generate().expect("identity"),
        &group,
        system(),
    )
    .await;
    assert!(stranger.introduce(&Map::new()).await);
    stays_out(&hub, stranger.peer_id()).await;

    // b's own frame on a link that attests nobody: b is evicted, its attested link closed.
    let bare = RawPeer::dial(&network, address, b_id.clone(), &group, system()).await;
    assert!(
        bare.send(KIND_PING, &bodies::ping_body(5), Some(hub.peer_id()))
            .await
    );
    evicted(&hub, b_id.peer_id()).await;
    eventually("b's attested link closed", || async { b.is_closed() }).await;
    assert!(!acked(&bare.received(), 5));
    let _ = hub.close().await;
}
