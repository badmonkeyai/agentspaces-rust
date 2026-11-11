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

//! Admission, founding, and hostile inputs at a Rust listening peer (SPEC §5.1, §5.2, §5.4):
//! an `OPEN` group admits every verified peer from its own introduction and refuses a forged or
//! foreign advertisement, and a third party's copy admits nobody; an `INVITE` group admits a
//! founder-issued or delegated credential and refuses a missing, misdirected, or revoked one,
//! evicting the members admitted under a credential when it is revoked; a listening founder
//! founds a signed group, restarts with the same GroupID, and serves a join by `aspace://` id,
//! while a group founded from text serves no founding; and floods of rumors, oversized digests,
//! relay frames for strangers, and admissions stay bounded and counted with no panic.

mod support;

use std::sync::Arc;
use std::time::Duration;

use agentspaces::clock::{Clock, SharedClock, SystemClock};
use agentspaces::group::{self, Charter, GroupSpec, MembershipPolicy};
use agentspaces::keystore;
use agentspaces::peer::{ListenerSpec, Peer, PeerConfig, PeerError};
use agentspaces::transport::memory::MemoryNetwork;
use agentspaces::wire::bodies::{
    self, KIND_ACK, KIND_DIGEST, KIND_PING, KIND_PULL_RESP, KIND_RELAY_FRAME, KIND_RUMOR,
};
use agentspaces::wire::cbor::{self, Map, Value};
use agentspaces::wire::identity::Identity;
use agentspaces::wire::{ids, revocation, social, time};
use support::{PATIENCE, RawPeer, eventually};

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
    tune: impl FnOnce(&mut PeerConfig),
) -> Peer {
    let mut config = PeerConfig::new(identity, group)
        .listen_on(ListenerSpec::bound(Arc::new(network.listen(address))));
    config.clock = system();
    config.listen.anti_entropy_period = Some(Duration::from_millis(200));
    tune(&mut config);
    Peer::start(config).await.expect("the listener starts")
}

/// A dial-only member of `group` dialing `address`, presenting `hints`.
async fn member(network: &MemoryNetwork, address: &str, group: GroupSpec, hints: Map) -> Peer {
    let mut config = PeerConfig::new(Identity::generate().expect("identity"), group);
    config.seeds = vec![address.parse().expect("seed")];
    config.dialers = vec![Arc::new(network.dialer())];
    config.clock = system();
    config.reconnect_interval = Duration::from_millis(50);
    config.dial_timeout = Duration::from_secs(1);
    config.join_timeout = Duration::from_secs(3);
    config.resource_hints = hints;
    Peer::start(config).await.expect("the member starts")
}

fn hints(credential: &str) -> Map {
    let mut hints = Map::new();
    hints.insert(social::HINT_KEY, credential);
    hints
}

/// Waits until `listener` lists `peer` among its admitted members (or not, `admitted` false,
/// held for a moment).
async fn admitted(listener: &Peer, peer: &str) {
    let listener = listener.clone();
    let peer = peer.to_owned();
    eventually("the admission", || {
        let listener = listener.clone();
        let peer = peer.clone();
        async move { listener.admitted_members().await.contains(&peer) }
    })
    .await;
}

/// Holds for half a second that `listener` has not admitted `peer`.
async fn stays_out(listener: &Peer, peer: &str) {
    for _ in 0..10 {
        assert!(
            !listener.admitted_members().await.contains(&peer.to_owned()),
            "{peer} was admitted"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Whether `frames` hold the listener's introduction addressed to `peer`.
fn introduced_to(frames: &[Map], peer: &str, listener: &str) -> bool {
    frames.iter().any(|env| {
        env.get("kind").and_then(Value::as_str) == Some(KIND_RUMOR)
            && env.get("from").and_then(Value::as_str) == Some(listener)
            && env.get("to").and_then(Value::as_str) == Some(peer)
    })
}

// ------------------------------------------------------------------------------- OPEN

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_open_group_admits_verified_peers_and_refuses_forgeries() {
    let network = MemoryNetwork::new();
    let address = "127.0.0.1:7811";
    let founding = "agentspaces-rust-open";
    let group = ids::group_id_from_founding(founding.as_bytes());
    let hub = listener(
        &network,
        address,
        Identity::generate().expect("identity"),
        GroupSpec::FoundingText(founding.to_owned()),
        |_| {},
    )
    .await;

    // A verified peer introducing itself is admitted and hears the hub's introduction at once.
    let honest = RawPeer::dial(
        &network,
        address,
        Identity::generate().expect("id"),
        &group,
        system(),
    )
    .await;
    assert!(honest.introduce(&Map::new()).await);
    admitted(&hub, honest.peer_id()).await;
    honest
        .wait_for("the hub's introduction", |frames| {
            introduced_to(frames, honest.peer_id(), hub.peer_id())
        })
        .await;

    // A third party's advertisement, introduced by another peer: a copy admits nobody.
    let absent = Identity::generate().expect("identity");
    let forger = RawPeer::dial(
        &network,
        address,
        Identity::generate().expect("id"),
        &group,
        system(),
    )
    .await;
    let copy = forger.signed_ad(&absent, &group, &Map::new());
    assert!(forger.rumor(bodies::STREAM_PEERS, "peer:copy", &copy).await);
    // An advertisement for another group, and one whose signature does not verify.
    let foreign = RawPeer::dial(
        &network,
        address,
        Identity::generate().expect("id"),
        &group,
        system(),
    )
    .await;
    let other = foreign.signed_ad(&foreign.identity, "zAnotherGroup", &Map::new());
    assert!(
        foreign
            .rumor(bodies::STREAM_PEERS, "peer:foreign", &other)
            .await
    );
    let tampered = RawPeer::dial(
        &network,
        address,
        Identity::generate().expect("id"),
        &group,
        system(),
    )
    .await;
    let mut bad = tampered.signed_ad(&tampered.identity, &group, &Map::new());
    if let Some(last) = bad.last_mut() {
        *last ^= 0x5a;
    }
    assert!(tampered.rumor(bodies::STREAM_PEERS, "peer:bad", &bad).await);
    // An admitted member forwarding the absent peer's advertisement admits nobody either.
    assert!(
        honest
            .rumor(bodies::STREAM_PEERS, "peer:forwarded", &copy)
            .await
    );

    let hub_peer = hub.clone();
    eventually("the refusals", || {
        let hub_peer = hub_peer.clone();
        async move {
            let refused = hub_peer.counters().await.listen.refused;
            refused.forged >= 2 && refused.foreign >= 1
        }
    })
    .await;
    for peer in [
        absent.peer_id(),
        forger.peer_id(),
        foreign.peer_id(),
        tampered.peer_id(),
    ] {
        stays_out(&hub, peer).await;
    }
    assert_eq!(
        hub.admitted_members().await,
        vec![honest.peer_id().to_owned()]
    );

    // A stranger's data frame is dropped and answered with nothing; its PING is answered.
    let before = forger.received().len();
    assert!(
        forger
            .send(KIND_DIGEST, &bodies::digest_body(&Map::new()), None)
            .await
    );
    assert!(
        forger
            .send(KIND_PING, &bodies::ping_body(7), Some(hub.peer_id()))
            .await
    );
    forger
        .wait_for("the ACK", |frames| {
            frames
                .iter()
                .any(|env| env.get("kind").and_then(Value::as_str) == Some(KIND_ACK))
        })
        .await;
    assert!(
        forger.of_kind(KIND_PULL_RESP).is_empty(),
        "a stranger's DIGEST is not answered"
    );
    assert!(forger.received().len() > before);
    let counters = hub.counters().await;
    assert!(counters.listen.stranger_frames >= 1, "{counters:?}");
    assert_eq!(counters.listen.admitted, 1, "{counters:?}");
    let _ = hub.close().await;
}

// ------------------------------------------------------------------------------- INVITE

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_invite_group_admits_credentials_and_evicts_revoked_ones() {
    let network = MemoryNetwork::new();
    let address = "127.0.0.1:7812";
    let founder = Identity::generate().expect("identity");
    let document = group::found(
        &founder,
        &Charter::new("crew", MembershipPolicy::Invite),
        now(),
    )
    .expect("found");
    let group_id = group::founding_group_id(&document).expect("it verifies");
    let spec = GroupSpec::FoundingDocument(document.clone());
    let hub = listener(&network, address, founder.clone(), spec.clone(), |_| {}).await;
    assert_eq!(hub.group_id(), group_id);

    // A founder-issued credential, bound to its candidate.
    let issued_to = Identity::generate().expect("identity");
    let credential = social::issue_credential(&founder, &group_id, issued_to.peer_id());
    let mut config = PeerConfig::new(issued_to.clone(), spec.clone());
    config.seeds = vec![address.parse().expect("seed")];
    config.dialers = vec![Arc::new(network.dialer())];
    config.reconnect_interval = Duration::from_millis(50);
    config.resource_hints = hints(&credential);
    let a = Peer::start(config).await.expect("a starts");
    admitted(&hub, a.peer_id()).await;

    // A delegated credential under an invite key the founder delegated.
    let invite = Identity::generate().expect("invite key");
    let delegation = social::delegate(
        &founder,
        &group_id,
        invite.public_raw(),
        now() + 3_600_000,
        Some("crew invite"),
    );
    let b_identity = Identity::generate().expect("identity");
    let delegated = social::issue_delegated(&delegation, &invite, b_identity.peer_id())
        .expect("a delegated credential");
    let mut config = PeerConfig::new(b_identity, spec.clone());
    config.seeds = vec![address.parse().expect("seed")];
    config.dialers = vec![Arc::new(network.dialer())];
    config.reconnect_interval = Duration::from_millis(50);
    config.resource_hints = hints(&delegated);
    let b = Peer::start(config).await.expect("b starts");
    admitted(&hub, b.peer_id()).await;

    // No credential, and another candidate's credential: refused.
    let c = member(&network, address, spec.clone(), Map::new()).await;
    let d = member(&network, address, spec.clone(), hints(&credential)).await;
    let hub_peer = hub.clone();
    eventually("the policy refusals", || {
        let hub_peer = hub_peer.clone();
        async move { hub_peer.counters().await.listen.refused.policy >= 2 }
    })
    .await;
    stays_out(&hub, c.peer_id()).await;
    stays_out(&hub, d.peer_id()).await;

    // A member admitted under its own credential carries the founder's revocations.
    let carrier_identity = Identity::generate().expect("identity");
    let carrier_credential =
        social::issue_credential(&founder, &group_id, carrier_identity.peer_id());
    let carrier = RawPeer::dial(&network, address, carrier_identity, &group_id, system()).await;
    assert!(carrier.introduce(&hints(&carrier_credential)).await);
    admitted(&hub, carrier.peer_id()).await;

    // Revoking a's credential evicts it, and it is refused when it comes back.
    let hash = social::credential_hash(&credential).expect("a hash");
    let payload = revoke_join(&founder, &group_id, &hash);
    assert!(
        carrier
            .rumor(revocation::CREDENTIAL_STREAM, "revoke:a", &payload)
            .await
    );
    let hub_peer = hub.clone();
    let a_id = a.peer_id().to_owned();
    eventually("a's eviction", || {
        let hub_peer = hub_peer.clone();
        let a_id = a_id.clone();
        async move { !hub_peer.admitted_members().await.contains(&a_id) }
    })
    .await;
    stays_out(&hub, a.peer_id()).await;

    // Revoking the delegation evicts every member admitted under it.
    let delegation_hash = social::delegation_hash(&delegated).expect("a hash");
    let payload = revoke_join(&founder, &group_id, &delegation_hash);
    assert!(
        carrier
            .rumor(revocation::CREDENTIAL_STREAM, "revoke:b", &payload)
            .await
    );
    let b_id = b.peer_id().to_owned();
    eventually("b's eviction", || {
        let hub_peer = hub_peer.clone();
        let b_id = b_id.clone();
        async move { !hub_peer.admitted_members().await.contains(&b_id) }
    })
    .await;
    stays_out(&hub, b.peer_id()).await;
    assert!(
        hub.admitted_members()
            .await
            .contains(&carrier.peer_id().to_owned())
    );
    for peer in [&a, &b, &c, &d] {
        let _ = peer.close().await;
    }
    let _ = hub.close().await;
}

// ------------------------------------------------------------------------------- founding

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_listening_founder_keeps_its_group_id_across_restarts_and_serves_joins_by_id() {
    let network = MemoryNetwork::new();
    let address = "127.0.0.1:7813";
    let dir = std::env::temp_dir().join(format!("aspace-listen-founding-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let charter = Charter::new("crew", MembershipPolicy::Open);
    let path = group::founding_path(&dir, "crew").expect("a path");

    let mut group_ids = Vec::new();
    for round in 0..2 {
        let identity = keystore::load_or_create(&dir).expect("the keystore");
        let document = group::found_or_load(&path, &identity, &charter, now()).expect("founding");
        let hub = listener(
            &network,
            address,
            identity,
            GroupSpec::FoundingDocument(document.clone()),
            |_| {},
        )
        .await;
        group_ids.push(hub.group_id().to_owned());
        // A peer that knows only the GroupID joins through the listener.
        let joiner = member(
            &network,
            address,
            GroupSpec::Join(format!("aspace://{}", hub.group_id())),
            Map::new(),
        )
        .await;
        assert_eq!(joiner.group_id(), hub.group_id(), "round {round}");
        let held = joiner.founding().await.expect("the verified founding");
        assert_eq!(
            cbor::encode(&Value::Map(held)),
            document,
            "the founding the listener holds"
        );
        admitted(&hub, joiner.peer_id()).await;
        assert!(hub.counters().await.listen.group_ads_served >= 1);
        let _ = joiner.close().await;
        let _ = hub.close().await;
        network.unlisten(address);
    }
    assert_eq!(group_ids[0], group_ids[1], "the restart keeps the GroupID");

    // A group founded from text has no signed founding: a join by id times out.
    let text = listener(
        &network,
        address,
        Identity::generate().expect("identity"),
        GroupSpec::FoundingText("agentspaces-rust-text".to_owned()),
        |_| {},
    )
    .await;
    let mut config = PeerConfig::new(
        Identity::generate().expect("identity"),
        GroupSpec::Join(format!("aspace://{}", text.group_id())),
    );
    config.seeds = vec![address.parse().expect("seed")];
    config.dialers = vec![Arc::new(network.dialer())];
    config.join_timeout = Duration::from_millis(1200);
    let refused = Peer::start(config).await;
    assert!(
        matches!(refused, Err(PeerError::JoinTimeout { .. })),
        "{refused:?}"
    );
    assert_eq!(text.counters().await.listen.group_ads_served, 0);
    let _ = text.close().await;
    let _ = std::fs::remove_dir_all(&dir);
}

// ------------------------------------------------------------------------------- hostile

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hostile_inputs_stay_bounded_and_counted() {
    let network = MemoryNetwork::new();
    let address = "127.0.0.1:7814";
    let founding = "agentspaces-rust-hostile";
    let group = ids::group_id_from_founding(founding.as_bytes());
    let hub = listener(
        &network,
        address,
        Identity::generate().expect("identity"),
        GroupSpec::FoundingText(founding.to_owned()),
        |config| {
            config.listen.max_members = 40;
            config.listen.max_links = 120;
            config.listen.admission_burst = 64;
            config.listen.admissions_per_second = 16;
            config.listen.max_replicated_spaces = 4;
        },
    )
    .await;
    let flooder = RawPeer::dial(
        &network,
        address,
        Identity::generate().expect("id"),
        &group,
        system(),
    )
    .await;
    assert!(flooder.introduce(&Map::new()).await);
    admitted(&hub, flooder.peer_id()).await;
    let watcher = RawPeer::dial(
        &network,
        address,
        Identity::generate().expect("id"),
        &group,
        system(),
    )
    .await;
    assert!(watcher.introduce(&Map::new()).await);
    admitted(&hub, watcher.peer_id()).await;

    // A rumor flood on a stream the hub does not read: forwarded once each, duplicates dropped.
    for n in 0..3000u32 {
        assert!(
            flooder
                .rumor("junk", &format!("j{n}"), &n.to_be_bytes())
                .await
        );
    }
    assert!(flooder.rumor("junk", "again", &0u32.to_be_bytes()).await);
    // Space rumors that do not decode, in more spaces than the hub replicates.
    for n in 0..10u32 {
        assert!(
            flooder
                .rumor(&format!("space:s{n}"), "bad", &[0xff, 0x00])
                .await
        );
    }
    // An oversized digest: more streams than one DIGEST is answered for.
    let mut digests = Map::new();
    for n in 0..200 {
        digests.insert(format!("space:x{n}"), vec![b'e'; 4096]);
    }
    assert!(
        flooder
            .send(
                KIND_DIGEST,
                &bodies::digest_body(&digests),
                Some(hub.peer_id())
            )
            .await
    );
    // Relay frames for a stranger and with a malformed path.
    let stranger = Identity::generate().expect("identity");
    let inner = flooder.frame(KIND_PING, &bodies::ping_body(1), Some(stranger.peer_id()));
    let relay = bodies::relay_frame_body(stranger.peer_id(), &inner, None, None);
    assert!(
        flooder
            .send(KIND_RELAY_FRAME, &relay, Some(hub.peer_id()))
            .await
    );
    let path = [watcher.peer_id(), hub.peer_id()];
    let relay = bodies::relay_frame_body(stranger.peer_id(), &inner, Some(&path), Some(0));
    assert!(
        flooder
            .send(KIND_RELAY_FRAME, &relay, Some(hub.peer_id()))
            .await
    );

    let hub_peer = hub.clone();
    let deadline = tokio::time::Instant::now() + PATIENCE;
    let counters = loop {
        let c = hub_peer.counters().await;
        let handled = c.listen.rumors_duplicate >= 1
            && c.listen.digests_truncated >= 1
            && c.listen.relays_not_member >= 1
            && c.listen.relays_bad_path >= 1;
        if handled {
            break c;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the flood was not handled in time: {c:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert!(counters.deltas_undecodable >= 10, "{counters:?}");
    assert!(counters.listen.rumors_unforwarded >= 10, "{counters:?}");
    assert!(counters.listen.spaces_replicated <= 4, "{counters:?}");
    // The other member hears the junk forwarded, each item at most once.
    watcher
        .wait_for("the forwarded flood", |frames| {
            frames
                .iter()
                .filter(|env| env.get("kind").and_then(Value::as_str) == Some(KIND_RUMOR))
                .count()
                > 100
        })
        .await;
    let junk = watcher
        .of_kind(KIND_RUMOR)
        .into_iter()
        .filter(|env| {
            env.get("body")
                .and_then(Value::as_bytes)
                .and_then(bodies::parse_rumor)
                .is_some_and(|rumor| rumor.stream_id == "junk")
        })
        .count();
    assert!(junk <= 3000, "{junk} junk rumors forwarded");

    // An admission flood: fresh peers on fresh links, past the bucket, the member bound, and
    // the link bound.
    let mut strangers = Vec::new();
    for _ in 0..150 {
        let raw = RawPeer::dial(
            &network,
            address,
            Identity::generate().expect("id"),
            &group,
            system(),
        )
        .await;
        let _ = raw.introduce(&Map::new()).await;
        strangers.push(raw);
    }
    // Past the link bound a new link takes the place of the oldest one nobody introduced itself
    // on (a refused stranger's), so the bound holds by closing those.
    eventually("the admission flood counted", || {
        let hub_peer = hub_peer.clone();
        async move {
            let c = hub_peer.counters().await.listen;
            c.refused.rate + c.refused.full >= 1 && c.links_refused + c.links_silent >= 1
        }
    })
    .await;
    assert!(hub.admitted_members().await.len() <= 40);
    let c = hub.counters().await.listen;
    assert!(
        c.links_accepted.saturating_sub(c.links_closed) <= 120,
        "the link bound held: {c:?}"
    );

    // A PULL_RESP nobody asked for: the flooder's targeted round is long gone from the bounded
    // list of members this hub expects answers from.
    assert!(
        flooder
            .send(
                KIND_PULL_RESP,
                &bodies::pull_resp_body(&Map::new()),
                Some(hub.peer_id())
            )
            .await
    );
    eventually("the unsolicited PULL_RESP counted", || {
        let hub_peer = hub_peer.clone();
        async move { hub_peer.counters().await.listen.pull_resps_unsolicited >= 1 }
    })
    .await;

    // A stranger that keeps sending data frames before introducing anyone is cut off.
    let pest = RawPeer::dial(
        &network,
        address,
        Identity::generate().expect("id"),
        &group,
        system(),
    )
    .await;
    drop(strangers);
    for _ in 0..100 {
        if !pest
            .send(KIND_DIGEST, &bodies::digest_body(&Map::new()), None)
            .await
        {
            break;
        }
    }
    eventually("the pest's link closed", || async { pest.is_closed() }).await;

    // The hub still serves an honest member.
    let honest = RawPeer::dial(
        &network,
        address,
        Identity::generate().expect("id"),
        &group,
        system(),
    )
    .await;
    let mut admitted_now = false;
    let deadline = tokio::time::Instant::now() + PATIENCE;
    while !admitted_now && tokio::time::Instant::now() < deadline {
        let _ = honest.introduce(&Map::new()).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        admitted_now = hub
            .admitted_members()
            .await
            .contains(&honest.peer_id().to_owned());
    }
    assert!(admitted_now || hub.admitted_members().await.len() >= 40);
    assert!(
        honest
            .send(KIND_PING, &bodies::ping_body(99), Some(hub.peer_id()))
            .await
    );
    honest
        .wait_for("an ACK", |frames| {
            frames
                .iter()
                .any(|env| env.get("kind").and_then(Value::as_str) == Some(KIND_ACK))
        })
        .await;
    let _ = hub.close().await;
}
