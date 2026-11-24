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

//! The targeted relay of SPEC v0.1.36 §5.2 from the holder's side. A Java member that holds no
//! link to a dial-only member, and cannot dial it, probes it through the holders its
//! advertisement names in `relay.via`: a `PING_REQ` to the holder, which carries a `PING` to the
//! member on its link and vouches for the member's `ACK` back to the prober. A Rust listening
//! peer is such a holder for the dial-only peers (Rust, TypeScript, Python, Ruby) that dial it;
//! the dial-only member names it and answers the probe at once. Here a raw member stands in for
//! the Java prober.

mod support;

use std::sync::Arc;
use std::time::Duration;

use agentspaces::clock::{SharedClock, SystemClock};
use agentspaces::group::GroupSpec;
use agentspaces::peer::{ListenerSpec, Peer, PeerConfig};
use agentspaces::transport::memory::MemoryNetwork;
use agentspaces::wire::bodies::{self, KIND_ACK, KIND_PING_REQ};
use agentspaces::wire::cbor::{self, Map, Value};
use agentspaces::wire::cbor_map;
use agentspaces::wire::identity::Identity;
use support::{RawPeer, eventually};

const FOUNDING: &str = "agentspaces-rust-targeted-relay";
const ADDRESS: &str = "127.0.0.1:7961";

fn system() -> SharedClock {
    Arc::new(SystemClock)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_probe_through_the_holder_named_in_relay_via_reaches_the_dial_only_member() {
    let network = MemoryNetwork::new();
    let mut config = PeerConfig::new(
        Identity::generate().expect("identity"),
        GroupSpec::FoundingText(FOUNDING.to_owned()),
    )
    .listen_on(ListenerSpec::bound(Arc::new(network.listen(ADDRESS))));
    config.clock = system();
    config.listen.anti_entropy_period = Some(Duration::from_millis(200));
    let holder = Peer::start(config).await.expect("the holder starts");

    let mut config = PeerConfig::new(
        Identity::generate().expect("identity"),
        GroupSpec::FoundingText(FOUNDING.to_owned()),
    );
    config.clock = system();
    config.seeds = vec![ADDRESS.parse().expect("seed")];
    config.dialers = vec![Arc::new(network.dialer())];
    let member = Peer::start(config)
        .await
        .expect("the dial-only member starts");
    let (holder_id, member_id) = (holder.peer_id().to_owned(), member.peer_id().to_owned());
    eventually("the member names its holder in relay.via", || {
        let member = member.clone();
        let holder_id = holder_id.clone();
        async move { member.seed_peer().await.as_deref() == Some(holder_id.as_str()) }
    })
    .await;
    eventually("the holder holds the member's link", || {
        let holder = holder.clone();
        let member_id = member_id.clone();
        async move { holder.linked_members().await.contains(&member_id) }
    })
    .await;

    // The prober, a member with no link to the dial-only member.
    let prober = RawPeer::dial(
        &network,
        ADDRESS,
        Identity::generate().expect("identity"),
        holder.group_id(),
        system(),
    )
    .await;
    assert!(prober.introduce(&Map::new()).await);
    eventually("the prober admitted", || {
        let holder = holder.clone();
        let prober_id = prober.peer_id().to_owned();
        async move { holder.admitted_members().await.contains(&prober_id) }
    })
    .await;
    let request = cbor::encode(&cbor_map! { "target" => member_id.as_str(), "nonce" => 4242 });
    assert!(prober.send(KIND_PING_REQ, &request, Some(&holder_id)).await);
    let vouched = |frames: &[Map]| {
        frames.iter().any(|env| {
            let body = env
                .get("body")
                .and_then(Value::as_bytes)
                .unwrap_or_default();
            env.get("kind").and_then(Value::as_str) == Some(KIND_ACK)
                && bodies::parse_ack(body) == Some(4242)
                && cbor::decode(body)
                    .ok()
                    .and_then(|ack| {
                        ack.get("onBehalf")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    })
                    .as_deref()
                    == Some(member_id.as_str())
        })
    };
    prober
        .wait_for("the holder's vouch for the dial-only member", vouched)
        .await;
    assert!(holder.counters().await.pings_relayed >= 1);
    let _ = member.close().await;
    let _ = holder.close().await;
}
