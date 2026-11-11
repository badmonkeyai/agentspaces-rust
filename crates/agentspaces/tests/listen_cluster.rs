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

//! Listening peers over `tls` with required attestation (SPEC §5.6), and two listening peers in
//! one group: the second dials the first and replicates what it carries, and when the first is
//! killed the dial-only members fail over to the second and keep working.

mod support;

use std::sync::Arc;
use std::time::Duration;

use agentspaces::clock::{SharedClock, SystemClock};
use agentspaces::group::GroupSpec;
use agentspaces::peer::{ListenerSpec, Peer, PeerConfig, PeerError, default_dialers};
use agentspaces::space::{Fleet, Lease, Template};
use agentspaces::transport::Dialer;
use agentspaces::transport::memory::MemoryNetwork;
use agentspaces::transport::tls::TlsDialer;
use agentspaces::wire::cbor::Map;
use agentspaces::wire::identity::Identity;
use serde::{Deserialize, Serialize};
use support::{PATIENCE, eventually};

const SPACE: &str = "tasks";
const SETTLE: Duration = Duration::from_millis(300);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, agentspaces::Entry)]
#[entry(schema = "com.acme.Job#v1")]
struct Job {
    topic: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, agentspaces::Entry)]
#[entry(schema = "com.acme.Done#v1")]
struct Done {
    topic: String,
    by: String,
}

fn system() -> SharedClock {
    Arc::new(SystemClock)
}

fn job(topic: &str) -> Job {
    Job {
        topic: topic.to_owned(),
    }
}

/// Waits until `listener` lists `peer` among the members it holds a link to.
async fn linked(listener: &Peer, peer: &str) {
    let listener = listener.clone();
    let peer = peer.to_owned();
    eventually("the member's link", || {
        let listener = listener.clone();
        let peer = peer.clone();
        async move { listener.linked_members().await.contains(&peer) }
    })
    .await;
}

/// Waits until `fleet` reads a job on `topic`.
async fn wait_job(fleet: &Fleet, topic: &str) {
    let wanted = Template::of::<Job>()
        .where_clause(&format!("topic={topic}"))
        .expect("a clause");
    fleet
        .space(SPACE)
        .read_typed::<Job>(&wanted, PATIENCE)
        .await
        .expect("read")
        .unwrap_or_else(|| panic!("no job {topic} in time"));
}

/// Takes and completes jobs on `fleet` until none is left within a second; answers their topics.
async fn take_all(fleet: &Fleet, name: &str) -> Vec<String> {
    let space = fleet.space(SPACE).with_settle(SETTLE);
    let mut took = Vec::new();
    while let Some(taken) = space
        .take_typed::<Job>(
            &Template::of::<Job>(),
            Lease::DEFAULT_TAKE,
            Duration::from_millis(1000),
        )
        .await
        .expect("take")
    {
        let topic = taken.value().topic.clone();
        taken
            .complete_with(
                &Done {
                    topic: topic.clone(),
                    by: name.to_owned(),
                },
                Lease::DEFAULT_RESULT,
                Map::new(),
            )
            .await
            .expect("complete");
        took.push(topic);
    }
    took
}

// ------------------------------------------------------------------------------- tls

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tls_hub_requiring_attestation_serves_attested_members_alone() {
    let founding = GroupSpec::FoundingText("agentspaces-rust-tls-hub".to_owned());
    // Required attestation refuses a plaintext listener outright.
    let mut plain = PeerConfig::new(Identity::generate().expect("identity"), founding.clone())
        .listen_on(ListenerSpec::tcp("127.0.0.1:0"));
    plain.listen.require_attestation = true;
    let refused = Peer::start(plain).await;
    assert!(
        matches!(refused, Err(PeerError::InvalidArgument(_))),
        "{refused:?}"
    );

    let mut config = PeerConfig::new(Identity::generate().expect("identity"), founding.clone())
        .listen_on(ListenerSpec::tls("127.0.0.1:0"));
    config.clock = system();
    config.listen.require_attestation = true;
    let hub = Peer::start(config).await.expect("the tls hub starts");
    let seed = format!("tls://{}", hub.listen_addrs()[0].address());
    let member = |dialers: Vec<Arc<dyn Dialer>>| {
        let founding = founding.clone();
        let seed = seed.clone();
        async move {
            let mut config = PeerConfig::new(Identity::generate().expect("identity"), founding);
            config.seeds = vec![seed.parse().expect("seed")];
            config.dialers = dialers;
            config.clock = system();
            config.reconnect_interval = Duration::from_millis(100);
            config.dial_timeout = Duration::from_secs(3);
            Fleet::from_peer(Peer::start(config).await.expect("the member starts"))
        }
    };
    let a = member(default_dialers()).await;
    let b = member(default_dialers()).await;
    let c = member(default_dialers()).await;
    for fleet in [&a, &b, &c] {
        linked(&hub, fleet.peer().peer_id()).await;
        let link = fleet.peer().link().expect("a link");
        assert_eq!(link.attested.as_deref(), Some(hub.peer_id()));
    }
    for n in 0..6 {
        a.space(SPACE)
            .write(&job(&format!("j{n}")), Lease::DEFAULT_WRITE, Map::new())
            .await
            .expect("write");
    }
    wait_job(&b, "j5").await;
    wait_job(&c, "j5").await;
    let (left, right) = tokio::join!(take_all(&b, "b"), take_all(&c, "c"));
    let mut took: Vec<String> = left.into_iter().chain(right).collect();
    took.sort();
    assert_eq!(took, (0..6).map(|n| format!("j{n}")).collect::<Vec<_>>());
    let space = a.space(SPACE);
    eventually("every result at the writer", || {
        let space = space.clone();
        async move {
            space
                .read_all_typed::<Done>(&Template::of::<Done>(), 100)
                .await
                .is_ok_and(|done| done.len() == 6)
        }
    })
    .await;

    // A member whose TLS dial presents no certificate is attested nowhere: never admitted.
    let anonymous: Arc<dyn Dialer> = Arc::new(TlsDialer::anonymous().expect("a dialer"));
    let stranger = member(vec![anonymous]).await;
    let hub_peer = hub.clone();
    eventually("the unattested frames dropped", || {
        let hub_peer = hub_peer.clone();
        async move { hub_peer.counters().await.listen.unattested_frames >= 1 }
    })
    .await;
    assert!(
        !hub.admitted_members()
            .await
            .contains(&stranger.peer().peer_id().to_owned())
    );
    for fleet in [&a, &b, &c, &stranger] {
        fleet.close().await.expect("close");
    }
    let _ = hub.close().await;
}

// ------------------------------------------------------------------------------- failover

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn members_fail_over_to_a_second_listening_peer_and_keep_working() {
    let network = MemoryNetwork::new();
    let (first_address, second_address) = ("127.0.0.1:7821", "127.0.0.1:7822");
    let founding = GroupSpec::FoundingText("agentspaces-rust-failover".to_owned());
    let listening = |address: &str, seeds: &[&str]| {
        let mut config = PeerConfig::new(Identity::generate().expect("identity"), founding.clone())
            .listen_on(ListenerSpec::bound(Arc::new(network.listen(address))));
        config.seeds = seeds
            .iter()
            .map(|seed| seed.parse().expect("seed"))
            .collect();
        config.dialers = vec![Arc::new(network.dialer())];
        config.clock = system();
        config.reconnect_interval = Duration::from_millis(100);
        config.listen.anti_entropy_period = Some(Duration::from_millis(200));
        config
    };
    let first = Peer::start(listening(first_address, &[]))
        .await
        .expect("the first hub");
    let second = Peer::start(listening(second_address, &[first_address]))
        .await
        .expect("the second hub");
    linked(&first, second.peer_id()).await;

    let member = || {
        let mut config = PeerConfig::new(Identity::generate().expect("identity"), founding.clone());
        config.seeds = vec![
            first_address.parse().expect("seed"),
            second_address.parse().expect("seed"),
        ];
        config.dialers = vec![Arc::new(network.dialer())];
        config.clock = system();
        config.reconnect_interval = Duration::from_millis(50);
        config.dial_timeout = Duration::from_secs(1);
        async move { Fleet::from_peer(Peer::start(config).await.expect("a member")) }
    };
    let a = member().await;
    let b = member().await;
    let c = member().await;
    for fleet in [&a, &b, &c] {
        linked(&first, fleet.peer().peer_id()).await;
    }
    for n in 0..4 {
        a.space(SPACE)
            .write(
                &job(&format!("before{n}")),
                Lease::DEFAULT_WRITE,
                Map::new(),
            )
            .await
            .expect("write");
    }
    wait_job(&b, "before3").await;
    // The second hub replicates through its link to the first.
    let replica = second.clone();
    eventually("the second hub's replica", || {
        let replica = replica.clone();
        async move { replica.space_states(SPACE).await.len() >= 4 }
    })
    .await;

    // The first hub dies; every member fails over to the second.
    let _ = first.close().await;
    network.unlisten(first_address);
    for fleet in [&a, &b, &c] {
        linked(&second, fleet.peer().peer_id()).await;
    }
    for fleet in [&a, &b, &c] {
        let peer = fleet.peer().clone();
        eventually("the member's new seed", || {
            let peer = peer.clone();
            let second = second.peer_id().to_owned();
            async move { peer.seed_peer().await.as_deref() == Some(second.as_str()) }
        })
        .await;
    }
    b.space(SPACE)
        .write(&job("after"), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write after the failover");
    wait_job(&c, "after").await;
    wait_job(&c, "before0").await;
    let (left, right) = tokio::join!(take_all(&b, "b"), take_all(&c, "c"));
    let mut took: Vec<String> = left.into_iter().chain(right).collect();
    took.sort();
    assert_eq!(
        took,
        ["after", "before0", "before1", "before2", "before3"],
        "every job, written before or after the failover, taken once"
    );
    let space = a.space(SPACE);
    eventually("every result at the writer", || {
        let space = space.clone();
        async move {
            space
                .read_all_typed::<Done>(&Template::of::<Done>(), 100)
                .await
                .is_ok_and(|done| done.len() == 5)
        }
    })
    .await;
    assert!(second.counters().await.listen.admitted >= 3);
    for fleet in [&a, &b, &c] {
        fleet.close().await.expect("close");
    }
    let _ = second.close().await;
}
