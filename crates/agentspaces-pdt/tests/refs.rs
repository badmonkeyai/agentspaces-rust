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

//! Refs between Rust members: a swap one member writes reads at another, concurrent swaps of
//! different keys merge with neither lost, a key both change takes the later head, and a removal
//! survives the merge.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use agentspaces::clock::SystemClock;
use agentspaces::content::{Content, ContentConfig};
use agentspaces::group::GroupSpec;
use agentspaces::peer::{ListenerSpec, Peer, PeerConfig};
use agentspaces::transport::memory::MemoryNetwork;
use agentspaces::wire::cbor::{self, Value};
use agentspaces::wire::identity::Identity;
use agentspaces::wire::pdt::store::MemoryNodes;
use agentspaces_pdt::{Pdt, PdtConfig, Ref};

const FOUNDING: &str = "agentspaces-rust-pdt-refs";

async fn eventually<F, Fut>(what: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while tokio::time::Instant::now() < deadline {
        if check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {what}");
}

fn text(t: &str) -> Vec<u8> {
    cbor::encode(&Value::from(t))
}

struct Net {
    network: MemoryNetwork,
    hub: Peer,
    address: String,
}

impl Net {
    async fn start(address: &str) -> Net {
        let network = MemoryNetwork::new();
        let mut config = PeerConfig::new(Identity::generate().expect("id"), GroupSpec::FoundingText(FOUNDING.to_owned()));
        config.clock = Arc::new(SystemClock);
        config = config.listen_on(ListenerSpec::bound(Arc::new(network.listen(address))));
        config.listen.anti_entropy_period = Some(Duration::from_millis(200));
        let hub = Peer::start(config).await.expect("hub");
        Net { network, hub, address: address.to_string() }
    }

    async fn member(&self) -> Pdt {
        let mut config = PeerConfig::new(Identity::generate().expect("id"), GroupSpec::FoundingText(FOUNDING.to_owned()));
        config.seeds = vec![self.address.parse().expect("seed")];
        config.dialers = vec![Arc::new(self.network.dialer())];
        config.clock = Arc::new(SystemClock);
        config.reconnect_interval = Duration::from_millis(50);
        let peer = Peer::start(config).await.expect("member");
        let id = peer.peer_id().to_owned();
        let hub = self.hub.clone();
        eventually("the hub links the member", || {
            let (hub, id) = (hub.clone(), id.clone());
            async move { hub.linked_members().await.contains(&id) }
        })
        .await;
        let content = Content::start(
            peer,
            Arc::new(MemoryNodes::new()),
            ContentConfig { tick: Duration::from_millis(50), request_timeout: Duration::from_secs(2), ..ContentConfig::default() },
        )
        .await
        .expect("content");
        let pdt = Pdt::new(content, PdtConfig { load_timeout: Duration::from_secs(5), ..PdtConfig::default() });
        pdt.spawn_ticker(Duration::from_millis(200));
        pdt
    }
}

async fn value_of(r: &Ref, pdt: &Pdt, key: &str) -> Option<Vec<u8>> {
    let map = r.deref_map().await.ok()?;
    map.get(&**pdt.nodes(), &text(key)).ok().flatten()
}

async fn sees(r: &Ref, pdt: &Pdt, key: &str, want: Option<&str>) {
    let want = want.map(text);
    eventually(&format!("{key} reads {want:?}"), || {
        let (r, pdt, want) = (r.clone(), pdt.clone(), want.clone());
        async move { value_of(&r, &pdt, key).await == want }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn swaps_read_across_members_and_concurrent_swaps_merge() {
    let net = Net::start("127.0.0.1:7851").await;
    let alice = net.member().await;
    let bob = net.member().await;
    let (a, b) = (alice.map_ref("facts").expect("ref"), bob.map_ref("facts").expect("ref"));

    // one writer, one reader
    let first = a.swap_map(|nodes, m| m.assoc(nodes, &text("k1"), &text("one"))).await.expect("swap");
    assert!(first.entry.is_some() && first.inline_bytes > 0, "{first:?}");
    sees(&b, &bob, "k1", Some("one")).await;
    let unchanged = a.swap_map(|nodes, m| m.assoc(nodes, &text("k1"), &text("one"))).await.expect("swap");
    assert!(unchanged.entry.is_none(), "an unchanged value writes no head");

    // bob builds on alice's head
    b.swap_map(|nodes, m| m.assoc(nodes, &text("k2"), &text("two"))).await.expect("swap");
    sees(&a, &alice, "k2", Some("two")).await;
    sees(&a, &alice, "k1", Some("one")).await;

    // concurrent swaps of different keys: both survive at both members
    let (ra, rb) = tokio::join!(
        a.swap_map(|nodes, m| m.assoc(nodes, &text("ka"), &text("from alice"))),
        b.swap_map(|nodes, m| m.assoc(nodes, &text("kb"), &text("from bob"))),
    );
    ra.expect("alice");
    rb.expect("bob");
    for (r, pdt) in [(&a, &alice), (&b, &bob)] {
        sees(r, pdt, "ka", Some("from alice")).await;
        sees(r, pdt, "kb", Some("from bob")).await;
        sees(r, pdt, "k1", Some("one")).await;
        sees(r, pdt, "k2", Some("two")).await;
    }

    // a removal on one side and an addition on the other: the removal holds after the merge
    let (ra, rb) = tokio::join!(
        a.swap_map(|nodes, m| m.dissoc(nodes, &text("k1"))),
        b.swap_map(|nodes, m| m.assoc(nodes, &text("k3"), &text("three"))),
    );
    ra.expect("alice");
    rb.expect("bob");
    for (r, pdt) in [(&a, &alice), (&b, &bob)] {
        sees(r, pdt, "k1", None).await;
        sees(r, pdt, "k3", Some("three")).await;
    }

    // a key both change at once: every member settles on the same value
    let (ra, rb) = tokio::join!(
        a.swap_map(|nodes, m| m.assoc(nodes, &text("both"), &text("alice"))),
        b.swap_map(|nodes, m| m.assoc(nodes, &text("both"), &text("bob"))),
    );
    ra.expect("alice");
    rb.expect("bob");
    eventually("both members agree on the contested key", || {
        let (a, b, alice, bob) = (a.clone(), b.clone(), alice.clone(), bob.clone());
        async move {
            let (x, y) = (value_of(&a, &alice, "both").await, value_of(&b, &bob, "both").await);
            x.is_some() && x == y
        }
    })
    .await;
    // Both members agreeing on the value does not mean both hold both heads: a member that holds only its own
    // head reads its own value, and the other, holding both, may read the same one as the later head. The merge
    // below would then name one head as its base and leave the other live, two heads for good (seen once as a
    // timeout of this test). Wait until both hold the same heads.
    eventually("both members hold the same heads", || {
        let (a, b) = (a.clone(), b.clone());
        async move {
            let roots = |heads: Vec<agentspaces_pdt::Head>| {
                let mut roots: Vec<String> = heads.into_iter().map(|h| h.root).collect();
                roots.sort();
                roots
            };
            match (a.heads().await, b.heads().await) {
                (Ok(x), Ok(y)) => !x.is_empty() && roots(x) == roots(y),
                _ => false,
            }
        }
    })
    .await;
    // the merged values converge on one root once a member writes the merge
    a.swap_map(|nodes, m| m.assoc(nodes, &text("settled"), &text("yes"))).await.expect("settle");
    eventually("one root everywhere", || {
        let (a, b) = (a.clone(), b.clone());
        async move {
            match (a.heads().await, b.heads().await) {
                (Ok(x), Ok(y)) => x.len() == 1 && y.len() == 1 && x[0].root == y[0].root,
                _ => false,
            }
        }
    })
    .await;
    assert_eq!(a.stats().await.heads_ignored, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_large_delta_moves_by_the_tree_exchange() {
    let net = Net::start("127.0.0.1:7852").await;
    let alice = net.member().await;
    let bob = net.member().await;
    let (a, b) = (alice.map_ref("big").expect("ref"), bob.map_ref("big").expect("ref"));
    let swapped = a
        .swap_map(|nodes, mut m| {
            for i in 0..2000 {
                m = m.assoc(nodes, &text(&format!("key-{i}")), &text(&format!("value number {i}")))?;
            }
            Ok(m)
        })
        .await
        .expect("swap");
    assert_eq!(swapped.inline_bytes, 0, "a delta past 32 KiB travels by the tree exchange");
    sees(&b, &bob, "key-1999", Some("value number 1999")).await;
    let map = b.deref_map().await.expect("deref");
    assert_eq!(map.count(), 2000);
}
