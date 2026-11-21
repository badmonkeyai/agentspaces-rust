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

//! The tree exchange of the content swarm between Rust members: a listening hub and dial-only
//! members, so a tree moves from one dial-only member to another through the hub's relay.

mod support;

use std::sync::Arc;
use std::time::Duration;

use agentspaces::clock::SystemClock;
use agentspaces::content::{Content, ContentConfig, ContentError, FetchOptions};
use agentspaces::group::GroupSpec;
use agentspaces::peer::{ListenerSpec, Peer, PeerConfig};
use agentspaces::transport::memory::MemoryNetwork;
use agentspaces::wire::cbor::Value;
use agentspaces::wire::pdt::champ::PMap;
use agentspaces::wire::pdt::file_entry::{FileEntry, REGULAR};
use agentspaces::wire::pdt::store::{Flusher, MemoryNodes, Nodes};
use agentspaces::wire::pdt::{blob, cid};
use agentspaces::wire::identity::Identity;
use support::eventually;

const FOUNDING: &str = "agentspaces-rust-content-trees";

fn bytes(n: usize, seed: u32) -> Vec<u8> {
    (0..n as u32).map(|i| (i.wrapping_add(seed).wrapping_mul(2_654_435_761) >> 13) as u8).collect()
}

fn content_config() -> ContentConfig {
    ContentConfig {
        request_timeout: Duration::from_secs(2),
        tick: Duration::from_millis(50),
        ..ContentConfig::default()
    }
}

struct Net {
    network: MemoryNetwork,
    hub: Peer,
}

impl Net {
    async fn start() -> Net {
        let network = MemoryNetwork::new();
        let mut config = PeerConfig::new(Identity::generate().expect("id"), GroupSpec::FoundingText(FOUNDING.to_owned()));
        config.clock = Arc::new(SystemClock);
        config = config.listen_on(ListenerSpec::bound(Arc::new(network.listen("127.0.0.1:7841"))));
        config.listen.anti_entropy_period = Some(Duration::from_millis(200));
        let hub = Peer::start(config).await.expect("hub");
        Net { network, hub }
    }

    async fn member(&self) -> (Content, Arc<MemoryNodes>) {
        let mut config = PeerConfig::new(Identity::generate().expect("id"), GroupSpec::FoundingText(FOUNDING.to_owned()));
        config.seeds = vec!["127.0.0.1:7841".parse().expect("seed")];
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
        let nodes = Arc::new(MemoryNodes::new());
        let content = Content::start(peer, nodes.clone(), content_config()).await.expect("content");
        (content, nodes)
    }
}

async fn sees(content: &Content, other: &Content) {
    let other = other.peer().peer_id().to_owned();
    eventually("the member advertises trees", || {
        let (content, other) = (content.clone(), other.clone());
        async move { content.tree_members().await.unwrap_or_default().contains(&other) }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tree_moves_between_dial_only_members_through_the_relay() {
    let net = Net::start().await;
    let (alice, alice_nodes) = net.member().await;
    let (bob, bob_nodes) = net.member().await;
    sees(&bob, &alice).await;
    sees(&alice, &bob).await;

    // alice writes a 3 MiB blob and a file-share map naming it
    let data = bytes(3 * 1024 * 1024, 7);
    let written = blob::write_bytes(&data, &mut Flusher::new(&*alice_nodes)).expect("blob");
    let entry = FileEntry::new(&written.root, data.len() as u64, REGULAR, "application/octet-stream").expect("entry");
    let map = PMap::empty()
        .assoc(&*alice_nodes, &agentspaces::wire::cbor::encode(&Value::from("files/data.bin")), &entry.encode())
        .expect("assoc");
    let (map_root, _) = map.commit(&*alice_nodes).expect("commit");
    alice.hold_tree(&written.root).await.expect("hold blob");
    alice.hold_tree(&map_root).await.expect("hold map");
    let unknown = cid::of(b"nobody holds this", cid::RAW);
    assert!(matches!(alice.hold_tree(&unknown).await, Err(ContentError::Incomplete(_))));

    // bob finds alice as a holder through the content space, and fetches both trees
    let root = written.root.clone();
    let alice_id = alice.peer().peer_id().to_owned();
    eventually("bob reads alice's holding", || {
        let (bob, root, alice_id) = (bob.clone(), root.clone(), alice_id.clone());
        async move { bob.holders(&root).await.unwrap_or_default().contains(&alice_id) }
    })
    .await;
    let report = bob.fetch_tree(&map_root, FetchOptions { timeout: Some(Duration::from_secs(30)), ..Default::default() }).await.expect("map");
    assert!(report.nodes >= 1);
    let fetched = PMap::load(&*bob_nodes, &map_root).expect("load map");
    let item = fetched.get(&*bob_nodes, &agentspaces::wire::cbor::encode(&Value::from("files/data.bin"))).expect("get").expect("present");
    assert_eq!(FileEntry::decode(&item).expect("entry"), entry);
    let report = bob.fetch_tree(&written.root, FetchOptions { timeout: Some(Duration::from_secs(30)), ..Default::default() }).await.expect("blob");
    assert_eq!(blob::read_all(&*bob_nodes, &written.root).expect("read"), data);
    assert!(report.bytes as usize >= data.len());

    // an edit near the end ships only the changed chunks and path when bob names his copy
    let mut edited = data.clone();
    let at = edited.len() - 1000;
    edited[at] ^= 0xFF;
    let edited_root = blob::write_bytes(&edited, &mut Flusher::new(&*alice_nodes)).expect("edit").root;
    alice.hold_tree(&edited_root).await.expect("hold edit");
    let report = bob
        .fetch_tree(&edited_root, FetchOptions { haves: vec![written.root.clone()], prefer: vec![alice_id.clone()], timeout: Some(Duration::from_secs(30)) })
        .await
        .expect("edit fetch");
    assert_eq!(blob::read_all(&*bob_nodes, &edited_root).expect("read"), edited);
    assert!(report.bytes < 600 * 1024, "the edit shipped {} bytes", report.bytes);

    // nobody holds it: the bounded fetch gives up and says why
    let missing = bob.fetch_tree(&unknown, FetchOptions { timeout: Some(Duration::from_millis(500)), ..Default::default() }).await;
    assert!(matches!(missing, Err(ContentError::TimedOut { .. })), "{missing:?}");

    let served = alice.counters().await.expect("counters");
    assert!(served.tree_wants_served >= 2 && served.nodes_served > 0, "{served:?}");
    assert!(served.holdings_written >= 3);
    alice.close().await.expect("close");
    bob.close().await.expect("close");
    let _ = net.hub.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_release_withdraws_the_holding() {
    let net = Net::start().await;
    let (alice, alice_nodes) = net.member().await;
    let (bob, _) = net.member().await;
    let root = blob::write_bytes(&bytes(100_000, 3), &mut Flusher::new(&*alice_nodes)).expect("blob").root;
    alice.hold_tree(&root).await.expect("hold");
    let id = alice.peer().peer_id().to_owned();
    eventually("bob sees the holding", || {
        let (bob, root, id) = (bob.clone(), root.clone(), id.clone());
        async move { bob.holders(&root).await.unwrap_or_default().contains(&id) }
    })
    .await;
    alice.release_tree(&root).await.expect("release");
    eventually("the holding is withdrawn", || {
        let (bob, root, id) = (bob.clone(), root.clone(), id.clone());
        async move { !bob.holders(&root).await.unwrap_or_default().contains(&id) }
    })
    .await;
    assert!(alice_nodes.has(&root), "the nodes stay in the store");
}

