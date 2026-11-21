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
//! The piece exchange of the content swarm between Rust members: a listening hub and dial-only
//! members, so pieces move from one dial-only member to another through the hub's relay.

mod support;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use agentspaces::clock::SystemClock;
use agentspaces::content::{Content, ContentConfig, ContentError, FetchOptions, FilePieces, MemoryPieces, PieceStore, PublishOptions};
use agentspaces::group::GroupSpec;
use agentspaces::peer::{ListenerSpec, Peer, PeerConfig};
use agentspaces::transport::memory::MemoryNetwork;
use agentspaces::wire::identity::Identity;
use agentspaces::wire::pdt::store::MemoryNodes;
use support::eventually;

const FOUNDING: &str = "agentspaces-rust-content-artifacts";

fn bytes(n: usize, seed: u32) -> Vec<u8> {
    (0..n as u32).map(|i| (i.wrapping_add(seed).wrapping_mul(2_654_435_761) >> 13) as u8).collect()
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("content-artifacts-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct Net {
    network: MemoryNetwork,
    hub: Peer,
}

impl Net {
    async fn start(address: &str) -> Net {
        let network = MemoryNetwork::new();
        let mut config = PeerConfig::new(Identity::generate().expect("id"), GroupSpec::FoundingText(FOUNDING.to_owned()));
        config.clock = Arc::new(SystemClock);
        config = config.listen_on(ListenerSpec::bound(Arc::new(network.listen(address))));
        config.listen.anti_entropy_period = Some(Duration::from_millis(200));
        Net { network, hub: Peer::start(config).await.expect("hub") }
    }

    async fn member(&self, address: &str, pieces: Arc<dyn PieceStore>) -> Content {
        let mut config = PeerConfig::new(Identity::generate().expect("id"), GroupSpec::FoundingText(FOUNDING.to_owned()));
        config.seeds = vec![address.parse().expect("seed")];
        config.dialers = vec![Arc::new(self.network.dialer())];
        config.clock = Arc::new(SystemClock);
        config.reconnect_interval = Duration::from_millis(50);
        let peer = Peer::start(config).await.expect("member");
        let (id, hub) = (peer.peer_id().to_owned(), self.hub.clone());
        eventually("the hub links the member", || {
            let (hub, id) = (hub.clone(), id.clone());
            async move { hub.linked_members().await.contains(&id) }
        })
        .await;
        let config = ContentConfig { request_timeout: Duration::from_secs(2), tick: Duration::from_millis(50), ..ContentConfig::default() };
        Content::start_with(peer, Arc::new(MemoryNodes::new()), pieces, config).await.expect("content")
    }
}

fn read(c: &Content, root: &str) -> Vec<u8> {
    let mut out = Vec::new();
    c.read_artifact(root, &mut out).expect("the artifact reads");
    out
}

fn small_pieces() -> PublishOptions {
    PublishOptions { piece_size: 64 * 1024, ..PublishOptions::default() }
}

#[tokio::test(flavor = "multi_thread")]
async fn artifacts_move_between_members_and_survive_a_restart() {
    let address = "127.0.0.1:7861";
    let net = Net::start(address).await;
    let alice = net.member(address, Arc::new(MemoryPieces::new())).await;
    let bob = net.member(address, Arc::new(MemoryPieces::new())).await;
    let dir = scratch("files");

    // an artifact whose table rides inline (46 pieces), and one whose table is a block (80 pieces)
    let small = bytes(3_000_000, 1);
    let large = bytes(80 * 64 * 1024 - 7, 2);
    std::fs::write(dir.join("small.bin"), &small).unwrap();
    std::fs::write(dir.join("large.bin"), &large).unwrap();
    let ms = alice.publish_file(&dir.join("small.bin"), small_pieces()).await.expect("small");
    let ml = alice.publish_file(&dir.join("large.bin"), small_pieces()).await.expect("large");
    assert!(ms.table.is_some() && ml.table.is_none() && ml.table_ref.is_some());
    let opts = || FetchOptions { timeout: Some(Duration::from_secs(60)), ..FetchOptions::default() };
    bob.fetch_artifact(&ms.root, opts()).await.expect("bob small");
    bob.fetch_artifact(&ml.root, opts()).await.expect("bob large");
    assert_eq!(read(&bob, &ms.root), small);
    assert_eq!(read(&bob, &ml.root), large);

    // carol, with a durable piece store, fetches from both holders
    let store_dir = scratch("carol-store");
    let carol = net.member(address, Arc::new(FilePieces::open(&store_dir, 1 << 30).unwrap())).await;
    let report = carol.fetch_artifact(&ml.root, opts()).await.expect("carol large");
    assert_eq!(read(&carol, &ml.root), large);
    assert!(report.requests >= 80, "{report:?}");
    let served = alice.counters().await.unwrap().pieces_served + bob.counters().await.unwrap().pieces_served;
    assert!(served >= 80 + 46 + 80);

    // a file published in place stops serving once it changes
    let place = dir.join("in-place.bin");
    std::fs::write(&place, bytes(500_000, 3)).unwrap();
    let mp = alice
        .publish_file(&place, PublishOptions { in_place: true, ..small_pieces() })
        .await
        .expect("in place");
    bob.fetch_artifact(&mp.root, opts()).await.expect("bob in place");
    std::fs::write(&place, b"changed").unwrap();
    let dave = net.member(address, Arc::new(MemoryPieces::new())).await;
    bob.close().await.unwrap();
    let late = dave.fetch_artifact(&mp.root, FetchOptions { timeout: Some(Duration::from_secs(3)), ..FetchOptions::default() }).await;
    assert!(matches!(late, Err(ContentError::TimedOut { .. })), "{late:?}");

    // carol restarts over her store; with alice and bob gone she alone serves the large artifact
    carol.close().await.unwrap();
    alice.close().await.unwrap();
    let carol = net.member(address, Arc::new(FilePieces::open(&store_dir, 1 << 30).unwrap())).await;
    assert!(carol.artifacts().iter().any(|a| a.manifest.root == ml.root && a.held == 80));
    dave.fetch_artifact(&ml.root, opts()).await.expect("dave from carol after her restart");
    assert_eq!(read(&dave, &ml.root), large);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}
