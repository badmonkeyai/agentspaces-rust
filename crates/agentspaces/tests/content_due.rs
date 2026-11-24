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

//! The content swarm's due work (SPEC v0.1.36 §9.5) on paused time: an idle member runs it only
//! when a renewal or its advertisement falls due, where it ran every 250 ms before.

use std::sync::Arc;
use std::time::Duration;

use agentspaces::clock::SystemClock;
use agentspaces::content::{Content, ContentConfig};
use agentspaces::group::GroupSpec;
use agentspaces::peer::{ListenerSpec, Peer, PeerConfig};
use agentspaces::transport::memory::MemoryNetwork;
use agentspaces::wire::identity::Identity;
use agentspaces::wire::pdt::store::MemoryNodes;

#[tokio::test(start_paused = true)]
async fn an_idle_member_runs_its_due_work_at_its_renewals_only() {
    let network = MemoryNetwork::new();
    let mut config = PeerConfig::new(
        Identity::generate().expect("id"),
        GroupSpec::FoundingText("agentspaces-rust-content-due".to_owned()),
    );
    config.clock = Arc::new(SystemClock);
    config = config.listen_on(ListenerSpec::bound(Arc::new(
        network.listen("127.0.0.1:7851"),
    )));
    let peer = Peer::start(config).await.expect("peer");
    let content = Content::start(
        peer.clone(),
        Arc::new(MemoryNodes::new()),
        ContentConfig {
            holding_lease: Duration::from_secs(5 * 60),
            advertise_every: Duration::from_secs(5 * 60),
            tick: Duration::from_millis(250),
            ..ContentConfig::default()
        },
    )
    .await
    .expect("content");
    // Two minutes idle: nothing falls due (the advertisement is due at five).
    tokio::time::sleep(Duration::from_secs(120)).await;
    let counters = content.counters().await.expect("counters");
    assert_eq!(counters.due_runs, 0, "no fixed tick: 480 runs before");
    // At five minutes the advertisement falls due, once.
    tokio::time::sleep(Duration::from_secs(181)).await;
    let counters = content.counters().await.expect("counters");
    assert_eq!(counters.due_runs, 1);
    let _ = peer.close().await;
}
