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

//! The trie audit of SPEC annex I.6 between Rust peers over the in-memory transport: a listening
//! peer that never pulled a space receives a partner's entries through its rounds alone (the
//! hashed opening, the descent, and the fetch by ids), under a small budget too, where fetch
//! answers are cut and continued; a member without `wire.ae=2` still reconciles by today's
//! digests and never receives an audit field; and a dial-only member's whole-space pull carries
//! a budget toward an auditing seed and continues while a remainder comes back.

use std::sync::Arc;
use std::time::Duration;

use agentspaces::clock::SystemClock;
use agentspaces::group::GroupSpec;
use agentspaces::peer::{ListenerSpec, Peer, PeerConfig};
use agentspaces::transport::memory::MemoryNetwork;
use agentspaces::wire::cbor::{Map, Value};
use agentspaces::wire::identity::Identity;
use tokio::time::Instant;

const FOUNDING: &str = "agentspaces-rust-audit";
const SPACE: &str = "tasks";
const TYPE: &str = "com.acme.Task#v1";
const LEASE_MS: i64 = 600_000;
const PATIENCE: Duration = Duration::from_secs(30);

async fn within<F, Fut>(what: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + PATIENCE;
    while !check().await {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn config(network: &MemoryNetwork, listen: Option<&str>, seed: Option<&str>) -> PeerConfig {
    let identity = Identity::generate().expect("identity");
    let mut config = PeerConfig::new(identity, GroupSpec::FoundingText(FOUNDING.to_owned()));
    config.clock = Arc::new(SystemClock);
    if let Some(address) = listen {
        config = config.listen_on(ListenerSpec::bound(Arc::new(network.listen(address))));
        config.listen.anti_entropy_period = Some(Duration::from_millis(200));
    }
    if let Some(seed) = seed {
        config.seeds = vec![seed.parse().expect("seed")];
        config.dialers = vec![Arc::new(network.dialer())];
        config.reconnect_interval = Duration::from_millis(50);
        config.dial_timeout = Duration::from_secs(2);
    }
    config
}

async fn write(peer: &Peer, n: usize, pad: usize) -> String {
    let mut payload = Map::new();
    payload.insert("topic", format!("task-{n}-{}", "x".repeat(pad)));
    payload.insert("priority", 1);
    peer.write_entry(SPACE, TYPE, Value::Map(payload), LEASE_MS, Map::new(), None)
        .await
        .expect("write")
}

async fn held(peer: &Peer) -> usize {
    peer.space_states(SPACE).await.len()
}

/// A partner holding `count` entries, and a listening peer with its own one entry that dials it
/// and never pulls the space: what the second holds of the first's comes by the audit.
async fn audit_pair(count: usize, pad: usize, budget: usize, address: &str) -> (Peer, Peer) {
    let network = MemoryNetwork::new();
    let a = Peer::start(config(&network, Some(address), None))
        .await
        .expect("a starts");
    for n in 0..count {
        write(&a, n, pad).await;
    }
    let mut b_config = config(&network, Some("127.0.0.1:7902"), Some(address));
    b_config.audit_budget = budget;
    let b = Peer::start(b_config).await.expect("b starts");
    write(&b, count + 1, 0).await; // opens the space on b without pulling it
    (a, b)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_listening_peer_reconciles_a_space_it_never_pulled_by_the_audit() {
    let (a, b) = audit_pair(300, 0, 1 << 20, "127.0.0.1:7901").await;
    within("b holds a's 300 entries and its own", || async {
        held(&b).await == 301
    })
    .await;
    within("a holds b's entry", || async { held(&a).await == 301 }).await;
    let asker = b.counters().await.audit;
    let partner = a.counters().await.audit;
    assert!(asker.openings_sent >= 1, "{asker:?}");
    assert!(asker.roots_received >= 1, "{asker:?}");
    assert!(asker.requests_sent >= 1, "the root was inner: {asker:?}");
    assert!(asker.ids_requested >= 300, "{asker:?}");
    assert!(partner.roots_answered >= 1, "{partner:?}");
    assert!(partner.sessions_opened >= 1, "{partner:?}");
    assert!(partner.requests_answered >= 1, "{partner:?}");
    assert!(partner.fetches_answered >= 1, "{partner:?}");
    assert!(partner.budgeted_answers >= 1, "{partner:?}");
    for counters in [&asker, &partner] {
        for bad in [
            "undecodable",
            "lacks-hint",
            "fingerprint-mismatch",
            "shape-mismatch",
        ] {
            assert!(!counters.refusals.contains_key(bad), "{bad}: {counters:?}");
        }
    }
    // Converged: the next openings find the hashes equal and fetch nothing more.
    let before = b.counters().await.audit.ids_requested;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(b.counters().await.audit.ids_requested, before);
    a.close().await.expect("close");
    b.close().await.expect("close");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_small_budget_cuts_fetch_answers_and_they_continue() {
    // 120 entries of about 1 KiB each against a 4 KiB budget: every fetch answer is cut.
    let (a, b) = audit_pair(120, 1024, 4096, "127.0.0.1:7901").await;
    within("b holds a's 120 entries and its own", || async {
        held(&b).await == 121
    })
    .await;
    let asker = b.counters().await.audit;
    assert!(asker.remainder_received > 0, "{asker:?}");
    assert!(asker.fetch_continued > 0, "{asker:?}");
    assert_eq!(asker.fetch_queued, 0, "{asker:?}");
    a.close().await.expect("close");
    b.close().await.expect("close");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_without_the_hint_reconciles_by_todays_digests() {
    let network = MemoryNetwork::new();
    let a = Peer::start(config(&network, Some("127.0.0.1:7901"), None))
        .await
        .expect("a starts");
    for n in 0..60 {
        write(&a, n, 0).await;
    }
    let mut b_config = config(&network, Some("127.0.0.1:7902"), Some("127.0.0.1:7901"));
    b_config.audit = false;
    let b = Peer::start(b_config).await.expect("b starts");
    write(&b, 999, 0).await;
    within("b holds a's 60 entries and its own", || async {
        held(&b).await == 61
    })
    .await;
    within("a holds b's entry", || async { held(&a).await == 61 }).await;
    tokio::time::sleep(Duration::from_millis(800)).await;
    let old = b.counters().await.audit;
    let new = a.counters().await.audit;
    assert_eq!(old.openings_sent, 0, "{old:?}");
    assert!(old.refusals.is_empty(), "no audit field reached b: {old:?}");
    assert_eq!(new.openings_sent, 0, "a never audits toward b: {new:?}");
    assert_eq!(new.roots_answered, 0, "{new:?}");
    a.close().await.expect("close");
    b.close().await.expect("close");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dial_only_pull_is_budgeted_toward_an_auditing_seed() {
    let network = MemoryNetwork::new();
    let a = Peer::start(config(&network, Some("127.0.0.1:7901"), None))
        .await
        .expect("a starts");
    for n in 0..80 {
        write(&a, n, 512).await;
    }
    let mut c_config = config(&network, None, Some("127.0.0.1:7901"));
    c_config.audit_budget = 4096;
    let c = Peer::start(c_config).await.expect("c starts");
    // Once c has read the seed's card it pulls under a budget.
    within("c learns the seed's card", || async {
        c.members().await.iter().any(|member| member == a.peer_id())
    })
    .await;
    c.pull_space(SPACE).await.expect("pull");
    within("c holds the 80 entries", || async { held(&c).await == 80 }).await;
    let counters = c.counters().await.audit;
    assert!(counters.remainder_received > 0, "{counters:?}");
    assert!(counters.pulls_continued > 0, "{counters:?}");
    assert!(a.counters().await.audit.budgeted_answers > 0);
    a.close().await.expect("close");
    c.close().await.expect("close");
}
