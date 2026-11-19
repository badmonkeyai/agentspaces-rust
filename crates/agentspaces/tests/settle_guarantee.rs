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

//! The settle guarantee of SPEC §7.4 (v0.1.35) between Rust peers over the in-memory transport.
//! One take wins an entry only while every claim reaches every rival claimant within the settle
//! window. Here the frames a dial-only peer sends are held past the window ([`HoldingDialer`]),
//! so two takers each judge themselves the winner. The held peer claims first, so its claim has
//! the earlier stamp and wins the lattice; the hub never heard of it and takes the entry too.
//! Beyond the window:
//!
//! - a holder that learns of a better claim before it completes does not complete (rule one);
//! - the lattice winner that learns of the displaced holder's completion before it completes
//!   acknowledges that completion and writes no result, whether it learns during its settle
//!   window (its take comes back empty) or after it won (its `complete` fails) (rule two);
//! - when both complete before either hears of the other, the shared state keeps one completion
//!   and the duplicate is counted once, where the winning claim is held (rule three).

mod support;

use std::sync::Arc;
use std::time::Duration;

use agentspaces::clock::{SharedClock, SystemClock};
use agentspaces::group::GroupSpec;
use agentspaces::peer::{ListenerSpec, Peer, PeerConfig};
use agentspaces::space::{Fleet, Lease, Space, SpaceError, Taken, Template};
use agentspaces::transport::memory::MemoryNetwork;
use agentspaces::wire::cbor::{Map, Value};
use agentspaces::wire::identity::Identity;
use support::{HoldingDialer, PATIENCE, eventually};

const FOUNDING: &str = "agentspaces-rust-settle-guarantee";
const SPACE: &str = "tasks";
const TASK: &str = "com.acme.Task#v1";
const FINDING: &str = "com.acme.Finding#v1";

/// The late claimant's window when the rival's completion must reach it within it: long, so the
/// rival's take and completion (a few hundred milliseconds) always fit.
const LONG_SETTLE: Duration = Duration::from_secs(3);
/// Every other window.
const SHORT_SETTLE: Duration = Duration::from_millis(200);

fn system() -> SharedClock {
    Arc::new(SystemClock)
}

fn task(topic: &str) -> Value {
    let mut payload = Map::new();
    payload.insert("topic", topic);
    payload.insert("priority", 1);
    Value::Map(payload)
}

fn finding(text: &str) -> Value {
    let mut payload = Map::new();
    payload.insert("summary", text);
    Value::Map(payload)
}

fn take_lease() -> Lease {
    Lease::from_millis(60_000).expect("lease")
}

/// The hub (listening) and the late peer (dial-only, its frames through `holding`).
struct Pair {
    hub: Peer,
    late: Peer,
    holding: HoldingDialer,
}

impl Pair {
    async fn start(network: &MemoryNetwork, address: &str) -> Pair {
        let mut config = PeerConfig::new(
            Identity::generate().expect("identity"),
            GroupSpec::FoundingText(FOUNDING.to_owned()),
        )
        .listen_on(ListenerSpec::bound(Arc::new(network.listen(address))));
        config.clock = system();
        config.peer_ad_interval = Duration::from_millis(100);
        config.listen.anti_entropy_period = Some(Duration::from_millis(100));
        let hub = Peer::start(config).await.expect("the hub starts");

        let holding = HoldingDialer::new(Arc::new(network.dialer()));
        let mut config = PeerConfig::new(
            Identity::generate().expect("identity"),
            GroupSpec::FoundingText(FOUNDING.to_owned()),
        );
        config.clock = system();
        config.seeds = vec![address.parse().expect("seed")];
        config.dialers = vec![Arc::new(holding.clone())];
        config.reconnect_interval = Duration::from_millis(50);
        config.dial_timeout = Duration::from_secs(2);
        config.peer_ad_interval = Duration::from_millis(100);
        config.listen.anti_entropy_period = Some(Duration::from_millis(100));
        let late = Peer::start(config).await.expect("the late peer starts");
        Pair { hub, late, holding }
    }

    fn space(peer: &Peer, settle: Duration) -> Space {
        Fleet::from_peer(peer.clone())
            .space(SPACE)
            .with_settle(settle)
    }

    /// The hub writes the contested task, and the late peer holds it.
    async fn contested(&self) {
        let hub = Pair::space(&self.hub, SHORT_SETTLE);
        hub.write_value(TASK, task("contested"), Lease::DEFAULT_WRITE, Map::new())
            .await
            .expect("write");
        let late = Pair::space(&self.late, SHORT_SETTLE);
        late.pull().await.expect("pull");
        let read = late
            .read(&Template::new(TASK), PATIENCE)
            .await
            .expect("read");
        assert!(read.is_some(), "the late peer holds the task");
    }

    /// The hub's take, judged alone: it never heard of the late peer's claim.
    async fn hub_takes(&self) -> Taken {
        Pair::space(&self.hub, SHORT_SETTLE)
            .take(&Template::new(TASK), take_lease(), Duration::ZERO)
            .await
            .expect("take")
            .expect("the hub never heard of the late claim, so it judged itself the winner")
    }

    /// Every replica holds the entry completed, and exactly `results` findings.
    async fn converges(&self, results: &[&str]) {
        for peer in [&self.hub, &self.late] {
            let space = Pair::space(peer, SHORT_SETTLE);
            eventually("the task completed everywhere, with its results", || {
                let space = space.clone();
                let peer = peer.clone();
                let mut want: Vec<String> = results.iter().map(|r| (*r).to_owned()).collect();
                want.sort();
                async move {
                    let _ = space.pull().await;
                    let completed = peer
                        .space_states(SPACE)
                        .await
                        .iter()
                        .filter(|state| {
                            state.get("completed").and_then(Value::as_bool) == Some(true)
                        })
                        .count();
                    let mut found: Vec<String> = space
                        .read_all(&Template::new(FINDING), 10)
                        .await
                        .unwrap_or_default()
                        .iter()
                        .filter_map(|view| {
                            view.payload()
                                .get("summary")
                                .and_then(Value::as_str)
                                .map(str::to_owned)
                        })
                        .collect();
                    found.sort();
                    let open = space
                        .read(&Template::new(TASK), Duration::ZERO)
                        .await
                        .ok()
                        .flatten();
                    completed == 1 && found == want && open.is_none()
                }
            })
            .await;
        }
    }

    async fn close(self) {
        let _ = self.late.close().await;
        let _ = self.hub.close().await;
    }
}

/// Waits until the late peer holds its own claim on the task.
async fn claimed(peer: &Peer) {
    eventually("the late peer's claim", || async {
        !peer.space_claims(SPACE).await.is_empty()
    })
    .await;
}

/// The hub's completion reached the late peer during the late peer's settle window: its claim
/// won the lattice, but the work is done, so its take stands down, acknowledging that completion
/// with no result.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rivals_completion_arriving_in_the_winners_window_makes_its_take_stand_down() {
    let network = MemoryNetwork::new();
    let pair = Pair::start(&network, "127.0.0.1:7971").await;
    pair.contested().await;
    pair.holding.hold();

    let late_space = Pair::space(&pair.late, LONG_SETTLE);
    let late_take = tokio::spawn(async move {
        late_space
            .take(&Template::new(TASK), take_lease(), Duration::ZERO)
            .await
    });
    claimed(&pair.late).await;
    tokio::time::sleep(Duration::from_millis(20)).await; // the hub's claim is stamped later
    let displaced = pair.hub_takes().await;
    displaced
        .complete(
            Some((FINDING, finding("done by the hub"))),
            Lease::DEFAULT_WRITE,
            Map::new(),
        )
        .await
        .expect("the hub completes");

    let taken = late_take.await.expect("the take").expect("take");
    assert!(
        taken.is_none(),
        "the late claim won the lattice, but the work is done: its take stands down"
    );
    assert_eq!(pair.late.counters().await.outbid_acknowledged, 1);

    pair.holding.release();
    pair.converges(&["done by the hub"]).await;
    for peer in [&pair.hub, &pair.late] {
        assert_eq!(
            peer.counters().await.duplicate_completions,
            0,
            "nothing was done twice"
        );
    }
    assert_eq!(pair.hub.counters().await.outbid_acknowledged, 0);
    pair.close().await;
}

/// The hub's completion reached the late peer after it won but before it completed: its
/// completion acknowledges the hub's, writes no result, and fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rivals_completion_arriving_after_the_winner_won_stops_its_result() {
    let network = MemoryNetwork::new();
    let pair = Pair::start(&network, "127.0.0.1:7972").await;
    pair.contested().await;
    pair.holding.hold();

    let winning = Pair::space(&pair.late, SHORT_SETTLE)
        .take(&Template::new(TASK), take_lease(), Duration::ZERO)
        .await
        .expect("take")
        .expect("the late peer judged its take alone");
    tokio::time::sleep(Duration::from_millis(20)).await;
    let displaced = pair.hub_takes().await;
    displaced
        .complete(
            Some((FINDING, finding("done by the hub"))),
            Lease::DEFAULT_WRITE,
            Map::new(),
        )
        .await
        .expect("the hub completes");
    // The hub's claim and completion reach the late peer while it is still working.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let completed = winning
        .complete(
            Some((FINDING, finding("done late"))),
            Lease::DEFAULT_WRITE,
            Map::new(),
        )
        .await;
    match completed {
        Err(error @ SpaceError::CompletedByDisplaced(_)) => {
            assert!(error.to_string().contains("completed first"), "{error}");
        }
        other => panic!("the late peer's result must not be written: {other:?}"),
    }
    assert_eq!(pair.late.counters().await.outbid_acknowledged, 1);

    pair.holding.release();
    pair.converges(&["done by the hub"]).await;
    for peer in [&pair.hub, &pair.late] {
        assert_eq!(peer.counters().await.duplicate_completions, 0);
    }
    pair.close().await;
}

/// The late peer's earlier claim reached the hub before the hub completed: the hub learned of a
/// better claim, so it must not complete; the lattice winner completes as ever.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_better_claim_arriving_before_the_completion_makes_the_displaced_holder_yield() {
    let network = MemoryNetwork::new();
    let pair = Pair::start(&network, "127.0.0.1:7973").await;
    pair.contested().await;
    pair.holding.hold();

    let winning = Pair::space(&pair.late, SHORT_SETTLE)
        .take(&Template::new(TASK), take_lease(), Duration::ZERO)
        .await
        .expect("take")
        .expect("the late peer judged its take alone");
    tokio::time::sleep(Duration::from_millis(20)).await;
    let displaced = pair.hub_takes().await;
    let late_holder = Some(winning.holder().to_owned());
    pair.holding.release();
    eventually("the late claim to reach the hub", || async {
        pair.hub
            .space_claims(SPACE)
            .await
            .iter()
            .any(|(_, signed)| {
                signed
                    .get("claim")
                    .and_then(|claim| claim.get("holder"))
                    .and_then(Value::as_str)
                    == late_holder.as_deref()
            })
    })
    .await;

    let refused = displaced
        .complete(
            Some((FINDING, finding("done by the hub"))),
            Lease::DEFAULT_WRITE,
            Map::new(),
        )
        .await;
    assert!(
        matches!(refused, Err(SpaceError::NotHeld(_))),
        "{refused:?}"
    );
    winning
        .complete(
            Some((FINDING, finding("done late"))),
            Lease::DEFAULT_WRITE,
            Map::new(),
        )
        .await
        .expect("the lattice winner completes");

    pair.converges(&["done late"]).await;
    for peer in [&pair.hub, &pair.late] {
        let counters = peer.counters().await;
        assert_eq!(counters.duplicate_completions, 0);
        assert_eq!(counters.outbid_acknowledged, 0);
    }
    pair.close().await;
}

/// Both completed before either heard of the other: the shared state keeps one completion, both
/// results stand, and the duplicate is counted once, at the replica whose claim won.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_holders_that_hear_of_each_other_only_after_completing_leave_a_counted_duplicate() {
    let network = MemoryNetwork::new();
    let pair = Pair::start(&network, "127.0.0.1:7974").await;
    pair.contested().await;
    pair.holding.hold();

    let winning = Pair::space(&pair.late, SHORT_SETTLE)
        .take(&Template::new(TASK), take_lease(), Duration::ZERO)
        .await
        .expect("take")
        .expect("the late peer judged its take alone");
    winning
        .complete(
            Some((FINDING, finding("done late"))),
            Lease::DEFAULT_WRITE,
            Map::new(),
        )
        .await
        .expect("the late peer completes");
    tokio::time::sleep(Duration::from_millis(20)).await;
    let displaced = pair.hub_takes().await;
    displaced
        .complete(
            Some((FINDING, finding("done by the hub"))),
            Lease::DEFAULT_WRITE,
            Map::new(),
        )
        .await
        .expect("the hub completes");

    eventually(
        "the duplicate counted where the winning claim is held",
        || async { pair.late.counters().await.duplicate_completions == 1 },
    )
    .await;
    pair.holding.release();
    pair.converges(&["done by the hub", "done late"]).await;
    // Anti-entropy offers the hub's completion again: still one duplicate, once per entry.
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(pair.late.counters().await.duplicate_completions, 1);
    assert_eq!(
        pair.hub.counters().await.duplicate_completions,
        0,
        "the displaced holder cannot tell an acknowledgement from work"
    );
    for peer in [&pair.hub, &pair.late] {
        assert_eq!(peer.counters().await.outbid_acknowledged, 0);
    }
    pair.close().await;
}
