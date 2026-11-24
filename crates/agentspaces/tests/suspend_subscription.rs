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

//! A push subscription's lease is a local period (SPEC v0.1.36 §9.5): nobody else reads it, and
//! its renewer runs on the monotonic clock, so it is judged on the monotonic clock too. A laptop
//! sleep (the wall clock jumps, the monotonic clock does not) or a forward NTP step lapses no
//! subscription; the lease still lapses once its time has passed on the monotonic clock. On wall
//! time the sleep lapsed every subscription at once, and its renewal then failed for good.
//!
//! Runs on paused Tokio time with a clock whose wall reading the test steps by hand: no sleeps
//! beyond virtual time.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use agentspaces::clock::Clock;
use agentspaces::group::GroupSpec;
use agentspaces::peer::{ListenerSpec, Peer, PeerConfig};
use agentspaces::space::{CloseReason, Fleet, Lease, Template};
use agentspaces::transport::memory::MemoryNetwork;
use agentspaces::wire::identity::Identity;

/// A wall clock that follows Tokio's (paused) monotonic clock plus a step the test sets: a
/// suspend is a step the monotonic clock never saw.
#[derive(Debug)]
struct SteppedClock {
    base_wall: i64,
    base: tokio::time::Instant,
    step: AtomicI64,
}

impl SteppedClock {
    fn new() -> Self {
        Self {
            base_wall: 1_900_000_000_000,
            base: tokio::time::Instant::now(),
            step: AtomicI64::new(0),
        }
    }

    fn mono(&self) -> i64 {
        i64::try_from(self.base.elapsed().as_millis()).unwrap_or(i64::MAX)
    }
}

impl Clock for SteppedClock {
    fn now_ms(&self) -> i64 {
        self.base_wall + self.mono() + self.step.load(Ordering::SeqCst)
    }

    fn local_ms(&self) -> i64 {
        self.base_wall + self.mono()
    }
}

#[tokio::test(start_paused = true)]
async fn a_suspend_lapses_no_subscription_and_the_lease_still_lapses_in_its_time() {
    let network = MemoryNetwork::new();
    let clock = Arc::new(SteppedClock::new());
    let mut config = PeerConfig::new(
        Identity::generate().expect("id"),
        GroupSpec::FoundingText("agentspaces-rust-suspend-subscription".to_owned()),
    );
    config.clock = Arc::clone(&clock) as Arc<dyn Clock>;
    config = config.listen_on(ListenerSpec::bound(Arc::new(
        network.listen("127.0.0.1:7861"),
    )));
    let peer = Peer::start(config).await.expect("peer");
    let space = Fleet::from_peer(peer.clone()).space("tasks");
    let subscription = space
        .notify(
            &Template::new("T#v1"),
            Lease::from_millis(60_000).expect("lease"),
            |_| {},
        )
        .await
        .expect("notify");
    let lapse = subscription.expires_at_millis();
    assert!(
        (lapse - clock.now_ms() - 60_000).abs() <= 1,
        "the lapse reads in wall time"
    );

    // A ten-minute suspend: the wall clock jumps, the monotonic clock does not.
    clock.step.store(600_000, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(1)).await;
    space
        .pull()
        .await
        .expect("a turn of the loop after the step");
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        subscription.is_open(),
        "the suspend lapsed the subscription: {:?}",
        subscription.close_reason()
    );
    subscription
        .renew(Lease::from_millis(60_000).expect("lease"))
        .expect("the renewal after the suspend");
    let renewed = subscription.expires_at_millis();
    assert!(
        (renewed - clock.now_ms() - 60_000).abs() <= 1,
        "the renewed lapse reads in wall time after the step: {renewed} vs {}",
        clock.now_ms()
    );

    // The lease lapses once its minute passes on the monotonic clock.
    tokio::time::sleep(Duration::from_secs(61)).await;
    space.pull().await.expect("a turn");
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(subscription.close_reason(), Some(CloseReason::Lapsed));
    let _ = peer.close().await;
}
