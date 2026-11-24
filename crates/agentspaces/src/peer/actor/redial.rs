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

//! How a peer redials its seeds (owner decisions of 2026-11-23, one rule for the core and every
//! client).
//!
//! # The redial table
//!
//! After a round of dials in which no seed answered, the peer waits the next step of a fixed
//! cycling table before the next round: 5 s, 10 s, 20 s, 30 s, then back to 5 s, and so on until
//! the peer is closed (a peer never gives up; the reconnect window only says it is unreachable).
//! The table is [`REDIAL_STEPS`], in multiples of the configured `reconnect_interval` (5 s by
//! default, so the default steps are exactly 5, 10, 20 and 30 s; a test that shortens the
//! interval shortens every step with it). Each wait has a
//! random spread of ±10 % ([`SPREAD_PERCENT`]), so many peers that lost the same seed at once do
//! not redial it in lockstep.
//!
//! The position in the table is per peer ([`RedialTable`]):
//!
//! - **Advance.** Each wait taken moves it one step, wrapping after the last.
//! - **Reset on success.** A link that held for a reconnect interval (5 s by default) puts it
//!   back at the start when it is lost, and is redialed at once; the rounds after that wait 5 s,
//!   10 s, and so on. Only the link's life counts, not what it carried.
//! - **Reset on wake.** A wake from a suspend puts it back at the start. With no link the peer
//!   redials at once; with a link it asks the seed with a `PING` and leaves it when no answer
//!   comes within the 2 s ping timeout (the dead-seed rule, [`seed_watch`](super::seed_watch)),
//!   failing over at once however young the link.
//!
//! Any other lost link is a quick drop and counts as a failed round: the redial waits the next
//! step first. That covers a seed that accepts and drops every connection and one that drops
//! each link soon after speaking (an overloaded seed shedding links), so such a seed is redialed
//! on the table, never in a loop. These are owner decisions 1 and 3 of 2026-11-23, the same rule
//! in the core and every client.
//!
//! # Dialing several seeds
//!
//! A round dials its seeds concurrently, and the first to answer wins ([`dial_any`]): no seed
//! waits out the connect timeout of a dead seed before it. The dials start in list order, each
//! [`DIAL_STAGGER`] after the one before or as soon as a dial in flight fails, whichever comes
//! first (the connection attempt delay of RFC 8305, "Happy Eyeballs"), and at most
//! [`MAX_DIALS_AT_ONCE`] are in flight. So when every seed is up the first in the list wins, and
//! the failover order (list order, the seed just left last: owner decision 2) holds, while a dead
//! first seed delays a join by a quarter second rather than by its whole connect timeout. The
//! dials still in flight when one answers are cancelled, and a channel that answered too late is
//! closed.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use agentspaces_wire::crypto;
use agentspaces_wire::identity::Identity;
use agentspaces_wire::seed::Seed;
use tokio::task::JoinSet;
use tokio::time::Instant;

use super::dial_one;
use crate::transport::{Channel, Dialer, TransportError};

/// The redial table, in multiples of the reconnect interval: 5, 10, 20 and 30 s at the default
/// 5 s, then back to the first.
pub(super) const REDIAL_STEPS: [u32; 4] = [1, 2, 4, 6];
/// The random spread of each wait, in percent either way.
pub(super) const SPREAD_PERCENT: u64 = 10;
/// How long after one dial of a round the next seed's dial starts, unless a dial in flight
/// fails sooner (RFC 8305's recommended connection attempt delay).
pub(super) const DIAL_STAGGER: Duration = Duration::from_millis(250);
/// The most dials of one round in flight at once (a seed name may expand to many addresses).
pub(super) const MAX_DIALS_AT_ONCE: usize = 16;

/// The wait at `position` of the table for `interval`, spread by `unit` (a uniformly random
/// `u64`): `unit` 0 gives 90 % of the step, `u64::MAX` just under 110 %.
pub(super) fn redial_wait(position: usize, interval: Duration, unit: u64) -> Duration {
    let step = interval.saturating_mul(REDIAL_STEPS[position % REDIAL_STEPS.len()]);
    let step_micros = step.as_micros();
    // The spread across 2 * SPREAD_PERCENT % of the step, in 1/2^64 parts.
    let span = step_micros * u128::from(SPREAD_PERCENT) * 2 / 100;
    let offset = (span * u128::from(unit)) >> 64;
    let low = step_micros * u128::from(100 - SPREAD_PERCENT) / 100;
    let micros = u64::try_from(low + offset).unwrap_or(u64::MAX);
    Duration::from_micros(micros)
}

/// A uniformly random `u64` from the crypto port (the middle of the spread if it fails).
fn random_unit() -> u64 {
    let mut bytes = [0u8; 8];
    match crypto::port().fill_random(&mut bytes) {
        Ok(()) => u64::from_be_bytes(bytes),
        Err(_) => u64::MAX / 2,
    }
}

/// A peer's position in the redial table ([module docs](self#the-redial-table)). The loop owns
/// it and lends it to the redial task in flight (one at a time), which advances it as it waits;
/// the loop resets it on a working link and on a wake.
#[derive(Debug, Clone, Default)]
pub(super) struct RedialTable {
    position: Arc<AtomicUsize>,
}

impl RedialTable {
    /// The wait before the next round, spread at random, and the position moved one step on
    /// (wrapping after the last).
    pub fn next_wait(&self, interval: Duration) -> Duration {
        self.next_wait_with(interval, random_unit())
    }

    /// [`RedialTable::next_wait`] with the spread drawn as `unit`.
    pub fn next_wait_with(&self, interval: Duration, unit: u64) -> Duration {
        let position = self
            .position
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |position| {
                Some((position + 1) % REDIAL_STEPS.len())
            })
            .unwrap_or(0);
        redial_wait(position, interval, unit)
    }

    /// Back to the first step (a working link, a wake).
    pub fn reset(&self) {
        self.position.store(0, Ordering::SeqCst);
    }

    /// The step the next wait takes.
    #[cfg(test)]
    pub fn position(&self) -> usize {
        self.position.load(Ordering::SeqCst)
    }
}

/// What the seed dials of one peer counted, shared by its join's first dial and every redial
/// task: read into [`PeerCounters::seed_dials`] and [`PeerCounters::late_seed_channels`].
///
/// [`PeerCounters::seed_dials`]: crate::peer::PeerCounters::seed_dials
/// [`PeerCounters::late_seed_channels`]: crate::peer::PeerCounters::late_seed_channels
#[derive(Debug, Default)]
pub(in crate::peer) struct DialCounts {
    /// Seed dials started.
    pub dials: AtomicU64,
    /// Channels that answered after another seed of the same round had won, closed unused.
    pub late: AtomicU64,
}

/// Dials `seeds` concurrently and returns the first to answer
/// ([module docs](self#dialing-several-seeds)); when none answers, every seed's failure is added
/// to `failures` in list order. Each dial started, and each channel that answered after the
/// winner (closed unused), is counted in `counts`.
pub(super) async fn dial_any(
    seeds: &[Seed],
    dialers: &[Arc<dyn Dialer>],
    identity: &Arc<Identity>,
    timeout: Duration,
    failures: &mut Vec<(Seed, TransportError)>,
    counts: &DialCounts,
) -> Option<(Channel, Seed)> {
    let mut dials = JoinSet::new();
    let mut failed: Vec<(usize, Seed, TransportError)> = Vec::new();
    let mut next = 0;
    let mut start_next_at = Instant::now();
    loop {
        let can_start = next < seeds.len() && dials.len() < MAX_DIALS_AT_ONCE;
        if can_start && (dials.is_empty() || Instant::now() >= start_next_at) {
            let (index, seed) = (next, seeds[next].clone());
            let (dialers, identity) = (dialers.to_vec(), Arc::clone(identity));
            counts.dials.fetch_add(1, Ordering::Relaxed);
            dials.spawn(async move {
                let result = dial_one(&seed, &dialers, &identity, timeout).await;
                (index, seed, result)
            });
            next += 1;
            start_next_at = Instant::now() + DIAL_STAGGER;
            continue;
        }
        let joined = if can_start {
            tokio::select! {
                joined = dials.join_next() => joined,
                () = tokio::time::sleep_until(start_next_at) => continue,
            }
        } else {
            dials.join_next().await
        };
        let Some(joined) = joined else {
            break; // nothing in flight and nothing left to start
        };
        match joined {
            // The set is dropped on return: the other dials are cancelled. A channel that
            // answered meanwhile is late: counted and closed, unused.
            Ok((_, seed, Ok(channel))) => {
                while let Some(joined) = dials.try_join_next() {
                    if let Ok((_, _, Ok(late))) = joined {
                        counts.late.fetch_add(1, Ordering::Relaxed);
                        late.closer.close();
                    }
                }
                return Some((channel, seed));
            }
            Ok((index, seed, Err(error))) => {
                failed.push((index, seed, error));
                // A failure starts the next dial at once rather than after the stagger.
                start_next_at = Instant::now();
            }
            Err(_) => start_next_at = Instant::now(), // a dial task that panicked: nothing to report
        }
    }
    failed.sort_by_key(|(index, ..)| *index);
    failures.extend(failed.into_iter().map(|(_, seed, error)| (seed, error)));
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::memory::MemoryNetwork;
    use crate::transport::{BoxFuture, Listener};

    const FIVE: Duration = Duration::from_secs(5);
    const MIDDLE: u64 = 1 << 63;

    /// At the default interval and the middle of the spread, the waits are exactly 5, 10, 20 and
    /// 30 s, then 5 s again: the table wraps rather than staying at its last step.
    #[test]
    fn the_table_runs_5_10_20_30_and_wraps() {
        let table = RedialTable::default();
        let waits: Vec<u64> = (0..9)
            .map(|_| table.next_wait_with(FIVE, MIDDLE).as_secs())
            .collect();
        assert_eq!(waits, [5, 10, 20, 30, 5, 10, 20, 30, 5]);
        assert_eq!(table.position(), 1);
    }

    /// The table is in multiples of the configured interval.
    #[test]
    fn the_steps_scale_with_the_interval() {
        let table = RedialTable::default();
        let waits: Vec<Duration> = (0..4)
            .map(|_| table.next_wait_with(Duration::from_millis(50), MIDDLE))
            .collect();
        assert_eq!(
            waits,
            [50, 100, 200, 300].map(Duration::from_millis),
            "{waits:?}"
        );
    }

    /// The spread stays within ±10 % of each step at both ends and for random draws.
    #[test]
    fn the_spread_stays_within_ten_percent() {
        for (position, step) in [5u64, 10, 20, 30].into_iter().enumerate() {
            let step = Duration::from_secs(step);
            let low = redial_wait(position, FIVE, 0);
            let high = redial_wait(position, FIVE, u64::MAX);
            assert_eq!(low, step * 9 / 10, "the low end of step {position}");
            assert!(high < step * 11 / 10, "the high end of step {position}");
            assert!(high > step * 109 / 100, "the high end is near 110 %");
        }
        let table = RedialTable::default();
        let mut spread = std::collections::BTreeSet::new();
        for _ in 0..400 {
            let position = table.position();
            let step = FIVE * REDIAL_STEPS[position];
            let wait = table.next_wait(FIVE);
            assert!(wait >= step * 9 / 10 && wait < step * 11 / 10, "{wait:?}");
            spread.insert(wait);
        }
        assert!(spread.len() > 100, "the waits are spread: {}", spread.len());
    }

    /// A reset puts the next wait back at the first step.
    #[test]
    fn a_reset_goes_back_to_the_first_step() {
        let table = RedialTable::default();
        for _ in 0..3 {
            table.next_wait_with(FIVE, MIDDLE);
        }
        assert_eq!(table.position(), 3);
        table.reset();
        assert_eq!(table.next_wait_with(FIVE, MIDDLE), FIVE);
    }

    /// A dialer over a memory network whose port 1 never answers (a seed that drops the SYN).
    #[derive(Debug)]
    struct Silent(crate::transport::memory::MemoryDialer);

    impl Dialer for Silent {
        fn schemes(&self) -> &[&'static str] {
            self.0.schemes()
        }

        fn dial<'a>(
            &'a self,
            seed: &'a Seed,
            identity: &'a Identity,
            timeout: Duration,
        ) -> BoxFuture<'a, Result<Channel, TransportError>> {
            if seed.port == 1 {
                return Box::pin(std::future::pending());
            }
            self.0.dial(seed, identity, timeout)
        }
    }

    fn mem(port: u16) -> Seed {
        Seed::new("127.0.0.1", port, "mem")
    }

    /// A first seed that never answers delays the round by the stagger, not by its 5 s connect
    /// timeout: the second seed, dialed concurrently, wins.
    #[tokio::test(start_paused = true)]
    async fn a_silent_first_seed_costs_the_stagger_not_the_timeout() {
        let network = MemoryNetwork::new();
        let listener = network.listen("127.0.0.1:2");
        let accepted = tokio::spawn(async move { listener.accept().await });
        let dialers: Vec<Arc<dyn Dialer>> = vec![Arc::new(Silent(network.dialer()))];
        let identity = Arc::new(Identity::generate().expect("identity"));
        let started = Instant::now();
        let mut failures = Vec::new();
        let (_channel, seed) = dial_any(
            &[mem(1), mem(2)],
            &dialers,
            &identity,
            FIVE,
            &mut failures,
            &DialCounts::default(),
        )
        .await
        .expect("the second seed answers");
        assert_eq!(seed, mem(2));
        assert_eq!(started.elapsed(), DIAL_STAGGER, "one stagger, no timeout");
        assert!(failures.is_empty());
        assert!(accepted.await.expect("accept task").is_some());
    }

    /// When every seed is up the first in the list wins (the failover order holds), and a seed
    /// that refuses at once starts the next dial at once.
    #[tokio::test(start_paused = true)]
    async fn the_first_seed_up_wins_and_a_refusal_starts_the_next_at_once() {
        let network = MemoryNetwork::new();
        let (first, second) = (network.listen("127.0.0.1:3"), network.listen("127.0.0.1:4"));
        let _accepting = tokio::spawn(async move {
            let _ = tokio::join!(first.accept(), second.accept());
        });
        let dialers: Vec<Arc<dyn Dialer>> = vec![Arc::new(network.dialer())];
        let identity = Arc::new(Identity::generate().expect("identity"));
        let mut failures = Vec::new();
        let (_channel, seed) = dial_any(
            &[mem(3), mem(4)],
            &dialers,
            &identity,
            FIVE,
            &mut failures,
            &DialCounts::default(),
        )
        .await
        .expect("an answer");
        assert_eq!(seed, mem(3), "the first in the list");

        // Port 9 has no listener: refused at once, so the next seed is dialed with no stagger.
        let started = Instant::now();
        let (_channel, seed) = dial_any(
            &[mem(9), mem(4)],
            &dialers,
            &identity,
            FIVE,
            &mut failures,
            &DialCounts::default(),
        )
        .await
        .expect("an answer");
        assert_eq!(seed, mem(4));
        assert_eq!(
            started.elapsed(),
            Duration::ZERO,
            "no stagger after a refusal"
        );
        assert!(
            failures.is_empty(),
            "failures are reported only when no seed answers"
        );
    }

    /// A dialer whose seeds never answer, except that port 100 fails after 6 s; it records
    /// when each dial started (paused time).
    #[derive(Debug, Default)]
    struct Crowd(std::sync::Mutex<Vec<(Instant, u16)>>);

    impl Dialer for Crowd {
        fn schemes(&self) -> &[&'static str] {
            &["mem"]
        }

        fn dial<'a>(
            &'a self,
            seed: &'a Seed,
            _identity: &'a Identity,
            _timeout: Duration,
        ) -> BoxFuture<'a, Result<Channel, TransportError>> {
            self.0
                .lock()
                .expect("not poisoned")
                .push((Instant::now(), seed.port));
            let port = seed.port;
            Box::pin(async move {
                if port == 100 {
                    tokio::time::sleep(Duration::from_secs(6)).await;
                    return Err(TransportError::Closed);
                }
                std::future::pending().await
            })
        }
    }

    /// At most [`MAX_DIALS_AT_ONCE`] (16) dials are in flight, as in Python, Ruby and
    /// TypeScript: with 16 silent seeds out the 17th waits for a slot, and a failure starts it
    /// at once.
    #[tokio::test(start_paused = true)]
    async fn at_most_sixteen_dials_are_in_flight() {
        assert_eq!(MAX_DIALS_AT_ONCE, 16);
        let crowd = Arc::new(Crowd::default());
        let dialers: Vec<Arc<dyn Dialer>> = vec![crowd.clone()];
        let seeds: Vec<Seed> = (100..120).map(mem).collect();
        let identity = Arc::new(Identity::generate().expect("identity"));
        let started = Instant::now();
        let round = tokio::spawn(async move {
            dial_any(
                &seeds,
                &dialers,
                &identity,
                FIVE * 10,
                &mut Vec::new(),
                &DialCounts::default(),
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(5_900)).await;
        assert_eq!(
            crowd.0.lock().expect("not poisoned").len(),
            16,
            "the 17th waits"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
        let dials = crowd.0.lock().expect("not poisoned").clone();
        assert_eq!(dials.len(), 17);
        assert_eq!(
            dials[16],
            (started + Duration::from_secs(6), 116),
            "started at the failure"
        );
        round.abort();
    }

    /// A dialer over a memory network that connects at once but hands port 1's channel over
    /// only after a quarter second (a handshake still running when another seed answers).
    #[derive(Debug)]
    struct SlowHandshake(crate::transport::memory::MemoryDialer);

    impl Dialer for SlowHandshake {
        fn schemes(&self) -> &[&'static str] {
            self.0.schemes()
        }

        fn dial<'a>(
            &'a self,
            seed: &'a Seed,
            identity: &'a Identity,
            timeout: Duration,
        ) -> BoxFuture<'a, Result<Channel, TransportError>> {
            Box::pin(async move {
                let channel = self.0.dial(seed, identity, timeout).await?;
                if seed.port == 1 {
                    tokio::time::sleep(DIAL_STAGGER).await;
                }
                Ok(channel)
            })
        }
    }

    /// The first seed's connection is made at once but its handshake ends exactly when the
    /// second seed (started a stagger later) answers: one wins, and the other's connection, late
    /// or still in its handshake, is closed rather than left open at its seed.
    #[tokio::test(start_paused = true)]
    async fn a_late_connection_is_closed() {
        let network = MemoryNetwork::new();
        let (first, second) = (network.listen("127.0.0.1:1"), network.listen("127.0.0.1:2"));
        let accepted = tokio::spawn(async move { (first.accept().await, second.accept().await) });
        let dialers: Vec<Arc<dyn Dialer>> = vec![Arc::new(SlowHandshake(network.dialer()))];
        let identity = Arc::new(Identity::generate().expect("identity"));
        let started = Instant::now();
        let mut failures = Vec::new();
        let (channel, seed) = dial_any(
            &[mem(1), mem(2)],
            &dialers,
            &identity,
            FIVE,
            &mut failures,
            &DialCounts::default(),
        )
        .await
        .expect("an answer");
        assert_eq!(started.elapsed(), DIAL_STAGGER);
        let (at_first, at_second) = accepted.await.expect("accept task");
        let (at_first, at_second) = (
            at_first.expect("dialed").expect("a channel"),
            at_second.expect("dialed").expect("a channel"),
        );
        let (mut winner_end, mut loser_end) = if seed == mem(1) {
            (at_first, at_second)
        } else {
            (at_second, at_first)
        };
        assert_eq!(
            tokio::time::timeout(FIVE, loser_end.receiver.recv())
                .await
                .expect("the losing seed sees its connection end"),
            None
        );
        assert!(
            tokio::time::timeout(FIVE, winner_end.receiver.recv())
                .await
                .is_err(),
            "the winner's link stays up"
        );
        drop(channel);
    }

    /// A dialer over a memory network that holds every dial until the test opens its gate.
    #[derive(Debug)]
    struct Gated(
        crate::transport::memory::MemoryDialer,
        Arc<tokio::sync::Semaphore>,
    );

    impl Dialer for Gated {
        fn schemes(&self) -> &[&'static str] {
            self.0.schemes()
        }

        fn dial<'a>(
            &'a self,
            seed: &'a Seed,
            identity: &'a Identity,
            timeout: Duration,
        ) -> BoxFuture<'a, Result<Channel, TransportError>> {
            Box::pin(async move {
                let _pass = self.1.acquire().await.map_err(|_| TransportError::Closed)?;
                self.0.dial(seed, identity, timeout).await
            })
        }
    }

    /// The counters every client keeps under one name (owner decision 4 of 2026-11-23): each
    /// seed dial started is counted (`seed_dials`), and a channel that answered after another
    /// seed of the round had won is counted and closed (`late_seed_channels`).
    #[tokio::test(start_paused = true)]
    async fn seed_dials_and_late_seed_channels_are_counted() {
        let network = MemoryNetwork::new();
        let (first, second) = (network.listen("127.0.0.1:1"), network.listen("127.0.0.1:2"));
        let accepted = tokio::spawn(async move { (first.accept().await, second.accept().await) });
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let dialers: Vec<Arc<dyn Dialer>> =
            vec![Arc::new(Gated(network.dialer(), Arc::clone(&gate)))];
        let identity = Arc::new(Identity::generate().expect("identity"));
        let counts = DialCounts::default();
        let opener = Arc::clone(&gate);
        let open = tokio::spawn(async move {
            // Both dials are out (the second a stagger after the first): both answer at once.
            tokio::time::sleep(DIAL_STAGGER * 2).await;
            opener.add_permits(2);
        });
        let (channel, _) = dial_any(
            &[mem(1), mem(2)],
            &dialers,
            &identity,
            FIVE,
            &mut Vec::new(),
            &counts,
        )
        .await
        .expect("an answer");
        open.await.expect("gate task");
        assert_eq!(counts.dials.load(Ordering::Relaxed), 2, "two dials started");
        assert_eq!(
            counts.late.load(Ordering::Relaxed),
            1,
            "the second answer came late"
        );
        let (at_first, at_second) = accepted.await.expect("accept task");
        let ends = [
            at_first.expect("dialed").expect("a channel"),
            at_second.expect("dialed").expect("a channel"),
        ];
        let mut closed = 0;
        for mut end in ends {
            if tokio::time::timeout(FIVE, end.receiver.recv())
                .await
                .is_ok()
            {
                closed += 1;
            }
        }
        assert_eq!(
            closed, 1,
            "the late channel is closed, the winner's stays up"
        );
        drop(channel);

        // A round whose first seed answers alone starts one dial and finds nothing late.
        let counts = DialCounts::default();
        let listener = network.listen("127.0.0.1:3");
        let _accepting = tokio::spawn(async move { listener.accept().await });
        let plain: Vec<Arc<dyn Dialer>> = vec![Arc::new(network.dialer())];
        dial_any(
            &[mem(3), mem(4)],
            &plain,
            &identity,
            FIVE,
            &mut Vec::new(),
            &counts,
        )
        .await
        .expect("an answer");
        assert_eq!(counts.dials.load(Ordering::Relaxed), 1);
        assert_eq!(counts.late.load(Ordering::Relaxed), 0);
    }

    /// When no seed answers, every failure is reported in list order, each dial bounded by the
    /// connect timeout and all of them overlapping: three silent seeds cost one timeout plus two
    /// staggers, not three timeouts.
    #[tokio::test(start_paused = true)]
    async fn no_answer_reports_every_seed_in_order_after_one_timeout() {
        let network = MemoryNetwork::new();
        let dialers: Vec<Arc<dyn Dialer>> = vec![Arc::new(Silent(network.dialer()))];
        let identity = Arc::new(Identity::generate().expect("identity"));
        let started = Instant::now();
        let mut failures = Vec::new();
        let seeds = [
            mem(1),
            Seed::new("127.0.0.2", 1, "mem"),
            Seed::new("127.0.0.3", 1, "mem"),
        ];
        assert!(
            dial_any(
                &seeds,
                &dialers,
                &identity,
                FIVE,
                &mut failures,
                &DialCounts::default()
            )
            .await
            .is_none()
        );
        assert_eq!(started.elapsed(), FIVE + DIAL_STAGGER * 2);
        let failed: Vec<Seed> = failures.iter().map(|(seed, _)| seed.clone()).collect();
        assert_eq!(failed, seeds);
        assert!(
            failures
                .iter()
                .all(|(_, error)| matches!(error, TransportError::Timeout(_)))
        );
    }
}
