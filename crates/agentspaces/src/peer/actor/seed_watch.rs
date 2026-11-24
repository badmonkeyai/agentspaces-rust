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

//! The dead-seed rule: how a peer judges the link it dialed (owner decision of 2026-11-23, one
//! rule for every dial-only client).
//!
//! A seed that leaves without a FIN (power loss, a partition, a laptop moved to another network)
//! leaves a half-open link: nothing arrives and nothing fails until TCP gives up, minutes later.
//! Until then the peer fails over to no other seed, and its `relay.via` hint names a holder that
//! is gone, so every member's targeted relay toward it fails.
//!
//! # The rule
//!
//! - **Quiet.** When nothing has been read off the dialed link for [`SEED_QUIET`] (45 s, 1.5 times
//!   the 30 s keepalive bound), the peer sends its seed one `PING`, addressed to the seed once it
//!   is known. Every member answers a `PING` at once (SPEC §5.2), so a live seed answers within a
//!   round trip, and a quiet group costs one `PING` and one `ACK` per 45 s.
//! - **Lost.** When the link is still silent [`SEED_ANSWER`] after that `PING`, the ping timeout a
//!   prober gives each `PING` (2 s, SPEC §9.4, the core's `GroupMembership` default), the seed is
//!   lost: the link is closed (`links_silent`), and the redial goes to another seed first, at once
//!   since the link lived longer than the reconnect interval, then cycles on the redial table
//!   ([`redial`](super::redial): 5, 10, 20, 30 s, then 5 s again).
//!   A seed is so left at most once per 47 s of silence, whatever it does, so a slow or flapping
//!   seed causes no failover storm.
//! - **Every dialed seed link.** The rule holds for the link a peer dialed to its seed whether
//!   or not the peer also listens (owner decision 5 of 2026-11-23).
//! - **Kept.** Any frame read off the link, the `ACK` or anything else, keeps the seed and starts
//!   the quiet wait again. So do bytes of a frame still arriving when the answer window ends
//!   (the transport's [`progress`](crate::transport::FrameReceiver::progress)): the seed is
//!   writing, and a large frame on a slow link is no dead seed (as Python's `_bytes_at`).
//! - **Resume.** A wake from a suspend asks the seed at once (the link may have died while the
//!   host slept; a `PING` already waiting is not sent again and becomes the wake's), and a peer
//!   that has no link redials at once rather than sitting out a reconnect pause. A late wake, the
//!   loop waking more than 30 s past its deadline with no wall step (a frozen process: SIGSTOP, a
//!   long collection or VM pause), is a wake too, and always asks again with a fresh answer
//!   window: a `PING` sent before the freeze had its window run out while nobody could read the
//!   answer (owner decision 3 of 2026-11-23). A wake's `PING`
//!   left unanswered fails over at once even from a link younger than the reconnect interval on
//!   the monotonic clock (which did not count the sleep): the wake started the table over, so its
//!   verdict is no quick drop (owner decision 3 of 2026-11-23, the same in every client).
//!
//! "Read off the link" is judged by the link's reader as each frame comes off the transport
//! ([`Heard`]), not by the loop as it handles frames, so a loop busy with a burst never takes a
//! seed that answered for a silent one. Both periods are on the monotonic clock: a wall step moves
//! neither.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use agentspaces_wire::bodies::{self, KIND_PING};
use tokio::time::Instant;

use super::{Actor, bump, random_nonce};

/// How long the dialed link may be silent before the peer asks its seed with a `PING`: 1.5 times
/// the 30 s keepalive bound.
pub(super) const SEED_QUIET: Duration = Duration::from_secs(45);
/// How long the peer waits, after that `PING`, for anything at all from the seed before it takes
/// the seed as lost: the ping timeout a prober gives each `PING` (SPEC §9.4,
/// `GroupMembership.Config.defaults()`), as Python's `LINK_ANSWER_S`.
pub(super) const SEED_ANSWER: Duration = Duration::from_secs(2);

/// When a link's reader last read a frame off its transport (any frame, whether it verifies or
/// not), shared by the reader and the loop. Monotonic.
#[derive(Debug)]
pub(super) struct Heard {
    base: Instant,
    /// Microseconds after `base`.
    micros: AtomicU64,
    /// The bytes the transport has read off the link, a frame still arriving included, when it
    /// counts them ([`FrameReceiver::progress`](crate::transport::FrameReceiver::progress)).
    bytes: Option<Arc<AtomicU64>>,
}

impl Heard {
    /// A link heard from now (it has just come up), whose transport counts its bytes read in
    /// `bytes` when it does.
    pub fn new(bytes: Option<Arc<AtomicU64>>) -> Arc<Self> {
        Arc::new(Self {
            base: Instant::now(),
            micros: AtomicU64::new(0),
            bytes,
        })
    }

    /// The bytes read off the link so far (0 on a transport that does not count them).
    pub fn bytes(&self) -> u64 {
        self.bytes
            .as_ref()
            .map_or(0, |bytes| bytes.load(Ordering::Relaxed))
    }

    /// Notes a frame read now.
    pub fn touch(&self) {
        let since = Instant::now().saturating_duration_since(self.base);
        let micros = u64::try_from(since.as_micros()).unwrap_or(u64::MAX);
        self.micros.fetch_max(micros, Ordering::Relaxed);
    }

    /// When a frame was last read (when the link came up, if none was).
    pub fn at(&self) -> Instant {
        let micros = self.micros.load(Ordering::Relaxed);
        self.base
            .checked_add(Duration::from_micros(micros))
            .unwrap_or(self.base)
    }
}

/// The dead-seed rule's state on the loop ([module docs](self)).
#[derive(Debug, Default)]
pub(super) struct SeedWatch {
    /// When the current link's seed was asked with a `PING` and has not been heard from since.
    asked: Option<Instant>,
    /// The link's bytes read ([`Heard::bytes`]) when it was asked: more by the end of the answer
    /// window is a frame still arriving, an answer.
    asked_bytes: u64,
    /// Whether the `PING` waiting is a wake's: its verdict fails over at once, however young the
    /// link on the monotonic clock (the wake already started the redial table over).
    pub(super) woke: bool,
}

impl SeedWatch {
    /// Forgets the question (a new link, or a lost one).
    pub fn reset(&mut self) {
        self.asked = None;
        self.asked_bytes = 0;
        self.woke = false;
    }
}

impl Actor {
    /// When the dead-seed rule next has something to judge: the end of the quiet wait, or of the
    /// answer window of a `PING` not yet answered. `None` without a dialed link.
    pub(super) fn seed_check_at(&self) -> Option<Instant> {
        if self.closed {
            return None;
        }
        let heard = self.link.as_ref()?.heard.at();
        match self.seed_watch.asked {
            Some(asked) if heard < asked => asked.checked_add(SEED_ANSWER),
            _ => heard.checked_add(SEED_QUIET),
        }
    }

    /// The dead-seed rule's deadline came: ask a quiet seed, or drop a seed that did not answer.
    pub(super) fn on_seed_check(&mut self) {
        let Some(link) = self.link.as_ref() else {
            self.seed_watch.reset();
            return;
        };
        if self.closed {
            return;
        }
        let now = Instant::now();
        let heard = link.heard.at();
        match self.seed_watch.asked {
            Some(asked) if heard < asked => {
                if now.saturating_duration_since(asked) < SEED_ANSWER {
                    return;
                }
                if link.heard.bytes() > self.seed_watch.asked_bytes {
                    // Bytes of a frame not yet whole: the seed is writing, and a slow link is no
                    // dead one. The quiet wait starts again from now.
                    link.heard.touch();
                    self.seed_watch.reset();
                    return;
                }
                bump(&mut self.counters.links_silent);
                tracing::warn!(
                    peer = %self.peer_id,
                    remote = %link.info.remote,
                    silent_s = now.saturating_duration_since(heard).as_secs(),
                    "agentspaces: the seed was silent and did not answer a PING; dropping the link to dial again"
                );
                let woke = self.seed_watch.woke;
                self.seed_watch.reset();
                self.lose_link_failing_over(woke);
            }
            _ => {
                self.seed_watch.reset();
                if now.saturating_duration_since(heard) >= SEED_QUIET {
                    self.ask_seed();
                }
            }
        }
    }

    /// Whether a `PING` to the seed waits for its answer (nothing heard since it was sent).
    pub(super) fn seed_asked(&self) -> bool {
        self.link.as_ref().is_some_and(|link| {
            self.seed_watch
                .asked
                .is_some_and(|asked| link.heard.at() < asked)
        })
    }

    /// Asks the seed whether it still reads the link: one `PING`, addressed to the seed once it is
    /// known. Asked once until anything is heard from it.
    pub(super) fn ask_seed(&mut self) {
        let Some(link) = self.link.as_ref() else {
            return;
        };
        let now = Instant::now();
        if self
            .seed_watch
            .asked
            .is_some_and(|asked| link.heard.at() < asked)
        {
            return; // asked already, and not answered yet
        }
        let Some(nonce) = random_nonce() else {
            return;
        };
        self.seed_watch.asked = Some(now);
        self.seed_watch.asked_bytes = link.heard.bytes();
        bump(&mut self.counters.seed_pings);
        let seed = self.seed_peer.clone();
        // A link with no room for a PING is judged all the same: the answer window runs.
        let _ = self.send(KIND_PING, &bodies::ping_body(nonce), seed.as_deref());
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use agentspaces_wire::bodies::{self, KIND_ACK, KIND_DIGEST, KIND_PING, KIND_PULL_RESP};
    use agentspaces_wire::cbor::{Map, Value};
    use agentspaces_wire::envelope;
    use agentspaces_wire::fold::{FoldContext, SpaceStore};
    use agentspaces_wire::identity::Identity;
    use agentspaces_wire::ids;
    use agentspaces_wire::records;
    use agentspaces_wire::revocation::Registry;
    use agentspaces_wire::seed::Seed;

    use super::super::tests::test_actor;
    use super::super::{Actor, Inbound};
    use super::{SEED_ANSWER, SEED_QUIET};
    use crate::peer::PeerEvent;
    use crate::transport::{Channel, Listener, memory};

    /// An actor on a link to a seed whose far end the test holds.
    fn linked() -> (
        Actor,
        Channel,
        tokio::sync::broadcast::Receiver<PeerEvent>,
        tokio::sync::mpsc::Receiver<Inbound>,
    ) {
        let (mut actor, events, inbound, _link) = test_actor();
        actor.seeds = vec![
            Seed::new("127.0.0.1", 7000, "tcp"),
            Seed::new("127.0.0.1", 7001, "tcp"),
        ];
        let (mine, theirs) = memory::pair("mem", "seed", "peer", None, None);
        actor.install_link(mine, Seed::new("127.0.0.1", 7000, "tcp"));
        actor.on_link_ready();
        (actor, theirs, events, inbound)
    }

    /// The frames the far end has received since the last call: (kind, to, body).
    async fn sent(theirs: &mut Channel) -> Vec<(String, Option<String>, Vec<u8>)> {
        // The pump hands frames to the transport in its own task, two at a time (the memory
        // link's queue): take what is queued and let it run again, until it has nothing more.
        let mut frames = Vec::new();
        let mut idle = 0;
        while idle < 16 {
            // What is queued now, without waiting (and so without moving paused time).
            let frame = tokio::select! {
                biased;
                frame = theirs.receiver.recv() => frame,
                () = std::future::ready(()) => None,
            };
            let Some(frame) = frame else {
                idle += 1;
                tokio::task::yield_now().await;
                continue;
            };
            idle = 0;
            let Some(env) = envelope::decode_frame(&frame) else {
                continue;
            };
            let kind = env
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let to = env.get("to").and_then(Value::as_str).map(str::to_owned);
            let body = env
                .get("body")
                .and_then(Value::as_bytes)
                .map(<[u8]>::to_vec)
                .unwrap_or_default();
            frames.push((kind, to, body));
        }
        frames
    }

    fn pings(frames: &[(String, Option<String>, Vec<u8>)]) -> usize {
        frames.iter().filter(|(kind, ..)| kind == KIND_PING).count()
    }

    /// A frame the seed sends: read by the link's reader (which marks the link heard) and handed
    /// to the loop, as the run loop would. Answers what the peer sent in return.
    async fn seed_says(
        actor: &mut Actor,
        theirs: &mut Channel,
        inbound: &mut tokio::sync::mpsc::Receiver<Inbound>,
        seed: &Identity,
        kind: &str,
        body: &[u8],
    ) -> Vec<(String, Option<String>, Vec<u8>)> {
        // A logical counter of its own per frame: two frames under one stamp are a replay, which
        // the peer drops before any handling (and the wall clock may not move between two).
        static LOGICAL: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(100);
        let logical = LOGICAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let stamp = format!(
            "{}:{logical}:{}",
            actor.now().saturating_add(1),
            seed.peer_id()
        );
        let env = envelope::envelope(
            &actor.group,
            kind,
            seed.peer_id(),
            &stamp,
            body,
            Some(&actor.peer_id.clone()),
        );
        theirs
            .sender
            .send(envelope::encode_frame(&env, seed))
            .await
            .expect("the link is up");
        let message = inbound.recv().await.expect("the reader forwards the frame");
        actor.on_inbound(message);
        sent(theirs).await
    }

    /// Runs the loop's dead-seed turn when its deadline falls due, as the run loop would.
    async fn check_at_due(actor: &mut Actor) {
        let due = actor.seed_check_at().expect("a deadline while linked");
        tokio::time::sleep_until(due).await;
        actor.on_seed_check();
    }

    /// A seed silent for 45 s is asked with one PING; one silent for the 2 s ping timeout more is
    /// dropped, and the redial goes to another seed at once.
    #[tokio::test(start_paused = true)]
    async fn a_seed_silent_for_45_s_is_pinged_and_one_that_does_not_answer_is_left_within_2_s() {
        let (mut actor, mut theirs, mut events, _inbound) = linked();
        let start = tokio::time::Instant::now();
        sent(&mut theirs).await;

        // Nothing before 45 s.
        tokio::time::advance(SEED_QUIET - Duration::from_millis(1)).await;
        assert_eq!(actor.seed_check_at(), Some(start + SEED_QUIET));
        actor.on_seed_check();
        assert_eq!(pings(&sent(&mut theirs).await), 0, "not before 45 s");

        check_at_due(&mut actor).await;
        let frames = sent(&mut theirs).await;
        assert_eq!(pings(&frames), 1, "{frames:?}");
        assert_eq!(actor.counters.seed_pings, 1);
        let asked = tokio::time::Instant::now();
        assert_eq!(actor.seed_check_at(), Some(asked + SEED_ANSWER));

        // Asked once: an early turn neither asks again nor drops it.
        tokio::time::advance(SEED_ANSWER - Duration::from_millis(1)).await;
        actor.on_seed_check();
        actor.ask_seed();
        assert_eq!(pings(&sent(&mut theirs).await), 0);
        assert!(actor.link.is_some());

        // No answer within the window: the seed is lost.
        while events.try_recv().is_ok() {}
        check_at_due(&mut actor).await;
        assert!(actor.link.is_none(), "the silent link is dropped");
        assert!(theirs.closer.is_closed());
        assert_eq!(actor.counters.links_silent, 1);
        assert_eq!(
            tokio::time::Instant::now().duration_since(start),
            Duration::from_secs(47),
            "dropped at the end of the answer window, the 2 s ping timeout after the PING"
        );
        assert_eq!(events.try_recv().ok(), Some(PeerEvent::Disconnected));
        assert!(actor.redial.is_some(), "redialing");
        assert_eq!(
            actor.candidate_seeds()[0],
            Seed::new("127.0.0.1", 7001, "tcp"),
            "another seed first"
        );
        assert_eq!(
            actor.seed_check_at(),
            None,
            "nothing to judge without a link"
        );
    }

    /// A seed that answers the PING (or says anything) is kept, and the quiet wait starts again
    /// from its answer.
    #[tokio::test(start_paused = true)]
    async fn an_answering_seed_is_kept() {
        let (mut actor, mut theirs, _events, mut inbound) = linked();
        let seed = Identity::generate().expect("identity");
        sent(&mut theirs).await;
        check_at_due(&mut actor).await;
        let frames = sent(&mut theirs).await;
        let ping = frames
            .iter()
            .find(|(kind, ..)| kind == KIND_PING)
            .expect("asked");
        let nonce = bodies::parse_ping(&ping.2).expect("a ping body");

        tokio::time::advance(Duration::from_secs(3)).await;
        seed_says(
            &mut actor,
            &mut theirs,
            &mut inbound,
            &seed,
            KIND_ACK,
            &bodies::ack_body(nonce),
        )
        .await;
        let answered = tokio::time::Instant::now();
        assert_eq!(
            actor.seed_check_at(),
            Some(answered + SEED_QUIET),
            "the quiet wait starts again from the answer"
        );
        tokio::time::advance(SEED_ANSWER).await;
        actor.on_seed_check();
        assert!(actor.link.is_some(), "kept");
        assert_eq!(actor.counters.links_silent, 0);

        // The seed's own traffic keeps it too: no PING while it speaks every 30 s.
        for nonce in 0..4 {
            seed_says(
                &mut actor,
                &mut theirs,
                &mut inbound,
                &seed,
                KIND_PING,
                &bodies::ping_body(nonce),
            )
            .await;
            tokio::time::advance(Duration::from_secs(30)).await;
            actor.on_seed_check();
        }
        assert_eq!(
            actor.counters.seed_pings, 1,
            "no PING while the seed speaks"
        );
        assert!(actor.link.is_some());
    }

    /// The ask goes to the seed by name once it is known (here, from its first addressed frame).
    #[tokio::test(start_paused = true)]
    async fn the_ping_is_addressed_to_a_known_seed() {
        let (mut actor, mut theirs, _events, mut inbound) = linked();
        let seed = Identity::generate().expect("identity");
        seed_says(
            &mut actor,
            &mut theirs,
            &mut inbound,
            &seed,
            KIND_PING,
            &bodies::ping_body(1),
        )
        .await;
        sent(&mut theirs).await;
        check_at_due(&mut actor).await;
        let frames = sent(&mut theirs).await;
        let ping = frames
            .iter()
            .find(|(kind, ..)| kind == KIND_PING)
            .expect("asked");
        assert_eq!(ping.1.as_deref(), Some(seed.peer_id()));
    }

    /// A wake from a suspend asks the seed at once (the link may have died in the sleep), so a
    /// dead one is left within the answer window rather than after 45 s more.
    #[tokio::test(start_paused = true)]
    async fn a_resume_asks_the_seed_at_once() {
        let (mut actor, mut theirs, ..) = linked();
        let clock = crate::clock::ManualClock::new(1_900_000_000_000);
        actor.clock = std::sync::Arc::new(clock.clone());
        actor.check_wall_step();
        sent(&mut theirs).await;
        tokio::time::advance(Duration::from_secs(5)).await;
        clock.advance(600_000);
        actor.check_wall_step();
        assert_eq!(actor.counters.resumes, 1);
        assert_eq!(pings(&sent(&mut theirs).await), 1, "asked at once");
        let asked = tokio::time::Instant::now();
        assert_eq!(actor.seed_check_at(), Some(asked + SEED_ANSWER));
        check_at_due(&mut actor).await;
        assert!(actor.link.is_none(), "no answer: left");
    }

    /// A wake while linked asks the seed with a PING (the link may have died in the sleep) and
    /// applies the dead-seed rule: no answer within the 2 s ping timeout fails over, at once and
    /// to another seed first, with the table started over (owner decision 3 of 2026-11-23).
    #[tokio::test(start_paused = true)]
    async fn a_wake_while_linked_pings_and_fails_over_on_silence() {
        let (mut actor, mut theirs, mut events, _inbound) = linked();
        let silent = std::sync::Arc::new(Silent::default());
        actor.dialers = vec![silent.clone()];
        actor.settings.reconnect_interval = Duration::from_secs(5);
        for _ in 0..3 {
            actor.redial_table.next_wait(Duration::from_secs(5));
        }
        let clock = crate::clock::ManualClock::new(1_900_000_000_000);
        actor.clock = std::sync::Arc::new(clock.clone());
        actor.check_wall_step();
        sent(&mut theirs).await;
        tokio::time::advance(Duration::from_secs(10)).await;

        clock.advance(600_000);
        actor.check_wall_step();
        let woke = tokio::time::Instant::now();
        assert_eq!(pings(&sent(&mut theirs).await), 1, "a PING at the wake");
        // The counters under the names every client uses (owner decision 4 of 2026-11-23).
        let counters = actor.counters();
        assert_eq!(
            (counters.seed_pings, counters.wake_pings, counters.resumes),
            (1, 1, 1)
        );
        assert!(actor.link.is_some(), "kept while the seed may still answer");
        assert_eq!(
            actor.redial_table.position(),
            0,
            "a wake starts the table over"
        );
        assert!(silent.dials().is_empty(), "no redial while linked");

        while events.try_recv().is_ok() {}
        check_at_due(&mut actor).await;
        assert_eq!(tokio::time::Instant::now() - woke, SEED_ANSWER);
        assert!(actor.link.is_none(), "silent for the ping timeout: left");
        assert_eq!(actor.counters.links_silent, 1);
        assert!(theirs.closer.is_closed());
        assert_eq!(events.try_recv().ok(), Some(PeerEvent::Disconnected));
        // Let the redial task make its first dial (no time passes).
        for _ in 0..64 {
            if !silent.dials().is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        let dials = silent.dials();
        assert_eq!(
            dials.first().map(|(at, seed)| (*at, seed.clone())),
            Some((woke + SEED_ANSWER, tcp(7001))),
            "failed over at once to the other seed: {dials:?}"
        );
    }

    /// Moves the wall clock and the monotonic clock together by `by`, a second at a time (no wall
    /// step), and lets the loop run each turn that fell due; answers what the peer sent meanwhile
    /// (read as it goes, so the link's queue never fills).
    async fn pass(
        clock: &crate::clock::ManualClock,
        theirs: &mut Channel,
        by: Duration,
    ) -> Vec<(String, Option<String>, Vec<u8>)> {
        let mut frames = Vec::new();
        let mut left = by;
        while !left.is_zero() {
            let step = left.min(Duration::from_secs(1));
            clock.advance(i64::try_from(step.as_millis()).expect("small"));
            tokio::time::advance(step).await;
            frames.extend(sent(theirs).await);
            left -= step;
        }
        frames
    }

    /// The loop's counters and whether it holds its link, read by a job on the loop.
    async fn on_loop(
        jobs: &tokio::sync::mpsc::Sender<super::super::Job>,
    ) -> (crate::peer::PeerCounters, bool) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let job: super::super::Job = Box::new(move |actor: &mut Actor| {
            let _ = tx.send((actor.counters(), actor.link.is_some()));
        });
        jobs.send(job).await.expect("the loop runs");
        rx.await.expect("answered")
    }

    /// Owner decision 3 of 2026-11-23: a loop wake more than 30 s late with no wall-clock step (a
    /// frozen process: SIGSTOP, a long collection or VM pause, whose monotonic clock counted the
    /// freeze) is a wake. Here the seed was asked with a PING just before the freeze; the loop
    /// wakes 58 s after that PING's answer window ended, before it could read the seed's answer.
    /// The wake asks again with a fresh window (it does not drop a seed whose answer the freeze
    /// kept from being read), re-checks held takes, and the seed's answer keeps the link. Before,
    /// the dead-seed check that fell due during the freeze dropped the link at the first turn.
    #[tokio::test(start_paused = true)]
    async fn a_frozen_process_is_a_wake_it_asks_its_seed_again_and_keeps_a_live_one() {
        let (mut actor, mut theirs, _events, inbound) = linked();
        let silent = std::sync::Arc::new(Silent::default());
        actor.dialers = vec![silent.clone()];
        let clock = crate::clock::ManualClock::new(1_900_000_000_000);
        actor.clock = std::sync::Arc::new(clock.clone());
        let mut wakes = actor.wakes.subscribe();
        let group = actor.group.clone();
        let me = actor.peer_id.clone();
        let (jobs_tx, jobs) = tokio::sync::mpsc::channel::<super::super::Job>(8);
        let loop_task = tokio::spawn(actor.run(jobs, inbound));
        sent(&mut theirs).await;

        // 45 s of quiet: one PING, its answer due 2 s later.
        let frames = pass(&clock, &mut theirs, SEED_QUIET).await;
        assert_eq!(pings(&frames), 1);
        let (counters, linked) = on_loop(&jobs_tx).await;
        assert_eq!(
            (counters.seed_pings, counters.late_wakes, linked),
            (1, 0, true)
        );
        wakes.mark_unchanged();

        // Frozen for 60 s: both clocks move at once, and nothing runs.
        clock.advance(60_000);
        tokio::time::advance(Duration::from_secs(60)).await;
        let frames = sent(&mut theirs).await;
        let (counters, linked) = on_loop(&jobs_tx).await;
        assert!(linked, "the seed is asked again, not dropped");
        assert_eq!(
            (
                counters.late_wakes,
                counters.resumes,
                counters.seed_pings,
                counters.wake_pings,
                counters.links_silent,
                counters.wall_steps
            ),
            (1, 1, 2, 1, 0, 0)
        );
        assert!(
            wakes.has_changed().expect("the loop runs"),
            "held takes re-check"
        );
        assert_eq!(pings(&frames), 1, "a fresh PING at the wake");

        // The seed answers within the fresh window: kept.
        let seed = Identity::generate().expect("identity");
        let stamp = format!(
            "{}:1:{}",
            crate::clock::Clock::now_ms(&clock) + 1,
            seed.peer_id()
        );
        let env = envelope::envelope(
            &group,
            KIND_ACK,
            seed.peer_id(),
            &stamp,
            &bodies::ack_body(1),
            Some(&me),
        );
        theirs
            .sender
            .send(envelope::encode_frame(&env, &seed))
            .await
            .expect("the link is up");
        pass(&clock, &mut theirs, Duration::from_secs(3)).await;
        let (counters, linked) = on_loop(&jobs_tx).await;
        assert!(linked, "the live seed is kept");
        assert_eq!((counters.links_silent, counters.late_wakes), (0, 1));
        assert!(silent.dials().is_empty());
        drop(jobs_tx);
        let _ = loop_task.await;
    }

    /// Owner decision 3 of 2026-11-23, a dial-only peer's view: after a late wake, a member whose
    /// card lapsed only while the peer was frozen is re-probed, not dropped. The peer re-pulls
    /// the view naming only the cards still live, so the seed sends that member's current card,
    /// and until the answer (or 11.25 s) the member stays in the per-entry horizon's view as
    /// lacking the hint. Before, the horizon dropped it at the wake and judged the rest hinted.
    #[tokio::test(start_paused = true)]
    async fn a_frozen_dial_only_peer_re_pulls_the_view_before_it_drops_a_lapsed_card() {
        let (mut actor, mut theirs, _events, _inbound) = linked();
        let t0: i64 = 1_900_000_000_000;
        let clock = crate::clock::ManualClock::new(t0);
        actor.clock = std::sync::Arc::new(clock.clone());
        actor.settings.horizon = true;
        let card = |issued: i64, ttl: &str, hinted: bool| {
            let mut hints = Map::new();
            if hinted {
                hints.insert("wire.horizon", "1");
            }
            let mut ad = Map::new();
            ad.insert("issued", agentspaces_wire::time::instant_iso(issued));
            ad.insert("ttl", ttl);
            ad.insert("resourceHints", Value::Map(hints));
            ad
        };
        // M lacks the hint and its card lapses 10 s from now; N is hinted for ten minutes.
        actor
            .members
            .hold_ad("zMemberM".to_owned(), card(t0 - 50_000, "PT1M", false), t0);
        actor
            .members
            .hold_ad("zMemberN".to_owned(), card(t0, "PT10M", true), t0);
        actor.on_loop_wake(None);
        assert!(!actor.view_hinted(t0), "M lacks the hint");
        sent(&mut theirs).await;

        // Frozen for 120 s: both clocks move at once; the loop wakes 119 s late.
        let armed = tokio::time::Instant::now() + Duration::from_secs(1);
        clock.advance(120_000);
        tokio::time::advance(Duration::from_secs(120)).await;
        actor.on_loop_wake(Some(armed));
        let now = actor.now();
        assert!(
            !actor.view_hinted(now),
            "M lapsed only while frozen: still in view, as lacking the hint"
        );
        assert_eq!(
            (actor.counters.late_wakes, actor.counters.view_reprobes),
            (1, 1)
        );
        let views: Vec<Vec<String>> = sent(&mut theirs)
            .await
            .into_iter()
            .filter(|(kind, ..)| kind == KIND_DIGEST)
            .filter_map(|(_, _, body)| agentspaces_wire::audit::parse_digest(&body).ok())
            .flat_map(|digest| digest.digests.unwrap_or_default())
            .filter(|(stream, _)| stream == "view")
            .map(|(_, lines)| {
                agentspaces_wire::serving::digest_lines(&lines)
                    .into_iter()
                    .map(|line| String::from_utf8_lossy(line).into_owned())
                    .collect()
            })
            .collect();
        assert_eq!(views.len(), 1, "one view pull to the seed: {views:?}");
        assert!(
            views[0].contains(&"zMemberN".to_owned()),
            "the live card is named"
        );
        assert!(
            !views[0].contains(&"zMemberM".to_owned()),
            "the lapsed card is not, so the seed sends its current one"
        );

        // No answer: the re-probe ends after 11.25 s, and the lapsed card is out.
        clock.advance(11_250);
        tokio::time::advance(Duration::from_millis(11_250)).await;
        let now = actor.now();
        assert!(actor.view_hinted(now), "M is out: the rest are hinted");
    }

    /// Owner decision 5 of 2026-11-23: the dead-link rule holds for every link dialed to a
    /// seed, a listening peer's included (a hub that also dials its own seed): 45 s of quiet asks
    /// with one PING, and 2 s more of silence drops the link and redials another seed.
    #[tokio::test(start_paused = true)]
    async fn a_listening_peers_dialed_seed_link_follows_the_dead_link_rule() {
        let (mut actor, mut theirs, _events, _inbound) = linked();
        actor.hub.listening = true;
        let silent = std::sync::Arc::new(Silent::default());
        actor.dialers = vec![silent.clone()];
        let start = tokio::time::Instant::now();
        sent(&mut theirs).await;
        assert_eq!(actor.seed_check_at(), Some(start + SEED_QUIET));
        check_at_due(&mut actor).await;
        assert_eq!(pings(&sent(&mut theirs).await), 1);
        check_at_due(&mut actor).await;
        assert_eq!(
            tokio::time::Instant::now() - start,
            SEED_QUIET + SEED_ANSWER
        );
        assert!(actor.link.is_none(), "silent past the answer window: left");
        assert_eq!(actor.counters.links_silent, 1);
        for _ in 0..64 {
            if !silent.dials().is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            silent.dials().first().map(|(_, seed)| seed.clone()),
            Some(tcp(7001)),
            "another seed first"
        );
    }

    /// A wake's PING left unanswered fails over at once even when the link is young on the
    /// monotonic clock (which does not count the sleep): the wake already started the table over,
    /// so its verdict is no quick drop (owner decision 3 of 2026-11-23, as TypeScript and Ruby).
    #[tokio::test(start_paused = true)]
    async fn a_wake_fails_over_at_once_even_from_a_young_link() {
        let (mut actor, mut theirs, _events, _inbound) = linked();
        let silent = std::sync::Arc::new(Silent::default());
        actor.dialers = vec![silent.clone()];
        actor.settings.reconnect_interval = Duration::from_secs(5);
        let clock = crate::clock::ManualClock::new(1_900_000_000_000);
        actor.clock = std::sync::Arc::new(clock.clone());
        actor.check_wall_step();
        sent(&mut theirs).await;
        tokio::time::advance(Duration::from_secs(1)).await;

        clock.advance(600_000);
        actor.check_wall_step();
        let woke = tokio::time::Instant::now();
        assert_eq!(pings(&sent(&mut theirs).await), 1, "a PING at the wake");
        check_at_due(&mut actor).await;
        assert_eq!(tokio::time::Instant::now() - woke, SEED_ANSWER);
        assert!(actor.link.is_none(), "silent for the ping timeout: left");
        for _ in 0..64 {
            if !silent.dials().is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            silent.dials().first().map(|(at, seed)| (*at, seed.clone())),
            Some((woke + SEED_ANSWER, tcp(7001))),
            "a 3 s link the wake's verdict closed fails over at once"
        );
        assert_eq!(actor.redial_table.position(), 0, "no step taken");
    }

    /// A wake that finds a PING already waiting sends no second one; that PING becomes the wake's,
    /// and its verdict fails over at once.
    #[tokio::test(start_paused = true)]
    async fn a_wake_with_a_ping_waiting_adopts_it() {
        let (mut actor, mut theirs, _events, _inbound) = linked();
        let silent = std::sync::Arc::new(Silent::default());
        actor.dialers = vec![silent.clone()];
        actor.settings.reconnect_interval = Duration::from_secs(5);
        let clock = crate::clock::ManualClock::new(1_900_000_000_000);
        actor.clock = std::sync::Arc::new(clock.clone());
        actor.check_wall_step();
        sent(&mut theirs).await;
        tokio::time::advance(Duration::from_secs(1)).await;
        actor.ask_seed();
        let asked = tokio::time::Instant::now();
        assert_eq!(pings(&sent(&mut theirs).await), 1);
        tokio::time::advance(Duration::from_millis(500)).await;
        clock.advance(600_000);
        actor.check_wall_step();
        assert_eq!(
            pings(&sent(&mut theirs).await),
            0,
            "the PING waiting is not sent again"
        );
        assert_eq!(
            (actor.counters.seed_pings, actor.counters.wake_pings),
            (1, 0),
            "no wake PING counted when none was sent"
        );
        check_at_due(&mut actor).await;
        assert_eq!(tokio::time::Instant::now() - asked, SEED_ANSWER);
        assert!(actor.link.is_none());
        for _ in 0..64 {
            if !silent.dials().is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            silent.dials().first().map(|(at, _)| *at),
            Some(asked + SEED_ANSWER),
            "the wake's verdict fails over at once"
        );
    }

    /// The next dial the redial reports (the lost link's own end is passed over).
    async fn next_dial(inbound: &mut tokio::sync::mpsc::Receiver<Inbound>) -> Inbound {
        loop {
            let message = inbound.recv().await.expect("a dial");
            if matches!(message, Inbound::Dialed { .. }) {
                return message;
            }
        }
    }

    /// A laptop that wakes while the peer waits out a reconnect pause dials at once rather than
    /// sitting out what is left of the pause.
    #[tokio::test(start_paused = true)]
    async fn a_wake_during_a_reconnect_pause_redials_at_once() {
        let network = memory::MemoryNetwork::new();
        let (mut actor, _events, mut inbound, _link) = test_actor();
        actor.dialers = vec![std::sync::Arc::new(network.dialer())];
        actor.settings.reconnect_interval = Duration::from_secs(5);
        let seed = Seed::new("127.0.0.1", 7000, "tcp");
        actor.seeds = vec![seed.clone()];
        let clock = crate::clock::ManualClock::new(1_900_000_000_000);
        actor.clock = std::sync::Arc::new(clock.clone());
        actor.check_wall_step();
        // The seed is gone: the link was lost at once after it came up (a quick drop), so the
        // redial pauses the table's first step (5 s) before its first round.
        let (mine, theirs) = memory::pair("mem", "seed", "peer", None, None);
        actor.install_link(mine, seed.clone());
        drop(theirs);
        actor.lose_link();
        assert!(actor.redial.is_some());
        // The host sleeps; on wake the seed is back.
        tokio::time::advance(Duration::from_millis(100)).await;
        let listener = network.listen("127.0.0.1:7000");
        let accepted = tokio::spawn(async move { listener.accept().await });
        clock.advance(600_000);
        let woke = tokio::time::Instant::now();
        actor.check_wall_step();
        assert_eq!(actor.counters.resumes, 1);
        let message = next_dial(&mut inbound).await;
        assert!(
            tokio::time::Instant::now().duration_since(woke) < Duration::from_secs(1),
            "dialed at once, not after the 5 s pause"
        );
        actor.on_inbound(message);
        assert!(actor.link.is_some(), "linked again");
        assert!(accepted.await.expect("accept task").is_some());
    }

    /// Without a wake the pause is sat out, as before (the control for the test above).
    #[tokio::test(start_paused = true)]
    async fn without_a_wake_the_reconnect_pause_is_kept() {
        let network = memory::MemoryNetwork::new();
        let (mut actor, _events, mut inbound, _link) = test_actor();
        actor.dialers = vec![std::sync::Arc::new(network.dialer())];
        actor.settings.reconnect_interval = Duration::from_secs(5);
        let seed = Seed::new("127.0.0.1", 7000, "tcp");
        actor.seeds = vec![seed.clone()];
        let (mine, theirs) = memory::pair("mem", "seed", "peer", None, None);
        actor.install_link(mine, seed.clone());
        drop(theirs);
        let lost = tokio::time::Instant::now();
        actor.lose_link();
        let listener = network.listen("127.0.0.1:7000");
        let _accepted = tokio::spawn(async move { listener.accept().await });
        next_dial(&mut inbound).await;
        assert!(
            tokio::time::Instant::now().duration_since(lost) >= Duration::from_millis(4_500),
            "the pause (the table's first step, 5 s less at most its 10 % spread) was kept"
        );
    }

    /// A dial-only peer answers its seed's DIGEST: an own write whose rumor was lost on the only
    /// link reaches the seed in the answer, so the seed's replica is repaired through it.
    #[tokio::test(start_paused = true)]
    async fn a_dial_only_peer_answers_its_seeds_digest_and_repairs_a_lost_own_rumor() {
        let (mut actor, mut theirs, _events, mut inbound) = linked();
        assert!(!actor.hub.listening, "dial-only");
        let seed = Identity::generate().expect("identity");
        actor.space_open("tasks").expect("open");
        let entry = actor
            .write_entry(
                "tasks",
                "T#v1",
                &Value::from("work"),
                120_000,
                &Map::new(),
                None,
            )
            .expect("write");
        // The write's rumor is lost in transit: the seed never reads it.
        let lost = sent(&mut theirs).await;
        assert!(
            lost.iter().any(|(kind, ..)| kind == bodies::KIND_RUMOR),
            "{lost:?}"
        );

        // The seed's anti-entropy round: its digest of the space, which holds nothing.
        let mut digests = Map::new();
        digests.insert("space:tasks", Value::Bytes(Vec::new()));
        let answers: Vec<_> = seed_says(
            &mut actor,
            &mut theirs,
            &mut inbound,
            &seed,
            KIND_DIGEST,
            &bodies::digest_body(&digests),
        )
        .await
        .into_iter()
        .filter(|(kind, ..)| kind == KIND_PULL_RESP)
        .collect();
        assert_eq!(answers.len(), 1, "answered");
        assert_eq!(answers[0].1.as_deref(), Some(seed.peer_id()), "to the seed");
        let deltas = bodies::parse_pull_resp(&answers[0].2).expect("a PULL_RESP body");
        let delta = deltas
            .get("space:tasks")
            .and_then(Value::as_bytes)
            .expect("the space's delta");
        let sync = records::decode_sync_delta(delta).expect("a sync delta");
        // The seed folds the answer as it folds any pulled delta: its replica holds the write.
        let registry = Registry::new(None, Some(actor.group.clone()));
        let space_id = ids::space_id_local(&format!("{}/tasks", actor.group));
        let ctx = FoldContext::new(actor.now(), &registry).with_space(&space_id);
        let mut replica = SpaceStore::default();
        for state in &sync.states {
            replica.fold_state(state, &ctx);
        }
        assert!(
            replica.state(&entry).is_some(),
            "the lost write is repaired at the seed"
        );

        // A digest that already names the write draws nothing.
        let held = actor.stream_digest("space:tasks").expect("digest");
        let mut digests = Map::new();
        digests.insert("space:tasks", Value::Bytes(held));
        tokio::time::advance(Duration::from_secs(1)).await;
        let again = seed_says(
            &mut actor,
            &mut theirs,
            &mut inbound,
            &seed,
            KIND_DIGEST,
            &bodies::digest_body(&digests),
        )
        .await;
        assert!(
            !again.iter().any(|(kind, ..)| kind == KIND_PULL_RESP),
            "{again:?}"
        );
        assert_eq!(
            actor.filter.replayed(),
            0,
            "handled, not dropped as a replay"
        );
    }

    /// Bytes of a frame still arriving at the end of the answer window are an answer: the seed is
    /// writing a large frame over a slow link, and is kept (Python's `_bytes_at`). Without them,
    /// the same silence drops the link.
    #[tokio::test(start_paused = true)]
    async fn bytes_of_a_frame_still_arriving_answer_the_ping() {
        use tokio::io::AsyncWriteExt;

        let (mut actor, _events, _inbound, _link) = test_actor();
        actor.seeds = vec![Seed::new("127.0.0.1", 7000, "tcp")];
        let (mine, mut raw) = tokio::io::duplex(1 << 16);
        let channel = crate::transport::stream::spawn_stream_channel(mine, "tcp", "seed", None);
        actor.install_link(channel, Seed::new("127.0.0.1", 7000, "tcp"));
        check_at_due(&mut actor).await;
        assert_eq!(actor.counters.seed_pings, 1, "asked");
        // The seed begins a 1 MiB frame and has written part of it when the window ends.
        raw.write_all(&(1u32 << 20).to_be_bytes())
            .await
            .expect("prefix");
        raw.write_all(&[0u8; 4096]).await.expect("part");
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
        check_at_due(&mut actor).await;
        assert!(actor.link.is_some(), "a seed still writing is kept");
        assert_eq!(actor.counters.links_silent, 0);
        let kept = tokio::time::Instant::now();
        assert_eq!(
            actor.seed_check_at(),
            Some(kept + SEED_QUIET),
            "the quiet wait starts again"
        );
        // Then nothing more: asked again at 45 s, and left 2 s later.
        check_at_due(&mut actor).await;
        assert_eq!(actor.counters.seed_pings, 2);
        check_at_due(&mut actor).await;
        assert!(actor.link.is_none(), "silent again: left");
        assert_eq!(actor.counters.links_silent, 1);
        drop(raw);
    }

    /// A dial-only peer that holds no displaced claim or completion answers only its seed's own
    /// DIGEST: one a relay carried (owner decision 1 of 2026-11-23 answers it only with such
    /// entries), or a member's copy forwarded on the link, draws no answer and is ignored and
    /// counted as before, so no member but the seed can make it upload.
    #[tokio::test(start_paused = true)]
    async fn a_dial_only_peer_answers_no_digest_but_its_seeds_own() {
        let (mut actor, mut theirs, _events, mut inbound) = linked();
        let seed = Identity::generate().expect("identity");
        let other = Identity::generate().expect("identity");
        actor.space_open("tasks").expect("open");
        actor
            .write_entry(
                "tasks",
                "T#v1",
                &Value::from("work"),
                120_000,
                &Map::new(),
                None,
            )
            .expect("write");
        // The seed names itself first (an addressed PING).
        seed_says(
            &mut actor,
            &mut theirs,
            &mut inbound,
            &seed,
            KIND_PING,
            &bodies::ping_body(1),
        )
        .await;
        assert_eq!(actor.seed_peer().as_deref(), Some(seed.peer_id()));
        let mut digests = Map::new();
        digests.insert("space:tasks", Value::Bytes(Vec::new()));
        let digest = bodies::digest_body(&digests);
        // Each frame under its own stamp (a replayed stamp is dropped before any handling).
        let frame = |from: &Identity, to: Option<&str>, logical: u32| {
            let stamp = format!(
                "{}:{logical}:{}",
                actor.now().saturating_add(1),
                from.peer_id()
            );
            let env = envelope::envelope(
                &actor.group,
                KIND_DIGEST,
                from.peer_id(),
                &stamp,
                &digest,
                to,
            );
            envelope::encode_frame(&env, from)
        };
        let me = actor.peer_id.clone();
        // Another member's DIGEST, relayed to this peer through the seed.
        let inner = frame(&other, Some(&me), 1);
        let relay = bodies::relay_frame_body(&me, &inner, None, None);
        let relayed = {
            let stamp = format!("{}:3:{}", actor.now().saturating_add(1), seed.peer_id());
            let env = envelope::envelope(
                &actor.group,
                bodies::KIND_RELAY_FRAME,
                seed.peer_id(),
                &stamp,
                &relay,
                Some(&me),
            );
            envelope::encode_frame(&env, &seed)
        };
        // Another member's DIGEST forwarded on the link unaddressed.
        let forwarded = frame(&other, None, 2);
        for bytes in [relayed, forwarded] {
            theirs.sender.send(bytes).await.expect("the link is up");
            let message = inbound.recv().await.expect("the reader forwards the frame");
            actor.on_inbound(message);
        }
        let frames = sent(&mut theirs).await;
        assert!(
            !frames.iter().any(|(kind, ..)| kind == KIND_PULL_RESP),
            "{frames:?}"
        );
        assert_eq!(actor.counters.ignored_kinds.get(KIND_DIGEST), Some(&2));
        assert_eq!(actor.filter.replayed(), 0);
        // The seed's own round is answered.
        let answered = seed_says(
            &mut actor,
            &mut theirs,
            &mut inbound,
            &seed,
            KIND_DIGEST,
            &digest,
        )
        .await;
        assert!(
            answered.iter().any(|(kind, ..)| kind == KIND_PULL_RESP),
            "{answered:?}"
        );
        assert_eq!(actor.filter.replayed(), 0);
    }

    // ----------------------------------------------------------------- the redial table

    /// A dialer that refuses every dial at once and records when each came (paused time).
    #[derive(Debug, Default)]
    struct Refusals(std::sync::Mutex<Vec<tokio::time::Instant>>);

    impl crate::transport::Dialer for Refusals {
        fn schemes(&self) -> &[&'static str] {
            &["tcp"]
        }

        fn dial<'a>(
            &'a self,
            _seed: &'a Seed,
            _identity: &'a Identity,
            _timeout: Duration,
        ) -> crate::transport::BoxFuture<'a, Result<Channel, crate::transport::TransportError>>
        {
            self.0
                .lock()
                .expect("not poisoned")
                .push(tokio::time::Instant::now());
            Box::pin(async { Err(crate::transport::TransportError::Closed) })
        }
    }

    impl Refusals {
        fn times(&self) -> Vec<tokio::time::Instant> {
            self.0.lock().expect("not poisoned").clone()
        }
    }

    /// An actor whose one seed refuses every dial, redialing on a 5 s interval for an hour.
    fn refused() -> (
        Actor,
        std::sync::Arc<Refusals>,
        tokio::sync::mpsc::Receiver<Inbound>,
    ) {
        let (mut actor, _events, inbound, _link) = test_actor();
        let refusals = std::sync::Arc::new(Refusals::default());
        actor.dialers = vec![refusals.clone()];
        actor.settings.reconnect_interval = Duration::from_secs(5);
        actor.settings.reconnect_window = Duration::from_secs(3600);
        actor.seeds = vec![Seed::new("127.0.0.1", 7000, "tcp")];
        (actor, refusals, inbound)
    }

    /// Installs a link to the seed and loses it at once.
    fn link_and_lose(actor: &mut Actor) {
        let (mine, theirs) = memory::pair("mem", "seed", "peer", None, None);
        actor.install_link(mine, Seed::new("127.0.0.1", 7000, "tcp"));
        drop(theirs);
        actor.lose_link();
    }

    /// Whether `gap` is `step` seconds spread by at most ±10 %.
    fn within_spread(gap: Duration, step: u64) -> bool {
        let step = Duration::from_secs(step);
        gap >= step * 9 / 10 && gap < step * 11 / 10
    }

    /// After a link is lost at once (a quick drop), the redials wait 5, 10, 20, 30 s, then 5 s
    /// again (each spread by at most ±10 %): the fixed cycling table, not a fixed interval.
    #[tokio::test(start_paused = true)]
    async fn the_redial_rounds_follow_the_cycling_table() {
        let (mut actor, refusals, _inbound) = refused();
        let lost = tokio::time::Instant::now();
        link_and_lose(&mut actor);
        tokio::time::sleep(Duration::from_secs(200)).await;
        let times = refusals.times();
        assert!(times.len() >= 10, "{} dials", times.len());
        let first = times[0].duration_since(lost);
        assert!(within_spread(first, 5), "the first round: {first:?}");
        let gaps: Vec<Duration> = times.windows(2).map(|pair| pair[1] - pair[0]).collect();
        for (round, step) in [10, 20, 30, 5, 10, 20, 30, 5].into_iter().enumerate() {
            assert!(
                within_spread(gaps[round], step),
                "round {round}: {:?} is not {step} s ±10 %: {gaps:?}",
                gaps[round]
            );
        }
    }

    /// Installs a link to the seed that carries nothing, keeps it `held`, then loses it.
    async fn hold_then_lose(actor: &mut Actor, held: Duration) -> tokio::time::Instant {
        let (mine, theirs) = memory::pair("mem", "seed", "peer", None, None);
        actor.install_link(mine, Seed::new("127.0.0.1", 7000, "tcp"));
        tokio::time::advance(held).await;
        drop(theirs);
        let lost = tokio::time::Instant::now();
        actor.lose_link();
        lost
    }

    /// A link that ends after 4 s, short of the 5 s hold, is a quick drop: it counts as a failed
    /// round, and the redial waits the table's next step (here the third, 20 s), not at once.
    #[tokio::test(start_paused = true)]
    async fn a_4_s_link_waits_the_next_step() {
        let (mut actor, refusals, _inbound) = refused();
        actor.outage_since = Some(tokio::time::Instant::now());
        for _ in 0..2 {
            actor.redial_table.next_wait(Duration::from_secs(5));
        }
        let lost = hold_then_lose(&mut actor, Duration::from_secs(4)).await;
        assert_eq!(actor.redial_table.position(), 3, "the table walked on");
        tokio::time::sleep(Duration::from_secs(30)).await;
        let first = refusals.times()[0].duration_since(lost);
        assert!(within_spread(first, 20), "{first:?}");
    }

    /// A link that ends after 6 s held past the 5 s hold, whatever it carried (here not one
    /// frame): it starts the table over and is redialed at once, and the round after waits the
    /// first step (5 s), not the 30 s the table had reached.
    #[tokio::test(start_paused = true)]
    async fn a_6_s_link_resets_the_table_and_is_redialed_at_once() {
        let (mut actor, refusals, _inbound) = refused();
        actor.outage_since = Some(tokio::time::Instant::now());
        for _ in 0..3 {
            actor.redial_table.next_wait(Duration::from_secs(5));
        }
        let lost = hold_then_lose(&mut actor, Duration::from_secs(6)).await;
        tokio::time::sleep(Duration::from_secs(8)).await;
        let times = refusals.times();
        assert_eq!(times.len(), 2, "{times:?}");
        assert_eq!(times[0], lost, "redialed at once");
        assert!(
            within_spread(times[1] - times[0], 5),
            "the table started over: {:?}",
            times[1] - times[0]
        );
    }

    /// A dialer whose seeds never answer (a black-holed SYN) and which records which seed each
    /// dial went to and when (paused time).
    #[derive(Debug, Default)]
    struct Silent(std::sync::Mutex<Vec<(tokio::time::Instant, Seed)>>);

    impl crate::transport::Dialer for Silent {
        fn schemes(&self) -> &[&'static str] {
            &["tcp"]
        }

        fn dial<'a>(
            &'a self,
            seed: &'a Seed,
            _identity: &'a Identity,
            _timeout: Duration,
        ) -> crate::transport::BoxFuture<'a, Result<Channel, crate::transport::TransportError>>
        {
            self.0
                .lock()
                .expect("not poisoned")
                .push((tokio::time::Instant::now(), seed.clone()));
            Box::pin(std::future::pending())
        }
    }

    impl Silent {
        fn dials(&self) -> Vec<(tokio::time::Instant, Seed)> {
            self.0.lock().expect("not poisoned").clone()
        }
    }

    fn tcp(port: u16) -> Seed {
        Seed::new("127.0.0.1", port, "tcp")
    }

    /// The redial after a lost link starts the seeds in list order, 250 ms apart, with the seed
    /// just lost last: linked to the middle seed of three, the order is the first, the third,
    /// then the middle one.
    #[tokio::test(start_paused = true)]
    async fn the_lost_seed_is_tried_last() {
        let (mut actor, _events, _inbound, _link) = test_actor();
        let silent = std::sync::Arc::new(Silent::default());
        actor.dialers = vec![silent.clone()];
        actor.settings.reconnect_interval = Duration::from_secs(5);
        actor.seeds = vec![tcp(7000), tcp(7001), tcp(7002)];
        let (mine, theirs) = memory::pair("mem", "seed", "peer", None, None);
        actor.install_link(mine, tcp(7001));
        assert_eq!(actor.candidate_seeds(), [tcp(7000), tcp(7002), tcp(7001)]);
        tokio::time::advance(Duration::from_secs(6)).await;
        drop(theirs);
        let lost = tokio::time::Instant::now();
        actor.lose_link();
        tokio::time::sleep(Duration::from_millis(600)).await;
        let dials = silent.dials();
        let order: Vec<Seed> = dials.iter().map(|(_, seed)| seed.clone()).collect();
        assert_eq!(order, [tcp(7000), tcp(7002), tcp(7001)]);
        let offsets: Vec<Duration> = dials.iter().map(|(at, _)| *at - lost).collect();
        assert_eq!(
            offsets,
            [0, 250, 500].map(Duration::from_millis),
            "a 250 ms stagger"
        );
    }

    /// The first verified frame on a new link ends the outage (a later loss starts a new
    /// reconnect window), but keeps the table's position: the table starts over only when a link
    /// that held is lost (`a_seed_that_speaks_then_drops_each_link_climbs_the_table`).
    #[tokio::test(start_paused = true)]
    async fn a_verified_frame_ends_the_outage_and_keeps_the_table() {
        let (mut actor, mut theirs, _events, mut inbound) = linked();
        // The link came after an outage of three failed rounds.
        actor.outage_since = Some(tokio::time::Instant::now());
        for _ in 0..3 {
            actor.redial_table.next_wait(Duration::from_secs(5));
        }
        assert_eq!(actor.redial_table.position(), 3);
        let seed = Identity::generate().expect("identity");
        seed_says(
            &mut actor,
            &mut theirs,
            &mut inbound,
            &seed,
            KIND_PING,
            &bodies::ping_body(1),
        )
        .await;
        assert_eq!(
            actor.redial_table.position(),
            3,
            "not yet: the link has not held"
        );
        assert_eq!(actor.outage_since, None);
    }

    /// Links a seed, has it send one verified frame, keeps the link `held`, then loses it; the
    /// redial that the loss starts is left running only when `keep` (else aborted, so its dials do
    /// not cross the next link).
    async fn speak_then_lose(
        actor: &mut Actor,
        inbound: &mut tokio::sync::mpsc::Receiver<Inbound>,
        seed: &Identity,
        held: Duration,
        keep: bool,
    ) -> tokio::time::Instant {
        let (mine, mut theirs) = memory::pair("mem", "seed", "peer", None, None);
        actor.install_link(mine, Seed::new("127.0.0.1", 7000, "tcp"));
        seed_says(
            actor,
            &mut theirs,
            inbound,
            seed,
            KIND_PING,
            &bodies::ping_body(1),
        )
        .await;
        tokio::time::advance(held).await;
        let lost = tokio::time::Instant::now();
        actor.lose_link();
        // The closed link's reader says so on the shared queue: take that here, so the next
        // link's frame is the next message (else it would read the stale loss instead).
        let ended = inbound.recv().await.expect("the reader reports the loss");
        assert!(matches!(ended, Inbound::Lost { .. }));
        if !keep && let Some(redial) = actor.redial.take() {
            redial.task.abort();
        }
        lost
    }

    /// A seed that speaks and then drops each link within the interval (an overloaded seed
    /// shedding its links) climbs the table as a refusal does, as the quick drop of the TypeScript
    /// and Python clients does: a verified frame alone does not start the table over, or such a
    /// seed would be redialed every 5 s for ever. Only a link that held past the interval starts
    /// it over, and is redialed at once.
    #[tokio::test(start_paused = true)]
    async fn a_seed_that_speaks_then_drops_each_link_climbs_the_table() {
        let (mut actor, refusals, mut inbound) = refused();
        let seed = Identity::generate().expect("identity");
        let quick = Duration::from_secs(1);
        for position in 1..=2 {
            speak_then_lose(&mut actor, &mut inbound, &seed, quick, false).await;
            assert_eq!(
                actor.redial_table.position(),
                position,
                "a quick drop walks the table"
            );
        }
        // The third quick drop waits the third step (20 s), not an interval since the link came up.
        let lost = speak_then_lose(&mut actor, &mut inbound, &seed, quick, true).await;
        tokio::time::sleep(Duration::from_secs(25)).await;
        let first = refusals.times()[0].duration_since(lost);
        assert!(within_spread(first, 20), "{first:?}");
        if let Some(redial) = actor.redial.take() {
            redial.task.abort();
        }

        // One more quick drop leaves the table at its second step (10 s).
        speak_then_lose(&mut actor, &mut inbound, &seed, quick, false).await;
        assert_eq!(actor.redial_table.position(), 1);
        // A link that held past the interval starts the table over and is redialed at once; the
        // round after that waits the first step (5 s), not the 10 s the table had reached.
        let before = refusals.times().len();
        let lost = speak_then_lose(
            &mut actor,
            &mut inbound,
            &seed,
            Duration::from_secs(6),
            true,
        )
        .await;
        tokio::time::sleep(Duration::from_secs(8)).await;
        let times = refusals.times();
        assert_eq!(times.len(), before + 2, "{times:?}");
        assert_eq!(times[before], lost, "redialed at once");
        let gap = times[before + 1] - times[before];
        assert!(within_spread(gap, 5), "the table started over: {gap:?}");
    }

    /// A wake from a suspend redials at once and starts the table over: the round after it waits
    /// 5 s, not the 30 s step the table had reached.
    #[tokio::test(start_paused = true)]
    async fn a_wake_redials_at_once_and_resets_the_table() {
        let (mut actor, refusals, _inbound) = refused();
        let clock = crate::clock::ManualClock::new(1_900_000_000_000);
        actor.clock = std::sync::Arc::new(clock.clone());
        actor.check_wall_step();
        link_and_lose(&mut actor);
        // Rounds at ~5 s and ~15 s: the wait now running is the 20 s step.
        tokio::time::sleep(Duration::from_secs(20)).await;
        assert_eq!(refusals.times().len(), 2);
        assert_eq!(actor.redial_table.position(), 3);

        clock.advance(600_000);
        let woke = tokio::time::Instant::now();
        actor.check_wall_step();
        assert_eq!(actor.counters.resumes, 1);
        tokio::time::sleep(Duration::from_secs(10)).await;
        let times = refusals.times();
        assert_eq!(times.len(), 4, "a dial at the wake and one 5 s later");
        assert_eq!(times[2], woke, "dialed at once");
        let gap = times[3] - times[2];
        assert!(within_spread(gap, 5), "the table started over: {gap:?}");
    }

    /// Owner decision 3 of 2026-11-23: a peer never gives up redialing. Its 10-minute reconnect
    /// window ends nothing: the peer says it is unreachable once per window (and answers a join
    /// waiting for its seed) and goes on dialing on its table; a wake after an outage of hours
    /// still redials at once. Before, the window's end was `GaveUp`: no dial after it, and a
    /// wake found no redial to bring forward.
    #[tokio::test(start_paused = true)]
    async fn the_redial_goes_on_past_the_window_and_a_wake_after_it_redials() {
        let (mut actor, refusals, mut inbound) = refused();
        actor.settings.reconnect_window = Duration::from_secs(600);
        let mut events = actor.events.subscribe();
        let clock = crate::clock::ManualClock::new(1_900_000_000_000);
        actor.clock = std::sync::Arc::new(clock.clone());
        actor.check_wall_step();
        let lost = tokio::time::Instant::now();
        link_and_lose(&mut actor);

        // Two windows pass: each lapse is told to the loop, which says so and redials on.
        let mut lapsed = 0;
        while lapsed < 2 {
            let message = tokio::time::timeout(Duration::from_secs(700), inbound.recv())
                .await
                .ok()
                .flatten()
                .expect("the redial goes on past the window");
            if matches!(message, Inbound::WindowLapsed { .. }) {
                lapsed += 1;
                let at = tokio::time::Instant::now() - lost;
                assert!(
                    at >= Duration::from_secs(600 * lapsed)
                        && at < Duration::from_secs(600 * lapsed + 40),
                    "window {lapsed} lapsed at {at:?}"
                );
            }
            actor.on_inbound(message);
        }
        assert!(actor.redial.is_some(), "still redialing");
        assert_eq!(actor.counters.windows_lapsed, 2);
        let told: Vec<PeerEvent> = std::iter::from_fn(|| events.try_recv().ok())
            .filter(|event| *event == PeerEvent::Unreachable)
            .collect();
        assert_eq!(told.len(), 2, "said once per window");
        let times = refusals.times();
        let late = times
            .iter()
            .filter(|at| at.duration_since(lost) > Duration::from_secs(600))
            .count();
        assert!(
            late >= 20,
            "{late} dials after the first window: it redials on"
        );

        // A wake after hours of outage (the host slept) dials at once.
        tokio::time::sleep(Duration::from_secs(3)).await;
        let before = refusals.times().len();
        clock.advance(4 * 3_600_000);
        let woke = tokio::time::Instant::now();
        actor.check_wall_step();
        tokio::task::yield_now().await;
        for _ in 0..64 {
            if refusals.times().len() > before {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            refusals.times().get(before).copied(),
            Some(woke),
            "the wake dials at once"
        );
    }
}
