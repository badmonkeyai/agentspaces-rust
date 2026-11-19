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

//! The periodic rounds of a dial-only peer (SPEC §5.3, the idle floor).
//!
//! A listening peer runs its rounds from the listening role's tick ([`serve`](super::serve)). A
//! dial-only peer holds one link, to its seed, and answers no `DIGEST`; it reconciles what it
//! pulled by rounds of its own toward the seed, so a rumor it missed arrives by the next round
//! rather than by the next reconnect.
//!
//! # When
//!
//! The rounds are armed once the link is ready: the pulls sent then are the first round, and the
//! next follows one jittered period later. Those pulls name every stream pulled with an empty
//! digest (send everything) and are packed as a round is ([`Actor::link_ready_pulls`]). They stop while there is no link, while a join waits
//! for its founding, and once the peer closes, and never run on a listening peer. The base period
//! is the listening role's ([`ListenConfig::anti_entropy_period`] when set, else the founding's
//! gossip period). After a round in which nothing counted as activity the period doubles, up to
//! 32 times the base; the next activity brings it back to the base. A round always runs, however
//! long the peer has been idle.
//!
//! # What counts as activity
//!
//! A space write, take, renewal, or release this peer published; a state or claim folded from a
//! rumor or a pulled delta that changed the space; a revocation this peer did not hold before.
//! The `peers` stream, advertisements, and anything refused or already held never count.
//!
//! # One round
//!
//! One reconciliation of every stream the peer pulled (both revocation streams, the
//! advertisements once pulled, each pulled space), each with this peer's own text digest, so the
//! seed answers only what is missing. The streams are packed as a listening peer packs its round
//! ([`pack_digests`]): a few dozen spaces fit one `DIGEST`, which spends one of the seed's paced
//! answers. Toward a seed whose card carries `wire.ae=2` the bodies carry this peer's budget, and
//! an answer cut short by it continues as every budgeted pull does.
//!
//! [`ListenConfig::anti_entropy_period`]: crate::peer::ListenConfig::anti_entropy_period

use std::time::Duration;

use agentspaces_wire::audit::DigestBody;
use agentspaces_wire::bodies::{KIND_DIGEST, STREAM_ADS, STREAM_SPACE_PREFIX};
use agentspaces_wire::revocation;
use tokio::time::Instant;

use super::Actor;
use super::serve::{jittered, next_period, pack_digests};

/// The state of a dial-only peer's periodic rounds ([module docs](self)).
#[derive(Debug)]
pub(in crate::peer) struct DialRounds {
    /// The base period, read when the rounds were armed.
    base: Duration,
    /// The period of the next round.
    period: Duration,
    /// When the next round runs; `None` while disarmed.
    next: Option<Instant>,
    /// Whether anything counted as activity since the last round.
    active: bool,
    /// The rounds run.
    rounds: u64,
}

impl Default for DialRounds {
    fn default() -> Self {
        Self {
            base: Duration::from_secs(1),
            period: Duration::from_secs(1),
            next: None,
            active: false,
            rounds: 0,
        }
    }
}

impl DialRounds {
    /// When the next round is due, if the rounds are armed.
    pub fn due(&self) -> Option<Instant> {
        self.next
    }

    /// Notes something that counts as activity ([module docs](self#what-counts-as-activity)).
    pub fn note_activity(&mut self) {
        self.active = true;
    }

    /// The rounds run so far.
    pub fn rounds(&self) -> u64 {
        self.rounds
    }

    /// The period of the next round, in milliseconds.
    pub fn period_millis(&self) -> u64 {
        u64::try_from(self.period.as_millis()).unwrap_or(u64::MAX)
    }
}

impl Actor {
    /// Whether this peer runs dial-only rounds now: it does not listen, holds a ready link, and
    /// is open.
    fn dial_rounds_apply(&self) -> bool {
        !self.closed && !self.hub.listening && !self.joining && self.link.is_some()
    }

    /// Arms the rounds after the link became ready (its pulls were the first round): the base
    /// period read afresh, the period back at it, the next round one jittered period from now.
    pub(super) fn arm_dial_rounds(&mut self) {
        if !self.dial_rounds_apply() {
            self.disarm_dial_rounds();
            return;
        }
        let base = self.gossip_period();
        let rounds = &mut self.dial_rounds;
        rounds.base = base;
        rounds.period = base;
        rounds.active = false;
        rounds.next = Some(Instant::now() + jittered(base));
    }

    /// Stops the rounds until the link is ready again.
    pub(super) fn disarm_dial_rounds(&mut self) {
        self.dial_rounds.next = None;
    }

    /// A round is due: run it, then set the next by the activity since the last one.
    pub(super) fn on_dial_round(&mut self) {
        if !self.dial_rounds_apply() {
            self.disarm_dial_rounds();
            return;
        }
        self.dial_round();
        let rounds = &mut self.dial_rounds;
        rounds.rounds = rounds.rounds.saturating_add(1);
        let active = std::mem::take(&mut rounds.active);
        rounds.period = next_period(rounds.period, rounds.base, active);
        rounds.next = Some(Instant::now() + jittered(rounds.period));
    }

    /// Every stream this peer pulled: both revocation streams, the advertisements once pulled,
    /// and each pulled space.
    fn pulled_streams(&self) -> Vec<String> {
        let mut streams: Vec<String> = revocation::STREAMS
            .iter()
            .map(|stream| (*stream).to_owned())
            .collect();
        if self.pulled_ads {
            streams.push(STREAM_ADS.to_owned());
        }
        streams.extend(
            self.pulled_spaces
                .iter()
                .map(|space| format!("{STREAM_SPACE_PREFIX}{space}")),
        );
        streams
    }

    /// The pulls on link-ready ([module docs](self#when)): every stream pulled, each with an empty
    /// digest so the seed sends everything it holds, packed as a round packs its streams, so 50
    /// spaces cost one or two `DIGEST`s of the seed's paced answers rather than one each. Toward a
    /// seed whose card carries `wire.ae=2` each body carries this peer's budget, and an answer cut
    /// short by it continues as every budgeted pull does.
    pub(super) fn link_ready_pulls(&mut self) {
        let digests: Vec<(String, Vec<u8>)> = self
            .pulled_streams()
            .into_iter()
            .map(|stream| (stream, Vec::new()))
            .collect();
        self.send_packed(digests);
    }

    /// One round toward the seed ([module docs](self#one-round)).
    fn dial_round(&mut self) {
        let digests: Vec<(String, Vec<u8>)> = self
            .pulled_streams()
            .into_iter()
            .filter_map(|stream| {
                let digest = self.stream_digest(&stream)?;
                Some((stream, digest))
            })
            .collect();
        self.send_packed(digests);
    }

    /// Sends `digests` to the seed packed into the fewest `DIGEST`s ([`pack_digests`]), each
    /// under this peer's budget toward a seed that audits; stops at the first the link refuses.
    fn send_packed(&mut self, digests: Vec<(String, Vec<u8>)>) {
        let budgeted = self
            .seed_peer
            .clone()
            .filter(|seed| self.partner_audits(seed));
        self.reset_continuations();
        for frame in pack_digests(digests) {
            let body = DigestBody {
                digests: Some(frame),
                budget: budgeted.as_ref().map(|_| self.audit.budget),
                ..DigestBody::default()
            };
            if let Some(seed) = &budgeted {
                self.note_budgeted_pull(seed);
            }
            if self.send(KIND_DIGEST, &body.encode(), None).is_err() {
                return; // the link went or has no room: the next round or link tries again
            }
        }
    }
}
