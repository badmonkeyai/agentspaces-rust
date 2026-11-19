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

//! The probe hashes of SPEC §5.2 (v0.1.35) on the actor.
//!
//! # What this peer sends
//!
//! This peer sends no failure-detection probes of its own; it answers every `PING` with an
//! `ACK`, and the probes it relays for a `PING_REQ` carry nothing. A listening peer, which runs
//! rounds and answers `DIGEST`s, answers a `PING` that carried `hashes` or `root` with an `ACK`
//! that carries its own: each stream it serves one by one while there are at most
//! [`ListenConfig::probe_streams`](crate::peer::ListenConfig::probe_streams) of them, else one
//! `root` over them. Both follow the prober's kind (annex I.6): toward a member whose current card
//! carries `wire.ae=2` a space's hash is its trie stream hash, toward any other its text digest's
//! SHA-256. A dial-only peer, which answers no `DIGEST`, attaches none, and every other `ACK`
//! carries none either, since the fields are optional.
//!
//! # What this peer reads
//!
//! The piggyback is read strictly ([`bodies::probe_hashes`]): a field that breaks a form rule is
//! counted under its reason and read as no information, and the probe is still answered. Since
//! an answer with hashes reads every stream this peer serves, each member's hashed probes draw
//! hashes at a pace ([`PROBE_HASH_BURST`], [`PROBE_HASH_RATE`] a second); past it the probe is
//! answered bare, which the prober reads as no information, and counted. An
//! absent `root` or `hashes` is no information: it starts nothing. While this peer's own rounds
//! have backed off, a difference on a stream both hold, or a `root` that differs from its own,
//! starts a targeted round with the prober, at most once per gossip period per member, when the
//! prober is a partner of this peer's rounds.

use std::collections::BTreeMap;

use agentspaces_wire::bodies::{self, KIND_PING, ProbeHashes};
use tokio::time::Instant;

use super::{Actor, bump};

/// The members whose last probe-started round is remembered, at most.
const PROBE_ROUNDS_TRACKED: usize = 1024;
/// A member's probes answered with this peer's hashes: a burst, and then this many a second. A
/// member probes another at most once per probe period, so honest probing stays well inside.
const PROBE_HASH_BURST: u32 = 4;
const PROBE_HASH_RATE: u32 = 2;

impl Actor {
    /// A `PING` from `sender` with `nonce`: reads its hashes, starts a targeted round when they
    /// show a difference ([module docs](self)), and answers the `ACK` body to send.
    pub(super) fn on_ping(&mut self, sender: &str, body: &[u8], nonce: i64) -> Vec<u8> {
        let probe = match bodies::decode_body(KIND_PING, body).map(|map| bodies::probe_hashes(&map))
        {
            Some(Ok(probe)) => probe,
            Some(Err(refusal)) => {
                *self
                    .hub
                    .counters
                    .probe_hashes_refused
                    .entry(refusal.as_str().to_owned())
                    .or_default() += 1;
                ProbeHashes::default()
            }
            None => ProbeHashes::default(),
        };
        if probe.is_empty() || !self.hub.listening {
            return bodies::ack_body(nonce);
        }
        if self.hub.probe_pace.len() >= PROBE_ROUNDS_TRACKED
            && !self.hub.probe_pace.contains_key(sender)
        {
            self.hub.probe_pace.clear();
        }
        let paced = !self
            .hub
            .probe_pace
            .entry(sender.to_owned())
            .or_insert_with(|| {
                crate::peer::listen::TokenBucket::new(PROBE_HASH_BURST, PROBE_HASH_RATE)
            })
            .take();
        if paced {
            bump(&mut self.hub.counters.probe_hashes_paced);
            return bodies::ack_body(nonce);
        }
        let own = self.stream_hashes_for(sender);
        self.compare_probe(sender, &probe, &own);
        let bound = self.hub.settings.probe_streams;
        bodies::ack_body_with(nonce, &ProbeHashes::of(own, bound))
    }

    /// Starts a targeted round with `sender` when its probe's hashes show a difference from
    /// `own` and this peer's rounds have backed off, at most once per gossip period per member.
    fn compare_probe(
        &mut self,
        sender: &str,
        probe: &ProbeHashes,
        own: &BTreeMap<String, [u8; 32]>,
    ) {
        if !self.rounds_backed_off() || !self.runs_rounds_with(sender) {
            return;
        }
        let differs = match (&probe.hashes, &probe.root) {
            (Some(hashes), _) => hashes
                .iter()
                .any(|(stream, hash)| own.get(stream).is_some_and(|mine| mine != hash)),
            (None, Some(root)) => bodies::probe_root(own) != *root,
            (None, None) => false,
        };
        if !differs {
            return;
        }
        let now = Instant::now();
        let period = self.hub.base_period;
        if self
            .hub
            .probe_rounds
            .get(sender)
            .is_some_and(|at| now.duration_since(*at) < period)
        {
            return;
        }
        if self.hub.probe_rounds.len() >= PROBE_ROUNDS_TRACKED {
            self.hub
                .probe_rounds
                .retain(|_, at| now.duration_since(*at) < period);
        }
        self.hub.probe_rounds.insert(sender.to_owned(), now);
        bump(&mut self.hub.counters.probe_rounds);
        self.round_with(sender);
    }
}
