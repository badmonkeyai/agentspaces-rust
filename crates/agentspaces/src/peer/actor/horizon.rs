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

//! The collection rule of SPEC §7.3 on the actor, and the lines a space acknowledges.
//!
//! # The rule
//!
//! Each space judges its rule afresh at every sweep and at the door, from this peer's view
//! ([`agentspaces_wire::horizon`]): the per-entry horizon applies only while this peer advertises
//! `wire.horizon=1` ([`PeerConfig::horizon`](crate::peer::PeerConfig::horizon)) and every member
//! in view does too, after the engage rounds (each one gossip period of the founding, or of this
//! peer's own rounds when they are slower) and the settle. A member is
//! in view while its advertisement is live, or while it is known only by a frame, which counts as
//! lacking the hint.
//! A member's stay in view starts when it enters the view and ends when it leaves (its
//! advertisement lapsed, or it was dropped or evicted); a withdrawal uses the per-entry horizon
//! only when every writing node is this peer or a hinted member whose stay has lasted one longest
//! lease plus five minutes. A leave is seen even when no judgement fell while the member was
//! away: the member view notes when each member entered it, anew for a member removed and held
//! again or whose advertisement lapsed before the next one came.
//!
//! # Acknowledgements (SPEC §7.3, §9.2 R7)
//!
//! A space acknowledges a verified state it refused because its actor is revoked or its stamps
//! are unacceptable, a claim refused because its holder is revoked, and a re-offered state its
//! door refused as past its horizon when it holds no state of that entry. Each line is written
//! `a:<line>` in the text digest and stands in the audited set as the line itself, so partners
//! stop re-offering it; at most 8192 per space, the least recently refused forgotten first. A
//! refusal's line is forgotten once what it refused is past its legacy horizon, and never sooner
//! than five minutes after the last refusal; a door refusal's line five minutes after the last
//! refusal.

use std::collections::{HashMap, HashSet};

use agentspaces_wire::ads as wire_ads;
use agentspaces_wire::cbor::{Map, Value};
use agentspaces_wire::fold::FoldContext;
use agentspaces_wire::horizon::{self, Rule, Standing, Writer};
use agentspaces_wire::serving;
use agentspaces_wire::trie;

use super::{Actor, bump};

/// How long an acknowledgement is held after the refusal it answers, at least: five minutes.
pub(in crate::peer) const ACK_HOLD_MILLIS: i64 = horizon::LAPSED_GRACE_MILLIS;

/// One member's current stay in the view.
#[derive(Debug, Clone, Copy)]
struct Stay {
    /// When it began, on the peer's clock.
    since: i64,
    /// The member view's generation at which the member entered it.
    entered: Option<u64>,
}

/// The view's half of the rule as this peer last derived it.
#[derive(Debug, Default)]
pub(in crate::peer) struct HorizonView {
    /// Each member in view and its current stay.
    stays: HashMap<String, Stay>,
    /// The member view's generation it was derived at, the time until which it holds (the
    /// earliest lapse of a live advertisement in view), and whether every member is hinted.
    derived: Option<(u64, i64, bool)>,
}

impl Actor {
    /// Whether every member in view advertises `wire.horizon=1` at `now`, deriving the view (and
    /// the stays) again when the member view changed or an advertisement in it lapsed since.
    fn view_hinted(&mut self, now: i64) -> bool {
        let generation = self.members.generation();
        if let Some((at, until, hinted)) = self.horizon_view.derived
            && at == generation
            && now < until
        {
            return hinted;
        }
        let mut hinted = true;
        let mut until = i64::MAX;
        let mut in_view: Vec<(String, Option<u64>)> = Vec::new();
        for (peer, ad) in self.members.iter() {
            if peer == self.peer_id {
                continue;
            }
            let entered = self.members.entered(peer);
            if ad.is_empty() {
                // Known only by a frame: its card has not arrived, so it lacks the hint.
                hinted = false;
                in_view.push((peer.to_owned(), entered));
                continue;
            }
            match wire_ads::ad_expires_at_millis(ad) {
                Some(expires) if expires > now => {
                    until = until.min(expires);
                    hinted &= horizon::hints_horizon(ad.get("resourceHints"));
                    in_view.push((peer.to_owned(), entered));
                }
                _ => {}
            }
        }
        let present: HashSet<&str> = in_view.iter().map(|(peer, _)| peer.as_str()).collect();
        let stays = &mut self.horizon_view.stays;
        stays.retain(|peer, _| present.contains(peer.as_str()));
        for (peer, entered) in in_view {
            // The same stay while the member never left the member view since it entered.
            if stays.get(&peer).is_none_or(|stay| stay.entered != entered) {
                stays.insert(
                    peer,
                    Stay {
                        since: now,
                        entered,
                    },
                );
            }
        }
        self.horizon_view.derived = Some((generation, until, hinted));
        hinted
    }

    /// The rule `space` applies at `now`: its gate judged against this peer's setting and view
    /// ([module docs](self)). `Legacy` for a space that is not open. A round is one gossip period
    /// of the founding ([`Actor::founding_period`]: one second when it is unknown, as the
    /// reference implementation counts it), on a dial-only peer as on a listening one; this
    /// peer's own rounds ([`Actor::gossip_period`]) count only when they are slower, so a faster
    /// `anti_entropy_period` never brings the per-entry horizon closer.
    pub(super) fn horizon_rule(&mut self, space: &str, now: i64) -> Rule {
        let hinted = self.settings.horizon && self.view_hinted(now);
        let period = self.gossip_period().max(self.founding_period());
        let round = i64::try_from(period.as_millis()).unwrap_or(i64::MAX);
        let rounds = self.settings.horizon_engage_rounds;
        match self.spaces.get_mut(space) {
            Some(slot) => {
                let max_lease = slot.max_lease;
                slot.gate.judge(now, hinted, round, max_lease, rounds)
            }
            None => Rule::Legacy,
        }
    }

    /// Where a writing node stands in this peer's view, as last derived.
    fn writer_standing(&self, replica: &str) -> Writer {
        if replica == self.peer_id {
            return if self.settings.horizon {
                Writer::This
            } else {
                Writer::Absent
            };
        }
        let hinted = self
            .members
            .get(replica)
            .is_some_and(|ad| horizon::hints_horizon(ad.get("resourceHints")));
        match self.horizon_view.stays.get(replica) {
            Some(stay) if hinted => Writer::InViewSince(stay.since),
            _ => Writer::Absent,
        }
    }

    /// Whether a space whose rule is `rule` and whose longest lease is `max_lease` collects
    /// `state` at `now`: the sweep and the door both judge by this.
    pub(super) fn collects(&self, rule: Rule, state: &Map, now: i64, max_lease: i64) -> bool {
        let vouched = rule == Rule::PerEntry
            && Standing::of(state) == Standing::Withdrawn
            && horizon::writers_vouched(state, now, max_lease, |replica| {
                self.writer_standing(replica)
            });
        horizon::collectable_here(state, now, max_lease, rule, vouched)
    }

    /// Whether this peer drops a state or claim of `entry_id` before folding it: under
    /// `wire.ae=2`, an id holding a control character (SPEC annex I.6), uncounted and
    /// unacknowledged.
    pub(super) fn drops_control_id(&self, entry_id: &str) -> bool {
        self.audit.enabled && trie::has_control(entry_id)
    }

    /// Acknowledges a verified state of `space` refused for its actor's revocation or its stamps
    /// (SPEC §7.3): forgotten once it is past its legacy horizon, and never sooner than
    /// [`ACK_HOLD_MILLIS`] from now.
    pub(super) fn acknowledge_refused_state(&mut self, space: &str, entry_id: &str, dto: &Map) {
        let now = self.now();
        let Some(slot) = self.spaces.get_mut(space) else {
            return;
        };
        let line = serving::state_line(entry_id, dto);
        let horizon = horizon::state_horizon(dto, slot.max_lease, Rule::Legacy).unwrap_or(i64::MAX);
        let forget_at = horizon.max(now.saturating_add(ACK_HOLD_MILLIS));
        slot.store.acknowledge(entry_id, &line, forget_at);
    }

    /// Acknowledges a claim of `space` refused because its holder is revoked (SPEC §9.2 R7):
    /// forgotten once the claim has lapsed and passed the lapse grace, and never sooner than
    /// [`ACK_HOLD_MILLIS`] from now.
    pub(super) fn acknowledge_refused_claim(&mut self, space: &str, entry_id: &str, signed: &Map) {
        let now = self.now();
        let Some(slot) = self.spaces.get_mut(space) else {
            return;
        };
        let line = serving::claim_line(entry_id, signed);
        let expiry = signed
            .get("claim")
            .and_then(|claim| claim.get("expiresAtMillis"))
            .and_then(Value::as_i64)
            .unwrap_or(now);
        let keep = horizon::keep_millis(Standing::Present, slot.max_lease, Rule::Legacy);
        let forget_at = expiry
            .saturating_add(keep)
            .max(now.saturating_add(ACK_HOLD_MILLIS));
        slot.store.acknowledge(entry_id, &line, forget_at);
    }

    /// Acknowledges a state of `space` that the door refused as past its horizon (SPEC §7.3),
    /// when this space holds no state of its entry and the state would otherwise merge
    /// ([`agentspaces_wire::fold::SpaceStore::judge`]); held [`ACK_HOLD_MILLIS`] after the last
    /// refusal.
    pub(super) fn acknowledge_collected(&mut self, space: &str, dto: &Map, now: i64) {
        let Some(entry_id) = agentspaces_wire::records::state_entry_id(dto) else {
            return;
        };
        let Some(slot) = self.spaces.get_mut(space) else {
            return;
        };
        if slot.store.state(entry_id).is_some() {
            return; // still held here: its own sweep collects it
        }
        let ctx = FoldContext::new(now, &self.registry).with_space(&slot.space_id);
        if slot.store.judge(dto, &ctx).is_err() {
            return;
        }
        let line = serving::state_line(entry_id, dto);
        if slot
            .store
            .acknowledge(entry_id, &line, now.saturating_add(ACK_HOLD_MILLIS))
        {
            bump(&mut self.counters.reoffers_acknowledged);
        }
    }
}
