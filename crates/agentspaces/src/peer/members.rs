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

//! The members a peer knows: every PeerID that signed a frame it accepted (held with an empty
//! advertisement) and every member whose verified self-advertisement the `peers` stream carried.
//!
//! The view is bounded. When it is full, a newcomer takes the place of the oldest member known only
//! by a frame (never one holding an advertisement), so a flood of fresh signers cannot freeze the
//! view and keep later members out; with no such member to replace, the newcomer is not recorded.

use std::collections::{BTreeMap, VecDeque};

use agentspaces_wire::ads as wire_ads;
use agentspaces_wire::cbor::{Map, Value};
use agentspaces_wire::time;

/// The bounded member view. See the [module docs](self).
#[derive(Debug)]
pub(super) struct MemberView {
    bound: usize,
    members: BTreeMap<String, Map>,
    /// Members recorded without an advertisement, oldest first. May name members since given
    /// an advertisement or removed; those are skipped (and compacted away).
    heard_only: VecDeque<String>,
    /// Moves whenever a member is added, its advertisement replaced, or a member removed.
    generation: u64,
    /// For each member, the generation at which it entered the view: a member removed and held
    /// again, or whose advertisement lapsed before the next one came, enters anew, so a stay
    /// measured from it starts afresh.
    entered: BTreeMap<String, u64>,
}

impl MemberView {
    /// An empty view of at most `bound` members.
    pub fn new(bound: usize) -> Self {
        Self {
            bound,
            members: BTreeMap::new(),
            heard_only: VecDeque::new(),
            generation: 0,
            entered: BTreeMap::new(),
        }
    }

    /// A counter that moves whenever the view changes, so a caller that derives something from
    /// it knows when to derive it again.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Every member with its advertisement (empty when only heard from), in PeerID order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Map)> {
        self.members.iter().map(|(peer, ad)| (peer.as_str(), ad))
    }

    /// How many members are held.
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// The generation at which `peer` entered the view in its current stay.
    pub fn entered(&self, peer: &str) -> Option<u64> {
        self.entered.get(peer).copied()
    }

    /// The advertisement held for `peer` (empty when only heard from).
    pub fn get(&self, peer: &str) -> Option<&Map> {
        self.members.get(peer)
    }

    /// The members, in PeerID order.
    pub fn ids(&self) -> Vec<String> {
        self.members.keys().cloned().collect()
    }

    /// Records `peer` as heard from (an empty advertisement) unless already held; whether it is
    /// held afterwards.
    pub fn hear(&mut self, peer: &str) -> bool {
        if self.members.contains_key(peer) {
            return true;
        }
        if !self.make_room() {
            return false;
        }
        self.members.insert(peer.to_owned(), Map::new());
        self.generation = self.generation.wrapping_add(1);
        self.entered.insert(peer.to_owned(), self.generation);
        self.heard_only.push_back(peer.to_owned());
        self.compact();
        true
    }

    /// Holds `ad` as `peer`'s advertisement, replacing what was held; whether it is held. At
    /// `now_ms` on this peer's clock: a member whose held advertisement had lapsed by then, or
    /// whose new one was issued after the held one lapsed, was out of the view in between, so it
    /// enters the view anew.
    pub fn hold_ad(&mut self, peer: String, ad: Map, now_ms: i64) -> bool {
        if !self.members.contains_key(&peer) && !self.make_room() {
            return false;
        }
        self.generation = self.generation.wrapping_add(1);
        let returned = self.members.get(&peer).is_some_and(|held| {
            let Some(lapse) = wire_ads::ad_expires_at_millis(held) else {
                return false; // known only by a frame: in view all along
            };
            let issued = ad
                .get("issued")
                .and_then(Value::as_str)
                .and_then(|issued| time::parse_instant_millis(issued).ok());
            lapse <= now_ms || issued.is_some_and(|issued| issued > lapse)
        });
        if self.members.insert(peer.clone(), ad).is_none() || returned {
            self.entered.insert(peer, self.generation);
        }
        true
    }

    /// Removes every member `keep` refuses.
    pub fn retain(&mut self, mut keep: impl FnMut(&str) -> bool) {
        let before = self.members.len();
        self.members.retain(|peer, _| keep(peer));
        if self.members.len() != before {
            self.generation = self.generation.wrapping_add(1);
            let members = &self.members;
            self.entered.retain(|peer, _| members.contains_key(peer));
        }
    }

    /// Frees one place when the view is full by dropping the oldest member known only by a
    /// frame; whether there is room.
    fn make_room(&mut self) -> bool {
        while self.members.len() >= self.bound {
            let Some(oldest) = self.heard_only.pop_front() else {
                return false;
            };
            if self.members.get(&oldest).is_some_and(Map::is_empty) {
                self.members.remove(&oldest);
                self.entered.remove(&oldest);
                self.generation = self.generation.wrapping_add(1);
            }
        }
        true
    }

    /// Drops stale names from the heard-only order once it outgrows the view.
    fn compact(&mut self) {
        if self.heard_only.len() > self.bound.saturating_mul(2) {
            let members = &self.members;
            self.heard_only
                .retain(|peer| members.get(peer).is_some_and(Map::is_empty));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ad() -> Map {
        [("issuer", "x")].into_iter().collect()
    }

    #[test]
    fn a_full_view_replaces_the_oldest_member_known_only_by_a_frame() {
        let mut view = MemberView::new(3);
        assert!(view.hold_ad("advertised".into(), ad(), 0));
        assert!(view.hear("first"));
        assert!(view.hear("second"));
        assert!(
            view.hear("third"),
            "the oldest heard-only member makes room"
        );
        assert_eq!(view.ids(), ["advertised", "second", "third"]);
        assert!(view.hold_ad("fourth".into(), ad(), 0));
        assert_eq!(view.ids(), ["advertised", "fourth", "third"]);
        // Members holding advertisements are never replaced.
        assert!(view.hold_ad("third".into(), ad(), 0));
        assert!(
            !view.hear("fifth"),
            "no member known only by a frame is left to replace"
        );
        assert_eq!(view.len(), 3);
        view.retain(|peer| peer != "fourth");
        assert!(view.hear("fifth"));
        assert!(view.get("fifth").is_some());
        assert_eq!(view.get("fifth"), Some(&Map::new()));
    }

    #[test]
    fn a_flood_of_fresh_signers_never_freezes_the_view() {
        let mut view = MemberView::new(8);
        for n in 0..10_000 {
            assert!(view.hear(&format!("flood-{n}")));
        }
        assert!(view.hear("latecomer"), "a later member is still recorded");
        assert!(view.get("latecomer").is_some());
        assert!(view.heard_only.len() <= 16 + 1, "the order stays compact");
    }
}
