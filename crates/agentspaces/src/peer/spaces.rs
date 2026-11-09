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

//! The peer's replicated spaces: one [`SpaceStore`] per space name, bound to the local SpaceID of
//! `"<group>/<name>"` so a record or claim of another space never folds into it, and the parsers
//! of the two shapes a space's state travels in (a rumor's delta and a pull response's sync).
//!
//! Only this peer opens a space ([`Spaces::slot`], from a pull or a write); data arriving for a
//! space it never opened is not folded ([`Spaces::get_mut`] finds nothing), as Java delivers a
//! stream only to the handler a `ReplicatedSpace` registered. So remote data can never use up
//! [`MAX_SPACES`] and lock this peer out of its own spaces.

use std::collections::HashMap;

use agentspaces_wire::bodies::STREAM_SPACE_PREFIX;
use agentspaces_wire::cbor::{self, Map, Value};
use agentspaces_wire::fold::SpaceStore;
use agentspaces_wire::ids;
use tokio::time::Instant;

/// The most spaces a peer opens (by pulling or writing them); opening a further one is refused.
pub(super) const MAX_SPACES: usize = 1024;

/// One replicated space.
#[derive(Debug)]
pub(super) struct Slot {
    /// `ids::space_id_local("<group>/<name>")`.
    pub space_id: String,
    /// What has folded.
    pub store: SpaceStore,
    /// The transitions already derived for each entry the store holds a state of, so each is
    /// told once ([`Fired`]).
    pub fired: HashMap<String, Fired>,
    /// The longest lease observed in the space, milliseconds, capped at
    /// [`MAX_TRACKED_LEASE_MILLIS`] (Java `maxLeaseObservedMillis`): the collection horizon's
    /// measure (SPEC §7.3).
    pub max_lease: i64,
    /// When a received state last made the space collect because it was full.
    pub full_collected: Option<Instant>,
}

/// The cap on the lease that feeds a space's collection horizon (Java
/// `ReplicatedSpace.MAX_TRACKED_LEASE_MILLIS`, 24 hours): one entry with a century-long lease
/// cannot stop the collection; a longer lease still keeps its own entry until it lapses.
pub(super) const MAX_TRACKED_LEASE_MILLIS: i64 = 24 * 60 * 60 * 1000;

impl Slot {
    /// Takes a lease of `millis` into the space's longest lease (Java `observeLease`): capped at
    /// [`MAX_TRACKED_LEASE_MILLIS`]; a lease that is not positive is ignored.
    pub fn observe_lease(&mut self, millis: i64) {
        let capped = millis.min(MAX_TRACKED_LEASE_MILLIS);
        if capped > self.max_lease {
            self.max_lease = capped;
        }
    }
}

/// The transitions of one entry already derived (Java's `expiredFired`, `reappearedEpochs`,
/// `takenEpochs`): each fires once per entry, `Taken` once per claim epoch and holder, and
/// `Reappeared` once per lapsed claim epoch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Fired {
    /// `Completed` was derived.
    pub completed: bool,
    /// `Expired` was derived.
    pub expired: bool,
    /// The `(epoch, holder)` of the last `Taken` derived.
    pub taken: Option<(i64, String)>,
    /// The claim epoch of the last `Reappeared` derived.
    pub reappeared: Option<i64>,
}

/// The spaces of one group, by name.
#[derive(Debug)]
pub(super) struct Spaces {
    group: String,
    slots: HashMap<String, Slot>,
    /// The bound of each space's store ([`SpaceStore::with_max_entries`]).
    max_entries: usize,
}

impl Spaces {
    /// No spaces yet, for `group`; each space opened holds at most `max_entries` entries (and as
    /// many claims), at least one.
    pub fn new(group: &str, max_entries: usize) -> Self {
        Self {
            group: group.to_owned(),
            slots: HashMap::new(),
            max_entries: max_entries.max(1),
        }
    }

    /// The names of the spaces opened.
    pub fn names(&self) -> Vec<String> {
        self.slots.keys().cloned().collect()
    }

    /// Every space opened.
    pub fn iter(&self) -> impl Iterator<Item = &Slot> {
        self.slots.values()
    }

    /// Whether any space is open.
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// How many spaces are open.
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Closes the space `name`: what folded of it is dropped and its slot is free; answers
    /// whether it was open.
    pub fn remove(&mut self, name: &str) -> bool {
        self.slots.remove(name).is_some()
    }

    /// The space `name`, if it has been opened.
    pub fn get(&self, name: &str) -> Option<&Slot> {
        self.slots.get(name)
    }

    /// The space `name` to fold into, if this peer has opened it; remote data never opens one.
    pub fn get_mut(&mut self, name: &str) -> Option<&mut Slot> {
        self.slots.get_mut(name)
    }

    /// The space `name`, opened on first use by this peer (a pull or a write); `None` for an
    /// empty name or when [`MAX_SPACES`] are already open.
    pub fn slot(&mut self, name: &str) -> Option<&mut Slot> {
        if name.is_empty() {
            return None;
        }
        if !self.slots.contains_key(name) {
            if self.slots.len() >= MAX_SPACES {
                return None;
            }
            let space_id = ids::space_id_local(&format!("{}/{name}", self.group));
            self.slots.insert(
                name.to_owned(),
                Slot {
                    space_id,
                    store: SpaceStore::with_max_entries(self.max_entries),
                    fired: HashMap::new(),
                    max_lease: 0,
                    full_collected: None,
                },
            );
        }
        self.slots.get_mut(name)
    }
}

/// The space name of a rumor or pull stream `space:<name>`, or `None` for another stream.
pub(super) fn space_name(stream: &str) -> Option<&str> {
    stream
        .strip_prefix(STREAM_SPACE_PREFIX)
        .filter(|name| !name.is_empty())
}

/// A space rumor's delta (Java `SpaceWire.Delta`, `{state, claimEntry, claim}`): the claim it
/// carries under its entry id, and the state. Either may be absent. `None` when the payload is
/// not a map.
pub(super) type Delta = (Option<(String, Map)>, Option<Map>);

/// Parses a space rumor's payload ([`Delta`]).
pub(super) fn parse_delta(payload: &[u8]) -> Option<Delta> {
    let mut delta = cbor::decode(payload).ok()?.into_map()?;
    let claim_entry = delta
        .remove("claimEntry")
        .and_then(Value::into_text)
        .filter(|entry| !entry.is_empty());
    let claim = delta.remove("claim").and_then(Value::into_map);
    let state = delta.remove("state").and_then(Value::into_map);
    Some((claim_entry.zip(claim), state))
}

/// A space's pull response delta (`{states: [...], claims: {entryId: signedClaim}}`): its claims
/// and its states, each skipping an item of the wrong shape. `None` when the bytes are not a map.
pub(super) type Sync = (Vec<(String, Map)>, Vec<Map>);

/// Parses a space's pull response delta ([`Sync`]).
pub(super) fn parse_sync(delta: &[u8]) -> Option<Sync> {
    let mut sync = cbor::decode(delta).ok()?.into_map()?;
    let claims = sync
        .remove("claims")
        .and_then(Value::into_map)
        .map(|claims| {
            claims
                .into_iter()
                .filter_map(|(entry, signed)| Some((entry.into_text()?, signed.into_map()?)))
                .collect()
        })
        .unwrap_or_default();
    let states = sync
        .remove("states")
        .and_then(Value::into_array)
        .map(|states| states.into_iter().filter_map(Value::into_map).collect())
        .unwrap_or_default();
    Some((claims, states))
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentspaces_wire::{cbor_array, cbor_map};

    #[test]
    fn spaces_open_on_first_use_and_bind_their_space_id() {
        let mut spaces = Spaces::new("zGroup", 8);
        assert!(spaces.get("tasks").is_none());
        assert!(
            spaces.get_mut("tasks").is_none(),
            "folding never opens a space"
        );
        let id = spaces.slot("tasks").map(|slot| slot.space_id.clone());
        assert_eq!(id, Some(ids::space_id_local("zGroup/tasks")));
        assert!(spaces.get("tasks").is_some());
        assert_eq!(
            spaces.get("tasks").map(|slot| slot.store.max_entries()),
            Some(8)
        );
        assert!(spaces.slot("").is_none());
        assert_eq!(space_name("space:tasks"), Some("tasks"));
        assert_eq!(space_name("space:"), None);
        assert_eq!(space_name("ads"), None);
    }

    #[test]
    fn the_longest_lease_is_kept_and_capped() {
        let mut spaces = Spaces::new("zGroup", 8);
        let Some(slot) = spaces.slot("tasks") else {
            panic!("a slot");
        };
        slot.observe_lease(-5);
        assert_eq!(slot.max_lease, 0);
        slot.observe_lease(1_000);
        slot.observe_lease(500);
        assert_eq!(slot.max_lease, 1_000);
        slot.observe_lease(i64::MAX);
        assert_eq!(slot.max_lease, MAX_TRACKED_LEASE_MILLIS);
    }

    #[test]
    fn deltas_and_syncs_parse_and_skip_what_is_misshapen() {
        let delta = cbor::encode(&cbor_map! {
            "state" => cbor_map! { "a" => 1 },
            "claimEntry" => "e1",
            "claim" => cbor_map! { "b" => 2 },
        });
        let (claim, state) = parse_delta(&delta).expect("a map");
        assert_eq!(claim.map(|(entry, _)| entry).as_deref(), Some("e1"));
        assert!(state.is_some());
        let none = cbor::encode(&cbor_map! { "state" => Value::Null, "claimEntry" => Value::Null });
        assert_eq!(parse_delta(&none), Some((None, None)));
        assert_eq!(parse_delta(&[0xff]), None);
        let sync = cbor::encode(&cbor_map! {
            "states" => cbor_array![cbor_map! { "a" => 1 }, 7],
            "claims" => cbor_map! { "e1" => cbor_map! { "b" => 2 }, "e2" => 3 },
        });
        let (claims, states) = parse_sync(&sync).expect("a map");
        assert_eq!(claims.len(), 1);
        assert_eq!(states.len(), 1);
    }
}
