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
use agentspaces_wire::fold::SpaceStore;
use agentspaces_wire::horizon::HorizonGate;
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
    /// The bytes of the entries' states held (`PeerConfig::space_max_bytes` bounds it): the
    /// sum of [`Slot::sizes`].
    pub bytes: usize,
    /// Each held entry's state size, as counted when it last applied.
    pub sizes: HashMap<String, usize>,
    /// The view's half of the per-entry horizon of SPEC §7.3: this space's mode and its
    /// hysteresis.
    pub gate: HorizonGate,
    /// What the settle guarantee of SPEC §7.4 remembers of this peer's own takes ([`SettleBook`]).
    pub settle: SettleBook,
}

/// The most entries each half of a [`SettleBook`] remembers; past it the oldest goes.
pub(super) const SETTLE_BOOK_CAP: usize = 1024;

/// What a space remembers, per entry, of the settle guarantee of SPEC §7.4 beyond its window,
/// for the claims this peer's own holders hold (Java `outbidCompletions`, `completedHere`). Each
/// half holds at most [`SETTLE_BOOK_CAP`] entries.
#[derive(Debug, Default)]
pub(super) struct SettleBook {
    /// The claim epoch at which a holder this peer's claim displaces in the lattice completed the
    /// entry while this peer still holds it present: this peer's take, when it is judged, or its
    /// completion, when it comes, acknowledges that completion with no result.
    outbid: Bounded,
    /// The claim epoch at which one of this peer's holders completed the entry with its own work:
    /// a displaced holder's authentic completion arriving after it is a duplicate.
    completed_here: Bounded,
}

impl SettleBook {
    /// The epoch of a displaced holder's completion noted for `entry_id`.
    pub fn outbid(&self, entry_id: &str) -> Option<i64> {
        self.outbid.get(entry_id)
    }

    /// Notes a displaced holder's completion of `entry_id` under this peer's claim at `epoch`.
    pub fn note_outbid(&mut self, entry_id: &str, epoch: i64) {
        self.outbid.insert(entry_id, epoch);
    }

    /// Forgets and answers the outbid completion noted for `entry_id`.
    pub fn take_outbid(&mut self, entry_id: &str) -> Option<i64> {
        self.outbid.remove(entry_id)
    }

    /// The epoch at which one of this peer's holders completed `entry_id` with its own work.
    pub fn completed_here(&self, entry_id: &str) -> Option<i64> {
        self.completed_here.get(entry_id)
    }

    /// Notes that one of this peer's holders completed `entry_id` with its work at `epoch`.
    pub fn note_completed_here(&mut self, entry_id: &str, epoch: i64) {
        self.completed_here.insert(entry_id, epoch);
    }

    /// Forgets the completion noted for `entry_id` when it was at `epoch`; whether it was.
    pub fn take_completed_here(&mut self, entry_id: &str, epoch: i64) -> bool {
        if self.completed_here.get(entry_id) == Some(epoch) {
            self.completed_here.remove(entry_id);
            return true;
        }
        false
    }

    /// Forgets an entry that left the store.
    pub fn forget(&mut self, entry_id: &str) {
        self.outbid.remove(entry_id);
        self.completed_here.remove(entry_id);
    }
}

/// Epochs by entry id in insertion order, at most [`SETTLE_BOOK_CAP`] of them.
#[derive(Debug, Default)]
struct Bounded {
    epochs: HashMap<String, (i64, u64)>,
    next: u64,
}

impl Bounded {
    fn get(&self, entry_id: &str) -> Option<i64> {
        self.epochs.get(entry_id).map(|(epoch, _)| *epoch)
    }

    fn insert(&mut self, entry_id: &str, epoch: i64) {
        self.next = self.next.wrapping_add(1);
        self.epochs.insert(entry_id.to_owned(), (epoch, self.next));
        if self.epochs.len() > SETTLE_BOOK_CAP
            && let Some(oldest) = self
                .epochs
                .iter()
                .min_by_key(|(_, (_, order))| *order)
                .map(|(id, _)| id.clone())
        {
            self.epochs.remove(&oldest);
        }
    }

    fn remove(&mut self, entry_id: &str) -> Option<i64> {
        self.epochs.remove(entry_id).map(|(epoch, _)| epoch)
    }
}

/// The cap on the lease that feeds a space's collection horizon (Java
/// `ReplicatedSpace.MAX_TRACKED_LEASE_MILLIS`, 24 hours): one entry with a century-long lease
/// cannot stop the collection; a longer lease still keeps its own entry until it lapses.
pub(super) const MAX_TRACKED_LEASE_MILLIS: i64 =
    agentspaces_wire::horizon::MAX_TRACKED_LEASE_MILLIS;

impl Slot {
    /// Forgets the size of an entry that left the store.
    pub fn forget_size(&mut self, entry_id: &str) {
        if let Some(size) = self.sizes.remove(entry_id) {
            self.bytes = self.bytes.saturating_sub(size);
        }
    }

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

    /// Whether the space `name` is open.
    pub fn contains(&self, name: &str) -> bool {
        self.slots.contains_key(name)
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
                    bytes: 0,
                    sizes: HashMap::new(),
                    gate: HorizonGate::new(),
                    settle: SettleBook::default(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use agentspaces_wire::cbor::{self, Value};
    use agentspaces_wire::records;
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

    /// SPEC §9.1 (v0.1.31): a space delta or pulled sync delta decodes under its record schema
    /// or not at all. A misshapen state or claim no longer drops alone: it makes the whole delta
    /// undecodable, which the actor counts (`deltas_undecodable`), as every implementation does.
    #[test]
    fn deltas_and_syncs_that_break_the_record_rules_do_not_decode() {
        let delta = cbor::encode(&cbor_map! {
            "state" => cbor_map! { "a" => 1 },
            "claimEntry" => "e1",
            "claim" => cbor_map! { "b" => 2 },
        });
        assert_eq!(records::decode_delta(&delta), None);
        let none = cbor::encode(&cbor_map! {
            "state" => Value::Null,
            "claimEntry" => Value::Null,
            "claim" => Value::Null,
        });
        assert_eq!(
            records::decode_delta(&none),
            Some(records::Delta::default())
        );
        // P1: a delta that omits a field does not decode.
        let short =
            cbor::encode(&cbor_map! { "state" => Value::Null, "claimEntry" => Value::Null });
        assert_eq!(records::decode_delta(&short), None);
        assert_eq!(records::decode_delta(&[0xff]), None);
        let sync = cbor::encode(&cbor_map! {
            "states" => cbor_array![cbor_map! { "a" => 1 }, 7],
            "claims" => cbor_map! { "e1" => cbor_map! { "b" => 2 }, "e2" => 3 },
        });
        assert_eq!(records::decode_sync_delta(&sync), None);
        let empty = cbor::encode(&cbor_map! {
            "states" => cbor_array![],
            "claims" => cbor_map! {},
        });
        assert_eq!(
            records::decode_sync_delta(&empty),
            Some(records::SyncDelta::default())
        );
    }
}
