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
use agentspaces_wire::cbor::Map;
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
    /// The verified claims a claim of this peer's own holders displaced in the lattice, at most
    /// [`DISPLACED_PER_ENTRY`] per entry (Java `displacedClaims`, SPEC v0.1.36 §7.4 *Pairing the
    /// evidence*): the first half of a pair whose second half, the displaced holder's completion,
    /// may come in another frame.
    displaced_claims: Lines<Vec<Map>>,
    /// The completed states dropped here while a claim of this peer's own holders held the entry,
    /// at most [`DISPLACED_PER_ENTRY`] per entry (Java `unprovenCompletions`): each failed to
    /// authenticate against that claim and may be a displaced holder's.
    unproven: Lines<Vec<Map>>,
    /// The entries one of this peer's holders completed under a claim that a better claim,
    /// merged here afterwards, displaced (Java `displacedOwn`): the claim is offered again
    /// ([`Reoffer`]).
    displaced_own: Lines<Reoffer>,
    /// The claims made here that a better claim of another peer displaced, the first one lost
    /// per entry, whether or not one of this peer's holders completed under it (Java
    /// `displacedHere`): what a dial-only peer answers a relayed `DIGEST` for (owner decision 1
    /// of 2026-11-23, SPEC v0.1.37 §9.4), so a winner's targeted round reaches it.
    displaced_here: Lines<Map>,
    /// The holders a claim of this peer's own holders displaced, per entry, and the targeted
    /// anti-entropy rounds opened toward them while that take is open (Java `displacedPulls`,
    /// owner decision 4 of 2026-11-23): [`DisplacedPull`].
    displaced_pulls: Lines<DisplacedPull>,
}

/// The most displaced claims, and the most unproven completions, kept per entry (Java
/// `DISPLACED_PER_ENTRY`); past it the oldest goes.
pub(super) const DISPLACED_PER_ENTRY: usize = 4;
/// The most offers of one displaced claim (Java `REOFFER_MAX`).
pub(super) const REOFFER_MAX: u32 = 6;
/// The wait after the first offer of a displaced claim; it doubles after each (Java
/// `REOFFER_BACKOFF_MILLIS`).
pub(super) const REOFFER_BACKOFF: std::time::Duration = std::time::Duration::from_secs(1);

/// The most targeted rounds toward the holders one entry's claim displaced (Java
/// `DISPLACED_PULL_MAX`): at once, then after 1, 2, 4, 8 and 16 s.
pub(super) const DISPLACED_PULL_MAX: u32 = 6;

/// The holders (PeerIDs) a claim of this peer's own holders displaced for one entry, and the
/// targeted anti-entropy rounds opened toward them so far (Java `DisplacedPull`). A displaced
/// holder's completion may have only one source, the holder itself, and anti-entropy repairs
/// only a round's opener, so the winner opens the rounds rather than wait for a random partner
/// pick to land on the holder.
#[derive(Debug, Clone)]
pub(super) struct DisplacedPull {
    /// The displaced holders' PeerIDs, in the order they were displaced.
    pub holders: Vec<String>,
    /// The rounds opened so far (each toward every holder).
    pub rounds: u32,
    /// No round before this instant (monotonic: a local period).
    pub next_at: Instant,
}

/// One of this peer's completions whose claim a better claim displaced, and its offers so far.
#[derive(Debug, Clone)]
pub(super) struct Reoffer {
    /// The displaced claim, signed, as it first travelled.
    pub proof: Map,
    /// The offers made so far.
    pub offers: u32,
    /// No offer before this instant (monotonic: a local period).
    pub next_at: Instant,
    /// Whether the offers are over (spent, the claim lapsed or aged): the line stays until the
    /// entry is collected, so a later frame carrying the displaced claim again cannot start a
    /// second round of offers ("at most six offers in all").
    pub ended: bool,
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

    /// Keeps `lost`, a claim made here that a better claim of another peer displaced for
    /// `entry_id` (Java `displacedHere.putIfAbsent`): the first one lost stays.
    pub fn note_displaced_here(&mut self, entry_id: &str, lost: &Map) {
        self.displaced_here.entry_with(entry_id, || lost.clone());
    }

    /// Forgets each displaced claim made here that `keep` refuses (Java `pruneDisplacedHere`).
    pub fn prune_displaced_here(&mut self, keep: impl Fn(&str, &Map) -> bool) {
        self.displaced_here
            .values
            .retain(|entry_id, (lost, _)| keep(entry_id, lost));
    }

    /// The displaced claims made here a relayed `DIGEST` draws (owner decision 1 of 2026-11-23,
    /// Java `displacedFor`): each kept [`SettleBook::note_displaced_here`] line, then each
    /// displaced claim still offered again (Java `displacedOwn`) whose entry has none, by entry.
    /// Nothing else this peer completed is among them. Prune first.
    pub fn displaced_lines(&self) -> Vec<(&str, &Map)> {
        let mut lines: Vec<(&str, &Map)> = self
            .displaced_here
            .values
            .iter()
            .map(|(entry_id, (lost, _))| (entry_id.as_str(), lost))
            .collect();
        for (entry_id, (line, _)) in &self.displaced_own.values {
            if !line.ended && self.displaced_here.get(entry_id).is_none() {
                lines.push((entry_id.as_str(), &line.proof));
            }
        }
        lines
    }

    /// Forgets an entry that left the store.
    pub fn forget(&mut self, entry_id: &str) {
        self.outbid.remove(entry_id);
        self.completed_here.remove(entry_id);
        self.displaced_claims.remove(entry_id);
        self.unproven.remove(entry_id);
        self.displaced_own.remove(entry_id);
        self.displaced_here.remove(entry_id);
        self.displaced_pulls.remove(entry_id);
    }

    /// Notes `holder` (a PeerID) as displaced for `entry_id` by a claim of this peer's own
    /// holders, for the targeted rounds (Java `noteDisplaced`): a new line is due at `now`; a
    /// holder newly displaced after the first round is asked at once. Answers when the line's
    /// next round is due.
    pub fn note_displaced_holder(&mut self, entry_id: &str, holder: &str, now: Instant) -> Instant {
        let pull = self.displaced_pulls.entry_with(entry_id, || DisplacedPull {
            holders: Vec::new(),
            rounds: 0,
            next_at: now,
        });
        if !pull.holders.iter().any(|held| held == holder) {
            if pull.holders.len() >= DISPLACED_PER_ENTRY {
                pull.holders.remove(0);
            }
            pull.holders.push(holder.to_owned());
            if pull.rounds > 0 {
                pull.next_at = pull.next_at.min(now);
            }
        }
        pull.next_at
    }

    /// The entries with a targeted-round line, for the due work to judge each.
    pub fn displaced_pull_entries(&self) -> Vec<String> {
        self.displaced_pulls.values.keys().cloned().collect()
    }

    /// The targeted-round line of `entry_id`.
    pub fn displaced_pull_mut(&mut self, entry_id: &str) -> Option<&mut DisplacedPull> {
        self.displaced_pulls.get_mut(entry_id)
    }

    /// Drops the targeted-round line of `entry_id` (the take is no longer open, or its rounds
    /// are spent).
    pub fn end_displaced_pull(&mut self, entry_id: &str) {
        self.displaced_pulls.remove(entry_id);
    }

    /// The targeted-round line of `entry_id`, for tests.
    #[cfg(test)]
    pub fn displaced_pull(&self, entry_id: &str) -> Option<&DisplacedPull> {
        self.displaced_pulls.get(entry_id)
    }

    /// Keeps `lost`, a verified claim that a claim of this peer's own holders displaced for
    /// `entry_id` (the same claim once; at most [`DISPLACED_PER_ENTRY`], the oldest going).
    pub fn note_displaced_claim(&mut self, entry_id: &str, lost: &Map) {
        let claim = lost.get("claim");
        let lines = self.displaced_claims.entry(entry_id);
        if lines.iter().any(|held| held.get("claim") == claim) {
            return;
        }
        if lines.len() >= DISPLACED_PER_ENTRY {
            lines.remove(0);
        }
        lines.push(lost.clone());
    }

    /// Keeps `state`, a completion dropped while this peer's claim held `entry_id` (the same
    /// signature once; at most [`DISPLACED_PER_ENTRY`], the oldest going). Answers whether a
    /// displaced claim is kept for the entry, so the pair is worth judging now.
    pub fn note_unproven(&mut self, entry_id: &str, state: &Map) -> bool {
        let sig = state.get("stateSig");
        let lines = self.unproven.entry(entry_id);
        if !lines.iter().any(|held| held.get("stateSig") == sig) {
            if lines.len() >= DISPLACED_PER_ENTRY {
                lines.remove(0);
            }
            lines.push(state.clone());
        }
        self.displaced_claims.get(entry_id).is_some()
    }

    /// The displaced claims and unproven completions kept for `entry_id`, when both are.
    pub fn pairs(&self, entry_id: &str) -> Option<(Vec<Map>, Vec<Map>)> {
        Some((
            self.displaced_claims.get(entry_id)?.clone(),
            self.unproven.get(entry_id)?.clone(),
        ))
    }

    /// How many displaced claims are kept for `entry_id`.
    #[cfg(test)]
    pub fn displaced_claims(&self, entry_id: &str) -> usize {
        self.displaced_claims.get(entry_id).map_or(0, Vec::len)
    }

    /// How many unproven completions are kept for `entry_id`.
    pub fn unproven(&self, entry_id: &str) -> usize {
        self.unproven.get(entry_id).map_or(0, Vec::len)
    }

    /// Starts offering `proof` again for `entry_id`, due at `now`, unless it is offered already.
    /// Answers whether it started.
    pub fn start_reoffer(&mut self, entry_id: &str, proof: &Map, now: Instant) -> bool {
        if self.displaced_own.get(entry_id).is_some() {
            return false;
        }
        self.displaced_own.entry_with(entry_id, || Reoffer {
            proof: proof.clone(),
            offers: 0,
            next_at: now,
            ended: false,
        });
        true
    }

    /// The re-offer line of `entry_id`, while its offers are not over.
    pub fn reoffer_mut(&mut self, entry_id: &str) -> Option<&mut Reoffer> {
        self.displaced_own
            .get_mut(entry_id)
            .filter(|line| !line.ended)
    }

    /// Whether a re-offer line is kept for `entry_id`.
    #[cfg(test)]
    pub fn reoffering(&self, entry_id: &str) -> bool {
        self.displaced_own
            .get(entry_id)
            .is_some_and(|line| !line.ended)
    }

    /// Stops offering `entry_id` again, for good (until the entry is collected).
    pub fn end_reoffer(&mut self, entry_id: &str) {
        if let Some(line) = self.displaced_own.get_mut(entry_id) {
            line.ended = true;
        }
    }
}

/// Values by entry id in insertion order, at most [`SETTLE_BOOK_CAP`] entries; past it the oldest
/// goes.
#[derive(Debug)]
struct Lines<V> {
    values: HashMap<String, (V, u64)>,
    next: u64,
}

impl<V> Default for Lines<V> {
    fn default() -> Self {
        Self {
            values: HashMap::new(),
            next: 0,
        }
    }
}

impl<V> Lines<V> {
    fn get(&self, entry_id: &str) -> Option<&V> {
        self.values.get(entry_id).map(|(value, _)| value)
    }

    fn get_mut(&mut self, entry_id: &str) -> Option<&mut V> {
        self.values.get_mut(entry_id).map(|(value, _)| value)
    }

    fn remove(&mut self, entry_id: &str) -> Option<V> {
        self.values.remove(entry_id).map(|(value, _)| value)
    }

    /// The value of `entry_id`, made by `make` (the oldest evicted first at the cap) when absent.
    fn entry_with(&mut self, entry_id: &str, make: impl FnOnce() -> V) -> &mut V {
        if !self.values.contains_key(entry_id)
            && self.values.len() >= SETTLE_BOOK_CAP
            && let Some(oldest) = self
                .values
                .iter()
                .min_by_key(|(_, (_, order))| *order)
                .map(|(id, _)| id.clone())
        {
            self.values.remove(&oldest);
        }
        let next = &mut self.next;
        &mut self
            .values
            .entry(entry_id.to_owned())
            .or_insert_with(|| {
                *next = next.wrapping_add(1);
                (make(), *next)
            })
            .0
    }
}

impl<V: Default> Lines<V> {
    fn entry(&mut self, entry_id: &str) -> &mut V {
        self.entry_with(entry_id, V::default)
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
