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

//! The space verbs on the actor ([`crate::space`] calls them through the [`Peer`] handle), and
//! the entry transitions it derives for watches.
//!
//! # Verbs
//!
//! Every verb runs in one actor turn, so what it checks still holds when it commits:
//!
//! - a take's claim ([`Actor::space_claim`]) re-reads the candidate's live claim and completion
//!   first (as `peer.py` and `peer.rb` do: a candidate list is a snapshot, and the members faster
//!   than this one may have claimed its entries since), builds the claim with the wire builder
//!   (epoch one past the held claim's, the stamp from this peer's clock for the holder), merges it
//!   here, and rumors it; [`Actor::space_settle`] then decides the race;
//! - a take's renewal re-signs the held claim with the same epoch, stamp, holder, and bid and the
//!   later expiry of the renewal rule, which the claim lattice prefers (Java `Taken.renew`,
//!   `peer.rb`'s `renew_claim`);
//! - a completion re-signs the joined state with `completed` set as the holder (the agent when
//!   the claim was the agent's: the two-key rule), carries the winning claim in the delta, and
//!   writes the result in the same turn, prepared before the completion commits (Java
//!   `completeInternal`);
//! - a renewal or cancellation of a write re-signs the joined state as its issuer (`peer.py`'s
//!   `renew_entry`, Java `Handle.renew` and `Handle.cancel`).
//!
//! Each folds through this peer's own fold first, so a state it builds is judged exactly as every
//! receiver judges it.
//!
//! # Transitions
//!
//! Folds and a sweep derive each entry's transitions once (Java `ReplicatedSpace.fire`,
//! `sweepLocked`): `Written` at the first fold of a live entry, `Completed` when the joined state
//! turns completed (for an entry first learned already completed, only when its value is held
//! here, and never with a `Written` or `Taken` before it: SPEC §7.2, *Completed on arrival*), `Taken` when a member's claim wins the lattice while live (once per epoch and
//! holder; this peer's own claim only once its take has won), and, from the sweep that runs when
//! the earliest such lapse falls due while a space has watchers ([`Actor::sweep_at`]), `Expired`
//! once per open entry whose write lease
//! lapsed and `Reappeared` once per lapsed claim epoch of an open entry. Each transition is offered
//! to the matching watches without waiting ([`crate::space::watch`]); one whose payload block is
//! still on its way waits (at most [`MAX_DEFERRED`] of them) until the block arrives.
//!
//! # Collection
//!
//! Every [`COLLECT_INTERVAL`], watched or not, each open space drops its tombstones past the
//! horizon of SPEC §7.3 ([`agentspaces_wire::horizon`]): a completed entry two of the space's
//! longest leases after its write lease lapsed, a withdrawn one (or one both withdrawn and
//! completed) the longer of that and the drift ceiling (ten minutes), a lapsed one the shorter of
//! two longest leases and five minutes; with its claim, its transitions' trackers, and the block
//! it pinned. Under the per-entry horizon (`wire.horizon=1` from this peer and every member in
//! view, [`super::horizon`]) a withdrawal whose writers this peer vouches for goes ten minutes
//! after its lease's expiry instead. The longest lease is the longest observed in the space
//! (writes, renewals, and claims), capped at 24 hours. A received state already past its horizon
//! is refused at the door by the same rule and clock (a member re-offering what this peer
//! collected), and acknowledged in the space's digest when this peer holds no state of it; lapsed
//! claims of entries with no state go too. A space at its bound collects before it refuses a new
//! entry: at once for a write of this peer, at most once a second for received ones.
//!
//! # Renewals (SPEC §7.2)
//!
//! A renewal of a write, a take, or a subscription never shortens its lease: the new expiry is
//! `max(current, now + extension)`. One that would change nothing succeeds, sends nothing, and is
//! counted in [`PeerCounters::renew_shortenings`](crate::peer::PeerCounters::renew_shortenings)
//! when it asked for less than the lease had left. A take's renewal keeps its claim's epoch,
//! stamp, holder, and bid, so no watcher reads it as a new take.
//!
//! [`Peer`]: crate::peer::Peer

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use agentspaces_wire::bodies::{self, RUMOR_HOPS, STREAM_SPACE_PREFIX};
use agentspaces_wire::cbor::{self, Map, Value};
use agentspaces_wire::fold::{self, FoldContext, FoldOutcome, Refusal};
use agentspaces_wire::hlc::Stamp;
use agentspaces_wire::horizon;
use agentspaces_wire::identity::AgentIdentity;
use agentspaces_wire::ids;
use agentspaces_wire::records::{self, PayloadSource, WRITE_LEASE_KIND};
use tokio::time::Instant;

use super::{Actor, DEFAULT_AGENT_NAME, PeerError, PeerEvent, bump, fits_a_frame};
use crate::peer::spaces::{
    DISPLACED_PULL_MAX, Fired, MAX_TRACKED_LEASE_MILLIS, REOFFER_BACKOFF, REOFFER_MAX, Slot,
};
use crate::space::watch::{CloseReason, WatchQueue};
use crate::space::{
    Attestation, ClaimTicket, EntryId, EntryView, EventKind, ResultWrite, SpaceError, SpaceEvent,
    Template,
};

/// The longest the watch sweep waits while anything watches, whatever its next due: a backstop
/// for a lapse that moved earlier without lowering the sweep. The sweep otherwise runs when the
/// earliest lapse it tells falls due (SPEC v0.1.36 §9.5: "when the earliest lapse falls due",
/// where it ran four times a second before).
pub(in crate::peer) const SWEEP_BACKSTOP: Duration = Duration::from_secs(30);
/// How often transitions waiting for their payload's block are offered again, while any wait
/// (the block is asked for again at most this often too).
const DEFERRED_RETRY: Duration = Duration::from_secs(1);
/// The most transitions waiting for their payload's block.
pub(in crate::peer) const MAX_DEFERRED: usize = 4096;
/// The most watches a peer holds at once.
const MAX_WATCHERS: usize = 4096;
/// The most agent identities a peer keeps (their renewed certificates) between calls.
const MAX_HELD_AGENTS: usize = 4096;
/// How often every open space collects its tombstones ([module docs](self#collection)).
pub(in crate::peer) const COLLECT_INTERVAL: Duration = Duration::from_secs(5);
/// How often a full space collects for a received state at most.
const FULL_COLLECT_INTERVAL: Duration = Duration::from_secs(1);

/// One watch: its space, its template, and its queue.
pub(in crate::peer) struct Watcher {
    space: String,
    template: Template,
    queue: Arc<WatchQueue>,
}

/// A transition waiting for its entry's payload block.
pub(in crate::peer) struct Deferred {
    space: String,
    kind: EventKind,
    entry_id: String,
}

/// An entry's view, or why there is none yet.
enum Viewed {
    Ready(EntryView),
    /// The payload is a block not held yet; it has been asked for.
    Pending,
    /// No such entry, or a payload this peer cannot read (a content root, bytes that are not
    /// CBOR).
    Unreadable,
}

// ---------------------------------------------------------------------------------------------
// Reading states and claims

fn record_of(state: &Map) -> Option<&Map> {
    state.get("record").and_then(Value::as_map)
}

fn is_completed(state: &Map) -> bool {
    state.get("completed").and_then(Value::as_bool) == Some(true)
}

/// The lease in force: the joined register `leaseValue`, else the record's `lease`.
fn lease_of(state: &Map) -> Option<&Value> {
    state
        .get("leaseValue")
        .filter(|lease| lease.as_map().is_some())
        .or_else(|| record_of(state)?.get("lease"))
}

/// When the lease in force lapses.
fn write_expiry(state: &Map) -> Option<i64> {
    lease_of(state)?.get("expiresAtMillis")?.as_i64()
}

/// Whether the entry's write lease no longer holds at `now` (Java `liveRecords`: only a `WRITE`
/// lease lapses; a state without a readable lease is not live).
fn write_lapsed(state: &Map, now: i64) -> bool {
    let kind = lease_of(state)
        .and_then(|lease| lease.get("kind"))
        .and_then(Value::as_str);
    match write_expiry(state) {
        None => true,
        Some(_) if kind.is_some_and(|kind| kind != WRITE_LEASE_KIND) => false,
        Some(expires) => expires <= now,
    }
}

/// Whether a reader could see the entry: present (not completed, an add not removed) and its
/// write lease holding.
fn visible(state: &Map, now: i64) -> bool {
    fold::is_present(state) && !write_lapsed(state, now)
}

fn claim_live(claim: &Map, now: i64) -> bool {
    claim
        .get("expiresAtMillis")
        .and_then(Value::as_i64)
        .is_some_and(|expires| expires > now)
}

fn claim_epoch(claim: &Map) -> i64 {
    claim.get("epoch").and_then(Value::as_i64).unwrap_or(0)
}

fn claim_holder(claim: &Map) -> Option<&str> {
    claim.get("holder").and_then(Value::as_str)
}

/// Java `SpaceStateCrdt.collectable` under the legacy rule (SPEC §7.3): whether `state` is a
/// tombstone past its horizon at `now` in a space whose longest lease is `max_lease`
/// ([`horizon::collectable`]). A state without a readable lease is kept.
#[cfg(test)]
fn collectable(state: &Map, now: i64, max_lease: i64) -> bool {
    horizon::collectable(state, now, max_lease, horizon::Rule::Legacy)
}

/// The lease a state carries, milliseconds: its expiry less the physical time of its lease stamp
/// (else of its record's issue stamp), as Java observes `leaseValue.expiresAtMillis -
/// leaseStamp.physical`.
pub(in crate::peer) fn state_lease_span(state: &Map) -> Option<i64> {
    let expiry = write_expiry(state)?;
    let stamp = Stamp::of(state.get("leaseStamp"))
        .or_else(|| Stamp::of(record_of(state)?.get("issued")))?;
    expiry.checked_sub(stamp.physical)
}

/// The hold a signed claim asks for, milliseconds: its expiry less its stamp's physical time.
pub(in crate::peer) fn claim_lease_span(signed: &Map) -> Option<i64> {
    let claim = signed.get("claim")?.as_map()?;
    let expiry = claim.get("expiresAtMillis")?.as_i64()?;
    expiry.checked_sub(Stamp::of(claim.get("stamp"))?.physical)
}

/// The block a state's record names as its payload, if any.
fn block_of(state: &Map) -> Option<&str> {
    match record_of(state).and_then(records::payload_source)? {
        PayloadSource::Block(cid) => Some(cid),
        _ => None,
    }
}

/// Whether the tags of `state`'s record meet `template`'s tag conditions (read before the payload
/// is decoded, as Java checks type and tags before it decodes).
fn tags_match(template: &Template, state: &Map) -> bool {
    match record_of(state)
        .and_then(|record| record.get("tags"))
        .and_then(Value::as_map)
    {
        Some(tags) => template.conditions().matches_tags(tags),
        None => template.conditions().matches_tags(&Map::new()),
    }
}

/// The tracker of `entry_id`, made on first use.
/// When the sweep next has something to tell of one entry at `now` (epoch milliseconds): its
/// write lease's lapse (`Expired`) or its live claim's (`Reappeared`), `now` when one is past and
/// untold, `None` when nothing the clock decides is left (completed, withdrawn, told, or a lease
/// that never lapses).
fn entry_sweep_due(
    state: &Map,
    claim: Option<&Map>,
    fired: Option<&Fired>,
    now: i64,
) -> Option<i64> {
    if !fold::is_present(state) {
        return None;
    }
    let told = fired.cloned().unwrap_or_default();
    if write_lapsed(state, now) {
        return (!told.expired).then_some(now);
    }
    let kind = lease_of(state)
        .and_then(|lease| lease.get("kind"))
        .and_then(Value::as_str);
    let mut due = write_expiry(state).filter(|_| kind.is_none_or(|kind| kind == WRITE_LEASE_KIND));
    if let Some(claim) = claim {
        let expires = claim.get("expiresAtMillis").and_then(Value::as_i64);
        let at = match expires {
            Some(expires) if expires > now => Some(expires),
            _ => (told.reappeared != Some(claim_epoch(claim))).then_some(now),
        };
        due = [due, at].into_iter().flatten().min();
    }
    due
}

fn fired_mut<'a>(fired: &'a mut HashMap<String, Fired>, entry_id: &str) -> &'a mut Fired {
    fired.entry(entry_id.to_owned()).or_default()
}

/// The view of an entry without its payload (`Value::Null` in its place).
fn bare_view(entry_id: &str, state: &Map, claim: Option<&Map>, now: i64) -> Option<EntryView> {
    let record = record_of(state)?;
    let schema = record.get("type")?.as_str()?;
    let issuer = record.get("issuer")?.as_str()?;
    let completed = is_completed(state);
    let attested = state
        .get("agentCertificate")
        .is_some_and(|certificate| !certificate.is_null());
    let holder = claim
        .filter(|claim| completed || claim_live(claim, now))
        .and_then(claim_holder)
        .map(str::to_owned);
    Some(EntryView {
        entry_id: EntryId::new(entry_id),
        schema: schema.to_owned(),
        payload: Arc::new(Value::Null),
        tags: record
            .get("tags")
            .and_then(Value::as_map)
            .cloned()
            .unwrap_or_default(),
        issuer: issuer.to_owned(),
        issued: record
            .get("issued")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        attestation: if attested {
            Attestation::AgentAttested
        } else {
            Attestation::PeerAsserted
        },
        expires_at_millis: write_expiry(state).unwrap_or(0),
        completed,
        holder,
    })
}

fn stream_of(space: &str) -> String {
    format!("{STREAM_SPACE_PREFIX}{space}")
}

fn refused(entry_id: &str, refusal: Refusal) -> SpaceError {
    SpaceError::Refused {
        entry_id: EntryId::new(entry_id),
        refusal,
    }
}

impl Actor {
    // ----------------------------------------------------------------------------- agents

    /// The agent to act as: the copy this peer holds (so a certificate it renewed stays renewed
    /// across calls; a different key under the same id replaces it), renewed at half-life
    /// before it signs ([`AgentIdentity::renew_if_due`]). An agent of another peer is refused.
    pub(super) fn acting_agent(
        &mut self,
        agent: AgentIdentity,
        now: i64,
    ) -> Result<AgentIdentity, PeerError> {
        let owner = ids::parse_agent_id(agent.agent_id()).map(|(peer, _)| peer);
        if owner != Some(self.peer_id.as_str()) {
            return Err(PeerError::ForeignAgent(agent.agent_id().to_owned()));
        }
        let id = agent.agent_id().to_owned();
        let mut held = match self.agents.remove(&id) {
            Some(held) if held.public_raw() == agent.public_raw() => held,
            _ => agent,
        };
        let renewed = held.renew_if_due(&self.identity, now);
        let acting = held.clone();
        if self.agents.len() < MAX_HELD_AGENTS {
            self.agents.insert(id, held);
        }
        renewed?;
        Ok(acting)
    }

    /// The AgentID acting: the agent's, or this peer's default agent name.
    fn actor_id(&self, agent: Option<&AgentIdentity>) -> String {
        agent.map_or_else(
            || self.identity.agent(DEFAULT_AGENT_NAME),
            |agent| agent.agent_id().to_owned(),
        )
    }

    fn refuses(&self, holder: &str, agent: Option<&AgentIdentity>) -> bool {
        let key = agent.map(|agent| agent.public_raw().as_slice());
        self.registry.refuses(holder, key, None)
    }

    // ----------------------------------------------------------------------------- spaces

    /// Opens `space` and pulls it once (its first use), unless the peer is closed. A pull that
    /// cannot go out now goes out with the next link.
    pub(crate) fn space_open(&mut self, space: &str) -> Result<(), SpaceError> {
        if self.closed || self.pulled_spaces.contains(space) {
            return Ok(());
        }
        match self.pull_space(space) {
            Ok(()) | Err(PeerError::SendOverflow | PeerError::NotConnected) => {
                // The first pull counts for the pacing of the waiting reads and takes.
                self.last_pull.insert(space.to_owned(), Instant::now());
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Pulls `space` unless it was pulled within `settle` (`Peer.pull_space_paced`). Only the
    /// waiting reads and takes pull this way, so on a closed peer it answers [`PeerError::Closed`]:
    /// they end at once instead of waiting out their timeouts.
    pub(crate) fn space_pull_paced(
        &mut self,
        space: &str,
        settle: Duration,
    ) -> Result<(), SpaceError> {
        if self.closed {
            return Err(PeerError::Closed.into());
        }
        let now = Instant::now();
        if self
            .last_pull
            .get(space)
            .is_some_and(|at| now.duration_since(*at) < settle)
        {
            return Ok(());
        }
        match self.pull_space(space) {
            Ok(()) | Err(PeerError::SendOverflow | PeerError::NotConnected) => {
                self.last_pull.insert(space.to_owned(), now);
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    /// The view of an entry with its payload decoded (in place: a block is never copied).
    fn view_of(&mut self, space: &str, entry_id: &str, now: i64) -> Viewed {
        let (view, payload) = {
            let Some(slot) = self.spaces.get(space) else {
                return Viewed::Unreadable;
            };
            let Some(state) = slot.store.state(entry_id) else {
                return Viewed::Unreadable;
            };
            let Some(view) = bare_view(entry_id, state, slot.store.claim_of(entry_id), now) else {
                return Viewed::Unreadable;
            };
            let payload = match record_of(state).and_then(records::payload_source) {
                Some(PayloadSource::Inline(bytes)) => Ok(cbor::decode(bytes).ok()),
                Some(PayloadSource::Null) => Ok(Some(Value::Null)),
                Some(PayloadSource::Block(cid)) => match self.blocks.get(cid) {
                    Some(data) => Ok(cbor::decode(data).ok()),
                    None => Err((
                        cid.to_owned(),
                        state
                            .get("issuerPublicKey")
                            .and_then(Value::as_bytes)
                            .map(<[u8]>::to_vec),
                    )),
                },
                Some(PayloadSource::Content(_)) | None => Ok(None),
            };
            (view, payload)
        };
        match payload {
            Ok(Some(payload)) => Viewed::Ready(EntryView {
                payload: Arc::new(payload),
                ..view
            }),
            Ok(None) => Viewed::Unreadable,
            Err((cid, key)) => {
                self.want_block(&cid, key.as_deref());
                Viewed::Pending
            }
        }
    }

    /// An entry of `space` by id, completed or not, with its payload; `None` when not held (or
    /// its payload block is still on its way, which is then asked for).
    pub(crate) fn space_entry(&mut self, space: &str, entry_id: &str) -> Option<EntryView> {
        let now = self.now();
        match self.view_of(space, entry_id, now) {
            Viewed::Ready(view) => Some(view),
            Viewed::Pending | Viewed::Unreadable => None,
        }
    }

    /// The available entries of `space` matching `template` (Java `availableRecords`: live and
    /// unclaimed, [`fold::SpaceStore::available`]), at most `limit`, in the order they first
    /// folded. The schema and the tags are judged before a payload is decoded, and decoding
    /// stops at `limit` matches. An entry whose payload block is still on its way is skipped (and
    /// the block asked for). Opens and pulls the space on first use.
    pub(crate) fn space_find(
        &mut self,
        space: &str,
        template: &Template,
        limit: usize,
    ) -> Result<Vec<EntryView>, SpaceError> {
        self.space_open(space)?;
        let now = self.now();
        let candidates: Vec<String> = match self.spaces.get(space) {
            Some(slot) => slot
                .store
                .available(template.schema(), now)
                .into_iter()
                .filter(|(_, state)| tags_match(template, state))
                .map(|(entry_id, _)| entry_id.to_owned())
                .collect(),
            None => return Ok(Vec::new()),
        };
        let mut found = Vec::new();
        for entry_id in candidates {
            if found.len() >= limit {
                break;
            }
            if let Viewed::Ready(view) = self.view_of(space, &entry_id, now)
                && template.matches(&view.schema, &view.payload, &view.tags)
            {
                found.push(view);
            }
        }
        Ok(found)
    }

    /// How many available entries of `template`'s schema and tags this peer cannot read yet
    /// because their payload block is on its way; each is asked for again (at most once a
    /// second).
    pub(crate) fn space_pending(
        &mut self,
        space: &str,
        template: &Template,
    ) -> Result<usize, SpaceError> {
        self.space_open(space)?;
        let now = self.now();
        let candidates: Vec<String> = match self.spaces.get(space) {
            Some(slot) => slot
                .store
                .available(template.schema(), now)
                .into_iter()
                .filter(|(_, state)| tags_match(template, state))
                .map(|(entry_id, _)| entry_id.to_owned())
                .collect(),
            None => return Ok(0),
        };
        Ok(candidates
            .iter()
            .filter(|entry_id| matches!(self.view_of(space, entry_id, now), Viewed::Pending))
            .count())
    }

    // ----------------------------------------------------------------------------- writes

    /// Merges a claim this peer signed into `space` (Java `tryTakeOnce`'s merge): the lattice
    /// alone decides, since the claim is this peer's own.
    fn merge_own_claim(
        &mut self,
        space: &str,
        entry_id: &str,
        signed: &Map,
    ) -> Result<FoldOutcome, SpaceError> {
        let slot = self
            .spaces
            .get_mut(space)
            .ok_or_else(|| SpaceError::UnknownEntry(EntryId::new(entry_id)))?;
        let before = slot.store.claim_proof(entry_id).cloned();
        let outcome = slot.store.merge_own_claim(entry_id, signed);
        if outcome.is_applied()
            && let Some(span) = claim_lease_span(signed)
        {
            slot.observe_lease(span);
        }
        if matches!(outcome, FoldOutcome::Applied | FoldOutcome::Unchanged) {
            self.after_claim_merge(space, entry_id, before.as_ref(), signed);
        }
        if outcome.is_applied() {
            self.note_sweep_entry(space, entry_id);
        }
        match outcome {
            FoldOutcome::Refused(refusal) => return Err(refused(entry_id, refusal)),
            FoldOutcome::Applied => {
                self.emit(PeerEvent::ClaimFolded {
                    space: space.to_owned(),
                    entry_id: entry_id.to_owned(),
                });
                self.bump_folds();
                self.dial_rounds.note_activity();
            }
            FoldOutcome::Unchanged | FoldOutcome::Deferred => {}
        }
        Ok(outcome)
    }

    /// Folds a state this peer built; an error when its own fold refuses it.
    fn fold_own_state(&mut self, space: &str, entry_id: &str, dto: &Map) -> Result<(), SpaceError> {
        match self.fold_state(space, dto) {
            Some(FoldOutcome::Refused(refusal)) => Err(refused(entry_id, refusal)),
            Some(_) => Ok(()),
            None => Err(SpaceError::UnknownEntry(EntryId::new(entry_id))),
        }
    }

    /// Claims one candidate of a take (`peer.py`'s `take_entry` body, with the live re-check):
    /// `None` when, judged again now, the entry is no longer free (a live claim, completed,
    /// withdrawn, or lapsed), so a stale candidate costs no settle window. Otherwise the claim
    /// (epoch one past the held claim's, or 1; the stamp from this peer's clock for the holder;
    /// bid 0.0, LEASE_RACE) is signed by the agent or the peer, merged here, and rumored under
    /// `c:<entry id>:<stamp>`.
    pub(crate) fn space_claim(
        &mut self,
        space: &str,
        entry_id: &str,
        agent: Option<AgentIdentity>,
        lease_millis: i64,
    ) -> Result<Option<ClaimTicket>, SpaceError> {
        self.check_open()?;
        let now = self.now();
        let agent = agent
            .map(|agent| self.acting_agent(agent, now))
            .transpose()?;
        let holder = self.actor_id(agent.as_ref());
        if self.refuses(&holder, agent.as_ref()) {
            return Err(PeerError::Revoked(holder).into());
        }
        let expires_at = now
            .checked_add(lease_millis)
            .ok_or_else(|| SpaceError::InvalidLease("the lease overflows".to_owned()))?;
        let (space_id, epoch) = {
            let Some(slot) = self.spaces.get(space) else {
                return Ok(None);
            };
            let Some(state) = slot.store.state(entry_id) else {
                return Ok(None);
            };
            if !visible(state, now) {
                return Ok(None);
            }
            let current = slot.store.claim_of(entry_id);
            if current.is_some_and(|claim| claim_live(claim, now)) {
                return Ok(None);
            }
            let epoch = current.map_or(1, |claim| claim_epoch(claim).saturating_add(1));
            (slot.space_id.clone(), epoch)
        };
        let stamp = self.issuer_stamp(&holder, now)?;
        let claim =
            records::take_claim(entry_id, &space_id, epoch, &stamp, &holder, 0.0, expires_at);
        let signed = records::signed_claim(&claim, &self.identity, agent.as_ref())
            .map_err(PeerError::from)?;
        let body = bodies::rumor_body(
            &stream_of(space),
            &format!("c:{entry_id}:{stamp}"),
            RUMOR_HOPS,
            &records::claim_delta(entry_id, &signed),
        );
        fits_a_frame(&body)?;
        self.merge_own_claim(space, entry_id, &signed)?;
        self.send_or_hold(body);
        Ok(Some(ClaimTicket {
            epoch,
            holder,
            expires_at,
        }))
    }

    /// After a claim's settle window: whether the take won (Java `tryTakeOnce`'s check): the
    /// lattice still names `holder` at `epoch`, the claim is live, the entry is present, and the
    /// holder is not revoked. A win tells the watches `Taken` and answers the entry's view
    /// *without* its payload (`Value::Null`): the take keeps the payload its candidate carried
    /// (Java's `claimedValue`), which the entry's signed record fixes, so a payload block evicted
    /// from the fetched cache during the settle window cannot empty a won take.
    ///
    /// A claim that won after a holder it displaced completed the entry (that holder heard of
    /// this claim later than the settle window, [`Actor::note_outbid_completion`]) finds the work
    /// done: the take acknowledges that completion under this claim, with no result, and answers
    /// `None` (SPEC §7.4, the settle guarantee's second rule).
    pub(crate) fn space_settle(
        &mut self,
        space: &str,
        entry_id: &str,
        holder: &str,
        epoch: i64,
        agent: Option<AgentIdentity>,
    ) -> Option<EntryView> {
        let now = self.now();
        let (view, done_by_outbid) = {
            let slot = self.spaces.get_mut(space)?;
            let state = slot.store.state(entry_id)?;
            let claim = slot.store.claim_of(entry_id)?;
            let won = fold::is_present(state)
                && claim_holder(claim) == Some(holder)
                && claim_epoch(claim) == epoch
                && claim_live(claim, now)
                && !self.registry.refuses(holder, None, None);
            let done_by_outbid = won && slot.settle.outbid(entry_id) == Some(epoch);
            let view = if won {
                bare_view(entry_id, state, Some(claim), now)
            } else {
                None
            };
            if !done_by_outbid {
                slot.settle.take_outbid(entry_id);
            }
            (view?, done_by_outbid)
        };
        if done_by_outbid {
            // The completion finds the line, acknowledges, counts, and reports it by failing; a
            // claim lost meanwhile has nothing to acknowledge and fails the same way.
            let _ = self.space_complete(space, entry_id, holder, epoch, agent, None);
            return None;
        }
        self.fire_taken(space, entry_id);
        Some(view)
    }

    /// The take `holder` holds on `entry_id` now, for a take found by id ([`Space::held`]): the
    /// claim in force names `holder`, is live, and the entry is present (not completed or
    /// withdrawn) and its payload readable. Answers the claim's ticket and the entry; `None`
    /// otherwise (or while its payload block is on its way, which is then asked for).
    ///
    /// [`Space::held`]: crate::space::Space::held
    pub(crate) fn space_held(
        &mut self,
        space: &str,
        entry_id: &str,
        agent: Option<AgentIdentity>,
    ) -> Option<(ClaimTicket, EntryView)> {
        let now = self.now();
        let holder = self.actor_id(agent.as_ref());
        let ticket = {
            let slot = self.spaces.get(space)?;
            let state = slot.store.state(entry_id)?;
            let claim = slot.store.claim_of(entry_id)?;
            let held = fold::is_present(state)
                && claim_holder(claim) == Some(holder.as_str())
                && claim_live(claim, now);
            if !held || self.registry.refuses(&holder, None, None) {
                return None;
            }
            ClaimTicket {
                epoch: claim_epoch(claim),
                expires_at: claim
                    .get("expiresAtMillis")
                    .and_then(Value::as_i64)
                    .unwrap_or(now),
                holder,
            }
        };
        match self.view_of(space, entry_id, now) {
            Viewed::Ready(view) => Some((ticket, view)),
            Viewed::Pending | Viewed::Unreadable => None,
        }
    }

    /// Checks that `holder` still holds `entry_id` at `epoch` (live, the entry present) and
    /// answers the signed claim; [`SpaceError::NotHeld`] otherwise.
    /// Whether a take has lapsed (owner decision 2 of 2026-11-23): the claim this peer
    /// holds for `entry_id` is no longer `holder`'s at `epoch` (a better claim displaced it, or
    /// the entry was completed or withdrawn), or its wall-time lease has passed. A result that
    /// arrives after the lapse completes nothing ([`crate::agent::TakeContext::lapsed`]).
    pub(crate) fn space_take_lapsed(
        &self,
        space: &str,
        entry_id: &str,
        holder: &str,
        epoch: i64,
    ) -> bool {
        self.held_claim(space, entry_id, holder, epoch, self.now())
            .is_err()
    }

    fn held_claim(
        &self,
        space: &str,
        entry_id: &str,
        holder: &str,
        epoch: i64,
        now: i64,
    ) -> Result<(String, Map), SpaceError> {
        let not_held = || SpaceError::NotHeld(EntryId::new(entry_id));
        let slot = self.spaces.get(space).ok_or_else(not_held)?;
        let state = slot.store.state(entry_id).ok_or_else(not_held)?;
        let claim = slot.store.claim_of(entry_id).ok_or_else(not_held)?;
        let held = fold::is_present(state)
            && claim_holder(claim) == Some(holder)
            && claim_epoch(claim) == epoch
            && claim_live(claim, now);
        if !held {
            return Err(not_held());
        }
        Ok((slot.space_id.clone(), claim.clone()))
    }

    /// Renews a held take (Java `Taken.renew`, `peer.rb`'s `renew_claim`): the claim re-signed
    /// with the same epoch, stamp, holder, and bid and the expiry `max(current, now + lease)`
    /// (SPEC §7.2), which the lattice prefers, rumored under `c:<entry id>:renew:<expiry>`. A
    /// renewal that would not move the expiry sends nothing. Answers the expiry in force.
    pub(crate) fn space_renew_claim(
        &mut self,
        space: &str,
        entry_id: &str,
        holder: &str,
        epoch: i64,
        agent: Option<AgentIdentity>,
        lease_millis: i64,
    ) -> Result<i64, SpaceError> {
        self.check_open()?;
        let now = self.now();
        let agent = agent
            .map(|agent| self.acting_agent(agent, now))
            .transpose()?;
        let (space_id, current) = self.held_claim(space, entry_id, holder, epoch, now)?;
        if self.refuses(holder, agent.as_ref()) {
            // Java (v0.1.13): every receiver refuses the renewal; the take lapses.
            return Err(PeerError::Revoked(holder.to_owned()).into());
        }
        let asked = now
            .checked_add(lease_millis)
            .ok_or_else(|| SpaceError::InvalidLease("the lease overflows".to_owned()))?;
        let held_expiry = current
            .get("expiresAtMillis")
            .and_then(Value::as_i64)
            .unwrap_or(now);
        let expires_at = horizon::renewed_expiry(held_expiry, now, lease_millis);
        if asked < held_expiry {
            bump(&mut self.counters.renew_shortenings);
        }
        if expires_at == held_expiry {
            // The hold already runs at least that long, and a renewal never shortens it.
            return Ok(held_expiry);
        }
        let stamp = current
            .get("stamp")
            .and_then(Value::as_str)
            .ok_or_else(|| SpaceError::NotHeld(EntryId::new(entry_id)))?;
        let bid = current.get("bid").and_then(Value::as_f64).unwrap_or(0.0);
        let renewed =
            records::take_claim(entry_id, &space_id, epoch, stamp, holder, bid, expires_at);
        let signed = records::signed_claim(&renewed, &self.identity, agent.as_ref())
            .map_err(PeerError::from)?;
        let body = bodies::rumor_body(
            &stream_of(space),
            &format!("c:{entry_id}:renew:{expires_at}"),
            RUMOR_HOPS,
            &records::claim_delta(entry_id, &signed),
        );
        fits_a_frame(&body)?;
        self.merge_own_claim(space, entry_id, &signed)?;
        self.send_or_hold(body);
        Ok(self
            .spaces
            .get(space)
            .and_then(|slot| slot.store.claim_of(entry_id))
            .and_then(|claim| claim.get("expiresAtMillis"))
            .and_then(Value::as_i64)
            .unwrap_or(expires_at))
    }

    /// Completes a held take (Java `completeInternal`, `peer.py`'s `complete_entry`): the result,
    /// when given, is prepared first (its tags checked, room for it in the space, signed, its
    /// record judged as every member's fold will judge it, sized, its block held), so a result
    /// that cannot be written fails the completion before anything commits, with the take still
    /// held (Java's "#2 atomicity"); then the joined state is re-signed with `completed` set by
    /// the holder (the agent when the claim is the agent's), folded here, and rumored under
    /// `d:<entry id>` with the winning claim (`claimEntry`, `claim`) that authenticates it; then
    /// the result is written. Answers the result's id.
    pub(crate) fn space_complete(
        &mut self,
        space: &str,
        entry_id: &str,
        holder: &str,
        epoch: i64,
        agent: Option<AgentIdentity>,
        result: Option<ResultWrite>,
    ) -> Result<Option<EntryId>, SpaceError> {
        self.check_open()?;
        let now = self.now();
        let agent = agent
            .map(|agent| self.acting_agent(agent, now))
            .transpose()?;
        self.held_claim(space, entry_id, holder, epoch, now)?;
        if self.refuses(holder, agent.as_ref()) {
            return Err(PeerError::Revoked(holder.to_owned()).into());
        }
        // A holder this claim displaced completed the entry after this take was judged (SPEC
        // §7.4): this completion acknowledges that one, and the result is not written.
        let outbid = self
            .spaces
            .get_mut(space)
            .and_then(|slot| slot.settle.take_outbid(entry_id));
        if outbid == Some(epoch) {
            self.commit_completion(space, entry_id, agent.as_ref(), now)?;
            bump(&mut self.counters.outbid_acknowledged);
            return Err(SpaceError::CompletedByDisplaced(EntryId::new(entry_id)));
        }
        let prepared = match result {
            Some(result) => {
                let prepared = self.prepare_write(
                    space,
                    &result.schema,
                    &result.payload,
                    result.lease_millis,
                    &result.tags,
                    agent.clone(),
                )?;
                if !self.prepared_verifies(&prepared, now) {
                    // Every member's fold would refuse this record: refuse it before the
                    // completion commits.
                    let entry_id = prepared.entry_id.clone();
                    self.discard_write(prepared);
                    return Err(refused(&entry_id, Refusal::UnverifiedRecord));
                }
                Some(prepared)
            }
            None => None,
        };
        if let Err(error) = self.commit_completion(space, entry_id, agent.as_ref(), now) {
            if let Some(prepared) = prepared {
                self.discard_write(prepared);
            }
            return Err(error);
        }
        // This holder did the work, so a displaced holder's completion arriving later is a
        // duplicate (SPEC §7.4, the settle guarantee's third rule).
        if let Some(slot) = self.spaces.get_mut(space) {
            slot.settle.note_completed_here(entry_id, epoch);
        }
        match prepared {
            Some(prepared) => Ok(Some(EntryId::new(self.commit_write(space, prepared)?))),
            None => Ok(None),
        }
    }

    /// The completion half of [`Actor::space_complete`]: the joined state re-signed with
    /// `completed` set by the holder, folded here, and rumored with the winning claim.
    fn commit_completion(
        &mut self,
        space: &str,
        entry_id: &str,
        agent: Option<&AgentIdentity>,
        now: i64,
    ) -> Result<(), SpaceError> {
        let (mut dto, proof) = {
            let slot = self
                .spaces
                .get(space)
                .ok_or_else(|| SpaceError::NotHeld(EntryId::new(entry_id)))?;
            let state = slot
                .store
                .state(entry_id)
                .ok_or_else(|| SpaceError::NotHeld(EntryId::new(entry_id)))?;
            (state.clone(), slot.store.claim_proof(entry_id).cloned())
        };
        dto.insert("completed", true);
        let signed_at = agent
            .map(|agent| self.issuer_stamp(agent.agent_id(), now))
            .transpose()?;
        let signed = records::sign_state(&dto, &self.identity, agent.zip(signed_at.as_deref()))
            .map_err(PeerError::from)?;
        let delta = records::delta(Some(&signed), proof.as_ref().map(|proof| (entry_id, proof)));
        let body = bodies::rumor_body(
            &stream_of(space),
            &format!("d:{entry_id}"),
            RUMOR_HOPS,
            &delta,
        );
        fits_a_frame(&body)?;
        self.fold_own_state(space, entry_id, &signed)?;
        self.send_or_hold(body);
        Ok(())
    }

    /// Whether the acting agent (or, without one, this peer) is the issuer of `state`'s record
    /// and may act on it: an agent-attested entry only by that agent (since v0.1.13).
    fn require_issuer(
        &self,
        entry_id: &str,
        state: &Map,
        agent: Option<&AgentIdentity>,
    ) -> Result<String, SpaceError> {
        let issuer = record_of(state)
            .and_then(|record| record.get("issuer"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let attested = state
            .get("agentCertificate")
            .is_some_and(|certificate| !certificate.is_null());
        let mine = match agent {
            Some(agent) => agent.agent_id() == issuer,
            None => {
                !attested
                    && ids::parse_agent_id(issuer).map(|(peer, _)| peer)
                        == Some(self.peer_id.as_str())
            }
        };
        if mine {
            Ok(issuer.to_owned())
        } else {
            Err(SpaceError::NotIssuer {
                entry_id: EntryId::new(entry_id),
                issuer: issuer.to_owned(),
                actor: self.actor_id(agent),
            })
        }
    }

    /// The joined state of an entry of `space`.
    fn joined_state(&self, space: &str, entry_id: &str) -> Result<Map, SpaceError> {
        self.spaces
            .get(space)
            .and_then(|slot| slot.store.state(entry_id))
            .cloned()
            .ok_or_else(|| SpaceError::UnknownEntry(EntryId::new(entry_id)))
    }

    /// Re-signs `dto` as the acting agent (or this peer), folds it here, and rumors it under
    /// `item` (the issuer's transitions: a renewal or a cancellation).
    fn publish_issuer_state(
        &mut self,
        space: &str,
        entry_id: &str,
        dto: &Map,
        agent: Option<&AgentIdentity>,
        item: &str,
        now: i64,
    ) -> Result<(), SpaceError> {
        let signed_at = agent
            .map(|agent| self.issuer_stamp(agent.agent_id(), now))
            .transpose()?;
        let signed = records::sign_state(dto, &self.identity, agent.zip(signed_at.as_deref()))
            .map_err(PeerError::from)?;
        let body = bodies::rumor_body(
            &stream_of(space),
            item,
            RUMOR_HOPS,
            &records::delta(Some(&signed), None),
        );
        fits_a_frame(&body)?;
        self.fold_own_state(space, entry_id, &signed)?;
        self.send_or_hold(body);
        Ok(())
    }

    /// Renews a write this peer (or its agent) issued (`peer.py`'s `renew_entry`, Java
    /// `Handle.renew`): a later lease stamp and the lease `{holder: issuer, expiresAtMillis:
    /// max(current, now + lease), kind: WRITE}` (SPEC §7.2), re-signed by the issuer, rumored under
    /// `r:<entry id>:<lease stamp>`. A renewal that would not move the expiry succeeds and sends
    /// nothing. A lapsed, completed, or withdrawn entry is [`SpaceError::LeaseLapsed`]; only the
    /// issuer renews ([`SpaceError::NotIssuer`]).
    pub(crate) fn space_renew_write(
        &mut self,
        space: &str,
        entry_id: &str,
        agent: Option<AgentIdentity>,
        lease_millis: i64,
    ) -> Result<(), SpaceError> {
        self.check_open()?;
        let now = self.now();
        let agent = agent
            .map(|agent| self.acting_agent(agent, now))
            .transpose()?;
        let mut dto = self.joined_state(space, entry_id)?;
        if !visible(&dto, now) {
            return Err(SpaceError::LeaseLapsed(EntryId::new(entry_id)));
        }
        let issuer = self.require_issuer(entry_id, &dto, agent.as_ref())?;
        if self.refuses(&issuer, agent.as_ref()) {
            return Err(PeerError::Revoked(issuer).into());
        }
        let asked = now
            .checked_add(lease_millis)
            .ok_or_else(|| SpaceError::InvalidLease("the lease overflows".to_owned()))?;
        let current = write_expiry(&dto).unwrap_or(now);
        let expires_at = horizon::renewed_expiry(current, now, lease_millis);
        if asked < current {
            bump(&mut self.counters.renew_shortenings);
        }
        if expires_at == current {
            // The lease already runs at least that long, and a renewal never shortens it.
            return Ok(());
        }
        let lease_stamp = self.issuer_stamp(&issuer, now)?;
        dto.insert("leaseStamp", lease_stamp.as_str());
        dto.insert(
            "leaseValue",
            agentspaces_wire::cbor_map! {
                "holder" => issuer.as_str(),
                "expiresAtMillis" => expires_at,
                "kind" => WRITE_LEASE_KIND,
            },
        );
        let item = format!("r:{entry_id}:{lease_stamp}");
        self.publish_issuer_state(space, entry_id, &dto, agent.as_ref(), &item, now)
    }

    /// Withdraws a write this peer (or its agent) issued (Java `Handle.cancel`, `peer.ts`'s
    /// `cancelEntry`): its `removes` come to cover its `adds`, re-signed by the issuer, rumored
    /// under `x:<entry id>`; every replica then reads the entry as gone. Idempotent; an entry
    /// already completed (by whichever member took it) answers `Ok` and sends nothing.
    pub(crate) fn space_cancel(
        &mut self,
        space: &str,
        entry_id: &str,
        agent: Option<AgentIdentity>,
    ) -> Result<(), SpaceError> {
        self.check_open()?;
        let now = self.now();
        let agent = agent
            .map(|agent| self.acting_agent(agent, now))
            .transpose()?;
        let mut dto = self.joined_state(space, entry_id)?;
        let issuer = self.require_issuer(entry_id, &dto, agent.as_ref())?;
        if self.refuses(&issuer, agent.as_ref()) {
            return Err(PeerError::Revoked(issuer).into());
        }
        if is_completed(&dto) {
            // Already gone on every replica: nothing to withdraw. A completed state's party is
            // its claim holder, so a state the issuer signed would be refused everywhere,
            // here too.
            return Ok(());
        }
        let removes = fold::union_dots(dto.get("removes"), dto.get("adds"));
        dto.insert("removes", removes);
        let item = format!("x:{entry_id}");
        self.publish_issuer_state(space, entry_id, &dto, agent.as_ref(), &item, now)
    }

    // ----------------------------------------------------------------------------- collection

    /// Folds a state received for `space` (a rumor's or a pull response's): a state already past
    /// its collection horizon is refused at the door (SPEC §7.3, Java `mergeState`: a member that
    /// collects later, or never, would otherwise bounce it back as new), judged by the rule and
    /// the clock the space's sweep uses, with its own lease counted in the space's longest, as
    /// Java observes it first, and acknowledged when this space holds no state of its entry; a
    /// new entry for a full space first collects the space (at most once every
    /// [`FULL_COLLECT_INTERVAL`]).
    pub(super) fn fold_remote_state(&mut self, space: &str, dto: &Map) -> Option<FoldOutcome> {
        let now = self.now();
        let mut collect = false;
        if self.spaces.contains(space) {
            let rule = self.horizon_rule(space, now);
            let slot = self.spaces.get(space)?;
            let own_span =
                state_lease_span(dto).map_or(0, |span| span.min(MAX_TRACKED_LEASE_MILLIS));
            if self.collects(rule, dto, now, slot.max_lease.max(own_span)) {
                self.counters.space_reoffers_refused =
                    self.counters.space_reoffers_refused.saturating_add(1);
                self.acknowledge_collected(space, dto, now);
                return Some(FoldOutcome::Unchanged);
            }
            let slot = self.spaces.get(space)?;
            let entry_id = record_of(dto)
                .and_then(|record| record.get("entryId"))
                .and_then(Value::as_str);
            collect = entry_id.is_some_and(|id| slot.store.state(id).is_none())
                && slot.store.len() >= slot.store.max_entries()
                && slot
                    .full_collected
                    .is_none_or(|at| at.elapsed() >= FULL_COLLECT_INTERVAL);
        }
        if collect {
            if let Some(slot) = self.spaces.get_mut(space) {
                slot.full_collected = Some(Instant::now());
            }
            self.collect_spaces(&[space.to_owned()], now);
        }
        let outcome = self.fold_state(space, dto);
        if let Some(outcome) = outcome {
            self.after_remote_state(space, dto, outcome);
        }
        outcome
    }

    /// Judges a completion of `space` this peer refused, received with the claim `proof` it
    /// travelled with (`claim_entry`, already folded), when a claim of one of this peer's own
    /// holders displaces `proof` in the lattice (Java `noteOutbidCompletion`). The displaced
    /// holder judged its take before this peer's claim reached it, later than the settle window
    /// (SPEC §7.4, the settle guarantee), ran its action and completed; its completion fails to
    /// authenticate against the claim held here, so it stays dropped, as SPEC §11a.4 has every
    /// replica do. When it authenticates under its own claim, and its holder is not revoked:
    ///
    /// - while this peer still holds the entry present under a live claim, the completion is
    ///   noted, so this peer's take, when it is judged, or its completion, when it comes,
    ///   acknowledges it with no result instead of doing the work again
    ///   ([`PeerCounters::outbid_acknowledged`]);
    /// - when this peer's holder already completed the entry with its own work at the held
    ///   claim's epoch, both did the work: the duplicate is counted, once per entry
    ///   ([`PeerCounters::duplicate_completions`]).
    ///
    /// A displaced claim at a lower epoch counts too: its holder never heard of the claim this
    /// peer saw lapse, so it claimed afresh, which only late delivery allows.
    ///
    /// [`PeerCounters::outbid_acknowledged`]: crate::peer::PeerCounters::outbid_acknowledged
    /// [`PeerCounters::duplicate_completions`]: crate::peer::PeerCounters::duplicate_completions
    pub(super) fn note_outbid_completion(
        &mut self,
        space: &str,
        claim_entry: &str,
        proof: &Map,
        received: &Map,
    ) {
        if !is_completed(received) {
            return;
        }
        let Some(entry_id) = records::state_entry_id(received) else {
            return;
        };
        let Some(displaced) = proof.get("claim").and_then(Value::as_map) else {
            return;
        };
        if entry_id != claim_entry
            || displaced.get("entryId").and_then(Value::as_str) != Some(entry_id)
        {
            return;
        }
        let now = self.now();
        let Some(slot) = self.spaces.get(space) else {
            return;
        };
        let (Some(held_proof), Some(state)) =
            (slot.store.claim_proof(entry_id), slot.store.state(entry_id))
        else {
            return;
        };
        let Some(held) = held_proof.get("claim").and_then(Value::as_map) else {
            return;
        };
        let (Some(held_holder), Some(displaced_holder)) =
            (claim_holder(held), claim_holder(displaced))
        else {
            return;
        };
        let ours = held_holder.split('/').next() == Some(self.peer_id.as_str());
        let held_epoch = claim_epoch(held);
        if !ours
            || held_holder == displaced_holder
            || claim_epoch(displaced) > held_epoch
            || records::merge_claims(Some(held_proof), proof) != *held_proof
        {
            return;
        }
        let duplicate = if fold::is_present(state) {
            if !claim_live(held, now)
                || !claim_live(displaced, now)
                || slot.settle.outbid(entry_id) == Some(held_epoch)
            {
                return;
            }
            false
        } else if is_completed(state) && slot.settle.completed_here(entry_id) == Some(held_epoch) {
            true
        } else {
            return;
        };
        let ctx = FoldContext::new(now, &self.registry).with_space(&slot.space_id);
        if !slot
            .store
            .authenticates_completion_under(received, proof, &ctx)
        {
            return;
        }
        let entry_id = entry_id.to_owned();
        let Some(slot) = self.spaces.get_mut(space) else {
            return;
        };
        if !duplicate {
            slot.settle.note_outbid(&entry_id, held_epoch);
        } else if slot.settle.take_completed_here(&entry_id, held_epoch) {
            bump(&mut self.counters.duplicate_completions);
            tracing::info!(
                peer = %self.peer_id,
                space,
                entry = %entry_id,
                displaced = displaced_holder,
                "agentspaces: an entry was completed twice: here, and by a holder whose claim lost \
                 the race but heard of the winner later than the settle window (SPEC 7.4); the \
                 shared state keeps one completion"
            );
        }
    }

    /// After a received or own claim of `entry_id` merged into `space` (applied or unchanged),
    /// with `before` the claim held until then: when the lattice kept one claim of two held by
    /// different holders, notes what rule two of the settle guarantee needs (SPEC v0.1.36 §7.4,
    /// *Pairing the evidence*; Java `mergeHeldClaim`).
    pub(super) fn after_claim_merge(
        &mut self,
        space: &str,
        entry_id: &str,
        before: Option<&Map>,
        incoming: &Map,
    ) {
        let Some(before) = before else {
            return;
        };
        let Some(kept) = self
            .spaces
            .get(space)
            .and_then(|slot| slot.store.claim_proof(entry_id))
            .cloned()
        else {
            return;
        };
        let lost = if kept == *before { incoming } else { before };
        self.note_displaced(space, entry_id, &kept, lost);
    }

    /// Keeps what rule two of the settle guarantee needs once the lattice kept `kept` over `lost`
    /// for `entry_id` (Java `noteDisplaced`): the displaced claim, when one of this peer's holders
    /// holds the kept one (it is judged at once against the completions dropped here for want of
    /// it); and this peer's own completion's claim, when `lost` is the claim one of this peer's
    /// holders completed under (it is offered again, [`Actor::offer_displaced`]). Every claim
    /// reaching here was verified or signed here. A renewal or an attestation upgrade of one
    /// holder's claim displaces nobody.
    fn note_displaced(&mut self, space: &str, entry_id: &str, kept: &Map, lost: &Map) {
        let (Some(kept_claim), Some(lost_claim)) = (
            kept.get("claim").and_then(Value::as_map),
            lost.get("claim").and_then(Value::as_map),
        ) else {
            return;
        };
        if kept_claim == lost_claim {
            return;
        }
        let (Some(kept_holder), Some(lost_holder)) =
            (claim_holder(kept_claim), claim_holder(lost_claim))
        else {
            return;
        };
        if kept_holder == lost_holder {
            return;
        }
        let ours = |holder: &str| holder.split('/').next() == Some(self.peer_id.as_str());
        let (kept_ours, lost_ours) = (ours(kept_holder), ours(lost_holder));
        let lost_epoch = claim_epoch(lost_claim);
        let Some(slot) = self.spaces.get_mut(space) else {
            return;
        };
        if lost_ours && !kept_ours {
            // The claim made here that this peer first lost on the entry, whether or not one of
            // its holders completed under it: what a relayed DIGEST draws (owner decision 1).
            slot.settle.note_displaced_here(entry_id, lost);
        }
        if kept_ours {
            slot.settle.note_displaced_claim(entry_id, lost);
            let unproven = slot.settle.unproven(entry_id) > 0;
            if !lost_ours && let Some(lost_peer) = lost_holder.split('/').next() {
                // The targeted rounds toward the displaced holder (owner decision 4), due at
                // once for a new line.
                let due = slot
                    .settle
                    .note_displaced_holder(entry_id, lost_peer, Instant::now());
                self.lower_displaced_pull_due(due);
            }
            if unproven {
                self.judge_displaced(space, entry_id);
            }
        } else if lost_ours
            && slot.settle.completed_here(entry_id) == Some(lost_epoch)
            && slot.settle.start_reoffer(entry_id, lost, Instant::now())
        {
            self.offer_displaced(space, entry_id);
        }
    }

    /// After a received state of `space` folded with `outcome`: a completion dropped while one
    /// of this peer's holders holds the entry's claim is kept, as it may be a displaced holder's
    /// whose claim comes in another frame (Java `rememberUnproven`), and judged against the
    /// displaced claims kept; a state that still shows the entry open makes this peer's own
    /// displaced claim due again once its backoff has passed (Java `staleOffered`).
    pub(super) fn after_remote_state(&mut self, space: &str, dto: &Map, outcome: FoldOutcome) {
        let Some(entry_id) = records::state_entry_id(dto) else {
            return;
        };
        if !is_completed(dto) {
            let due = self
                .spaces
                .get_mut(space)
                .and_then(|slot| slot.settle.reoffer_mut(entry_id))
                .is_some_and(|line| Instant::now() >= line.next_at);
            if due {
                self.offer_displaced(space, entry_id);
            }
            return;
        }
        if !matches!(outcome, FoldOutcome::Refused(_) | FoldOutcome::Unchanged) {
            return;
        }
        let Some(slot) = self.spaces.get_mut(space) else {
            return;
        };
        let Some(held_holder) = slot
            .store
            .claim_of(entry_id)
            .and_then(claim_holder)
            .map(str::to_owned)
        else {
            return;
        };
        if held_holder.split('/').next() != Some(self.peer_id.as_str())
            || dto.get("signer").and_then(Value::as_str) == Some(held_holder.as_str())
        {
            // Not this peer's claim, or the held claim's own completion coming back.
            return;
        }
        if slot.settle.note_unproven(entry_id, dto) {
            self.judge_displaced(space, entry_id);
        }
    }

    /// Judges each completion dropped here for `entry_id` against each claim this peer's claim
    /// displaced for it (Java `judgeDisplaced`): the pair authenticates a displaced holder's
    /// completion as the delta that first carried both would have, whichever frames brought
    /// them; [`Actor::note_outbid_completion`] makes every check it makes for that delta.
    fn judge_displaced(&mut self, space: &str, entry_id: &str) {
        let Some((claims, states)) = self
            .spaces
            .get(space)
            .and_then(|slot| slot.settle.pairs(entry_id))
        else {
            return;
        };
        for state in &states {
            let signer = state.get("signer").and_then(Value::as_str);
            for claim in &claims {
                let holder = claim
                    .get("claim")
                    .and_then(Value::as_map)
                    .and_then(claim_holder);
                if signer.is_none() || signer == holder {
                    self.note_outbid_completion(space, entry_id, claim, state);
                }
            }
        }
    }

    /// Offers again this peer's displaced claim of `entry_id` when it is due, as the claim delta
    /// it first travelled in (under the same item id), and moves its next offer back: at once,
    /// then no sooner than 1 s, 2 s, 4 s, and so on after the previous offer, at most
    /// [`REOFFER_MAX`] offers in all (SPEC v0.1.36 §7.4; the lenient retries of §9.4). The line
    /// goes once its offers are spent, its claim lapsed, its stamp is half the drift ceiling old
    /// (past which a replica holding the better claim would refuse it as a far-past contest), or
    /// the entry left the store. Nothing runs while no frame shows the entry open.
    pub(super) fn offer_displaced(&mut self, space: &str, entry_id: &str) {
        let wall = self.now();
        let now = Instant::now();
        let Some(slot) = self.spaces.get_mut(space) else {
            return;
        };
        let gone = slot.store.state(entry_id).is_none();
        let Some(line) = slot.settle.reoffer_mut(entry_id) else {
            return;
        };
        let claim = line.proof.get("claim").and_then(Value::as_map);
        let stamp = claim
            .and_then(|claim| claim.get("stamp"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        let physical = stamp
            .as_deref()
            .and_then(Stamp::parse)
            .map(|stamp| stamp.physical);
        let spent = line.offers >= REOFFER_MAX
            || gone
            || !claim.is_some_and(|claim| claim_live(claim, wall))
            || physical.is_none_or(|physical| {
                wall.saturating_sub(physical) > agentspaces_wire::limits::MAX_DRIFT_MILLIS / 2
            });
        if spent {
            slot.settle.end_reoffer(entry_id);
            return;
        }
        if now < line.next_at {
            return;
        }
        let backoff = REOFFER_BACKOFF.saturating_mul(1u32 << line.offers.min(30));
        line.next_at = now.checked_add(backoff).unwrap_or(now);
        line.offers = line.offers.saturating_add(1);
        let proof = line.proof.clone();
        let Some(stamp) = stamp else {
            return;
        };
        let body = bodies::rumor_body(
            &stream_of(space),
            &format!("c:{entry_id}:{stamp}"),
            RUMOR_HOPS,
            &records::claim_delta(entry_id, &proof),
        );
        bump(&mut self.counters.displaced_reoffers);
        self.send_or_hold(body);
    }

    /// Forgets the displaced claims made here in `space` no longer worth sending (Java
    /// `pruneDisplacedHere`): the entry left the store, the claim lapsed, or its stamp nears the
    /// drift ceiling, as a re-offer judges. Answers whether a displaced claim is still held
    /// there (Java `holdsDisplaced`), so a relayed DIGEST naming the space draws an answer.
    pub(super) fn holds_displaced(&mut self, space: &str) -> bool {
        let wall = self.now();
        let Some(slot) = self.spaces.get_mut(space) else {
            return false;
        };
        let store = &slot.store;
        slot.settle.prune_displaced_here(|entry_id, lost| {
            let claim = lost.get("claim").and_then(Value::as_map);
            let physical = claim
                .and_then(|claim| claim.get("stamp"))
                .and_then(Value::as_str)
                .and_then(Stamp::parse)
                .map(|stamp| stamp.physical);
            store.state(entry_id).is_some()
                && claim.is_some_and(|claim| claim_live(claim, wall))
                && physical.is_some_and(|physical| {
                    wall.saturating_sub(physical) <= agentspaces_wire::limits::MAX_DRIFT_MILLIS / 2
                })
        });
        slot.settle
            .displaced_lines()
            .iter()
            .any(|(entry_id, _)| slot.store.state(entry_id).is_some())
    }

    /// Brings the targeted rounds' deadline forward to `due` ([`Actor::run_displaced_pulls`]).
    pub(super) fn lower_displaced_pull_due(&mut self, due: Instant) {
        self.displaced_pull_due = Some(self.displaced_pull_due.map_or(due, |at| at.min(due)));
    }

    /// The targeted anti-entropy rounds toward displaced holders that are due (Java
    /// `pullDisplacedHolders`, owner decision 4 of 2026-11-23). While one of this peer's holders
    /// holds an entry's winning claim and the entry is still present here, each holder that
    /// claim displaced is sent a round of this peer's digests ([`Actor::round_with`]): at once,
    /// then after 1, 2, 4, 8 and 16 s, at most [`DISPLACED_PULL_MAX`] rounds, on the monotonic
    /// clock. A displaced holder's completion may have only one source, the holder, and a round
    /// repairs its opener, so this peer learns of it within one round rather than waiting for
    /// its periodic round's random partner to be that holder. A line ends once the take is no
    /// longer open here: the claim is no longer this peer's or lapsed, the entry is no longer
    /// present (completed here or elsewhere, or withdrawn), or the displaced completion is
    /// already noted. No wire change: a round is the usual `DIGEST`.
    pub(super) fn run_displaced_pulls(&mut self) {
        let wall = self.now();
        let now = Instant::now();
        let mut partners: Vec<String> = Vec::new();
        let mut next: Option<Instant> = None;
        let me = self.peer_id.clone();
        for name in self.spaces.names() {
            let Some(slot) = self.spaces.get_mut(&name) else {
                continue;
            };
            for entry_id in slot.settle.displaced_pull_entries() {
                let held = slot.store.claim_of(&entry_id);
                let open = held.is_some_and(|claim| {
                    claim_holder(claim).and_then(|holder| holder.split('/').next())
                        == Some(me.as_str())
                        && claim_live(claim, wall)
                        && slot.settle.outbid(&entry_id) != Some(claim_epoch(claim))
                }) && slot.store.state(&entry_id).is_some_and(fold::is_present);
                let Some(pull) = slot.settle.displaced_pull_mut(&entry_id) else {
                    continue;
                };
                if !open || pull.rounds >= DISPLACED_PULL_MAX {
                    slot.settle.end_displaced_pull(&entry_id);
                    continue;
                }
                if now >= pull.next_at {
                    for holder in &pull.holders {
                        if !partners.contains(holder) {
                            partners.push(holder.clone());
                        }
                    }
                    let backoff = REOFFER_BACKOFF.saturating_mul(1u32 << pull.rounds.min(30));
                    pull.next_at = now.checked_add(backoff).unwrap_or(now);
                    pull.rounds = pull.rounds.saturating_add(1);
                    if pull.rounds >= DISPLACED_PULL_MAX {
                        slot.settle.end_displaced_pull(&entry_id);
                        continue;
                    }
                }
                next = Some(next.map_or(pull.next_at, |at: Instant| at.min(pull.next_at)));
            }
        }
        self.displaced_pull_due = next;
        for partner in partners {
            bump(&mut self.counters.displaced_pull_rounds);
            tracing::debug!(
                peer = %self.peer_id,
                partner = %partner,
                "agentspaces: a targeted anti-entropy round toward a holder this peer's claim displaced"
            );
            self.round_with(&partner);
        }
    }

    /// Whether `space` has room for one more entry, collecting it first when it is full.
    pub(super) fn space_has_room(&mut self, space: &str, now: i64) -> bool {
        let room = |slot: &Slot| slot.store.len() < slot.store.max_entries();
        match self.spaces.get(space) {
            None => return true,
            Some(slot) if room(slot) => return true,
            Some(_) => {}
        }
        self.collect_spaces(&[space.to_owned()], now);
        self.spaces.get(space).is_some_and(room)
    }

    /// The collection timer: every open space collects its tombstones.
    pub(super) fn on_collect(&mut self) {
        self.collect_now();
    }

    /// Every open space collects its tombstones now; how many entries went.
    pub(crate) fn collect_now(&mut self) -> usize {
        self.last_collect = Instant::now();
        let now = self.now();
        let names = self.spaces.names();
        self.collect_spaces(&names, now)
    }

    /// Collects the tombstones of `spaces` past their horizon ([module docs](self#collection)),
    /// after the watch sweep has told what lapsed. Answers how many entries went.
    fn collect_spaces(&mut self, spaces: &[String], now: i64) -> usize {
        if self.watching() {
            // `Expired` and `Reappeared` are told before their entries go (Java's sweep fires,
            // then collects).
            self.on_sweep();
        }
        let mut released = Vec::new();
        let mut gone: HashSet<(String, String)> = HashSet::new();
        let mut count = 0usize;
        for space in spaces {
            if !self.spaces.contains(space) {
                continue;
            }
            let rule = self.horizon_rule(space, now);
            let tombstones: Vec<String> = match self.spaces.get(space) {
                Some(slot) => slot
                    .store
                    .states()
                    .filter(|(_, state)| self.collects(rule, state, now, slot.max_lease))
                    .map(|(entry_id, _)| entry_id.to_owned())
                    .collect(),
                None => continue,
            };
            let Some(slot) = self.spaces.get_mut(space) else {
                continue;
            };
            slot.store.forget_acknowledged(now);
            // Claims fold before their states; a lapsed one whose state never came (or was
            // refused at the door) takes nothing and is kept by nothing.
            let orphans: Vec<String> = slot
                .store
                .claims()
                .filter(|(entry_id, signed)| {
                    slot.store.state(entry_id).is_none()
                        && !signed
                            .get("claim")
                            .and_then(Value::as_map)
                            .is_some_and(|claim| claim_live(claim, now))
                })
                .map(|(entry_id, _)| entry_id.to_owned())
                .collect();
            for entry_id in tombstones {
                if let Some(state) = slot.store.remove(&entry_id) {
                    released.extend(block_of(&state).map(str::to_owned));
                }
                slot.forget_size(&entry_id);
                slot.fired.remove(&entry_id);
                slot.settle.forget(&entry_id);
                gone.insert((space.clone(), entry_id));
                count = count.saturating_add(1);
            }
            for entry_id in orphans {
                slot.store.remove(&entry_id);
                slot.forget_size(&entry_id);
                count = count.saturating_add(1);
            }
        }
        if !gone.is_empty() {
            self.deferred.retain(|deferred| {
                !gone.contains(&(deferred.space.clone(), deferred.entry_id.clone()))
            });
        }
        self.release_blocks(released);
        self.counters.space_collected = self
            .counters
            .space_collected
            .saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
        count
    }

    /// Releases the blocks `cids` (as in Java, a collected entry unpins its block), but those
    /// an entry still held in any space names.
    pub(super) fn release_blocks(&mut self, cids: impl IntoIterator<Item = String>) {
        let mut cids: BTreeSet<String> = cids.into_iter().collect();
        if cids.is_empty() {
            return;
        }
        'scan: for slot in self.spaces.iter() {
            for (_, state) in slot.store.states() {
                if let Some(cid) = block_of(state) {
                    cids.remove(cid);
                    if cids.is_empty() {
                        break 'scan;
                    }
                }
            }
        }
        for cid in cids {
            self.blocks.release(&cid);
        }
    }

    // ----------------------------------------------------------------------------- watches

    /// Adds a watch of `space` for `template` delivering into `queue`. Opens and pulls the
    /// space on first use. The first watch of a space marks the lapses already past as told, so
    /// a watch hears of what happens from now on.
    pub(crate) fn space_watch(
        &mut self,
        space: &str,
        template: Template,
        queue: Arc<WatchQueue>,
    ) -> Result<(), SpaceError> {
        if self.closed {
            queue.close(CloseReason::PeerClosed);
            return Ok(());
        }
        if queue.closed().is_some() {
            // Its owner went away before this job ran (a dropped `watch` future): nobody would
            // ever read or close it.
            return Ok(());
        }
        self.space_open(space)?;
        if self.spaces.slot(space).is_none() {
            return Err(PeerError::InvalidArgument(format!("cannot open space {space:?}")).into());
        }
        self.watchers
            .retain(|watcher| watcher.queue.closed().is_none());
        if self.watchers.len() >= MAX_WATCHERS {
            return Err(PeerError::InvalidArgument(format!(
                "this peer already holds {MAX_WATCHERS} watches"
            ))
            .into());
        }
        if !self.watchers.iter().any(|watcher| watcher.space == space) {
            let now = self.now();
            if let Some(slot) = self.spaces.get_mut(space) {
                mark_past_lapses(slot, now);
            }
        }
        if self.watchers.is_empty() {
            self.last_sweep = Instant::now();
        }
        let lapses = self.watch_lapse_wall(queue.expires_at());
        self.watchers.push(Watcher {
            space: space.to_owned(),
            template,
            queue,
        });
        // The new watch's lapse, and its space's lapses if it is the first to watch it.
        self.lower_sweep(lapses);
        let now = self.now();
        let due = self.space_sweep_due(space, now);
        if let Some(due) = due {
            self.lower_sweep(due);
        }
        Ok(())
    }

    /// When the watch sweep runs next while anything watches: the earliest lapse it tells
    /// ([`Actor::sweep_due`], wall time re-anchored on every call), at most
    /// [`SWEEP_BACKSTOP`] after the last sweep, and within [`DEFERRED_RETRY`] while transitions
    /// wait for their block. `None` while nothing watches.
    pub(super) fn sweep_at(&self) -> Option<Instant> {
        if !self.watching() {
            return None;
        }
        let now = Instant::now();
        let due = self
            .sweep_due
            .map(|at| super::serve::wall_due(now, self.now(), at));
        let backstop = self.last_sweep.checked_add(SWEEP_BACKSTOP);
        let deferred = if self.deferred.is_empty() {
            None
        } else {
            self.last_sweep.checked_add(DEFERRED_RETRY)
        };
        [due, backstop, deferred].into_iter().flatten().min()
    }

    /// Runs the watch sweep no later than `at_ms` (epoch milliseconds).
    fn lower_sweep(&mut self, at_ms: i64) {
        self.sweep_due = Some(self.sweep_due.map_or(at_ms, |due| due.min(at_ms)));
    }

    /// The earliest lapse the sweep tells in `space`, if anything watches it.
    fn space_sweep_due(&self, space: &str, now: i64) -> Option<i64> {
        if !self.watchers.iter().any(|watcher| watcher.space == space) {
            return None;
        }
        let slot = self.spaces.get(space)?;
        slot.store
            .states()
            .filter_map(|(entry_id, state)| {
                entry_sweep_due(
                    state,
                    slot.store.claim_of(entry_id),
                    slot.fired.get(entry_id),
                    now,
                )
            })
            .min()
    }

    /// Lowers the sweep to what `entry_id` of `space` next has to tell, if anything watches it:
    /// called after a state or claim of it applied.
    fn note_sweep_entry(&mut self, space: &str, entry_id: &str) {
        if !self.watchers.iter().any(|watcher| watcher.space == space) {
            return;
        }
        let now = self.now();
        let due = self.spaces.get(space).and_then(|slot| {
            entry_sweep_due(
                slot.store.state(entry_id)?,
                slot.store.claim_of(entry_id),
                slot.fired.get(entry_id),
                now,
            )
        });
        if let Some(due) = due {
            self.lower_sweep(due);
        }
    }

    /// Whether anything watches (the sweep runs only then).
    pub(super) fn watching(&self) -> bool {
        !self.watchers.is_empty()
    }

    /// The transitions after a state of `entry_id` folded (applied) into `space`: `Written` at
    /// the first fold of a live entry, `Completed` when the joined state turned completed. An
    /// entry first learned already completed (SPEC §7.2, *Completed on arrival*) was never
    /// present here: it raises no `Written` (nor `Taken`, which needs a present entry), and
    /// `Completed` only when its value is held here already; no block is fetched for it.
    pub(super) fn after_state(&mut self, space: &str, entry_id: &str, is_new: bool) {
        let now = self.now();
        let (written, completed) = {
            let Some(Slot { store, fired, .. }) = self.spaces.get_mut(space) else {
                return;
            };
            let Some(state) = store.state(entry_id) else {
                return;
            };
            let written = is_new && visible(state, now);
            let tracker = fired_mut(fired, entry_id);
            let completed = is_completed(state) && !tracker.completed;
            if completed {
                tracker.completed = true;
            }
            (written, completed)
        };
        if written {
            self.deliver(space, EventKind::Written, entry_id);
        }
        if completed {
            if is_new {
                if self.value_held(space, entry_id) {
                    self.deliver(space, EventKind::Completed, entry_id);
                }
            } else {
                self.deliver(space, EventKind::Completed, entry_id);
            }
        }
        self.note_sweep_entry(space, entry_id);
    }

    /// Whether an entry's value is available here without fetching anything: an inline or null
    /// payload, or a block already held.
    fn value_held(&self, space: &str, entry_id: &str) -> bool {
        let Some(state) = self
            .spaces
            .get(space)
            .and_then(|slot| slot.store.state(entry_id))
        else {
            return false;
        };
        match record_of(state).and_then(records::payload_source) {
            Some(PayloadSource::Inline(_) | PayloadSource::Null) => true,
            Some(PayloadSource::Block(cid)) => self.blocks.get(cid).is_some(),
            Some(PayloadSource::Content(_)) | None => false,
        }
    }

    /// The transition after a member's claim on `entry_id` won the lattice in `space`: `Taken`,
    /// once per epoch and holder, while the claim is live and the entry present.
    pub(super) fn after_claim(&mut self, space: &str, entry_id: &str) {
        self.fire_taken(space, entry_id);
        self.note_sweep_entry(space, entry_id);
    }

    /// Tells `Taken` for the claim in force on `entry_id`, unless already told for its epoch
    /// and holder (or it is not live, or the entry is not present).
    fn fire_taken(&mut self, space: &str, entry_id: &str) {
        let now = self.now();
        {
            let Some(Slot { store, fired, .. }) = self.spaces.get_mut(space) else {
                return;
            };
            let (Some(state), Some(claim)) = (store.state(entry_id), store.claim_of(entry_id))
            else {
                return;
            };
            if !fold::is_present(state) || !claim_live(claim, now) {
                return;
            }
            let key = (
                claim_epoch(claim),
                claim_holder(claim).unwrap_or_default().to_owned(),
            );
            let tracker = fired_mut(fired, entry_id);
            if tracker.taken.as_ref() == Some(&key) {
                return;
            }
            tracker.taken = Some(key);
        }
        self.deliver(space, EventKind::Taken, entry_id);
    }

    /// The sweep (`space.py`'s `_sweep`, Java `sweepLocked`): ends the watches closed or lapsed,
    /// derives `Expired` and `Reappeared` in the watched spaces, and retries the transitions
    /// waiting for a block.
    pub(super) fn on_sweep(&mut self) {
        self.last_sweep = Instant::now();
        let now = self.now();
        let local = self.clock.local_ms();
        self.watchers.retain(|watcher| {
            if watcher.queue.closed().is_some() {
                return false;
            }
            if watcher.queue.lapsed(local) {
                watcher.queue.close(CloseReason::Lapsed);
                return false;
            }
            true
        });
        let watched: BTreeSet<String> = self
            .watchers
            .iter()
            .map(|watcher| watcher.space.clone())
            .collect();
        let mut transitions = Vec::new();
        for space in watched {
            let Some(Slot { store, fired, .. }) = self.spaces.get_mut(&space) else {
                continue;
            };
            for (entry_id, state) in store.states() {
                if !fold::is_present(state) {
                    continue;
                }
                if write_lapsed(state, now) {
                    let tracker = fired_mut(fired, entry_id);
                    if !tracker.expired {
                        tracker.expired = true;
                        transitions.push((space.clone(), EventKind::Expired, entry_id.to_owned()));
                    }
                    continue;
                }
                if let Some(claim) = store.claim_of(entry_id)
                    && !claim_live(claim, now)
                {
                    let epoch = claim_epoch(claim);
                    let tracker = fired_mut(fired, entry_id);
                    if tracker.reappeared != Some(epoch) {
                        tracker.reappeared = Some(epoch);
                        transitions.push((
                            space.clone(),
                            EventKind::Reappeared,
                            entry_id.to_owned(),
                        ));
                    }
                }
            }
        }
        for (space, kind, entry_id) in transitions {
            self.deliver(&space, kind, &entry_id);
        }
        self.retry_deferred();
        // The next due: the earliest lapse still to tell, or a watch's own.
        let now = self.now();
        let spaces: BTreeSet<String> = self
            .watchers
            .iter()
            .map(|watcher| watcher.space.clone())
            .collect();
        let entries = spaces
            .iter()
            .filter_map(|space| self.space_sweep_due(space, now));
        let watches = self
            .watchers
            .iter()
            .map(|watcher| self.watch_lapse_wall(watcher.queue.expires_at()));
        self.sweep_due = entries.chain(watches).min();
    }

    /// A watch's lapse, kept on the clock's local base (a subscription's lease is a local period,
    /// SPEC v0.1.36 §9.5), as the wall instant the sweep's due is kept in at this reading. A wall
    /// step asks the sweep again at once ([`Actor::on_wall_step`]), which re-reads it.
    fn watch_lapse_wall(&self, local: i64) -> i64 {
        if local == i64::MAX {
            return i64::MAX;
        }
        self.now()
            .saturating_add(local.saturating_sub(self.clock.local_ms()))
    }

    /// A wall step (SPEC v0.1.36 §9.5): the sweep runs at once while anything watches, so the
    /// lapses it keeps in wall time are read again.
    pub(super) fn sweep_after_wall_step(&mut self) {
        if self.watching() {
            let now = self.now();
            self.lower_sweep(now);
        }
    }

    /// Offers one transition to the watches of `space` whose templates match; one whose payload
    /// block is not held yet waits for it.
    fn deliver(&mut self, space: &str, kind: EventKind, entry_id: &str) {
        if !self
            .watchers
            .iter()
            .any(|watcher| watcher.space == space && watcher.queue.closed().is_none())
        {
            return;
        }
        let now = self.now();
        let view = match self.view_of(space, entry_id, now) {
            Viewed::Ready(view) => view,
            Viewed::Pending => {
                if self.deferred.len() >= MAX_DEFERRED {
                    self.deferred.pop_front();
                    self.counters.deferred_events_dropped =
                        self.counters.deferred_events_dropped.saturating_add(1);
                }
                self.deferred.push_back(Deferred {
                    space: space.to_owned(),
                    kind,
                    entry_id: entry_id.to_owned(),
                });
                return;
            }
            Viewed::Unreadable => return,
        };
        let event = SpaceEvent { kind, entry: view };
        let local = self.clock.local_ms();
        self.watchers.retain(|watcher| {
            if watcher.queue.closed().is_some() {
                return false;
            }
            if watcher.space != space {
                return true;
            }
            if watcher.queue.lapsed(local) {
                watcher.queue.close(CloseReason::Lapsed);
                return false;
            }
            if watcher.template.matches(
                &event.entry.schema,
                &event.entry.payload,
                &event.entry.tags,
            ) {
                watcher.queue.push(event.clone());
            }
            true
        });
    }

    /// Offers again the transitions that waited for a block (a block arrived, or the sweep). A
    /// `Written` is offered only while its entry is still present and unexpired (SPEC §7.2): one
    /// that completed meanwhile raises its `Completed` alone, and one withdrawn or lapsed raises
    /// nothing.
    pub(super) fn retry_deferred(&mut self) {
        if self.deferred.is_empty() {
            return;
        }
        let now = self.now();
        let waiting = std::mem::take(&mut self.deferred);
        for deferred in waiting {
            if deferred.kind == EventKind::Written
                && !self
                    .spaces
                    .get(&deferred.space)
                    .and_then(|slot| slot.store.state(&deferred.entry_id))
                    .is_some_and(|state| visible(state, now))
            {
                continue;
            }
            self.deliver(&deferred.space, deferred.kind, &deferred.entry_id);
        }
    }

    /// Closes `space` ([`Peer::close_space`](crate::peer::Peer::close_space)): its slot, its
    /// pull bookkeeping, and the transitions waiting for its blocks go; refused (`false`) while a
    /// live watch follows it.
    pub(crate) fn close_space(&mut self, space: &str) -> bool {
        self.watchers
            .retain(|watcher| watcher.queue.closed().is_none());
        if self.watchers.iter().any(|watcher| watcher.space == space) {
            return false;
        }
        // The space's stamp counts outlive it (SPEC §9: a counter only grows).
        if let Some(slot) = self.spaces.get(space) {
            let counters = &mut self.counters;
            counters.stamps_logical_refused = counters
                .stamps_logical_refused
                .saturating_add(slot.store.stamps_logical_refused());
            counters.stamps_far_future_refused = counters
                .stamps_far_future_refused
                .saturating_add(slot.store.stamps_far_future_refused());
            counters.stamps_far_future_deferred = counters
                .stamps_far_future_deferred
                .saturating_add(slot.store.stamps_far_future_deferred());
        }
        let closed = self.spaces.remove(space);
        self.pulled_spaces.remove(space);
        self.last_pull.remove(space);
        self.deferred.retain(|deferred| deferred.space != space);
        closed
    }

    /// How many spaces are open.
    pub(crate) fn open_spaces(&self) -> usize {
        self.spaces.len()
    }

    /// Ends every watch: the peer closed.
    pub(super) fn close_watches(&mut self) {
        for watcher in self.watchers.drain(..) {
            watcher.queue.close(CloseReason::PeerClosed);
        }
        self.deferred.clear();
    }
}

/// Marks the lapses already past in `slot` as told (a space's first watch hears what happens
/// from now on): `Expired` for open entries whose write lease lapsed, `Reappeared` for the
/// lapsed claim epochs of open entries.
fn mark_past_lapses(slot: &mut Slot, now: i64) {
    let Slot { store, fired, .. } = slot;
    for (entry_id, state) in store.states() {
        if !fold::is_present(state) {
            continue;
        }
        if write_lapsed(state, now) {
            fired_mut(fired, entry_id).expired = true;
        } else if let Some(claim) = store.claim_of(entry_id)
            && !claim_live(claim, now)
        {
            fired_mut(fired, entry_id).reappeared = Some(claim_epoch(claim));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentspaces_wire::cbor_map;

    fn state(lease: Value, completed: bool, removed: bool) -> Map {
        let dot = cbor_map! { "replica" => "p", "counter" => 1 };
        cbor_map! {
            "record" => cbor_map! { "type" => "T#v1", "issuer" => "p/a", "lease" => lease.clone() },
            "adds" => vec![dot.clone()],
            "removes" => if removed { vec![dot] } else { Vec::new() },
            "leaseValue" => lease,
            "completed" => completed,
        }
        .into_map()
        .unwrap_or_default()
    }

    fn lease(expires: i64, kind: &str) -> Value {
        cbor_map! { "holder" => "p/a", "expiresAtMillis" => expires, "kind" => kind }
    }

    #[test]
    fn only_a_write_lease_lapses_and_only_a_present_entry_is_visible() {
        assert!(visible(&state(lease(10, "WRITE"), false, false), 9));
        assert!(!visible(&state(lease(10, "WRITE"), false, false), 10));
        assert!(visible(&state(lease(10, "TAKE"), false, false), 99));
        assert!(!visible(&state(lease(10, "WRITE"), true, false), 0));
        assert!(!visible(&state(lease(10, "WRITE"), false, true), 0));
        assert!(write_lapsed(&Map::new(), 0), "no lease is no live entry");
    }

    #[test]
    fn tombstones_are_collectable_past_their_horizon_as_java_judges_them() {
        let minute = 60_000;
        // A live entry never is, however long ago the longest lease.
        assert!(!collectable(
            &state(lease(100, "WRITE"), false, false),
            99,
            0
        ));
        // A lapsed one: twice the longest lease, at most five minutes.
        let lapsed = state(lease(100, "WRITE"), false, false);
        assert!(!collectable(&lapsed, 100 + 2 * 50 - 1, 50));
        assert!(collectable(&lapsed, 100 + 2 * 50, 50));
        assert!(!collectable(&lapsed, 100 + 5 * minute - 1, 60 * minute));
        assert!(collectable(&lapsed, 100 + 5 * minute, 60 * minute));
        // A completed or withdrawn one: twice the longest lease, whatever its length.
        for done in [
            state(lease(100, "WRITE"), true, false),
            state(lease(100, "WRITE"), false, true),
        ] {
            assert!(!collectable(&done, 99, 0), "not before its lease lapsed");
            assert!(!collectable(&done, 100 + 2 * 60 * minute - 1, 60 * minute));
            assert!(collectable(&done, 100 + 2 * 60 * minute, 60 * minute));
        }
        // A completed one at once under a zero longest lease; a withdrawn one never before the
        // drift floor, ten minutes past its lease (SPEC §7.3, v0.1.35).
        assert!(collectable(
            &state(lease(100, "WRITE"), true, false),
            100,
            0
        ));
        let withdrawn = state(lease(100, "WRITE"), false, true);
        assert!(!collectable(&withdrawn, 100 + 10 * minute - 1, 0));
        assert!(collectable(&withdrawn, 100 + 10 * minute, 0));
        // A present entry under a lease of another kind never lapses, so never goes.
        assert!(!collectable(
            &state(lease(100, "TAKE"), false, false),
            i64::MAX,
            0
        ));
        // No readable lease: kept. An overflowing horizon: kept.
        assert!(!collectable(&Map::new(), i64::MAX, 0));
        let far = state(lease(i64::MAX - 1, "WRITE"), true, false);
        assert!(!collectable(&far, i64::MAX, i64::MAX));
    }

    #[test]
    fn lease_spans_run_from_their_stamps() {
        let mut dto = state(lease(10_500, "WRITE"), false, false);
        dto.insert("leaseStamp", "10000:0:p");
        assert_eq!(state_lease_span(&dto), Some(500));
        let signed = cbor_map! {
            "claim" => cbor_map! { "expiresAtMillis" => 70_000, "stamp" => "10000:3:p/a" },
        }
        .into_map()
        .unwrap_or_default();
        assert_eq!(claim_lease_span(&signed), Some(60_000));
        assert_eq!(claim_lease_span(&Map::new()), None);
    }

    #[test]
    fn views_name_the_holder_of_a_live_or_completing_claim() {
        let claim = cbor_map! { "holder" => "p/b", "expiresAtMillis" => 5, "epoch" => 2 }
            .into_map()
            .unwrap_or_default();
        let open = state(lease(100, "WRITE"), false, false);
        let live = bare_view("e", &open, Some(&claim), 4).map(|view| view.holder);
        assert_eq!(live, Some(Some("p/b".to_owned())));
        let lapsed = bare_view("e", &open, Some(&claim), 5).map(|view| view.holder);
        assert_eq!(lapsed, Some(None));
        let done = state(lease(100, "WRITE"), true, false);
        let completed = bare_view("e", &done, Some(&claim), 50).map(|view| view.holder);
        assert_eq!(completed, Some(Some("p/b".to_owned())));
        assert_eq!(claim_epoch(&claim), 2);
    }
}

/// Rule two of the settle guarantee with its evidence in different frames, and the displaced
/// holder's re-offer (SPEC v0.1.36 §7.4, *Pairing the evidence*), between two actors with no link:
/// each frame one sends waits in its outbox, and the test hands it to the other as the frames
/// the race would have carried.
#[cfg(test)]
mod settle_pairing_tests {
    use std::sync::Arc;
    use std::time::Duration;

    use agentspaces_wire::audit::{self as wire_audit, DigestBody};
    use agentspaces_wire::bodies::{self, Rumor};
    use agentspaces_wire::cbor::{Map, Value};
    use agentspaces_wire::records;

    use super::super::serve::RELAYED_ANSWER_BURST;
    use super::super::tests::test_actor;
    use super::super::{Actor, Via};
    use super::claim_epoch;
    use crate::clock::ManualClock;

    const SPACE: &str = "tasks";
    const T0: i64 = 1_900_000_000_000;

    /// An actor on a manual wall clock reading `at`, its space opened.
    fn actor(at: i64) -> (Actor, ManualClock) {
        let (mut actor, ..) = test_actor();
        let clock = ManualClock::new(at);
        actor.clock = Arc::new(clock.clone());
        actor.space_open(SPACE).expect("open");
        actor.outbox.clear();
        (actor, clock)
    }

    /// The rumors `actor` sent since the last call.
    fn sent(actor: &mut Actor) -> Vec<Rumor> {
        actor
            .outbox
            .drain(..)
            .filter_map(|body| bodies::parse_rumor(&body))
            .collect()
    }

    fn deliver(actor: &mut Actor, rumor: &Rumor) {
        let _ = actor.on_rumor(rumor.clone(), Via::Dialed);
    }

    /// `rumor`'s delta with its claim removed: the completion alone, as a replica that merged
    /// the better claim offers it.
    fn state_alone(rumor: &Rumor) -> Rumor {
        let delta = records::decode_delta(&rumor.payload).expect("a delta");
        let state = delta.state.expect("a state");
        Rumor {
            payload: records::delta(Some(&state), None),
            ..rumor.clone()
        }
    }

    /// The race: `w` writes the entry and claims it first (the earlier stamp, so its claim wins
    /// the lattice); `l` never hears of that claim, claims later, judges itself the winner, and
    /// completes. Answers the entry id, `w`'s epoch, and the rumors: `w`'s write, `w`'s claim,
    /// `l`'s claim, and `l`'s completion (with its claim).
    struct Race {
        entry: String,
        w_epoch: i64,
        l_epoch: i64,
        write: Rumor,
        w_claim: Rumor,
        l_claim: Rumor,
        l_completion: Rumor,
    }

    fn run_race(w: &mut Actor, l: &mut Actor, l_completes: bool) -> Race {
        let entry = w
            .write_entry(
                SPACE,
                "T#v1",
                &Value::from("work"),
                120_000,
                &Map::new(),
                None,
            )
            .expect("write");
        let write = sent(w).remove(0);
        deliver(l, &write);
        let w_ticket = w
            .space_claim(SPACE, &entry, None, 60_000)
            .expect("claim")
            .expect("free");
        let w_claim = sent(w).remove(0);
        let l_ticket = l
            .space_claim(SPACE, &entry, None, 60_000)
            .expect("claim")
            .expect("free here: l never heard of w's claim");
        let l_claim = sent(l).remove(0);
        assert!(
            l.space_settle(SPACE, &entry, &l_ticket.holder, l_ticket.epoch, None)
                .is_some(),
            "l judges its take alone and wins"
        );
        let mut l_completion = l_claim.clone();
        if l_completes {
            l.space_complete(SPACE, &entry, &l_ticket.holder, l_ticket.epoch, None, None)
                .expect("l completes");
            l_completion = sent(l).remove(0);
        }
        Race {
            entry,
            w_epoch: w_ticket.epoch,
            l_epoch: l_ticket.epoch,
            write,
            w_claim,
            l_claim,
            l_completion,
        }
    }

    fn outbid(actor: &Actor, entry: &str) -> Option<i64> {
        actor
            .spaces
            .get(SPACE)
            .and_then(|slot| slot.settle.outbid(entry))
    }

    #[tokio::test]
    async fn a_displaced_claim_heard_first_pairs_with_its_completion_arriving_alone() {
        let (mut w, _) = actor(T0);
        let (mut l, _) = actor(T0 + 10);
        let race = run_race(&mut w, &mut l, true);

        deliver(&mut w, &race.l_claim);
        let slot = w.spaces.get(SPACE).expect("space");
        assert_eq!(
            slot.settle.displaced_claims(&race.entry),
            1,
            "kept as evidence"
        );
        assert_eq!(outbid(&w, &race.entry), None, "no completion yet");

        deliver(&mut w, &state_alone(&race.l_completion));
        assert_eq!(
            outbid(&w, &race.entry),
            Some(race.w_epoch),
            "the pair from two frames authenticates l's completion"
        );
        let holder = w.actor_id(None);
        assert!(
            w.space_settle(SPACE, &race.entry, &holder, race.w_epoch, None)
                .is_none(),
            "w's take acknowledges l's completion instead of doing the work"
        );
        assert_eq!(w.counters.outbid_acknowledged, 1);
    }

    #[tokio::test]
    async fn a_completion_heard_first_pairs_with_its_claim_arriving_later() {
        let (mut w, _) = actor(T0);
        let (mut l, _) = actor(T0 + 10);
        let race = run_race(&mut w, &mut l, true);

        deliver(&mut w, &state_alone(&race.l_completion));
        let slot = w.spaces.get(SPACE).expect("space");
        assert_eq!(slot.settle.unproven(&race.entry), 1, "kept, unproven");
        assert_eq!(outbid(&w, &race.entry), None);

        deliver(&mut w, &race.l_claim);
        assert_eq!(outbid(&w, &race.entry), Some(race.w_epoch));
    }

    /// The control: before the pairing, only the one frame carrying both halves taught the
    /// winner (the delta with its claim still works); a claim with no completion pairs nothing.
    #[tokio::test]
    async fn the_same_frame_still_pairs_and_a_claim_alone_pairs_nothing() {
        let (mut w, _) = actor(T0);
        let (mut l, _) = actor(T0 + 10);
        let race = run_race(&mut w, &mut l, true);
        deliver(&mut w, &race.l_completion);
        assert_eq!(outbid(&w, &race.entry), Some(race.w_epoch));

        let (mut w, _) = actor(T0);
        let (mut l, _) = actor(T0 + 10);
        let race = run_race(&mut w, &mut l, false);
        deliver(&mut w, &race.l_claim);
        assert_eq!(outbid(&w, &race.entry), None, "nothing completed");
    }

    /// The memory is bounded: at most four completions per entry, the oldest going.
    #[tokio::test]
    async fn at_most_four_unproven_completions_are_kept_per_entry() {
        let (mut w, _) = actor(T0);
        let (mut l, _) = actor(T0 + 10);
        let race = run_race(&mut w, &mut l, true);
        let alone = state_alone(&race.l_completion);
        let mut delta = records::decode_delta(&alone.payload)
            .and_then(|delta| delta.state)
            .expect("state");
        for n in 0..6u8 {
            delta.insert("stateSig", Value::Bytes(vec![n; 64]));
            let rumor = Rumor {
                payload: records::delta(Some(&delta), None),
                ..alone.clone()
            };
            deliver(&mut w, &rumor);
        }
        let slot = w.spaces.get(SPACE).expect("space");
        assert_eq!(slot.settle.unproven(&race.entry), 4);
    }

    /// The displaced holder: it completed, then adopted the better claim. It offers its claim at
    /// once, then again only when a frame shows the entry open and the backoff (1 s, 2 s, 4 s,
    /// ...) has passed, at most six times in all.
    #[tokio::test(start_paused = true)]
    async fn the_displaced_holder_reoffers_its_claim_with_a_doubling_backoff_six_times_at_most() {
        let (mut w, _) = actor(T0);
        let (mut l, l_clock) = actor(T0 + 10);
        let race = run_race(&mut w, &mut l, true);

        deliver(&mut l, &race.w_claim);
        let offered = sent(&mut l);
        assert_eq!(
            offered.len(),
            1,
            "offered at once on adopting the better claim"
        );
        assert_eq!(
            offered[0].item_id, race.l_claim.item_id,
            "under its first item id"
        );
        assert_eq!(
            offered[0].payload, race.l_claim.payload,
            "the claim delta it first sent"
        );
        assert_eq!(l.counters.displaced_reoffers, 1);

        // A frame showing the entry open before the backoff: nothing.
        deliver(&mut l, &race.write);
        assert!(sent(&mut l).is_empty(), "not before 1 s");
        let mut offers = 1;
        for backoff in [1u64, 2, 4, 8, 16, 32] {
            tokio::time::advance(Duration::from_millis(backoff * 1000 - 1)).await;
            deliver(&mut l, &race.write);
            assert!(sent(&mut l).is_empty(), "not before {backoff} s");
            tokio::time::advance(Duration::from_millis(1)).await;
            l_clock.advance(1);
            deliver(&mut l, &race.write);
            let again = sent(&mut l).len();
            if offers < 6 {
                assert_eq!(again, 1, "offer {} after {backoff} s", offers + 1);
                offers += 1;
            } else {
                assert_eq!(again, 0, "six offers at most");
            }
        }
        assert_eq!(l.counters.displaced_reoffers, 6);
        assert!(
            !l.spaces
                .get(SPACE)
                .expect("space")
                .settle
                .reoffering(&race.entry)
        );
        // A completion frame (the entry not open) never asks for an offer.
        deliver(&mut l, &race.l_completion);
        assert!(sent(&mut l).is_empty());
    }

    /// The backoff between offers is a local period on the monotonic clock (owner decision of
    /// 2026-11-23): a wall step forward does not bring the next offer early, and a step back does
    /// not hold it back.
    #[tokio::test(start_paused = true)]
    async fn the_reoffer_backoff_ignores_a_wall_step() {
        let (mut w, _) = actor(T0);
        let (mut l, l_clock) = actor(T0 + 10);
        let race = run_race(&mut w, &mut l, true);
        deliver(&mut l, &race.w_claim);
        assert_eq!(sent(&mut l).len(), 1, "offered at once");

        // The wall clock jumps 30 s ahead (the claim, leased 60 s, is still live); the monotonic
        // clock has not moved, so the 1 s backoff has not passed.
        l_clock.advance(30_000);
        deliver(&mut l, &race.write);
        assert!(
            sent(&mut l).is_empty(),
            "a forward step brings nothing early"
        );

        // The wall clock steps back 20 s, and 1 s passes on the monotonic clock: the backoff has
        // passed, whatever the wall clock reads.
        l_clock.advance(-20_000);
        tokio::time::advance(Duration::from_secs(1)).await;
        deliver(&mut l, &race.write);
        assert_eq!(sent(&mut l).len(), 1, "a step back holds nothing back");

        // The next backoff (2 s) runs from that offer on the monotonic clock alone.
        l_clock.advance(10_000);
        tokio::time::advance(Duration::from_millis(1_999)).await;
        deliver(&mut l, &race.write);
        assert!(sent(&mut l).is_empty(), "not before 2 s");
        tokio::time::advance(Duration::from_millis(1)).await;
        deliver(&mut l, &race.write);
        assert_eq!(sent(&mut l).len(), 1);
        assert_eq!(l.counters.displaced_reoffers, 3);
    }

    /// A lapsed claim is not offered again: the line ends.
    #[tokio::test(start_paused = true)]
    async fn a_lapsed_displaced_claim_is_not_offered_again() {
        let (mut w, _) = actor(T0);
        let (mut l, l_clock) = actor(T0 + 10);
        let race = run_race(&mut w, &mut l, true);
        deliver(&mut l, &race.w_claim);
        assert_eq!(sent(&mut l).len(), 1);
        tokio::time::advance(Duration::from_secs(2)).await;
        l_clock.advance(61_000);
        deliver(&mut l, &race.write);
        assert!(sent(&mut l).is_empty(), "the claim lapsed");
        assert!(
            !l.spaces
                .get(SPACE)
                .expect("space")
                .settle
                .reoffering(&race.entry)
        );
    }

    /// The kinds and addressees of the frames the far end of `theirs` received since the last
    /// call, with their bodies (taken without moving paused time).
    async fn frames_on(
        theirs: &mut crate::transport::Channel,
    ) -> Vec<(String, Option<String>, Vec<u8>)> {
        let mut frames = Vec::new();
        let mut idle = 0;
        while idle < 16 {
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
            let Some(env) = agentspaces_wire::envelope::decode_frame(&frame) else {
                continue;
            };
            let kind = env.get("kind").and_then(Value::as_str).unwrap_or_default();
            let to = env.get("to").and_then(Value::as_str).map(str::to_owned);
            let body = env
                .get("body")
                .and_then(Value::as_bytes)
                .unwrap_or_default();
            frames.push((kind.to_owned(), to, body.to_vec()));
        }
        frames
    }

    /// Owner decision 4 of 2026-11-23: the winner holding a displaced claim opens a round toward
    /// the displaced holder at once, so it learns that holder's completion (whose rumor to it was
    /// lost) within one round, even with its periodic rounds disarmed. Before the change it
    /// waited for a periodic round whose random partner was the displaced holder.
    #[tokio::test(start_paused = true)]
    async fn the_winner_pulls_a_displaced_holder_within_one_targeted_round() {
        let (mut w, _) = actor(T0);
        let (mut l, _) = actor(T0 + 10);
        let race = run_race(&mut w, &mut l, true);
        // w's link to a seed, whose far end the test holds; its periodic rounds never run.
        let (mine, mut theirs) = crate::transport::memory::pair("mem", "seed", "peer", None, None);
        w.install_link(
            mine,
            agentspaces_wire::seed::Seed::new("127.0.0.1", 7000, "tcp"),
        );
        w.on_link_ready();
        w.disarm_dial_rounds();
        let _ = frames_on(&mut theirs).await;

        // w hears l's claim alone: l's completion rumor never reached it.
        deliver(&mut w, &race.l_claim);
        assert_eq!(outbid(&w, &race.entry), None, "no completion yet");
        assert!(
            w.displaced_pull_due
                .is_some_and(|due| due <= tokio::time::Instant::now()),
            "a targeted round is due at once"
        );
        w.run_displaced_pulls();
        let digests: Vec<_> = frames_on(&mut theirs)
            .await
            .into_iter()
            .filter(|(kind, ..)| kind == agentspaces_wire::bodies::KIND_DIGEST)
            .collect();
        assert_eq!(digests.len(), 1, "one round: {digests:?}");
        assert_eq!(
            digests[0].1.as_deref(),
            Some(l.peer_id.as_str()),
            "addressed to the displaced holder"
        );
        assert_eq!(w.counters.displaced_pull_rounds, 1);
        assert!(w.awaits(&l.peer_id), "its answer is expected");
        assert_eq!(w.dial_rounds.rounds(), 0, "no periodic round ran");

        // l answers the round with what w's digest lacks: its completion.
        let stream = super::stream_of(SPACE);
        let digest = w.stream_digest(&stream).expect("w's digest");
        let delta = l
            .whole_delta(&w.peer_id, &stream, &digest)
            .expect("l holds what w lacks");
        let mut deltas = Map::new();
        deltas.insert(stream.as_str(), Value::Bytes(delta));
        assert!(w.on_pull_resp(deltas).is_ok(), "applied");
        assert_eq!(
            outbid(&w, &race.entry),
            Some(race.w_epoch),
            "the displaced completion is learned from the round's answer"
        );
        // The line ends with the take no longer open to that holder's completion.
        w.run_displaced_pulls();
        assert_eq!(w.counters.displaced_pull_rounds, 1, "no further round");
        assert!(
            w.spaces
                .get(SPACE)
                .and_then(|slot| slot.settle.displaced_pull(&race.entry))
                .is_none()
        );
        assert_eq!(w.displaced_pull_due, None);
    }

    /// The rounds' cadence, on the monotonic clock: at once, then 1, 2, 4, 8 and 16 s after the
    /// one before, six in all, then the line goes.
    #[tokio::test(start_paused = true)]
    async fn the_targeted_rounds_run_at_once_then_1_2_4_8_16_s_six_in_all() {
        let (mut w, _) = actor(T0);
        let (mut l, _) = actor(T0 + 10);
        let race = run_race(&mut w, &mut l, false);
        let start = tokio::time::Instant::now();
        deliver(&mut w, &race.l_claim);
        let mut at = Vec::new();
        while let Some(due) = w.displaced_pull_due {
            tokio::time::advance(due.saturating_duration_since(tokio::time::Instant::now())).await;
            let before = w.counters.displaced_pull_rounds;
            w.run_displaced_pulls();
            if w.counters.displaced_pull_rounds > before {
                at.push((tokio::time::Instant::now() - start).as_secs());
            }
            assert!(at.len() <= 6, "six rounds at most: {at:?}");
        }
        assert_eq!(at, [0, 1, 3, 7, 15, 31]);
        assert!(
            w.spaces
                .get(SPACE)
                .and_then(|slot| slot.settle.displaced_pull(&race.entry))
                .is_none(),
            "the spent line goes"
        );
    }

    /// The rounds stop once the take is no longer open: the claim lapsed (wall time), or the
    /// entry completed here; and the loser (whose claim was displaced) runs none.
    #[tokio::test(start_paused = true)]
    async fn the_targeted_rounds_end_when_the_take_is_no_longer_open() {
        let (mut w, w_clock) = actor(T0);
        let (mut l, _) = actor(T0 + 10);
        let race = run_race(&mut w, &mut l, false);
        deliver(&mut w, &race.l_claim);
        w.run_displaced_pulls();
        assert_eq!(w.counters.displaced_pull_rounds, 1);
        w_clock.advance(61_000); // w's 60 s claim lapsed
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        w.run_displaced_pulls();
        assert_eq!(
            w.counters.displaced_pull_rounds, 1,
            "a lapsed claim: no round"
        );
        assert_eq!(w.displaced_pull_due, None);

        let (mut w, _) = actor(T0);
        let (mut l, _) = actor(T0 + 10);
        let race = run_race(&mut w, &mut l, false);
        deliver(&mut w, &race.l_claim);
        let holder = w.actor_id(None);
        w.space_complete(SPACE, &race.entry, &holder, race.w_epoch, None, None)
            .expect("w completes");
        w.run_displaced_pulls();
        assert_eq!(
            w.counters.displaced_pull_rounds, 0,
            "completed here: no round"
        );

        // The displaced side opens none: its claim is not the kept one.
        deliver(&mut l, &race.w_claim);
        assert_eq!(l.displaced_pull_due, None);
    }

    /// The loop runs the targeted rounds as due work: a displaced claim heard on a turn opens
    /// the first round on the next, and the next round waits on the loop's deadline (1 s).
    #[tokio::test(start_paused = true)]
    async fn the_loop_runs_the_targeted_rounds_when_due() {
        let (mut w, _) = actor(T0);
        let (mut l, _) = actor(T0 + 10);
        let race = run_race(&mut w, &mut l, false);
        let (jobs_tx, jobs) = tokio::sync::mpsc::channel::<super::super::Job>(8);
        let (_inbound_tx, inbound) = tokio::sync::mpsc::channel(8);
        let loop_task = tokio::spawn(w.run(jobs, inbound));
        let rounds = || async {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let job: super::super::Job = Box::new(move |actor: &mut Actor| {
                let _ = tx.send(actor.counters.displaced_pull_rounds);
            });
            jobs_tx.send(job).await.expect("the loop runs");
            rx.await.expect("answered")
        };
        let claim = race.l_claim.clone();
        let job: super::super::Job = Box::new(move |actor: &mut Actor| {
            let _ = actor.on_rumor(claim, Via::Dialed);
        });
        jobs_tx.send(job).await.expect("the loop runs");
        tokio::task::yield_now().await;
        assert_eq!(rounds().await, 1, "the first round at once");
        tokio::time::advance(Duration::from_millis(999)).await;
        assert_eq!(rounds().await, 1, "not before 1 s");
        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(rounds().await, 2, "the second round 1 s later");
        drop(jobs_tx);
        let _ = loop_task.await;
    }

    /// The raw frames the far end of `theirs` received since the last call (taken without
    /// moving paused time).
    async fn raw_on(theirs: &mut crate::transport::Channel) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        let mut idle = 0;
        while idle < 16 {
            let frame = tokio::select! {
                biased;
                frame = theirs.receiver.recv() => frame,
                () = std::future::ready(()) => None,
            };
            match frame {
                Some(frame) => {
                    idle = 0;
                    frames.push(frame);
                }
                None => {
                    idle += 1;
                    tokio::task::yield_now().await;
                }
            }
        }
        frames
    }

    /// A raw frame's kind, addressee and body.
    fn opened(frame: &[u8]) -> (String, Option<String>, Vec<u8>) {
        let env = agentspaces_wire::envelope::decode_frame(frame).expect("a frame");
        (
            env.get("kind")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            env.get("to").and_then(Value::as_str).map(str::to_owned),
            env.get("body")
                .and_then(Value::as_bytes)
                .unwrap_or_default()
                .to_vec(),
        )
    }

    /// The test's seed: it relays `inner` to `to` as a one-hop RELAY_FRAME, signed by itself.
    fn relayed_by(
        seed: &agentspaces_wire::identity::Identity,
        group: &str,
        to: &str,
        inner: &[u8],
        stamp_ms: i64,
        logical: u32,
    ) -> Vec<u8> {
        let body = bodies::relay_frame_body(to, inner, None, None);
        let stamp = format!("{stamp_ms}:{logical}:{}", seed.peer_id());
        let env = agentspaces_wire::envelope::envelope(
            group,
            bodies::KIND_RELAY_FRAME,
            seed.peer_id(),
            &stamp,
            &body,
            Some(to),
        );
        agentspaces_wire::envelope::encode_frame(&env, seed)
    }

    /// An actor on a link to the test's seed, with the link's far end and the actor's inbound
    /// queue; its periodic rounds never run.
    fn on_seed(
        mut actor: Actor,
    ) -> (
        Actor,
        crate::transport::Channel,
        tokio::sync::mpsc::Receiver<super::super::Inbound>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        actor.inbound_tx = tx;
        let (mine, theirs) = crate::transport::memory::pair("mem", "seed", "peer", None, None);
        actor.install_link(
            mine,
            agentspaces_wire::seed::Seed::new("127.0.0.1", 7000, "tcp"),
        );
        actor.on_link_ready();
        actor.disarm_dial_rounds();
        (actor, theirs, rx)
    }

    /// Delivers `frame` on `theirs` and has `actor` handle it.
    async fn arrive(
        actor: &mut Actor,
        theirs: &mut crate::transport::Channel,
        inbound: &mut tokio::sync::mpsc::Receiver<super::super::Inbound>,
        frame: Vec<u8>,
    ) {
        theirs.sender.send(frame).await.expect("the link is up");
        let message = inbound.recv().await.expect("the reader forwards it");
        actor.on_inbound(message);
    }

    /// Owner decision 1 of 2026-11-23: a dial-only displaced holder answers a winner's targeted
    /// round that its seed relays, with only the entries it holds a displaced claim of (here
    /// with its completion), under its answer pace; the winner learns the completion from it. Both
    /// peers are dial-only, on links to one seed the test plays.
    #[tokio::test(start_paused = true)]
    async fn a_dial_only_holder_answers_a_relayed_round_with_only_its_displaced_entries() {
        let (mut w, _) = actor(T0);
        let (mut l, _) = actor(T0 + 10);
        let race = run_race(&mut w, &mut l, true);
        // w's better claim reaches l, displacing l's (as the core, l answers a relayed round
        // only for a displaced claim made here, not for a completion it has not yet seen lose).
        deliver(&mut l, &race.w_claim);
        let _ = sent(&mut l);
        // l also holds an entry of its own it never took, and one of w's it never touched.
        let own = l
            .write_entry(
                SPACE,
                "T#v1",
                &Value::from("mine"),
                120_000,
                &Map::new(),
                None,
            )
            .expect("write");
        let _ = sent(&mut l);
        let other = w
            .write_entry(
                SPACE,
                "T#v1",
                &Value::from("theirs"),
                120_000,
                &Map::new(),
                None,
            )
            .expect("write");
        for rumor in sent(&mut w) {
            deliver(&mut l, &rumor);
        }
        let seed = agentspaces_wire::identity::Identity::generate().expect("identity");
        let group = w.group.clone();
        let (mut w, mut w_far, mut w_in) = on_seed(w);
        let (mut l, mut l_far, mut l_in) = on_seed(l);
        let mut logical = 0u32;
        let mut stamp = |actor: &Actor| {
            logical += 1;
            (actor.now().saturating_add(1), logical)
        };
        // Each peer has heard its seed (an addressed PING), so it relays through it.
        for (actor, far, inbound) in [
            (&mut w, &mut w_far, &mut w_in),
            (&mut l, &mut l_far, &mut l_in),
        ] {
            let (ms, n) = stamp(actor);
            let env = agentspaces_wire::envelope::envelope(
                &group,
                bodies::KIND_PING,
                seed.peer_id(),
                &format!("{ms}:{n}:{}", seed.peer_id()),
                &bodies::ping_body(1),
                Some(&actor.peer_id.clone()),
            );
            arrive(
                actor,
                far,
                inbound,
                agentspaces_wire::envelope::encode_frame(&env, &seed),
            )
            .await;
            assert_eq!(actor.seed_peer().as_deref(), Some(seed.peer_id()));
        }
        let _ = raw_on(&mut w_far).await;
        let _ = raw_on(&mut l_far).await;

        // w hears l's claim alone and opens its targeted round toward l, through the seed.
        deliver(&mut w, &race.l_claim);
        w.run_displaced_pulls();
        let round: Vec<Vec<u8>> = raw_on(&mut w_far)
            .await
            .into_iter()
            .filter(|frame| opened(frame).0 == bodies::KIND_RELAY_FRAME)
            .collect();
        assert_eq!(round.len(), 1, "one round, relayed through the seed");
        let inner = bodies::parse_relay_frame(&opened(&round[0]).2)
            .expect("a relay")
            .frame;
        assert_eq!(opened(&inner).0, bodies::KIND_DIGEST);

        // The seed relays it to l; l answers through the seed.
        let (ms, n) = stamp(&l);
        let me = l.peer_id.clone();
        arrive(
            &mut l,
            &mut l_far,
            &mut l_in,
            relayed_by(&seed, &group, &me, &inner, ms, n),
        )
        .await;
        assert_eq!(l.counters.displaced_digest_answers, 1);
        let answers: Vec<Vec<u8>> = raw_on(&mut l_far)
            .await
            .into_iter()
            .filter_map(|frame| {
                let (kind, _, body) = opened(&frame);
                (kind == bodies::KIND_RELAY_FRAME).then(|| bodies::parse_relay_frame(&body))?
            })
            .filter(|relay| relay.target == w.peer_id)
            .map(|relay| relay.frame)
            .collect();
        assert_eq!(answers.len(), 1, "one PULL_RESP, to w");
        let (kind, to, body) = opened(&answers[0]);
        assert_eq!(kind, bodies::KIND_PULL_RESP);
        assert_eq!(to.as_deref(), Some(w.peer_id.as_str()));
        let deltas = bodies::parse_pull_resp(&body).expect("a PULL_RESP");
        assert_eq!(deltas.len(), 1, "one stream: {deltas:?}");
        let sync = deltas
            .get(super::stream_of(SPACE).as_str())
            .and_then(Value::as_bytes)
            .and_then(records::decode_sync_delta)
            .expect("the space's delta");
        let mut entries: Vec<&str> = sync
            .states
            .iter()
            .filter_map(records::state_entry_id)
            .chain(sync.claims.iter().map(|(entry, _)| entry.as_str()))
            .collect();
        entries.dedup();
        assert_eq!(entries, [race.entry.as_str()], "only the displaced entry");
        assert!(!entries.contains(&own.as_str()) && !entries.contains(&other.as_str()));

        // The seed relays the answer to w, which learns l's completion.
        let (ms, n) = stamp(&w);
        let to_w = w.peer_id.clone();
        arrive(
            &mut w,
            &mut w_far,
            &mut w_in,
            relayed_by(&seed, &group, &to_w, &answers[0], ms, n),
        )
        .await;
        assert_eq!(
            outbid(&w, &race.entry),
            Some(race.w_epoch),
            "the displaced completion came from the relayed round's answer"
        );

        // Under the asker's own answer pace (the cross-client check of 2026-11-23): w keeps
        // asking until its bucket is spent (its first round took one token); its next round is
        // paced and draws nothing.
        for _ in 1..RELAYED_ANSWER_BURST {
            let (ms, n) = stamp(&l);
            arrive(
                &mut l,
                &mut l_far,
                &mut l_in,
                relayed_by(&seed, &group, &me, &inner_again(&mut w, &me), ms, n),
            )
            .await;
        }
        let _ = raw_on(&mut l_far).await;
        assert_eq!(l.counters.relayed_answers_paced, 0);
        let (ms, n) = stamp(&l);
        arrive(
            &mut l,
            &mut l_far,
            &mut l_in,
            relayed_by(&seed, &group, &me, &inner_again(&mut w, &me), ms, n),
        )
        .await;
        assert_eq!(l.counters.relayed_answers_paced, 1);
        assert_eq!(
            l.counters.displaced_digest_answers,
            u64::from(RELAYED_ANSWER_BURST),
            "each round in the bucket drew the displaced claim again"
        );
        assert!(
            !raw_on(&mut l_far)
                .await
                .iter()
                .any(|frame| opened(frame).0 == bodies::KIND_RELAY_FRAME),
            "nothing answered"
        );
        // The relayed flood spent w's bucket alone: the seed's own round, read off the dialed
        // link, is still answered (a relayed DIGEST storm cannot starve the seed's repair) ...
        let paced = l.hub.counters.pulls_paced;
        let mut seed_digests = Map::new();
        seed_digests.insert(super::stream_of(SPACE), Value::Bytes(Vec::new()));
        let (ms, n) = stamp(&l);
        let env = agentspaces_wire::envelope::envelope(
            &group,
            bodies::KIND_DIGEST,
            seed.peer_id(),
            &format!("{ms}:{n}:{}", seed.peer_id()),
            &bodies::digest_body(&seed_digests),
            Some(&me),
        );
        arrive(
            &mut l,
            &mut l_far,
            &mut l_in,
            agentspaces_wire::envelope::encode_frame(&env, &seed),
        )
        .await;
        assert_eq!(
            l.hub.counters.pulls_paced, paced,
            "the seed's round is not paced"
        );
        assert!(
            raw_on(&mut l_far)
                .await
                .iter()
                .any(|frame| opened(frame).0 == bodies::KIND_PULL_RESP),
            "the seed's own round answered"
        );
        // ... and another asker still has a bucket of its own.
        assert!(l.pace_relayed_answer("another-winner"));
    }

    /// The PULL_RESP bodies and DIGEST bodies `far` saw relayed to `target`, by kind.
    async fn relayed_to(
        far: &mut crate::transport::Channel,
        target: &str,
    ) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let mut pulls = Vec::new();
        let mut digests = Vec::new();
        for frame in raw_on(far).await {
            let (kind, _, body) = opened(&frame);
            if kind != bodies::KIND_RELAY_FRAME {
                continue;
            }
            let Some(relay) = bodies::parse_relay_frame(&body) else {
                continue;
            };
            if relay.target != target {
                continue;
            }
            let (inner, _, inner_body) = opened(&relay.frame);
            if inner == bodies::KIND_PULL_RESP {
                pulls.push(inner_body);
            } else if inner == bodies::KIND_DIGEST {
                digests.push(inner_body);
            }
        }
        (pulls, digests)
    }

    /// Owner decision 1 of 2026-11-23, aligned with the core (`GossipBus.onDigestDisplacedOnly`,
    /// `ReplicatedSpace.displacedFor`): a relayed `DIGEST` draws only the entries whose claim
    /// made here a better claim of another peer displaced, with or without a completion under
    /// it; another completion of this peer's own work is not among them. It reads `hashes`
    /// (answered with `want` for the spaces that hold such a claim and differ) and `digests`
    /// (a PULL_RESP of those entries alone); `ids` and `tree` draw nothing.
    #[tokio::test(start_paused = true)]
    async fn a_relayed_round_draws_only_the_displaced_claims_made_here_as_the_core_does() {
        let (mut w, _) = actor(T0);
        let (mut l, _) = actor(T0 + 10);
        // The race with no completion by l: l's claim is displaced once w's reaches it.
        let race = run_race(&mut w, &mut l, false);
        deliver(&mut l, &race.w_claim);
        let _ = sent(&mut l);
        // l takes and completes an entry of its own, uncontested: nothing displaced it.
        let own = l
            .write_entry(
                SPACE,
                "T#v1",
                &Value::from("mine"),
                120_000,
                &Map::new(),
                None,
            )
            .expect("write");
        let ticket = l
            .space_claim(SPACE, &own, None, 60_000)
            .expect("claim")
            .expect("free");
        assert!(
            l.space_settle(SPACE, &own, &ticket.holder, ticket.epoch, None)
                .is_some()
        );
        l.space_complete(SPACE, &own, &ticket.holder, ticket.epoch, None, None)
            .expect("l completes its own");
        let _ = sent(&mut l);

        let seed = agentspaces_wire::identity::Identity::generate().expect("identity");
        let group = l.group.clone();
        let (mut l, mut l_far, mut l_in) = on_seed(l);
        let mut logical = 0u32;
        let mut stamp = |actor: &Actor| {
            logical += 1;
            (actor.now().saturating_add(1), logical)
        };
        let (ms, n) = stamp(&l);
        let me = l.peer_id.clone();
        let ping = agentspaces_wire::envelope::envelope(
            &group,
            bodies::KIND_PING,
            seed.peer_id(),
            &format!("{ms}:{n}:{}", seed.peer_id()),
            &bodies::ping_body(1),
            Some(&me),
        );
        arrive(
            &mut l,
            &mut l_far,
            &mut l_in,
            agentspaces_wire::envelope::encode_frame(&ping, &seed),
        )
        .await;
        assert_eq!(l.seed_peer().as_deref(), Some(seed.peer_id()));
        let _ = raw_on(&mut l_far).await;
        let stream = super::stream_of(SPACE);
        let w_id = w.peer_id.clone();

        // An opening of hashes: answered with want for the space, as the core answers it.
        let opening = DigestBody {
            hashes: Some(vec![(stream.clone(), vec![0u8; 32])]),
            ..DigestBody::default()
        };
        let inner = w.signed_frame(bodies::KIND_DIGEST, &opening.encode(), Some(&me));
        let (ms, n) = stamp(&l);
        arrive(
            &mut l,
            &mut l_far,
            &mut l_in,
            relayed_by(&seed, &group, &me, &inner, ms, n),
        )
        .await;
        let (pulls, digests) = relayed_to(&mut l_far, &w_id).await;
        assert!(pulls.is_empty(), "an opening draws no PULL_RESP");
        assert_eq!(digests.len(), 1, "one DIGEST asking for the text form");
        let asked = wire_audit::parse_digest(&digests[0]).expect("a DIGEST");
        assert_eq!(asked.want, Some(vec![stream.clone()]));
        assert_eq!(l.counters.displaced_digest_answers, 1);

        // The text digests: the displaced claim made here, with no completion under it, and
        // nothing of the entry l completed with its own work.
        let (ms, n) = stamp(&l);
        arrive(
            &mut l,
            &mut l_far,
            &mut l_in,
            relayed_by(&seed, &group, &me, &inner_again(&mut w, &me), ms, n),
        )
        .await;
        let (pulls, _) = relayed_to(&mut l_far, &w_id).await;
        assert_eq!(pulls.len(), 1, "one PULL_RESP, to w");
        let deltas = bodies::parse_pull_resp(&pulls[0]).expect("a PULL_RESP");
        let sync = deltas
            .get(stream.as_str())
            .and_then(Value::as_bytes)
            .and_then(records::decode_sync_delta)
            .expect("the space's delta");
        let claims: Vec<(&str, i64)> = sync
            .claims
            .iter()
            .map(|(entry, signed)| {
                let claim = signed
                    .get("claim")
                    .and_then(Value::as_map)
                    .expect("a claim");
                (entry.as_str(), claim_epoch(claim))
            })
            .collect();
        assert_eq!(
            claims,
            [(race.entry.as_str(), race.l_epoch)],
            "l's displaced claim alone"
        );
        assert!(
            sync.states
                .iter()
                .filter_map(records::state_entry_id)
                .all(|entry| entry == race.entry),
            "no state of the entry l completed uncontested"
        );
        assert_eq!(l.counters.displaced_digest_answers, 2);

        // ids and tree alone draw nothing.
        let fetch = DigestBody {
            ids: Some(vec![(
                stream.clone(),
                vec![own.clone(), race.entry.clone()],
            )]),
            ..DigestBody::default()
        };
        let inner = w.signed_frame(bodies::KIND_DIGEST, &fetch.encode(), Some(&me));
        let (ms, n) = stamp(&l);
        arrive(
            &mut l,
            &mut l_far,
            &mut l_in,
            relayed_by(&seed, &group, &me, &inner, ms, n),
        )
        .await;
        let (pulls, digests) = relayed_to(&mut l_far, &w_id).await;
        assert!(pulls.is_empty() && digests.is_empty(), "ids draw nothing");
        assert_eq!(l.counters.displaced_digest_answers, 2);
    }

    /// A fresh DIGEST of `w`'s whole digests, addressed to `to` (another round's frame).
    fn inner_again(w: &mut Actor, to: &str) -> Vec<u8> {
        let mut digests = Map::new();
        for (stream, digest) in w.full_digests() {
            digests.insert(stream, Value::Bytes(digest));
        }
        w.signed_frame(
            bodies::KIND_DIGEST,
            &bodies::digest_body(&digests),
            Some(to),
        )
    }

    /// The winner side end to end: the loser's re-offer is the claim half the winner needs.
    #[tokio::test(start_paused = true)]
    async fn the_reoffer_completes_the_winners_pair() {
        let (mut w, _) = actor(T0);
        let (mut l, _) = actor(T0 + 10);
        let race = run_race(&mut w, &mut l, true);
        // The winner heard the completion alone (the frame carrying both was lost).
        deliver(&mut w, &state_alone(&race.l_completion));
        assert_eq!(outbid(&w, &race.entry), None);
        // The loser adopts the winner's claim and offers its own again.
        deliver(&mut l, &race.w_claim);
        for rumor in sent(&mut l) {
            deliver(&mut w, &rumor);
        }
        assert_eq!(outbid(&w, &race.entry), Some(race.w_epoch));
    }

    /// Owner decision 2 of 2026-11-23: a take has lapsed when its claim is no longer ours
    /// or its wall-time lease has expired. The loser's take, still inside its lease on wall time,
    /// lapsed the moment the winner's claim displaced its own; the winner's lapses only at its
    /// lease's end; a take of an entry another holder completed has lapsed too.
    #[tokio::test]
    async fn a_take_has_lapsed_once_its_claim_is_no_longer_ours_or_its_lease_ran_out() {
        let (mut w, w_clock) = actor(T0);
        let (mut l, _) = actor(T0 + 10);
        let race = run_race(&mut w, &mut l, false);
        let (w_holder, l_holder) = (w.actor_id(None), l.actor_id(None));
        assert!(
            !l.space_take_lapsed(SPACE, &race.entry, &l_holder, race.l_epoch),
            "l holds its take"
        );
        // l hears w's better claim: its own is displaced, well inside its 60 s lease.
        deliver(&mut l, &race.w_claim);
        assert!(
            l.space_take_lapsed(SPACE, &race.entry, &l_holder, race.l_epoch),
            "the claim is no longer l's: lapsed, though its lease runs on"
        );
        // w's take holds until its lease runs out on wall time.
        deliver(&mut w, &race.l_claim);
        assert!(!w.space_take_lapsed(SPACE, &race.entry, &w_holder, race.w_epoch));
        assert!(
            w.space_take_lapsed(SPACE, &race.entry, &w_holder, race.w_epoch + 1),
            "another epoch is not this take"
        );
        w_clock.advance(60_001);
        assert!(
            w.space_take_lapsed(SPACE, &race.entry, &w_holder, race.w_epoch),
            "the lease ran out"
        );
        // An entry completed by its winner: the displaced holder's take has lapsed.
        let (mut w2, _) = actor(T0);
        let (mut l2, _) = actor(T0 + 10);
        let race2 = run_race(&mut w2, &mut l2, false);
        let holder = w2.actor_id(None);
        w2.space_complete(SPACE, &race2.entry, &holder, race2.w_epoch, None, None)
            .expect("w2 completes");
        for rumor in sent(&mut w2) {
            deliver(&mut l2, &rumor);
        }
        let l2_holder = l2.actor_id(None);
        assert!(l2.space_take_lapsed(SPACE, &race2.entry, &l2_holder, race2.l_epoch));
    }
}

/// The watch sweep as due work (SPEC v0.1.36 §9.5): it runs when the earliest lapse it tells
/// falls due, on a paused monotonic clock and a manual wall clock.
#[cfg(test)]
mod sweep_tests {
    use std::sync::Arc;
    use std::time::Duration;

    use agentspaces_wire::cbor::{Map, Value};
    use tokio::time::Instant;

    use super::super::tests::test_actor;
    use super::SWEEP_BACKSTOP;
    use crate::clock::ManualClock;
    use crate::space::Template;
    use crate::space::watch::WatchQueue;

    const SPACE: &str = "tasks";
    const T0: i64 = 1_900_000_000_000;

    #[tokio::test(start_paused = true)]
    async fn the_sweep_runs_at_the_earliest_lapse_not_four_times_a_second() {
        let (mut actor, ..) = test_actor();
        let clock = ManualClock::new(T0);
        actor.clock = Arc::new(clock.clone());
        assert_eq!(actor.sweep_at(), None, "nothing watches: no sweep");
        let queue = WatchQueue::new(64, T0 + 3_600_000);
        actor
            .space_watch(SPACE, Template::new("T#v1"), Arc::clone(&queue))
            .expect("watch");
        let start = Instant::now();
        let entry = actor
            .write_entry(SPACE, "T#v1", &Value::from("x"), 5_000, &Map::new(), None)
            .expect("write");
        assert_eq!(
            actor.sweep_at(),
            Some(start + Duration::from_secs(5)),
            "due at the write lease's lapse"
        );
        // A wall-clock step forward re-anchors the deadline on the next turn.
        clock.advance(2_000);
        assert_eq!(actor.sweep_at(), Some(start + Duration::from_secs(3)));
        tokio::time::advance(Duration::from_secs(3)).await;
        clock.advance(3_000);
        actor.on_sweep();
        let told = actor
            .spaces
            .get(SPACE)
            .and_then(|slot| slot.fired.get(&entry))
            .is_some_and(|fired| fired.expired);
        assert!(told, "Expired told at the lapse");
        assert_eq!(
            actor.sweep_at(),
            Some(Instant::now() + SWEEP_BACKSTOP),
            "nothing left but the watch's own lapse an hour out: the backstop"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_claim_lapsing_before_the_write_is_the_due() {
        let (mut actor, ..) = test_actor();
        let clock = ManualClock::new(T0);
        actor.clock = Arc::new(clock.clone());
        let queue = WatchQueue::new(64, T0 + 3_600_000);
        actor
            .space_watch(SPACE, Template::new("T#v1"), Arc::clone(&queue))
            .expect("watch");
        let start = Instant::now();
        let entry = actor
            .write_entry(SPACE, "T#v1", &Value::from("x"), 600_000, &Map::new(), None)
            .expect("write");
        let ticket = actor
            .space_claim(SPACE, &entry, None, 4_000)
            .expect("claim")
            .expect("free");
        assert!(ticket.epoch >= 1);
        assert_eq!(
            actor.sweep_at(),
            Some(start + Duration::from_secs(4)),
            "the claim lapses first"
        );
    }
}
