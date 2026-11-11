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
//! - a take's renewal re-signs the held claim with the same epoch, stamp, holder, and bid and a
//!   later expiry, which the claim lattice prefers (Java `Taken.renew`, `peer.rb`'s
//!   `renew_claim`);
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
//! turns completed, `Taken` when a member's claim wins the lattice while live (once per epoch and
//! holder; this peer's own claim only once its take has won), and, from the sweep that runs every
//! [`SWEEP_INTERVAL`] while a space has watchers, `Expired` once per open entry whose write lease
//! lapsed and `Reappeared` once per lapsed claim epoch of an open entry. Each transition is offered
//! to the matching watches without waiting ([`crate::space::watch`]); one whose payload block is
//! still on its way waits (at most [`MAX_DEFERRED`] of them) until the block arrives.
//!
//! # Collection
//!
//! Every [`COLLECT_INTERVAL`], watched or not, each open space drops its tombstones past the
//! horizon of SPEC §7.3 (Java `SpaceStateCrdt.collectable`, `ReplicatedSpace.sweepLocked`): a
//! completed or withdrawn entry two of the space's longest leases after its write lease lapsed, a
//! lapsed one after the shorter of that and five minutes; with its claim, its transitions'
//! trackers, and the block it pinned. The longest lease is the longest observed in the space
//! (writes, renewals, and claims), capped at 24 hours. A received state already past that
//! horizon is refused at the door (a member re-offering what this peer collected; Python, Ruby,
//! and TypeScript peers never collect), and lapsed claims of entries with no state go too. A
//! space at its bound collects before it refuses a new entry: at once for a write of this peer,
//! at most once a second for received ones.
//!
//! [`Peer`]: crate::peer::Peer

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use agentspaces_wire::bodies::{self, RUMOR_HOPS, STREAM_SPACE_PREFIX};
use agentspaces_wire::cbor::{self, Map, Value};
use agentspaces_wire::fold::{self, FoldOutcome, Refusal};
use agentspaces_wire::hlc::Stamp;
use agentspaces_wire::identity::AgentIdentity;
use agentspaces_wire::ids;
use agentspaces_wire::records::{self, PayloadSource, WRITE_LEASE_KIND};
use tokio::time::Instant;

use super::{Actor, DEFAULT_AGENT_NAME, PeerError, PeerEvent, fits_a_frame};
use crate::peer::spaces::{Fired, MAX_TRACKED_LEASE_MILLIS, Slot};
use crate::space::watch::{CloseReason, WatchQueue};
use crate::space::{
    Attestation, ClaimTicket, EntryId, EntryView, EventKind, ResultWrite, SpaceError, SpaceEvent,
    Template,
};

/// How often the transitions the clock decides (`Expired`, `Reappeared`, a subscription's lapse)
/// are looked for while anything watches (`space.py`'s sweep, four times a second).
pub(in crate::peer) const SWEEP_INTERVAL: Duration = Duration::from_millis(250);
/// The most transitions waiting for their payload's block.
pub(in crate::peer) const MAX_DEFERRED: usize = 4096;
/// The most watches a peer holds at once.
const MAX_WATCHERS: usize = 4096;
/// The most agent identities a peer keeps (their renewed certificates) between calls.
const MAX_HELD_AGENTS: usize = 4096;
/// How often every open space collects its tombstones ([module docs](self#collection)).
pub(in crate::peer) const COLLECT_INTERVAL: Duration = Duration::from_secs(5);
/// How long a lapsed entry's tombstone stays at most (Java `SpaceStateCrdt.LAPSED_GRACE_MILLIS`,
/// five minutes): a lapse is judged alike on every replica, so it need not wait two longest
/// leases as a completion or a withdrawal does.
const LAPSED_GRACE_MILLIS: i64 = 5 * 60 * 1000;
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

/// Java `SpaceStateCrdt.collectable` (SPEC §7.3): whether `state` is a tombstone past its horizon
/// at `now` in a space whose longest lease is `max_lease`. An entry still visible (present, its
/// write lease holding; a lease of another kind never lapses) never is. Otherwise its horizon is
/// its lease's expiry plus two longest leases for a completed or withdrawn entry, the shorter of
/// that and [`LAPSED_GRACE_MILLIS`] for a lapsed one. A state without a readable lease is kept.
pub(in crate::peer) fn collectable(state: &Map, now: i64, max_lease: i64) -> bool {
    let Some(expiry) = write_expiry(state) else {
        return false;
    };
    if expiry > now {
        return false;
    }
    let present = fold::is_present(state);
    if present && !write_lapsed(state, now) {
        return false;
    }
    let twice = max_lease.max(0).saturating_mul(2);
    let keep = if present {
        twice.min(LAPSED_GRACE_MILLIS)
    } else {
        twice
    };
    expiry
        .checked_add(keep)
        .is_some_and(|horizon| horizon <= now)
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
        let outcome = slot.store.merge_own_claim(entry_id, signed);
        if outcome.is_applied()
            && let Some(span) = claim_lease_span(signed)
        {
            slot.observe_lease(span);
        }
        match outcome {
            FoldOutcome::Refused(refusal) => return Err(refused(entry_id, refusal)),
            FoldOutcome::Applied => {
                self.emit(PeerEvent::ClaimFolded {
                    space: space.to_owned(),
                    entry_id: entry_id.to_owned(),
                });
                self.bump_folds();
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
    pub(crate) fn space_settle(
        &mut self,
        space: &str,
        entry_id: &str,
        holder: &str,
        epoch: i64,
    ) -> Option<EntryView> {
        let now = self.now();
        let view = {
            let slot = self.spaces.get(space)?;
            let state = slot.store.state(entry_id)?;
            let claim = slot.store.claim_of(entry_id)?;
            let won = fold::is_present(state)
                && claim_holder(claim) == Some(holder)
                && claim_epoch(claim) == epoch
                && claim_live(claim, now);
            if !won || self.registry.refuses(holder, None, None) {
                return None;
            }
            bare_view(entry_id, state, Some(claim), now)?
        };
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
    /// with the same epoch, stamp, holder, and bid and the expiry `now + lease`, which the lattice
    /// prefers, rumored under `c:<entry id>:renew:<expiry>`. Answers the expiry in force.
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
        let expires_at = now
            .checked_add(lease_millis)
            .ok_or_else(|| SpaceError::InvalidLease("the lease overflows".to_owned()))?;
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
    /// `Handle.renew`): a later lease stamp and the lease `{holder: issuer, expiresAtMillis: now +
    /// lease, kind: WRITE}`, re-signed by the issuer, rumored under `r:<entry id>:<lease stamp>`.
    /// A lapsed, completed, or withdrawn entry is [`SpaceError::LeaseLapsed`].
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
        let expires_at = now
            .checked_add(lease_millis)
            .ok_or_else(|| SpaceError::InvalidLease("the lease overflows".to_owned()))?;
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
    /// the collection horizon is refused at the door (SPEC §7.3, Java `mergeState`: a member that
    /// collects later, or never, would otherwise bounce it back as new), judged with its own
    /// lease counted in the space's longest, as Java observes it first; a new entry for a full
    /// space first collects the space (at most once every [`FULL_COLLECT_INTERVAL`]).
    pub(super) fn fold_remote_state(&mut self, space: &str, dto: &Map) -> Option<FoldOutcome> {
        let now = self.now();
        let mut collect = false;
        if let Some(slot) = self.spaces.get(space) {
            let own_span =
                state_lease_span(dto).map_or(0, |span| span.min(MAX_TRACKED_LEASE_MILLIS));
            if collectable(dto, now, slot.max_lease.max(own_span)) {
                self.counters.space_reoffers_refused =
                    self.counters.space_reoffers_refused.saturating_add(1);
                return Some(FoldOutcome::Unchanged);
            }
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
        self.fold_state(space, dto)
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
        self.last_collect = Instant::now();
        let now = self.now();
        let names = self.spaces.names();
        self.collect_spaces(&names, now);
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
            let Some(slot) = self.spaces.get_mut(space) else {
                continue;
            };
            let max_lease = slot.max_lease;
            let tombstones: Vec<String> = slot
                .store
                .states()
                .filter(|(_, state)| collectable(state, now, max_lease))
                .map(|(entry_id, _)| entry_id.to_owned())
                .collect();
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
        self.watchers.push(Watcher {
            space: space.to_owned(),
            template,
            queue,
        });
        Ok(())
    }

    /// Whether anything watches (the sweep runs only then).
    pub(super) fn watching(&self) -> bool {
        !self.watchers.is_empty()
    }

    /// The transitions after a state of `entry_id` folded (applied) into `space`: `Written` at
    /// the first fold of a live entry, `Completed` when the joined state turned completed.
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
            self.deliver(space, EventKind::Completed, entry_id);
        }
    }

    /// The transition after a member's claim on `entry_id` won the lattice in `space`: `Taken`,
    /// once per epoch and holder, while the claim is live and the entry present.
    pub(super) fn after_claim(&mut self, space: &str, entry_id: &str) {
        self.fire_taken(space, entry_id);
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
        self.watchers.retain(|watcher| {
            if watcher.queue.closed().is_some() {
                return false;
            }
            if watcher.queue.lapsed(now) {
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
        self.watchers.retain(|watcher| {
            if watcher.queue.closed().is_some() {
                return false;
            }
            if watcher.space != space {
                return true;
            }
            if watcher.queue.lapsed(now) {
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

    /// Offers again the transitions that waited for a block (a block arrived, or the sweep).
    pub(super) fn retry_deferred(&mut self) {
        if self.deferred.is_empty() {
            return;
        }
        let waiting = std::mem::take(&mut self.deferred);
        for deferred in waiting {
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
            assert!(collectable(&done, 100, 0));
            assert!(!collectable(&done, 100 + 2 * 60 * minute - 1, 60 * minute));
            assert!(collectable(&done, 100 + 2 * 60 * minute, 60 * minute));
        }
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
