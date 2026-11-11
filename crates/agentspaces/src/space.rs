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

//! The Space API (SPEC §7, Layer 3): leased writes, reads, exclusive takes and their
//! completion, and watches of a replicated space, over a running [`Peer`].
//!
//! Payloads at this layer are CBOR [`Value`]s with a schema string (the entry's wire type name,
//! `"<Type>#v<version>"`); the typed verbs ([`typed`]) wrap them for Rust types that implement
//! [`Entry`](crate::entry::Entry). The Python `space.py`, the Ruby `space.rb`, and the TypeScript
//! peer are the behavioural references; Java `ReplicatedSpace` is the authority.
//!
//! ```no_run
//! # async fn run(config: agentspaces::peer::PeerConfig) -> Result<(), agentspaces::space::SpaceError> {
//! use std::time::Duration;
//! use agentspaces::space::{Fleet, Lease, Template};
//! use agentspaces::wire::cbor::{Map, Value};
//! use agentspaces::wire::cbor_map;
//!
//! let fleet = Fleet::join(config).await?;
//! let tasks = fleet.space("tasks");
//! tasks
//!     .write_value("com.acme.Task#v1", cbor_map! { "topic" => "index", "priority" => 3 }, Lease::parse("10m")?, Map::new())
//!     .await?;
//! let template = Template::new("com.acme.Task#v1").where_clause("priority>=3")?;
//! if let Some(taken) = tasks.take(&template, Lease::parse("1m")?, Duration::from_secs(15)).await? {
//!     let topic = taken.entry().payload().get("topic").cloned().unwrap_or(Value::Null);
//!     let result = cbor_map! { "topic" => topic, "summary" => "done" };
//!     taken.complete(Some(("com.acme.Result#v1", result)), Lease::DEFAULT_RESULT, Map::new()).await?;
//! }
//! fleet.close().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # The verbs
//!
//! - [`Space::write_value`] writes a signed, leased entry; [`Space::renew_write`] and
//!   [`Space::cancel`] renew or withdraw the writer's own entries.
//! - [`Space::read`], [`Space::read_all`], and [`Space::get`] read what this peer holds. A read
//!   that waits wakes on each fold and pulls the space at most once per settle window; it never
//!   polls.
//! - [`Space::take`] takes one matching entry exclusively under LEASE_RACE (SPEC §7.4), and the
//!   [`Taken`] it answers completes it (with a result written in the same space, atomically),
//!   renews its hold, or releases it. [`Space::held`] finds a take this handle's actor holds by
//!   the entry's id (another process on the same keystore, or a take whose future was dropped).
//! - [`Space::watch`] streams the entries' transitions ([`SpaceEvent`]); [`Space::notify`] is the
//!   leased push subscription of the Java space.
//! - The typed verbs ([`typed`]) take and give [`Entry`](crate::entry::Entry) types:
//!   [`Space::write`], [`Space::read_typed`], [`Space::read_all_typed`], [`Space::get_typed`],
//!   [`Space::take_typed`] (whose [`TypedTaken`] completes with a typed result,
//!   [`Taken::complete_with`]), [`Space::watch_typed`], and [`Space::notify_typed`], over
//!   [`Template::of`] and [`EntryView::decode`].
//!
//! [`Space::as_agent`] acts as an agent identity: records, claims, and states are then signed by
//! the agent's own key under its certificate (AGENT_ATTESTED everywhere), which the peer renews
//! at half-life before it signs.
//!
//! # A take
//!
//! A take walks the entries that are available (live and unclaimed, Java `availableRecords`) and
//! match, in the order they first folded. Before each claim it judges that entry again against what
//! has folded since (as the Python and Ruby peers do: a candidate list is a snapshot, and faster
//! members may have claimed its entries meanwhile), so a stale candidate is skipped without costing
//! a settle window. For a free one it publishes a signed claim (epoch one past the held claim's,
//! its stamp from the peer's clock), waits one settle window ([`Space::with_settle`], 600 ms by
//! default as in Python and Ruby; a Java space defaults to 200 ms), pulls the space again and waits
//! for a fold, and wins only if the claim lattice still names it at that epoch and the entry is not
//! completed. A take always makes one attempt, as Java's `takeAs` tries once before it looks at the
//! clock, so a timeout of [`Duration::ZERO`] is a take that never waits; after a claim it stops at
//! its deadline, also between candidates, and a claim already published waits out its settle window
//! first. Each pass looks at a few candidates only (decoding a payload is the costly part, and a
//! take claims one). Every claim bids 0.0 (LEASE_RACE); AUCTION takes are not offered at this
//! layer.
//!
//! [`Taken::release`] stops renewing: there is no un-claim on the wire, so the hold lapses at its
//! expiry and the entry reappears. A take whose future is dropped after its claim went out does
//! the same; see [`Space::take`]'s cancel safety.
//!
//! A take answers [`PeerError::Closed`] once the peer is closed, also one already waiting; so
//! does a read that finds no match among the entries held.
//!
//! # Cancel safety
//!
//! [`Space::watch`] and [`Space::notify`] are cancel-safe: dropping their future never leaves a
//! watch registered. [`Space::take`] is not, once its claim is out ([`Space::take`]). The other
//! verbs run in one actor turn each; a dropped future may or may not have had its effect.

#![warn(missing_docs)]

pub mod typed;
pub mod types;
pub mod watch;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use agentspaces_wire::cbor::{Map, Value};
use agentspaces_wire::identity::AgentIdentity;
use tokio::time::Instant;

pub use typed::{TypedEvent, TypedEvents, TypedTaken, TypedView};
pub use types::{
    Attestation, EntryId, EntryView, EventKind, Lease, SpaceError, SpaceEvent, Template,
};
pub(crate) use types::{ClaimTicket, ResultWrite};
pub use watch::{CloseReason, SpaceEvents, Subscription};

use crate::clock::SharedClock;
use crate::peer::{Peer, PeerConfig, PeerError};
use watch::WatchQueue;

/// The default settle window of a take (`peer.py` and the Ruby peer settle for 600 ms).
pub const DEFAULT_SETTLE: Duration = Duration::from_millis(600);

/// How many events a watch holds for a watcher that has not taken them yet; past that its oldest
/// are dropped ([`watch`]).
pub const DEFAULT_WATCH_CAPACITY: usize = 1024;

/// How long a take waits, after its settle window and a pull, for a fold before it judges the
/// race (`peer.py`'s `await_fold(min(settle, 0.3))`).
const SETTLE_FOLD_WAIT: Duration = Duration::from_millis(300);

/// How many candidates one pass of a take decodes and walks before it looks again: a take
/// claims one, a lost race loops at once, and each candidate's payload is decoded on the actor,
/// so a long window only stalls the peer (and grows as typed takes refuse candidates).
const CANDIDATES_PER_PASS: usize = 8;

// ---------------------------------------------------------------------------------------------
// The fleet

/// A member of a fleet: a façade over a running [`Peer`] that hands out [`Space`]s. Cheap to
/// clone; every clone drives the same peer.
#[derive(Debug, Clone)]
pub struct Fleet {
    peer: Peer,
}

impl Fleet {
    /// Starts a peer from `config` ([`Peer::start`]) and wraps it.
    pub async fn join(config: PeerConfig) -> Result<Fleet, PeerError> {
        Ok(Fleet {
            peer: Peer::start(config).await?,
        })
    }

    /// Starts a listening peer from `config` ([`Peer::start`] with its listeners,
    /// [`PeerConfig::listen`]) and wraps it: a hub that admits members, forwards their rumors,
    /// answers their pulls, relays their frames, and holds the spaces it replicates. Its own
    /// spaces work as any member's. [`Peer::listen_addrs`] names the addresses it bound.
    ///
    /// ```no_run
    /// # async fn run() -> Result<(), agentspaces::peer::PeerError> {
    /// use agentspaces::group::GroupSpec;
    /// use agentspaces::peer::{ListenerSpec, PeerConfig};
    /// use agentspaces::space::Fleet;
    /// use agentspaces::wire::identity::Identity;
    ///
    /// let identity = Identity::generate().expect("identity");
    /// let config = PeerConfig::new(identity, GroupSpec::FoundingText("crew".into()))
    ///     .listen_on(ListenerSpec::tcp("0.0.0.0:7711").advertise("10.0.0.5:7711"));
    /// let hub = Fleet::listen(config).await?;
    /// println!("{} listens on {:?}", hub.peer().peer_id(), hub.peer().listen_addrs());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`PeerError::InvalidArgument`] when `config` names no listener, and the errors of
    /// [`Peer::start`].
    pub async fn listen(config: PeerConfig) -> Result<Fleet, PeerError> {
        if !config.is_listening() {
            return Err(PeerError::InvalidArgument(
                "a listening fleet needs at least one listener".to_owned(),
            ));
        }
        Self::join(config).await
    }

    /// Starts a peer from the process's configuration (the `ASPACE_*` variables over the fleet
    /// YAML, [`Peer::join_from_env`]) and wraps it.
    pub async fn join_from_env() -> Result<Fleet, PeerError> {
        Ok(Fleet {
            peer: Peer::join_from_env().await?,
        })
    }

    /// Starts a peer from a resolved [`Config`](crate::Config) ([`Peer::join_config`]: its
    /// identity, group, seeds, timings, and spaces) and wraps it, as in
    /// `Fleet::join_config(&Config::load("fleet.yaml")?)`.
    pub async fn join_config(config: &crate::Config) -> Result<Fleet, PeerError> {
        Ok(Fleet {
            peer: Peer::join_config(config).await?,
        })
    }

    /// Wraps a running peer.
    pub fn from_peer(peer: Peer) -> Fleet {
        Fleet { peer }
    }

    /// A handle on space `name` of the fleet's group ([`Peer::space`]).
    pub fn space(&self, name: &str) -> Space {
        self.peer.space(name)
    }

    /// The peer underneath.
    pub fn peer(&self) -> &Peer {
        &self.peer
    }

    /// Closes the peer for good ([`Peer::close`]); every watch ends. Idempotent.
    pub async fn close(&self) -> Result<(), PeerError> {
        self.peer.close().await
    }
}

// ---------------------------------------------------------------------------------------------
// The space

/// One replicated space of the peer's group, by name: the Layer 3 verbs over CBOR payloads. A
/// cheap, cloneable handle ([`Peer::space`], [`Fleet::space`]); the space is opened (pulled) on
/// its first use. See the [module docs](self).
///
/// A handle acts as the peer's default agent (`<peerId>/rust`, peer-signed) unless made to act
/// as an agent identity ([`Space::as_agent`]).
#[derive(Clone)]
pub struct Space {
    peer: Peer,
    name: Arc<str>,
    agent: Option<Arc<AgentIdentity>>,
    settle: Duration,
    watch_capacity: usize,
    opened: Arc<AtomicBool>,
    /// A stop signal its takes heed ([`Space::halting_on`]): once it reads `true` a take claims
    /// nothing more and stops waiting. `None` for every handle but a bound agent's take loops.
    halt: Option<tokio::sync::watch::Receiver<bool>>,
}

impl std::fmt::Debug for Space {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Space")
            .field("name", &self.name)
            .field("peer", &self.peer.peer_id())
            .field("agent", &self.agent.as_ref().map(|agent| agent.agent_id()))
            .field("settle", &self.settle)
            .finish()
    }
}

impl Space {
    pub(crate) fn new(peer: Peer, name: &str) -> Space {
        Space {
            peer,
            name: Arc::from(name),
            agent: None,
            settle: DEFAULT_SETTLE,
            watch_capacity: DEFAULT_WATCH_CAPACITY,
            opened: Arc::new(AtomicBool::new(false)),
            halt: None,
        }
    }

    /// This space with takes that heed `halt` (a bound agent's stop signal; a server's stop, or its
    /// client going away): once it reads `true`, a take makes no further claim and stops waiting
    /// for one, answering `Ok(None)`. A claim already made settles as ever, and is answered when it
    /// wins: the stop never cancels a claim in flight, which the wire has no way to take back (SPEC
    /// §7.4). This is the cancel-safe way to end a waiting take early, where dropping its future
    /// would leave a published claim held (see [`Space::take`]).
    pub fn halting_on(&self, halt: tokio::sync::watch::Receiver<bool>) -> Space {
        Space {
            halt: Some(halt),
            ..self.clone()
        }
    }

    /// Whether this handle's stop signal reads `true` ([`Space::halting_on`]).
    fn halted(&self) -> bool {
        self.halt.as_ref().is_some_and(|halt| *halt.borrow())
    }

    /// Resolves once this handle's stop signal reads `true`; never without one (or once its
    /// sender is gone).
    async fn halt_requested(&self) {
        match self.halt.clone() {
            Some(mut halt) => {
                if halt.wait_for(|halted| *halted).await.is_err() {
                    std::future::pending::<()>().await;
                }
            }
            None => std::future::pending::<()>().await,
        }
    }

    /// The space's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The peer underneath.
    pub fn peer(&self) -> &Peer {
        &self.peer
    }

    /// This space acting as `agent`, an agent identity of this peer
    /// ([`Identity::subordinate`](crate::wire::identity::Identity::subordinate),
    /// [`Identity::renewing_subordinate`](crate::wire::identity::Identity::renewing_subordinate)):
    /// its writes, claims, renewals, cancellations, and completions are signed by the agent's
    /// key with its certificate carried, and every member stores its entries AGENT_ATTESTED. The
    /// peer keeps the identity's renewed certificates and renews them at half-life before
    /// signing. A verb of an agent of another peer answers [`PeerError::ForeignAgent`].
    pub fn as_agent(&self, agent: AgentIdentity) -> Space {
        Space {
            agent: Some(Arc::new(agent)),
            ..self.clone()
        }
    }

    /// The agent identity this handle acts as, if any.
    pub fn agent(&self) -> Option<&AgentIdentity> {
        self.agent.as_deref()
    }

    /// This space with another settle window for its takes ([`DEFAULT_SETTLE`] otherwise; a Java
    /// space uses 200 ms). It also paces the pulls of waiting reads and takes.
    pub fn with_settle(&self, settle: Duration) -> Space {
        Space {
            settle,
            ..self.clone()
        }
    }

    /// The settle window of this handle's takes.
    pub fn settle(&self) -> Duration {
        self.settle
    }

    /// This space with another capacity for the queues of its watches
    /// ([`DEFAULT_WATCH_CAPACITY`] otherwise; at least 1).
    pub fn with_watch_capacity(&self, capacity: usize) -> Space {
        Space {
            watch_capacity: capacity.max(1),
            ..self.clone()
        }
    }

    fn agent_owned(&self) -> Option<AgentIdentity> {
        self.agent.as_deref().cloned()
    }

    /// Opens and pulls the space once, on this handle's first verb.
    async fn open(&self) -> Result<(), SpaceError> {
        if !self.opened.load(Ordering::Acquire) {
            self.peer.space_open(&self.name).await?;
            self.opened.store(true, Ordering::Release);
        }
        Ok(())
    }

    /// Pulls the space now (an anti-entropy pull of its states and claims, SPEC §5.3); it is
    /// pulled again after every reconnect.
    pub async fn pull(&self) -> Result<(), SpaceError> {
        self.opened.store(true, Ordering::Release);
        Ok(self.peer.pull_space(&self.name).await?)
    }

    // ------------------------------------------------------------------------- writes

    /// Writes one entry of `schema` with `payload` for `lease`, its `tags` (text to text) inside
    /// the signed record, and answers its id. The entry folds here at once, so a local read sees
    /// it, and is rumored to the group (held for the next link when there is none). A payload
    /// over 64 KiB travels as a block.
    ///
    /// # Errors
    ///
    /// [`PeerError::InvalidArgument`] for a tag whose key or value is not text (every member
    /// would refuse the record); [`SpaceError::Refused`] with
    /// [`Refusal::Full`](crate::wire::fold::Refusal::Full) when the space holds its bound of
    /// entries ([`PeerConfig::space_max_entries`]) even after collecting its tombstones; and
    /// [`PeerError::Closed`] on a closed peer. Nothing is sent then.
    pub async fn write_value(
        &self,
        schema: &str,
        payload: Value,
        lease: Lease,
        tags: Map,
    ) -> Result<EntryId, SpaceError> {
        self.open().await?;
        let id = self
            .peer
            .write_entry(
                &self.name,
                schema,
                payload,
                lease.millis(),
                tags,
                self.agent.as_deref(),
            )
            .await?;
        Ok(EntryId::new(id))
    }

    /// Renews the write lease of an entry this handle's actor wrote (`peer.py`'s `renew_entry`,
    /// Java `EntryHandle.renew`): the lease runs `lease` from now, re-signed by the issuer.
    /// [`SpaceError::NotIssuer`] for another writer's entry (an agent-attested entry renews only
    /// as its agent), [`SpaceError::LeaseLapsed`] once its lease lapsed or it was completed or
    /// withdrawn.
    pub async fn renew_write(&self, entry_id: &EntryId, lease: Lease) -> Result<(), SpaceError> {
        self.open().await?;
        self.peer
            .space_renew_write(
                &self.name,
                entry_id.as_str(),
                self.agent_owned(),
                lease.millis(),
            )
            .await
    }

    /// Withdraws an entry this handle's actor wrote (Java `EntryHandle.cancel`): a state whose
    /// removes cover its adds, signed by the issuer; every member then reads the entry as gone
    /// and no take can claim it. Idempotent: an entry already completed (by whichever member
    /// took it, a race a writer cancelling on timeout meets) answers `Ok` and sends nothing.
    /// [`SpaceError::NotIssuer`] for another writer's entry.
    pub async fn cancel(&self, entry_id: &EntryId) -> Result<(), SpaceError> {
        self.open().await?;
        self.peer
            .space_cancel(&self.name, entry_id.as_str(), self.agent_owned())
            .await
    }

    // ------------------------------------------------------------------------- reads

    /// The available entries matching `template` (live and unclaimed, Java `readAll`), at most
    /// `limit`, in the order they first folded here. Never waits; an entry whose payload block
    /// is still on its way is skipped this time (and the block asked for).
    pub async fn read_all(
        &self,
        template: &Template,
        limit: usize,
    ) -> Result<Vec<EntryView>, SpaceError> {
        self.open().await?;
        self.find_decoded(template, limit, &mut Some).await
    }

    /// How many available entries of `template`'s schema (and tags) [`Space::read_all`] passes
    /// over because their payload block is still on its way: a payload over the inline limit
    /// (64 KiB) is fetched from its writer or another member that holds it. Each is asked for
    /// again (at most once a second), and [`PeerEvent::Block`](crate::peer::PeerEvent::Block)
    /// tells when one arrives. Never waits.
    ///
    /// # Errors
    ///
    /// [`PeerError::Closed`] once the peer is closed.
    pub async fn pending_payloads(&self, template: &Template) -> Result<usize, SpaceError> {
        self.open().await?;
        self.peer.space_pending(&self.name, template.clone()).await
    }

    /// The available entries matching `template` that `decode` accepts, at most `limit`, in the
    /// order they first folded here: what [`Space::read_all`] finds, kept where `decode` answers
    /// `Some` (the typed verbs pass over entries that do not decode as their type). One find
    /// when every match is accepted; when some are not, the find looks further along, twice as
    /// far each time, until `limit` are accepted or the matches run out.
    async fn find_decoded<D>(
        &self,
        template: &Template,
        limit: usize,
        decode: &mut impl FnMut(EntryView) -> Option<D>,
    ) -> Result<Vec<D>, SpaceError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut wanted = limit;
        loop {
            let views = self
                .peer
                .space_find(&self.name, template.clone(), wanted)
                .await?;
            let exhausted = views.len() < wanted || wanted == usize::MAX;
            let found: Vec<D> = views
                .into_iter()
                .filter_map(&mut *decode)
                .take(limit)
                .collect();
            if found.len() >= limit || exhausted {
                return Ok(found);
            }
            wanted = wanted.saturating_mul(2);
        }
    }

    /// The first available entry matching `template`, waiting up to `timeout` for one (`space.py`'s
    /// `read`): while none matches, the space is pulled at most once per settle window and the wait
    /// wakes on each fold, never polling. `Ok(None)` at the timeout. The entries held are always
    /// looked at once, so [`Duration::ZERO`] reads without waiting; a timeout too long for the
    /// clock to represent (such as [`Duration::MAX`]) waits with no deadline.
    ///
    /// # Errors
    ///
    /// [`PeerError::Closed`] once the peer is closed and nothing held matches (a read already
    /// waiting ends then too); a match held is still answered after the close.
    pub async fn read(
        &self,
        template: &Template,
        timeout: Duration,
    ) -> Result<Option<EntryView>, SpaceError> {
        self.read_decoded(template, timeout, Some).await
    }

    /// [`Space::read`] of the first match `decode` accepts.
    async fn read_decoded<D>(
        &self,
        template: &Template,
        timeout: Duration,
        mut decode: impl FnMut(EntryView) -> Option<D>,
    ) -> Result<Option<D>, SpaceError> {
        self.open().await?;
        // `None`: the timeout reaches past what the clock can hold, so there is no deadline.
        let deadline = Instant::now().checked_add(timeout);
        let mut folds = self.peer.folds();
        loop {
            folds.borrow_and_update();
            let found = self.find_decoded(template, 1, &mut decode).await?;
            if let Some(value) = found.into_iter().next() {
                return Ok(Some(value));
            }
            let now = Instant::now();
            if deadline.is_some_and(|deadline| now >= deadline) {
                return Ok(None);
            }
            self.peer.space_pull_paced(&self.name, self.settle).await?;
            if let Ok(Err(_)) =
                tokio::time::timeout(self.wait(deadline, now), folds.changed()).await
            {
                return Err(PeerError::Closed.into());
            }
        }
    }

    /// How long a waiting read or take waits for a fold at `now`: a settle window, or what is
    /// left before `deadline` when that is shorter.
    fn wait(&self, deadline: Option<Instant>, now: Instant) -> Duration {
        deadline.map_or(self.settle, |deadline| {
            self.settle.min(deadline.saturating_duration_since(now))
        })
    }

    /// The entry `entry_id` as this peer holds it, whatever its state (live, taken, completed,
    /// withdrawn, or lapsed, until its tombstone is collected: SPEC §7.3, two of the space's
    /// longest leases after its lease lapsed, at most five minutes for a lapse); `None` when it
    /// is not held here (or its payload block is still on its way).
    pub async fn get(&self, entry_id: &EntryId) -> Result<Option<EntryView>, SpaceError> {
        self.open().await?;
        self.peer.space_entry(&self.name, entry_id.as_str()).await
    }

    // ------------------------------------------------------------------------- takes

    /// Takes one available entry matching `template` exclusively, holding it for `lease`, and
    /// waits up to `timeout` for one (SPEC §7.4 LEASE_RACE; see the [module docs](self#a-take)).
    /// `Ok(None)` when nothing could be taken in time. The hold may be at most
    /// [`Lease::MAX_TAKE`]. One attempt is always made, so [`Duration::ZERO`] takes an entry
    /// available here without waiting (Java's non-blocking take); a timeout too long for the
    /// clock to represent (such as [`Duration::MAX`]) waits with no deadline.
    ///
    /// # Errors
    ///
    /// [`PeerError::Closed`] once the peer is closed, also for a take already waiting.
    ///
    /// # Cancel safety
    ///
    /// Not cancel-safe once its claim is published. Dropping the future then
    /// (`tokio::time::timeout`, `select!`, `JoinHandle::abort`) leaves that claim held with no
    /// [`Taken`] to complete or renew it, and since SPEC §7.4 has no un-claim the entry stays
    /// unavailable to every member until `lease` lapses (up to [`Lease::MAX_TAKE`]), as an
    /// uncompleted or released take does. Bound the wait with `timeout`, not by cancelling; in a
    /// `select!` loop run the take on a task of its own, or pin one take future across iterations
    /// (`tokio::pin!` and `&mut take`) instead of making a new one each time round. A take
    /// cancelled this way can still be found and completed by id ([`Space::held`]).
    pub async fn take(
        &self,
        template: &Template,
        lease: Lease,
        timeout: Duration,
    ) -> Result<Option<Taken>, SpaceError> {
        let taken = self
            .take_decoded(template, lease, timeout, |_| Some(()))
            .await?;
        Ok(taken.map(|(taken, ())| taken))
    }

    /// [`Space::take`] of a candidate `decode` accepts: a candidate it refuses is never claimed.
    /// Answers the take and what `decode` made of its entry.
    async fn take_decoded<D>(
        &self,
        template: &Template,
        lease: Lease,
        timeout: Duration,
        mut decode: impl FnMut(&EntryView) -> Option<D>,
    ) -> Result<Option<(Taken, D)>, SpaceError> {
        if lease > Lease::MAX_TAKE {
            return Err(SpaceError::InvalidLease(format!(
                "a take may hold for {} at most, not {lease}",
                Lease::MAX_TAKE
            )));
        }
        self.open().await?;
        // `None`: the timeout reaches past what the clock can hold, so there is no deadline.
        let deadline = Instant::now().checked_add(timeout);
        let mut folds = self.peer.folds();
        loop {
            if self.halted() {
                return Ok(None); // a stopping agent takes nothing new
            }
            self.peer.space_pull_paced(&self.name, self.settle).await?;
            folds.borrow_and_update();
            let candidates = self
                .find_decoded(template, CANDIDATES_PER_PASS, &mut |view| {
                    decode(&view).map(|value| (view, value))
                })
                .await?;
            let mut claimed = false;
            for (candidate, value) in candidates {
                // One attempt before the clock is looked at (Java `tryTakeOnce`, then the
                // deadline): a candidate already held is skipped without a claim, so the attempt
                // ends at the first claim made.
                if claimed && deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                    return Ok(None);
                }
                if self.halted() {
                    return Ok(None);
                }
                let entry_id = candidate.entry_id().as_str();
                let Some(ticket) = self
                    .peer
                    .space_claim(&self.name, entry_id, self.agent_owned(), lease.millis())
                    .await?
                else {
                    continue; // claimed, completed, or withdrawn since the list was made
                };
                claimed = true;
                tokio::time::sleep(self.settle).await;
                self.peer.space_pull_paced(&self.name, self.settle).await?;
                folds.borrow_and_update();
                let _ =
                    tokio::time::timeout(self.settle.min(SETTLE_FOLD_WAIT), folds.changed()).await;
                if let Some(settled) = self
                    .peer
                    .space_settle(&self.name, entry_id, &ticket.holder, ticket.epoch)
                    .await?
                {
                    // The settled view names the holder and the state; the payload is the one
                    // found (an entry's signed record fixes it), which a block evicted during
                    // the settle window cannot take away (Java's `claimedValue`).
                    let entry = EntryView {
                        payload: candidate.payload,
                        ..settled
                    };
                    let taken = Taken {
                        // The stop signal stays with the take loop: the handle a handler is given
                        // (`Taken::space`, `TakeContext::space`) takes as any other does.
                        space: Space {
                            halt: None,
                            ..self.clone()
                        },
                        entry,
                        lease,
                        expires_at: ticket.expires_at,
                        ticket,
                    };
                    return Ok(Some((taken, value)));
                }
            }
            let now = Instant::now();
            if deadline.is_some_and(|deadline| now >= deadline) {
                return Ok(None);
            }
            if !claimed {
                // Nothing to claim: wait for a fold (an entry, a lapsed claim's successor) or
                // the end of this settle window, or for the agent's stop.
                let folded = tokio::select! {
                    folded = tokio::time::timeout(self.wait(deadline, now), folds.changed()) => folded,
                    () = self.halt_requested() => return Ok(None),
                };
                if let Ok(Err(_)) = folded {
                    return Err(PeerError::Closed.into());
                }
            }
        }
    }

    /// The take this handle's actor holds on `entry_id` (a live claim naming `<peerId>/rust`, or
    /// its agent under [`Space::as_agent`]), found by id: the holder may be another process on
    /// the same keystore (`aspace take`, then `aspace complete <id>`), or a take whose future was
    /// dropped. The space is pulled, and the call waits up to `timeout` for the claim to fold, as
    /// [`Space::read`] does. `Ok(None)` when the entry is not held here, its live claim names
    /// another holder, or it was completed or withdrawn.
    ///
    /// The [`Taken`] answered completes and renews as one [`Space::take`] answered; its
    /// [`Taken::lease`] is the hold left.
    pub async fn held(
        &self,
        entry_id: &EntryId,
        timeout: Duration,
    ) -> Result<Option<Taken>, SpaceError> {
        self.open().await?;
        let deadline = Instant::now().checked_add(timeout);
        let mut folds = self.peer.folds();
        loop {
            folds.borrow_and_update();
            if let Some((ticket, entry)) = self
                .peer
                .space_held(&self.name, entry_id.as_str(), self.agent_owned())
                .await?
            {
                let left = ticket
                    .expires_at
                    .saturating_sub(self.peer.clock().now_ms())
                    .max(1);
                let lease = Lease::from_millis(left)?;
                return Ok(Some(Taken {
                    space: self.clone(),
                    entry,
                    lease,
                    expires_at: ticket.expires_at,
                    ticket,
                }));
            }
            let now = Instant::now();
            if deadline.is_some_and(|deadline| now >= deadline) {
                return Ok(None);
            }
            self.peer.space_pull_paced(&self.name, self.settle).await?;
            if let Ok(Err(_)) =
                tokio::time::timeout(self.wait(deadline, now), folds.changed()).await
            {
                return Err(PeerError::Closed.into());
            }
        }
    }

    // ------------------------------------------------------------------------- watches

    /// Watches the entries matching `template`: every transition from now on ([`EventKind`]:
    /// `Written`, `Taken`, `Completed`, `Expired`, `Reappeared`), at least once each, in the
    /// order this peer derived them. Delivery never waits on the watcher: a watcher more than its
    /// queue's capacity behind loses its oldest events ([`watch`], [`SpaceEvents::dropped`]).
    ///
    /// # Cancel safety
    ///
    /// Cancel-safe: the events' owner exists before the watch is registered, so a future dropped
    /// at any point (`select!`, a timeout) leaves no watch behind.
    pub async fn watch(&self, template: &Template) -> Result<SpaceEvents, SpaceError> {
        self.open().await?;
        let queue = WatchQueue::new(self.watch_capacity, i64::MAX);
        let events = SpaceEvents::new(Arc::clone(&queue));
        self.peer
            .space_watch(&self.name, template.clone(), queue)
            .await?;
        Ok(events)
    }

    /// The leased push subscription of the Java space (`Space.notify`, `space.py`'s `notify`):
    /// `handler` runs, on a task of its own, for each transition of a matching entry until `lease`
    /// lapses on the peer's clock unless [`Subscription::renew`]ed, the subscription is closed, or
    /// the peer closes. Must be called within a Tokio runtime.
    ///
    /// The handler runs on the runtime: it must not block (a blocking handler holds one of the
    /// runtime's workers, and so the peer). The blocking facade runs its handlers on a thread of
    /// their own instead ([`crate::blocking::Space::notify`]).
    ///
    /// # Cancel safety
    ///
    /// Cancel-safe, as [`Space::watch`] is.
    pub async fn notify<F>(
        &self,
        template: &Template,
        lease: Lease,
        mut handler: F,
    ) -> Result<Subscription, SpaceError>
    where
        F: FnMut(SpaceEvent) + Send + 'static,
    {
        let (mut events, queue, clock) = self.subscribe(template, lease).await?;
        let task = tokio::spawn(async move {
            while let Some(event) = events.next().await {
                handler(event);
            }
        });
        Ok(Subscription::new(queue, clock, task))
    }

    /// The registration half of [`Space::notify`]: a watch lapsing `lease` from now on the peer's
    /// clock, its events, its queue, and the clock. Cancel-safe: the events own the queue before
    /// it is registered.
    pub(crate) async fn subscribe(
        &self,
        template: &Template,
        lease: Lease,
    ) -> Result<(SpaceEvents, Arc<WatchQueue>, SharedClock), SpaceError> {
        self.open().await?;
        let clock = Arc::clone(self.peer.clock());
        let expires_at = clock.now_ms().saturating_add(lease.millis());
        let queue = WatchQueue::new(self.watch_capacity, expires_at);
        let events = SpaceEvents::new(Arc::clone(&queue));
        self.peer
            .space_watch(&self.name, template.clone(), Arc::clone(&queue))
            .await?;
        Ok((events, queue, clock))
    }
}

// ---------------------------------------------------------------------------------------------
// A take

/// An entry this peer holds exclusively ([`Space::take`], Java `TakenEntry`): complete it (with a
/// result or without), renew the hold while working, or release it. Dropping it is releasing it.
#[derive(Debug)]
pub struct Taken {
    space: Space,
    entry: EntryView,
    lease: Lease,
    expires_at: i64,
    ticket: ClaimTicket,
}

impl Taken {
    /// The taken entry.
    pub fn entry(&self) -> &EntryView {
        &self.entry
    }

    /// The taken entry's id.
    pub fn entry_id(&self) -> &EntryId {
        self.entry.entry_id()
    }

    /// The space it was taken from.
    pub fn space(&self) -> &Space {
        &self.space
    }

    /// The holder: the AgentID the claim names.
    pub fn holder(&self) -> &str {
        &self.ticket.holder
    }

    /// The claim's epoch.
    pub fn epoch(&self) -> i64 {
        self.ticket.epoch
    }

    /// The hold the take asked for.
    pub fn lease(&self) -> Lease {
        self.lease
    }

    /// When the hold lapses unless renewed, epoch milliseconds.
    pub fn expires_at_millis(&self) -> i64 {
        self.expires_at
    }

    /// Completes the take (Java `Space.complete`, `space.py`'s `Taken.complete`): the entry is
    /// consumed for good, the completion signed by the holder (its agent when taken as one) and
    /// carrying the winning claim, so every member authenticates it. With `result` (a schema and
    /// a payload) a result entry is written into the same space under `result_lease` with
    /// `tags`, atomically: it is validated and prepared before the completion commits, so a
    /// result that cannot be written fails the call with the take still held. Answers the
    /// result's id.
    ///
    /// # Errors
    ///
    /// [`SpaceError::NotHeld`] when the hold lapsed or was lost (the entry may already be
    /// another member's). With the take still held and nothing sent: [`PeerError::InvalidArgument`]
    /// for a result tag that is not text, [`SpaceError::Refused`] with
    /// [`Refusal::Full`](crate::wire::fold::Refusal::Full) when the space has no room for the
    /// result, and the other errors of [`Space::write_value`].
    pub async fn complete(
        &self,
        result: Option<(&str, Value)>,
        result_lease: Lease,
        tags: Map,
    ) -> Result<Option<EntryId>, SpaceError> {
        let result = result.map(|(schema, payload)| ResultWrite {
            schema: schema.to_owned(),
            payload,
            lease_millis: result_lease.millis(),
            tags,
        });
        self.finish(result).await
    }

    /// Completes the take with `result` written, when given ([`Taken::complete`]).
    async fn finish(&self, result: Option<ResultWrite>) -> Result<Option<EntryId>, SpaceError> {
        self.space
            .peer
            .space_complete(
                &self.space.name,
                self.entry.entry_id().as_str(),
                &self.ticket,
                self.space.agent_owned(),
                result,
            )
            .await
    }

    /// Renews the hold to `lease` from now (Java `TakenEntry.renew`): the claim re-signed with the
    /// same epoch and stamp and a later expiry, which every member's claim lattice prefers.
    /// Answers the new expiry. [`SpaceError::NotHeld`] once the hold lapsed or was lost.
    pub async fn renew(&mut self, lease: Lease) -> Result<i64, SpaceError> {
        if lease > Lease::MAX_TAKE {
            return Err(SpaceError::InvalidLease(format!(
                "a take may hold for {} at most, not {lease}",
                Lease::MAX_TAKE
            )));
        }
        let expires_at = self
            .space
            .peer
            .space_renew_claim(
                &self.space.name,
                self.entry.entry_id().as_str(),
                &self.ticket,
                self.space.agent_owned(),
                lease.millis(),
            )
            .await?;
        self.expires_at = expires_at;
        self.lease = lease;
        Ok(expires_at)
    }

    /// Releases the take: it is no longer renewed. There is no un-claim on the wire (SPEC §7.4),
    /// so the hold lapses at [`Taken::expires_at_millis`] and the entry then reappears for every
    /// member (`Reappeared`).
    pub fn release(self) {}
}
