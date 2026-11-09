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

//! The [`Peer`] handle: starts a peer and queues calls to its actor.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use agentspaces_wire::bodies::{self, KIND_PIPE_DATA};
use agentspaces_wire::cbor::{self, Map, Value};
use agentspaces_wire::founding;
use agentspaces_wire::identity::AgentIdentity;
use agentspaces_wire::ids;
use tokio::sync::{broadcast, mpsc, oneshot, watch};

use super::actor::{self, Actor, Job, Settings, Start};
use super::{LinkInfo, PeerConfig, PeerCounters, PeerError, PeerEvent, RelaySignal, SpaceStore};
use crate::clock::SharedClock;
use crate::group::GroupSpec;
use crate::space::watch::WatchQueue;
use crate::space::{ClaimTicket, EntryId, EntryView, ResultWrite, Space, SpaceError, Template};

/// How many events a subscriber may fall behind before it misses some
/// ([`broadcast::error::RecvError::Lagged`]).
const EVENT_CAPACITY: usize = 1024;

/// A running dial-only peer: a cheap, cloneable handle to the actor that owns its state (see the
/// [module docs](super)). Every clone drives the same peer; the peer stops when the last clone is
/// dropped, or for good at [`Peer::close`].
///
/// Reads (`members`, `counters`, `space_states`, ...) answer from what the peer holds, also after
/// [`Peer::close`]. Verbs answer [`PeerError::Closed`] once the peer is closed.
#[derive(Clone)]
pub struct Peer {
    peer_id: Arc<str>,
    group_id: Arc<str>,
    jobs: mpsc::Sender<Job>,
    events: broadcast::Sender<PeerEvent>,
    link: watch::Receiver<Option<LinkInfo>>,
    folds: watch::Receiver<u64>,
    clock: SharedClock,
}

impl fmt::Debug for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Peer")
            .field("peer_id", &self.peer_id)
            .field("group_id", &self.group_id)
            .field("link", &*self.link.borrow())
            .finish()
    }
}

impl Peer {
    /// Starts a peer: dials the seeds in order until one accepts (a `tcp` or `tls` host name
    /// expanded to its addresses first), then joins.
    ///
    /// - [`GroupSpec::FoundingText`]: the GroupID derives from the text; the peer introduces
    ///   itself at once (a signed self-advertisement RUMOR on `peers`), announces CHANNEL_HELLO on
    ///   an attested link, and pulls the revocations.
    /// - [`GroupSpec::FoundingDocument`]: the document is verified here (SPEC §5.1) and its
    ///   GroupID joined as above.
    /// - [`GroupSpec::Join`]: the peer sends an unaddressed GROUP_AD_WANT (again every
    ///   [`GROUP_AD_WANT_INTERVAL`](super::GROUP_AD_WANT_INTERVAL)) and waits up to
    ///   [`PeerConfig::join_timeout`] for a GROUP_AD that verifies to exactly that GroupID,
    ///   ignoring every other answer, before it introduces itself. On timeout the peer is closed
    ///   and [`PeerError::JoinTimeout`] returned.
    pub async fn start(config: PeerConfig) -> Result<Peer, PeerError> {
        let PeerConfig {
            identity,
            group,
            seeds,
            dialers,
            clock,
            reconnect_interval,
            reconnect_window,
            peer_ad_interval,
            dial_timeout,
            join_timeout,
            resource_hints,
            founder,
            send_queue_bytes,
            send_stall_timeout,
            space_max_entries,
            fetched_block_bytes,
        } = config;
        let (group_id, founding, joining) = resolve_group(&group)?;
        let settings = Settings::new(
            reconnect_interval,
            reconnect_window,
            peer_ad_interval,
            dial_timeout,
            send_queue_bytes,
            send_stall_timeout,
        )
        .with_bounds(space_max_entries, fetched_block_bytes);
        let seeds = actor::expand_seeds(&seeds, &dialers, settings.dial_timeout).await;
        if seeds.is_empty() {
            return Err(PeerError::NoSeeds);
        }
        let (channel, seed) =
            actor::dial_first(&seeds, &dialers, &identity, settings.dial_timeout).await?;
        let (events, _) = broadcast::channel(EVENT_CAPACITY);
        let (link_watch, link) = watch::channel(None);
        let (folds_tx, folds) = watch::channel(0);
        let peer_id: Arc<str> = Arc::from(identity.peer_id());
        let jobs = actor::spawn(
            Start {
                identity,
                group: group_id.clone(),
                founder,
                founding,
                joining,
                clock: Arc::clone(&clock),
                settings,
                dialers,
                seeds,
                resource_hints,
                events: events.clone(),
                link_watch,
                folds: folds_tx,
            },
            channel,
            seed,
        );
        let peer = Peer {
            peer_id,
            group_id: Arc::from(group_id.as_str()),
            jobs,
            events,
            link,
            folds,
            clock,
        };
        if joining {
            let (waiter, ready) = oneshot::channel();
            peer.call(move |actor| actor.await_ready(waiter)).await?;
            let outcome = tokio::time::timeout(join_timeout, ready).await;
            let failure = match outcome {
                Ok(Ok(Ok(()))) => None,
                Ok(Ok(Err(error))) => Some(error),
                Ok(Err(_)) => Some(PeerError::Closed),
                Err(_) => Some(PeerError::JoinTimeout {
                    group: group_id,
                    timeout: join_timeout,
                }),
            };
            if let Some(error) = failure {
                let _ = peer.close().await;
                return Err(error);
            }
        }
        Ok(peer)
    }

    /// Runs `call` on the actor and returns its answer; [`PeerError::Closed`] when the actor is
    /// gone.
    pub(super) async fn call<R: Send + 'static>(
        &self,
        call: impl FnOnce(&mut Actor) -> R + Send + 'static,
    ) -> Result<R, PeerError> {
        let (reply, answer) = oneshot::channel();
        let job: Job = Box::new(move |actor| {
            let _ = reply.send(call(actor));
        });
        self.jobs.send(job).await.map_err(|_| PeerError::Closed)?;
        answer.await.map_err(|_| PeerError::Closed)
    }

    /// This peer's PeerID.
    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }

    /// The GroupID this peer joined.
    pub fn group_id(&self) -> &str {
        &self.group_id
    }

    /// Whether the peer holds a link now.
    pub fn is_connected(&self) -> bool {
        self.link.borrow().is_some()
    }

    /// The link the peer holds now, if any.
    pub fn link(&self) -> Option<LinkInfo> {
        self.link.borrow().clone()
    }

    /// A receiver of the peer's events from now on.
    pub fn subscribe(&self) -> broadcast::Receiver<PeerEvent> {
        self.events.subscribe()
    }

    /// The members heard from: every PeerID that signed a frame this peer accepted or whose
    /// signed advertisement the `peers` stream carried, less those since revoked. The view holds
    /// 65 536 members; when full, a newcomer replaces the oldest member known only by a frame.
    pub async fn members(&self) -> Vec<String> {
        self.call(|actor| actor.members()).await.unwrap_or_default()
    }

    /// A member's verified self-advertisement, once the `peers` stream carried one: the newest
    /// for this group, while it lives and its issuer is not revoked.
    pub async fn member_ad(&self, peer: &str) -> Option<Map> {
        let peer = peer.to_owned();
        self.call(move |actor| actor.member_ad(&peer))
            .await
            .ok()
            .flatten()
    }

    /// The members this peer's link reaches: those that signed a frame that arrived on it (not
    /// inside a relay).
    pub async fn reachable(&self) -> Vec<String> {
        self.call(|actor| actor.reachable())
            .await
            .unwrap_or_default()
    }

    /// The seed's PeerID, learned from the first frame it addressed to this peer; this peer's
    /// `relay.via`.
    pub async fn seed_peer(&self) -> Option<String> {
        self.call(|actor| actor.seed_peer()).await.ok().flatten()
    }

    /// The verified signed group advertisement this peer joined with (a join by id or a founding
    /// document); `None` for a group founded from text.
    pub async fn founding(&self) -> Option<Map> {
        self.call(|actor| actor.founding()).await.ok().flatten()
    }

    /// The live agent cards the `ads` stream carried, without those of a revoked peer, agent, or
    /// agent key. Each names one of its issuer's own agents (`<issuer>/<local name>`; a card
    /// naming another peer's agent is refused on arrival), and each is the newest its issuer
    /// issued under its id: two issuers' cards under one id are both held, neither replacing the
    /// other.
    pub async fn cards(&self) -> Vec<Map> {
        self.call(|actor| actor.cards()).await.unwrap_or_default()
    }

    /// A renewing subordinate identity of this peer for its agent `<peerId>/<local_name>` (SPEC
    /// §4.2, Java `PeerIdentity.renewingSubordinate`): a fresh key certified by this peer from now
    /// for `ttl_iso` (`java.time.Duration` text, `"PT24H"` as Java's binders use), re-certified at
    /// half-life whenever the peer signs as it. [`Space::as_agent`] acts as it; every member then
    /// stores what it writes, claims, and completes AGENT_ATTESTED.
    ///
    /// # Errors
    ///
    /// [`PeerError::Identity`] for a local name that is empty or contains `/`, or a lifetime that
    /// does not parse; [`PeerError::Closed`] on a closed peer.
    pub async fn agent_identity(
        &self,
        local_name: &str,
        ttl_iso: &str,
    ) -> Result<AgentIdentity, PeerError> {
        let local_name = local_name.to_owned();
        let ttl_iso = ttl_iso.to_owned();
        self.call(move |actor| actor.agent_identity(&local_name, &ttl_iso))
            .await?
    }

    /// Runs `sign` on the actor with this peer's identity, `agent` as the peer holds it (its
    /// certificate renewed at half-life first), and the time now in epoch milliseconds: how an
    /// advertisement this peer issues for one of its agents (an `AgentCard`) is built and
    /// certified. The closure must be quick, as every call on the actor.
    pub(crate) async fn with_signer<R: Send + 'static>(
        &self,
        agent: Option<AgentIdentity>,
        sign: impl FnOnce(&agentspaces_wire::identity::Identity, Option<&AgentIdentity>, i64) -> R
        + Send
        + 'static,
    ) -> Result<R, PeerError> {
        self.call(move |actor| actor.with_signer(agent, sign))
            .await?
    }

    /// The live advertisements of one type (`AgentCard`, `CapabilityAdvertisement`, ...), without
    /// those of a revoked issuer: the newest each issuer issued under each id (an issuer replaces
    /// only its own advertisements).
    pub async fn ads(&self, ad_type: &str) -> Vec<Map> {
        let ad_type = ad_type.to_owned();
        self.call(move |actor| actor.ads(&ad_type))
            .await
            .unwrap_or_default()
    }

    /// What the peer has counted.
    pub async fn counters(&self) -> PeerCounters {
        self.call(|actor| actor.counters())
            .await
            .unwrap_or_default()
    }

    /// The last relay signals (at most 64) relays sent back about frames they could not carry.
    pub async fn relay_signals(&self) -> Vec<RelaySignal> {
        self.call(|actor| actor.relay_signals())
            .await
            .unwrap_or_default()
    }

    /// Whether the group's revocations revoke a peer (by PeerID) or an agent (by AgentID).
    pub async fn is_revoked(&self, peer_or_agent: &str) -> bool {
        let id = peer_or_agent.to_owned();
        self.call(move |actor| actor.revoked(&id))
            .await
            .unwrap_or_default()
    }

    /// Anti-entropy pull of a space (SPEC §5.3): an empty digest for `space:<name>` with the
    /// revocation streams riding along. Pulled again after every reconnect; without a link the
    /// pull waits for the next one.
    ///
    /// Pulling (or writing) a space opens it: the peer folds only spaces it opened, and data
    /// arriving for any other space is not kept ([`PeerCounters::unopened_space_items`]). A
    /// pull the link's full queue refuses answers [`PeerError::SendOverflow`].
    pub async fn pull_space(&self, space: &str) -> Result<(), PeerError> {
        let space = space.to_owned();
        self.call(move |actor| actor.pull_space(&space)).await?
    }

    /// Closes `space`: the peer drops what it folded of it and stops pulling it after a
    /// reconnect, so the slot counts no more against the bound of open spaces (1024), as for a
    /// space never opened. A later pull, write, read, or take opens it again (and pulls it anew).
    /// Answers `false`, closing nothing, while a watch follows it (or when it was not open). A
    /// take this peer holds there stays held by the group: completing it later pulls the space
    /// again ([`Space::held`](crate::space::Space::held)).
    pub async fn close_space(&self, space: &str) -> Result<bool, PeerError> {
        let space = space.to_owned();
        self.call(move |actor| actor.close_space(&space)).await
    }

    /// How many spaces are open now.
    pub async fn open_spaces(&self) -> usize {
        self.call(|actor| actor.open_spaces())
            .await
            .unwrap_or_default()
    }

    /// Anti-entropy pull of the `ads` stream (SPEC §6.2); pulled again after every reconnect.
    pub async fn pull_ads(&self) -> Result<(), PeerError> {
        self.call(|actor| actor.pull_ads()).await?
    }

    /// Anti-entropy pull of the revocation streams (SPEC §5.6).
    pub async fn pull_revocations(&self) -> Result<(), PeerError> {
        self.call(|actor| actor.pull_revocations()).await?
    }

    /// Writes one signed entry into space `space` and returns its id: the record and state as
    /// the wire builders make them (`<peerId>/rust` the issuer, or `agent`'s own when given),
    /// folded here at once and rumored on `space:<space>` under `w:<entry id>`. The payload is
    /// `payload`'s CBOR, stored as a block when it exceeds the inline limit (and refused when it
    /// exceeds the block cap, 8 MiB less 64 KiB, which no frame can carry); `tags` travel inside
    /// the signed record. Without a link, or while the link's queue is busy, the rumor waits in
    /// the outbox for room.
    pub async fn write_entry(
        &self,
        space: &str,
        type_name: &str,
        payload: Value,
        lease_millis: i64,
        tags: Map,
        agent: Option<&AgentIdentity>,
    ) -> Result<String, PeerError> {
        let space = space.to_owned();
        let type_name = type_name.to_owned();
        let agent = agent.cloned();
        self.call(move |actor| {
            actor.write_entry(&space, &type_name, &payload, lease_millis, &tags, agent)
        })
        .await?
    }

    /// The joined states of a space, in the order their entries first folded.
    pub async fn space_states(&self, space: &str) -> Vec<Map> {
        let space = space.to_owned();
        self.call(move |actor| actor.space_states(&space))
            .await
            .unwrap_or_default()
    }

    /// The winning signed claims of a space, by entry id.
    pub async fn space_claims(&self, space: &str) -> Vec<(String, Map)> {
        let space = space.to_owned();
        self.call(move |actor| actor.space_claims(&space))
            .await
            .unwrap_or_default()
    }

    /// Runs `inspect` over a space's store on the actor (a read of anything the store answers);
    /// `None` when the space was never opened.
    ///
    /// The closure runs on the peer's actor, so it must be quick: the peer handles nothing else
    /// meanwhile. If it panics, the panic is caught there and resumed here, in the caller, and
    /// the peer carries on.
    pub async fn with_space<R: Send + 'static>(
        &self,
        space: &str,
        inspect: impl FnOnce(&SpaceStore) -> R + Send + 'static,
    ) -> Option<R> {
        let space = space.to_owned();
        let answer = self
            .call(move |actor| actor.with_space(&space, inspect))
            .await
            .ok()
            .flatten()?;
        match answer {
            Ok(value) => Some(value),
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }

    /// The payload bytes of an entry: inline, a held block, or the CBOR null. A block not yet
    /// held is asked for (of its issuer and the seed) and `None` returned.
    pub async fn payload_of(&self, space: &str, entry_id: &str) -> Option<Vec<u8>> {
        let space = space.to_owned();
        let entry_id = entry_id.to_owned();
        self.call(move |actor| actor.payload_of(&space, &entry_id))
            .await
            .ok()
            .flatten()
    }

    /// Publishes an advertisement this peer issued (an `AgentCard`, an `AssetCard`) on the `ads`
    /// stream in the stored form, under `<id>:<issued millis>`; this peer's cache holds it too.
    /// The advertisement is sent as given, but every Rust cache, this peer's included, refuses
    /// an `AgentCard` whose `agent` is not one of this peer's own (`<peerId>/<local name>`).
    pub async fn publish_ad(&self, ad_type: &str, ad: Map) -> Result<(), PeerError> {
        let ad_type = ad_type.to_owned();
        self.call(move |actor| actor.publish_ad(&ad_type, &ad))
            .await?
    }

    /// Sends one addressed frame to member `to`: directly to the seed, or wrapped in a
    /// RELAY_FRAME the seed carries for any other member (SPEC §5.4).
    pub async fn send_addressed(
        &self,
        kind: &str,
        body: Vec<u8>,
        to: &str,
    ) -> Result<(), PeerError> {
        let kind = kind.to_owned();
        let to = to.to_owned();
        self.call(move |actor| actor.send_addressed(&kind, &body, &to))
            .await?
    }

    /// Sends one capability frame (PIPE_DATA `{capability, payload}`) to member `to`.
    pub async fn send_pipe(
        &self,
        to: &str,
        capability: &str,
        payload: &[u8],
    ) -> Result<(), PeerError> {
        self.send_addressed(
            KIND_PIPE_DATA,
            bodies::pipe_data_body(capability, payload),
            to,
        )
        .await
    }

    /// Stores a block here and returns its id; served to any member that asks (at most once a
    /// second to each). A block over the block cap (8 MiB less 64 KiB) is refused, as is one past
    /// the 256 MiB of own blocks a peer holds; blocks fetched for entries read never displace
    /// these.
    pub async fn put_block(&self, data: Vec<u8>) -> Result<String, PeerError> {
        self.call(move |actor| actor.put_block(data)).await?
    }

    /// A block held here.
    pub async fn block(&self, cid: &str) -> Option<Vec<u8>> {
        let cid = cid.to_owned();
        self.call(move |actor| actor.block(&cid))
            .await
            .ok()
            .flatten()
    }

    /// The id of the block the payload of entry `entry_id` in `space` travels as, when this peer
    /// wrote it (the block is one of its own): payloads over the inline limit (64 KiB) are held
    /// by their writer and fetched from it, so a writer about to leave makes sure another member
    /// holds the block first ([`Peer::probe_block`]).
    pub async fn own_payload_block(&self, space: &str, entry_id: &str) -> Option<String> {
        let space = space.to_owned();
        let entry_id = entry_id.to_owned();
        self.call(move |actor| actor.own_payload_block(&space, &entry_id))
            .await
            .ok()
            .flatten()
    }

    /// Asks member `to` (the seed, say) for one of this peer's own blocks to learn whether it
    /// holds it: when it does, it answers with the block, and the peer tells
    /// [`PeerEvent::BlockHeld`]; a member that does not hold it does not answer, so ask again
    /// after a while. Subscribe ([`Peer::subscribe`]) before asking.
    ///
    /// # Errors
    ///
    /// [`PeerError::InvalidArgument`] for a block that is not one of this peer's own,
    /// [`PeerError::Closed`] once closed, and the errors of sending an addressed frame.
    pub async fn probe_block(&self, cid: &str, to: &str) -> Result<(), PeerError> {
        let cid = cid.to_owned();
        let to = to.to_owned();
        self.call(move |actor| actor.probe_block(&cid, &to)).await?
    }

    /// Closes the peer for good: the link closes and no redial follows. Idempotent.
    pub async fn close(&self) -> Result<(), PeerError> {
        match self.call(|actor| actor.close()).await {
            Ok(()) | Err(PeerError::Closed) => Ok(()),
            Err(other) => Err(other),
        }
    }
}

/// The space verbs' calls on the actor ([`crate::space`] drives them; see
/// `actor::space_ops`).
impl Peer {
    /// A handle on space `name` of this peer's group ([`Space`]): cheap, cloneable, and opened
    /// (pulled) on its first use.
    pub fn space(&self, name: &str) -> Space {
        Space::new(self.clone(), name)
    }

    /// The wall clock the peer stamps and leases with.
    pub(crate) fn clock(&self) -> &SharedClock {
        &self.clock
    }

    /// A receiver of the fold counter: it changes whenever a state or claim folds unrefused.
    pub(crate) fn folds(&self) -> watch::Receiver<u64> {
        self.folds.clone()
    }

    pub(crate) async fn space_open(&self, space: &str) -> Result<(), SpaceError> {
        let space = space.to_owned();
        self.call(move |actor| actor.space_open(&space)).await?
    }

    pub(crate) async fn space_pull_paced(
        &self,
        space: &str,
        settle: Duration,
    ) -> Result<(), SpaceError> {
        let space = space.to_owned();
        self.call(move |actor| actor.space_pull_paced(&space, settle))
            .await?
    }

    pub(crate) async fn space_find(
        &self,
        space: &str,
        template: Template,
        limit: usize,
    ) -> Result<Vec<EntryView>, SpaceError> {
        let space = space.to_owned();
        self.call(move |actor| actor.space_find(&space, &template, limit))
            .await?
    }

    pub(crate) async fn space_pending(
        &self,
        space: &str,
        template: Template,
    ) -> Result<usize, SpaceError> {
        let space = space.to_owned();
        self.call(move |actor| actor.space_pending(&space, &template))
            .await?
    }

    pub(crate) async fn space_entry(
        &self,
        space: &str,
        entry_id: &str,
    ) -> Result<Option<EntryView>, SpaceError> {
        let space = space.to_owned();
        let entry_id = entry_id.to_owned();
        Ok(self
            .call(move |actor| actor.space_entry(&space, &entry_id))
            .await?)
    }

    pub(crate) async fn space_claim(
        &self,
        space: &str,
        entry_id: &str,
        agent: Option<AgentIdentity>,
        lease_millis: i64,
    ) -> Result<Option<ClaimTicket>, SpaceError> {
        let space = space.to_owned();
        let entry_id = entry_id.to_owned();
        self.call(move |actor| actor.space_claim(&space, &entry_id, agent, lease_millis))
            .await?
    }

    pub(crate) async fn space_settle(
        &self,
        space: &str,
        entry_id: &str,
        holder: &str,
        epoch: i64,
    ) -> Result<Option<EntryView>, SpaceError> {
        let space = space.to_owned();
        let entry_id = entry_id.to_owned();
        let holder = holder.to_owned();
        Ok(self
            .call(move |actor| actor.space_settle(&space, &entry_id, &holder, epoch))
            .await?)
    }

    pub(crate) async fn space_held(
        &self,
        space: &str,
        entry_id: &str,
        agent: Option<AgentIdentity>,
    ) -> Result<Option<(ClaimTicket, EntryView)>, SpaceError> {
        let space = space.to_owned();
        let entry_id = entry_id.to_owned();
        Ok(self
            .call(move |actor| actor.space_held(&space, &entry_id, agent))
            .await?)
    }

    pub(crate) async fn space_renew_claim(
        &self,
        space: &str,
        entry_id: &str,
        ticket: &ClaimTicket,
        agent: Option<AgentIdentity>,
        lease_millis: i64,
    ) -> Result<i64, SpaceError> {
        let space = space.to_owned();
        let entry_id = entry_id.to_owned();
        let holder = ticket.holder.clone();
        let epoch = ticket.epoch;
        self.call(move |actor| {
            actor.space_renew_claim(&space, &entry_id, &holder, epoch, agent, lease_millis)
        })
        .await?
    }

    pub(crate) async fn space_complete(
        &self,
        space: &str,
        entry_id: &str,
        ticket: &ClaimTicket,
        agent: Option<AgentIdentity>,
        result: Option<ResultWrite>,
    ) -> Result<Option<EntryId>, SpaceError> {
        let space = space.to_owned();
        let entry_id = entry_id.to_owned();
        let holder = ticket.holder.clone();
        let epoch = ticket.epoch;
        self.call(move |actor| {
            actor.space_complete(&space, &entry_id, &holder, epoch, agent, result)
        })
        .await?
    }

    pub(crate) async fn space_renew_write(
        &self,
        space: &str,
        entry_id: &str,
        agent: Option<AgentIdentity>,
        lease_millis: i64,
    ) -> Result<(), SpaceError> {
        let space = space.to_owned();
        let entry_id = entry_id.to_owned();
        self.call(move |actor| actor.space_renew_write(&space, &entry_id, agent, lease_millis))
            .await?
    }

    pub(crate) async fn space_cancel(
        &self,
        space: &str,
        entry_id: &str,
        agent: Option<AgentIdentity>,
    ) -> Result<(), SpaceError> {
        let space = space.to_owned();
        let entry_id = entry_id.to_owned();
        self.call(move |actor| actor.space_cancel(&space, &entry_id, agent))
            .await?
    }

    pub(crate) async fn space_watch(
        &self,
        space: &str,
        template: Template,
        queue: Arc<WatchQueue>,
    ) -> Result<(), SpaceError> {
        let space = space.to_owned();
        self.call(move |actor| actor.space_watch(&space, template, queue))
            .await?
    }
}

/// The GroupID to join, the verified founding when one is held, and whether the founding must
/// still be asked for (a join by id).
fn resolve_group(group: &GroupSpec) -> Result<(String, Option<Map>, bool), PeerError> {
    match group {
        GroupSpec::FoundingText(text) => {
            Ok((ids::group_id_from_founding(text.as_bytes()), None, false))
        }
        GroupSpec::Join(uri) => ids::parse_group_id(uri)
            .map(|id| (id.to_owned(), None, true))
            .ok_or_else(|| PeerError::InvalidGroup(uri.clone())),
        GroupSpec::FoundingDocument(bytes) => {
            let signed = cbor::decode(bytes).map_err(|_| PeerError::InvalidFounding)?;
            let id = founding::verify_signed_group_ad(&signed).ok_or(PeerError::InvalidFounding)?;
            let signed = signed.into_map().ok_or(PeerError::InvalidFounding)?;
            Ok((id, Some(signed), false))
        }
    }
}
