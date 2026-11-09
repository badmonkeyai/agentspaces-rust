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

//! The actor: the one task that owns a peer's state, and the link tasks around it.
//!
//! Every mutation happens here, in the order the actor sees its inputs: a job from a [`Peer`]
//! handle (a closure over the actor with a oneshot reply), a message from a link's reader, pump,
//! or the redial task ([`Inbound`]), or a timer (the self-advertisement's re-lease, the join's
//! re-ask). The actor never awaits anything but its next input: it offers frames to a link's
//! pump queue without waiting ([`SendQueue::offer`]), and a dial runs in its own task.
//!
//! The space verbs and the entry transitions watches hear of live in [`space_ops`].
//!
//! [`Peer`]: super::Peer

mod space_ops;

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use agentspaces_wire::ads as wire_ads;
use agentspaces_wire::bodies::{
    self, KIND_ACK, KIND_BLOCK, KIND_BLOCK_WANT, KIND_CHANNEL_HELLO, KIND_DIGEST, KIND_GROUP_AD,
    KIND_PING, KIND_PING_REQ, KIND_PIPE_DATA, KIND_PULL_RESP, KIND_RELAY_FRAME, KIND_RUMOR,
    RELAY_SIGNAL_CAPABILITY, RUMOR_HOPS, RelaySignal, Rumor, STREAM_ADS, STREAM_PEERS,
    STREAM_SPACE_PREFIX,
};
use agentspaces_wire::cbor::{self, Map, Value};
use agentspaces_wire::crypto;
use agentspaces_wire::envelope::{self, Auth, FrameFilter};
use agentspaces_wire::fold::{FoldContext, FoldOutcome, Refusal, SpaceStore};
use agentspaces_wire::founding;
use agentspaces_wire::hlc::{Hlc, Stamp};
use agentspaces_wire::identity::{AgentIdentity, Identity};
use agentspaces_wire::ids;
use agentspaces_wire::limits::{INLINE_PAYLOAD_LIMIT, MAX_FRAME_BYTES};
use agentspaces_wire::records::{self, EntryWrite, NULL_PAYLOAD, PayloadSource};
use agentspaces_wire::revocation::{self, Registry};
use agentspaces_wire::seed::Seed;
use agentspaces_wire::time;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, broadcast, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use super::ads::{AdCache, pulled_ads};
use super::blocks::{
    BlockStore, MAX_FETCHED_BLOCK_BYTES, MAX_OWN_BLOCK_BYTES, MAX_SINGLE_BLOCK_BYTES, Refused,
};
use super::members::MemberView;
use super::spaces::{Spaces, parse_delta, parse_sync, space_name};
use super::{
    DEFAULT_AGENT_NAME, FilterCounters, GROUP_AD_WANT_INTERVAL, LinkInfo, PeerCounters, PeerError,
    PeerEvent,
};
use crate::clock::SharedClock;
use crate::transport::{Channel, Closer, Dialer, FrameReceiver, FrameSender, TransportError};
use space_ops::{COLLECT_INTERVAL, Deferred, SWEEP_INTERVAL, Watcher};

/// A call queued by a [`Peer`](super::Peer) handle: it runs on the actor and replies itself.
pub(super) type Job = Box<dyn FnOnce(&mut Actor) + Send>;

/// How many handle calls may wait for the actor.
pub(super) const JOB_QUEUE: usize = 64;
/// How many verified frames (and link events) may wait for the actor before readers wait. The
/// frames are bounded by bytes too ([`INBOUND_BUDGET_BYTES`]).
const INBOUND_QUEUE: usize = 1024;
/// The bytes of verified frames one link may have waiting for the actor (Java
/// `FramePump.DEFAULT_CAP_BYTES`): past it the link's reader waits, so the transport stops
/// reading the socket and a fast or hostile seed cannot grow the peer's memory.
pub(super) const INBOUND_BUDGET_BYTES: usize = 64 * 1024 * 1024;
/// The most members (and reachable members) a peer remembers.
const MAX_MEMBERS: usize = 1 << 16;
/// The most frame kinds named in the ignored-kind counter.
const MAX_NAMED_KINDS: usize = 64;
/// The counter name of every further ignored kind.
const OTHER_KINDS: &str = "<other>";
/// The most writes held while the peer has no link (or its queue has no room for them).
const OUTBOX_LIMIT: usize = 1024;
/// The relay signals kept (the Python peer keeps 64).
const RELAY_SIGNALS_KEPT: usize = 64;
/// The block ids a peer remembers asking for.
const MAX_ASKED_BLOCKS: usize = 4096;
/// How often one block may be asked for, and answered to one member.
const BLOCK_ASK_INTERVAL: Duration = Duration::from_secs(1);
/// The (member, block) pairs a peer remembers answering.
const MAX_SERVED_BLOCKS: usize = 4096;
/// The indirect probes (PING_REQ) a peer carries at once (Java `PeerNode` relays, 1024).
const MAX_RELAYS: usize = 1024;
/// The largest logical counter of a stamp this peer merges into its clock. Honest nodes never
/// issue 65 536 stamps within one millisecond; a stamp near `i32::MAX` would pin the clock's
/// counter and make every later stamp this peer issues the same, so receivers drop its frames
/// as replays.
const MAX_OBSERVED_LOGICAL: i32 = 1 << 16;
/// Java's default member TTL (`GroupMembership.Config.defaults().memberTtl`): a member not
/// heard from for this long is dropped from a Java node's view.
const MEMBER_TTL: Duration = Duration::from_secs(30);
/// Java's default probe period (`GroupMembership.Config.defaults().probeInterval`), and how far a
/// quiet group stretches it (`GroupMembership.MAX_QUIET_STRETCH`, a factor of 4).
const PROBE_INTERVAL: Duration = Duration::from_secs(1);
const QUIET_STRETCH: u32 = 4;
/// An upper bound on what a signed frame adds to its body: the envelope's other fields (group,
/// kind, sender, recipient, stamp), the sender's key, the signature, and the CBOR around them.
const FRAME_OVERHEAD: usize = 1024;
/// The shortest and longest timer a peer accepts from its configuration.
const MIN_TIMER: Duration = Duration::from_millis(1);
const MAX_TIMER: Duration = Duration::from_secs(365 * 24 * 60 * 60);

/// The timings and bounds the actor and its tasks run on, clamped to sane ranges.
#[derive(Debug, Clone)]
pub(super) struct Settings {
    pub reconnect_interval: Duration,
    pub reconnect_window: Duration,
    pub peer_ad_interval: Duration,
    pub dial_timeout: Duration,
    pub send_queue_bytes: usize,
    pub send_stall_timeout: Duration,
    /// The bound of each space's store (`PeerConfig::space_max_entries`).
    pub space_max_entries: usize,
    /// The fetched-block budget (`PeerConfig::fetched_block_bytes`).
    pub fetched_block_bytes: usize,
}

impl Settings {
    /// Settings with every duration clamped to `1 ms ..= 365 days` (a zero period would spin
    /// and an enormous one would overflow the timer arithmetic).
    pub fn new(
        reconnect_interval: Duration,
        reconnect_window: Duration,
        peer_ad_interval: Duration,
        dial_timeout: Duration,
        send_queue_bytes: usize,
        send_stall_timeout: Duration,
    ) -> Self {
        let clamp = |d: Duration| d.clamp(MIN_TIMER, MAX_TIMER);
        Self {
            reconnect_interval: clamp(reconnect_interval),
            reconnect_window: clamp(reconnect_window),
            peer_ad_interval: clamp(peer_ad_interval),
            dial_timeout: clamp(dial_timeout),
            send_queue_bytes: send_queue_bytes.max(1),
            send_stall_timeout: clamp(send_stall_timeout),
            space_max_entries: agentspaces_wire::fold::DEFAULT_MAX_ENTRIES,
            fetched_block_bytes: MAX_FETCHED_BLOCK_BYTES,
        }
    }

    /// These settings with the bound of each space's store (at least 1) and the fetched-block
    /// budget.
    pub fn with_bounds(self, space_max_entries: usize, fetched_block_bytes: usize) -> Self {
        Self {
            space_max_entries: space_max_entries.max(1),
            fetched_block_bytes,
            ..self
        }
    }
}

/// How often the self-advertisement is re-leased in a group of `members` other members, as Java's
/// `PeerNode.refreshIntervalMillis` refreshes its own: the configured `interval`, unless the
/// group's probe cycle (one member per [`PROBE_INTERVAL`], stretched [`QUIET_STRETCH`] times
/// when quiet) has outgrown the [`MEMBER_TTL`]. Past that size the probes cannot reach every
/// member inside the TTL, so the re-lease is the keepalive and runs at half the TTL at most,
/// leaving a whole interval of margin before a Java seed expires this peer.
fn re_lease_period(interval: Duration, members: usize) -> Duration {
    let cycle = u32::try_from(members.saturating_add(1))
        .ok()
        .and_then(|count| PROBE_INTERVAL.checked_mul(count))
        .and_then(|cycle| cycle.checked_mul(QUIET_STRETCH))
        .unwrap_or(Duration::MAX);
    if cycle < MEMBER_TTL {
        interval
    } else {
        interval.min(MEMBER_TTL / 2)
    }
}

/// What starts an actor.
pub(super) struct Start {
    pub identity: Identity,
    pub group: String,
    pub founder: Option<String>,
    pub founding: Option<Map>,
    pub joining: bool,
    pub clock: SharedClock,
    pub settings: Settings,
    pub dialers: Vec<Arc<dyn Dialer>>,
    pub seeds: Vec<Seed>,
    pub resource_hints: Map,
    pub events: broadcast::Sender<PeerEvent>,
    pub link_watch: watch::Sender<Option<LinkInfo>>,
    /// Counts the folds that were not refused (states and claims), so a waiting read or take
    /// wakes on the next one.
    pub folds: watch::Sender<u64>,
}

/// What a link's reader and pump and the redial task tell the actor.
pub(super) enum Inbound {
    /// A frame that verified on link `link`, with how it was authenticated, and its share of the
    /// link's inbound byte budget ([`INBOUND_BUDGET_BYTES`]), given back once it is handled.
    Frame {
        link: u64,
        env: Map,
        auth: Auth,
        budget: OwnedSemaphorePermit,
    },
    /// A frame that did not verify on link `link`.
    Malformed { link: u64 },
    /// Link `link`'s send queue drained after the actor asked to hear of it: the held writes may
    /// go out.
    Relief { link: u64 },
    /// Link `link` ended.
    Lost { link: u64 },
    /// Redial `attempt` opened a channel to `seed`.
    Dialed {
        channel: Box<Channel>,
        seed: Seed,
        attempt: u64,
    },
    /// Redial `attempt` ran out of its window.
    GaveUp { attempt: u64 },
}

/// A frame handler's verdict on a body it could not read: counted as malformed.
struct Malformed;

/// The outcome of offering a frame to a link's pump.
enum Offer {
    Queued,
    Full,
    Closed,
}

/// How much of a link's send queue a frame may fill.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Budget {
    /// The whole queue ([`Settings::send_queue_bytes`]): the protocol's own small frames and the
    /// owner's sends, each awaited by its caller.
    Whole,
    /// Half of it: what can come in bursts the far end did not pace. The writes flushed from
    /// the outbox wait there for room, and a block answer is skipped (the asker asks again), so
    /// a burst never fills a healthy link's queue.
    Half,
}

/// What a link's pump and the actor share.
#[derive(Debug, Default)]
struct PumpShared {
    /// The bytes offered and not yet handed to the transport.
    queued: AtomicUsize,
    /// Set by the actor when writes wait for room; the pump answers with [`Inbound::Relief`]
    /// once the queue has drained to a quarter.
    wants_relief: AtomicBool,
    /// Set by the pump when a frame waited [`Settings::send_stall_timeout`] for the transport:
    /// the far end stopped reading and the pump closed the link.
    stalled: AtomicBool,
}

/// A link's outbound queue, bounded by bytes and never waited on: the actor offers, the pump
/// task drains into the transport and is the only one that waits.
///
/// The bytes are counted until the pump hands a frame to the transport, whose own queue holds
/// at most [`crate::transport::CHANNEL_QUEUE`] frames; so a link holds at most its bound plus
/// that many frames plus the one being written.
struct SendQueue {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    shared: Arc<PumpShared>,
}

impl SendQueue {
    /// Whether a frame of `length` bytes fits under `limit`: always when nothing is queued (a
    /// frame larger than the bound goes alone, as Java's `FramePump` lets it).
    fn has_room(&self, length: usize, limit: usize) -> bool {
        let queued = self.shared.queued.load(Ordering::SeqCst);
        queued == 0 || queued.saturating_add(length) <= limit
    }

    /// Queues `frame` when it fits under `limit` ([`SendQueue::has_room`]).
    fn offer(&self, frame: Vec<u8>, limit: usize) -> Offer {
        let length = frame.len();
        if !self.has_room(length, limit) {
            return Offer::Full;
        }
        self.shared.queued.fetch_add(length, Ordering::SeqCst);
        if self.tx.send(frame).is_err() {
            self.shared.queued.fetch_sub(length, Ordering::SeqCst);
            return Offer::Closed;
        }
        Offer::Queued
    }
}

/// The link the actor holds.
struct Link {
    id: u64,
    info: LinkInfo,
    queue: SendQueue,
    closer: Closer,
    hello_sent: bool,
    /// When the link was installed: a redial after its loss waits until a
    /// `Settings::reconnect_interval` has passed since then.
    up_at: Instant,
}

/// A redial in progress.
struct Redial {
    attempt: u64,
    task: JoinHandle<()>,
}

/// A write signed and sized but not yet folded or sent ([`Actor::prepare_write`]).
struct PreparedWrite {
    entry_id: String,
    state: Map,
    body: Vec<u8>,
    /// The payload's block, held as an own block, when the payload travels as one.
    block: Option<String>,
}

/// An indirect probe this peer carries for a member (Java `PeerNode.Relay`): `origin` asked
/// (PING_REQ) whether `target` is alive under `origin_nonce`.
struct Relay {
    origin: String,
    origin_nonce: i64,
    target: String,
}

/// The state of one peer. See the [module docs](self).
pub(super) struct Actor {
    identity: Arc<Identity>,
    peer_id: String,
    group: String,
    clock: SharedClock,
    settings: Settings,
    dialers: Vec<Arc<dyn Dialer>>,
    seeds: Vec<Seed>,
    hlc: Hlc,
    issuer_clocks: HashMap<String, Hlc>,
    filter: FrameFilter,
    registry: Registry,
    spaces: Spaces,
    ads: AdCache,
    members: MemberView,
    reachable: BTreeSet<String>,
    seed_peer: Option<String>,
    resource_hints: Map,
    counters: PeerCounters,
    link: Option<Link>,
    next_link_id: u64,
    current_seed: Option<Seed>,
    redial: Option<Redial>,
    redial_attempts: u64,
    /// When the peer lost its last link that carried a verified frame; `None` while the current
    /// link has carried one. The reconnect window runs from here, so links a seed accepts and
    /// drops without a word do not restart it.
    outage_since: Option<Instant>,
    pulled_spaces: BTreeSet<String>,
    pulled_ads: bool,
    joining: bool,
    founding: Option<Map>,
    ready: Vec<oneshot::Sender<Result<(), PeerError>>>,
    next_want: Option<Instant>,
    last_intro_ms: i64,
    /// When the self-advertisement was last re-leased (or due and skipped): the next re-lease
    /// is a [`re_lease_period`] after it.
    last_lease: Instant,
    outbox: VecDeque<Vec<u8>>,
    blocks: BlockStore,
    block_asked: HashMap<String, Instant>,
    /// The own blocks this peer asked a member for to learn that it holds them
    /// ([`Actor::probe_block`]), and whom it asked.
    block_probes: HashMap<String, (String, Instant)>,
    /// When each (member, block) pair was last answered.
    block_served: HashMap<(String, String), Instant>,
    relays: HashMap<i64, Relay>,
    /// The relay nonces, oldest first (may name relays already answered).
    relay_order: VecDeque<i64>,
    relay_signals: VecDeque<RelaySignal>,
    /// Frames the links' pumps discarded because their link closed first.
    send_dropped: Arc<AtomicU64>,
    closed: bool,
    events: broadcast::Sender<PeerEvent>,
    link_watch: watch::Sender<Option<LinkInfo>>,
    inbound_tx: mpsc::Sender<Inbound>,
    /// The fold counter waiting reads and takes watch.
    folds: watch::Sender<u64>,
    /// When each space was last pulled for the space verbs (its first use and the paced pulls
    /// of waiting reads and takes).
    last_pull: HashMap<String, Instant>,
    /// The agent identities acted as, by AgentID: their renewed certificates persist.
    agents: HashMap<String, AgentIdentity>,
    /// The watches, in the order they were added.
    watchers: Vec<Watcher>,
    /// When the watch sweep last ran.
    last_sweep: Instant,
    /// When the spaces' collection (SPEC §7.3) last ran.
    last_collect: Instant,
    /// Transitions waiting for their payload's block.
    deferred: VecDeque<Deferred>,
}

/// Starts an actor on `channel` (dialed to `seed`) and returns its job queue. The actor sends
/// its first frames at once: the GROUP_AD_WANT of a join by id, else the introduction and the
/// revocation pull.
pub(super) fn spawn(start: Start, channel: Channel, seed: Seed) -> mpsc::Sender<Job> {
    let (jobs_tx, jobs_rx) = mpsc::channel(JOB_QUEUE);
    let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_QUEUE);
    let mut actor = Actor::new(start, inbound_tx);
    actor.install_link(channel, seed);
    if actor.joining {
        actor.send_want();
    } else {
        actor.on_link_ready();
    }
    tokio::spawn(actor.run(jobs_rx, inbound_rx));
    jobs_tx
}

impl Actor {
    fn new(start: Start, inbound_tx: mpsc::Sender<Inbound>) -> Self {
        let peer_id = start.identity.peer_id().to_owned();
        let mut registry = Registry::new(start.founder, Some(start.group.clone()));
        if registry.founder().is_none() {
            registry.set_founder(start.founding.as_ref().and_then(founder_of));
        }
        Self {
            hlc: Hlc::new(peer_id.clone()),
            identity: Arc::new(start.identity),
            spaces: Spaces::new(&start.group, start.settings.space_max_entries),
            blocks: BlockStore::new(MAX_OWN_BLOCK_BYTES, start.settings.fetched_block_bytes),
            group: start.group,
            clock: start.clock,
            settings: start.settings,
            dialers: start.dialers,
            seeds: start.seeds,
            issuer_clocks: HashMap::new(),
            filter: FrameFilter::new(),
            registry,
            ads: AdCache::default(),
            members: MemberView::new(MAX_MEMBERS),
            reachable: BTreeSet::new(),
            seed_peer: None,
            resource_hints: start.resource_hints,
            counters: PeerCounters::default(),
            link: None,
            next_link_id: 0,
            current_seed: None,
            redial: None,
            redial_attempts: 0,
            outage_since: None,
            pulled_spaces: BTreeSet::new(),
            pulled_ads: false,
            joining: start.joining,
            founding: start.founding,
            ready: Vec::new(),
            next_want: None,
            last_intro_ms: i64::MIN,
            last_lease: Instant::now(),
            outbox: VecDeque::new(),
            block_asked: HashMap::new(),
            block_probes: HashMap::new(),
            block_served: HashMap::new(),
            relays: HashMap::new(),
            relay_order: VecDeque::new(),
            relay_signals: VecDeque::new(),
            send_dropped: Arc::new(AtomicU64::new(0)),
            closed: false,
            events: start.events,
            link_watch: start.link_watch,
            inbound_tx,
            folds: start.folds,
            last_pull: HashMap::new(),
            agents: HashMap::new(),
            watchers: Vec::new(),
            last_sweep: Instant::now(),
            last_collect: Instant::now(),
            deferred: VecDeque::new(),
            peer_id,
        }
    }

    /// The actor's loop: until every handle is gone, run the next job, inbound message, or timer.
    async fn run(mut self, mut jobs: mpsc::Receiver<Job>, mut inbound: mpsc::Receiver<Inbound>) {
        loop {
            let want_at = self.next_want;
            // Re-armed every turn, so a group that grows past the probe cycle shortens the
            // pending re-lease at once.
            let period = re_lease_period(self.settings.peer_ad_interval, self.members.len());
            let lease_at = self.last_lease.checked_add(period);
            // The watch sweep runs only while something watches; the collection while a space
            // is open, watched or not.
            let sweep_at = if self.watching() {
                self.last_sweep.checked_add(SWEEP_INTERVAL)
            } else {
                None
            };
            let collect_at = if self.spaces.is_empty() {
                None
            } else {
                self.last_collect.checked_add(COLLECT_INTERVAL)
            };
            tokio::select! {
                job = jobs.recv() => match job {
                    Some(job) => job(&mut self),
                    None => break,
                },
                Some(message) = inbound.recv() => self.on_inbound(message),
                () = wake_at(lease_at) => self.on_re_lease(),
                () = wake_at(want_at) => self.on_want_tick(),
                () = wake_at(sweep_at) => self.on_sweep(),
                () = wake_at(collect_at) => self.on_collect(),
            }
        }
        self.close();
    }

    /// Merges a stamp into this peer's clock, unless its logical counter is over
    /// [`MAX_OBSERVED_LOGICAL`] (a stamp that would pin the clock) or it does not parse.
    fn observe_stamp(&mut self, stamp: &str, now: i64) {
        if Stamp::parse(stamp).is_some_and(|parsed| parsed.logical <= MAX_OBSERVED_LOGICAL) {
            self.hlc.observe(stamp, now);
        }
    }

    // ------------------------------------------------------------------------- clocks

    fn now(&self) -> i64 {
        self.clock.now_ms()
    }

    /// A fresh stamp for an issuer (an agent id) that sorts after everything this peer has
    /// stamped or observed, as `wire.hlc_now(issuer)` does per node.
    fn issuer_stamp(&mut self, issuer: &str, now: i64) -> String {
        let base = self.hlc.last();
        let clock = self
            .issuer_clocks
            .entry(issuer.to_owned())
            .or_insert_with(|| Hlc::new(issuer));
        if let Some((physical, logical)) = base {
            clock.observe(&format!("{physical}:{logical}:{issuer}"), now);
        }
        clock.now(now)
    }

    fn emit(&self, event: PeerEvent) {
        let _ = self.events.send(event);
    }

    /// Counts a fold that was not refused, waking the reads and takes waiting for one.
    fn bump_folds(&self) {
        self.folds
            .send_modify(|count| *count = count.wrapping_add(1));
    }

    // ------------------------------------------------------------------------- links

    /// Takes `channel` as the current link: spawns its reader and its pump, re-derives the relay
    /// this peer names for it, and publishes it. Returns the link's id.
    fn install_link(&mut self, channel: Channel, seed: Seed) -> u64 {
        let Channel {
            scheme,
            remote,
            attested,
            sender,
            receiver,
            closer,
        } = channel;
        self.next_link_id = self.next_link_id.wrapping_add(1);
        let id = self.next_link_id;
        let (tx, rx) = mpsc::unbounded_channel();
        let shared = Arc::new(PumpShared::default());
        tokio::spawn(pump(
            rx,
            Pump {
                shared: Arc::clone(&shared),
                sender,
                closer: closer.clone(),
                stall: self.settings.send_stall_timeout,
                link: id,
                inbound: self.inbound_tx.clone(),
                low_water: self.settings.send_queue_bytes / 4,
                dropped: Arc::clone(&self.send_dropped),
            },
        ));
        tokio::spawn(read_link(
            receiver,
            attested.clone(),
            id,
            self.inbound_tx.clone(),
            Arc::new(Semaphore::new(INBOUND_BUDGET_BYTES)),
        ));
        self.relay_for_link(attested.as_deref(), &seed);
        let info = LinkInfo {
            scheme,
            remote,
            attested,
        };
        tracing::debug!(peer = %self.peer_id, remote = %info.remote, "agentspaces: link up");
        self.link = Some(Link {
            id,
            info: info.clone(),
            queue: SendQueue { tx, shared },
            closer,
            hello_sent: false,
            up_at: Instant::now(),
        });
        self.current_seed = Some(seed);
        self.link_watch.send_replace(Some(info.clone()));
        self.emit(PeerEvent::Connected(info));
        id
    }

    /// The relay this peer names (`relay.via`) and wraps addressed frames through, re-derived for a
    /// new link to `seed`. On an attested link the transport already proved who the seed is, so it
    /// is the relay at once. A link to another seed over an unattested transport clears the old
    /// one, which no longer carries this peer: frames go direct, and the self-advertisement names
    /// no relay, until the new seed addresses this peer ([`Actor::heard_from`]). A redial of the
    /// same seed keeps it.
    fn relay_for_link(&mut self, attested: Option<&str>, seed: &Seed) {
        if let Some(attested) = attested.filter(|peer| !self.registry.peer_revoked(peer)) {
            if self.seed_peer.as_deref() != Some(attested) {
                self.seed_peer = Some(attested.to_owned());
                self.resource_hints.insert("relay.via", attested);
            }
        } else if self.current_seed.as_ref() != Some(seed) {
            self.seed_peer = None;
            self.resource_hints.remove("relay.via");
        }
    }

    fn is_current(&self, link: u64) -> bool {
        self.link.as_ref().is_some_and(|held| held.id == link)
    }

    /// Drops the current link and, unless the peer is closed, starts redialing.
    ///
    /// Dial rounds start at least [`Settings::reconnect_interval`] apart, also when a dial
    /// succeeds and the link is lost at once (a `tls` seed dialed over `tcp` accepts the
    /// connection and drops it): the first round after a loss waits until an interval has passed
    /// since the lost link came up, so only a link that lived longer is redialed at once. The
    /// reconnect window runs from the loss of the last link that carried a verified frame.
    fn lose_link(&mut self) {
        let Some(link) = self.link.take() else {
            return;
        };
        link.closer.close();
        if link.queue.shared.stalled.load(Ordering::SeqCst) {
            bump(&mut self.counters.send_overflows);
            tracing::warn!(
                peer = %self.peer_id,
                remote = %link.info.remote,
                "agentspaces: the link took no frame for the send stall timeout; closed it"
            );
        }
        tracing::debug!(peer = %self.peer_id, remote = %link.info.remote, "agentspaces: link lost");
        self.link_watch.send_replace(None);
        self.emit(PeerEvent::Disconnected);
        if !self.closed {
            let now = Instant::now();
            let since = *self.outage_since.get_or_insert(now);
            let pause = link
                .up_at
                .checked_add(self.settings.reconnect_interval)
                .map_or(Duration::ZERO, |due| due.saturating_duration_since(now));
            self.start_redial(since.checked_add(self.settings.reconnect_window), pause);
        }
    }

    /// The seeds to redial after a lost link: the one after the current first, the current one
    /// last, so the failover goes to the next seed (`Peer._candidate_seeds`).
    fn candidate_seeds(&self) -> Vec<Seed> {
        let position = self
            .current_seed
            .as_ref()
            .and_then(|current| self.seeds.iter().position(|seed| seed == current));
        match position {
            Some(index) => {
                let (head, tail) = self.seeds.split_at(index.saturating_add(1));
                tail.iter().chain(head).cloned().collect()
            }
            None if self.seeds.is_empty() => self.current_seed.iter().cloned().collect(),
            None => self.seeds.clone(),
        }
    }

    /// Starts a redial that waits `pause` before its first round and gives up at `deadline`.
    fn start_redial(&mut self, deadline: Option<Instant>, pause: Duration) {
        if let Some(redial) = self.redial.take() {
            redial.task.abort();
        }
        self.redial_attempts = self.redial_attempts.wrapping_add(1);
        let attempt = self.redial_attempts;
        let task = tokio::spawn(redial(
            self.candidate_seeds(),
            self.dialers.clone(),
            Arc::clone(&self.identity),
            self.settings.clone(),
            self.inbound_tx.clone(),
            Schedule {
                attempt,
                deadline,
                pause,
            },
        ));
        self.redial = Some(Redial { attempt, task });
    }

    fn on_inbound(&mut self, message: Inbound) {
        match message {
            Inbound::Frame {
                link,
                env,
                auth,
                budget,
            } => {
                if self.is_current(link) {
                    // A verified frame: the far end speaks the protocol, so the link is a
                    // working one and a later loss starts a new reconnect window.
                    self.outage_since = None;
                    bump(&mut self.counters.frames_received);
                    if self.handle(env, Some(auth), false).is_err() {
                        bump(&mut self.counters.malformed);
                    }
                }
                // The frame's bytes leave the link's inbound budget once it is handled.
                drop(budget);
            }
            Inbound::Malformed { link } => {
                if self.is_current(link) {
                    bump(&mut self.counters.malformed);
                }
            }
            Inbound::Relief { link } => {
                if self.is_current(link) && !self.joining {
                    self.flush_outbox();
                }
            }
            Inbound::Lost { link } => {
                if self.is_current(link) {
                    self.lose_link();
                }
            }
            Inbound::Dialed {
                channel,
                seed,
                attempt,
            } => self.on_dialed(*channel, seed, attempt),
            Inbound::GaveUp { attempt } => {
                if self
                    .redial
                    .as_ref()
                    .is_some_and(|redial| redial.attempt == attempt)
                {
                    self.redial = None;
                    tracing::warn!(peer = %self.peer_id, "agentspaces: no working link within the reconnect window; giving up");
                    for waiter in self.ready.drain(..) {
                        let _ = waiter.send(Err(PeerError::NotConnected));
                    }
                    self.emit(PeerEvent::GaveUp);
                }
            }
        }
    }

    /// A redial opened a channel: take it, then re-introduce and re-pull (or ask for the
    /// founding again while a join by id waits), as `Peer._reconnect` does.
    fn on_dialed(&mut self, channel: Channel, seed: Seed, attempt: u64) {
        let current = self
            .redial
            .as_ref()
            .is_some_and(|redial| redial.attempt == attempt);
        if self.closed || !current || self.link.is_some() {
            channel.closer.close();
            return;
        }
        self.redial = None;
        bump(&mut self.counters.reconnects);
        let link = self.install_link(channel, seed);
        self.resume_on(link);
    }

    /// After a redial installed `link`: re-introduce and re-pull (or ask for the founding again
    /// while a join by id waits), then tell the subscribers the peer reconnected, but only if
    /// `link` is still up. The re-introduction may already have lost it (its pump had closed):
    /// then Disconnected went out and a redial started, and this dial did not reconnect.
    fn resume_on(&mut self, link: u64) {
        if self.joining {
            self.send_want();
        } else {
            self.on_link_ready();
        }
        if self.is_current(link) {
            self.emit(PeerEvent::Reconnected {
                reconnects: self.counters.reconnects,
            });
        }
    }

    /// On a link the peer may speak on: introduce, pull the revocations and whatever was pulled
    /// before, and send the writes made while there was no link.
    fn on_link_ready(&mut self) {
        self.introduce();
        let _ = self.send_revocation_digest();
        if self.pulled_ads {
            let _ = self.send_ads_digest();
        }
        for space in self.pulled_spaces.clone() {
            let _ = self.send_space_digest(&space);
        }
        self.flush_outbox();
    }

    /// The re-lease is due: introduce again (which also re-arms it), and send any writes still
    /// waiting for room, should a relief have been missed.
    fn on_re_lease(&mut self) {
        self.last_lease = Instant::now();
        // The cadence runs with or without open spaces: expired advertisements leave the cache
        // even when none arrive (SPEC §6.2).
        let now = self.now();
        self.ads.expire(now);
        if !self.closed && !self.joining && self.link.is_some() {
            self.introduce();
            self.flush_outbox();
        }
    }

    fn on_want_tick(&mut self) {
        if self.joining && !self.closed {
            if self.link.is_some() {
                self.send_want();
            } else {
                self.next_want = Instant::now().checked_add(GROUP_AD_WANT_INTERVAL);
            }
        } else {
            self.next_want = None;
        }
    }

    // ------------------------------------------------------------------------- sending

    /// A frame signed by this peer with a fresh stamp.
    fn signed_frame(&mut self, kind: &str, body: &[u8], to: Option<&str>) -> Vec<u8> {
        let now = self.now();
        let stamp = self.hlc.now(now);
        let env = envelope::envelope(&self.group, kind, &self.peer_id, &stamp, body, to);
        envelope::encode_frame(&env, &self.identity)
    }

    /// Signs and offers one frame to the current link within the whole queue.
    fn send(&mut self, kind: &str, body: &[u8], to: Option<&str>) -> Result<(), PeerError> {
        self.send_with(kind, body, to, Budget::Whole)
    }

    /// Signs and offers one frame to the current link within `budget`.
    fn send_with(
        &mut self,
        kind: &str,
        body: &[u8],
        to: Option<&str>,
        budget: Budget,
    ) -> Result<(), PeerError> {
        if self.link.is_none() {
            return Err(PeerError::NotConnected);
        }
        let frame = self.signed_frame(kind, body, to);
        self.offer(frame, budget)
    }

    /// The bytes of the current link's queue `budget` allows.
    fn limit(&self, budget: Budget) -> usize {
        match budget {
            Budget::Whole => self.settings.send_queue_bytes,
            Budget::Half => self.settings.send_queue_bytes / 2,
        }
    }

    /// Whether the current link's queue has room for `length` bytes within `budget`.
    fn has_room(&self, length: usize, budget: Budget) -> bool {
        let limit = self.limit(budget);
        self.link
            .as_ref()
            .is_some_and(|link| link.queue.has_room(length, limit))
    }

    /// Asks the current link's pump to say when its queue has drained ([`Inbound::Relief`]),
    /// then looks again for room for `length` bytes within half the queue, since the pump may
    /// have drained just before it saw the ask: whether there is room now.
    fn arm_relief(&self, length: usize) -> bool {
        let Some(link) = &self.link else {
            return false;
        };
        link.queue.shared.wants_relief.store(true, Ordering::SeqCst);
        link.queue.has_room(length, self.limit(Budget::Half))
    }

    /// Offers a frame to the current link's pump without waiting. A frame that does not fit
    /// `budget` is refused (counted in [`PeerCounters::send_refused`] when it had the whole
    /// queue) and the link stays up: only a far end that stops taking frames for
    /// [`Settings::send_stall_timeout`] closes it, from the pump (see the module docs).
    fn offer(&mut self, frame: Vec<u8>, budget: Budget) -> Result<(), PeerError> {
        if frame.len() > MAX_FRAME_BYTES {
            return Err(PeerError::FrameTooLarge(frame.len()));
        }
        let limit = self.limit(budget);
        let Some(link) = &self.link else {
            return Err(PeerError::NotConnected);
        };
        match link.queue.offer(frame, limit) {
            Offer::Queued => Ok(()),
            Offer::Full => {
                if budget == Budget::Whole {
                    bump(&mut self.counters.send_refused);
                    tracing::debug!(
                        peer = %self.peer_id,
                        remote = %link.info.remote,
                        "agentspaces: the link's send queue is full; a frame was refused"
                    );
                }
                Err(PeerError::SendOverflow)
            }
            Offer::Closed => {
                self.lose_link();
                Err(PeerError::NotConnected)
            }
        }
    }

    /// The relay an addressed frame to `to` goes through, or `None` for a direct send: the seed,
    /// for every member but the seed itself (`Peer.relay_for`).
    fn relay_for(&self, to: &str) -> Option<String> {
        self.seed_peer.clone().filter(|seed| seed != to)
    }

    /// Sends an addressed frame directly or, when the seed must carry it, wrapped in a one-hop
    /// RELAY_FRAME to the seed (`Peer.send_addressed`).
    fn send_addressed_frame(&mut self, kind: &str, body: &[u8], to: &str) -> Result<(), PeerError> {
        self.send_addressed_with(kind, body, to, Budget::Whole)
    }

    /// [`Actor::send_addressed_frame`] within `budget`.
    fn send_addressed_with(
        &mut self,
        kind: &str,
        body: &[u8],
        to: &str,
        budget: Budget,
    ) -> Result<(), PeerError> {
        let Some(relay) = self.relay_for(to) else {
            return self.send_with(kind, body, Some(to), budget);
        };
        if self.link.is_none() {
            return Err(PeerError::NotConnected);
        }
        let inner = self.signed_frame(kind, body, Some(to));
        let outer = bodies::relay_frame_body(to, &inner, None, None);
        self.send_with(KIND_RELAY_FRAME, &outer, Some(&relay), budget)?;
        bump(&mut self.counters.relayed_out);
        Ok(())
    }

    /// Rumors one of this peer's own items (a write, an advertisement), or keeps it in the outbox
    /// until the peer has a link with room again.
    fn send_or_hold(&mut self, body: Vec<u8>) {
        if self.link.is_some() && !self.joining {
            self.flush_outbox();
            if self.outbox.is_empty()
                && self
                    .send_with(KIND_RUMOR, &body, None, Budget::Half)
                    .is_ok()
            {
                return;
            }
        }
        let length = body.len().saturating_add(FRAME_OVERHEAD);
        self.outbox.push_back(body);
        while self.outbox.len() > OUTBOX_LIMIT {
            self.outbox.pop_front();
            bump(&mut self.counters.outbox_dropped);
        }
        if !self.joining && self.arm_relief(length) {
            self.flush_outbox();
        }
    }

    /// Sends the held rumors in order while the link's queue has room for them within half its
    /// bound, so a large outbox goes out in slices as the pump drains rather than as one burst over
    /// a healthy link; the rest wait for [`Inbound::Relief`]. A rumor too large for a frame is
    /// dropped and counted rather than block the ones behind it.
    fn flush_outbox(&mut self) {
        while let Some(length) = self
            .outbox
            .front()
            .map(|body| body.len().saturating_add(FRAME_OVERHEAD))
        {
            if !self.has_room(length, Budget::Half) && !self.arm_relief(length) {
                return;
            }
            let Some(body) = self.outbox.pop_front() else {
                return;
            };
            match self.send_with(KIND_RUMOR, &body, None, Budget::Half) {
                Ok(()) => {}
                Err(PeerError::FrameTooLarge(_)) => bump(&mut self.counters.outbox_dropped),
                Err(_) => {
                    self.outbox.push_front(body);
                    let _ = self.arm_relief(length);
                    return;
                }
            }
        }
    }

    /// Publishes this peer's leased self-advertisement on the `peers` stream (SPEC §5.2), then
    /// announces CHANNEL_HELLO once on an attested link. The item id's milliseconds never repeat,
    /// so a re-introduction within one millisecond is not taken for the same item.
    fn introduce(&mut self) {
        let now = self.now();
        let issued = time::instant_iso(now.div_euclid(1000).saturating_mul(1000));
        let ad = wire_ads::peer_advertisement(
            &self.group,
            &self.identity,
            &issued,
            Some(&self.resource_hints),
        );
        let payload = wire_ads::signed_peer_ad(&ad, &self.identity);
        self.last_lease = Instant::now();
        let item_ms = now.max(self.last_intro_ms.saturating_add(1));
        self.last_intro_ms = item_ms;
        let item = format!("peer:{}:{item_ms}", self.peer_id);
        let body = bodies::rumor_body(STREAM_PEERS, &item, RUMOR_HOPS, &payload);
        let _ = self.send(KIND_RUMOR, &body, None);
        self.announce_channel();
    }

    /// On a link the transport attested, announces once that this peer accepts channel-attested
    /// frames there (CHANNEL_HELLO, SPEC §5.6), addressed to the attested peer and signed. This
    /// peer keeps signing what it sends.
    fn announce_channel(&mut self) {
        let Some(link) = self.link.as_mut() else {
            return;
        };
        if link.hello_sent {
            return;
        }
        let Some(attested) = link.info.attested.clone() else {
            return;
        };
        link.hello_sent = true;
        let body = bodies::channel_hello_body(true, &attested);
        let _ = self.send(KIND_CHANNEL_HELLO, &body, Some(&attested));
    }

    /// The unaddressed GROUP_AD_WANT of a join by GroupID (the seed's PeerID is unknown until it
    /// answers), and the time of the next ask.
    fn send_want(&mut self) {
        let now = self.now();
        let stamp = self.hlc.now(now);
        let env = bodies::group_ad_want_envelope(&self.group, &self.peer_id, &stamp, None);
        let frame = envelope::encode_frame(&env, &self.identity);
        let _ = self.offer(frame, Budget::Whole);
        self.next_want = Instant::now().checked_add(GROUP_AD_WANT_INTERVAL);
    }

    fn send_digest(&mut self, streams: &[&str]) -> Result<(), PeerError> {
        let digests: Map = streams
            .iter()
            .map(|stream| (*stream, Vec::<u8>::new()))
            .collect();
        self.send(KIND_DIGEST, &bodies::digest_body(&digests), None)
    }

    fn send_revocation_digest(&mut self) -> Result<(), PeerError> {
        self.send_digest(&revocation::STREAMS)
    }

    fn send_ads_digest(&mut self) -> Result<(), PeerError> {
        self.send_digest(&[STREAM_ADS])
    }

    /// The anti-entropy pull of a space with the revocation streams riding along (a partner
    /// answers only the streams a digest names).
    fn send_space_digest(&mut self, space: &str) -> Result<(), PeerError> {
        let stream = format!("{STREAM_SPACE_PREFIX}{space}");
        let mut streams = vec![stream.as_str()];
        streams.extend(revocation::STREAMS);
        self.send_digest(&streams)
    }

    // ------------------------------------------------------------------------- receiving

    /// Handles one verified envelope (`Peer._handle`): the reader filter, the sender's
    /// revocation, the frame filter, the clock, membership, then the kind. An `Err` is a body
    /// that does not parse, counted as malformed by the caller; nothing here ends the reader.
    fn handle(&mut self, mut env: Map, auth: Option<Auth>, relayed: bool) -> Result<(), Malformed> {
        if !envelope::accepts(&env, &self.group, &self.peer_id) {
            return Ok(());
        }
        // A revoked identity gets nothing, permanently, before any other check (Java
        // `PeerNode.dispatch`): no answer, no event, no membership, and no place in the replay
        // cache. A relayed inner frame comes back through here and is judged the same.
        if env
            .get("from")
            .and_then(Value::as_str)
            .is_some_and(|from| self.registry.peer_revoked(from))
        {
            bump(&mut self.counters.revoked_frames);
            return Ok(());
        }
        let now = self.now();
        if !self.filter.admit(&env, now) {
            return Ok(()); // stale, far ahead, or a replay: counted by the filter, nothing more
        }
        match auth {
            Some(Auth::Attested) => bump(&mut self.counters.attested_frames),
            Some(Auth::Session) => bump(&mut self.counters.session_frames),
            _ => {}
        }
        if let Some(stamp) = env.get("stamp").and_then(Value::as_str) {
            self.observe_stamp(stamp, now);
        }
        let to_us = env.get("to").and_then(Value::as_str) == Some(self.peer_id.as_str());
        let kind = env
            .remove("kind")
            .and_then(Value::into_text)
            .ok_or(Malformed)?;
        let sender = env
            .remove("from")
            .and_then(Value::into_text)
            .ok_or(Malformed)?;
        let body = match env.remove("body") {
            Some(Value::Bytes(body)) => body,
            None | Some(Value::Null) => Vec::new(),
            Some(_) => return Err(Malformed),
        };
        if sender != self.peer_id {
            self.heard_from(&sender, relayed, to_us);
        }
        match kind.as_str() {
            KIND_PING => {
                let nonce = bodies::parse_ping(&body).ok_or(Malformed)?;
                let ack = bodies::ack_body(nonce);
                // Java answers `send(group, from, ACK)`: addressed to the prober, and back through
                // the relay when the PING came inside a RELAY_FRAME, else the seed takes an ACK it
                // never asked for and the prober evicts this peer.
                let _ = if relayed {
                    self.send_addressed_frame(KIND_ACK, &ack, &sender)
                } else {
                    self.send(KIND_ACK, &ack, Some(&sender))
                };
            }
            KIND_PING_REQ => {
                let (target, nonce) = parse_ping_req(&body).ok_or(Malformed)?;
                self.on_ping_req(sender, target, nonce);
            }
            KIND_ACK => {
                let nonce = bodies::parse_ping(&body).ok_or(Malformed)?;
                self.on_ack(&sender, nonce);
            }
            KIND_PIPE_DATA => self.on_pipe(sender, &body)?,
            KIND_RELAY_FRAME => return self.on_relay_frame(&body, relayed),
            KIND_BLOCK_WANT => {
                let cid = bodies::parse_block_want(&body).ok_or(Malformed)?;
                self.serve_block(&sender, &cid);
            }
            KIND_BLOCK => {
                let block = bodies::parse_block(&body).ok_or(Malformed)?;
                if self.block_asked.contains_key(&block.cid) && block.verifies() {
                    self.block_asked.remove(&block.cid);
                    let cid = block.cid.clone();
                    if self.blocks.hold_fetched(block.cid, block.bytes) {
                        self.emit(PeerEvent::Block { cid });
                        self.retry_deferred();
                    }
                } else if self
                    .block_probes
                    .get(&block.cid)
                    .is_some_and(|(asked, _)| *asked == sender)
                    && block.verifies()
                {
                    // The member asked holds the block: this peer holds it already.
                    self.block_probes.remove(&block.cid);
                    self.emit(PeerEvent::BlockHeld {
                        cid: block.cid,
                        by: sender,
                    });
                }
            }
            KIND_GROUP_AD => self.on_group_ad(&body)?,
            KIND_RUMOR => self.on_rumor(bodies::parse_rumor(&body).ok_or(Malformed)?)?,
            KIND_PULL_RESP => {
                self.on_pull_resp(bodies::parse_pull_resp(&body).ok_or(Malformed)?)?;
            }
            _ => self.ignore_kind(kind),
        }
        Ok(())
    }

    /// A verified frame is a member heard from, and (unless a relay carried it) one this peer's
    /// link reaches. The first frame the seed addresses to this peer names the seed: it is the
    /// relay this peer declares (`relay.via`), so the peer introduces itself again.
    fn heard_from(&mut self, sender: &str, relayed: bool, to_us: bool) {
        self.members.hear(sender);
        if relayed {
            return;
        }
        if !self.reachable.contains(sender) && self.reachable.len() < MAX_MEMBERS {
            self.reachable.insert(sender.to_owned());
        }
        if to_us && self.link.is_some() && self.seed_peer.as_deref() != Some(sender) {
            self.seed_peer = Some(sender.to_owned());
            self.resource_hints.insert("relay.via", sender);
            // A join by id introduces only after the founding verifies; that introduction
            // carries the hint.
            if !self.joining {
                self.introduce();
            }
        }
    }

    /// A PING_REQ: `origin` asks this peer to probe `target` for it (Java `PeerNode` PING_REQ, a
    /// SWIM indirect probe). The probe goes under a fresh, unguessable nonce, through the seed when
    /// the target is behind it; [`Actor::on_ack`] vouches for the target when it answers.
    fn on_ping_req(&mut self, origin: String, target: String, origin_nonce: i64) {
        if target.is_empty() || target == self.peer_id {
            return;
        }
        let Some(nonce) = random_nonce() else {
            return;
        };
        while self.relays.len() >= MAX_RELAYS {
            let Some(oldest) = self.relay_order.pop_front() else {
                break;
            };
            self.relays.remove(&oldest);
        }
        if self.relay_order.len() > MAX_RELAYS.saturating_mul(2) {
            let relays = &self.relays;
            self.relay_order.retain(|nonce| relays.contains_key(nonce));
        }
        self.relays.insert(
            nonce,
            Relay {
                origin,
                origin_nonce,
                target: target.clone(),
            },
        );
        self.relay_order.push_back(nonce);
        if self
            .send_addressed_frame(KIND_PING, &bodies::ping_body(nonce), &target)
            .is_ok()
        {
            bump(&mut self.counters.pings_relayed);
        }
    }

    /// An ACK. When it answers a probe this peer carries and comes from that probe's target, the
    /// origin hears `{nonce: its own, onBehalf: target}`; an ACK from anyone else is a forgery and
    /// changes nothing. Any other ACK is dropped quietly: this peer sends no probes of its own.
    fn on_ack(&mut self, sender: &str, nonce: i64) {
        if self
            .relays
            .get(&nonce)
            .is_none_or(|relay| relay.target != sender)
        {
            return;
        }
        let Some(relay) = self.relays.remove(&nonce) else {
            return;
        };
        let body = ack_on_behalf_body(relay.origin_nonce, &relay.target);
        let _ = self.send_addressed_frame(KIND_ACK, &body, &relay.origin);
    }

    /// A BLOCK_WANT: the held block, answered at most once a second to each member, and only
    /// while the link's queue has room within half its bound. An answer skipped for either
    /// reason is counted; the asker asks again.
    fn serve_block(&mut self, requester: &str, cid: &str) {
        let Some(length) = self.blocks.get(cid).map(Vec::len) else {
            return;
        };
        let now = Instant::now();
        let key = (requester.to_owned(), cid.to_owned());
        if self
            .block_served
            .get(&key)
            .is_some_and(|served| now.duration_since(*served) < BLOCK_ASK_INTERVAL)
        {
            bump(&mut self.counters.replies_skipped);
            return;
        }
        // The answer, and the RELAY_FRAME around it when the seed carries it.
        let estimate = length.saturating_add(FRAME_OVERHEAD.saturating_mul(2));
        if !self.has_room(estimate, Budget::Half) {
            bump(&mut self.counters.replies_skipped);
            return;
        }
        let Some(body) = self
            .blocks
            .get(cid)
            .map(|data| bodies::block_body(cid, data))
        else {
            return;
        };
        match self.send_addressed_with(KIND_BLOCK, &body, requester, Budget::Half) {
            Ok(()) => {
                bump(&mut self.counters.blocks_served);
                if self.block_served.len() >= MAX_SERVED_BLOCKS {
                    self.block_served
                        .retain(|_, served| now.duration_since(*served) < BLOCK_ASK_INTERVAL);
                }
                if self.block_served.len() < MAX_SERVED_BLOCKS {
                    self.block_served.insert(key, now);
                }
            }
            Err(PeerError::FrameTooLarge(size)) => {
                bump(&mut self.counters.blocks_unsendable);
                tracing::warn!(
                    peer = %self.peer_id,
                    %cid,
                    size,
                    "agentspaces: a held block does not fit a frame; not served"
                );
            }
            Err(PeerError::SendOverflow) => bump(&mut self.counters.replies_skipped),
            Err(_) => {}
        }
    }

    fn ignore_kind(&mut self, kind: String) {
        let named = self.counters.ignored_kinds.contains_key(&kind)
            || self.counters.ignored_kinds.len() < MAX_NAMED_KINDS;
        let key = if named { kind } else { OTHER_KINDS.to_owned() };
        bump(self.counters.ignored_kinds.entry(key).or_insert(0));
    }

    fn on_pipe(&mut self, from: String, body: &[u8]) -> Result<(), Malformed> {
        let pipe = bodies::parse_pipe_data(body).ok_or(Malformed)?;
        if pipe.capability == RELAY_SIGNAL_CAPABILITY {
            let signal = bodies::parse_relay_signal(&pipe.payload).ok_or(Malformed)?;
            self.relay_signals.push_back(signal);
            while self.relay_signals.len() > RELAY_SIGNALS_KEPT {
                self.relay_signals.pop_front();
            }
            return Ok(());
        }
        self.emit(PeerEvent::Pipe {
            from,
            capability: pipe.capability,
            payload: pipe.payload,
        });
        Ok(())
    }

    /// A RELAY_FRAME addressed to this peer: the inner frame, fully signed, handled as relayed
    /// when it is for this peer and not itself a relay. A dial-only peer forwards nothing.
    fn on_relay_frame(&mut self, body: &[u8], relayed: bool) -> Result<(), Malformed> {
        let relay = bodies::parse_relay_frame(body).ok_or(Malformed)?;
        if relay.target != self.peer_id || relayed {
            return Ok(());
        }
        let inner = envelope::decode_frame(&relay.frame).ok_or(Malformed)?;
        if inner.get("kind").and_then(Value::as_str) == Some(KIND_RELAY_FRAME) {
            return Ok(());
        }
        bump(&mut self.counters.relayed_in);
        self.handle(inner, None, true)
    }

    /// A GROUP_AD (SPEC §9): taken only while a join by GroupID waits, and only when it passes
    /// the four checks of SPEC §5.1 and derives to exactly the wanted GroupID. Anything else is
    /// ignored, so a hostile seed can delay the join and never substitute a policy.
    fn on_group_ad(&mut self, body: &[u8]) -> Result<(), Malformed> {
        if !self.joining || self.closed {
            return Ok(());
        }
        let signed = cbor::decode(body).map_err(|_| Malformed)?;
        if founding::verify_signed_group_ad(&signed).as_deref() != Some(self.group.as_str()) {
            return Ok(());
        }
        let Some(signed) = signed.into_map() else {
            return Ok(());
        };
        if self.registry.founder().is_none() {
            self.registry.set_founder(founder_of(&signed));
        }
        self.founding = Some(signed);
        self.joining = false;
        self.next_want = None;
        self.on_link_ready();
        for waiter in self.ready.drain(..) {
            let _ = waiter.send(Ok(()));
        }
        Ok(())
    }

    fn on_rumor(&mut self, rumor: Rumor) -> Result<(), Malformed> {
        let stream = rumor.stream_id.as_str();
        if rumor.payload.is_empty() {
            return Ok(());
        }
        if revocation::STREAMS.contains(&stream) {
            let now = self.now();
            if self.registry.accept(stream, &rumor.payload, now) {
                // The revoked member's advertisements leave the cache now, as in Java.
                self.ads.purge(&self.registry);
                if stream == revocation::PEER_STREAM {
                    self.enforce_peer_revocations();
                }
            }
        } else if stream == STREAM_PEERS {
            self.accept_peer_ad(&rumor.payload);
        } else if stream == STREAM_ADS {
            let stored = cbor::decode(&rumor.payload).map_err(|_| Malformed)?;
            self.accept_ad(&stored);
        } else if let Some(space) = space_name(stream) {
            let (claim, state) = parse_delta(&rumor.payload).ok_or(Malformed)?;
            // Claim before state: a completion authenticates against the holder's claim.
            if let Some((entry_id, signed)) = claim {
                self.fold_claim(space, &entry_id, &signed);
            }
            if let Some(state) = state {
                self.fold_remote_state(space, &state);
            }
        }
        Ok(())
    }

    /// A PULL_RESP, applied in Java's registration order, not in the order its streams arrived
    /// (`GossipBus.onPullResp`): the revocations first, then the advertisements, then each
    /// space's claims before its states. Wire v3 writes the deltas in canonical map order,
    /// shorter stream ids first, so `space:tasks` arrives before `credential-revocations`;
    /// folding in that order would keep, for good, an entry by an agent the same response
    /// revokes, which every Java node refuses. A stream that does not parse is skipped (and the
    /// frame counted malformed); the others still apply.
    fn on_pull_resp(&mut self, deltas: Map) -> Result<(), Malformed> {
        let now = self.now();
        let mut malformed = false;
        let delta_of = |stream: &str| {
            deltas
                .get(stream)
                .and_then(Value::as_bytes)
                .filter(|bytes| !bytes.is_empty())
        };
        let mut revoked_peers = false;
        let mut revoked_any = false;
        for stream in revocation::STREAMS {
            let Some(bytes) = delta_of(stream) else {
                continue;
            };
            match cbor::decode(bytes) {
                Ok(Value::Array(items)) => {
                    for signed in &items {
                        if self.registry.accept_signed(stream, signed, now) {
                            revoked_any = true;
                            revoked_peers |= stream == revocation::PEER_STREAM;
                        }
                    }
                }
                Ok(Value::Null) => {}
                _ => malformed = true,
            }
        }
        if revoked_any {
            self.ads.purge(&self.registry);
        }
        if revoked_peers {
            self.enforce_peer_revocations();
        }
        if let Some(bytes) = delta_of(STREAM_ADS) {
            match pulled_ads(bytes) {
                Some(stored) => stored.iter().for_each(|ad| self.accept_ad(ad)),
                None => malformed = true,
            }
        }
        for (stream, delta) in &deltas {
            let (Some(stream), Some(bytes)) = (stream.as_str(), delta.as_bytes()) else {
                continue;
            };
            let Some(space) = space_name(stream).filter(|_| !bytes.is_empty()) else {
                continue;
            };
            match parse_sync(bytes) {
                Some((claims, states)) => {
                    for (entry_id, signed) in &claims {
                        self.fold_claim(space, entry_id, signed);
                    }
                    for state in &states {
                        self.fold_remote_state(space, state);
                    }
                }
                None => malformed = true,
            }
        }
        if malformed { Err(Malformed) } else { Ok(()) }
    }

    /// Enforces the peer revocations held, as Java's `onPeerRevoked` does when one lands: every
    /// revoked PeerID leaves the member and reachable sets and the probes carried for it, a
    /// revoked seed stops being this peer's relay (`relay.via`), and a link to a revoked seed
    /// (the one it attested, or the one that addressed this peer) is closed so the peer fails
    /// over to the next seed. Its frames are dropped from then on ([`Actor::handle`]).
    fn enforce_peer_revocations(&mut self) {
        let registry = &self.registry;
        self.members.retain(|peer| !registry.peer_revoked(peer));
        self.reachable.retain(|peer| !registry.peer_revoked(peer));
        self.relays.retain(|_, relay| {
            !registry.peer_revoked(&relay.origin) && !registry.peer_revoked(&relay.target)
        });
        let seed_revoked = self
            .seed_peer
            .as_deref()
            .is_some_and(|seed| registry.peer_revoked(seed));
        let attested_revoked = self
            .link
            .as_ref()
            .and_then(|link| link.info.attested.as_deref())
            .is_some_and(|attested| registry.peer_revoked(attested));
        if seed_revoked {
            self.seed_peer = None;
            self.resource_hints.remove("relay.via");
        }
        if (seed_revoked || attested_revoked) && self.link.is_some() {
            tracing::warn!(peer = %self.peer_id, "agentspaces: the seed is revoked; leaving it");
            self.lose_link();
        }
    }

    /// A `peers` stream item: the signed advertisement, kept under its issuer when the signature
    /// and the derivation hold (`Peer._accept_peer_ad`) and, as Java's `verifiedPeerAd`,
    /// `admitAdvertisement`, and `hold` judge it: it names this group, has not expired, was issued
    /// no more than [`wire_ads::MAX_AD_ISSUED_SKEW_MILLIS`] ahead, its issuer is not revoked, and
    /// it is not older than the one held (the newest wins; an equal one replaces).
    fn accept_peer_ad(&mut self, payload: &[u8]) {
        let Some((ad, issuer)) = wire_ads::verify_signed_peer_ad(payload) else {
            return;
        };
        if issuer == self.peer_id
            || self.registry.peer_revoked(&issuer)
            || ad.get("group").and_then(Value::as_str) != Some(self.group.as_str())
        {
            return;
        }
        let now = self.now();
        let Some(issued) = issued_millis(&ad) else {
            return;
        };
        let live = wire_ads::ad_expires_at_millis(&ad).is_some_and(|expires| expires > now);
        let ahead =
            i128::from(issued) > i128::from(now) + i128::from(wire_ads::MAX_AD_ISSUED_SKEW_MILLIS);
        if !live || ahead {
            return;
        }
        if self
            .members
            .get(&issuer)
            .and_then(issued_millis)
            .is_some_and(|held| held > issued)
        {
            return;
        }
        self.members.hold_ad(issuer, ad);
    }

    /// A stored advertisement from the `ads` stream or a pull (`Peer.accept_ad`).
    fn accept_ad(&mut self, stored: &Value) {
        let now = self.now();
        if let Some(admitted) = self.ads.admit(stored, now, &self.registry)
            && admitted.changed
        {
            self.emit(PeerEvent::AdAccepted {
                ad_type: admitted.ad_type,
                id: admitted.id,
            });
        }
    }

    /// Folds one state into space `space`, feeds the clock with its stamps when it applied, and
    /// tells the subscribers. A space this peer never opened is not folded into (counted in
    /// [`PeerCounters::unopened_space_items`]): remote data never opens a space.
    ///
    /// A fold that was not refused wakes the waiting reads and takes; one that applied derives
    /// the entry's transitions for the watches ([`Actor::after_state`]).
    fn fold_state(&mut self, space: &str, dto: &Map) -> Option<FoldOutcome> {
        let now = self.now();
        let Some(slot) = self.spaces.get_mut(space) else {
            bump(&mut self.counters.unopened_space_items);
            return None;
        };
        let record = dto.get("record");
        let entry_id = record
            .and_then(|record| record.get("entryId"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let known = slot.store.state(&entry_id).is_some();
        let ctx = FoldContext::new(now, &self.registry).with_space(&slot.space_id);
        let outcome = slot.store.fold_state(dto, &ctx);
        if !outcome.is_refused()
            && let Some(span) = space_ops::state_lease_span(dto)
        {
            // Authentic and admitted: its lease counts for the collection horizon (Java
            // `observeLease` after the verification).
            slot.observe_lease(span);
        }
        if outcome.is_applied() {
            for stamp in [
                record.and_then(|record| record.get("issued")),
                dto.get("leaseStamp"),
            ]
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            {
                self.observe_stamp(stamp, now);
            }
        }
        self.emit(PeerEvent::StateFolded {
            space: space.to_owned(),
            entry_id: entry_id.clone(),
            outcome,
        });
        if !outcome.is_refused() {
            self.bump_folds();
        }
        if outcome.is_applied() {
            self.after_state(space, &entry_id, !known);
        }
        Some(outcome)
    }

    /// Folds one signed claim into space `space` under `entry_id`, if this peer opened it. A
    /// fold that was not refused wakes the waiting reads and takes; a claim that won the lattice
    /// derives `Taken` for the watches ([`Actor::after_claim`]).
    fn fold_claim(&mut self, space: &str, entry_id: &str, signed: &Map) -> Option<FoldOutcome> {
        let now = self.now();
        let Some(slot) = self.spaces.get_mut(space) else {
            bump(&mut self.counters.unopened_space_items);
            return None;
        };
        let ctx = FoldContext::new(now, &self.registry).with_space(&slot.space_id);
        let outcome = slot.store.fold_claim(entry_id, signed, &ctx);
        if outcome.is_applied()
            && let Some(span) = space_ops::claim_lease_span(signed)
        {
            slot.observe_lease(span);
        }
        if outcome.is_applied() {
            if let Some(stamp) = signed
                .get("claim")
                .and_then(|claim| claim.get("stamp"))
                .and_then(Value::as_str)
            {
                self.observe_stamp(stamp, now);
            }
            self.emit(PeerEvent::ClaimFolded {
                space: space.to_owned(),
                entry_id: entry_id.to_owned(),
            });
        }
        if !outcome.is_refused() {
            self.bump_folds();
        }
        if outcome.is_applied() {
            self.after_claim(space, entry_id);
        }
        Some(outcome)
    }

    // ------------------------------------------------------------------------- blocks

    /// Asks the entry's issuing peer and the seed for a block, at most once a second per block.
    fn want_block(&mut self, cid: &str, issuer_key: Option<&[u8]>) {
        let now = Instant::now();
        if self
            .block_asked
            .get(cid)
            .is_some_and(|asked| now.duration_since(*asked) < BLOCK_ASK_INTERVAL)
        {
            return;
        }
        if !self.block_asked.contains_key(cid) && self.block_asked.len() >= MAX_ASKED_BLOCKS {
            self.block_asked
                .retain(|_, asked| now.duration_since(*asked) < Duration::from_secs(60));
            if self.block_asked.len() >= MAX_ASKED_BLOCKS {
                return;
            }
        }
        self.block_asked.insert(cid.to_owned(), now);
        let mut targets: Vec<String> = issuer_key.map(ids::derive_id).into_iter().collect();
        if let Some(seed) = &self.seed_peer
            && !targets.contains(seed)
        {
            targets.push(seed.clone());
        }
        let body = bodies::block_want_body(cid);
        for target in targets {
            if target != self.peer_id {
                let _ = self.send_addressed_frame(KIND_BLOCK_WANT, &body, &target);
            }
        }
    }

    // ------------------------------------------------------------------------- calls

    pub(super) fn await_ready(&mut self, waiter: oneshot::Sender<Result<(), PeerError>>) {
        if self.closed {
            let _ = waiter.send(Err(PeerError::Closed));
        } else if !self.joining {
            let _ = waiter.send(Ok(()));
        } else {
            self.ready.push(waiter);
        }
    }

    pub(super) fn members(&self) -> Vec<String> {
        self.members.ids()
    }

    /// A member's held self-advertisement while it lives and its issuer is not revoked.
    pub(super) fn member_ad(&self, peer: &str) -> Option<Map> {
        if self.registry.peer_revoked(peer) {
            return None;
        }
        let ad = self.members.get(peer).filter(|ad| !ad.is_empty())?;
        wire_ads::ad_expires_at_millis(ad)
            .is_some_and(|expires| expires > self.now())
            .then(|| ad.clone())
    }

    pub(super) fn reachable(&self) -> Vec<String> {
        self.reachable.iter().cloned().collect()
    }

    pub(super) fn seed_peer(&self) -> Option<String> {
        self.seed_peer.clone()
    }

    pub(super) fn founding(&self) -> Option<Map> {
        self.founding.clone()
    }

    pub(super) fn cards(&self) -> Vec<Map> {
        self.ads.cards(self.now(), &self.registry)
    }

    pub(super) fn ads(&self, ad_type: &str) -> Vec<Map> {
        self.ads.live(ad_type, self.now(), &self.registry)
    }

    pub(super) fn relay_signals(&self) -> Vec<RelaySignal> {
        self.relay_signals.iter().cloned().collect()
    }

    pub(super) fn revoked(&self, agent_or_peer: &str) -> bool {
        self.registry.peer_revoked(agent_or_peer)
            || self.registry.refuses(agent_or_peer, None, None)
    }

    pub(super) fn counters(&self) -> PeerCounters {
        let mut counters = self.counters.clone();
        counters.filter = FilterCounters {
            stale: self.filter.stale(),
            ahead: self.filter.ahead(),
            replayed: self.filter.replayed(),
        };
        counters.send_dropped = self.send_dropped.load(Ordering::Relaxed);
        // This peer's own writes refused for room, and what each store refused.
        counters.space_refused_inserts = self
            .spaces
            .iter()
            .map(|slot| slot.store.refused_inserts())
            .fold(counters.space_refused_inserts, u64::saturating_add);
        counters
    }

    fn check_open(&self) -> Result<(), PeerError> {
        if self.closed {
            Err(PeerError::Closed)
        } else {
            Ok(())
        }
    }

    /// A renewing subordinate identity of this peer for its agent `local_name`, certified from
    /// now for `ttl_iso` (`Peer.agent_identity`, Java `PeerIdentity.renewingSubordinate`).
    pub(super) fn agent_identity(
        &mut self,
        local_name: &str,
        ttl_iso: &str,
    ) -> Result<AgentIdentity, PeerError> {
        self.check_open()?;
        let now = self.now();
        let agent = self
            .identity
            .renewing_subordinate(local_name, ttl_iso, None, now)?;
        // Held from now on, so its renewals persist across the verbs that act as it.
        self.acting_agent(agent, now)
    }

    /// Runs `sign` with this peer's identity, `agent` as the peer holds it (renewed at half-life
    /// first, [`Actor::acting_agent`]), and the time now: what an advertisement this peer issues
    /// for one of its agents is built and certified with.
    pub(super) fn with_signer<R>(
        &mut self,
        agent: Option<AgentIdentity>,
        sign: impl FnOnce(&Identity, Option<&AgentIdentity>, i64) -> R,
    ) -> Result<R, PeerError> {
        self.check_open()?;
        let now = self.now();
        let agent = agent
            .map(|agent| self.acting_agent(agent, now))
            .transpose()?;
        Ok(sign(&self.identity, agent.as_ref(), now))
    }

    pub(super) fn pull_space(&mut self, space: &str) -> Result<(), PeerError> {
        self.check_open()?;
        if self.spaces.slot(space).is_none() {
            return Err(PeerError::InvalidArgument(format!(
                "cannot open space {space:?}"
            )));
        }
        self.pulled_spaces.insert(space.to_owned());
        offline_ok(self.send_space_digest(space))
    }

    pub(super) fn pull_ads(&mut self) -> Result<(), PeerError> {
        self.check_open()?;
        self.pulled_ads = true;
        offline_ok(self.send_ads_digest())
    }

    pub(super) fn pull_revocations(&mut self) -> Result<(), PeerError> {
        self.check_open()?;
        offline_ok(self.send_revocation_digest())
    }

    /// Writes one signed entry (`Peer.write_entry`): the record and state as the wire builders
    /// make them, folded here at once and rumored on `space:<name>` under `w:<entry id>`.
    pub(super) fn write_entry(
        &mut self,
        space: &str,
        type_name: &str,
        payload: &Value,
        lease_millis: i64,
        tags: &Map,
        agent: Option<AgentIdentity>,
    ) -> Result<String, PeerError> {
        self.check_open()?;
        let agent = match agent {
            Some(agent) => {
                let now = self.now();
                Some(self.acting_agent(agent, now)?)
            }
            None => None,
        };
        let prepared = self.prepare_write(space, type_name, payload, lease_millis, tags, agent)?;
        self.commit_write(space, prepared)
    }

    /// Everything of a write but its commit: the space opened, the tags checked (text to text, as
    /// Java's `Map<String, String>`: every member's fold refuses a record with any other tag),
    /// room for a new entry in the space (collecting its tombstones first when it is full), the
    /// payload encoded (and held as a block when it exceeds the inline limit), the record and
    /// state signed by `agent` (already [`Actor::acting_agent`]'s, renewed) or this peer, and the
    /// rumor sized. Nothing is folded or sent, so a completion can prepare its result before it
    /// commits (Java `prepareWrite`), and every check that can fail runs here: a write that fails
    /// leaves nothing behind.
    fn prepare_write(
        &mut self,
        space: &str,
        type_name: &str,
        payload: &Value,
        lease_millis: i64,
        tags: &Map,
        agent: Option<AgentIdentity>,
    ) -> Result<PreparedWrite, PeerError> {
        self.check_open()?;
        if lease_millis <= 0 {
            return Err(PeerError::InvalidArgument(format!(
                "a lease must be positive, not {lease_millis} ms"
            )));
        }
        if let Some((key, value)) = tags
            .iter()
            .find(|(key, value)| key.as_str().is_none() || value.as_str().is_none())
        {
            return Err(PeerError::InvalidArgument(format!(
                "tags are text to text, not {key:?} => {value:?}"
            )));
        }
        let now = self.now();
        let expires = now
            .checked_add(lease_millis)
            .ok_or_else(|| PeerError::InvalidArgument("the lease overflows".to_owned()))?;
        let space_id = match self.spaces.slot(space) {
            Some(slot) => slot.space_id.clone(),
            None => {
                return Err(PeerError::InvalidArgument(format!(
                    "cannot open space {space:?}"
                )));
            }
        };
        let entry_id = uuid_v4()?;
        if !self.space_has_room(space, now) {
            bump(&mut self.counters.space_refused_inserts);
            return Err(PeerError::Refused {
                entry_id,
                refusal: Refusal::Full,
            });
        }
        let issuer = match agent.as_ref() {
            Some(agent) => {
                let owner = ids::parse_agent_id(agent.agent_id()).map(|(peer, _)| peer);
                if owner != Some(self.peer_id.as_str()) {
                    return Err(PeerError::ForeignAgent(agent.agent_id().to_owned()));
                }
                agent.agent_id().to_owned()
            }
            None => self.identity.agent(DEFAULT_AGENT_NAME),
        };
        let agent_key = agent.as_ref().map(|agent| agent.public_raw().as_slice());
        if self.registry.refuses(&issuer, agent_key, None) {
            return Err(PeerError::Revoked(issuer));
        }
        // Every member reads a payload only in the wire encoding (`cbor::decode`, Java's strict
        // reader): a payload with a map key that is not text, nested past the depth limit, or
        // holding an integer no CBOR form carries would be written and then read by no one, so it
        // is refused here, where its writer hears of it. A payload past the frame cap is left to
        // the block cap's own refusal.
        let encoded = cbor::try_encode(payload).map_err(|error| {
            PeerError::InvalidArgument(format!("the payload has no wire encoding: {error}"))
        })?;
        if encoded.len() <= MAX_FRAME_BYTES
            && let Err(error) = cbor::decode(&encoded)
        {
            return Err(PeerError::InvalidArgument(format!(
                "the payload is not in the wire encoding every member reads: {error}"
            )));
        }
        let block = (encoded.len() > INLINE_PAYLOAD_LIMIT).then(|| bodies::block_cid(&encoded));
        let (inline, payload_ref) = match &block {
            Some(cid) => (None, Some(cid.as_str())),
            None => (Some(encoded.as_slice()), None),
        };
        let issued = self.issuer_stamp(&issuer, now);
        let signed_at = agent
            .as_ref()
            .map(|agent| self.issuer_stamp(agent.agent_id(), now));
        let write = EntryWrite {
            entry_id: &entry_id,
            space_id: &space_id,
            type_name,
            payload: inline,
            payload_ref,
            tags: Some(tags),
            key_epoch: None,
            issued: &issued,
            expires_at_millis: expires,
            counter: 1,
        };
        let agent_signing = agent.as_ref().zip(signed_at.as_deref());
        let state =
            records::entry_state(&write, &self.identity, DEFAULT_AGENT_NAME, agent_signing)?;
        let delta = records::delta(Some(&state), None);
        let body = bodies::rumor_body(
            &format!("{STREAM_SPACE_PREFIX}{space}"),
            &format!("w:{entry_id}"),
            RUMOR_HOPS,
            &delta,
        );
        fits_a_frame(&body)?;
        if let Some(cid) = &block {
            // Held last, once nothing else can fail, and refused before anything is folded or
            // rumored: a block no frame can carry would replicate an entry no member could ever
            // read.
            let length = encoded.len();
            self.blocks
                .hold_own(cid.clone(), encoded)
                .map_err(|refused| block_refusal(refused, length))?;
        }
        Ok(PreparedWrite {
            entry_id,
            state,
            body,
            block,
        })
    }

    /// Commits a prepared write: folded here (the writer holds its own entry too, so a local
    /// read sees it at once) and rumored. Answers its id; [`PeerError::Refused`] when its own fold
    /// refuses it (which [`Actor::prepare_write`]'s checks leave to a bug), and then nothing is
    /// sent.
    fn commit_write(&mut self, space: &str, prepared: PreparedWrite) -> Result<String, PeerError> {
        let PreparedWrite {
            entry_id,
            state,
            body,
            block,
        } = prepared;
        let failure = match self.fold_state(space, &state) {
            Some(FoldOutcome::Refused(refusal)) => PeerError::Refused { entry_id, refusal },
            Some(_) => {
                self.send_or_hold(body);
                return Ok(entry_id);
            }
            None => PeerError::InvalidArgument(format!("cannot open space {space:?}")),
        };
        self.release_blocks(block);
        Err(failure)
    }

    /// Whether every member's fold would admit a prepared write's record
    /// ([`records::verify_record`], as the fold judges it): the safety net a completion runs on
    /// its result before the completion commits.
    fn prepared_verifies(&self, prepared: &PreparedWrite, now: i64) -> bool {
        let state = &prepared.state;
        let record = state.get("record").and_then(Value::as_map);
        let key = state.get("issuerPublicKey").and_then(Value::as_bytes);
        match (record, key) {
            (Some(record), Some(key)) => {
                records::verify_record(record, key, state.get("agentCertificate"), now)
            }
            _ => false,
        }
    }

    /// Drops a prepared write that will not be committed: its block, unless a held entry names
    /// it too.
    fn discard_write(&mut self, prepared: PreparedWrite) {
        self.release_blocks(prepared.block);
    }

    pub(super) fn space_states(&self, space: &str) -> Vec<Map> {
        self.spaces
            .get(space)
            .map(|slot| slot.store.state_values().cloned().collect())
            .unwrap_or_default()
    }

    pub(super) fn space_claims(&self, space: &str) -> Vec<(String, Map)> {
        self.spaces
            .get(space)
            .map(|slot| {
                slot.store
                    .claims()
                    .map(|(entry_id, signed)| (entry_id.to_owned(), signed.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Runs `inspect` over a space's store; `None` when the space was never opened. A panic in
    /// `inspect` is caught here and handed back, so it unwinds in the caller and never on the
    /// actor. Catching it is sound: the closure only reads the store.
    pub(super) fn with_space<R>(
        &self,
        space: &str,
        inspect: impl FnOnce(&SpaceStore) -> R,
    ) -> Option<std::thread::Result<R>> {
        self.spaces
            .get(space)
            .map(|slot| std::panic::catch_unwind(AssertUnwindSafe(|| inspect(&slot.store))))
    }

    /// Publishes an advertisement this peer issued on the `ads` stream in the stored form, under
    /// `<id>:<issued millis>` (`Peer.publish_ad`); this peer's cache holds it too.
    pub(super) fn publish_ad(&mut self, ad_type: &str, ad: &Map) -> Result<(), PeerError> {
        self.check_open()?;
        let id = ad
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| PeerError::InvalidArgument("an advertisement has an id".to_owned()))?;
        let issued = ad
            .get("issued")
            .and_then(Value::as_str)
            .and_then(|issued| time::parse_instant_millis(issued).ok())
            .ok_or_else(|| {
                PeerError::InvalidArgument("an advertisement has an issued instant".to_owned())
            })?;
        let item = format!("{id}:{issued}");
        let stored = Value::Map(wire_ads::stored_ad(ad_type, ad, &self.identity));
        let body = bodies::rumor_body(STREAM_ADS, &item, RUMOR_HOPS, &cbor::encode(&stored));
        fits_a_frame(&body)?;
        self.accept_ad(&stored);
        self.send_or_hold(body);
        Ok(())
    }

    pub(super) fn send_addressed(
        &mut self,
        kind: &str,
        body: &[u8],
        to: &str,
    ) -> Result<(), PeerError> {
        self.check_open()?;
        self.send_addressed_frame(kind, body, to)
    }

    /// Holds one of this peer's own blocks; a block over the single-block cap, or past the own
    /// budget, is refused.
    pub(super) fn put_block(&mut self, data: Vec<u8>) -> Result<String, PeerError> {
        let cid = bodies::block_cid(&data);
        let length = data.len();
        self.blocks
            .pin_own(cid.clone(), data)
            .map_err(|refused| block_refusal(refused, length))?;
        Ok(cid)
    }

    pub(super) fn block(&self, cid: &str) -> Option<Vec<u8>> {
        self.blocks.get(cid).cloned()
    }

    /// The id of the block an entry's payload travels as, when this peer holds it as one of its
    /// own (it wrote the entry here).
    pub(super) fn own_payload_block(&self, space: &str, entry_id: &str) -> Option<String> {
        let state = self.spaces.get(space)?.store.state(entry_id)?;
        let record = state.get("record")?.as_map()?;
        match records::payload_source(record)? {
            PayloadSource::Block(cid) if self.blocks.is_own(cid) => Some(cid.to_owned()),
            _ => None,
        }
    }

    /// Asks member `to` for one of this peer's own blocks to learn whether it holds it: its
    /// answer, verified, is told as [`PeerEvent::BlockHeld`] (and not kept: this peer holds the
    /// block). Asked again, it asks again.
    pub(super) fn probe_block(&mut self, cid: &str, to: &str) -> Result<(), PeerError> {
        self.check_open()?;
        if !self.blocks.is_own(cid) {
            return Err(PeerError::InvalidArgument(format!(
                "{cid} is not a block of this peer's own"
            )));
        }
        let now = Instant::now();
        if !self.block_probes.contains_key(cid) && self.block_probes.len() >= MAX_ASKED_BLOCKS {
            self.block_probes
                .retain(|_, (_, asked)| now.duration_since(*asked) < Duration::from_secs(60));
            if self.block_probes.len() >= MAX_ASKED_BLOCKS {
                return Err(PeerError::SendOverflow);
            }
        }
        self.block_probes
            .insert(cid.to_owned(), (to.to_owned(), now));
        self.send_addressed_frame(KIND_BLOCK_WANT, &bodies::block_want_body(cid), to)
    }

    /// The payload bytes of an entry's record: inline, a held block, or the CBOR null; a block
    /// not yet held is asked for and `None` returned (`Peer.payload_of`). A content-swarm root
    /// is not resolved here.
    pub(super) fn payload_of(&mut self, space: &str, entry_id: &str) -> Option<Vec<u8>> {
        let state = self.spaces.get(space)?.store.state(entry_id)?;
        let record = state.get("record")?.as_map()?;
        let wanted = match records::payload_source(record)? {
            PayloadSource::Inline(payload) => return Some(payload.to_vec()),
            PayloadSource::Null => return Some(NULL_PAYLOAD.to_vec()),
            PayloadSource::Content(_) => return None,
            PayloadSource::Block(cid) => {
                if let Some(data) = self.blocks.get(cid) {
                    return Some(data.clone());
                }
                let key = state
                    .get("issuerPublicKey")
                    .and_then(Value::as_bytes)
                    .map(<[u8]>::to_vec);
                (cid.to_owned(), key)
            }
        };
        self.want_block(&wanted.0, wanted.1.as_deref());
        None
    }

    /// Ends the peer: the link closes, no redial follows, and every later verb answers
    /// [`PeerError::Closed`]. Reads still answer from what was held.
    pub(super) fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        if let Some(redial) = self.redial.take() {
            redial.task.abort();
        }
        self.lose_link();
        self.next_want = None;
        self.outbox.clear();
        for waiter in self.ready.drain(..) {
            let _ = waiter.send(Err(PeerError::Closed));
        }
        self.close_watches();
        // Wakes the reads and takes waiting for a fold: their next pass answers `Closed`.
        self.bump_folds();
    }
}

/// An actor dropped without its [`Actor::close`] (a panic unwinding it, say) still closes:
/// the redial is aborted, the link closed, the handles see no link, and subscribers hear
/// `Disconnected`. After a normal end this does nothing more.
impl Drop for Actor {
    fn drop(&mut self) {
        self.close();
    }
}

/// The founder's PeerID of a signed group advertisement.
fn founder_of(signed: &Map) -> Option<String> {
    signed
        .get("advertisement")
        .and_then(|ad| ad.get("issuer"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// A pull with no link (or one that just closed) is not an error: it is sent again after the
/// next link's introduction. A pull refused by a full queue is, since the link stays up.
fn offline_ok(result: Result<(), PeerError>) -> Result<(), PeerError> {
    match result {
        Err(PeerError::NotConnected) => Ok(()),
        other => other,
    }
}

/// The error a refused block surfaces as.
fn block_refusal(refused: Refused, length: usize) -> PeerError {
    match refused {
        Refused::Oversize => PeerError::InvalidArgument(format!(
            "a block of {length} bytes is over the {MAX_SINGLE_BLOCK_BYTES}-byte cap: no frame \
             can carry it (a content swarm can)"
        )),
        Refused::Full => PeerError::InvalidArgument("the block store is full".to_owned()),
    }
}

/// The `issued` instant of an advertisement in epoch milliseconds.
fn issued_millis(ad: &Map) -> Option<i64> {
    ad.get("issued")
        .and_then(Value::as_str)
        .and_then(|issued| time::parse_instant_millis(issued).ok())
}

/// A PING_REQ body `{target, nonce}` (Java `Bodies.PingReq`): the PeerID to probe and the
/// asker's nonce, 0 when absent or null (Jackson's default for the primitive `long`).
fn parse_ping_req(body: &[u8]) -> Option<(String, i64)> {
    let value = cbor::decode(body).ok()?;
    let request = value.as_map()?;
    let target = request.get("target")?.as_str()?.to_owned();
    let nonce = match request.get("nonce") {
        None | Some(Value::Null) => 0,
        Some(nonce) => nonce.as_i64()?,
    };
    Some((target, nonce))
}

/// The ACK `{nonce, onBehalf}` a relay sends the origin of a PING_REQ once the target answered
/// (Java `new Bodies.Ack(originNonce, target)`).
fn ack_on_behalf_body(nonce: i64, target: &str) -> Vec<u8> {
    let mut body = Map::with_capacity(2);
    body.insert("nonce", nonce);
    body.insert("onBehalf", target);
    cbor::encode(&Value::Map(body))
}

/// An unguessable probe nonce from the crypto port's random source; `None` when it fails.
fn random_nonce() -> Option<i64> {
    let mut bytes = [0u8; 8];
    crypto::port().fill_random(&mut bytes).ok()?;
    Some(i64::from_be_bytes(bytes))
}

/// Whether a body fits a frame with room for its envelope and signature
/// ([`FRAME_OVERHEAD`]); a rumor that cannot travel is refused before anything is held.
fn fits_a_frame(body: &[u8]) -> Result<(), PeerError> {
    let size = body.len().saturating_add(FRAME_OVERHEAD);
    if size > MAX_FRAME_BYTES {
        Err(PeerError::FrameTooLarge(size))
    } else {
        Ok(())
    }
}

fn bump(counter: &mut u64) {
    *counter = counter.saturating_add(1);
}

/// A version 4 UUID in its lower-case text form, from the crypto port's random source (the entry
/// ids `wire.py` draws with `uuid4`).
fn uuid_v4() -> Result<String, PeerError> {
    let mut bytes = [0u8; 16];
    crypto::port()
        .fill_random(&mut bytes)
        .map_err(|error| PeerError::Random(error.to_string()))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    ))
}

async fn wake_at(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

async fn until_closed(closed: &mut watch::Receiver<bool>) {
    loop {
        if *closed.borrow_and_update() {
            return;
        }
        if closed.changed().await.is_err() {
            return;
        }
    }
}

// ----------------------------------------------------------------------------- link tasks

/// Drains a link, verifies each frame with the link's attestation, and forwards it to the actor
/// with its share of `budget` (one permit per byte); tells the actor when the link ends. Once
/// the budget is spent this task waits, so the transport stops reading.
async fn read_link(
    mut receiver: FrameReceiver,
    attested: Option<String>,
    link: u64,
    inbound: mpsc::Sender<Inbound>,
    budget: Arc<Semaphore>,
) {
    while let Some(frame) = receiver.recv().await {
        let share = u32::try_from(frame.len().min(INBOUND_BUDGET_BYTES)).unwrap_or(u32::MAX);
        let Ok(permit) = Arc::clone(&budget).acquire_many_owned(share).await else {
            return;
        };
        let message = match envelope::decode_frame_detailed(&frame, attested.as_deref(), None) {
            Some((env, auth)) => Inbound::Frame {
                link,
                env,
                auth,
                budget: permit,
            },
            None => Inbound::Malformed { link },
        };
        drop(frame);
        if inbound.send(message).await.is_err() {
            return;
        }
    }
    let _ = inbound.send(Inbound::Lost { link }).await;
}

/// What a link's pump needs besides its queue.
struct Pump {
    shared: Arc<PumpShared>,
    sender: FrameSender,
    closer: Closer,
    /// How long one frame may wait for the transport before the link counts as stalled.
    stall: Duration,
    link: u64,
    inbound: mpsc::Sender<Inbound>,
    /// The queued bytes at or below which a waiting relief is sent.
    low_water: usize,
    /// The peer-wide count of frames discarded unwritten.
    dropped: Arc<AtomicU64>,
}

/// How one handoff to the transport ended.
enum Handoff {
    Sent,
    Failed,
    Stalled,
}

/// Writes the actor's frames to the link in order; the only task that waits on the transport.
/// A frame the transport does not take within the stall timeout means the far end stopped
/// reading: the pump marks the link stalled and closes it. When the actor asked for relief, the
/// pump tells it once the queue has drained to its low water. Ends (and closes the link) when the
/// queue's sender is dropped, a send fails, the link stalls, or the link closes; every frame
/// still queued then is counted as dropped.
async fn pump(mut frames: mpsc::UnboundedReceiver<Vec<u8>>, pump: Pump) {
    let Pump {
        shared,
        sender,
        closer,
        stall,
        link,
        inbound,
        low_water,
        dropped,
    } = pump;
    let mut closed = closer.watch();
    loop {
        let frame = tokio::select! {
            frame = frames.recv() => frame,
            () = until_closed(&mut closed) => None,
        };
        let Some(frame) = frame else {
            break;
        };
        let length = frame.len();
        let handoff = tokio::select! {
            sent = sender.send(frame) => if sent.is_ok() { Handoff::Sent } else { Handoff::Failed },
            () = until_closed(&mut closed) => Handoff::Failed,
            () = tokio::time::sleep(stall) => Handoff::Stalled,
        };
        shared.queued.fetch_sub(length, Ordering::SeqCst);
        match handoff {
            Handoff::Sent => {}
            Handoff::Failed => {
                dropped.fetch_add(1, Ordering::Relaxed);
                break;
            }
            Handoff::Stalled => {
                shared.stalled.store(true, Ordering::SeqCst);
                dropped.fetch_add(1, Ordering::Relaxed);
                break;
            }
        }
        if shared.queued.load(Ordering::SeqCst) <= low_water
            && shared.wants_relief.swap(false, Ordering::SeqCst)
        {
            let told = tokio::select! {
                sent = inbound.send(Inbound::Relief { link }) => sent.is_ok(),
                () = until_closed(&mut closed) => false,
            };
            if !told {
                break;
            }
        }
    }
    closer.close();
    frames.close();
    while let Ok(frame) = frames.try_recv() {
        shared.queued.fetch_sub(frame.len(), Ordering::SeqCst);
        dropped.fetch_add(1, Ordering::Relaxed);
    }
}

// ----------------------------------------------------------------------------- dialing

/// The first dialer serving `scheme`.
fn dialer_for<'a>(dialers: &'a [Arc<dyn Dialer>], scheme: &str) -> Option<&'a Arc<dyn Dialer>> {
    dialers
        .iter()
        .find(|dialer| dialer.schemes().contains(&scheme))
}

/// The seeds to dial, in order (`Peer._expand_seeds`): a seed no dialer serves is skipped; a
/// `tcp` or `tls` seed is resolved to each of its addresses (kept as written when it does not
/// resolve within `timeout`); duplicates fold.
pub(super) async fn expand_seeds(
    seeds: &[Seed],
    dialers: &[Arc<dyn Dialer>],
    timeout: Duration,
) -> Vec<Seed> {
    let mut expanded: Vec<Seed> = Vec::new();
    for seed in seeds {
        if dialer_for(dialers, &seed.scheme).is_none() {
            tracing::warn!(%seed, "agentspaces: skipping a seed no dialer serves");
            continue;
        }
        let mut addresses = Vec::new();
        if seed.scheme == "tcp" || seed.scheme == "tls" {
            let lookup = tokio::net::lookup_host((seed.host.as_str(), seed.port));
            if let Ok(Ok(found)) = tokio::time::timeout(timeout, lookup).await {
                for address in found {
                    addresses.push(Seed::new(
                        address.ip().to_string(),
                        seed.port,
                        seed.scheme.clone(),
                    ));
                }
            }
        }
        if addresses.is_empty() {
            addresses.push(seed.clone());
        }
        for address in addresses {
            if !expanded.contains(&address) {
                expanded.push(address);
            }
        }
    }
    expanded
}

/// Dials one seed with the dialer for its scheme, bounded by `timeout`.
async fn dial_one(
    seed: &Seed,
    dialers: &[Arc<dyn Dialer>],
    identity: &Identity,
    timeout: Duration,
) -> Result<Channel, TransportError> {
    let dialer = dialer_for(dialers, &seed.scheme)
        .ok_or_else(|| TransportError::UnsupportedScheme(seed.scheme.clone()))?;
    match tokio::time::timeout(timeout, dialer.dial(seed, identity, timeout)).await {
        Ok(result) => result,
        Err(_) => Err(TransportError::Timeout(seed.to_string())),
    }
}

/// Dials the seeds in order until one accepts (`Peer.connect_any`); when none does, the error
/// says how they failed ([`no_seed_accepted`]).
pub(super) async fn dial_first(
    seeds: &[Seed],
    dialers: &[Arc<dyn Dialer>],
    identity: &Identity,
    timeout: Duration,
) -> Result<(Channel, Seed), PeerError> {
    let mut failures = Vec::new();
    for seed in seeds {
        match dial_one(seed, dialers, identity, timeout).await {
            Ok(channel) => return Ok((channel, seed.clone())),
            Err(error) => failures.push((seed.clone(), error)),
        }
    }
    Err(no_seed_accepted(&failures))
}

/// What every seed failing as `failures` says: [`PeerError::SeedNotAttested`] when a seed
/// attested nobody (an authentication failure, whatever the others did),
/// [`PeerError::DialTimedOut`] when every dial timed out, else [`PeerError::NoSeedAccepted`].
/// Each carries every seed and its failure.
pub(super) fn no_seed_accepted(failures: &[(Seed, TransportError)]) -> PeerError {
    let text = failures
        .iter()
        .map(|(seed, error)| format!("{seed}: {error}"))
        .collect::<Vec<_>>()
        .join("; ");
    if failures
        .iter()
        .any(|(_, error)| matches!(error, TransportError::NotAttested(_)))
    {
        PeerError::SeedNotAttested(text)
    } else if !failures.is_empty()
        && failures
            .iter()
            .all(|(_, error)| matches!(error, TransportError::Timeout(_)))
    {
        PeerError::DialTimedOut(text)
    } else {
        PeerError::NoSeedAccepted(text)
    }
}

/// When a redial runs: its attempt number, when it gives up, and how long it waits before its
/// first round.
struct Schedule {
    attempt: u64,
    deadline: Option<Instant>,
    pause: Duration,
}

/// After a lost link: waits the schedule's pause, then dials the candidates (the next seed
/// first) every `reconnect_interval` until one accepts or the deadline passes
/// (`Peer._reconnect`, with the rounds paced as `Actor::lose_link` describes).
async fn redial(
    candidates: Vec<Seed>,
    dialers: Vec<Arc<dyn Dialer>>,
    identity: Arc<Identity>,
    settings: Settings,
    inbound: mpsc::Sender<Inbound>,
    schedule: Schedule,
) {
    let Schedule {
        attempt,
        deadline,
        pause,
    } = schedule;
    if !pause.is_zero() {
        tokio::time::sleep(pause).await;
    }
    loop {
        // An actor that is gone (it ended, or a panic unwound it) wants no link.
        if inbound.is_closed() {
            return;
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            let _ = inbound.send(Inbound::GaveUp { attempt }).await;
            return;
        }
        for seed in &candidates {
            if inbound.is_closed() {
                return;
            }
            let Ok(channel) = dial_one(seed, &dialers, &identity, settings.dial_timeout).await
            else {
                continue;
            };
            let message = Inbound::Dialed {
                channel: Box::new(channel),
                seed: seed.clone(),
                attempt,
            };
            if let Err(mpsc::error::SendError(Inbound::Dialed { channel, .. })) =
                inbound.send(message).await
            {
                channel.closer.close();
            }
            return;
        }
        tokio::time::sleep(settings.reconnect_interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// How every seed failed decides the error, whatever the number of seeds: all timed out is a
    /// timeout, a seed that attested nobody an authentication failure, anything else (or a mix of
    /// refusals and timeouts) no seed accepting.
    #[test]
    fn dial_failures_are_classified_by_how_every_seed_failed() {
        let seed = |port| Seed::new("127.0.0.1", port, "tls");
        let timeout = |port| (seed(port), TransportError::Timeout(seed(port).to_string()));
        let refused = |port| {
            (
                seed(port),
                TransportError::Io(std::io::Error::from(std::io::ErrorKind::ConnectionRefused)),
            )
        };
        let unattested = |port| {
            (
                seed(port),
                TransportError::NotAttested(seed(port).to_string()),
            )
        };
        assert!(matches!(
            no_seed_accepted(&[timeout(1)]),
            PeerError::DialTimedOut(text) if text.contains("tls://127.0.0.1:1")
        ));
        assert!(matches!(
            no_seed_accepted(&[timeout(1), timeout(2)]),
            PeerError::DialTimedOut(text) if text.contains(":1") && text.contains(":2")
        ));
        assert!(matches!(
            no_seed_accepted(&[unattested(1)]),
            PeerError::SeedNotAttested(_)
        ));
        assert!(matches!(
            no_seed_accepted(&[timeout(1), unattested(2), refused(3)]),
            PeerError::SeedNotAttested(_)
        ));
        assert!(matches!(
            no_seed_accepted(&[refused(1)]),
            PeerError::NoSeedAccepted(_)
        ));
        assert!(matches!(
            no_seed_accepted(&[timeout(1), refused(2)]),
            PeerError::NoSeedAccepted(_)
        ));
        assert!(matches!(
            no_seed_accepted(&[]),
            PeerError::NoSeedAccepted(_)
        ));
    }

    #[test]
    fn uuids_are_version_4_text() {
        let id = uuid_v4().expect("random");
        assert_eq!(id.len(), 36);
        assert_eq!(id.as_bytes()[14], b'4');
        assert!(matches!(id.as_bytes()[19], b'8' | b'9' | b'a' | b'b'));
        assert_ne!(id, uuid_v4().expect("random"));
    }

    #[test]
    fn settings_clamp_their_timers() {
        let settings = Settings::new(
            Duration::ZERO,
            Duration::MAX,
            Duration::ZERO,
            Duration::ZERO,
            0,
            Duration::ZERO,
        );
        assert_eq!(settings.reconnect_interval, MIN_TIMER);
        assert_eq!(settings.reconnect_window, MAX_TIMER);
        assert_eq!(settings.send_queue_bytes, 1);
        assert_eq!(settings.send_stall_timeout, MIN_TIMER);
    }

    #[tokio::test]
    async fn a_full_send_queue_refuses_without_waiting() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let queue = SendQueue {
            tx,
            shared: Arc::new(PumpShared::default()),
        };
        assert!(
            matches!(queue.offer(vec![0; 64], 10), Offer::Queued),
            "alone"
        );
        assert!(matches!(queue.offer(vec![0; 1], 10), Offer::Full));
        let _ = rx.recv().await;
        queue.shared.queued.store(0, Ordering::SeqCst);
        assert!(matches!(queue.offer(vec![0; 4], 10), Offer::Queued));
        assert!(matches!(queue.offer(vec![0; 6], 10), Offer::Queued));
        assert!(matches!(queue.offer(vec![0; 1], 10), Offer::Full));
        assert!(queue.has_room(1, 11) && !queue.has_room(1, 10));
        drop(rx);
        queue.shared.queued.store(0, Ordering::SeqCst);
        assert!(matches!(queue.offer(vec![0; 1], 10), Offer::Closed));
    }

    /// Once the group outgrows the probe cycle a Java seed runs, `(members + 1) × 1 s × 4` against
    /// its 30 s member TTL, the re-lease (the peer's keepalive) runs at half the TTL.
    #[test]
    fn the_re_lease_runs_at_half_the_member_ttl_once_the_group_outgrows_the_probe_cycle() {
        let thirty = Duration::from_secs(30);
        for members in 0..=6 {
            assert_eq!(
                re_lease_period(thirty, members),
                thirty,
                "{members} members"
            );
        }
        for members in [7, 8, 100, usize::MAX] {
            assert_eq!(
                re_lease_period(thirty, members),
                Duration::from_secs(15),
                "{members} members"
            );
        }
        // A shorter configured interval is kept either way.
        let ten = Duration::from_secs(10);
        assert_eq!(re_lease_period(ten, 3), ten);
        assert_eq!(re_lease_period(ten, 100), ten);
    }

    /// A link's reader forwards verified frames only within its byte budget; past it the reader
    /// waits and the transport's small queue fills, so the far end's sends wait too.
    #[tokio::test]
    async fn the_inbound_budget_bounds_the_bytes_waiting_for_the_actor() {
        use crate::transport::{CHANNEL_QUEUE, memory};

        let (far, near) = memory::pair("mem", "near", "far", None, None);
        let (tx, mut rx) = mpsc::channel(INBOUND_QUEUE);
        const BUDGET: usize = 1024 * 1024;
        tokio::spawn(read_link(
            near.receiver,
            None,
            1,
            tx,
            Arc::new(Semaphore::new(BUDGET)),
        ));
        let identity = Identity::generate().expect("identity");
        let body = vec![7u8; 100 * 1024];
        let frame = |n: i64| {
            let stamp = format!("{n}:0:{}", identity.peer_id());
            let env =
                envelope::envelope("zGroup", KIND_PING, identity.peer_id(), &stamp, &body, None);
            envelope::encode_frame(&env, &identity)
        };
        let size = frame(1).len();
        let mut sent = 0usize;
        loop {
            let next = frame(i64::try_from(sent).expect("small") + 1);
            match tokio::time::timeout(Duration::from_millis(300), far.sender.send(next)).await {
                Ok(Ok(())) => sent += 1,
                Ok(Err(error)) => panic!("the link failed: {error}"),
                Err(_) => break,
            }
            assert!(sent < 1000, "the reader never pushed back");
        }
        let within = BUDGET / size;
        assert!(
            (within..=within + CHANNEL_QUEUE + 1).contains(&sent),
            "{sent} frames of {size} bytes went in against a {BUDGET}-byte budget"
        );
        // Handling one frame gives its bytes back: one more frame goes in.
        let handled = rx.recv().await.expect("a forwarded frame");
        assert!(matches!(handled, Inbound::Frame { .. }));
        drop(handled);
        let next = frame(5000);
        tokio::time::timeout(Duration::from_secs(2), far.sender.send(next))
            .await
            .expect("room once a frame was handled")
            .expect("the link is up");
    }

    /// An actor for unit tests: a fresh identity in a text-founded group, no dialers, and the
    /// event stream it tells.
    fn test_actor() -> (
        Actor,
        broadcast::Receiver<PeerEvent>,
        mpsc::Receiver<Inbound>,
        watch::Receiver<Option<LinkInfo>>,
    ) {
        let (events, subscriber) = broadcast::channel(64);
        let (link_watch, link) = watch::channel(None);
        let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_QUEUE);
        let start = Start {
            identity: Identity::generate().expect("identity"),
            group: "zGroup".to_owned(),
            founder: None,
            founding: None,
            joining: false,
            clock: Arc::new(crate::clock::SystemClock),
            settings: Settings::new(
                Duration::from_millis(50),
                Duration::from_secs(10),
                Duration::from_secs(30),
                Duration::from_secs(1),
                1024 * 1024,
                Duration::from_secs(30),
            ),
            dialers: Vec::new(),
            seeds: Vec::new(),
            resource_hints: Map::new(),
            events,
            link_watch,
            folds: watch::channel(0).0,
        };
        (Actor::new(start, inbound_tx), subscriber, inbound_rx, link)
    }

    /// An actor dropped without its close (a panic unwinding it, say) still closes: the link is
    /// closed, the handles see no link, and the subscribers hear Disconnected.
    #[tokio::test]
    async fn an_actor_dropped_without_close_still_closes() {
        use crate::transport::memory;

        let (mut actor, mut events, _inbound, link) = test_actor();
        let (mine, theirs) = memory::pair("mem", "seed", "peer", None, None);
        actor.install_link(mine, Seed::new("127.0.0.1", 7000, "tcp"));
        assert!(link.borrow().is_some());
        while events.try_recv().is_ok() {}
        drop(actor);
        assert!(link.borrow().is_none(), "the handles see no link");
        assert!(theirs.closer.is_closed(), "the link is closed");
        assert_eq!(events.try_recv().ok(), Some(PeerEvent::Disconnected));
    }

    /// When the re-introduction on a redialed link loses it (its pump already gone), the
    /// subscribers hear Disconnected and never a Reconnected for that link.
    #[tokio::test]
    async fn a_reconnect_whose_link_is_lost_at_once_is_not_told() {
        use crate::transport::memory;

        let (mut actor, mut events, _inbound, _link) = test_actor();
        let (mine, _theirs) = memory::pair("mem", "seed", "peer", None, None);
        let link = actor.install_link(mine, Seed::new("127.0.0.1", 7000, "tcp"));
        // The pump is gone before the re-introduction: every offer finds its queue closed.
        if let Some(held) = actor.link.as_mut() {
            let (tx, rx) = mpsc::unbounded_channel();
            drop(rx);
            held.queue.tx = tx;
        }
        actor.resume_on(link);
        let mut told = Vec::new();
        while let Ok(event) = events.try_recv() {
            told.push(event);
        }
        assert!(told.contains(&PeerEvent::Disconnected), "{told:?}");
        assert!(
            !told
                .iter()
                .any(|event| matches!(event, PeerEvent::Reconnected { .. })),
            "{told:?}"
        );
        assert!(actor.link.is_none());

        // A link that survives its re-introduction is told.
        let (mine, _theirs) = memory::pair("mem", "seed", "peer", None, None);
        let link = actor.install_link(mine, Seed::new("127.0.0.1", 7000, "tcp"));
        actor.resume_on(link);
        let mut told = Vec::new();
        while let Ok(event) = events.try_recv() {
            told.push(event);
        }
        assert!(
            told.iter()
                .any(|event| matches!(event, PeerEvent::Reconnected { .. })),
            "{told:?}"
        );
    }

    /// A dialer that counts its dials and refuses them all.
    #[derive(Debug, Default)]
    struct Refusing(AtomicUsize);

    impl Dialer for Refusing {
        fn schemes(&self) -> &[&'static str] {
            &["tcp"]
        }

        fn dial<'a>(
            &'a self,
            _seed: &'a Seed,
            _identity: &'a Identity,
            _timeout: Duration,
        ) -> crate::transport::BoxFuture<'a, Result<Channel, TransportError>> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Err(TransportError::Closed) })
        }
    }

    /// A redial whose actor is gone stops at once instead of dialing out its window.
    #[tokio::test]
    async fn a_redial_stops_when_its_actor_is_gone() {
        let refusing = Arc::new(Refusing::default());
        let dialers: Vec<Arc<dyn Dialer>> = vec![refusing.clone()];
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let settings = Settings::new(
            Duration::from_millis(10),
            Duration::from_secs(60),
            Duration::from_secs(30),
            Duration::from_secs(1),
            1024,
            Duration::from_secs(30),
        );
        let finished = tokio::time::timeout(
            Duration::from_secs(1),
            redial(
                vec![Seed::new("127.0.0.1", 7000, "tcp")],
                dialers,
                Arc::new(Identity::generate().expect("identity")),
                settings,
                tx,
                Schedule {
                    attempt: 1,
                    deadline: Instant::now().checked_add(Duration::from_secs(60)),
                    pause: Duration::ZERO,
                },
            ),
        )
        .await;
        assert!(finished.is_ok(), "the redial outlived its actor");
        assert_eq!(refusing.0.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn ping_requests_parse_as_java_writes_them() {
        let request = |target: Value, nonce: Value| {
            let mut body = Map::new();
            body.insert("target", target);
            body.insert("nonce", nonce);
            cbor::encode(&Value::Map(body))
        };
        assert_eq!(
            parse_ping_req(&request(Value::from("zTarget"), Value::from(42))),
            Some(("zTarget".to_owned(), 42))
        );
        assert_eq!(
            parse_ping_req(&request(Value::from("zTarget"), Value::Null)),
            Some(("zTarget".to_owned(), 0))
        );
        assert_eq!(parse_ping_req(&request(Value::Null, Value::from(1))), None);
        assert_eq!(
            parse_ping_req(&request(Value::from("t"), Value::from("x"))),
            None
        );
        assert_eq!(parse_ping_req(&[0xff]), None);
        let ack = cbor::decode(&ack_on_behalf_body(7, "zTarget")).expect("an ACK");
        assert_eq!(ack.get("nonce").and_then(Value::as_i64), Some(7));
        assert_eq!(ack.get("onBehalf").and_then(Value::as_str), Some("zTarget"));
    }
}
