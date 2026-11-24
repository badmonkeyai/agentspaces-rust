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

mod audit;
mod horizon;
mod probes;
mod redial;
pub(super) use redial::DialCounts;
mod rounds;
mod seed_watch;
mod serve;
mod space_ops;

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use agentspaces_wire::ads as wire_ads;
use agentspaces_wire::bodies::{
    self, KIND_ACK, KIND_BLOCK, KIND_BLOCK_WANT, KIND_CHANNEL_HELLO, KIND_DIGEST, KIND_GROUP_AD,
    KIND_GROUP_AD_WANT, KIND_PING, KIND_PING_REQ, KIND_PIPE_DATA, KIND_PULL_RESP, KIND_RELAY_FRAME,
    KIND_RUMOR, RELAY_SIGNAL_CAPABILITY, RUMOR_HOPS, RelaySignal, Rumor, STREAM_ADS, STREAM_PEERS,
    STREAM_SPACE_PREFIX,
};
use agentspaces_wire::cbor::{self, Map, Value};
use agentspaces_wire::crypto;
use agentspaces_wire::envelope::{self, Auth, FrameFilter};
use agentspaces_wire::fold::{FoldContext, FoldOutcome, Refusal, SpaceStore};
use agentspaces_wire::founding;
use agentspaces_wire::hlc::Hlc;
use agentspaces_wire::identity::{AgentIdentity, Identity};
use agentspaces_wire::ids;
use agentspaces_wire::limits::{
    CARD_SPILL_THRESHOLD_BYTES, CARD_SPILL_WARN_BYTES, INLINE_PAYLOAD_LIMIT, MAX_FRAME_BYTES,
};
use agentspaces_wire::records::{self, EntryWrite, NULL_PAYLOAD, PayloadSource};
use agentspaces_wire::revocation::{self, Registry};
use agentspaces_wire::seed::Seed;
use agentspaces_wire::serving;
use agentspaces_wire::time;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, broadcast, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use super::ads::{AdCache, pulled_ads};
use super::blocks::{
    BlockStore, MAX_FETCHED_BLOCK_BYTES, MAX_OWN_BLOCK_BYTES, MAX_SINGLE_BLOCK_BYTES, Refused,
};
use super::listen::{self, BoundListener, ListenConfig};
use super::members::MemberView;
use super::spaces::{Spaces, space_name};
use super::watchdog::LoopBeat;
use super::{
    DEFAULT_AGENT_NAME, FilterCounters, GROUP_AD_WANT_INTERVAL, LinkInfo, PeerCounters, PeerError,
    PeerEvent,
};
use crate::clock::SharedClock;
use crate::transport::{Channel, Closer, Dialer, FrameReceiver, FrameSender, TransportError};
use serve::{Hub, Via};
use space_ops::{COLLECT_INTERVAL, Deferred, Watcher};

/// A call queued by a [`Peer`](super::Peer) handle: it runs on the actor and replies itself.
pub(super) type Job = Box<dyn FnOnce(&mut Actor) + Send>;

/// What woke the loop for one turn.
enum Wake {
    Job(Job),
    Inbound(Inbound),
    ReLease,
    Want,
    Sweep,
    Collect,
    Housekeeping,
    DialRound,
    SeedCheck,
    DisplacedPull,
    Nudged,
}

/// How many handle calls may wait for the actor.
pub(super) const JOB_QUEUE: usize = 64;
/// How many verified frames (and link events) may wait for the actor before readers wait. The
/// frames are bounded by bytes too ([`INBOUND_BUDGET_BYTES`]).
const INBOUND_QUEUE: usize = 1024;
/// The bytes of verified frames one link may have waiting for the actor (Java
/// `FramePump.DEFAULT_CAP_BYTES`): past it the link's reader waits, so the transport stops
/// reading the socket and a fast or hostile seed cannot grow the peer's memory.
pub(super) const INBOUND_BUDGET_BYTES: usize = 64 * 1024 * 1024;
/// The bytes of verified frames one accepted link may have waiting for the actor: two frames at
/// the frame cap. Every accepted link draws on a shared budget too ([`ACCEPTED_BUDGET_BYTES`]),
/// so many links cannot pin many times the memory one may.
const ACCEPTED_LINK_BUDGET_BYTES: usize = 16 * 1024 * 1024;
/// The bytes of verified frames all accepted links together may have waiting for the actor.
pub(super) const ACCEPTED_BUDGET_BYTES: usize = 256 * 1024 * 1024;
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
/// The (card id, size) pairs a peer remembers warning about before it forgets them all.
const MAX_WARNED_CARDS: usize = 1024;
/// The keepalive bound every Java member keeps (`GroupMembership.KEEPALIVE_TTL`, SPEC v0.1.36
/// §5.2, *The member TTL*): the TTL a released 0.6.0 Java member judges this peer by (a 0.7.0
/// member judges by 45 s or more), so this peer keeps its own keepalive, the re-lease of its
/// self-advertisement, inside it. It is no TTL this peer judges others by: it drops nobody for
/// silence (its views follow advertisement expiry).
const KEEPALIVE_TTL: Duration = Duration::from_secs(30);
/// A change of more than this in (wall − monotonic) time between two turns of the loop is a
/// wall-clock step (an NTP step either way, or a suspend, which the monotonic clock does not
/// count): the wall-anchored deadlines are asked again (SPEC v0.1.36 §9.5).
const WALL_STEP: Duration = Duration::from_secs(1);
/// A wake of the loop this much past its armed deadline, with no wall-clock step, is a late
/// wake (owner decision 3 of 2026-11-23, the same in every implementation): a frozen process
/// (SIGSTOP, a long collection or VM pause) whose monotonic clock counted the freeze. The
/// members judged this peer by the time that passed, so it is a wake as a suspend is.
pub(super) const LATE_WAKE: Duration = Duration::from_secs(30);
/// How long after a wake a dial-only peer keeps a member whose card lapsed during the absence in
/// its view (counted as lacking the horizon hint, the cautious side) while it re-pulls the view
/// ([`Actor::reprobe_view`]): 1.5 times the 2 s answer window plus the widest first redial step
/// (5.5 s), as every client.
const VIEW_REPROBE_WAIT: Duration = Duration::from_millis(11_250);
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
    /// The bytes of states each space holds (`PeerConfig::space_max_bytes`).
    pub space_max_bytes: usize,
    /// The listening role's settings, clamped (`PeerConfig::listen`).
    pub listen: ListenSettings,
    /// Whether this peer advertises `wire.ae=2` and audits (`PeerConfig::audit`).
    pub audit: bool,
    /// The budget this peer asks for (`PeerConfig::audit_budget`).
    pub audit_budget: i64,
    /// Whether this peer advertises `wire.horizon=1` and applies the per-entry horizon
    /// (`PeerConfig::horizon`).
    pub horizon: bool,
    /// The fully hinted rounds before the per-entry horizon engages
    /// (`PeerConfig::horizon_engage_rounds`, clamped to 1 ..= 64).
    pub horizon_engage_rounds: u32,
}

/// The listening role's settings ([`ListenConfig`]), clamped to sane ranges.
#[derive(Debug, Clone)]
pub(super) struct ListenSettings {
    pub require_attestation: bool,
    pub replicate_heard: bool,
    pub max_replicated_spaces: usize,
    pub max_links: usize,
    pub max_members: usize,
    pub admission_burst: u32,
    pub admissions_per_second: u32,
    pub anti_entropy_period: Option<Duration>,
    pub introduction_timeout: Duration,
    pub link_idle_timeout: Duration,
    pub probe_streams: usize,
}

impl ListenSettings {
    /// The settings of `config`, every timer clamped to `1 ms ..= 365 days` and every bound to
    /// at least one.
    pub fn of(config: &ListenConfig) -> Self {
        let clamp = |d: Duration| d.clamp(MIN_TIMER, MAX_TIMER);
        Self {
            require_attestation: config.require_attestation,
            replicate_heard: config.replicate_heard,
            max_replicated_spaces: config.max_replicated_spaces,
            max_links: config.max_links.max(1),
            max_members: config.max_members.max(1),
            admission_burst: config.admission_burst.max(1),
            admissions_per_second: config.admissions_per_second,
            anti_entropy_period: config.anti_entropy_period.map(clamp),
            introduction_timeout: clamp(config.introduction_timeout),
            link_idle_timeout: clamp(config.link_idle_timeout),
            probe_streams: config
                .probe_streams
                .min(agentspaces_wire::bodies::PROBE_STREAMS_MAX),
        }
    }
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
            space_max_bytes: super::DEFAULT_SPACE_MAX_BYTES,
            listen: ListenSettings::of(&ListenConfig::default()),
            audit: true,
            audit_budget: agentspaces_wire::audit::BUDGET_DEFAULT,
            horizon: true,
            horizon_engage_rounds: agentspaces_wire::horizon::DEFAULT_ENGAGE_ROUNDS,
        }
    }

    /// These settings with the per-entry horizon of SPEC §7.3 on or off and its engage rounds
    /// (clamped to 1 ..= 64).
    pub fn with_horizon(self, horizon: bool, engage_rounds: u32) -> Self {
        Self {
            horizon,
            horizon_engage_rounds: engage_rounds.clamp(
                agentspaces_wire::horizon::ENGAGE_ROUNDS_MIN,
                agentspaces_wire::horizon::ENGAGE_ROUNDS_MAX,
            ),
            ..self
        }
    }

    /// These settings with the audit of SPEC annex I.6 on or off and the budget it asks for.
    pub fn with_audit(self, audit: bool, audit_budget: usize) -> Self {
        Self {
            audit,
            audit_budget: i64::try_from(audit_budget).unwrap_or(i64::MAX),
            ..self
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

    /// These settings with the bound of bytes each space's states hold (at least 1) and the
    /// listening role's settings.
    pub fn with_listen(self, space_max_bytes: usize, listen: &ListenConfig) -> Self {
        Self {
            space_max_bytes: space_max_bytes.max(1),
            listen: ListenSettings::of(listen),
            ..self
        }
    }
}

/// How often the self-advertisement is re-leased in a group of `members` other members, as Java's
/// `PeerNode.refreshIntervalMillis` refreshes its own: the configured `interval`, unless the
/// group's probe cycle (one member per [`PROBE_INTERVAL`], stretched [`QUIET_STRETCH`] times
/// when quiet) has outgrown the [`KEEPALIVE_TTL`]. Past that size the probes cannot reach every
/// member inside the TTL, so the re-lease is the keepalive and runs at half the TTL at most,
/// leaving a whole interval of margin before a Java seed expires this peer.
fn re_lease_period(interval: Duration, members: usize) -> Duration {
    let cycle = u32::try_from(members.saturating_add(1))
        .ok()
        .and_then(|count| PROBE_INTERVAL.checked_mul(count))
        .and_then(|cycle| cycle.checked_mul(QUIET_STRETCH))
        .unwrap_or(Duration::MAX);
    if cycle < KEEPALIVE_TTL {
        interval
    } else {
        interval.min(KEEPALIVE_TTL / 2)
    }
}

/// What starts an actor.
pub(super) struct Start {
    pub identity: Identity,
    /// This peer's clock, built over its PeerID (which [`Hlc::new`] validates where the peer
    /// starts).
    pub hlc: Hlc,
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
    /// The listeners bound (none for a dial-only peer).
    pub listeners: Vec<BoundListener>,
    /// The spaces a listening peer replicates from the start.
    pub replicate: Vec<String>,
    /// What the seed dials counted, from the join's first dial on ([`redial::DialCounts`]).
    pub dial_counts: Arc<redial::DialCounts>,
    /// Counts the wakes the loop saw (wall-clock steps and late wakes), so a held take re-checks
    /// its hold at once ([`crate::agent::TakeContext::keepalive`]).
    pub wakes: watch::Sender<u64>,
}

/// What a link's reader and pump and the redial task tell the actor.
pub(super) enum Inbound {
    /// A frame that verified on link `link`, with how it was authenticated, and its share of the
    /// link's inbound byte budget ([`INBOUND_BUDGET_BYTES`]; an accepted link's is smaller and
    /// it holds a share of the budget all accepted links share too), given back once it is
    /// handled.
    Frame {
        link: u64,
        env: Map,
        auth: Auth,
        budget: OwnedSemaphorePermit,
        shared: Option<OwnedSemaphorePermit>,
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
    /// Redial `attempt` went a whole reconnect window without a link; it goes on redialing.
    WindowLapsed { attempt: u64 },
    /// A listener accepted a channel.
    Accepted { channel: Box<Channel> },
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
    /// When a verified frame last arrived on it (an accepted link's idle timer).
    heard_at: Instant,
    /// When its reader last read a frame off the transport (the dialed link's dead-seed rule,
    /// [`seed_watch`]).
    heard: Arc<seed_watch::Heard>,
    /// The member that introduced itself on it (an accepted link's owner, SPEC §5.2).
    owner: Option<String>,
    /// Frames a stranger sent on it before any member introduced itself (an accepted link).
    strangers: u32,
    /// Burst frames waiting for room in its queue (an accepted link; the dialed link keeps the
    /// outbox instead), bounded by bytes and frames.
    backlog: VecDeque<Vec<u8>>,
    /// The bytes in `backlog`.
    backlog_bytes: usize,
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
    /// This loop's heartbeat, read by the process's watchdog ([`super::watchdog`]).
    beat: Arc<LoopBeat>,
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
    /// The position in the redial table ([`redial`]), lent to the redial in flight.
    redial_table: redial::RedialTable,
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
    /// The wakes seen ([`Start::wakes`]).
    wakes: watch::Sender<u64>,
    /// When each space was last pulled for the space verbs (its first use and the paced pulls
    /// of waiting reads and takes).
    last_pull: HashMap<String, Instant>,
    /// The agent identities acted as, by AgentID: their renewed certificates persist.
    agents: HashMap<String, AgentIdentity>,
    /// The watches, in the order they were added.
    watchers: Vec<Watcher>,
    /// When the watch sweep last ran.
    last_sweep: Instant,
    /// When the watch sweep next has a lapse to tell (epoch milliseconds, wall time): the
    /// earliest write or claim lease of a watched open entry, or a watch's own lapse.
    sweep_due: Option<i64>,
    /// The issue instants of this peer's cards and self-advertisement (SPEC v0.1.36 §9.5).
    issues: super::issue::IssueClock,
    /// The monotonic instant the wall-step check measures from, and (wall − monotonic) as last
    /// read, milliseconds.
    clock_base: Instant,
    wall_offset: Option<i64>,
    /// When the spaces' collection (SPEC §7.3) last ran.
    last_collect: Instant,
    /// Transitions waiting for their payload's block.
    deferred: VecDeque<Deferred>,
    /// The (card id, encoded size) pairs a size warning was logged for (SPEC §6.1a.5).
    warned_cards: HashSet<(String, usize)>,
    /// The listening role's state ([`serve`]); inert on a dial-only peer.
    hub: Hub,
    /// The trie audit of SPEC annex I.6 ([`audit`]).
    audit: audit::AuditState,
    /// The view's half of the per-entry horizon of SPEC §7.3 ([`horizon`]).
    horizon_view: horizon::HorizonView,
    /// A dial-only peer's periodic rounds toward its seed ([`rounds`]).
    dial_rounds: rounds::DialRounds,
    /// The dead-seed rule's state ([`seed_watch`]).
    seed_watch: seed_watch::SeedWatch,
    /// What the seed dials counted ([`redial::DialCounts`]), shared with the redial tasks.
    dial_counts: Arc<redial::DialCounts>,
    /// When the next targeted round toward a displaced holder is due, if any line is held
    /// ([`Actor::run_displaced_pulls`]).
    displaced_pull_due: Option<Instant>,
    /// When the last late wake was answered: one freeze is one wake, however many of the loop's
    /// and the watchdog's signals report it ([`Actor::check_late_wake`]).
    last_late_wake: Option<Instant>,
    /// Until when a dial-only peer re-probes its view after a wake ([`Actor::reprobe_view`]):
    /// the wall time when it went quiet, and the monotonic end of the wait.
    view_reprobe: Option<(i64, Instant)>,
}

/// Starts an actor, on `dialed` (a channel dialed to a seed) when there is one, and returns its
/// job queue. The actor sends its first frames at once: the GROUP_AD_WANT of a join by id, else
/// the introduction and the revocation pull. A listening peer starts accepting links on its
/// listeners; one whose seeds did not answer at start redials them in the background.
pub(super) fn spawn(
    mut start: Start,
    dialed: Option<(Channel, Seed)>,
) -> (mpsc::Sender<Job>, Arc<LoopBeat>) {
    let (jobs_tx, jobs_rx) = mpsc::channel(JOB_QUEUE);
    let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_QUEUE);
    let listeners = std::mem::take(&mut start.listeners);
    let replicate = std::mem::take(&mut start.replicate);
    let mut actor = Actor::new(start, inbound_tx.clone(), &listeners);
    for bound in listeners {
        actor
            .hub
            .accept_tasks
            .push(listen::spawn_accept(bound.listener, inbound_tx.clone()));
    }
    match dialed {
        Some((channel, seed)) => {
            actor.install_link(channel, seed);
            if actor.joining {
                actor.send_want();
            } else {
                actor.on_link_ready();
            }
        }
        None if !actor.seeds.is_empty() => {
            // A listening peer whose seeds did not answer: it serves its own links meanwhile.
            let now = Instant::now();
            actor.outage_since = Some(now);
            let pause = actor
                .redial_table
                .next_wait(actor.settings.reconnect_interval);
            actor.start_redial(now.checked_add(actor.settings.reconnect_window), pause);
        }
        None => {}
    }
    actor.start_listening(&replicate);
    let beat = Arc::clone(&actor.beat);
    tokio::spawn(actor.run(jobs_rx, inbound_rx));
    (jobs_tx, beat)
}

impl Actor {
    fn new(start: Start, inbound_tx: mpsc::Sender<Inbound>, listeners: &[BoundListener]) -> Self {
        let peer_id = start.identity.peer_id().to_owned();
        let hub = Hub::new(&start.settings.listen, listeners);
        let resource_hints = with_horizon_level(
            with_audit_level(
                with_app_card_level(start.resource_hints),
                start.settings.audit,
            ),
            start.settings.horizon,
        );
        // Each rule is a promise the card makes: a peer audits and applies the per-entry horizon
        // only while its card says so, so a configured hint of another value turns it off.
        let mut settings = start.settings;
        settings.audit &=
            agentspaces_wire::audit::hints_audit(Some(&Value::Map(resource_hints.clone())));
        settings.horizon &=
            agentspaces_wire::horizon::hints_horizon(Some(&Value::Map(resource_hints.clone())));
        let audit_state = audit::AuditState::new(settings.audit, settings.audit_budget);
        let mut registry = Registry::new(start.founder, Some(start.group.clone()));
        if registry.founder().is_none() {
            registry.set_founder(start.founding.as_ref().and_then(founder_of));
        }
        Self {
            beat: LoopBeat::register(peer_id.clone()),
            hlc: start.hlc,
            identity: Arc::new(start.identity),
            spaces: Spaces::new(&start.group, settings.space_max_entries),
            blocks: BlockStore::new(MAX_OWN_BLOCK_BYTES, settings.fetched_block_bytes),
            group: start.group,
            clock: start.clock,
            settings,
            dialers: start.dialers,
            seeds: start.seeds,
            issuer_clocks: HashMap::new(),
            filter: FrameFilter::new(),
            registry,
            ads: AdCache::default(),
            members: MemberView::new(MAX_MEMBERS),
            reachable: BTreeSet::new(),
            seed_peer: None,
            resource_hints,
            counters: PeerCounters::default(),
            link: None,
            next_link_id: 0,
            current_seed: None,
            redial: None,
            redial_attempts: 0,
            redial_table: redial::RedialTable::default(),
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
            wakes: start.wakes,
            last_pull: HashMap::new(),
            agents: HashMap::new(),
            watchers: Vec::new(),
            last_sweep: Instant::now(),
            sweep_due: None,
            issues: super::issue::IssueClock::default(),
            clock_base: Instant::now(),
            wall_offset: None,
            last_collect: Instant::now(),
            deferred: VecDeque::new(),
            warned_cards: HashSet::new(),
            audit: audit_state,
            horizon_view: horizon::HorizonView::default(),
            dial_rounds: rounds::DialRounds::default(),
            seed_watch: seed_watch::SeedWatch::default(),
            dial_counts: start.dial_counts,
            displaced_pull_due: None,
            last_late_wake: None,
            view_reprobe: None,
            hub,
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
            // The watch sweep runs only while something watches, when its earliest lapse falls
            // due; the collection while a space is open, watched or not.
            let sweep_at = self.sweep_at();
            let collect_at = if self.spaces.is_empty() {
                None
            } else {
                self.last_collect.checked_add(COLLECT_INTERVAL)
            };
            let tick_at = self.hub.next_tick;
            let round_at = self.dial_rounds.due();
            let seed_at = self.seed_check_at();
            let pull_at = self.displaced_pull_due;
            let armed = [
                lease_at, want_at, sweep_at, collect_at, tick_at, round_at, seed_at, pull_at,
            ]
            .into_iter()
            .flatten()
            .min();
            let slept_from = Instant::now();
            self.beat
                .arm(armed.map(|at| at.saturating_duration_since(slept_from)));
            let beat = Arc::clone(&self.beat);
            let wake = tokio::select! {
                job = jobs.recv() => match job {
                    Some(job) => Wake::Job(job),
                    None => break,
                },
                Some(message) = inbound.recv() => Wake::Inbound(message),
                () = wake_at(lease_at) => Wake::ReLease,
                () = wake_at(want_at) => Wake::Want,
                () = wake_at(sweep_at) => Wake::Sweep,
                () = wake_at(collect_at) => Wake::Collect,
                () = wake_at(tick_at) => Wake::Housekeeping,
                () = wake_at(round_at) => Wake::DialRound,
                () = wake_at(seed_at) => Wake::SeedCheck,
                () = wake_at(pull_at) => Wake::DisplacedPull,
                // The watchdog found this loop idle past its deadline: the next turn recomputes
                // every deadline, and an overdue one fires at once.
                () = beat.nudged() => Wake::Nudged,
            };
            // Before the turn runs what woke it: a wake (a wall step, or a late wake of a frozen
            // process) re-asks the seed and re-probes the members first, so no deadline that
            // fell due during a freeze judges anyone by the time the freeze took.
            // A deadline already past when the wait began (a wall-anchored one, say) fires at
            // once: its lateness counts from the wait's start.
            self.on_loop_wake(armed.map(|at| at.max(slept_from)));
            self.turn(wake);
        }
        self.beat.end(false);
        self.close();
    }

    /// One turn of the loop: what woke it, run with its heartbeat published, and a panic in it
    /// contained (logged by the panic hook, counted, and the loop goes on: the reference
    /// implementation's contained participant throw; three in ten minutes read DOWN).
    fn turn(&mut self, wake: Wake) {
        self.beat.start_turn();
        let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| match wake {
            Wake::Job(job) => job(self),
            Wake::Inbound(message) => self.on_inbound(message),
            Wake::ReLease => self.on_re_lease(),
            Wake::Want => self.on_want_tick(),
            Wake::Sweep => self.on_sweep(),
            Wake::Collect => self.on_collect(),
            Wake::Housekeeping => self.on_listen_tick(),
            Wake::DialRound => self.on_dial_round(),
            Wake::SeedCheck => self.on_seed_check(),
            Wake::DisplacedPull => self.run_displaced_pulls(),
            Wake::Nudged => {}
        }));
        self.beat.end_turn();
        if outcome.is_err() {
            let down = self.beat.note_panic();
            tracing::error!(
                peer = %self.peer_id,
                down,
                "agentspaces: a turn of the peer's loop panicked; contained, the loop goes on"
            );
        }
    }

    /// Milliseconds on this peer's monotonic clock (from its start, offset so it is never 0):
    /// the time base of local periods that no wire value is compared with, such as the audit's
    /// session, descent, and fetch timeouts (SPEC v0.1.36 §9.5: local periods on a monotonic
    /// clock, so a wall step neither cuts them short nor stretches them).
    fn local_ms(&self) -> i64 {
        let since = Instant::now().saturating_duration_since(self.clock_base);
        i64::try_from(since.as_millis())
            .unwrap_or(i64::MAX)
            .saturating_add(1_000)
    }

    /// What the loop checks each time it wakes, before the turn: a wall-clock step
    /// ([`Actor::check_wall_step`]) and, with none, a late wake against `armed`, the deadline
    /// it slept toward ([`Actor::check_late_wake`]).
    pub(super) fn on_loop_wake(&mut self, armed: Option<Instant>) {
        if !self.check_wall_step() {
            self.check_late_wake(armed);
        }
    }

    /// A late wake (owner decision 3 of 2026-11-23): the loop woke more than [`LATE_WAKE`] past
    /// `armed`, the deadline it slept toward, or the process's watchdog found its own tick that
    /// late ([`LoopBeat::take_late_wake`]), with no wall-clock step: a frozen process (SIGSTOP,
    /// a long collection or VM pause), whose monotonic clock counted the freeze. It is a wake:
    /// the seed is PINGed again with a fresh answer window (the one a PING had before the freeze
    /// ran out while nobody could read the answer), held takes re-check at once, and a listening
    /// peer probes the members it would otherwise drop for the silence the freeze made
    /// ([`Actor::reprobe_after_freeze`]). One freeze is one wake.
    fn check_late_wake(&mut self, armed: Option<Instant>) {
        let now = Instant::now();
        let by_deadline =
            armed.map_or(Duration::ZERO, |armed| now.saturating_duration_since(armed));
        let late = by_deadline.max(self.beat.take_late_wake());
        if late <= LATE_WAKE
            || self
                .last_late_wake
                .is_some_and(|at| now.saturating_duration_since(at) < LATE_WAKE)
        {
            return;
        }
        self.last_late_wake = Some(now);
        bump(&mut self.counters.late_wakes);
        self.wakes
            .send_modify(|wakes| *wakes = wakes.wrapping_add(1));
        self.lower_housekeeping(now);
        if self.closed || self.joining {
            return;
        }
        tracing::info!(
            peer = %self.peer_id,
            late_ms = u64::try_from(late.as_millis()).unwrap_or(u64::MAX),
            "agentspaces: the loop woke late with no wall-clock step (a frozen process?); \
             re-asking the seed and re-probing the members"
        );
        self.reprobe_after_freeze(now);
        self.resume(
            now,
            true,
            i64::try_from(late.as_millis()).unwrap_or(i64::MAX),
        );
    }

    /// Reads (wall − monotonic) time and, when it moved by more than [`WALL_STEP`] since the
    /// last turn, takes it as a wall-clock step ([`Actor::on_wall_step`]); answers whether it
    /// did. Local periods run on the monotonic clock and never step; stamps, leases, and
    /// expiries stay on wall time.
    fn check_wall_step(&mut self) -> bool {
        let mono = i64::try_from(
            Instant::now()
                .saturating_duration_since(self.clock_base)
                .as_millis(),
        )
        .unwrap_or(i64::MAX);
        let offset = self.now().saturating_sub(mono);
        let last = self.wall_offset.replace(offset);
        if let Some(last) = last {
            let step = offset.saturating_sub(last);
            if step.unsigned_abs() > u64::try_from(WALL_STEP.as_millis()).unwrap_or(u64::MAX) {
                self.on_wall_step(step);
                return true;
            }
        }
        false
    }

    /// A wall-clock step of `step` milliseconds (SPEC v0.1.36 §9.5). The deadlines anchored to
    /// wall time (the watch sweep's lapses, a lapsed member on a listening peer) are asked again
    /// at once;
    /// a forward step longer than the [`KEEPALIVE_TTL`], such as a suspend, is a resume: the
    /// members judged this peer by the wall time that passed, so it re-introduces itself at once
    /// (its self-advertisement to the seed and to every member it holds a link to) and asks for a
    /// round, instead of waiting out its re-lease (the reference implementation sends its self
    /// advertisement to every member and probes each once; this peer runs no prober).
    fn on_wall_step(&mut self, step: i64) {
        bump(&mut self.counters.wall_steps);
        // Every held take re-checks its wall-time lease now (owner decision 5 of 2026-11-23).
        self.wakes
            .send_modify(|wakes| *wakes = wakes.wrapping_add(1));
        let now = Instant::now();
        self.lower_housekeeping(now);
        self.sweep_after_wall_step();
        let keepalive = i64::try_from(KEEPALIVE_TTL.as_millis()).unwrap_or(i64::MAX);
        if step <= keepalive || self.closed || self.joining {
            return;
        }
        tracing::info!(
            peer = %self.peer_id,
            step_ms = step,
            "agentspaces: the wall clock stepped forward past the keepalive (a suspend?); re-introducing"
        );
        self.resume(now, false, step);
    }

    /// A wake, from a suspend (a wall step) or a freeze (a late wake): this peer re-introduces
    /// itself, starts the redial table over, asks its seed under the wake rule (or redials at
    /// once with no link), and asks for its rounds now. `fresh_ping`: the PING already waiting,
    /// if any, is not adopted but sent again with a fresh answer window (a freeze ran its window
    /// out on the monotonic clock while nobody could read the answer; a suspend did not).
    fn resume(&mut self, now: Instant, fresh_ping: bool, away_ms: i64) {
        bump(&mut self.counters.resumes);
        self.reprobe_view(now, away_ms);
        if self.link.is_some() || self.hub.listening {
            self.introduce();
            self.flush_outbox();
        }
        // A wake starts the redial table over, whether or not the peer is linked now.
        self.redial_table.reset();
        if self.link.is_some() {
            // The link may have died while the host slept, with no FIN to tell: ask the seed now,
            // so a dead one is left within the answer window ([`seed_watch`]).
            if fresh_ping {
                self.seed_watch.reset();
            }
            let asked = self.counters.seed_pings;
            self.ask_seed();
            if self.counters.seed_pings > asked {
                bump(&mut self.counters.wake_pings);
            }
            // The PING in force (sent now, or already waiting) is the wake's: no answer within
            // the ping timeout fails over at once, however young the link.
            self.seed_watch.woke = self.seed_asked();
        } else if self.redial.is_some() {
            // A redial pausing between rounds (on the monotonic clock, which did not count the
            // sleep) dials again now rather than sitting out what is left of its pause.
            self.redial_now();
        }
        self.dial_rounds.note_activity();
        self.dial_rounds.bring_forward(now);
        self.note_hub_activity();
        self.bring_round_forward(now);
    }

    /// Merges a remote stamp into this peer's clock ([`Hlc::observe`]): only an acceptable stamp
    /// merges (SPEC §9: one whose logical counter is above 65536 never reaches the clock), with
    /// its physical part clamped one millisecond inside the drift ceiling.
    fn observe_stamp(&mut self, stamp: &str, now: i64) {
        self.hlc.observe(stamp, now);
    }

    // ------------------------------------------------------------------------- clocks

    fn now(&self) -> i64 {
        self.clock.now_ms()
    }

    /// A fresh stamp for an issuer (an agent id) that sorts after everything this peer has
    /// stamped or observed, as `wire.hlc_now(issuer)` does per node. The issuer's clock validates
    /// its node when it is first built (SPEC §9: a node never emits a stamp a receiver refuses
    /// for its node), so an agent id holding a control character or past the node bound is
    /// refused here, before anything is signed.
    fn issuer_stamp(&mut self, issuer: &str, now: i64) -> Result<String, PeerError> {
        let base = self.hlc.last();
        let clock = match self.issuer_clocks.entry(issuer.to_owned()) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(entry) => {
                let clock = Hlc::new(issuer).map_err(|error| {
                    PeerError::InvalidArgument(format!("{issuer} cannot stamp: {error}"))
                })?;
                entry.insert(clock)
            }
        };
        if let Some((physical, logical)) = base {
            clock.observe(&format!("{physical}:{logical}:{issuer}"), now);
        }
        Ok(clock.now(now))
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
        let link = self.open_link(channel, false);
        let id = link.id;
        self.relay_for_link(link.info.attested.as_deref(), &seed);
        let info = link.info.clone();
        tracing::debug!(peer = %self.peer_id, remote = %info.remote, "agentspaces: link up");
        self.link = Some(link);
        self.seed_watch.reset();
        self.current_seed = Some(seed);
        self.link_watch.send_replace(Some(info.clone()));
        self.emit(PeerEvent::Connected(info));
        id
    }

    /// Spawns `channel`'s reader and pump under a fresh link id and returns the link, not yet
    /// held anywhere. An `accepted` link reads within the smaller budget of accepted links and
    /// the budget they share.
    fn open_link(&mut self, channel: Channel, accepted: bool) -> Link {
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
        let heard = seed_watch::Heard::new(receiver.progress());
        let (own, shared_budget) = if accepted {
            (
                ACCEPTED_LINK_BUDGET_BYTES,
                Some(Arc::clone(&self.hub.inbound_budget)),
            )
        } else {
            (INBOUND_BUDGET_BYTES, None)
        };
        tokio::spawn(read_link(
            receiver,
            attested.clone(),
            id,
            self.inbound_tx.clone(),
            Budgets {
                own: Arc::new(Semaphore::new(own)),
                own_bytes: own,
                shared: shared_budget,
            },
            Arc::clone(&heard),
        ));
        let now = Instant::now();
        Link {
            id,
            info: LinkInfo {
                scheme,
                remote,
                attested,
            },
            queue: SendQueue { tx, shared },
            closer,
            hello_sent: false,
            up_at: now,
            heard_at: now,
            heard,
            owner: None,
            strangers: 0,
            backlog: VecDeque::new(),
            backlog_bytes: 0,
        }
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
    /// A link that held for a [`Settings::reconnect_interval`] (5 s by default) starts the redial
    /// table over and is redialed at once. Any other link is a quick drop and counts as a failed
    /// round: the redial first waits the next step of the redial table ([`redial`]). That covers a
    /// seed that accepts each connection and drops it (a `tls` seed dialed over `tcp`) and one
    /// that drops each link soon after speaking (an overloaded seed shedding links), so such a
    /// seed is redialed on the table, never in a loop. Only the link's life counts, not what it
    /// carried (owner decision 1 of 2026-11-23, the same rule in every client). The reconnect
    /// window runs from the loss of the last link that carried a verified frame.
    fn lose_link(&mut self) {
        self.lose_link_failing_over(false);
    }

    /// [`Actor::lose_link`]; `at_once` (the verdict on a wake's unanswered `PING`) redials at
    /// once from the table's start however young the link was.
    fn lose_link_failing_over(&mut self, at_once: bool) {
        let Some(link) = self.link.take() else {
            return;
        };
        self.seed_watch.reset();
        self.disarm_dial_rounds();
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
            let held = at_once
                || now.saturating_duration_since(link.up_at) >= self.settings.reconnect_interval;
            let pause = if held {
                self.redial_table.reset();
                Duration::ZERO
            } else {
                self.redial_table
                    .next_wait(self.settings.reconnect_interval)
            };
            self.start_redial(since.checked_add(self.settings.reconnect_window), pause);
        }
    }

    /// The seeds to redial after a lost link, in the order [`redial::dial_any`] starts them: the
    /// seeds in list order with the one just lost moved last, so the failover goes to another
    /// seed first (owner decision 2 of 2026-11-23, the same order in every client).
    fn candidate_seeds(&self) -> Vec<Seed> {
        match &self.current_seed {
            Some(current) if self.seeds.contains(current) => self
                .seeds
                .iter()
                .filter(|seed| *seed != current)
                .chain(std::iter::once(current))
                .cloned()
                .collect(),
            current if self.seeds.is_empty() => current.iter().cloned().collect(),
            _ => self.seeds.clone(),
        }
    }

    /// Starts a redial that waits `pause` before its first round and says the peer is
    /// unreachable at `deadline` (then once per window after), redialing on.
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
                table: self.redial_table.clone(),
                counts: Arc::clone(&self.dial_counts),
            },
        ));
        self.redial = Some(Redial { attempt, task });
    }

    /// Restarts the redial in progress with no pause before its first round, keeping its
    /// reconnect window (a wake from a suspend: [`Actor::on_wall_step`], which also starts the
    /// redial table over).
    fn redial_now(&mut self) {
        if self.closed || self.link.is_some() || self.redial.is_none() {
            return;
        }
        let since = *self.outage_since.get_or_insert_with(Instant::now);
        self.start_redial(
            since.checked_add(self.settings.reconnect_window),
            Duration::ZERO,
        );
    }

    fn on_inbound(&mut self, message: Inbound) {
        match message {
            Inbound::Frame {
                link,
                env,
                auth,
                budget,
                shared,
            } => {
                if self.is_current(link) {
                    // A verified frame: the far end speaks the protocol, so a later loss starts
                    // a new reconnect window. The redial table starts over only if the link then
                    // holds for an interval ([`Actor::lose_link`]).
                    self.outage_since = None;
                    bump(&mut self.counters.frames_received);
                    if self.handle(env, Some(auth), Via::Dialed).is_err() {
                        bump(&mut self.counters.malformed);
                    }
                } else if self.hub.accepted.contains_key(&link) {
                    self.on_accepted_frame(link, env, auth);
                }
                // The frame's bytes leave the link's inbound budget once it is handled.
                drop(budget);
                drop(shared);
            }
            Inbound::Malformed { link } => {
                if self.is_current(link) || self.hub.accepted.contains_key(&link) {
                    bump(&mut self.counters.malformed);
                }
            }
            Inbound::Relief { link } => {
                if self.is_current(link) {
                    if !self.joining {
                        self.flush_outbox();
                        self.flush_dialed_backlog();
                    }
                } else {
                    self.flush_backlog(link);
                }
            }
            Inbound::Lost { link } => {
                if self.is_current(link) {
                    self.lose_link();
                } else {
                    self.drop_accepted(link);
                }
            }
            Inbound::Accepted { channel } => self.accept_link(*channel),
            Inbound::Dialed {
                channel,
                seed,
                attempt,
            } => self.on_dialed(*channel, seed, attempt),
            Inbound::WindowLapsed { attempt } => {
                // The peer never gives up redialing (owner decision 3 of 2026-11-23, the lenient
                // retries of SPEC §9.4): a whole window without a link is said, and a join
                // waiting for its seed is answered, while the redial goes on.
                if self
                    .redial
                    .as_ref()
                    .is_some_and(|redial| redial.attempt == attempt)
                {
                    bump(&mut self.counters.windows_lapsed);
                    tracing::warn!(peer = %self.peer_id, "agentspaces: no working link within the reconnect window; still redialing");
                    for waiter in self.ready.drain(..) {
                        let _ = waiter.send(Err(PeerError::NotConnected));
                    }
                    self.emit(PeerEvent::Unreachable);
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
    /// before (packed, [`Actor::link_ready_pulls`]), send the writes made while there was no
    /// link, and (dial-only) arm the periodic rounds ([`rounds`]), whose first these pulls are.
    fn on_link_ready(&mut self) {
        self.introduce();
        // One packed pull of every stream, not one frame per space (a seed paces its answers).
        self.link_ready_pulls();
        self.flush_outbox();
        self.flush_dialed_backlog();
        self.arm_dial_rounds();
    }

    /// The re-lease is due: introduce again (which also re-arms it), and send any writes still
    /// waiting for room, should a relief have been missed.
    fn on_re_lease(&mut self) {
        self.last_lease = Instant::now();
        // The cadence runs with or without open spaces: expired advertisements leave the cache
        // even when none arrive (SPEC §6.2).
        let now = self.now();
        self.ads.expire(now);
        if !self.closed && !self.joining && (self.link.is_some() || self.hub.listening) {
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
        // A listening peer reaches a member on the link it introduced itself on, or through the
        // relay its advertisement declares when that relay holds a link here.
        if let Some((id, relay)) = self.accepted_route(to) {
            return match relay {
                None => self.send_accepted(id, kind, body, Some(to), budget),
                Some(relay) => {
                    let inner = self.signed_frame(kind, body, Some(to));
                    let outer = bodies::relay_frame_body(to, &inner, None, None);
                    self.send_accepted(id, KIND_RELAY_FRAME, &outer, Some(&relay), budget)?;
                    bump(&mut self.counters.relayed_out);
                    Ok(())
                }
            };
        }
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
        if self.hub.listening && !self.joining {
            // Every accepted link hears it at once; the dialed link (if any) below.
            self.publish_accepted(&body);
            if self.link.is_none() && self.seeds.is_empty() {
                return; // no seed to hold it for
            }
        }
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
        let payload = self.self_ad_payload(now);
        self.last_lease = Instant::now();
        let item_ms = now.max(self.last_intro_ms.saturating_add(1));
        self.last_intro_ms = item_ms;
        let item = format!("peer:{}:{item_ms}", self.peer_id);
        let body = bodies::rumor_body(STREAM_PEERS, &item, RUMOR_HOPS, &payload);
        if self.link.is_some() {
            let _ = self.send(KIND_RUMOR, &body, None);
            self.announce_channel();
        }
        // A listening peer refreshes its advertisement directly to each member it holds a link
        // to, unforwarded (SPEC §5.2).
        self.introduce_accepted(&item, &payload);
        self.hub.own_ad = Some(payload);
    }

    /// This peer's signed self-advertisement as of `now` (SPEC §5.2): its resource hints and, on
    /// a listening peer, the endpoints of its listeners and the RELAY role (SPEC §5.4). A peer
    /// that advertises endpoints is dialed directly, so it names no `relay.via`.
    fn self_ad_payload(&mut self, now: i64) -> Vec<u8> {
        let issued = self.self_ad_issue(now);
        let issued = time::instant_iso(issued);
        let mut hints = self.resource_hints.clone();
        if !self.hub.endpoints.is_empty() {
            hints.remove("relay.via");
        }
        let mut ad =
            wire_ads::peer_advertisement(&self.group, &self.identity, &issued, Some(&hints));
        if !self.hub.endpoints.is_empty() {
            let endpoints: Vec<Value> =
                self.hub.endpoints.iter().cloned().map(Value::Map).collect();
            ad.insert("endpoints", Value::Array(endpoints));
        }
        if self.hub.listening {
            ad.insert("roles", Value::Array(vec![Value::from(serve::ROLE_RELAY)]));
        }
        wire_ads::signed_peer_ad(&ad, &self.identity)
    }

    /// The issue instant of this peer's self-advertisement at `now`: the whole second, unless the
    /// last one was issued at or after it with other content (its hints, endpoints, or roles), then
    /// a millisecond after that one, so a member keeping the newest copy takes the change (SPEC
    /// v0.1.36 §9.5).
    fn self_ad_issue(&mut self, now: i64) -> i64 {
        let mut content = Map::new();
        content.insert("resourceHints", Value::Map(self.resource_hints.clone()));
        content.insert(
            "endpoints",
            Value::Array(self.hub.endpoints.iter().cloned().map(Value::Map).collect()),
        );
        content.insert("listening", self.hub.listening);
        let fingerprint = crypto::port().sha256(&cbor::encode(&Value::Map(content)));
        let whole = now.div_euclid(1000).saturating_mul(1000);
        let id = format!("peer:{}", self.peer_id);
        self.issues.next(&id, whole, fingerprint)
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
        let body = self.pull_body(streams);
        self.reset_continuations();
        if let Some(seed) = self.seed_peer.clone()
            && self.partner_audits(&seed)
        {
            self.note_budgeted_pull(&seed);
        }
        self.send(KIND_DIGEST, &body, None)
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
    /// revocation, the frame filter, on an accepted link the admission gate ([`Actor::gate`]),
    /// the clock, membership, then the kind. `via` says which link the frame came on, and so
    /// where an answer goes. An `Err` is a body that does not parse, counted as malformed by the
    /// caller; nothing here ends the reader.
    fn handle(&mut self, mut env: Map, auth: Option<Auth>, via: Via) -> Result<(), Malformed> {
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
        // Frames that arrive on (or through) an accepted link pass the admission gate before any
        // side effect, the clock merge included (SPEC §5.1).
        let gated = via.gate();
        if gated.is_none() && self.hub.settings.require_attestation {
            // SPEC §5.6's required attestation holds on the dialed link too: only the seed its
            // transport attested speaks there, and no relayed inner frame is taken.
            let attested = self
                .link
                .as_ref()
                .and_then(|link| link.info.attested.as_deref());
            let from = env.get("from").and_then(Value::as_str);
            if via.is_relayed() || attested.is_none() || attested != from {
                bump(&mut self.hub.counters.unattested_frames);
                return Ok(());
            }
        }
        if gated.is_none()
            && let Some(stamp) = env.get("stamp").and_then(Value::as_str)
        {
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
        if let Some(link) = gated {
            match self.gate(link, &sender, via) {
                serve::Gate::Member => {
                    if let Some(stamp) = env.get("stamp").and_then(Value::as_str) {
                        self.observe_stamp(stamp, now);
                    }
                }
                serve::Gate::Stranger => return self.on_stranger(link, sender, &kind, &body),
                serve::Gate::Drop => return Ok(()),
            }
        }
        if sender != self.peer_id {
            self.heard_from(&sender, via, to_us);
        }
        if let Via::Accepted(id) = via {
            // A member speaking on a link nobody introduced itself on yet (it came back on a new
            // one): the link is its, and it hears this peer's introduction there.
            self.bind_link(id, &sender);
        }
        match kind.as_str() {
            KIND_PING => {
                let nonce = bodies::parse_ping(&body).ok_or(Malformed)?;
                let ack = self.on_ping(&sender, &body, nonce);
                // Java answers `send(group, from, ACK)`: addressed to the prober, and back through
                // the relay when the PING came inside a RELAY_FRAME, else the seed takes an ACK it
                // never asked for and the prober evicts this peer.
                let _ = self.reply(via, KIND_ACK, &ack, &sender);
            }
            KIND_PING_REQ => {
                let (target, nonce) = bodies::parse_ping_req(&body).ok_or(Malformed)?;
                self.on_ping_req(sender, target, nonce);
            }
            KIND_ACK => {
                let nonce = bodies::parse_ack(&body).ok_or(Malformed)?;
                self.on_ack(&sender, nonce);
            }
            KIND_PIPE_DATA => self.on_pipe(sender, &body)?,
            KIND_RELAY_FRAME => return self.on_relay_frame(&body, via, &sender),
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
                        self.fetched(&cid);
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
            KIND_RUMOR => self.on_rumor(bodies::parse_rumor(&body).ok_or(Malformed)?, via)?,
            KIND_PULL_RESP => self.on_pull_resp_frame(&sender, &body, via)?,
            // A listening peer answers a DIGEST on any link. A dial-only one answers its seed's
            // own round whole (owner decision of 2026-11-23): a DIGEST read directly off its
            // dialed link from the seed, so its own rumors lost on that link are repaired when the
            // seed's round reaches it. A DIGEST a relay carried from another member is answered
            // only with this peer's displaced claims made here (owner decision 1 of
            // 2026-11-23, [`Actor::answer_displaced_digest`]); any other, and another member's
            // forwarded copy, draws no answer: no member but the seed can make this peer upload
            // anything else. Only a listening peer serves foundings.
            KIND_DIGEST
                if self.hub.listening
                    || (via == Via::Dialed && self.seed_peer.as_deref() == Some(&*sender)) =>
            {
                self.on_digest(&sender, &body, via)?;
            }
            KIND_DIGEST if via.is_relayed() => {
                if !self.answer_displaced_digest(&sender, &body, via)? {
                    self.ignore_kind(kind);
                }
            }
            KIND_GROUP_AD_WANT if self.hub.listening => {
                if let Some(link) = via.direct_link(self.link.as_ref().map(|link| link.id)) {
                    self.serve_founding(link, &sender);
                }
            }
            _ => self.ignore_kind(kind),
        }
        Ok(())
    }

    /// A verified frame is a member heard from, and (unless a relay carried it) one this peer's
    /// link reaches. The first frame the seed addresses to this peer names the seed: it is the
    /// relay this peer declares (`relay.via`), so the peer introduces itself again.
    fn heard_from(&mut self, sender: &str, via: Via, to_us: bool) {
        self.members.hear(sender);
        if via != Via::Dialed {
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
        // The answer, and the RELAY_FRAME around it when the seed carries it, on the link that
        // carries it: a member's accepted link (with nothing waiting in its backlog), else the
        // dialed one.
        let estimate = length.saturating_add(FRAME_OVERHEAD.saturating_mul(2));
        let room = match self.accepted_route(requester) {
            Some((id, _)) => self.accepted_has_room(id, estimate),
            None => self.has_room(estimate, Budget::Half),
        };
        if !room {
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
    /// when it is for this peer and not itself a relay. A dial-only peer forwards nothing; a
    /// listening one carries a frame for a member on to it ([`Actor::relay_onward`]).
    fn on_relay_frame(&mut self, body: &[u8], via: Via, sender: &str) -> Result<(), Malformed> {
        let relay = bodies::parse_relay_frame(body).ok_or(Malformed)?;
        if via.is_relayed() {
            return Ok(());
        }
        if relay.target != self.peer_id {
            if self.hub.listening {
                self.relay_onward(relay, sender);
            }
            return Ok(());
        }
        let inner = envelope::decode_frame(&relay.frame).ok_or(Malformed)?;
        if inner.get("kind").and_then(Value::as_str) == Some(KIND_RELAY_FRAME) {
            return Ok(());
        }
        bump(&mut self.counters.relayed_in);
        let outer = match via {
            Via::Accepted(id) => Some(id),
            _ => None,
        };
        self.handle(inner, None, Via::Relayed(outer))
    }

    /// A GROUP_AD (SPEC §9): taken only while a join by GroupID waits, and only when it passes
    /// the four checks of SPEC §5.1 and derives to exactly the wanted GroupID. Anything else is
    /// ignored, so a hostile seed can delay the join and never substitute a policy.
    fn on_group_ad(&mut self, body: &[u8]) -> Result<(), Malformed> {
        if !self.joining || self.closed {
            return Ok(());
        }
        let signed = Value::Map(bodies::decode_body(KIND_GROUP_AD, body).ok_or(Malformed)?);
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

    /// A RUMOR: its item handled by stream. A listening peer first drops a rumor it has seen
    /// (by stream and payload hash, SPEC §5.3), then forwards one that decoded and verified to
    /// its other links ([`Actor::forward_rumor`]).
    fn on_rumor(&mut self, rumor: Rumor, via: Via) -> Result<(), Malformed> {
        if rumor.payload.is_empty() {
            return Ok(());
        }
        let listening = self.hub.listening;
        if listening && !self.hub.seen.insert(&rumor.stream_id, &rumor.payload) {
            bump(&mut self.hub.counters.rumors_duplicate);
            return Ok(());
        }
        let verdict = self.rumor_item(&rumor);
        if listening {
            if rumor.stream_id != STREAM_PEERS {
                self.note_hub_activity();
            }
            if matches!(verdict, Ok(true)) {
                self.forward_rumor(&rumor, via);
            } else {
                bump(&mut self.hub.counters.rumors_unforwarded);
            }
        }
        verdict.map(|_| ())
    }

    /// Handles one rumor item by stream; `Ok(true)` when it decoded and verified, so a listening
    /// peer may forward it (an item of a stream this peer does not read is forwarded as it is).
    fn rumor_item(&mut self, rumor: &Rumor) -> Result<bool, Malformed> {
        let stream = rumor.stream_id.as_str();
        if revocation::STREAMS.contains(&stream) {
            let now = self.now();
            if self.registry.accept(stream, &rumor.payload, now) {
                self.dial_rounds.note_activity();
                // The revoked member's advertisements leave the cache now, as in Java.
                self.ads.purge(&self.registry);
                if stream == revocation::PEER_STREAM {
                    self.enforce_peer_revocations();
                } else {
                    self.enforce_credential_revocations();
                }
                return Ok(true);
            }
            Ok(serve::signed_revocation_verifies(&rumor.payload))
        } else if stream == STREAM_PEERS {
            Ok(self.accept_peer_ad(&rumor.payload))
        } else if stream == STREAM_ADS {
            let stored = agentspaces_wire::schema::decode(&rumor.payload, "AdCache.StoredAd")
                .ok_or(Malformed)?;
            Ok(self.accept_ad(&stored))
        } else if let Some(space) = space_name(stream) {
            // SPEC §9.1: a delta outside the wire encoding (a stamp that is no canonical stamp
            // item among them) is dropped whole, counted, and strikes nobody.
            let Some(delta) = records::decode_delta(&rumor.payload) else {
                bump(&mut self.counters.deltas_undecodable);
                return Ok(false);
            };
            self.replicate_space(space);
            let mut verified = true;
            // Claim before state: a completion authenticates against the holder's claim.
            let mut claim_folded = false;
            if let Some((entry_id, signed)) = &delta.claim {
                let outcome = self.fold_claim(space, entry_id, signed);
                claim_folded = outcome.is_some_and(|outcome| !outcome.is_refused());
                verified &= serve::forwardable(outcome);
            }
            if let Some(state) = delta.state {
                let outcome = self.fold_remote_state(space, &state);
                // A completion the claim held here displaces (SPEC §7.4, the settle guarantee).
                if claim_folded
                    && outcome.is_some_and(FoldOutcome::is_refused)
                    && let Some((entry_id, signed)) = &delta.claim
                {
                    self.note_outbid_completion(space, entry_id, signed, &state);
                }
                verified &= serve::forwardable(outcome);
            }
            Ok(verified)
        } else {
            Ok(true)
        }
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
            // Java reads the delta as `SignedRevocation[]` under the wire encoding (SPEC §9.1).
            match agentspaces_wire::schema::load_canonical(bytes) {
                Some(Value::Array(items)) => {
                    for signed in &items {
                        if self.registry.accept_signed(stream, signed, now) {
                            revoked_any = true;
                            revoked_peers |= stream == revocation::PEER_STREAM;
                        }
                    }
                }
                Some(Value::Null) => {}
                _ => malformed = true,
            }
        }
        if revoked_any {
            self.dial_rounds.note_activity();
            self.ads.purge(&self.registry);
        }
        if revoked_peers {
            self.enforce_peer_revocations();
        }
        if revoked_any {
            self.enforce_credential_revocations();
        }
        if let Some(bytes) = delta_of(STREAM_ADS) {
            match pulled_ads(bytes) {
                Some(stored) => stored.iter().for_each(|ad| {
                    self.accept_ad(ad);
                }),
                None => malformed = true,
            }
        }
        if !self.hub.listening {
            // A dial-only peer's pull of the membership view (SPEC §5.2; v0.1.21): each signed
            // advertisement its digest did not name is held as a forwarded copy on `peers` is.
            if let Some(payloads) =
                delta_of(serving::STREAM_VIEW).and_then(serving::parse_view_delta)
            {
                for payload in &payloads {
                    self.accept_peer_ad(payload);
                }
                // The view answered: a wake's re-probe ends, and what lapsed stays lapsed.
                self.end_view_reprobe();
            }
        }
        if self.hub.listening {
            // The membership view (SPEC §5.2): a copy of a member's advertisement refreshes a
            // member already admitted and admits nobody.
            if let Some(payloads) =
                delta_of(serving::STREAM_VIEW).and_then(serving::parse_view_delta)
            {
                for payload in &payloads {
                    self.accept_peer_ad(payload);
                }
            }
            // The view carries advertisements, which are liveness and never activity (SPEC §5.3,
            // the idle floor): a pull that brought nothing else leaves the rounds stretched.
            if deltas
                .iter()
                .any(|(stream, _)| stream.as_str() != Some(serving::STREAM_VIEW))
            {
                self.note_hub_activity();
            }
        }
        for (stream, delta) in &deltas {
            let (Some(stream), Some(bytes)) = (stream.as_str(), delta.as_bytes()) else {
                continue;
            };
            let Some(space) = space_name(stream).filter(|_| !bytes.is_empty()) else {
                continue;
            };
            match records::decode_sync_delta(bytes) {
                Some(sync) => {
                    let mut folded: HashSet<&str> = HashSet::new();
                    for (entry_id, signed) in &sync.claims {
                        if self
                            .fold_claim(space, entry_id, signed)
                            .is_some_and(|outcome| !outcome.is_refused())
                        {
                            folded.insert(entry_id.as_str());
                        }
                    }
                    for state in &sync.states {
                        let outcome = self.fold_remote_state(space, state);
                        // A completion the claim held here displaces (SPEC §7.4).
                        if outcome.is_some_and(FoldOutcome::is_refused)
                            && let Some(entry_id) = records::state_entry_id(state)
                            && folded.contains(entry_id)
                            && let Some((_, signed)) = sync
                                .claims
                                .iter()
                                .find(|(claimed, _)| claimed.as_str() == entry_id)
                        {
                            self.note_outbid_completion(space, entry_id, signed, state);
                        }
                    }
                }
                // Counted as an undecodable delta; the other streams still apply.
                None => bump(&mut self.counters.deltas_undecodable),
            }
        }
        if malformed { Err(Malformed) } else { Ok(()) }
    }

    /// Enforces the peer revocations held, as Java's `onPeerRevoked` does when one lands: every
    /// revoked PeerID leaves the member and reachable sets and the probes carried for it, a
    /// revoked seed stops being this peer's relay (`relay.via`), and a link to a revoked seed
    /// (the one it attested, or the one that addressed this peer) is closed so the peer fails
    /// over to another seed. Its frames are dropped from then on ([`Actor::handle`]).
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
        // A listening peer evicts every revoked member and closes its link (Java
        // `onPeerRevoked`).
        let revoked: Vec<String> = self
            .hub
            .admitted
            .keys()
            .filter(|peer| self.registry.peer_revoked(peer))
            .cloned()
            .collect();
        for peer in revoked {
            self.evict(&peer);
        }
    }

    /// A `peers` stream item: the signed advertisement, kept under its issuer when the signature
    /// and the derivation hold (`Peer._accept_peer_ad`) and, as Java's `verifiedPeerAd`,
    /// `admitAdvertisement`, and `hold` judge it: it names this group, has not expired, was issued
    /// no more than [`wire_ads::MAX_AD_ISSUED_SKEW_MILLIS`] ahead, its issuer is not revoked, and
    /// it is not older than the one held (the newest wins; an equal one replaces).
    ///
    /// Answers whether the advertisement verified for this group (a listening peer forwards only
    /// such). On a listening peer it also refreshes an admitted member's advertisement, whoever
    /// carried it; it admits nobody ([`Actor::admit`] does, from a newcomer's own introduction).
    fn accept_peer_ad(&mut self, payload: &[u8]) -> bool {
        let Some((ad, issuer)) = wire_ads::verify_signed_peer_ad(payload) else {
            return false;
        };
        if issuer == self.peer_id {
            return true; // this peer's own, echoed: verified, held nowhere
        }
        if self.registry.peer_revoked(&issuer)
            || ad.get("group").and_then(Value::as_str) != Some(self.group.as_str())
        {
            return false;
        }
        let now = self.now();
        let Some(issued) = issued_millis(&ad) else {
            return false;
        };
        let live = wire_ads::ad_expires_at_millis(&ad).is_some_and(|expires| expires > now);
        let ahead =
            i128::from(issued) > i128::from(now) + i128::from(wire_ads::MAX_AD_ISSUED_SKEW_MILLIS);
        if !live || ahead {
            return false;
        }
        if self
            .members
            .get(&issuer)
            .and_then(issued_millis)
            .is_some_and(|held| held > issued)
        {
            return true;
        }
        self.refresh_member(&issuer, &ad, payload, issued);
        self.members.hold_ad(issuer, ad, now);
        true
    }

    /// A stored advertisement from the `ads` stream or a pull (`Peer.accept_ad`); whether the
    /// cache admitted it (or holds a newer one of its issuer under its id).
    fn accept_ad(&mut self, stored: &Value) -> bool {
        let now = self.now();
        let Some(admitted) = self.ads.admit(stored, now, &self.registry) else {
            return false;
        };
        if admitted.changed {
            self.emit(PeerEvent::AdAccepted {
                ad_type: admitted.ad_type,
                id: admitted.id,
            });
        }
        true
    }

    /// Folds one state into space `space`, feeds the clock with its stamps when it applied, and
    /// tells the subscribers. A space this peer never opened is not folded into (counted in
    /// [`PeerCounters::unopened_space_items`]): remote data never opens a space.
    ///
    /// A fold that was not refused wakes the waiting reads and takes; one that applied derives
    /// the entry's transitions for the watches ([`Actor::after_state`]). Under `wire.ae=2` a
    /// state whose entry id holds a control character is dropped first, uncounted and
    /// unacknowledged (SPEC annex I.6); a verified state refused for its actor's revocation or its
    /// stamps is acknowledged in the space's digest (SPEC §7.3).
    fn fold_state(&mut self, space: &str, dto: &Map) -> Option<FoldOutcome> {
        let now = self.now();
        if !self.spaces.contains(space) {
            bump(&mut self.counters.unopened_space_items);
            return None;
        }
        let record = dto.get("record");
        let entry_id = agentspaces_wire::records::state_entry_id(dto)
            .unwrap_or_default()
            .to_owned();
        if self.drops_control_id(&entry_id) {
            return Some(FoldOutcome::Refused(Refusal::ControlId));
        }
        let slot = self.spaces.get_mut(space)?;
        let known = slot.store.state(&entry_id).is_some();
        let size = serve::state_size(dto);
        if !known && slot.bytes.saturating_add(size) > self.settings.space_max_bytes {
            // A new entry past the space's byte bound: refused as a full space is.
            bump(&mut self.counters.space_bytes_refused);
            let outcome = FoldOutcome::Refused(Refusal::Full);
            self.emit(PeerEvent::StateFolded {
                space: space.to_owned(),
                entry_id,
                outcome,
            });
            return Some(outcome);
        }
        let ctx = FoldContext::new(now, &self.registry).with_space(&slot.space_id);
        let outcome = slot.store.fold_state(dto, &ctx);
        if matches!(
            outcome,
            FoldOutcome::Refused(
                Refusal::Revoked | Refusal::StampLogical | Refusal::StampFarFuture
            )
        ) {
            self.acknowledge_refused_state(space, &entry_id, dto);
        }
        let Some(slot) = self.spaces.get_mut(space) else {
            return Some(outcome);
        };
        if outcome.is_applied() {
            let held = slot.sizes.insert(entry_id.clone(), size).unwrap_or(0);
            slot.bytes = slot.bytes.saturating_sub(held).saturating_add(size);
        }
        // A deferred state (SPEC §7.3) merged nothing: no lease to observe, no fold to wake on.
        let merged = matches!(outcome, FoldOutcome::Applied | FoldOutcome::Unchanged);
        if merged && let Some(span) = space_ops::state_lease_span(dto) {
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
        if merged {
            self.bump_folds();
        }
        if outcome.is_applied() {
            self.dial_rounds.note_activity();
            self.after_state(space, &entry_id, !known);
            if self.hub.listening {
                self.fetch_payload(space, &entry_id);
            }
        }
        Some(outcome)
    }

    /// Folds one signed claim into space `space` under `entry_id`, if this peer opened it. A
    /// fold that was not refused wakes the waiting reads and takes; a claim that won the lattice
    /// derives `Taken` for the watches ([`Actor::after_claim`]).
    fn fold_claim(&mut self, space: &str, entry_id: &str, signed: &Map) -> Option<FoldOutcome> {
        let now = self.now();
        if !self.spaces.contains(space) {
            bump(&mut self.counters.unopened_space_items);
            return None;
        }
        if self.drops_control_id(entry_id) {
            return Some(FoldOutcome::Refused(Refusal::ControlId));
        }
        let slot = self.spaces.get_mut(space)?;
        let before = slot.store.claim_proof(entry_id).cloned();
        let ctx = FoldContext::new(now, &self.registry).with_space(&slot.space_id);
        let outcome = slot.store.fold_claim(entry_id, signed, &ctx);
        if outcome == FoldOutcome::Refused(Refusal::Revoked) {
            // SPEC §9.2 R7: a revoked holder's claim is acknowledged with an `a:c:` line.
            self.acknowledge_refused_claim(space, entry_id, signed);
        }
        let slot = self.spaces.get_mut(space)?;
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
        if matches!(outcome, FoldOutcome::Applied | FoldOutcome::Unchanged) {
            self.bump_folds();
        }
        if outcome.is_applied() {
            self.dial_rounds.note_activity();
            self.after_claim(space, entry_id);
        }
        if matches!(outcome, FoldOutcome::Applied | FoldOutcome::Unchanged) {
            // SPEC v0.1.36 §7.4, *Pairing the evidence*.
            self.after_claim_merge(space, entry_id, before.as_ref(), signed);
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
        let mut reachable = self.reachable.clone();
        reachable.extend(self.hub.routes.keys().cloned());
        reachable.into_iter().collect()
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
            far_future: self.filter.far_future(),
            far_future_skewed: self.filter.far_future_skewed(),
            logical_refused: self.filter.logical_refused(),
        };
        counters.ads_refused_cache_full = self.ads.refused_cache_full();
        // What each open store counted, beside what the closed ones counted before they closed.
        for slot in self.spaces.iter() {
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
        counters.send_dropped = self.send_dropped.load(Ordering::Relaxed);
        counters.seed_dials = self.dial_counts.dials.load(Ordering::Relaxed);
        counters.late_seed_channels = self.dial_counts.late.load(Ordering::Relaxed);
        counters.listen = self.hub.counters.clone();
        counters.audit = self.audit.counters();
        counters.dial_rounds = self.dial_rounds.rounds();
        counters.dial_round_period_millis = self.dial_rounds.period_millis();
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
        if agentspaces_wire::trie::has_control(&entry_id) {
            // SPEC annex I.6: an id holding a control character is refused where it is built for
            // a write. A version 4 UUID never holds one; the check keeps the rule if ids change.
            return Err(PeerError::InvalidArgument(format!(
                "entry id {entry_id:?} holds a control character"
            )));
        }
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
        let issued = self.issuer_stamp(&issuer, now)?;
        let signed_at = agent
            .as_ref()
            .map(|agent| self.issuer_stamp(agent.agent_id(), now))
            .transpose()?;
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

    pub(super) fn space_horizon(&mut self, space: &str) -> Option<super::HorizonStatus> {
        let now = self.now();
        let rule = self.horizon_rule(space, now);
        let slot = self.spaces.get(space)?;
        Some(super::HorizonStatus {
            mode: slot.gate.mode(),
            rule,
            engagements: slot.gate.engagements(),
            settlements: slot.gate.settlements(),
            disengagements: slot.gate.disengagements(),
            max_lease_millis: slot.max_lease,
            acknowledged_lines: slot.store.acknowledged_count(),
        })
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
        // A changed card issued in the millisecond of the last one under its id is issued a
        // millisecond later, so its item id differs (SPEC v0.1.36 §9.5).
        let mut unissued = ad.clone();
        unissued.remove("issued");
        let fingerprint = crypto::port().sha256(&cbor::encode(&Value::Map(unissued)));
        let issued_at = self
            .issues
            .next(&format!("{ad_type}:{id}"), issued, fingerprint);
        let mut reissued;
        let ad = if issued_at == issued {
            ad
        } else {
            reissued = ad.clone();
            reissued.insert("issued", time::instant_iso(issued_at));
            &reissued
        };
        let item = format!("{id}:{issued_at}");
        // SPEC §6.1a.2: a dial-only member cannot see every member's AppCard level, so it writes
        // none of the gated fields (origin, formats, a host whose signOn is idp, spill).
        let (ad, downgraded) = wire_ads::app_card_at_level(ad_type, ad);
        if downgraded {
            bump(&mut self.counters.app_cards_downgraded);
        }
        let ad = &ad;
        self.note_card_size(ad_type, id, ad);
        let stored = Value::Map(wire_ads::stored_ad(ad_type, ad, &self.identity));
        let body = bodies::rumor_body(STREAM_ADS, &item, RUMOR_HOPS, &cbor::encode(&stored));
        fits_a_frame(&body)?;
        self.accept_ad(&stored);
        self.send_or_hold(body);
        Ok(())
    }

    /// SPEC §6.1a.5: a card whose encoding passes the spill threshold would travel as a stub,
    /// but only where a content swarm serves the group, which this peer does not run; it goes
    /// inline and counts (`cardsOversizeInline`). A card past 56 KiB logs a warning once per id
    /// and encoded size, so an operator sees a card approach the threshold.
    fn note_card_size(&mut self, ad_type: &str, id: &str, ad: &Map) {
        if ad_type != wire_ads::AD_TYPE_AGENT_CARD && ad_type != wire_ads::AD_TYPE_APP_CARD {
            return;
        }
        let size = cbor::encode(&Value::Map(ad.clone())).len();
        if size > CARD_SPILL_THRESHOLD_BYTES {
            bump(&mut self.counters.cards_oversize_inline);
        }
        if size > CARD_SPILL_WARN_BYTES && self.warned_cards.insert((id.to_owned(), size)) {
            tracing::warn!(
                card = %id,
                bytes = size,
                "agentspaces: a card approaches or passes the 65,536-byte spill threshold"
            );
            if self.warned_cards.len() > MAX_WARNED_CARDS {
                self.warned_cards.clear();
            }
        }
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

    /// Asks member `from` (and the seed) for a block by id; the answer is held among the fetched
    /// blocks and announced as [`PeerEvent::Block`] once it verifies.
    pub(super) fn fetch_block(&mut self, cid: &str, from: Option<&str>) -> Result<(), PeerError> {
        self.check_open()?;
        let now = Instant::now();
        if !self.block_asked.contains_key(cid) && self.block_asked.len() >= MAX_ASKED_BLOCKS {
            self.block_asked
                .retain(|_, asked| now.duration_since(*asked) < Duration::from_secs(60));
            if self.block_asked.len() >= MAX_ASKED_BLOCKS {
                return Err(PeerError::SendOverflow);
            }
        }
        self.block_asked.insert(cid.to_owned(), now);
        let mut targets: Vec<String> = from.map(str::to_owned).into_iter().collect();
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
        Ok(())
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
        self.stop_listening();
        self.disarm_dial_rounds();
        self.next_want = None;
        self.outbox.clear();
        self.clear_dialed_backlog();
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
        if std::thread::panicking() {
            self.beat.end(true);
        }
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

/// The resource hints a peer advertises, with `wire.ae=2` when it audits (SPEC annex I.6).
fn with_audit_level(mut hints: Map, audit: bool) -> Map {
    if audit && !hints.contains_key(agentspaces_wire::audit::HINT_AE) {
        hints.insert(
            agentspaces_wire::audit::HINT_AE,
            agentspaces_wire::audit::AE_LEVEL,
        );
    }
    hints
}

/// The resource hints a peer advertises, with `wire.horizon=1` when it keeps the renewal rule of
/// SPEC §7.2 and applies the per-entry horizon of §7.3.
fn with_horizon_level(mut hints: Map, horizon: bool) -> Map {
    if horizon && !hints.contains_key(agentspaces_wire::horizon::HINT_HORIZON) {
        hints.insert(
            agentspaces_wire::horizon::HINT_HORIZON,
            agentspaces_wire::horizon::HORIZON_LEVEL,
        );
    }
    hints
}

/// The resource hints a peer advertises, with the AppCard level it reads (SPEC §6.1a.2, §9:
/// `wire.appcard=2`, since this crate decodes the v0.1.32 schemas of the `AppCard` and the
/// `AgentCard` with their value rules) unless the configuration set the hint itself.
fn with_app_card_level(mut hints: Map) -> Map {
    if !hints.contains_key(wire_ads::HINT_APP_CARD) {
        hints.insert(
            wire_ads::HINT_APP_CARD,
            wire_ads::APP_CARD_LEVEL.to_string(),
        );
    }
    hints
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

/// The inbound byte budgets a link's reader draws on: its own, and (an accepted link) the one
/// all accepted links share.
struct Budgets {
    own: Arc<Semaphore>,
    /// The permits `own` was created with: no frame takes more.
    own_bytes: usize,
    shared: Option<Arc<Semaphore>>,
}

/// Drains a link, verifies each frame with the link's attestation, and forwards it to the actor
/// with its share of the link's budgets (one permit per byte); tells the actor when the link
/// ends. Once a budget is spent this task waits, so the transport stops reading. Each frame read
/// marks the link `heard` (the dead-seed rule, [`seed_watch`]).
async fn read_link(
    mut receiver: FrameReceiver,
    attested: Option<String>,
    link: u64,
    inbound: mpsc::Sender<Inbound>,
    budgets: Budgets,
    heard: Arc<seed_watch::Heard>,
) {
    while let Some(frame) = receiver.recv().await {
        heard.touch();
        let share = u32::try_from(frame.len().min(budgets.own_bytes)).unwrap_or(u32::MAX);
        let Ok(permit) = Arc::clone(&budgets.own).acquire_many_owned(share).await else {
            return;
        };
        let shared = match &budgets.shared {
            Some(shared) => match Arc::clone(shared).acquire_many_owned(share).await {
                Ok(permit) => Some(permit),
                Err(_) => return,
            },
            None => None,
        };
        let message = match envelope::decode_frame_detailed(&frame, attested.as_deref(), None) {
            Some((env, auth)) => Inbound::Frame {
                link,
                env,
                auth,
                budget: permit,
                shared,
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

/// Dials the seeds concurrently, the first to answer winning ([`redial::dial_any`], staggered
/// in list order); when none does, the error says how they failed ([`no_seed_accepted`]).
pub(super) async fn dial_first(
    seeds: &[Seed],
    dialers: &[Arc<dyn Dialer>],
    identity: &Identity,
    timeout: Duration,
    counts: &redial::DialCounts,
) -> Result<(Channel, Seed), PeerError> {
    let identity = Arc::new(identity.clone());
    let mut failures = Vec::new();
    redial::dial_any(seeds, dialers, &identity, timeout, &mut failures, counts)
        .await
        .ok_or_else(|| no_seed_accepted(&failures))
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

/// When a redial runs: its attempt number, when its window lapses (it redials on), how long it
/// waits before its first round, the peer's redial table, which paces the rounds after it, and
/// the dial counts it adds to.
struct Schedule {
    attempt: u64,
    deadline: Option<Instant>,
    pause: Duration,
    table: redial::RedialTable,
    counts: Arc<redial::DialCounts>,
}

/// After a lost link: waits the schedule's pause, then dials the candidates concurrently (in
/// list order with the seed just lost last, [`redial::dial_any`]) in rounds paced by the redial table until one accepts
/// or the deadline passes (`Peer._reconnect`, with the first round paced as `Actor::lose_link`
/// describes).
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
        mut deadline,
        pause,
        table,
        counts,
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
            // A whole window without a link: said once per window, and the redial goes on
            // (owner decision 3 of 2026-11-23: a peer never gives up redialing).
            if inbound
                .send(Inbound::WindowLapsed { attempt })
                .await
                .is_err()
            {
                return;
            }
            deadline = Instant::now().checked_add(settings.reconnect_window);
        }
        let mut failures = Vec::new();
        if let Some((channel, seed)) = redial::dial_any(
            &candidates,
            &dialers,
            &identity,
            settings.dial_timeout,
            &mut failures,
            &counts,
        )
        .await
        {
            let message = Inbound::Dialed {
                channel: Box::new(channel),
                seed,
                attempt,
            };
            if let Err(mpsc::error::SendError(Inbound::Dialed { channel, .. })) =
                inbound.send(message).await
            {
                channel.closer.close();
            }
            return;
        }
        tokio::time::sleep(table.next_wait(settings.reconnect_interval)).await;
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
            Budgets {
                own: Arc::new(Semaphore::new(BUDGET)),
                own_bytes: BUDGET,
                shared: None,
            },
            seed_watch::Heard::new(None),
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
    pub(super) fn test_actor() -> (
        Actor,
        broadcast::Receiver<PeerEvent>,
        mpsc::Receiver<Inbound>,
        watch::Receiver<Option<LinkInfo>>,
    ) {
        let (events, subscriber) = broadcast::channel(64);
        let (link_watch, link) = watch::channel(None);
        let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_QUEUE);
        let identity = Identity::generate().expect("identity");
        let start = Start {
            hlc: Hlc::new(identity.peer_id()).expect("a PeerID is a stamp node"),
            identity,
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
            listeners: Vec::new(),
            replicate: Vec::new(),
            dial_counts: Arc::default(),
            wakes: watch::channel(0).0,
        };
        (
            Actor::new(start, inbound_tx, &[]),
            subscriber,
            inbound_rx,
            link,
        )
    }

    /// A forward wall step longer than the keepalive (a suspend) re-introduces the peer at once
    /// on its link; a small step or a step back is counted and re-anchors the wall deadlines
    /// only (SPEC v0.1.36 §9.5).
    #[tokio::test(start_paused = true)]
    async fn a_suspend_re_introduces_at_once_and_a_small_step_does_not() {
        use crate::transport::memory;

        let (mut actor, ..) = test_actor();
        let clock = crate::clock::ManualClock::new(1_900_000_000_000);
        actor.clock = Arc::new(clock.clone());
        let (mine, mut theirs) = memory::pair("mem", "seed", "peer", None, None);
        actor.install_link(mine, Seed::new("127.0.0.1", 7000, "tcp"));
        actor.on_link_ready();
        async fn sent(rx: &mut crate::transport::FrameReceiver) -> Vec<Vec<u8>> {
            let mut frames = Vec::new();
            while let Ok(Some(frame)) =
                tokio::time::timeout(Duration::from_millis(1), rx.recv()).await
            {
                frames.push(frame);
            }
            frames
        }
        sent(&mut theirs.receiver).await;
        actor.check_wall_step();
        // A slew and a small step: nothing.
        clock.advance(900);
        actor.check_wall_step();
        assert_eq!(actor.counters.wall_steps, 0);
        // A step back of 5 s: counted, nothing sent.
        clock.advance(-5_000);
        actor.check_wall_step();
        assert_eq!((actor.counters.wall_steps, actor.counters.resumes), (1, 0));
        assert!(
            sent(&mut theirs.receiver).await.is_empty(),
            "nothing sent for a step back"
        );
        actor.check_wall_step();
        // A suspend of ten minutes (the monotonic clock did not move): a resume.
        let before = actor.last_intro_ms;
        clock.advance(600_000);
        actor.check_wall_step();
        assert_eq!((actor.counters.wall_steps, actor.counters.resumes), (2, 1));
        assert!(actor.last_intro_ms > before, "re-introduced at once");
        let frames = sent(&mut theirs.receiver).await;
        let kinds: Vec<String> = frames
            .iter()
            .filter_map(|frame| envelope::decode_frame(frame))
            .filter_map(|env| env.get("kind").and_then(Value::as_str).map(str::to_owned))
            .collect();
        assert!(kinds.iter().any(|kind| kind == KIND_RUMOR), "{kinds:?}");
    }

    /// A changed card published in the millisecond of the last one under its id is issued a
    /// millisecond later, under another item id (SPEC v0.1.36 §9.5); the same card again keeps
    /// its instant.
    #[tokio::test]
    async fn a_changed_card_in_the_same_millisecond_is_issued_a_millisecond_later() {
        let (mut actor, ..) = test_actor();
        let issued = 1_900_000_000_000i64;
        let card = |version: &str| {
            let mut ad = Map::new();
            ad.insert(
                "id",
                format!("aspace://{}/cap/test/{}", actor.group, actor.peer_id),
            );
            ad.insert("issuer", actor.peer_id.as_str());
            ad.insert("group", actor.group.as_str());
            ad.insert("issued", time::instant_iso(issued));
            ad.insert("ttl", "PT15M");
            ad.insert("capabilityType", "test");
            ad.insert("version", version);
            ad.insert("binding", "pipe");
            ad.insert("parameters", Value::Map(Map::new()));
            ad.insert("costHints", Value::Map(Map::new()));
            ad
        };
        let items = |actor: &mut Actor| -> Vec<String> {
            actor
                .outbox
                .drain(..)
                .filter_map(|body| bodies::parse_rumor(&body))
                .map(|rumor| rumor.item_id)
                .collect()
        };
        let (first, changed) = (card("0.1"), card("0.2"));
        actor
            .publish_ad(wire_ads::AD_TYPE_CAPABILITY, &first)
            .expect("publish");
        actor
            .publish_ad(wire_ads::AD_TYPE_CAPABILITY, &changed)
            .expect("publish");
        actor
            .publish_ad(wire_ads::AD_TYPE_CAPABILITY, &changed)
            .expect("publish");
        let items = items(&mut actor);
        let id = first.get("id").and_then(Value::as_str).unwrap_or_default();
        assert_eq!(
            items,
            vec![
                format!("{id}:{issued}"),
                format!("{id}:{}", issued + 1),
                format!("{id}:{}", issued + 1),
            ]
        );
    }

    /// A turn that panics is contained: the caller's reply is lost, the loop counts the panic,
    /// reads DEGRADED, and goes on serving (SPEC v0.1.36 §9.5, the watchdog's repeated-throw
    /// rule); its heartbeat shows a turn in hand while one runs.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_panicking_turn_is_contained_and_the_loop_goes_on() {
        use crate::group::GroupSpec;
        use crate::peer::{ListenerSpec, LoopStatus, Peer, PeerConfig};
        use crate::transport::memory::MemoryNetwork;

        let network = MemoryNetwork::new();
        let config = PeerConfig::new(
            Identity::generate().expect("identity"),
            GroupSpec::FoundingText("agentspaces-rust-watchdog".to_owned()),
        )
        .listen_on(ListenerSpec::bound(Arc::new(
            network.listen("127.0.0.1:7991"),
        )));
        let peer = Peer::start(config).await.expect("start");
        assert_eq!(peer.loop_health().status, LoopStatus::Up);
        let in_turn = peer
            .call(|actor| actor.beat.health().in_turn)
            .await
            .expect("call");
        assert!(in_turn, "a job runs inside a turn");
        let lost = peer
            .call(|_| -> u8 { panic!("a test panic inside one turn") })
            .await;
        assert!(matches!(lost, Err(PeerError::Closed)), "{lost:?}");
        // The loop goes on: the next call is answered, after the panic was counted.
        peer.call(|_| ()).await.expect("the loop still answers");
        let health = peer.loop_health();
        assert_eq!((health.panics, health.status), (1, LoopStatus::Degraded));
        assert!(health.turns >= 3);
        peer.close().await.expect("close");
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

    /// A burst to an accepted link whose far end stopped reading waits in the link's backlog,
    /// bounded by half the queue's bytes, and what the bound pushes out is counted; the actor
    /// never waits.
    #[tokio::test]
    async fn an_accepted_link_s_backlog_is_bounded_and_counts_what_it_drops() {
        use crate::transport::memory;

        let (mut actor, _events, _inbound, _link) = test_actor();
        let (mine, _theirs) = memory::pair("mem", "member", "hub", None, None);
        let link = actor.open_link(mine, true);
        let id = link.id;
        actor.hub.accepted.insert(id, link);
        let frame = vec![7u8; 16 * 1024];
        for _ in 0..200 {
            actor
                .offer_accepted(id, frame.clone(), Budget::Half)
                .expect("a burst frame is taken");
        }
        let (frames, bytes) = actor
            .hub
            .accepted
            .get(&id)
            .map(|link| (link.backlog.len(), link.backlog_bytes))
            .expect("the link is held");
        let bound = actor.settings.send_queue_bytes / 2;
        assert!(
            frames > 0 && bytes <= bound,
            "{frames} frames, {bytes} bytes"
        );
        assert!(actor.hub.counters.backlog_dropped > 0);
        assert!(matches!(
            actor.offer_accepted(id, vec![0u8; MAX_FRAME_BYTES + 1], Budget::Half),
            Err(PeerError::FrameTooLarge(_))
        ));
        actor.drop_accepted(id);
        assert!(actor.hub.accepted.is_empty());
        assert_eq!(actor.hub.counters.links_closed, 1);
    }

    /// A listening peer's forwards to its seed, while the seed's link has no room, wait within a
    /// bound of bytes (half the queue, as an accepted link's backlog), and never push this peer's
    /// own held writes out of the outbox: a member's flood of rumors pins no more of this peer's
    /// memory than one link's backlog, and costs it none of its own writes.
    #[tokio::test]
    async fn forwards_to_the_seed_wait_within_a_byte_bound_and_spare_own_writes() {
        use crate::transport::memory;

        let (mut actor, _events, _inbound, _link) = test_actor();
        actor.hub.listening = true;
        // The seed's end never reads: the link's queue fills and stays full.
        let (mine, _theirs) = memory::pair("mem", "seed", "peer", None, None);
        actor.install_link(mine, Seed::new("127.0.0.1", 7000, "tcp"));
        let own = bodies::rumor_body("space:own", "own-1", RUMOR_HOPS, b"own write");
        actor.outbox.push_back(own.clone());
        let payload = vec![7u8; 64 * 1024];
        for n in 0..1100 {
            let rumor = Rumor {
                stream_id: "junk".to_owned(),
                item_id: format!("j{n}"),
                hops_remaining: i64::from(RUMOR_HOPS),
                payload: payload.clone(),
            };
            actor.forward_rumor(&rumor, Via::Accepted(999));
        }
        assert!(
            actor.outbox.contains(&own),
            "a forwarded rumor pushed this peer's own write out"
        );
        let held = actor.pending_outbound();
        assert!(
            held <= actor.settings.send_queue_bytes.saturating_mul(2),
            "{held} bytes held for a link whose queue is {} bytes",
            actor.settings.send_queue_bytes
        );
        assert!(actor.hub.counters.backlog_dropped > 0);
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
                    table: redial::RedialTable::default(),
                    counts: Arc::default(),
                },
            ),
        )
        .await;
        assert!(finished.is_ok(), "the redial outlived its actor");
        assert_eq!(refusing.0.load(Ordering::SeqCst), 0);
    }

    /// SPEC §6.1a.2: the peer advertises the AppCard level it reads, unless configured
    /// otherwise, and, dial-only, publishes its own cards without the fields the level gates.
    #[tokio::test]
    async fn the_app_card_level_is_advertised_and_own_cards_carry_no_gated_field() {
        let hints = with_app_card_level(Map::new());
        assert_eq!(
            hints.get(wire_ads::HINT_APP_CARD).and_then(Value::as_str),
            Some("2")
        );
        let mut configured = Map::new();
        configured.insert(wire_ads::HINT_APP_CARD, "1");
        assert_eq!(
            with_app_card_level(configured)
                .get(wire_ads::HINT_APP_CARD)
                .and_then(Value::as_str),
            Some("1")
        );
        let (mut actor, _events, _inbound, _link) = test_actor();
        let now = actor.now();
        let issued = time::instant_iso(now.div_euclid(1000).saturating_mul(1000));
        let peer_id = actor.peer_id.clone();
        let id = format!("aspace://zGroup/app/{peer_id}/board");
        let origin = wire_ads::app_card_origin("console", "c/board", "", None).expect("origin");
        let card = wire_ads::AppCard {
            id: &id,
            issuer: &peer_id,
            group: "zGroup",
            issued: &issued,
            ttl: "PT15M",
            name: "board",
            origin: Some(&origin),
            formats: &["text/html"],
            ..wire_ads::AppCard::default()
        }
        .to_map()
        .expect("a card");
        actor
            .publish_ad(wire_ads::AD_TYPE_APP_CARD, &card)
            .expect("published");
        assert_eq!(actor.counters().app_cards_downgraded, 1);
        let held = actor
            .ads
            .live(wire_ads::AD_TYPE_APP_CARD, now, &actor.registry);
        assert_eq!(held.len(), 1);
        assert!(!held[0].contains_key("origin") && !held[0].contains_key("formats"));
    }

    #[test]
    fn ping_requests_parse_as_java_writes_them() {
        let request = |target: Value, nonce: Value| {
            let mut body = Map::new();
            body.insert("target", target);
            body.insert("nonce", nonce);
            cbor::encode(&Value::Map(body))
        };
        let parse_ping_req = bodies::parse_ping_req;
        assert_eq!(
            parse_ping_req(&request(Value::from("zTarget"), Value::from(42))),
            Some(("zTarget".to_owned(), 42))
        );
        // The primitive nonce is never null (SPEC §9.1 P4): such a body does not decode.
        assert_eq!(
            parse_ping_req(&request(Value::from("zTarget"), Value::Null)),
            None
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
