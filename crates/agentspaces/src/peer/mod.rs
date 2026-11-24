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

//! The fleet member: a [`Peer`] joins a group through a seed, stays a live member by answering
//! probes (back through the seed when a relay carried them), carrying the indirect probes
//! (PING_REQ) other members ask of it, and re-leasing its self-advertisement, folds replicated
//! state into the spaces it opened, verifies every signature, refuses every frame of a revoked
//! peer, and reconnects after a lost link. Started with listeners ([`ListenConfig`]) it is also a
//! listening member, a hub other members link to (see [Listening](#listening)); without any it is
//! dial-only (SPEC §5.4). The Python peer (`peer.py`) and the Ruby peer (`peer.rb`) are the
//! dial-only role's behavioural references, the TypeScript service host the listening role's; the
//! Java node is the authority.
//!
//! # Starting
//!
//! - [`Peer::join_from_env`]: from the `ASPACE_*` variables over the fleet YAML
//!   ([`crate::config`]), with the keystore's identity, the `tcp` and `tls` dialers, and the
//!   system clock; [`Peer::join_config`] from a [`Config`] resolved in code.
//! - [`Peer::join`] and [`Peer::join_as`]: the same from [`PeerSettings`] built in code.
//! - [`Peer::start`]: from a [`PeerConfig`] built by hand (other dialers, a manual clock, test
//!   timings, listeners) or with [`PeerConfig::from_settings`].
//! - [`Fleet::listen`](crate::space::Fleet::listen): a listening peer from a [`PeerConfig`] with
//!   listeners ([`PeerConfig::listen_on`]), wrapped for the Space API.
//!
//! # Listening
//!
//! A peer started with listeners ([`ListenerSpec::tcp`], [`ListenerSpec::tls`], or a listener the
//! caller bound) accepts links and serves the members on them as a hub, so Rust peers form a
//! group with no other implementation in it:
//!
//! - *Admission* (SPEC §5.1, §5.2): a newcomer introduces itself with its own signed
//!   advertisement; the group's membership policy decides (`OPEN`, or `INVITE` with a
//!   founder-issued or delegated credential, refused once revoked), and the hub answers with its
//!   own introduction and the live members' advertisements on that link. A third party's copy of
//!   an advertisement refreshes a member and admits nobody. Admissions are rate-limited and
//!   bounded ([`ListenConfig::max_members`]); with [`ListenConfig::require_attestation`] a link
//!   must attest its member (SPEC §5.6).
//! - *Gossip* (SPEC §5.3): a rumor one link brings is handled once (duplicates by stream and
//!   payload hash are dropped) and forwarded to the other links with its hop budget clamped to 6
//!   and decremented; the hub's own rumors go to every link.
//! - *Anti-entropy* (SPEC §5.3, §7, §9): DIGESTs are answered with PULL_RESPs in Java's formats
//!   for the view, the advertisements, the revocations, and every space the hub replicates (the
//!   configured ones and, by default, every space it hears of, bounded: see [`ListenConfig`]);
//!   the hub runs rounds of its own with members that run anti-entropy, backing off while idle.
//! - *Blocks*: the payload block of a replicated entry is fetched from its writer (or another
//!   member) with retries and backoff, and served to whoever asks, so a writer may leave once the
//!   hub holds it ([`Peer::probe_block`]).
//! - *Relay* (SPEC §5.4): a RELAY_FRAME for a member on one of the hub's links is delivered, in
//!   the one-hop and the path form; one for a stranger is refused and counted.
//! - *Founding* (SPEC §4.4, §5.1): a hub started with a signed founding document
//!   ([`crate::group::found_or_load`]) serves it as GROUP_AD, so `aspace://<group id>` joins work;
//!   a group known only from a founding text serves none.
//!
//! What it counts is in [`PeerCounters::listen`]. A full mesh, in which every member dials every
//! other, is not this role: the hub's members reach one another through it.
//!
//! [`PeerSettings`]: crate::config::PeerSettings
//! [`Config`]: crate::config::Config
//!
//! # Shape
//!
//! One Tokio task, the *actor*, owns every piece of mutable state: the frame filter, the hybrid
//! logical clock, the revocation registry, one [`SpaceStore`] per space (keyed by the local
//! SpaceID of `"<group>/<name>"`), the advertisement cache, the member and reachable sets, the
//! seed's PeerID once learned, and the counters. A [`Peer`] is a cheap, cloneable handle: each of
//! its calls is queued to the actor with a oneshot reply. Each link has two helper tasks: a
//! *reader* that drains the link, verifies each frame ([`decode_frame_detailed`] with the link's
//! attested PeerID) and forwards it to the actor, and a *pump* that writes the actor's outbound
//! frames to the link.
//!
//! # The actor never waits on a link
//!
//! A node that answers frames by sending (a probe's ACK, an introduction, a block) must never
//! wait for room on a link while it handles another frame: two nodes whose handlers each wait on
//! a send to the other stop for good, because neither drains the link the other writes to. The
//! Java node fixed this with its `FramePump`. Here the actor only *offers* a frame to the link's
//! pump queue, which is bounded by bytes ([`PeerConfig::send_queue_bytes`]) and never blocks; the
//! pump task is the only one that waits on the transport.
//!
//! - A full queue is not taken for a dead link: the actor may offer a burst faster than the
//!   pump drains even a healthy one. What comes in bursts uses half the queue at most: the
//!   writes waiting in the outbox go out in slices as the pump drains (it tells the actor when
//!   the queue is low again), and a block answer that does not fit is skipped and counted
//!   ([`PeerCounters::replies_skipped`]); the asker asks again. A frame that does not fit the
//!   whole queue is refused ([`PeerError::SendOverflow`], [`PeerCounters::send_refused`]) and
//!   the link stays up.
//! - A far end that stopped reading is one whose transport takes no frame for
//!   [`PeerConfig::send_stall_timeout`]: the pump closes the link and the stall is counted
//!   ([`PeerCounters::send_overflows`]), so the peer redials and re-introduces itself as after
//!   any lost link. Frames still queued are counted ([`PeerCounters::send_dropped`]); writes
//!   made meanwhile wait in a small outbox and go out after the re-introduction.
//! - A link holds at most its queue bound plus the transport's few frames
//!   ([`crate::transport::CHANNEL_QUEUE`]) outbound, and 64 MiB of verified frames waiting for
//!   the actor inbound (Java's `FramePump` cap); past that its reader waits, and the transport
//!   stops reading the socket.
//!
//! # Robustness
//!
//! Late, replayed, unknown, and malformed frames are the normal case on a network. A frame that
//! does not verify, or whose body does not parse, is counted ([`PeerCounters::malformed`]); a
//! verified frame is judged by the reader filter (its group, and `to` absent or this peer) and
//! then by the frame filter (stale, far ahead, replayed: dropped and counted in
//! [`PeerCounters::filter`]) before it has any effect; a kind this peer does not act on is
//! ignored and counted per kind. No frame ends the reader.
//!
//! [`decode_frame_detailed`]: crate::wire::envelope::decode_frame_detailed

mod actor;
mod ads;
mod blocks;
mod handle;
mod issue;
mod join;
mod listen;
mod members;
mod spaces;
mod watchdog;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use agentspaces_wire::cbor::Map;
use agentspaces_wire::fold::FoldOutcome;
use agentspaces_wire::identity::{Identity, IdentityError};
use agentspaces_wire::records::RecordError;
use agentspaces_wire::seed::Seed;

use crate::clock::{SharedClock, SystemClock};
use crate::config::ConfigError;
use crate::group::GroupSpec;
use crate::keystore::KeystoreError;
use crate::transport::{Dialer, TransportError};

pub use agentspaces_wire::bodies::RelaySignal;
pub use agentspaces_wire::fold::SpaceStore;
pub use handle::Peer;
pub use join::{default_dialers, settings_identity};
pub use listen::{AdmissionRefusals, ListenConfig, ListenCounters, ListenerSpec};
pub use watchdog::{LoopHealth, LoopStatus};

/// The agent name a peer writes under when no agent identity is given (`<peerId>/rust`), as the
/// Python peer writes under `python` and the Ruby peer under `ruby`.
pub const DEFAULT_AGENT_NAME: &str = "rust";

/// How often a join by GroupID asks the seed again for the founding advertisement while it waits
/// (the Ruby peer's schedule), so a seed that starts a moment after the joiner still answers.
pub const GROUP_AD_WANT_INTERVAL: Duration = Duration::from_secs(2);

/// How a [`Peer`] starts: who it is, what it joins, where it dials, and its timings.
#[derive(Debug, Clone)]
pub struct PeerConfig {
    /// This peer's identity: its key signs every frame, record, and advertisement.
    pub identity: Identity,
    /// The group to join: a founding text, a GroupID to join by id, or a founding document.
    pub group: GroupSpec,
    /// The seeds, dialed in order until one accepts; a lost link fails over to the next. A `tcp`
    /// or `tls` seed written with a host name is expanded to each of its addresses.
    pub seeds: Vec<Seed>,
    /// The dialers; a seed is dialed by the first dialer serving its scheme, and a seed no dialer
    /// serves is skipped.
    pub dialers: Vec<Arc<dyn Dialer>>,
    /// The wall clock for stamps, leases, and frame freshness.
    pub clock: SharedClock,
    /// The unit of the redial table (default 5 s). After a round of dials in which no seed
    /// answered, the next round waits 1, 2, 4, then 6 times this (5, 10, 20, 30 s by default),
    /// then 1 times it again, each wait spread at random by ±10 %. A link that held for this
    /// interval starts the table over when it is lost and is redialed at once, and so does a wake
    /// from a suspend with no link; a link lost within this interval of coming up is a quick drop
    /// and counts as a failed round, so a seed that sheds every link is redialed on the table.
    /// Each round dials its seeds concurrently, staggered 250 ms apart in list order with the seed
    /// just lost last, and the first to answer wins.
    pub reconnect_interval: Duration,
    /// How long a lost link may go without a working one before the peer says so (default
    /// 10 min): [`PeerEvent::Unreachable`], once per window, and a join waiting for its seed is
    /// answered [`PeerError::NotConnected`]. The peer never gives up redialing: it goes on, on
    /// the redial table, until it is closed, and a wake from a suspend redials at once however
    /// long the outage (owner decision 3 of 2026-11-23). The window runs from the loss of the
    /// last link that carried a verified frame, so links a seed accepts and drops without a word
    /// do not extend it.
    pub reconnect_window: Duration,
    /// How often the self-advertisement is re-leased (default 30 s; the advertisement's own TTL
    /// is 10 min).
    ///
    /// The re-lease is also this peer's keepalive with a Java seed, which drops a member it has not
    /// heard from for its member TTL: 30 s on a released 0.6.0 member, 45 s or more since SPEC
    /// v0.1.36, whose members still keep their own keepalive inside 30 s (§5.2). Once the group
    /// outgrows the seed's probe cycle (`(members + 1) × 1 s × 4 ≥ 30 s`, about seven members)
    /// probes no longer keep every member heard, so, as Java's `PeerNode.refreshIntervalMillis`
    /// does, the peer then re-leases at most every 15 s, half that 30 s keepalive bound. Keep this
    /// interval at most half the seed's member TTL when the seed runs a shorter one.
    pub peer_ad_interval: Duration,
    /// The bound on one dial (default 10 s).
    pub dial_timeout: Duration,
    /// How long a join by GroupID waits for a verified founding advertisement (default 10 s).
    pub join_timeout: Duration,
    /// The resource hints the self-advertisement carries (text to text, SPEC §5.1): a join
    /// credential under `aspace:join`, for example. The peer adds `relay.via` itself once it
    /// learns its seed's PeerID.
    pub resource_hints: Map,
    /// The group founder's PeerID when known from configuration: it roots the acceptance of peer
    /// revocations. A join by GroupID or a founding document supplies it from the verified
    /// founding.
    pub founder: Option<String>,
    /// The bytes of outbound frames a link may queue (default 16 MiB); a frame that does not fit
    /// is refused and the link stays up. Bursts (held writes, block answers) use half of it at
    /// most. The link holds at most this plus [`crate::transport::CHANNEL_QUEUE`] frames and the
    /// one being written. See the module docs.
    pub send_queue_bytes: usize,
    /// How long one frame may wait for the transport to take it before the far end counts as
    /// no longer reading and the link is closed and redialed (default 30 s). A link too slow
    /// to take one frame in this time counts as stalled too.
    pub send_stall_timeout: Duration,
    /// The most entries each space holds, live ones and the tombstones not yet collected alike
    /// (default [`DEFAULT_MAX_ENTRIES`](agentspaces_wire::fold::DEFAULT_MAX_ENTRIES), 65 536;
    /// claims are bounded the same, separately). Completed, withdrawn, and lapsed entries are
    /// collected past their horizon (SPEC §7.3, as Java collects them), so only entries alive at
    /// once count against it for long. A space at its bound refuses a further entry: a write
    /// answers [`SpaceError::Refused`](crate::space::SpaceError::Refused) with
    /// [`Refusal::Full`](agentspaces_wire::fold::Refusal::Full), and a received one is counted
    /// ([`PeerCounters::space_refused_inserts`]). At least 1.
    pub space_max_entries: usize,
    /// The bytes of payload blocks fetched for entries this peer read that it keeps (default
    /// 128 MiB); the oldest is evicted to make room, and a block larger than the whole budget is
    /// never kept (its entry stays unreadable here). The peer's own blocks have a budget of their
    /// own (256 MiB) and are never evicted; a block an entry pinned is released when the entry is
    /// collected.
    pub fetched_block_bytes: usize,
    /// The bytes of entry states each space holds (default 256 MiB, at least 1), counted as the
    /// encoded size of each entry's signed state; a new entry past it is refused as for
    /// [`PeerConfig::space_max_entries`] and counted ([`PeerCounters::space_bytes_refused`]).
    /// Payloads over the inline limit travel as blocks and count against the block budgets
    /// instead.
    pub space_max_bytes: usize,
    /// The listening role: listeners, required attestation, replicated spaces, bounds, and
    /// timers ([`ListenConfig`]). Without listeners the peer is dial-only.
    pub listen: ListenConfig,
    /// Whether the peer advertises `wire.ae=2` and repairs spaces by the trie audit of SPEC
    /// annex I.6 toward members whose current card carries it (default `true`). Off, the peer
    /// sends and reads today's digest forms only, and drops a body carrying an audit field.
    pub audit: bool,
    /// The bytes this peer asks a partner's answers to hold at most (`budget`, SPEC annex I.6;
    /// default 1 MiB, clamped to 4 KiB ..= 4 MiB).
    pub audit_budget: usize,
    /// Whether the peer advertises `wire.horizon=1` and lets its spaces collect a withdrawn
    /// entry by the per-entry horizon of SPEC §7.3 while every member in view advertises it too
    /// (default `true`). The hint promises that every renewal this peer makes keeps the rule of
    /// §7.2, which this crate always does, and that no identity this peer renews for is renewed
    /// from a second node at the same time: a deployment that runs one identity (one keystore)
    /// on two nodes at once turns this off. Off, every space keeps the legacy horizon.
    pub horizon: bool,
    /// The fully hinted rounds of anti-entropy the view must hold before the per-entry horizon
    /// engages (default 3, clamped to 1 ..= 64), each one gossip period of the founding, or of
    /// [`ListenConfig::anti_entropy_period`] when that is slower. It comes into force
    /// one longest lease plus five minutes after it engages.
    pub horizon_engage_rounds: u32,
}

impl PeerConfig {
    /// A configuration for `identity` joining `group` with no seeds and no dialers yet, the
    /// system clock, and the default timings.
    pub fn new(identity: Identity, group: GroupSpec) -> Self {
        Self {
            identity,
            group,
            seeds: Vec::new(),
            dialers: Vec::new(),
            clock: Arc::new(SystemClock),
            reconnect_interval: Duration::from_secs(5),
            reconnect_window: Duration::from_secs(600),
            peer_ad_interval: Duration::from_secs(30),
            dial_timeout: Duration::from_secs(10),
            join_timeout: Duration::from_secs(10),
            resource_hints: Map::new(),
            founder: None,
            send_queue_bytes: 16 * 1024 * 1024,
            send_stall_timeout: Duration::from_secs(30),
            space_max_entries: agentspaces_wire::fold::DEFAULT_MAX_ENTRIES,
            fetched_block_bytes: blocks::MAX_FETCHED_BLOCK_BYTES,
            space_max_bytes: DEFAULT_SPACE_MAX_BYTES,
            listen: ListenConfig::default(),
            audit: true,
            audit_budget: 1 << 20,
            horizon: true,
            horizon_engage_rounds: agentspaces_wire::horizon::DEFAULT_ENGAGE_ROUNDS,
        }
    }

    /// This configuration with one more listener ([`ListenConfig::listeners`]): the peer then
    /// accepts links and serves as a hub ([`Peer::start`]).
    #[must_use]
    pub fn listen_on(mut self, listener: ListenerSpec) -> Self {
        self.listen.listeners.push(listener);
        self
    }

    /// Whether the peer listens ([`ListenConfig::listeners`] is not empty).
    pub fn is_listening(&self) -> bool {
        !self.listen.listeners.is_empty()
    }
}

/// The default of [`PeerConfig::space_max_bytes`].
pub const DEFAULT_SPACE_MAX_BYTES: usize = 256 * 1024 * 1024;

/// Why a peer could not start, or a call could not be carried out.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PeerError {
    /// No seed was given, or none has a dialer for its scheme.
    #[error("no seeds to dial")]
    NoSeeds,
    /// Every seed refused (or some refused and some timed out); carries each seed and its
    /// failure.
    #[error("no seed accepted a connection: {0}")]
    NoSeedAccepted(String),
    /// Every seed's dial timed out; carries each seed and its failure.
    #[error("no seed answered in time: {0}")]
    DialTimedOut(String),
    /// A seed's channel certificate attested nobody where an attested seed is required (`tls`),
    /// and no seed accepted; carries each seed and its failure.
    #[error("no seed accepted a connection, and a seed was not attested: {0}")]
    SeedNotAttested(String),
    /// The group to join names no GroupID (an empty or malformed `aspace://` URI).
    #[error("not a GroupID or aspace:// URI: {0:?}")]
    InvalidGroup(String),
    /// A founding document does not pass the four checks of SPEC §5.1.
    #[error("the founding document does not verify")]
    InvalidFounding,
    /// A join by GroupID received no verified founding advertisement in time.
    #[error(
        "no verified GROUP_AD for {group} within {timeout:?}; a group started from a founding \
         text has no signed founding and cannot be joined by id"
    )]
    JoinTimeout {
        /// The GroupID wanted.
        group: String,
        /// The time waited.
        timeout: Duration,
    },
    /// The peer was closed.
    #[error("the peer is closed")]
    Closed,
    /// The peer has no link at the moment (it is redialing).
    #[error("the peer has no link to send on")]
    NotConnected,
    /// The link's send queue had no room for the frame: it was not sent, and the link stays up
    /// (a far end that stops reading is closed by the stall timeout instead,
    /// [`PeerConfig::send_stall_timeout`]).
    #[error("the link's send queue is full; the frame was not sent")]
    SendOverflow,
    /// A frame would exceed the wire's frame cap.
    #[error("a frame of {0} bytes exceeds the frame cap")]
    FrameTooLarge(usize),
    /// The agent (or its key) is revoked in this group.
    #[error("{0} is revoked in this group")]
    Revoked(String),
    /// The agent identity does not belong to this peer.
    #[error("{0} is not an agent of this peer")]
    ForeignAgent(String),
    /// An argument is out of range (a lease that is not positive, an advertisement without an
    /// `id` or `issued`, a tag that is not text to text).
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    /// This peer's own fold refused a state it built ([`Peer::write_entry`]): the space holds its
    /// bound of entries ([`Refusal::Full`](agentspaces_wire::fold::Refusal::Full),
    /// [`PeerConfig::space_max_entries`]), or the record is one no member would accept. Nothing
    /// was sent. The Space API answers it as
    /// [`SpaceError::Refused`](crate::space::SpaceError::Refused).
    #[error("the fold refused the state built for {entry_id}: {refusal}")]
    Refused {
        /// The entry's id.
        entry_id: String,
        /// The fold's reason.
        refusal: agentspaces_wire::fold::Refusal,
    },
    /// A record or state could not be signed.
    #[error(transparent)]
    Record(#[from] RecordError),
    /// An agent identity could not renew its certificate.
    #[error(transparent)]
    Identity(#[from] IdentityError),
    /// The random source failed.
    #[error("random source: {0}")]
    Random(String),
    /// The settings were refused before anything was dialed ([`Peer::join`],
    /// [`Peer::join_from_env`]).
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// The keystore could not be loaded or written ([`Peer::join`]).
    #[error(transparent)]
    Keystore(#[from] KeystoreError),
    /// A listener could not be bound ([`ListenConfig::listeners`]).
    #[error("cannot listen: {0}")]
    Listen(#[from] TransportError),
}

/// The link a peer currently holds: how it was opened and what its handshake proved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkInfo {
    /// The scheme dialed (`tcp`, `tls`, `mem`, ...).
    pub scheme: String,
    /// The remote address as dialed.
    pub remote: String,
    /// The PeerID the transport attested for the remote end, if any.
    pub attested: Option<String>,
}

/// How many frames the frame filter dropped, under the names of SPEC §9's counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct FilterCounters {
    /// Older than the frame age bound (`framesStale`).
    pub stale: u64,
    /// Past the far-future ceiling, skewed or not: `far_future` plus `far_future_skewed`.
    pub ahead: u64,
    /// A `(from, stamp)` pair already seen (`framesReplayed`).
    pub replayed: u64,
    /// Past `wall + MAX_DRIFT` by more than the 5-second skew margin (`framesFarFuture`).
    pub far_future: u64,
    /// Past `wall + MAX_DRIFT` by at most the skew margin (`framesFarFutureSkewed`).
    pub far_future_skewed: u64,
    /// A stamp whose logical counter is above 65536 (`framesLogicalRefused`).
    pub logical_refused: u64,
}

/// What a peer has counted: the frames it dropped and why, and the life of its links.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PeerCounters {
    /// Frames received on the link that verified (a seed or member that speaks the protocol):
    /// zero means nothing was heard from the seed yet, whatever the transport accepted.
    pub frames_received: u64,
    /// Frames that did not verify, or whose body did not parse.
    pub malformed: u64,
    /// Verified frames of a kind this peer does not act on, per kind (at most 64 kinds are named;
    /// the rest count under `"<other>"`).
    pub ignored_kinds: BTreeMap<String, u64>,
    /// The frame filter's drops.
    pub filter: FilterCounters,
    /// Frames accepted bare under the link's attestation (SPEC §5.6).
    pub attested_frames: u64,
    /// Frames accepted under a session tag.
    pub session_frames: u64,
    /// Links re-established after a loss.
    pub reconnects: u64,
    /// Reconnect windows that passed without a working link ([`PeerEvent::Unreachable`]); the
    /// peer redialed on through each.
    pub windows_lapsed: u64,
    /// Wall-clock steps of more than a second against the monotonic clock (an NTP step either
    /// way, or a suspend), seen between two turns of the peer's loop (SPEC v0.1.36 §9.5).
    pub wall_steps: u64,
    /// Wakes: forward wall-clock steps longer than the 30 s keepalive bound, such as a suspend,
    /// and late wakes ([`PeerCounters::late_wakes`]). Each re-introduced this peer at once rather
    /// than waiting out its re-lease, and asked its seed.
    pub resumes: u64,
    /// Late wakes: the peer's loop (or the process's watchdog) woke more than 30 s after its
    /// deadline with no wall-clock step, as a frozen process does (SIGSTOP, a long collection or
    /// VM pause), whose monotonic clock counted the freeze. Each is a wake as a suspend is (owner
    /// decision 3 of 2026-11-23): the seed is PINGed again with a fresh answer window, held takes
    /// are re-checked, and a listening peer probes the members it would otherwise drop for a
    /// silence that only the freeze made. Also counted in [`PeerCounters::resumes`].
    pub late_wakes: u64,
    /// Wakes after which a dial-only peer re-probed its view: it re-pulled the view naming only
    /// the cards still live, and kept each member whose card lapsed only while it was away in
    /// view (as lacking the horizon hint) until the answer or 11.25 s (owner decision 3 of
    /// 2026-11-23).
    pub view_reprobes: u64,
    /// PINGs this peer sent its seed because the dialed link was silent for 45 s, or on a wake
    /// from a suspend (the dead-seed rule, owner decision of 2026-11-23). The wake's share is
    /// also counted in [`PeerCounters::wake_pings`].
    pub seed_pings: u64,
    /// The [`PeerCounters::seed_pings`] sent on a wake with the link up (on a wall step's wake,
    /// none when a PING already waited for its answer: it became the wake's; a late wake always
    /// asks again, since the waiting PING's window ran out while the process was frozen).
    pub wake_pings: u64,
    /// Seed dials started: the join's first round and every redial round, one per seed dialed
    /// (owner decision 4 of 2026-11-23: one set of counter names in every client).
    pub seed_dials: u64,
    /// Channels that answered after another seed of the same round had won, closed unused.
    pub late_seed_channels: u64,
    /// Dialed links closed because the seed stayed silent for the 2 s ping timeout after such a
    /// PING (no frame, and no byte of one still arriving): the peer took
    /// the seed as lost and redialed, another seed first.
    pub links_silent: u64,
    /// Links closed because the far end stopped reading: a frame waited longer than
    /// [`PeerConfig::send_stall_timeout`] for the transport.
    pub send_overflows: u64,
    /// Frames refused because a link's send queue had no room for them; the link stayed up.
    pub send_refused: u64,
    /// Frames a link's pump discarded unwritten because the link closed (or stalled) first.
    pub send_dropped: u64,
    /// Block answers not sent: the link's queue was more than half full, or the same member
    /// asked for the same block within a second. The asker asks again.
    pub replies_skipped: u64,
    /// Block answers queued to members that asked.
    pub blocks_served: u64,
    /// Held blocks that could not be served because their answer exceeds the frame cap.
    pub blocks_unsendable: u64,
    /// Frames dropped because their sender's PeerID is revoked in this group.
    pub revoked_frames: u64,
    /// States and claims received for a space this peer never opened (pulled or written); not
    /// folded.
    pub unopened_space_items: u64,
    /// Indirect probes (PING_REQ) this peer carried to their target for another member.
    pub pings_relayed: u64,
    /// Frames this peer sent through its seed as a relay (RELAY_FRAME).
    pub relayed_out: u64,
    /// Frames that reached this peer inside a RELAY_FRAME.
    pub relayed_in: u64,
    /// Writes dropped from the outbox, which holds 1024 while the peer has no link or no room.
    pub outbox_dropped: u64,
    /// Entry transitions a watch never heard of because their payload block had not arrived
    /// while more than 4096 others waited for theirs (the oldest are dropped).
    pub deferred_events_dropped: u64,
    /// States and claims (received or this peer's own) a space refused because it already held
    /// its bound of entries ([`PeerConfig::space_max_entries`]), over every space.
    pub space_refused_inserts: u64,
    /// Entries collected from the spaces: completed, withdrawn, or lapsed past their horizon
    /// (SPEC §7.3), with their claims; and lapsed claims of entries this peer holds no state of.
    pub space_collected: u64,
    /// Received states refused at the door because they were already past the collection
    /// horizon: a member re-offering a tombstone this peer collects (SPEC §7.3).
    pub space_reoffers_refused: u64,
    /// Door refusals acknowledged in the space's digest (`collectedReoffersAcknowledged`, SPEC
    /// §7.3): the entry held no state here and the refused state verified. A refusal of a line
    /// already acknowledged only renews its hold.
    pub reoffers_acknowledged: u64,
    /// Renewals (of a write, a take, or a subscription) asked for less than the lease had left,
    /// which kept the longer lease (`renewShortenings`, SPEC §7.2).
    pub renew_shortenings: u64,
    /// Takes here whose claim won the lattice after a holder it displaced had completed the
    /// entry: each acknowledged that completion under its own claim, with no result, instead of
    /// doing the work again (SPEC §7.4, the settle guarantee). The take came back empty, or its
    /// completion failed with [`SpaceError::CompletedByDisplaced`].
    ///
    /// [`SpaceError::CompletedByDisplaced`]: crate::space::SpaceError::CompletedByDisplaced
    pub outbid_acknowledged: u64,
    /// Entries one of this peer's holders completed with its own work whose displaced rival's
    /// authentic completion arrived afterwards (`duplicateCompletions`, SPEC §7.4): both did the
    /// work, which a claim delivered later than the settle window allows. The shared state keeps
    /// one completion; this counts the duplicate once per entry, at the replica whose claim won.
    pub duplicate_completions: u64,
    /// Offers this peer made again of a displaced claim of its own completion (Java
    /// `displacedReoffers`, SPEC v0.1.36 §7.4): a better claim displaced the claim one of its
    /// holders completed under, so the winner's replica needs that claim to recognize the
    /// completion; offered at once, then no sooner than 1 s, 2 s, 4 s, ... after the previous
    /// offer, at most six times, and only while a frame still shows the entry open.
    pub displaced_reoffers: u64,
    /// Targeted anti-entropy rounds this peer opened toward holders a claim of its own holders
    /// displaced, while that take was open (Java `displacedPullRounds`, owner decision 4 of
    /// 2026-11-23): at once, then after 1, 2, 4, 8 and 16 s, at most six per entry, so the
    /// displaced holder's completion reaches this peer within one round.
    pub displaced_pull_rounds: u64,
    /// `DIGEST`s a relay carried to this dial-only peer from a member other than its seed,
    /// answered with only the claims made here that a better claim displaced, with or without
    /// their completions, in the spaces they name: a `want` for an opening, or a PULL_RESP for
    /// text digests (owner decision 1 of 2026-11-23): the winner of a contested take learns the displaced
    /// holder's completion from its targeted round (Java `displacedDigestAnswers`).
    pub displaced_digest_answers: u64,
    /// Such `DIGEST`s left unanswered because the asker's own answer bucket (16 at once, 4 a
    /// second, per asker as in every client) was spent (`relayedAnswersPaced`).
    pub relayed_answers_paced: u64,
    /// Space deltas and pulled sync deltas that did not decode under the wire encoding (SPEC
    /// §9.1), a stamp outside the canonical grammar included (`deltasUndecodable`). Each is
    /// dropped whole and strikes nobody.
    pub deltas_undecodable: u64,
    /// Distinct verified states and claims refused for a stamp whose logical counter is above
    /// 65536 (`stampsLogicalRefused`, SPEC §7.3, §7.4), over every space.
    pub stamps_logical_refused: u64,
    /// Distinct verified states and claims refused for a stamp more than an hour past the
    /// far-future margin (`stampsFarFutureRefused`).
    pub stamps_far_future_refused: u64,
    /// Distinct verified states and claims deferred for a stamp past the far-future margin
    /// (`stampsFarFutureDeferred`): no misbehavior, a skewed or dragged peer.
    pub stamps_far_future_deferred: u64,
    /// Advertisements the cache refused under its entry bound or its byte budget
    /// (`adsRefusedCacheFull`, SPEC §6.3).
    pub ads_refused_cache_full: u64,
    /// Cards this peer published without a field the AppCard level gates (`appCardsDowngraded`,
    /// SPEC §6.1a.2): a dial-only member cannot see every member's hint, so it writes none.
    pub app_cards_downgraded: u64,
    /// Cards this peer published inline although their encoding passes the spill threshold of
    /// 65,536 bytes (`cardsOversizeInline`, SPEC §6.1a.5): this peer runs no content swarm, so it
    /// never spills.
    pub cards_oversize_inline: u64,
    /// New entries a space refused because its states held [`PeerConfig::space_max_bytes`]
    /// bytes, received or this peer's own, over every space.
    pub space_bytes_refused: u64,
    /// Periodic anti-entropy rounds this peer ran toward its seed as a dial-only peer (SPEC
    /// §5.3); a listening peer counts its rounds in [`ListenCounters::rounds`].
    pub dial_rounds: u64,
    /// The period of a dial-only peer's next round, milliseconds (a gauge): the base period
    /// after activity, doubled per idle round up to 32 times it.
    pub dial_round_period_millis: u64,
    /// What the listening role counted (all zero on a dial-only peer).
    pub listen: ListenCounters,
    /// What the trie audit of SPEC annex I.6 counted.
    pub audit: AuditCounters,
}

/// Where one space stands on the collection rule of SPEC §7.3 ([`Peer::space_horizon`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct HorizonStatus {
    /// The per-entry horizon's mode: `Legacy` while this peer or a member in view lacks
    /// `wire.horizon=1`, `Waiting` while it counts the fully hinted rounds, `Settling` for one
    /// longest lease plus five minutes after it engaged, then `PerEntry`.
    pub mode: agentspaces_wire::horizon::Mode,
    /// The rule the space applies now.
    pub rule: agentspaces_wire::horizon::Rule,
    /// How many times the per-entry horizon engaged.
    pub engagements: u64,
    /// How many times it came into force.
    pub settlements: u64,
    /// How many times a member without the hint disengaged it from settling or in force.
    pub disengagements: u64,
    /// The longest lease the space has observed, milliseconds (capped at 24 hours).
    pub max_lease_millis: i64,
    /// The lines the space acknowledges in its digest now (at most 8192).
    pub acknowledged_lines: usize,
}

/// What the trie audit of SPEC annex I.6 counted ([`PeerCounters::audit`]); the counters only
/// grow, the gauges say what holds now.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuditCounters {
    /// Rounds this peer opened by the audit (`hashes` toward a member on `wire.ae=2`).
    pub openings_sent: u64,
    /// Openings this peer answered with a root or a `want`.
    pub openings_answered: u64,
    /// Roots this peer answered.
    pub roots_answered: u64,
    /// Sessions this peer opened as the partner.
    pub sessions_opened: u64,
    /// Sessions open now (a gauge).
    pub open_sessions: u64,
    /// Request bodies this peer answered within a session.
    pub requests_answered: u64,
    /// Nodes those answers carried.
    pub nodes_answered: u64,
    /// Request bodies this peer sent as the asker.
    pub requests_sent: u64,
    /// Root answers this peer accepted as the asker.
    pub roots_received: u64,
    /// Answer nodes this peer accepted as the asker.
    pub answers_received: u64,
    /// Entry ids asked for in fetch bodies, each ask counted.
    pub ids_requested: u64,
    /// Fetch bodies this peer answered.
    pub fetches_answered: u64,
    /// Ids a budget-cut answer left out that went to the same partner at once.
    pub fetch_continued: u64,
    /// Ids queued again for another member (not sent, or the answer did not come).
    pub fetch_requeued: u64,
    /// Fetch bodies whose answer did not come within the wait.
    pub fetch_timed_out: u64,
    /// Ids every member in view left out, kept for an audit to name again.
    pub fetch_parked: u64,
    /// Ids the fetch queue's bound turned away.
    pub fetch_queue_full: u64,
    /// Ids wanted now (a gauge).
    pub fetch_queued: u64,
    /// Budgeted `PULL_RESP`s this peer sent.
    pub budgeted_answers: u64,
    /// States partners counted as left out for the budget in their answers.
    pub remainder_received: u64,
    /// Budgeted pulls continued at once after a remainder.
    pub pulls_continued: u64,
    /// Audited slots derived from a space's store into its trie: each store change and each
    /// write lease that lapses derives its own entry's slot again, and only a space's first
    /// audit (or a store that replaced it) derives them all.
    pub slots_derived: u64,
    /// Refusals and fallbacks by key (`undecodable`, `lacks-hint`, `request-without-session`,
    /// `session-busy`, `session-cooling`, `session-capped`, `unsolicited-answer`,
    /// `fingerprint-mismatch`, `shape-mismatch`, `descent-capped`, `repeated-request`,
    /// `text-fallback`).
    pub refusals: BTreeMap<String, u64>,
}

impl PeerCounters {
    /// The total of [`PeerCounters::ignored_kinds`].
    pub fn ignored_total(&self) -> u64 {
        self.ignored_kinds.values().sum()
    }
}

/// What a peer tells its subscribers ([`Peer::subscribe`]).
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum PeerEvent {
    /// A link is up (the first one, or one redialed).
    Connected(LinkInfo),
    /// The link was lost (or closed).
    Disconnected,
    /// After a lost link, a new one is up and the peer has re-introduced itself and re-pulled
    /// what it had pulled.
    Reconnected {
        /// How many reconnects so far.
        reconnects: u64,
    },
    /// Not sent since 0.7.0: a peer never gives up redialing (owner decision 3 of 2026-11-23),
    /// and a whole reconnect window without a link is [`PeerEvent::Unreachable`]. Kept for one
    /// release so matches on it still compile.
    GaveUp,
    /// A whole reconnect window passed without a working link (one that carried a verified
    /// frame): a join waiting for its seed is answered [`PeerError::NotConnected`], and the peer
    /// goes on redialing on its table until it is closed. Said once per window.
    Unreachable,
    /// A received or written state was folded (or refused) into a space.
    StateFolded {
        /// The space name.
        space: String,
        /// The entry id (empty when the state named none).
        entry_id: String,
        /// What the fold did.
        outcome: FoldOutcome,
    },
    /// A take claim won the lattice for an entry.
    ClaimFolded {
        /// The space name.
        space: String,
        /// The entry id.
        entry_id: String,
    },
    /// A verified advertisement entered the cache (new, or newer than the one held).
    AdAccepted {
        /// Its type tag.
        ad_type: String,
        /// Its id.
        id: String,
    },
    /// A capability frame (PIPE_DATA) addressed to this peer.
    Pipe {
        /// The sending member.
        from: String,
        /// The capability.
        capability: String,
        /// The payload.
        payload: Vec<u8>,
    },
    /// A block this peer asked for arrived and verified.
    Block {
        /// The block's id.
        cid: String,
    },
    /// A member answered [`Peer::probe_block`] with the block, verified: it holds it, so the
    /// members can fetch it from there once this peer is gone.
    BlockHeld {
        /// The block's id.
        cid: String,
        /// The member that holds it.
        by: String,
    },
    /// A listening peer admitted a member from its own introduction on an accepted link.
    Admitted {
        /// The member's PeerID.
        peer: String,
    },
}
