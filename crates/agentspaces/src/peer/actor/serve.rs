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

//! The listening role on the actor (SPEC §5.1 to §5.4): the accepted links, admission, gossip
//! forwarding, the anti-entropy server and this peer's own rounds, relaying, and fetching the
//! payload blocks of replicated entries. A dial-only peer holds an inert [`Hub`].
//!
//! # Links
//!
//! Inbound, an accepted link may have at most 16 MiB of verified frames waiting for the actor,
//! and all accepted links together 256 MiB; past either its reader waits and its transport stops
//! reading, so neither one member nor many links can make the actor's inbox grow without bound.
//!
//! Each accepted link has its own pump queue, bounded by bytes like the dialed link's, and a
//! backlog for bursts (forwarded rumors, relayed frames, pull answers) that do not fit half the
//! queue: at most half the queue's bytes and [`BACKLOG_FRAMES`] frames, the oldest dropped and
//! counted past either, sent as the pump drains. The actor never waits on a link. A link is owned
//! by the member that introduced itself on it (or first spoke on it), and a member owns at most
//! [`MAX_MEMBER_LINKS`] (the oldest of its others closes past it); addressed frames for that
//! member go to the newest link it owns (the one heard last among the others it owns, when that
//! one closes), and frames for a member whose advertisement names a relay (`relay.via`) holding a link here go
//! to that relay inside a RELAY_FRAME. A link that introduces nobody within the introduction
//! timeout, or stays silent past the idle timeout, is closed; members heard only on a closed link
//! stop being reachable.
//!
//! # Admission (SPEC §5.1, §5.2)
//!
//! A frame on an accepted link from a peer that is not an admitted member may only be a PING
//! (answered on the link), a GROUP_AD_WANT (answered with the founding this peer verified, never
//! for a group founded from text), a CHANNEL_HELLO (ignored: this peer signs every frame), or an
//! introduction: a `peers` RUMOR carrying the sender's own signed advertisement; anything else is
//! dropped and counted. Every stranger frame, of whatever kind, counts against its link: past 64
//! a link nobody introduced itself on is closed, and one a member owns drops them. Only an
//! admission spends the admission bucket ([`super::super::ListenConfig::admission_burst`]), so a
//! stranger's flood starves no newcomer. An introduction admits its sender when the
//! advertisement verifies, names this group, lives, and is not revoked, and the group's policy
//! admits it: `OPEN` every verified peer; `INVITE` a founder-issued or delegated credential under
//! `aspace:join` in the wire encoding of its record, verified with public data against the
//! founding and refused once it (or its delegation) is revoked; `POLICY` nobody, since no
//! validator runs here; and nobody at all while a join by GroupID still waits for the founding
//! it would admit under. A member admitted under a delegation that has since expired is
//! re-admitted under the same credential, as SPEC §5.1 requires (held in memory, not across
//! restarts). The newcomer gets this peer's own introduction on the same link at once, then the
//! advertisements of the live members (each directly, unforwarded), and its introduction goes on
//! to the other links. A newcomer that runs anti-entropy itself (its first DIGEST names the `view`
//! stream, as a Java member's does at once) also gets a targeted round from this peer; a
//! dial-only newcomer, which answers no DIGEST, pulls what it needs instead. A copy of an advertisement that a third party carries refreshes a member already
//! admitted and admits nobody. Members are bounded; one whose advertisement lapsed while no link
//! carries it is dropped. An evicted member (a revoked credential, delegation, or PeerID) loses
//! every link it owns.
//!
//! # Gossip and anti-entropy (SPEC §5.3, §7, §9)
//!
//! A rumor seen before (by stream and payload hash, in a bounded memory) is dropped. Any other is
//! handled, then forwarded to every other member (once each, on the link its addressed frames
//! take) with its hop budget clamped to 6 and decremented, unless it did not decode or verify;
//! this peer's own rumors go to every member the same way. A DIGEST is
//! answered with the PULL_RESP frames of what the asker lacks, in Java's formats
//! ([`agentspaces_wire::serving`]), the revocations first, a space's claims before its states,
//! split into frames of at most [`PULL_CHUNK_BYTES`] and cut short past half the link's queue,
//! the bound of the backlog that may hold it, so a busy link never drops the head of an answer
//! (the next pull of that asker resumes where the cut fell). Each member's DIGESTs are paced. This
//! peer runs its own rounds with members that run anti-entropy themselves (they send DIGESTs
//! naming the `view` stream) and with its seed: every period, doubled per idle round up to 32
//! times, and a targeted one with each such newcomer; it applies a PULL_RESP from an accepted link
//! only as the answer of a member it asked within the last [`EXPECTED_FOR`] (the first frame of
//! the answer, and the rest within [`ANSWER_WINDOW`]), at most [`MAX_EXPECTED`] at once.
//!
//! # Blocks
//!
//! A replicated entry whose payload is a block not held here has the block fetched: asked of its
//! writer and the seed, then of the other members in turn, again after 1, 2, 4, ... up to 30
//! seconds with jitter, until it arrives, the entry leaves, or [`FETCH_DEADLINE`] passes. Every
//! held block is served to members that ask for it.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use agentspaces_wire::ads as wire_ads;
use agentspaces_wire::bodies::{
    self, KIND_ACK, KIND_BLOCK_WANT, KIND_CHANNEL_HELLO, KIND_DIGEST, KIND_GROUP_AD,
    KIND_GROUP_AD_WANT, KIND_PING, KIND_PULL_RESP, KIND_RELAY_FRAME, KIND_RUMOR, RUMOR_HOPS,
    RelayFrame, Rumor, STREAM_ADS, STREAM_PEERS, STREAM_SPACE_PREFIX,
};
use agentspaces_wire::cbor::{Map, Value};
use agentspaces_wire::crypto;
use agentspaces_wire::envelope::Auth;
use agentspaces_wire::fold::{FoldOutcome, Refusal};
use agentspaces_wire::identity::Identity;
use agentspaces_wire::ids;
use agentspaces_wire::limits::MAX_FRAME_BYTES;
use agentspaces_wire::records::{self, PayloadSource};
use agentspaces_wire::revocation;
use agentspaces_wire::serving;
use agentspaces_wire::social::{self, JoinVerdict};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use super::{
    Actor, Budget, FRAME_OVERHEAD, Link, ListenSettings, MAX_ASKED_BLOCKS, Malformed, Offer, bump,
    issued_millis,
};
use crate::peer::listen::{BoundListener, ListenCounters, TokenBucket};
use crate::peer::{PeerError, PeerEvent};
use crate::transport::Channel;

/// How often the listening role's housekeeping runs (links, members, fetches, rounds).
const TICK: Duration = Duration::from_millis(500);
/// The rumors remembered for duplicate suppression (by stream and payload hash).
const SEEN_CAPACITY: usize = 16_384;
/// The frames a stranger may send on an accepted link before any member introduced itself on
/// it; past this the link is closed.
const MAX_STRANGER_FRAMES: u32 = 64;
/// The most accepted links one member owns at once (a member back on a new link while its old
/// one lingers, two processes sharing a keystore); past it the oldest of its others closes.
const MAX_MEMBER_LINKS: usize = 4;
/// The most frames an accepted link's backlog holds (its bytes are bounded by half the queue).
const BACKLOG_FRAMES: usize = 4096;
/// A member's frames: a burst and a rate per second (Java `TokenBucket`'s defaults).
const MEMBER_BURST: u32 = 50_000;
const MEMBER_RATE: u32 = 10_000;
/// A member's DIGESTs answered: a burst (a joiner pulls several streams at once) and a rate.
const ANSWER_BURST: u32 = 16;
const ANSWER_RATE: u32 = 4;
/// The most streams of one DIGEST answered.
const MAX_DIGEST_STREAMS: usize = 64;
/// The target size of one PULL_RESP body; an answer larger than it goes in several frames.
pub(in crate::peer) const PULL_CHUNK_BYTES: usize = 1024 * 1024;
/// How long after asking a member this peer applies its PULL_RESPs, and how many members it
/// expects answers from at once.
pub(in crate::peer) const EXPECTED_FOR: Duration = Duration::from_secs(30);
const MAX_EXPECTED: usize = 16;
/// How long after a partner's first PULL_RESP the rest of its answer (an answer larger than one
/// frame) is still applied.
const ANSWER_WINDOW: Duration = Duration::from_secs(5);
/// The most members remembered as running anti-entropy (partners of this peer's rounds).
const MAX_DIGESTERS: usize = 1024;
/// How far this peer's own rounds stretch while idle (SPEC §5.3: 32 times the period).
const ROUND_STRETCH: u32 = 32;
/// The block fetches pending at once, how long one is pursued, and its longest backoff.
const MAX_FETCHES: usize = 1024;
pub(in crate::peer) const FETCH_DEADLINE: Duration = Duration::from_secs(600);
const FETCH_BACKOFF_CAP: Duration = Duration::from_secs(30);
/// The delegated admissions remembered past their delegation's expiry (SPEC §5.1).
const MAX_ADMISSION_MEMORY: usize = 4096;
/// The streams of one answer's resume cursors kept per member.
const MAX_CURSORS: usize = 64;
/// The longest relay path (SPEC §5.4, `max-path-hops`).
const MAX_PATH_HOPS: usize = 4;
/// The role a listening peer advertises.
pub(in crate::peer) const ROLE_RELAY: &str = "RELAY";

/// Which link a frame came on, and so where its answer goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::peer) enum Via {
    /// The dialed link (the seed's).
    Dialed,
    /// An accepted link.
    Accepted(u64),
    /// Inside a RELAY_FRAME that came on the dialed link (`None`) or an accepted one.
    Relayed(Option<u64>),
}

impl Via {
    /// Whether a relay carried the frame.
    pub fn is_relayed(self) -> bool {
        matches!(self, Via::Relayed(_))
    }

    /// The accepted link whose admission rules judge the frame, if any.
    pub fn gate(self) -> Option<u64> {
        match self {
            Via::Accepted(id) | Via::Relayed(Some(id)) => Some(id),
            Via::Dialed | Via::Relayed(None) => None,
        }
    }

    /// The link the frame arrived on directly (`dialed` is the dialed link's id).
    pub fn direct_link(self, dialed: Option<u64>) -> Option<u64> {
        match self {
            Via::Dialed => dialed,
            Via::Accepted(id) => Some(id),
            Via::Relayed(_) => None,
        }
    }
}

/// The admission gate's verdict on a frame from an accepted link.
pub(in crate::peer) enum Gate {
    /// An admitted member's frame: handled.
    Member,
    /// A stranger's: only the bootstrap kinds ([`Actor::on_stranger`]).
    Stranger,
    /// Dropped (and counted).
    Drop,
}

/// An admitted member.
pub(in crate::peer) struct Member {
    /// Its signed advertisement (the `peers` payload), what the view's delta carries.
    payload: Vec<u8>,
    /// The advertisement's `issued`, epoch milliseconds.
    issued_ms: i64,
    /// When the advertisement lapses, epoch milliseconds.
    expires_ms: i64,
    /// The hashes of the join credential (and delegation) that admitted it, if any.
    credentials: Vec<[u8; 32]>,
    /// Its frames' rate.
    rate: TokenBucket,
    /// Its DIGESTs' rate.
    answers: TokenBucket,
    /// Where the next answer of each stream resumes after one that was cut short.
    cursors: HashMap<String, usize>,
    /// Whether this peer still owes it the targeted round of a newcomer (SPEC §5.3), run once its
    /// first DIGEST shows it runs anti-entropy itself.
    round_owed: bool,
}

/// Rumors seen, by stream and payload hash, in a bounded memory.
#[derive(Default)]
pub(in crate::peer) struct Seen {
    keys: HashSet<[u8; 32]>,
    order: VecDeque<[u8; 32]>,
}

impl Seen {
    /// Remembers a rumor; whether it was new.
    pub fn insert(&mut self, stream: &str, payload: &[u8]) -> bool {
        let port = crypto::port();
        let mut material = port.sha256(payload).to_vec();
        material.extend_from_slice(stream.as_bytes());
        let key = port.sha256(&material);
        if !self.keys.insert(key) {
            return false;
        }
        self.order.push_back(key);
        while self.order.len() > SEEN_CAPACITY {
            if let Some(oldest) = self.order.pop_front() {
                self.keys.remove(&oldest);
            }
        }
        true
    }
}

/// A member asked in a round: whose PULL_RESP this peer applies, until it answered (and for
/// [`ANSWER_WINDOW`] after, for the rest of a long answer) or [`EXPECTED_FOR`] passed.
struct Expected {
    peer: String,
    asked: Instant,
    answered: Option<Instant>,
}

impl Expected {
    /// Whether a PULL_RESP arriving at `now` is still part of the answer.
    fn open(&self, now: Instant) -> bool {
        match self.answered {
            None => now.duration_since(self.asked) < EXPECTED_FOR,
            Some(at) => now.duration_since(at) < ANSWER_WINDOW,
        }
    }
}

/// A payload block being fetched for a replicated entry.
struct Fetch {
    /// The entry's writer, asked first.
    issuer: Option<String>,
    /// The entry, to stop once it leaves.
    space: String,
    entry_id: String,
    started: Instant,
    next_at: Instant,
    attempt: u32,
}

/// The listening role's state. See the [module docs](self).
pub(in crate::peer) struct Hub {
    /// Whether this peer listens at all.
    pub listening: bool,
    /// Whether it stopped accepting links before it closes ([`Actor::stop_accepting`]).
    pub draining: bool,
    pub settings: ListenSettings,
    /// The endpoints the advertisement names.
    pub endpoints: Vec<Map>,
    /// The accepted links, by id.
    pub accepted: BTreeMap<u64, Link>,
    /// Forwarded rumors waiting for room on the dialed link (their bodies, signed when sent),
    /// bounded as an accepted link's backlog is, apart from this peer's own held writes.
    dialed_backlog: VecDeque<Vec<u8>>,
    dialed_backlog_bytes: usize,
    /// Each admitted member's link, by PeerID.
    pub routes: HashMap<String, u64>,
    /// The admitted members, by PeerID.
    pub admitted: HashMap<String, Member>,
    /// The delegated credentials that admitted each member (hex hashes), kept past expiry.
    admission_memory: HashMap<String, String>,
    /// The bootstrap bucket every stranger frame spends.
    admissions: TokenBucket,
    /// DIGESTs answered on the dialed link.
    dialed_answers: TokenBucket,
    pub seen: Seen,
    /// The members asked in a round, when, and when their answer began.
    expected: VecDeque<Expected>,
    /// Members that run anti-entropy themselves (they named `view` in a DIGEST).
    digesters: BTreeSet<String>,
    /// The spaces opened because they were heard of.
    replicated: BTreeSet<String>,
    fetches: HashMap<String, Fetch>,
    /// Whether anything moved since the last round (SPEC §5.3's idle backoff).
    pub activity: bool,
    base_period: Duration,
    round_period: Duration,
    next_round: Option<Instant>,
    pub next_tick: Option<Instant>,
    /// The last self-advertisement payload, what the view's delta carries for this peer.
    pub own_ad: Option<Vec<u8>>,
    pub accept_tasks: Vec<JoinHandle<()>>,
    /// The inbound byte budget every accepted link's reader also draws on.
    pub inbound_budget: Arc<Semaphore>,
    pub counters: ListenCounters,
}

impl Hub {
    /// The state of a peer listening on `listeners` (none: an inert hub).
    pub fn new(settings: &ListenSettings, listeners: &[BoundListener]) -> Self {
        let base = settings
            .anti_entropy_period
            .unwrap_or(Duration::from_secs(1));
        Self {
            listening: !listeners.is_empty(),
            draining: false,
            settings: settings.clone(),
            endpoints: listeners
                .iter()
                .filter_map(|bound| bound.endpoint.clone())
                .collect(),
            accepted: BTreeMap::new(),
            dialed_backlog: VecDeque::new(),
            dialed_backlog_bytes: 0,
            routes: HashMap::new(),
            admitted: HashMap::new(),
            admission_memory: HashMap::new(),
            admissions: TokenBucket::new(settings.admission_burst, settings.admissions_per_second),
            dialed_answers: TokenBucket::new(ANSWER_BURST, ANSWER_RATE),
            seen: Seen::default(),
            expected: VecDeque::new(),
            digesters: BTreeSet::new(),
            replicated: BTreeSet::new(),
            fetches: HashMap::new(),
            activity: false,
            base_period: base,
            round_period: base,
            next_round: None,
            next_tick: None,
            own_ad: None,
            accept_tasks: Vec::new(),
            inbound_budget: Arc::new(Semaphore::new(super::ACCEPTED_BUDGET_BYTES)),
            counters: ListenCounters::default(),
        }
    }
}

/// Whether a fold outcome leaves the item fit to forward: anything but a refusal for what the
/// item itself is (malformed, unverified, revoked, a hostile stamp). `None` (a space not open
/// here) forwards the decoded item as it is.
pub(in crate::peer) fn forwardable(outcome: Option<FoldOutcome>) -> bool {
    match outcome {
        Some(FoldOutcome::Refused(refusal)) => !matches!(
            refusal,
            Refusal::Malformed
                | Refusal::MalformedStamp
                | Refusal::TooManyDots
                | Refusal::ForeignDots
                | Refusal::ForeignSpace
                | Refusal::UnverifiedRecord
                | Refusal::UnverifiedClaim
                | Refusal::UnverifiedState
                | Refusal::Revoked
                | Refusal::StampLogical
                | Refusal::StampFarFuture
        ),
        _ => true,
    }
}

/// Whether a revocation rumor payload is a `SignedRevocation` whose signature verifies under its
/// key, so a listening peer may forward it although its own registry keeps it already (or
/// refuses it for want of the founder).
pub(in crate::peer) fn signed_revocation_verifies(payload: &[u8]) -> bool {
    let Some(signed) =
        agentspaces_wire::schema::decode_map(payload, "RevocationRegistry.SignedRevocation")
    else {
        return false;
    };
    let field = |key: &str| signed.get(key).and_then(Value::as_bytes);
    match (field("adBytes"), field("publicKey"), field("signature")) {
        (Some(ad), Some(key), Some(signature)) => Identity::verify(key, ad, signature),
        _ => false,
    }
}

/// An upper bound on a value's encoded size, without encoding it: what a state costs its
/// space's byte bound and an item its PULL_RESP chunk.
pub(in crate::peer) fn value_size(value: &Value) -> usize {
    const HEAD: usize = 9;
    match value {
        Value::Text(text) => HEAD.saturating_add(text.len()),
        Value::Bytes(bytes) => HEAD.saturating_add(bytes.len()),
        Value::Array(items) => items
            .iter()
            .map(value_size)
            .fold(HEAD, usize::saturating_add),
        Value::Map(map) => map_size(map),
        _ => HEAD.saturating_add(HEAD),
    }
}

fn map_size(map: &Map) -> usize {
    map.iter()
        .map(|(key, value)| value_size(key).saturating_add(value_size(value)))
        .fold(2, usize::saturating_add)
}

/// What a state costs its space's byte bound ([`value_size`]).
pub(in crate::peer) fn state_size(state: &Map) -> usize {
    map_size(state)
}

/// A uniformly random `u64` from the crypto port (0 if it fails).
fn random_u64() -> u64 {
    let mut bytes = [0u8; 8];
    let _ = crypto::port().fill_random(&mut bytes);
    u64::from_be_bytes(bytes)
}

/// `period` plus a random spread of up to a quarter of it.
fn jittered(period: Duration) -> Duration {
    let spread = period / 4;
    let nanos = u64::try_from(spread.as_nanos()).unwrap_or(u64::MAX);
    if nanos == 0 {
        return period;
    }
    period.saturating_add(Duration::from_nanos(random_u64() % nanos))
}

/// Whether a RELAY_FRAME's path is well formed for this relay at `hop` (SPEC §5.4): at most
/// [`MAX_PATH_HOPS`] relays, none repeated, the target not among them, this peer at `hop`, and
/// the previous hop the frame's sender.
fn path_well_formed(path: &[String], hop: usize, me: &str, target: &str, sender: &str) -> bool {
    let distinct: HashSet<&str> = path.iter().map(String::as_str).collect();
    path.len() <= MAX_PATH_HOPS
        && distinct.len() == path.len()
        && !distinct.contains(target)
        && path.get(hop).map(String::as_str) == Some(me)
        && (hop == 0 || path.get(hop - 1).map(String::as_str) == Some(sender))
}

/// One item of a PULL_RESP answer.
enum Piece<'a> {
    Revocation(&'a Map),
    View(Vec<u8>),
    Ad(&'a Value),
    Claim(&'a str, &'a Map),
    State(&'a Map),
}

impl Piece<'_> {
    fn size(&self) -> usize {
        match self {
            Piece::Revocation(map) | Piece::Claim(_, map) | Piece::State(map) => map_size(map),
            Piece::View(payload) => payload.len().saturating_add(9),
            Piece::Ad(value) => value_size(value),
        }
    }
}

/// One stream's pieces of an answer, packed into chunks.
struct Chunk<'a> {
    streams: Vec<(String, Vec<Piece<'a>>)>,
    bytes: usize,
}

impl Actor {
    // ------------------------------------------------------------------------- start and stop

    /// On a listening peer: opens the spaces it replicates from the start (pulled from the seed,
    /// if any), caches its advertisement, and arms the housekeeping tick and the first round.
    pub(super) fn start_listening(&mut self, replicate: &[String]) {
        if !self.hub.listening {
            return;
        }
        for name in replicate {
            let _ = self.pull_space(name);
        }
        if self.hub.settings.anti_entropy_period.is_none() {
            // The founding's gossip period (SPEC §5.1), one second for a group from text.
            let period = self
                .founding
                .as_ref()
                .and_then(|founding| founding.get("advertisement"))
                .and_then(|ad| ad.get("gossip"))
                .and_then(|gossip| gossip.get("period"))
                .and_then(Value::as_str)
                .and_then(|period| agentspaces_wire::time::parse_duration_millis(period).ok())
                .and_then(|millis| u64::try_from(millis).ok())
                .filter(|millis| *millis > 0)
                .map_or(Duration::from_secs(1), Duration::from_millis)
                .min(Duration::from_secs(3600));
            self.hub.base_period = period;
            self.hub.round_period = period;
        }
        let now = self.now();
        self.hub.own_ad = Some(self.self_ad_payload(now));
        let at = Instant::now();
        self.hub.next_round = Some(at + jittered(self.hub.base_period));
        self.hub.next_tick = Some(at + TICK);
    }

    /// Stops accepting and closes every accepted link (the peer is closing).
    pub(super) fn stop_listening(&mut self) {
        for task in self.hub.accept_tasks.drain(..) {
            task.abort();
        }
        let ids: Vec<u64> = self.hub.accepted.keys().copied().collect();
        for id in ids {
            self.drop_accepted(id);
        }
        self.hub.next_tick = None;
        self.hub.next_round = None;
        self.hub.fetches.clear();
    }

    // ------------------------------------------------------------------------- links

    /// Takes a channel a listener accepted, unless the peer is closed or holds its bound of
    /// accepted links. At the bound, the oldest link nobody introduced itself on makes room (it
    /// had its time to introduce someone): links that never introduce anyone, kept open and
    /// replaced as the introduction timeout closes them, never lock newcomers out. Only when
    /// every link held carries a member is the channel refused.
    pub(super) fn accept_link(&mut self, channel: Channel) {
        if self.closed || !self.hub.listening || self.hub.draining {
            channel.closer.close();
            bump(&mut self.hub.counters.links_refused);
            return;
        }
        if self.hub.accepted.len() >= self.hub.settings.max_links {
            let oldest = self
                .hub
                .accepted
                .values()
                .filter(|link| link.owner.is_none())
                .min_by_key(|link| link.up_at)
                .map(|link| link.id);
            let Some(oldest) = oldest else {
                channel.closer.close();
                bump(&mut self.hub.counters.links_refused);
                return;
            };
            bump(&mut self.hub.counters.links_silent);
            self.drop_accepted(oldest);
        }
        let link = self.open_link(channel, true);
        tracing::debug!(peer = %self.peer_id, remote = %link.info.remote, "agentspaces: link accepted");
        bump(&mut self.hub.counters.links_accepted);
        self.hub.accepted.insert(link.id, link);
    }

    /// Closes and forgets accepted link `id`; its member stops being reachable here.
    pub(super) fn drop_accepted(&mut self, id: u64) {
        let Some(link) = self.hub.accepted.remove(&id) else {
            return;
        };
        link.closer.close();
        if link.queue.shared.stalled.load(Ordering::SeqCst) {
            bump(&mut self.counters.send_overflows);
        }
        if !link.backlog.is_empty() {
            let dropped = u64::try_from(link.backlog.len()).unwrap_or(u64::MAX);
            self.send_dropped.fetch_add(dropped, Ordering::Relaxed);
        }
        if let Some(owner) = &link.owner
            && self.hub.routes.get(owner) == Some(&id)
        {
            self.hub.routes.remove(owner);
            // A member that still speaks on another link it owns (an older one, after the newer
            // one its addressed frames took has closed) is reached there.
            if let Some(other) = self
                .hub
                .accepted
                .values()
                .filter(|other| other.owner.as_deref() == Some(owner.as_str()))
                .max_by_key(|other| other.heard_at)
                .map(|other| other.id)
            {
                self.hub.routes.insert(owner.clone(), other);
            }
        }
        bump(&mut self.hub.counters.links_closed);
        tracing::debug!(peer = %self.peer_id, remote = %link.info.remote, "agentspaces: accepted link closed");
    }

    /// A verified frame on accepted link `id`.
    pub(super) fn on_accepted_frame(&mut self, id: u64, env: Map, auth: Auth) {
        if let Some(link) = self.hub.accepted.get_mut(&id) {
            link.heard_at = Instant::now();
        }
        bump(&mut self.counters.frames_received);
        if self.handle(env, Some(auth), Via::Accepted(id)).is_err() {
            bump(&mut self.counters.malformed);
        }
    }

    /// Offers `frame` to accepted link `id` within `budget`. A burst frame ([`Budget::Half`])
    /// that does not fit waits in the link's backlog; a frame with the whole queue that does not
    /// fit is refused and counted, as on the dialed link.
    pub(super) fn offer_accepted(
        &mut self,
        id: u64,
        frame: Vec<u8>,
        budget: Budget,
    ) -> Result<(), PeerError> {
        if frame.len() > MAX_FRAME_BYTES {
            return Err(PeerError::FrameTooLarge(frame.len()));
        }
        let limit = self.limit(budget);
        let backlog_bytes = self.settings.send_queue_bytes / 2;
        let half = self.limit(Budget::Half);
        let Some(link) = self.hub.accepted.get_mut(&id) else {
            return Err(PeerError::NotConnected);
        };
        if budget == Budget::Half
            && (!link.backlog.is_empty() || !link.queue.has_room(frame.len(), limit))
        {
            link.backlog_bytes = link.backlog_bytes.saturating_add(frame.len());
            link.backlog.push_back(frame);
            while link.backlog.len() > BACKLOG_FRAMES || link.backlog_bytes > backlog_bytes {
                let Some(oldest) = link.backlog.pop_front() else {
                    break;
                };
                link.backlog_bytes = link.backlog_bytes.saturating_sub(oldest.len());
                bump(&mut self.hub.counters.backlog_dropped);
            }
            link.queue.shared.wants_relief.store(true, Ordering::SeqCst);
            let front = link.backlog.front().map_or(0, Vec::len);
            if link.queue.has_room(front, half) {
                self.flush_backlog(id);
            }
            return Ok(());
        }
        match link.queue.offer(frame, limit) {
            Offer::Queued => Ok(()),
            Offer::Full => {
                bump(&mut self.counters.send_refused);
                Err(PeerError::SendOverflow)
            }
            Offer::Closed => {
                self.drop_accepted(id);
                Err(PeerError::NotConnected)
            }
        }
    }

    /// Whether accepted link `id` can take a burst of `length` bytes at once: nothing waits in
    /// its backlog and its queue has room within half its bound.
    pub(super) fn accepted_has_room(&self, id: u64, length: usize) -> bool {
        let half = self.limit(Budget::Half);
        self.hub
            .accepted
            .get(&id)
            .is_some_and(|link| link.backlog.is_empty() && link.queue.has_room(length, half))
    }

    /// Sends accepted link `id`'s backlog while its queue has room within half its bound; the
    /// rest waits for the next relief.
    pub(super) fn flush_backlog(&mut self, id: u64) {
        let half = self.limit(Budget::Half);
        let mut closed = false;
        if let Some(link) = self.hub.accepted.get_mut(&id) {
            while let Some(length) = link.backlog.front().map(Vec::len) {
                if !link.queue.has_room(length, half) {
                    link.queue.shared.wants_relief.store(true, Ordering::SeqCst);
                    break;
                }
                let Some(frame) = link.backlog.pop_front() else {
                    break;
                };
                link.backlog_bytes = link.backlog_bytes.saturating_sub(length);
                if matches!(link.queue.offer(frame, half), Offer::Closed) {
                    closed = true;
                    break;
                }
            }
        }
        if closed {
            self.drop_accepted(id);
        }
    }

    /// Signs and offers one frame on accepted link `id`.
    pub(super) fn send_accepted(
        &mut self,
        id: u64,
        kind: &str,
        body: &[u8],
        to: Option<&str>,
        budget: Budget,
    ) -> Result<(), PeerError> {
        if !self.hub.accepted.contains_key(&id) {
            return Err(PeerError::NotConnected);
        }
        let frame = self.signed_frame(kind, body, to);
        self.offer_accepted(id, frame, budget)
    }

    /// Signs and offers one frame on link `id`, the dialed one or an accepted one.
    fn send_on_link(
        &mut self,
        id: u64,
        kind: &str,
        body: &[u8],
        to: Option<&str>,
        budget: Budget,
    ) -> Result<(), PeerError> {
        if self.is_current(id) {
            self.send_with(kind, body, to, budget)
        } else {
            self.send_accepted(id, kind, body, to, budget)
        }
    }

    /// Answers `to` the way its frame came: on the dialed link, on its accepted link, or (a
    /// relayed frame) by the route an addressed frame to it takes.
    pub(super) fn reply(
        &mut self,
        via: Via,
        kind: &str,
        body: &[u8],
        to: &str,
    ) -> Result<(), PeerError> {
        self.reply_with(via, kind, body, to, Budget::Whole)
    }

    fn reply_with(
        &mut self,
        via: Via,
        kind: &str,
        body: &[u8],
        to: &str,
        budget: Budget,
    ) -> Result<(), PeerError> {
        match via {
            Via::Dialed => self.send_with(kind, body, Some(to), budget),
            Via::Accepted(id) => self.send_accepted(id, kind, body, Some(to), budget),
            Via::Relayed(_) => self.send_addressed_with(kind, body, to, budget),
        }
    }

    /// The accepted link an addressed frame to `to` goes on: the one `to` introduced itself on,
    /// else that of a relay `to`'s advertisement declares (`relay.via`, comma-joined), which then
    /// carries it as a one-hop RELAY_FRAME.
    pub(super) fn accepted_route(&self, to: &str) -> Option<(u64, Option<String>)> {
        if let Some(id) = self.hub.routes.get(to) {
            return Some((*id, None));
        }
        let ad = self.members.get(to)?;
        let via = ad
            .get("resourceHints")
            .and_then(|hints| hints.get("relay.via"))
            .and_then(Value::as_str)?;
        via.split(',').map(str::trim).find_map(|relay| {
            self.hub
                .routes
                .get(relay)
                .map(|id| (*id, Some(relay.to_owned())))
        })
    }

    /// Closes accepted links that introduced nobody within the introduction timeout or stayed
    /// silent past the idle timeout.
    fn close_silent_links(&mut self, now: Instant) {
        let introduction = self.hub.settings.introduction_timeout;
        let idle = self.hub.settings.link_idle_timeout;
        let silent: Vec<u64> = self
            .hub
            .accepted
            .values()
            .filter(|link| {
                (link.owner.is_none() && now.duration_since(link.up_at) >= introduction)
                    || now.duration_since(link.heard_at) >= idle
            })
            .map(|link| link.id)
            .collect();
        for id in silent {
            bump(&mut self.hub.counters.links_silent);
            self.drop_accepted(id);
        }
    }

    // ------------------------------------------------------------------------- admission

    /// The admission gate (SPEC §5.1, §5.6) for a frame from `sender` that came on (or through)
    /// accepted link `id`.
    pub(super) fn gate(&mut self, id: u64, sender: &str, via: Via) -> Gate {
        let attested = self
            .hub
            .accepted
            .get(&id)
            .and_then(|link| link.info.attested.clone());
        if self.hub.settings.require_attestation
            && (via.is_relayed() || attested.as_deref() != Some(sender))
        {
            bump(&mut self.hub.counters.unattested_frames);
            if !via.is_relayed() && attested.is_none() && self.hub.admitted.contains_key(sender) {
                // A member's fresh link that attests nobody: what a withdrawn credential looks
                // like at this layer (SPEC §5.6). It is refused until it re-attests.
                tracing::warn!(peer = %self.peer_id, member = %sender, "agentspaces: a member's link attests nobody; evicted");
                self.evict(sender);
            }
            return Gate::Drop;
        }
        match self.hub.admitted.get_mut(sender) {
            Some(member) => {
                if member.rate.take() {
                    Gate::Member
                } else {
                    bump(&mut self.hub.counters.rate_limited);
                    Gate::Drop
                }
            }
            None if via.is_relayed() => {
                bump(&mut self.hub.counters.stranger_frames);
                Gate::Drop
            }
            None => Gate::Stranger,
        }
    }

    /// A frame from a peer that is not a member, on accepted link `id`: only a PING, a
    /// GROUP_AD_WANT, a CHANNEL_HELLO, or an introduction, within the link's allowance of
    /// stranger frames ([`Actor::stranger_allowed`]). Only an admission spends the admission
    /// bucket, so a stranger's flood of the other kinds starves no newcomer.
    pub(super) fn on_stranger(
        &mut self,
        id: u64,
        sender: String,
        kind: &str,
        body: &[u8],
    ) -> Result<(), Malformed> {
        if !self.stranger_allowed(id) {
            return Ok(());
        }
        match kind {
            KIND_PING => {
                let nonce = bodies::parse_ping(body).ok_or(Malformed)?;
                let _ = self.send_accepted(
                    id,
                    KIND_ACK,
                    &bodies::ack_body(nonce),
                    Some(&sender),
                    Budget::Whole,
                );
            }
            KIND_GROUP_AD_WANT => self.serve_founding(id, &sender),
            KIND_RUMOR => {
                let rumor = bodies::parse_rumor(body).ok_or(Malformed)?;
                if rumor.stream_id == STREAM_PEERS {
                    self.admit(id, &sender, &rumor);
                } else {
                    bump(&mut self.hub.counters.stranger_frames);
                }
            }
            KIND_CHANNEL_HELLO => {} // this peer signs every frame it sends
            _ => bump(&mut self.hub.counters.stranger_frames),
        }
        Ok(())
    }

    /// Counts a stranger's frame, of whatever kind, against accepted link `id`: past
    /// [`MAX_STRANGER_FRAMES`] a link nobody introduced itself on is closed, and one a member
    /// owns drops the frame. Whether the frame may be handled.
    fn stranger_allowed(&mut self, id: u64) -> bool {
        let Some(link) = self.hub.accepted.get_mut(&id) else {
            return false;
        };
        link.strangers = link.strangers.saturating_add(1);
        if link.strangers <= MAX_STRANGER_FRAMES {
            return true;
        }
        let close = link.owner.is_none();
        bump(&mut self.hub.counters.stranger_frames);
        if close {
            bump(&mut self.hub.counters.links_silent);
            self.drop_accepted(id);
        }
        false
    }

    /// A stranger's introduction on accepted link `id`: admitted when it is the sender's own
    /// verified advertisement for this group, live and unrevoked, and the group's policy admits
    /// it (see the [module docs](self#admission-spec-51-52)).
    fn admit(&mut self, id: u64, sender: &str, rumor: &Rumor) {
        let refused = |actor: &mut Actor, reason: fn(&mut ListenCounters) -> &mut u64| {
            bump(reason(&mut actor.hub.counters));
        };
        let Some((ad, issuer)) = wire_ads::verify_signed_peer_ad(&rumor.payload) else {
            return refused(self, |c| &mut c.refused.forged);
        };
        if issuer != sender {
            // A third party's copy admits nobody.
            return refused(self, |c| &mut c.refused.forged);
        }
        if issuer == self.peer_id {
            return;
        }
        if self.registry.peer_revoked(&issuer) {
            return refused(self, |c| &mut c.refused.revoked);
        }
        if ad.get("group").and_then(Value::as_str) != Some(self.group.as_str()) {
            return refused(self, |c| &mut c.refused.foreign);
        }
        let now = self.now();
        let issued = issued_millis(&ad);
        let expires = wire_ads::ad_expires_at_millis(&ad);
        let (Some(issued), Some(expires)) = (issued, expires) else {
            return refused(self, |c| &mut c.refused.expired);
        };
        let ahead =
            i128::from(issued) > i128::from(now) + i128::from(wire_ads::MAX_AD_ISSUED_SKEW_MILLIS);
        if expires <= now || ahead {
            return refused(self, |c| &mut c.refused.expired);
        }
        let (attested, owner) = match self.hub.accepted.get(&id) {
            Some(link) => (link.info.attested.clone(), link.owner.clone()),
            None => return,
        };
        if self.hub.settings.require_attestation && attested.as_deref() != Some(issuer.as_str()) {
            return refused(self, |c| &mut c.refused.unattested);
        }
        if owner.as_deref().is_some_and(|owner| owner != issuer) {
            return refused(self, |c| &mut c.refused.link_taken);
        }
        let Ok(credentials) = self.admission_policy(&issuer, &ad, now) else {
            tracing::debug!(peer = %self.peer_id, newcomer = %issuer, "agentspaces: the membership policy refused a newcomer");
            return refused(self, |c| &mut c.refused.policy);
        };
        if !self.hub.admitted.contains_key(&issuer)
            && self.hub.admitted.len() >= self.hub.settings.max_members
        {
            self.expire_members(now);
            if self.hub.admitted.len() >= self.hub.settings.max_members {
                return refused(self, |c| &mut c.refused.full);
            }
        }
        // The bucket bounds admissions, what costs this peer most (its introduction and the
        // view to the newcomer, the forward to every link): only one about to happen spends it.
        if !self.hub.admissions.take() {
            return refused(self, |c| &mut c.refused.rate);
        }
        let fresh = !self.hub.admitted.contains_key(&issuer);
        self.hub.admitted.insert(
            issuer.clone(),
            Member {
                payload: rumor.payload.clone(),
                issued_ms: issued,
                expires_ms: expires,
                credentials,
                rate: TokenBucket::new(MEMBER_BURST, MEMBER_RATE),
                answers: TokenBucket::new(ANSWER_BURST, ANSWER_RATE),
                cursors: HashMap::new(),
                round_owed: fresh,
            },
        );
        self.members.hold_ad(issuer.clone(), ad);
        if let Some(link) = self.hub.accepted.get_mut(&id) {
            link.owner = Some(issuer.clone());
        }
        self.hub.routes.insert(issuer.clone(), id);
        if fresh {
            bump(&mut self.hub.counters.admitted);
            tracing::debug!(peer = %self.peer_id, member = %issuer, "agentspaces: admitted");
            self.emit(PeerEvent::Admitted {
                peer: issuer.clone(),
            });
        }
        // The newcomer learns this peer on the same link before any later frame (SPEC §5.2),
        // then the members it does not hold yet (a dial-only newcomer pulls no view). A member
        // back on a new link (a visitor run again, a member that restarted) held nothing over
        // its absence, so it hears the view too, paced by its answer bucket (a member that
        // relinks in a loop gets no view per link); a re-lease on its link does not.
        self.introduce_to(id, &issuer);
        if fresh || (owner.is_none() && self.view_paced(&issuer)) {
            self.send_view(id, &issuer);
        }
        if self.hub.seen.insert(&rumor.stream_id, &rumor.payload) {
            self.forward_rumor(rumor, Via::Accepted(id));
        }
    }

    /// Binds an accepted link that has no owner yet to the admitted member speaking on it (a
    /// member back on a new link), and introduces this peer there. A member keeps at most
    /// [`MAX_MEMBER_LINKS`] links: past it the oldest of its others closes, so one member cannot
    /// take every link this peer allows.
    pub(super) fn bind_link(&mut self, id: u64, member: &str) {
        let Some(link) = self.hub.accepted.get_mut(&id) else {
            return;
        };
        if link.owner.is_some() || link.info.attested.as_deref().is_some_and(|a| a != member) {
            return;
        }
        link.owner = Some(member.to_owned());
        self.hub.routes.insert(member.to_owned(), id);
        let mut others: Vec<(Instant, u64)> = self
            .hub
            .accepted
            .values()
            .filter(|other| other.id != id && other.owner.as_deref() == Some(member))
            .map(|other| (other.up_at, other.id))
            .collect();
        if others.len() >= MAX_MEMBER_LINKS {
            others.sort_unstable();
            let excess = others.len() + 1 - MAX_MEMBER_LINKS;
            for (_, old) in others.into_iter().take(excess) {
                self.drop_accepted(old);
            }
        }
        self.introduce_to(id, member);
        if self.view_paced(member) {
            self.send_view(id, member);
        }
    }

    /// Whether admitted `member` may hear the view again on a new link: it spends a token of its
    /// answer bucket, as an answered DIGEST does.
    fn view_paced(&mut self, member: &str) -> bool {
        self.hub
            .admitted
            .get_mut(member)
            .is_some_and(|admitted| admitted.answers.take())
    }

    /// The group's membership policy for `issuer` (SPEC §5.1): the credential hashes that admit
    /// it (none for `OPEN`, the founder, or a group founded from text), or `Err` when refused.
    fn admission_policy(&mut self, issuer: &str, ad: &Map, now: i64) -> Result<Vec<[u8; 32]>, ()> {
        if self.joining {
            // A join by GroupID still waits for the founding: no policy has verified yet, and
            // the group may admit only invited peers (SPEC §5.1).
            return Err(());
        }
        let Some(group_ad) = self
            .founding
            .as_ref()
            .and_then(|founding| founding.get("advertisement"))
            .and_then(Value::as_map)
        else {
            return Ok(Vec::new()); // founded from text: OPEN, as the Java demos found it
        };
        let founder = group_ad
            .get("issuer")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        if issuer == founder {
            return Ok(Vec::new());
        }
        match group_ad.get("membershipPolicy").and_then(Value::as_str) {
            Some("OPEN") => Ok(Vec::new()),
            Some("INVITE") => self.judge_invite(issuer, ad, &founder, now),
            _ => Err(()),
        }
    }

    /// INVITE admission: the `aspace:join` credential verifies (or only its delegation expired
    /// and this peer admitted the member under it before), and neither it nor its delegation is
    /// revoked.
    fn judge_invite(
        &mut self,
        issuer: &str,
        ad: &Map,
        founder: &str,
        now: i64,
    ) -> Result<Vec<[u8; 32]>, ()> {
        let credential = ad
            .get("resourceHints")
            .and_then(|hints| hints.get(social::HINT_KEY))
            .and_then(Value::as_str)
            .ok_or(())?;
        let verdict = social::judge_credential(credential, issuer, founder, &self.group, now);
        if verdict == JoinVerdict::Invalid {
            return Err(());
        }
        // The credential's hash and, for a delegated one, its delegation's, each read the way
        // the verdict read the credential (Java `delegationHash`, null for a founder-issued
        // credential), so no padding the verdict forgives hides the delegation from its
        // revocation.
        let mut hashes = vec![social::credential_hash(credential).map_err(|_| ())?];
        hashes.extend(social::delegation_hash(credential).ok());
        if hashes
            .iter()
            .any(|hash| self.registry.join_credential_revoked(hash))
        {
            return Err(());
        }
        let record: String = hashes
            .iter()
            .map(|hash| serving::revocation_line("", hash))
            .collect::<Vec<_>>()
            .join(",");
        if verdict == JoinVerdict::Expired {
            return if self.hub.admission_memory.get(issuer) == Some(&record) {
                Ok(hashes)
            } else {
                Err(())
            };
        }
        if self.hub.admission_memory.len() < MAX_ADMISSION_MEMORY
            || self.hub.admission_memory.contains_key(issuer)
        {
            self.hub.admission_memory.insert(issuer.to_owned(), record);
        }
        Ok(hashes)
    }

    /// Refreshes an admitted member's advertisement with a newer one, whoever carried it.
    pub(super) fn refresh_member(&mut self, issuer: &str, ad: &Map, payload: &[u8], issued: i64) {
        let Some(member) = self.hub.admitted.get_mut(issuer) else {
            return;
        };
        if issued < member.issued_ms {
            return;
        }
        member.issued_ms = issued;
        if let Some(expires) = wire_ads::ad_expires_at_millis(ad) {
            member.expires_ms = expires;
        }
        member.payload = payload.to_vec();
    }

    /// Drops an admitted member and closes every link it owns, not only the one its addressed
    /// frames take: a link left open would go on carrying the group's rumors to it.
    pub(super) fn evict(&mut self, peer: &str) {
        self.hub.admitted.remove(peer);
        self.hub.digesters.remove(peer);
        self.members.retain(|member| member != peer);
        let owned: Vec<u64> = self
            .hub
            .accepted
            .values()
            .filter(|link| link.owner.as_deref() == Some(peer))
            .map(|link| link.id)
            .collect();
        for id in owned {
            self.drop_accepted(id);
        }
        self.hub.routes.remove(peer);
    }

    /// Evicts every member admitted under a join credential (or delegation) now revoked.
    pub(super) fn enforce_credential_revocations(&mut self) {
        let revoked: Vec<String> = self
            .hub
            .admitted
            .iter()
            .filter(|(_, member)| {
                member
                    .credentials
                    .iter()
                    .any(|hash| self.registry.join_credential_revoked(hash))
            })
            .map(|(peer, _)| peer.clone())
            .collect();
        for peer in revoked {
            tracing::info!(peer = %self.peer_id, member = %peer, "agentspaces: a member's join credential is revoked; evicted");
            self.evict(&peer);
        }
    }

    /// Drops the members whose advertisement lapsed while no link carries them.
    fn expire_members(&mut self, now: i64) {
        let lapsed: Vec<String> = self
            .hub
            .admitted
            .iter()
            .filter(|(peer, member)| {
                member.expires_ms <= now && !self.hub.routes.contains_key(*peer)
            })
            .map(|(peer, _)| peer.clone())
            .collect();
        for peer in lapsed {
            bump(&mut self.hub.counters.members_expired);
            self.hub.admitted.remove(&peer);
            self.hub.digesters.remove(&peer);
            self.members.retain(|member| member != peer);
        }
    }

    /// Answers a GROUP_AD_WANT on link `id` with the founding this peer verified; a group known
    /// only from a founding text serves none (SPEC §5.1).
    pub(super) fn serve_founding(&mut self, id: u64, asker: &str) {
        let Some(body) = self.founding.as_ref().and_then(bodies::group_ad_body) else {
            return;
        };
        if self
            .send_on_link(id, KIND_GROUP_AD, &body, Some(asker), Budget::Whole)
            .is_ok()
        {
            bump(&mut self.hub.counters.group_ads_served);
        }
    }

    // ------------------------------------------------------------------------- introductions

    /// This peer's introduction, unforwarded (a hop budget of one), to `member` on accepted link
    /// `id`.
    fn introduce_to(&mut self, id: u64, member: &str) {
        let now = self.now();
        let payload = self.self_ad_payload(now);
        let item_ms = now.max(self.last_intro_ms.saturating_add(1));
        self.last_intro_ms = item_ms;
        let item = format!("peer:{}:{item_ms}", self.peer_id);
        let body = bodies::rumor_body(STREAM_PEERS, &item, 1, &payload);
        let _ = self.send_accepted(id, KIND_RUMOR, &body, Some(member), Budget::Whole);
        self.hub.own_ad = Some(payload);
    }

    /// The advertisements of the live members to `newcomer` on accepted link `id`, each directly
    /// and unforwarded (a hop budget of one): the membership view a newcomer that runs no
    /// anti-entropy of its own would otherwise learn only from each member's next re-lease.
    fn send_view(&mut self, id: u64, newcomer: &str) {
        let now = self.now();
        let payloads: Vec<(String, i64, Vec<u8>)> = self
            .hub
            .admitted
            .iter()
            .filter(|(peer, member)| *peer != newcomer && member.expires_ms > now)
            .map(|(peer, member)| (peer.clone(), member.issued_ms, member.payload.clone()))
            .collect();
        for (peer, issued, payload) in payloads {
            let item = format!("peer:{peer}:{issued}");
            let body = bodies::rumor_body(STREAM_PEERS, &item, 1, &payload);
            let _ = self.send_accepted(id, KIND_RUMOR, &body, Some(newcomer), Budget::Half);
        }
    }

    /// The re-lease of this peer's advertisement to every member on an accepted link, directly
    /// and unforwarded (SPEC §5.2's paced refresh), once each, on the link its addressed frames
    /// take.
    pub(super) fn introduce_accepted(&mut self, item: &str, payload: &[u8]) {
        let owners: Vec<(u64, String)> = self
            .hub
            .routes
            .iter()
            .map(|(owner, id)| (*id, owner.clone()))
            .collect();
        if owners.is_empty() {
            return;
        }
        let body = bodies::rumor_body(STREAM_PEERS, item, 1, payload);
        for (id, owner) in owners {
            let _ = self.send_accepted(id, KIND_RUMOR, &body, Some(&owner), Budget::Whole);
        }
    }

    // ------------------------------------------------------------------------- gossip

    /// One of this peer's own rumors (a write, an advertisement) to every member on an accepted
    /// link, signed once and sent once per member, on the link its addressed frames take (as a
    /// Java node sends on one connection per member): a member's further links multiply nothing.
    pub(super) fn publish_accepted(&mut self, body: &[u8]) {
        if let Some(rumor) = bodies::parse_rumor(body) {
            self.hub.seen.insert(&rumor.stream_id, &rumor.payload);
            if rumor.stream_id != STREAM_PEERS {
                self.hub.activity = true;
            }
        }
        let targets: Vec<u64> = self.hub.routes.values().copied().collect();
        if targets.is_empty() {
            return;
        }
        let frame = self.signed_frame(KIND_RUMOR, body, None);
        for id in targets {
            let _ = self.offer_accepted(id, frame.clone(), Budget::Half);
        }
    }

    /// Forwards a rumor that arrived `via` one link to every other member on an accepted link
    /// (once each, as [`Actor::publish_accepted`] sends) and to the dialed link, its hop budget
    /// clamped to 6 and decremented (SPEC §5.3); a budget of one ends here.
    pub(super) fn forward_rumor(&mut self, rumor: &Rumor, via: Via) {
        let hops = rumor.hops_remaining.min(i64::from(RUMOR_HOPS));
        let Ok(hops) = i32::try_from(hops) else {
            return;
        };
        if hops <= 1 || via.is_relayed() {
            return;
        }
        let from = match via {
            Via::Accepted(id) => Some(id),
            _ => None,
        };
        let targets: Vec<u64> = self
            .hub
            .routes
            .values()
            .copied()
            .filter(|id| Some(*id) != from)
            .collect();
        let to_dialed = via != Via::Dialed && self.link.is_some() && !self.joining;
        if targets.is_empty() && !to_dialed {
            return;
        }
        let body = bodies::rumor_body(&rumor.stream_id, &rumor.item_id, hops - 1, &rumor.payload);
        let frame = self.signed_frame(KIND_RUMOR, &body, None);
        for id in targets {
            let _ = self.offer_accepted(id, frame.clone(), Budget::Half);
        }
        if to_dialed {
            let length = frame.len();
            let sent = self.hub.dialed_backlog.is_empty()
                && self.has_room(length, Budget::Half)
                && self.offer(frame, Budget::Half).is_ok();
            if !sent {
                self.hold_for_dialed(body);
            }
        }
        bump(&mut self.hub.counters.rumors_forwarded);
    }

    /// Holds a forwarded rumor's body until the dialed link has room, re-signed then: within
    /// half the queue's bytes and [`BACKLOG_FRAMES`] bodies, the oldest dropped and counted past
    /// either, as an accepted link's backlog. Kept apart from the outbox, so a member's flood
    /// never pushes this peer's own held writes out, nor pins more than one backlog's bytes.
    fn hold_for_dialed(&mut self, body: Vec<u8>) {
        let bound = self.settings.send_queue_bytes / 2;
        self.hub.dialed_backlog_bytes = self.hub.dialed_backlog_bytes.saturating_add(body.len());
        self.hub.dialed_backlog.push_back(body);
        while self.hub.dialed_backlog.len() > BACKLOG_FRAMES
            || self.hub.dialed_backlog_bytes > bound
        {
            let Some(oldest) = self.hub.dialed_backlog.pop_front() else {
                break;
            };
            self.hub.dialed_backlog_bytes =
                self.hub.dialed_backlog_bytes.saturating_sub(oldest.len());
            bump(&mut self.hub.counters.backlog_dropped);
        }
        let front = self.hub.dialed_backlog.front().map_or(0, Vec::len);
        if self.arm_relief(front.saturating_add(FRAME_OVERHEAD)) {
            self.flush_dialed_backlog();
        }
    }

    /// Sends the forwarded rumors held for the dialed link while it has room within half its
    /// queue; the rest wait for the next relief.
    pub(super) fn flush_dialed_backlog(&mut self) {
        while let Some(length) = self
            .hub
            .dialed_backlog
            .front()
            .map(|body| body.len().saturating_add(FRAME_OVERHEAD))
        {
            if !self.has_room(length, Budget::Half) && !self.arm_relief(length) {
                return;
            }
            let Some(body) = self.hub.dialed_backlog.pop_front() else {
                return;
            };
            self.hub.dialed_backlog_bytes =
                self.hub.dialed_backlog_bytes.saturating_sub(body.len());
            match self.send_with(KIND_RUMOR, &body, None, Budget::Half) {
                Ok(()) => {}
                Err(PeerError::FrameTooLarge(_)) => bump(&mut self.hub.counters.backlog_dropped),
                Err(_) => {
                    self.hub.dialed_backlog_bytes =
                        self.hub.dialed_backlog_bytes.saturating_add(body.len());
                    self.hub.dialed_backlog.push_front(body);
                    let _ = self.arm_relief(length);
                    return;
                }
            }
        }
    }

    /// Forgets the forwarded rumors held for the dialed link (the peer is closing).
    pub(super) fn clear_dialed_backlog(&mut self) {
        self.hub.dialed_backlog.clear();
        self.hub.dialed_backlog_bytes = 0;
    }

    /// Opens space `name` because a rumor brought an entry of it, within
    /// `ListenConfig::max_replicated_spaces`; whether it is open.
    pub(super) fn replicate_space(&mut self, name: &str) -> bool {
        if self.spaces.contains(name) {
            return true;
        }
        if !self.hub.listening || !self.hub.settings.replicate_heard {
            return false;
        }
        if self.hub.replicated.len() >= self.hub.settings.max_replicated_spaces
            || self.spaces.slot(name).is_none()
        {
            bump(&mut self.hub.counters.spaces_refused);
            return false;
        }
        self.hub.replicated.insert(name.to_owned());
        bump(&mut self.hub.counters.spaces_replicated);
        // Pulled from the seed too, now and after every reconnect.
        self.pulled_spaces.insert(name.to_owned());
        if self.link.is_some() && !self.joining {
            let _ = self.send_space_digest(name);
        }
        true
    }

    // ------------------------------------------------------------------------- anti-entropy

    /// Whether a PULL_RESP from `sender` is applied: always on the dialed link (as a dial-only
    /// peer takes its seed's), and from an accepted link only as the answer of a member this
    /// peer asked within [`EXPECTED_FOR`] (its first PULL_RESP, and the rest of the answer
    /// within [`ANSWER_WINDOW`]).
    pub(super) fn pull_resp_wanted(&mut self, sender: &str, via: Via) -> bool {
        if via.gate().is_none() {
            return true;
        }
        let now = Instant::now();
        if let Some(expected) = self
            .hub
            .expected
            .iter_mut()
            .find(|expected| expected.peer == sender && expected.open(now))
        {
            expected.answered.get_or_insert(now);
            return true;
        }
        bump(&mut self.hub.counters.pull_resps_unsolicited);
        false
    }

    /// Answers a DIGEST from `sender` with what its digests show it lacks, in as many PULL_RESP
    /// frames as it takes (see the [module docs](self#gossip-and-anti-entropy-spec-53-7-9)).
    pub(super) fn on_digest(
        &mut self,
        sender: &str,
        body: &[u8],
        via: Via,
    ) -> Result<(), Malformed> {
        let digests = bodies::parse_digest(body).ok_or(Malformed)?;
        let paced = match self.hub.admitted.get_mut(sender) {
            Some(member) => !member.answers.take(),
            None => !self.hub.dialed_answers.take(),
        };
        if paced {
            bump(&mut self.hub.counters.pulls_paced);
            return Ok(());
        }
        // A member whose DIGEST names the view runs anti-entropy itself: it answers this peer's
        // rounds, and a newcomer gets its targeted round now.
        let mut owed = false;
        if digests.contains_key(serving::STREAM_VIEW) {
            if self.hub.digesters.len() < MAX_DIGESTERS || self.hub.digesters.contains(sender) {
                self.hub.digesters.insert(sender.to_owned());
            }
            if let Some(member) = self.hub.admitted.get_mut(sender) {
                owed = std::mem::take(&mut member.round_owed);
            }
        }
        let mut asked: Vec<(&str, &[u8])> = digests
            .iter()
            .filter_map(|(stream, digest)| Some((stream.as_str()?, digest.as_bytes()?)))
            .collect();
        if asked.len() > MAX_DIGEST_STREAMS {
            asked.truncate(MAX_DIGEST_STREAMS);
            bump(&mut self.hub.counters.digests_truncated);
        }
        let cursors = self
            .hub
            .admitted
            .get(sender)
            .map(|member| member.cursors.clone())
            .unwrap_or_default();
        let (frames, next_cursors, truncated) = self.answer_digest(sender, &asked, &cursors);
        if truncated {
            bump(&mut self.hub.counters.digests_truncated);
        }
        if let Some(member) = self.hub.admitted.get_mut(sender) {
            member.cursors = next_cursors;
        }
        if !frames.is_empty() {
            bump(&mut self.hub.counters.pulls_answered);
            self.hub.activity = true;
        }
        for frame in frames {
            if self
                .reply_with(via, KIND_PULL_RESP, &frame, sender, Budget::Half)
                .is_ok()
            {
                bump(&mut self.hub.counters.pull_frames);
            }
        }
        if owed {
            self.round_with(sender);
        }
        Ok(())
    }

    /// The PULL_RESP bodies answering `asked` (stream, the asker's digest), the cursors to resume
    /// from next time, and whether the answer was cut short.
    fn answer_digest(
        &self,
        asker: &str,
        asked: &[(&str, &[u8])],
        cursors: &HashMap<String, usize>,
    ) -> (Vec<Vec<u8>>, HashMap<String, usize>, bool) {
        let now = self.now();
        // Java's registration order: the revocations, then the view and the advertisements, then
        // the spaces, so a pull never brings a record before the revocation that judges it.
        let rank = |stream: &str| match stream {
            revocation::PEER_STREAM => 0,
            revocation::CREDENTIAL_STREAM => 1,
            serving::STREAM_VIEW => 2,
            STREAM_ADS => 3,
            _ => 4,
        };
        let mut ordered: Vec<&(&str, &[u8])> = asked.iter().collect();
        ordered.sort_by_key(|(stream, _)| rank(stream));
        let mut streams: Vec<(String, Vec<Piece<'_>>)> = Vec::new();
        for (stream, remote) in ordered {
            let pieces = self.missing_pieces(asker, stream, remote, now);
            if !pieces.is_empty() {
                streams.push(((*stream).to_owned(), pieces));
            }
        }
        // Pack in order, resuming each stream where the last cut answer stopped. The answer, each
        // frame's envelope and each stream's key counted, fits the backlog that may hold it (half
        // the link's queue): on a busy link the backlog then drops older frames, never the head
        // of this answer, whose revocations judge the states after them.
        let budget = self.settings.send_queue_bytes / 2;
        let chunk_limit = PULL_CHUNK_BYTES
            .min(budget.saturating_sub(FRAME_OVERHEAD))
            .max(1);
        let mut chunks: Vec<Chunk<'_>> = Vec::new();
        let mut total = 0usize;
        let mut next_cursors = HashMap::new();
        let mut truncated = false;
        'streams: for (stream, mut pieces) in streams {
            let len = pieces.len();
            let start = cursors.get(&stream).copied().unwrap_or(0) % len.max(1);
            pieces.rotate_left(start);
            for (index, piece) in pieces.into_iter().enumerate() {
                let size = piece.size();
                let fits = chunks
                    .last()
                    .is_some_and(|chunk| chunk.bytes.saturating_add(size) <= chunk_limit);
                let continues = fits
                    && chunks
                        .last()
                        .and_then(|chunk| chunk.streams.last())
                        .is_some_and(|(name, _)| *name == stream);
                let mut cost = size;
                if !fits {
                    cost = cost.saturating_add(FRAME_OVERHEAD);
                }
                if !continues {
                    cost = cost.saturating_add(stream.len().saturating_add(18));
                }
                if total.saturating_add(cost) > budget && total > 0 {
                    truncated = true;
                    if next_cursors.len() < MAX_CURSORS {
                        next_cursors.insert(stream.clone(), (start + index) % len);
                    }
                    break 'streams;
                }
                total = total.saturating_add(cost);
                if !fits {
                    chunks.push(Chunk {
                        streams: Vec::new(),
                        bytes: 0,
                    });
                }
                let Some(chunk) = chunks.last_mut() else {
                    break 'streams;
                };
                chunk.bytes = chunk.bytes.saturating_add(size);
                match chunk.streams.last_mut() {
                    Some((name, items)) if *name == stream => items.push(piece),
                    _ => chunk.streams.push((stream.clone(), vec![piece])),
                }
            }
        }
        let frames = chunks.into_iter().map(encode_chunk).collect();
        (frames, next_cursors, truncated)
    }

    /// What `asker` lacks of `stream`, given its digest.
    fn missing_pieces<'a>(
        &'a self,
        asker: &str,
        stream: &str,
        remote: &[u8],
        now: i64,
    ) -> Vec<Piece<'a>> {
        let mut pieces = Vec::new();
        if stream == revocation::PEER_STREAM || stream == revocation::CREDENTIAL_STREAM {
            let lines = serving::digest_lines(remote);
            let (prefix, table) = if stream == revocation::PEER_STREAM {
                ("r:", self.registry.peers())
            } else {
                ("c:", self.registry.credentials())
            };
            for (key, held) in table {
                let line = serving::revocation_line(&format!("{prefix}{key}"), &held.digest);
                if !lines.contains(line.as_bytes()) && !held.signed.is_empty() {
                    pieces.push(Piece::Revocation(&held.signed));
                }
            }
        } else if stream == serving::STREAM_VIEW {
            let lines = serving::digest_lines(remote);
            if !lines.contains(self.peer_id.as_bytes())
                && let Some(own) = &self.hub.own_ad
            {
                pieces.push(Piece::View(own.clone()));
            }
            for (peer, member) in &self.hub.admitted {
                if peer != asker && member.expires_ms > now && !lines.contains(peer.as_bytes()) {
                    pieces.push(Piece::View(member.payload.clone()));
                }
            }
        } else if stream == STREAM_ADS {
            let keys = serving::ad_digest_keys(remote);
            for cached in self.ads.live_entries(now, &self.registry) {
                let Some(id) = cached.ad.get("id").and_then(Value::as_str) else {
                    continue;
                };
                if !keys.contains(serving::ad_key(id, cached.issued_ms).as_bytes()) {
                    pieces.push(Piece::Ad(&cached.stored));
                }
            }
        } else if let Some(space) = stream.strip_prefix(STREAM_SPACE_PREFIX)
            && let Some(slot) = self.spaces.get(space)
        {
            let lines = serving::digest_lines(remote);
            for (entry_id, signed) in slot.store.claims() {
                if !serving::names_line(&lines, &serving::claim_line(entry_id, signed)) {
                    pieces.push(Piece::Claim(entry_id, signed));
                }
            }
            for (entry_id, joined) in slot.store.states() {
                if !serving::names_line(&lines, &serving::state_line(entry_id, joined))
                    && let Some(signed) = slot.store.signed_state(entry_id)
                {
                    pieces.push(Piece::State(signed));
                }
            }
        }
        pieces
    }

    /// This peer's full digests (every stream it serves), the opening of its own round.
    fn full_digests(&self) -> Vec<(String, Vec<u8>)> {
        let now = self.now();
        let mut digests = Vec::new();
        let peers = self
            .registry
            .peers()
            .iter()
            .map(|(peer, held)| serving::revocation_line(&format!("r:{peer}"), &held.digest));
        digests.push((
            revocation::PEER_STREAM.to_owned(),
            serving::revocation_digest(peers),
        ));
        let credentials = self
            .registry
            .credentials()
            .iter()
            .map(|(key, held)| serving::revocation_line(&format!("c:{key}"), &held.digest));
        digests.push((
            revocation::CREDENTIAL_STREAM.to_owned(),
            serving::revocation_digest(credentials),
        ));
        let live = self
            .hub
            .admitted
            .iter()
            .filter(|(_, member)| member.expires_ms > now)
            .map(|(peer, _)| peer.as_str())
            .chain(std::iter::once(self.peer_id.as_str()));
        digests.push((serving::STREAM_VIEW.to_owned(), serving::view_digest(live)));
        let ads = self
            .ads
            .live_entries(now, &self.registry)
            .filter_map(|cached| Some((cached.ad.get("id")?.as_str()?, cached.issued_ms)));
        digests.push((STREAM_ADS.to_owned(), serving::ad_digest(ads)));
        for name in self.spaces.names() {
            if let Some(slot) = self.spaces.get(&name) {
                digests.push((
                    format!("{STREAM_SPACE_PREFIX}{name}"),
                    serving::space_digest(slot.store.states(), slot.store.claims()),
                ));
            }
        }
        digests
    }

    /// One anti-entropy round with `partner`: this peer's full digests, in as many DIGEST frames
    /// as they take, and the partner's answers expected for [`EXPECTED_FOR`].
    pub(super) fn round_with(&mut self, partner: &str) {
        let digests = self.full_digests();
        let mut frames: Vec<Map> = vec![Map::new()];
        let mut size = 0usize;
        for (stream, digest) in digests {
            let length = digest.len().saturating_add(stream.len());
            if length.saturating_add(FRAME_OVERHEAD.saturating_mul(2)) > MAX_FRAME_BYTES {
                continue; // a digest no frame carries: that stream waits for a later round
            }
            if size.saturating_add(length) > PULL_CHUNK_BYTES && size > 0 {
                frames.push(Map::new());
                size = 0;
            }
            size = size.saturating_add(length);
            if let Some(frame) = frames.last_mut() {
                frame.insert(stream, digest);
            }
        }
        self.hub
            .expected
            .retain(|expected| expected.peer != partner);
        self.hub.expected.push_back(Expected {
            peer: partner.to_owned(),
            asked: Instant::now(),
            answered: None,
        });
        while self.hub.expected.len() > MAX_EXPECTED {
            self.hub.expected.pop_front();
        }
        for digests in frames {
            let body = bodies::digest_body(&digests);
            let _ = self.send_addressed_with(KIND_DIGEST, &body, partner, Budget::Whole);
        }
        bump(&mut self.hub.counters.rounds);
    }

    /// The periodic round: with a random member that runs anti-entropy (or the seed), then the
    /// period doubles while nothing moved, up to 32 times (SPEC §5.3).
    fn periodic_round(&mut self, now: Instant) {
        let mut partners: Vec<String> = self
            .hub
            .digesters
            .iter()
            .filter(|peer| self.hub.routes.contains_key(*peer))
            .cloned()
            .collect();
        if let Some(seed) = &self.seed_peer
            && self.link.is_some()
            && !self.joining
            && !partners.contains(seed)
        {
            partners.push(seed.clone());
        }
        if !partners.is_empty() {
            let pick = usize::try_from(random_u64() % partners.len() as u64).unwrap_or(0);
            let partner = partners.swap_remove(pick.min(partners.len() - 1));
            self.round_with(&partner);
            if std::mem::take(&mut self.hub.activity) {
                self.hub.round_period = self.hub.base_period;
            } else {
                let longest = self.hub.base_period.saturating_mul(ROUND_STRETCH);
                self.hub.round_period = self.hub.round_period.saturating_mul(2).min(longest);
            }
        }
        self.hub.next_round = Some(now + jittered(self.hub.round_period));
    }

    // ------------------------------------------------------------------------- relays

    /// A RELAY_FRAME for another member (SPEC §5.4): delivered on the link this peer holds to
    /// the target, as the relay's own view holds it, or passed once to the next relay of its
    /// path; anything else is dropped and counted.
    pub(super) fn relay_onward(&mut self, relay: RelayFrame, sender: &str) {
        let hop = relay
            .hop
            .and_then(|hop| usize::try_from(hop).ok())
            .unwrap_or(0);
        if let Some(path) = &relay.path
            && !path_well_formed(path, hop, &self.peer_id, &relay.target, sender)
        {
            bump(&mut self.hub.counters.relays_bad_path);
            return;
        }
        let member = !self.registry.peer_revoked(&relay.target)
            && (self.hub.admitted.contains_key(&relay.target)
                || self.members.get(&relay.target).is_some());
        if !member {
            bump(&mut self.hub.counters.relays_not_member);
            return;
        }
        if self.relay_to(&relay.target, &relay.body()) {
            return;
        }
        if let Some(next) = relay.path.as_ref().and_then(|path| path.get(hop + 1))
            && self.relay_to(next, &relay.next_hop().body())
        {
            return;
        }
        bump(&mut self.hub.counters.relays_unreachable);
    }

    /// Sends a RELAY_FRAME body addressed to `peer` on a link this peer holds to it; whether it
    /// went.
    fn relay_to(&mut self, peer: &str, body: &[u8]) -> bool {
        let sent = if let Some(&id) = self.hub.routes.get(peer) {
            self.send_accepted(id, KIND_RELAY_FRAME, body, Some(peer), Budget::Half)
                .is_ok()
        } else if self.seed_peer.as_deref() == Some(peer) && self.link.is_some() {
            self.send_with(KIND_RELAY_FRAME, body, Some(peer), Budget::Half)
                .is_ok()
        } else {
            return false;
        };
        if sent {
            bump(&mut self.hub.counters.relays_forwarded);
        }
        sent
    }

    // ------------------------------------------------------------------------- blocks

    /// Starts fetching the payload block of a replicated entry this peer does not hold.
    pub(super) fn fetch_payload(&mut self, space: &str, entry_id: &str) {
        let Some(state) = self
            .spaces
            .get(space)
            .and_then(|slot| slot.store.state(entry_id))
        else {
            return;
        };
        let Some(PayloadSource::Block(cid)) = state
            .get("record")
            .and_then(Value::as_map)
            .and_then(records::payload_source)
        else {
            return;
        };
        if self.blocks.get(cid).is_some() || self.hub.fetches.contains_key(cid) {
            return;
        }
        let cid = cid.to_owned();
        let issuer = state
            .get("issuerPublicKey")
            .and_then(Value::as_bytes)
            .map(ids::derive_id);
        if self.hub.fetches.len() >= MAX_FETCHES {
            bump(&mut self.hub.counters.block_fetches_abandoned);
            return;
        }
        let now = Instant::now();
        self.hub.fetches.insert(
            cid.clone(),
            Fetch {
                issuer,
                space: space.to_owned(),
                entry_id: entry_id.to_owned(),
                started: now,
                next_at: now,
                attempt: 0,
            },
        );
        self.fetch_round(&cid, now);
    }

    /// A fetched block arrived: its fetch is done.
    pub(super) fn fetched(&mut self, cid: &str) {
        if self.hub.fetches.remove(cid).is_some() {
            bump(&mut self.hub.counters.blocks_fetched);
        }
    }

    /// Runs the fetches that are due.
    fn run_fetches(&mut self, now: Instant) {
        let due: Vec<String> = self
            .hub
            .fetches
            .iter()
            .filter(|(_, fetch)| fetch.next_at <= now)
            .map(|(cid, _)| cid.clone())
            .collect();
        for cid in due {
            self.fetch_round(&cid, now);
        }
    }

    /// One ask for a block: of its writer and the seed first, then of one other member in turn,
    /// the next ask after a backoff with jitter; the fetch ends once the block is held, the entry
    /// left, or [`FETCH_DEADLINE`] passed.
    fn fetch_round(&mut self, cid: &str, now: Instant) {
        let Some(fetch) = self.hub.fetches.get(cid) else {
            return;
        };
        if self.blocks.get(cid).is_some() {
            self.fetched(cid);
            return;
        }
        let gone = self
            .spaces
            .get(&fetch.space)
            .and_then(|slot| slot.store.state(&fetch.entry_id))
            .is_none();
        if gone || now.duration_since(fetch.started) >= FETCH_DEADLINE {
            self.hub.fetches.remove(cid);
            bump(&mut self.hub.counters.block_fetches_abandoned);
            return;
        }
        let mut targets: Vec<String> = Vec::new();
        if let Some(issuer) = &fetch.issuer {
            targets.push(issuer.clone());
        }
        if fetch.attempt == 0 {
            targets.extend(self.seed_peer.clone());
        } else {
            let mut others: Vec<String> = self.hub.routes.keys().cloned().collect();
            others.extend(self.seed_peer.clone());
            others.sort();
            others.retain(|peer| !targets.contains(peer));
            if !others.is_empty() {
                let index = usize::try_from(fetch.attempt).unwrap_or(0) % others.len();
                targets.push(others.swap_remove(index));
            }
        }
        targets.retain(|peer| *peer != self.peer_id);
        targets.dedup();
        let attempt = fetch.attempt;
        if let Some(fetch) = self.hub.fetches.get_mut(cid) {
            fetch.attempt = attempt.saturating_add(1);
            let backoff = Duration::from_secs(1)
                .saturating_mul(1u32 << attempt.min(5))
                .min(FETCH_BACKOFF_CAP);
            fetch.next_at = now + jittered(backoff);
        }
        if !self.note_asked(cid) {
            return;
        }
        let body = bodies::block_want_body(cid);
        for target in targets {
            if self
                .send_addressed_with(KIND_BLOCK_WANT, &body, &target, Budget::Whole)
                .is_ok()
            {
                bump(&mut self.hub.counters.block_asks);
            }
        }
    }

    /// Records that a block was asked for, so its answer is kept; `false` when the bounded
    /// memory of asks is full of recent ones.
    fn note_asked(&mut self, cid: &str) -> bool {
        let now = Instant::now();
        if !self.block_asked.contains_key(cid) && self.block_asked.len() >= MAX_ASKED_BLOCKS {
            self.block_asked
                .retain(|_, asked| now.duration_since(*asked) < Duration::from_secs(60));
            if self.block_asked.len() >= MAX_ASKED_BLOCKS {
                return false;
            }
        }
        self.block_asked.insert(cid.to_owned(), now);
        true
    }

    // ------------------------------------------------------------------------- housekeeping

    /// The listening role's tick: silent links, lapsed members, stale expectations, due
    /// fetches, and the periodic round.
    pub(super) fn on_listen_tick(&mut self) {
        let now = Instant::now();
        if self.closed || !self.hub.listening {
            self.hub.next_tick = None;
            return;
        }
        self.hub.next_tick = Some(now + TICK);
        self.close_silent_links(now);
        let wall = self.now();
        self.expire_members(wall);
        self.hub.expected.retain(|expected| expected.open(now));
        self.run_fetches(now);
        if self.hub.next_round.is_some_and(|at| at <= now) {
            self.periodic_round(now);
        }
    }

    /// The members this peer admitted (linked or not), in PeerID order.
    pub(in crate::peer) fn admitted_members(&self) -> Vec<String> {
        let mut admitted: Vec<String> = self.hub.admitted.keys().cloned().collect();
        admitted.sort();
        admitted
    }

    /// The members this peer holds an accepted link to.
    pub(in crate::peer) fn linked_members(&self) -> Vec<String> {
        let mut linked: Vec<String> = self.hub.routes.keys().cloned().collect();
        linked.sort();
        linked
    }

    /// Stops accepting links for good, before the peer closes: the accept tasks end, and a
    /// channel accepted meanwhile is closed at once. The links held stay up.
    pub(in crate::peer) fn stop_accepting(&mut self) {
        for task in self.hub.accept_tasks.drain(..) {
            task.abort();
        }
        self.hub.draining = true;
    }

    /// The outbound bytes still waiting on the links: offered and not yet handed to a transport,
    /// in an accepted link's backlog, or in the outbox and the forwards held for the dialed link
    /// while it is up.
    pub(in crate::peer) fn pending_outbound(&self) -> usize {
        let accepted = self.hub.accepted.values().fold(0usize, |total, link| {
            total
                .saturating_add(link.queue.shared.queued.load(Ordering::SeqCst))
                .saturating_add(link.backlog_bytes)
        });
        let dialed = self.link.as_ref().map_or(0, |link| {
            let outbox = self
                .outbox
                .iter()
                .fold(0usize, |total, frame| total.saturating_add(frame.len()));
            link.queue
                .shared
                .queued
                .load(Ordering::SeqCst)
                .saturating_add(outbox)
                .saturating_add(self.hub.dialed_backlog_bytes)
        });
        accepted.saturating_add(dialed)
    }
}

/// The PULL_RESP body of one chunk: each stream's pieces in its delta encoding.
fn encode_chunk(chunk: Chunk<'_>) -> Vec<u8> {
    let mut deltas = Map::with_capacity(chunk.streams.len());
    for (stream, pieces) in chunk.streams {
        let delta = if stream == revocation::PEER_STREAM || stream == revocation::CREDENTIAL_STREAM
        {
            let signed: Vec<&Map> = pieces
                .iter()
                .filter_map(|piece| match piece {
                    Piece::Revocation(map) => Some(*map),
                    _ => None,
                })
                .collect();
            serving::revocations_delta(&signed)
        } else if stream == serving::STREAM_VIEW {
            let payloads: Vec<&[u8]> = pieces
                .iter()
                .filter_map(|piece| match piece {
                    Piece::View(payload) => Some(payload.as_slice()),
                    _ => None,
                })
                .collect();
            serving::view_delta(&payloads)
        } else if stream == STREAM_ADS {
            let stored: Vec<&Value> = pieces
                .iter()
                .filter_map(|piece| match piece {
                    Piece::Ad(value) => Some(*value),
                    _ => None,
                })
                .collect();
            serving::ads_delta(&stored)
        } else {
            let mut states = Vec::new();
            let mut claims = Vec::new();
            for piece in &pieces {
                match piece {
                    Piece::State(state) => states.push(*state),
                    Piece::Claim(entry_id, signed) => claims.push((*entry_id, *signed)),
                    _ => {}
                }
            }
            serving::sync_delta(&states, &claims)
        };
        deltas.insert(stream, delta);
    }
    bodies::pull_resp_body(&deltas)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_seen_memory_is_bounded_and_keyed_by_stream_and_payload() {
        let mut seen = Seen::default();
        assert!(seen.insert("space:tasks", b"one"));
        assert!(!seen.insert("space:tasks", b"one"));
        assert!(seen.insert("space:other", b"one"), "another stream");
        for n in 0..(SEEN_CAPACITY + 10) {
            seen.insert("flood", &n.to_be_bytes());
        }
        assert!(seen.keys.len() <= SEEN_CAPACITY && seen.order.len() <= SEEN_CAPACITY);
        assert!(
            seen.insert("space:tasks", b"one"),
            "the oldest were forgotten"
        );
    }

    #[test]
    fn relay_paths_are_judged_as_the_spec_states() {
        let path = |hops: &[&str]| hops.iter().map(|h| (*h).to_owned()).collect::<Vec<_>>();
        assert!(path_well_formed(&path(&["me"]), 0, "me", "t", "origin"));
        assert!(path_well_formed(&path(&["a", "me"]), 1, "me", "t", "a"));
        assert!(
            !path_well_formed(&path(&["a", "me"]), 1, "me", "t", "b"),
            "previous hop"
        );
        assert!(
            !path_well_formed(&path(&["me", "me"]), 0, "me", "t", "o"),
            "repeated"
        );
        assert!(
            !path_well_formed(&path(&["me", "t"]), 0, "me", "t", "o"),
            "the target"
        );
        assert!(
            !path_well_formed(&path(&["x"]), 0, "me", "t", "o"),
            "not this relay"
        );
        assert!(!path_well_formed(
            &path(&["me", "a", "b", "c", "d"]),
            0,
            "me",
            "t",
            "o"
        ));
        assert!(!path_well_formed(&path(&["me"]), 3, "me", "t", "o"));
    }

    #[test]
    fn only_hostile_refusals_stop_a_forward() {
        assert!(forwardable(None));
        assert!(forwardable(Some(FoldOutcome::Applied)));
        assert!(forwardable(Some(FoldOutcome::Refused(Refusal::Full))));
        assert!(forwardable(Some(FoldOutcome::Refused(
            Refusal::RecordPending
        ))));
        assert!(!forwardable(Some(FoldOutcome::Refused(
            Refusal::UnverifiedRecord
        ))));
        assert!(!forwardable(Some(FoldOutcome::Refused(Refusal::Revoked))));
    }

    /// A DIGEST answered on a busy link (its backlog holding frames already) keeps its whole
    /// answer, the revocations first: an answer never outgrows the backlog that holds it, so the
    /// backlog drops older frames and never the revocations that judge the states after them.
    #[tokio::test]
    async fn an_answer_on_a_busy_link_keeps_its_revocations() {
        use crate::transport::memory;
        use agentspaces_wire::{envelope, time};

        let (mut actor, _events, _inbound, _link) = super::super::tests::test_actor();
        actor.hub.listening = true;
        actor.settings.send_queue_bytes = 4 * 1024 * 1024;
        // A held revocation, the founder's.
        let founder = Identity::generate().expect("identity");
        actor
            .registry
            .set_founder(Some(founder.peer_id().to_owned()));
        let now = actor.now();
        let ad = revocation::credential_revocation(
            founder.peer_id(),
            &actor.group,
            &time::instant_iso(now - 1000),
            "PT720H",
            &revocation::join_credential_target(&[9u8; 32]),
            revocation::UNSPECIFIED,
            None,
        )
        .expect("a revocation");
        let signed =
            agentspaces_wire::cbor::encode(&Value::Map(revocation::sign_revocation(&ad, &founder)));
        assert!(
            actor
                .registry
                .accept(revocation::CREDENTIAL_STREAM, &signed, now)
        );
        // Members whose advertisements make the answer's view several MiB.
        for n in 0..6u8 {
            actor.hub.admitted.insert(
                format!("member-{n}"),
                Member {
                    payload: vec![n; 1024 * 1024],
                    issued_ms: now,
                    expires_ms: now + 60_000,
                    credentials: Vec::new(),
                    rate: TokenBucket::new(MEMBER_BURST, MEMBER_RATE),
                    answers: TokenBucket::new(ANSWER_BURST, ANSWER_RATE),
                    cursors: HashMap::new(),
                    round_owed: false,
                },
            );
        }
        // The asker's link is busy: its queue full (a slow reader), a forward waiting already.
        let (mine, _theirs) = memory::pair("mem", "member", "hub", None, None);
        let link = actor.open_link(mine, true);
        let id = link.id;
        link.queue
            .shared
            .queued
            .store(actor.settings.send_queue_bytes, Ordering::SeqCst);
        actor.hub.accepted.insert(id, link);
        if let Some(link) = actor.hub.accepted.get_mut(&id) {
            link.backlog.push_back(vec![0u8; 1024]);
            link.backlog_bytes = 1024;
        }
        let mut digests = Map::new();
        for stream in [revocation::CREDENTIAL_STREAM, serving::STREAM_VIEW] {
            digests.insert(stream, Vec::<u8>::new());
        }
        assert!(
            actor
                .on_digest("asker", &bodies::digest_body(&digests), Via::Accepted(id))
                .is_ok(),
            "the digest parses"
        );
        let held: Vec<Vec<u8>> = actor
            .hub
            .accepted
            .get(&id)
            .map(|link| link.backlog.iter().cloned().collect())
            .unwrap_or_default();
        let revocations = held.iter().any(|frame| {
            envelope::decode_frame(frame)
                .and_then(|env| {
                    env.get("body")
                        .and_then(Value::as_bytes)
                        .map(<[u8]>::to_vec)
                })
                .and_then(|body| bodies::parse_pull_resp(&body))
                .is_some_and(|deltas| deltas.get(revocation::CREDENTIAL_STREAM).is_some())
        });
        assert!(
            revocations,
            "the answer lost its revocations ({} frames held, {} dropped)",
            held.len(),
            actor.hub.counters.backlog_dropped
        );
    }

    #[test]
    fn sizes_bound_the_encoding() {
        use agentspaces_wire::cbor;
        let value = agentspaces_wire::cbor_map! {
            "a" => "text",
            "b" => Value::Bytes(vec![1; 300]),
            "c" => Value::Array(vec![Value::from(1), Value::from("x")]),
        };
        assert!(value_size(&value) >= cbor::encode(&value).len());
    }
}
